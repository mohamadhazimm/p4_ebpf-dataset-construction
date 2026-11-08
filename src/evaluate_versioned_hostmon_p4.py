#!/usr/bin/env python3
"""Compare P4-network and HostMon/eBPF features on the isolated 2026-10-17 cohort."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer

STUDY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from train_compare import make_model, metrics_for  # noqa: E402


DEFAULT_DATA_ROOT = (
    STUDY_ROOT
    / "data/versioned-collector/telemetry-2026-10-17.2-20261017T220948Z"
)
DEFAULT_MALWARE_LABELS = (
    STUDY_ROOT
    / "data/malware/revision4/training521_holdout461_20261017/malware_hash_labels.csv"
)
HOST_GROUPS = (
    "host_runtime",
    "hostmon_syscall_sequence",
    "host_event_extras",
    "ebpf_syscall_counts",
)
STATISTICS = ("mean", "max", "sum", "std", "active_windows")
COHORTS = {
    "train": (("malware-training-535", 1), ("benign-training-500", 0)),
    "test": (("malware-holdout-323", 1), ("benign-validation-138", 0)),
}
EXPECTED_COMPLETED = {
    "malware-training-535": 521,
    "malware-holdout-323": 315,
    "benign-training-500": 500,
    "benign-validation-138": 138,
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def aggregate_feature(rows: list[dict[str, str]], field: str) -> dict[str, float]:
    values = []
    for row in rows:
        try:
            value = float(row[field])
        except (TypeError, ValueError):
            continue
        if math.isfinite(value):
            values.append(value)
    if not values:
        return {statistic: math.nan for statistic in STATISTICS}
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return {
        "mean": mean,
        "max": max(values),
        "sum": sum(values),
        "std": math.sqrt(variance),
        "active_windows": float(sum(value != 0 for value in values)),
    }


def load_benign_manifests() -> dict[str, dict[str, dict[str, str]]]:
    result = {}
    for split in ("training", "validation"):
        path = (
            STUDY_ROOT
            / f"data/benign/revision4/expanded/{split}/workload_manifest.csv"
        )
        result[split] = {row["sample_artifact"]: row for row in read_csv(path)}
    if len(result["training"]) != 500 or len(result["validation"]) != 138:
        raise ValueError("Benign workload manifest counts do not match the cohorts")
    training_groups = {row["group_id"] for row in result["training"].values()}
    validation_groups = {row["group_id"] for row in result["validation"].values()}
    if training_groups & validation_groups:
        raise ValueError("Benign package groups overlap across train and test")
    return result


def host_status(path: Path) -> str:
    return next(
        (
            line.split("=", 1)[1]
            for line in path.read_text(errors="replace").splitlines()
            if line.startswith("status=")
        ),
        "missing_status",
    )


def load_cohorts(data_root: Path, corrected_root: Path | None = None):
    collection = json.loads((data_root / "collection_manifest.json").read_text())
    schema_version = collection["telemetry_schema_version"]
    runner_hash = collection["malware_runner_sha256"]
    benign_manifests = load_benign_manifests()
    examples = {"train": [], "test": []}
    status_counts = {}
    declared_groups = None
    signal_fields = None
    corrected_audit = {}
    if corrected_root is not None:
        summary = json.loads((corrected_root / "reconstruction_summary.json").read_text())
        manifest_hash = hashlib.sha256(
            (data_root / "collection_manifest.json").read_bytes()
        ).hexdigest()
        if summary["source_collection_manifest_sha256"] != manifest_hash:
            raise ValueError("Corrected CSVs belong to a different collection manifest")
        corrected_audit = {
            (row["cohort"], row["sample_artifact"]): row
            for row in read_csv(corrected_root / "reconstruction_audit.csv")
        }

    for split, cohorts in COHORTS.items():
        for cohort, label in cohorts:
            definition = collection["cohorts"][cohort]
            manifest_path = data_root / definition["manifest"]
            samples = [
                line.strip()
                for line in manifest_path.read_text(encoding="ascii").splitlines()
                if line.strip()
            ]
            if len(samples) != definition["expected_samples"]:
                raise ValueError(f"{cohort}: frozen manifest count mismatch")
            audit = json.loads(
                (data_root / "summaries" / f"{cohort}.json").read_text()
            )
            if (
                audit.get("runner_schema_version") != schema_version
                or audit.get("runner_sha256") != runner_hash
            ):
                raise ValueError(f"{cohort}: audit runner provenance mismatch")

            accepted = []
            host_statuses = Counter()
            for artifact in samples:
                sample_dir = data_root / "runs" / cohort / artifact
                status = host_status(sample_dir / "host_run.txt")
                host_statuses[status] += 1
                if status != "completed":
                    continue
                run_jsons = list((sample_dir / "output").rglob("run.json"))
                if len(run_jsons) != 1:
                    raise ValueError(
                        f"{cohort}/{artifact}: expected one run.json, found {len(run_jsons)}"
                    )
                run_dir = run_jsons[0].parent
                metadata = json.loads(run_jsons[0].read_text())
                if (
                    metadata.get("telemetry_schema_version") != schema_version
                    or metadata.get("malware_runner_sha256") != runner_hash
                ):
                    raise ValueError(f"{cohort}/{artifact}: run provenance mismatch")

                groups = metadata.get("telemetry_feature_groups", {})
                if declared_groups is None:
                    declared_groups = groups
                elif groups != declared_groups:
                    raise ValueError(f"{cohort}/{artifact}: feature groups differ")
                fields = groups.get("p4_network", []) + [
                    field
                    for group in HOST_GROUPS
                    for field in groups.get(group, [])
                ]
                if not groups.get("p4_network") or any(
                    not groups.get(group) for group in HOST_GROUPS
                ):
                    raise ValueError("Required P4 or HostMon/eBPF feature group is missing")
                if len(fields) != len(set(fields)):
                    raise ValueError("Feature groups contain duplicate signal names")
                if signal_fields is None:
                    signal_fields = fields
                elif fields != signal_fields:
                    raise ValueError(f"{cohort}/{artifact}: feature list differs")

                telemetry_rows = read_csv(run_dir / "telemetry.csv")
                if corrected_root is not None:
                    audit_row = corrected_audit[(cohort, artifact)]
                    corrected_path = corrected_root / "telemetry" / cohort / artifact / "telemetry.csv"
                    for path, field in (
                        (run_dir / "telemetry.csv", "source_telemetry_sha256"),
                        (corrected_path, "corrected_telemetry_sha256"),
                    ):
                        if hashlib.sha256(path.read_bytes()).hexdigest() != audit_row[field]:
                            raise ValueError(f"Reconstruction hash mismatch: {path}")
                    corrected_rows = read_csv(corrected_path)
                    if len(telemetry_rows) != len(corrected_rows):
                        raise ValueError(f"Corrected window count differs: {artifact}")
                    for original, corrected in zip(telemetry_rows, corrected_rows, strict=True):
                        if set(original) != set(corrected) or any(
                            original[field] != corrected[field]
                            for field in original
                            if field not in groups["p4_network"]
                        ):
                            raise ValueError(f"Non-P4 values changed: {artifact}")
                    telemetry_rows = corrected_rows
                if not telemetry_rows:
                    raise ValueError(f"{cohort}/{artifact}: no telemetry windows")
                missing = set(fields) - set(telemetry_rows[0])
                if missing:
                    raise ValueError(
                        f"{cohort}/{artifact}: missing telemetry fields {sorted(missing)}"
                    )
                accepted.append((artifact, metadata, telemetry_rows, fields))

            status_counts[cohort] = dict(host_statuses)
            if host_statuses != Counter(audit.get("status_counts", {})):
                raise ValueError(f"{cohort}: host statuses differ from final audit")
            completed = len(accepted)
            if (
                completed != EXPECTED_COMPLETED[cohort]
                or completed != audit["status_counts"].get("completed", 0)
            ):
                raise ValueError(
                    f"{cohort}: expected {EXPECTED_COMPLETED[cohort]} completed, got {completed}"
                )

            if label == 0:
                manifest_split = "training" if split == "train" else "validation"
                if {item[0] for item in accepted} != set(benign_manifests[manifest_split]):
                    raise ValueError(f"{cohort}: run and benign manifest differ")

            for artifact, metadata, telemetry_rows, fields in accepted:
                example = {
                    "sample_artifact": artifact,
                    "sample_name": str(metadata.get("sample_name") or artifact),
                    "cohort": cohort,
                    "label": label,
                    "runner_status": str(metadata.get("status", "")),
                    "ebpf_status": str(metadata.get("ebpf_status", "")),
                    "window_count": len(telemetry_rows),
                    "benign_package_group": "",
                }
                if label == 0:
                    manifest_split = "training" if split == "train" else "validation"
                    example["benign_package_group"] = benign_manifests[
                        manifest_split
                    ][artifact]["group_id"]
                for field in fields:
                    for statistic, value in aggregate_feature(
                        telemetry_rows, field
                    ).items():
                        example[f"{field}__{statistic}"] = value
                examples[split].append(example)
            print(f"Loaded {cohort}: {completed}/{definition['expected_samples']}")

    train_artifacts = {row["sample_artifact"] for row in examples["train"]}
    test_artifacts = {row["sample_artifact"] for row in examples["test"]}
    if train_artifacts & test_artifacts:
        raise ValueError("Sample artifacts overlap across train and test")
    return examples, declared_groups, status_counts


def split_malware_by_family(
    rows: list[dict], labels_path: Path, train_fraction: float, seed: int
):
    labels = {row["sha256"].lower(): row for row in read_csv(labels_path)}
    by_family: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        digest = Path(row["sample_artifact"]).stem.lower()
        label = labels.get(digest)
        if label is None:
            raise ValueError(f"No family label for {row['sample_artifact']}")
        expected_membership = (
            "training" if row["cohort"] == "malware-training-535" else "holdout"
        )
        if label["telemetry_model_membership"] != expected_membership:
            raise ValueError(f"Unexpected model membership for {row['sample_artifact']}")
        family = label.get("family_label", "").strip() or "unknown/unassigned"
        by_family[family].append({**row, "family_label": family, "sha256": digest})

    rng = np.random.default_rng(seed)
    training = []
    validation = []
    counts = {}
    for family in sorted(by_family):
        samples = by_family[family]
        shuffled = rng.permutation(len(samples))
        train_count = max(1, int(round(len(samples) * train_fraction)))
        if len(samples) > 1:
            train_count = min(len(samples) - 1, train_count)
        training.extend(samples[int(index)] for index in shuffled[:train_count])
        validation.extend(samples[int(index)] for index in shuffled[train_count:])
        counts[family] = {
            "total": len(samples),
            "training": train_count,
            "validation": len(samples) - train_count,
        }

    training.sort(key=lambda row: row["sample_artifact"])
    validation.sort(key=lambda row: row["sample_artifact"])
    return training, validation, counts


def numeric_matrix(rows: list[dict], features: list[str]) -> np.ndarray:
    matrix = np.full((len(rows), len(features)), np.nan, dtype=float)
    for row_index, row in enumerate(rows):
        for column_index, feature in enumerate(features):
            value = row[feature]
            if math.isfinite(value):
                matrix[row_index, column_index] = value
    return matrix


def select_balanced_host_signals(
    rows: list[dict],
    host_fields: list[str],
    labels: np.ndarray,
    signal_budget: int,
    seed: int,
) -> tuple[list[str], dict[str, float]]:
    candidate_features = [
        f"{field}__{statistic}"
        for field in host_fields
        for statistic in STATISTICS
    ]
    matrix = numeric_matrix(rows, candidate_features)
    nonempty = np.isfinite(matrix).any(axis=0)
    candidate_features = [
        feature for feature, keep in zip(candidate_features, nonempty, strict=True) if keep
    ]
    matrix = SimpleImputer(strategy="median").fit_transform(matrix[:, nonempty])
    scores = mutual_info_classif(matrix, labels, random_state=seed)

    scores_by_signal: dict[str, list[float]] = {}
    for feature, score in zip(candidate_features, scores, strict=True):
        signal = feature.rpartition("__")[0]
        scores_by_signal.setdefault(signal, []).append(float(score))
    mean_scores = {
        signal: float(np.mean(signal_scores))
        for signal, signal_scores in scores_by_signal.items()
    }
    if len(mean_scores) < signal_budget:
        raise ValueError(
            f"Only {len(mean_scores)} usable host signals for budget {signal_budget}"
        )
    selected = sorted(
        mean_scores, key=lambda signal: (-mean_scores[signal], signal)
    )[:signal_budget]
    return selected, mean_scores


def write_dataset(path: Path, rows: list[dict], feature_names: list[str]) -> None:
    metadata = [
        "sample_artifact",
        "sample_name",
        "cohort",
        "label",
        "runner_status",
        "ebpf_status",
        "window_count",
        "benign_package_group",
    ]
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(
            destination,
            fieldnames=metadata + feature_names,
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    key: ""
                    if isinstance(value, float) and not math.isfinite(value)
                    else value
                    for key, value in row.items()
                }
            )


def sample_per_class(rows: list[dict], count: int | None, seed: int) -> list[dict]:
    if count is None:
        return rows
    if count < 1:
        raise ValueError("Sample count per class must be positive")
    rng = np.random.default_rng(seed)
    selected = []
    for label in (0, 1):
        candidates = [row for row in rows if int(row["label"]) == label]
        if len(candidates) < count:
            raise ValueError(f"Requested {count} samples for class {label}, only {len(candidates)} available")
        indices = rng.choice(len(candidates), size=count, replace=False)
        selected.extend(candidates[int(index)] for index in indices)
    return sorted(selected, key=lambda row: (row["cohort"], row["sample_artifact"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--malware-labels", type=Path, default=DEFAULT_MALWARE_LABELS)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--corrected-csv-root", type=Path)
    parser.add_argument("--frozen-experiment", type=Path)
    parser.add_argument("--train-per-class", type=int)
    parser.add_argument("--validation-per-class", type=int)
    parser.add_argument("--include-native-hostmon", action="store_true")
    parser.add_argument("--malware-train-fraction", type=float, default=0.10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if not 0 < args.malware_train_fraction < 0.5:
        parser.error("--malware-train-fraction must be greater than 0 and less than 0.5")
    if any(count is not None and count < 1 for count in (args.train_per_class, args.validation_per_class)):
        parser.error("Subset limits must be positive")
    if args.frozen_experiment and (args.train_per_class or args.validation_per_class or args.include_native_hostmon):
        parser.error("Frozen experiments require unchanged sample assignments and feature sets")
    data_root = args.data_root.expanduser().resolve()
    output_dir = args.output_dir or data_root / "modeling/hostmon-p4-family10-20261018"
    output_dir = output_dir.expanduser().resolve()
    if output_dir.exists():
        parser.error(f"Refusing to overwrite existing output directory: {output_dir}")

    examples, groups, _ = load_cohorts(data_root, args.corrected_csv_root)
    all_malware = [
        row
        for split_rows in examples.values()
        for row in split_rows
        if int(row["label"]) == 1
    ]
    benign_training = [row for row in examples["train"] if int(row["label"]) == 0]
    benign_validation = [row for row in examples["test"] if int(row["label"]) == 0]
    malware_training, malware_validation, family_split_counts = split_malware_by_family(
        all_malware,
        args.malware_labels.expanduser().resolve(),
        args.malware_train_fraction,
        args.seed,
    )
    train_rows = sorted(
        malware_training + benign_training,
        key=lambda row: (row["cohort"], row["sample_artifact"]),
    )
    validation_rows = sorted(
        malware_validation + benign_validation,
        key=lambda row: (row["cohort"], row["sample_artifact"]),
    )
    train_rows = sample_per_class(train_rows, args.train_per_class, args.seed)
    validation_rows = sample_per_class(validation_rows, args.validation_per_class, args.seed + 1)
    if args.train_per_class or args.validation_per_class:
        for family, counts in family_split_counts.items():
            counts["available_training"] = counts["training"]
            counts["available_validation"] = counts["validation"]
            counts["training"] = sum(row.get("family_label") == family for row in train_rows)
            counts["validation"] = sum(row.get("family_label") == family for row in validation_rows)
    y_train = np.asarray([int(row["label"]) for row in train_rows])
    y_validation = np.asarray([int(row["label"]) for row in validation_rows])
    if set(y_train) != {0, 1} or set(y_validation) != {0, 1}:
        raise ValueError("Both binary classes must appear in training and validation")
    if {row["sample_artifact"] for row in train_rows} & {
        row["sample_artifact"] for row in validation_rows
    }:
        raise ValueError("A sample appears in both training and validation")

    frozen_report = None
    if args.frozen_experiment is not None:
        frozen_report = json.loads((args.frozen_experiment / "metrics.json").read_text())
        expected = {
            row["sample_artifact"]: (row["split"], row["cohort"], int(row["label"]))
            for row in read_csv(args.frozen_experiment / "split_assignments.csv")
        }
        actual = {
            row["sample_artifact"]: (split, row["cohort"], int(row["label"]))
            for split, rows in (("training", train_rows), ("validation", validation_rows))
            for row in rows
        }
        if actual != expected:
            raise ValueError("Sample split differs from frozen experiment")

    p4_fields = list(groups["p4_network"])
    host_fields = [field for group in HOST_GROUPS for field in groups[group]]
    if frozen_report is None:
        selected_host_fields, host_signal_scores = select_balanced_host_signals(
            train_rows, host_fields, y_train, len(p4_fields), args.seed
        )
    else:
        selection = frozen_report["feature_definition"]["balanced_host_selection"]
        selected_host_fields = selection["selected_signals"]
        host_signal_scores = selection["mean_mutual_information"]
        if len(selected_host_fields) != len(p4_fields) or not set(selected_host_fields) <= set(host_fields):
            raise ValueError("Frozen host selection does not match the signal budget")
    signal_sets = {
        "p4_network": p4_fields,
        "hostmon_ebpf_balanced_29": selected_host_fields,
        "hybrid_p4_hostmon_ebpf_balanced_58": p4_fields + selected_host_fields,
    }
    if args.include_native_hostmon:
        native_fields = list(groups["hostmon_syscall_sequence"])
        if len(native_fields) != 26:
            raise ValueError("Expected exactly 26 native HostMon signals")
        signal_sets["hostmon_native_26"] = native_fields
        signal_sets["hybrid_p4_hostmon_native_55"] = p4_fields + native_fields
    feature_sets = {
        name: [f"{field}__{statistic}" for field in fields for statistic in STATISTICS]
        for name, fields in signal_sets.items()
    }
    for name, features in feature_sets.items():
        feature_sets[name] = [
            feature
            for feature in features
            if any(math.isfinite(row[feature]) for row in train_rows)
        ]
        if not feature_sets[name]:
            raise ValueError(f"No numeric training features for {name}")
    if args.frozen_experiment is not None:
        frozen_features = json.loads(
            (args.frozen_experiment / "feature_columns.json").read_text()
        )
        if feature_sets != frozen_features:
            raise ValueError("Feature columns differ from frozen experiment")

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
    )
    try:
        (staging / "models").mkdir()
        report = {
            "evaluation": "Family-stratified malware training/validation split; benign package-disjoint manifests; binary malware detection",
            "seed": args.seed,
            "subset": {
                "training_per_class": args.train_per_class,
                "validation_per_class": args.validation_per_class,
                "method": "Uniform sampling without replacement within each class of the existing separate splits",
                "training_seed": args.seed,
                "validation_seed": args.seed + 1,
            },
            "corrected_csv_root": str(args.corrected_csv_root.resolve())
            if args.corrected_csv_root else None,
            "frozen_experiment": str(args.frozen_experiment.resolve())
            if args.frozen_experiment else None,
            "malware_train_fraction_per_family": args.malware_train_fraction,
            "positive_label": "malware",
            "threshold": 0.5,
            "training_samples": len(train_rows),
            "validation_samples": len(validation_rows),
            "malware_family_split_counts": family_split_counts,
            "malware_families_in_training": sum(
                counts["training"] > 0 for counts in family_split_counts.values()
            ),
            "malware_families_in_validation": sum(
                counts["validation"] > 0 for counts in family_split_counts.values()
            ),
            "single_sample_families_training_only": [
                family
                for family, counts in family_split_counts.items()
                if counts["total"] == 1 and counts["training"] > 0
            ],
            "training_class_counts": {
                "benign": int((y_train == 0).sum()),
                "malware": int((y_train == 1).sum()),
            },
            "validation_class_counts": {
                "benign": int((y_validation == 0).sum()),
                "malware": int((y_validation == 1).sum()),
            },
            "feature_definition": {
                "p4_network_groups": ["p4_network"],
                "hostmon_ebpf_groups": list(HOST_GROUPS),
                "balanced_host_selection": {
                    "method": "training-only mutual information; mean score across five summaries per signal",
                    "signal_budget": len(p4_fields),
                    "selected_signals": selected_host_fields,
                    "mean_mutual_information": {
                        signal: host_signal_scores[signal]
                        for signal in selected_host_fields
                    },
                },
                "excluded_groups": [
                    group
                    for group in groups
                    if group not in {"p4_network", *HOST_GROUPS}
                ],
                "aggregation_statistics": list(STATISTICS),
                "signals_by_model": signal_sets,
                "native_hostmon_note": "Native field names from the runner's hostmon_syscall_sequence group; not a rerun of the live repository collector",
                "metadata_and_status_fields_excluded_from_model": True,
            },
            "split_checks": {
                "malware_samples_disjoint": True,
                "malware_family_stratified": True,
                "benign_manifests_disjoint": True,
                "benign_package_groups_disjoint": True,
                "no_sample_artifact_overlap": True,
            },
            "models": {},
        }
        predictions = []
        importances = []
        raw_signal_counts = {name: len(fields) for name, fields in signal_sets.items()}
        for name, features in feature_sets.items():
            model = make_model(args.seed)
            model.fit(numeric_matrix(train_rows, features), y_train)
            probabilities = model.predict_proba(
                numeric_matrix(validation_rows, features)
            )[:, 1]
            predicted = (probabilities >= 0.5).astype(int)
            report["models"][name] = {
                "raw_signal_count": raw_signal_counts[name],
                "aggregated_feature_count": len(features),
                "metrics": metrics_for(y_validation, predicted, probabilities),
            }
            joblib.dump(
                {
                    "model": model,
                    "feature_names": features,
                    "feature_set": name,
                    "seed": args.seed,
                    "threshold": 0.5,
                },
                staging / "models" / f"{name}.joblib",
            )
            importances.extend(
                {
                    "feature_set": name,
                    "feature": feature,
                    "importance": float(importance),
                }
                for feature, importance in zip(
                    features, model[-1].feature_importances_, strict=True
                )
            )
            predictions.extend(
                {
                    "model": name,
                    "sample_artifact": row["sample_artifact"],
                    "cohort": row["cohort"],
                    "family_label": row.get("family_label", "benign"),
                    "true_label": int(row["label"]),
                    "runner_status": row["runner_status"],
                    "probability_malware": float(probability),
                    "prediction": int(prediction),
                    "correct": int(prediction == row["label"]),
                }
                for row, probability, prediction in zip(
                    validation_rows, probabilities, predicted, strict=True
                )
            )
            print(f"{name}: {report['models'][name]['metrics']}")

        all_features = sorted(
            {feature for features in feature_sets.values() for feature in features}
        )
        write_dataset(staging / "training_samples.csv", train_rows, all_features)
        write_dataset(staging / "validation_samples.csv", validation_rows, all_features)
        with (staging / "validation_predictions.csv").open(
            "w", newline="", encoding="utf-8"
        ) as destination:
            writer = csv.DictWriter(destination, fieldnames=list(predictions[0]))
            writer.writeheader()
            writer.writerows(predictions)
        assignments = [
            {
                "sample_artifact": row["sample_artifact"],
                "cohort": row["cohort"],
                "label": int(row["label"]),
                "family_label": row.get("family_label", "benign"),
                "benign_package_group": row["benign_package_group"],
                "split": split,
            }
            for split, rows in (("training", train_rows), ("validation", validation_rows))
            for row in rows
        ]
        with (staging / "split_assignments.csv").open(
            "w", newline="", encoding="utf-8"
        ) as destination:
            writer = csv.DictWriter(destination, fieldnames=list(assignments[0]))
            writer.writeheader()
            writer.writerows(assignments)
        importances.sort(
            key=lambda row: (row["feature_set"], -row["importance"], row["feature"])
        )
        with (staging / "feature_importances.csv").open(
            "w", newline="", encoding="utf-8"
        ) as destination:
            writer = csv.DictWriter(
                destination, fieldnames=["feature_set", "feature", "importance"]
            )
            writer.writeheader()
            writer.writerows(importances)
        with (staging / "host_feature_selection.csv").open(
            "w", newline="", encoding="utf-8"
        ) as destination:
            writer = csv.DictWriter(
                destination,
                fieldnames=["selected", "host_signal", "training_mean_mutual_information"],
            )
            writer.writeheader()
            writer.writerows(
                {
                    "selected": int(signal in selected_host_fields),
                    "host_signal": signal,
                    "training_mean_mutual_information": score,
                }
                for signal, score in sorted(
                    host_signal_scores.items(),
                    key=lambda item: (-item[1], item[0]),
                )
            )
        (staging / "feature_columns.json").write_text(
            json.dumps(feature_sets, indent=2) + "\n", encoding="utf-8"
        )
        (staging / "metrics.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(staging, output_dir)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print(f"RESULT_DIR {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())