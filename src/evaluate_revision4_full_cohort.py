#!/usr/bin/env python3
"""Build and score the 2026-10-17 revision-4 malware/benign cohort."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
from scapy.utils import PcapReader
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parents[1]
P4_DIR = WORKSPACE / "p4_ebpf"
sys.path.insert(0, str(P4_DIR))

import analyze_p4_pcap_ablation as p4_analyzer  # noqa: E402
from reconstruct_ambiguous_p4 import enumerate_weighted_assignments  # noqa: E402
from train_compare import make_model, metrics_for, numeric_matrix  # noqa: E402


DEFAULT_STUDY_DIR = ROOT
DEFAULT_MALWARE_RUNS = ROOT / "data/malware/revision4/runs/training-535-20261017"
DEFAULT_BENIGN_RUNS = ROOT / "data/benign/revision4/expanded/runs/training-500-20261017"
DEFAULT_LABELS = ROOT / "data/malware/revision4/training521_holdout461_20261017/malware_hash_labels.csv"
DEFAULT_BENIGN_MANIFEST = ROOT / "data/benign/revision4/expanded/training/workload_manifest.csv"
DEFAULT_OUTPUT = ROOT / "data/malware/revision4/full_cohort_evaluation_20261017"
STATISTICS = ("mean", "max", "sum", "std", "active_windows")
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    def csv_safe(value):
        if not isinstance(value, str):
            return value
        return "".join(
            character
            if character in "\t\n\r" or 32 <= ord(character) < 127 or ord(character) >= 128
            else f"\\x{ord(character):02x}"
            for character in value
        )

    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(
            {name: csv_safe(value) for name, value in row.items()}
            for row in rows
        )


def numeric(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def aggregate(values: list[float]) -> dict[str, float]:
    if not values:
        return {statistic: math.nan for statistic in STATISTICS}
    mean_value = sum(values) / len(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    return {
        "mean": mean_value,
        "max": max(values),
        "sum": sum(values),
        "std": math.sqrt(variance),
        "active_windows": float(sum(value != 0 for value in values)),
    }


def index_run_dirs(root: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for metadata_path in sorted(root.rglob("run.json")):
        artifact = metadata_path.parents[2].name
        if artifact in result:
            raise ValueError(f"Multiple run records for sample artifact {artifact} under {root}")
        result[artifact] = metadata_path.parent
    return result


def reconstruct_p4(run_dir: Path, telemetry_rows: list[dict[str, str]], metadata: dict):
    pcap_path = run_dir / "packet_capture.pcap"
    initial_features, _, diagnostics = p4_analyzer.derive_p4_features(
        pcap_path, telemetry_rows, metadata
    )
    if diagnostics["alignment_status"] == "unique":
        return initial_features, {
            **diagnostics,
            "p4_reconstruction_method": "unique_packet_window_assignment",
            "counter_consistent_assignments": 1,
            "feasible_offset_duration_seconds": "",
            "varying_p4_features": 0,
        }, []

    with PcapReader(str(pcap_path)) as capture:
        frame_times = np.asarray([float(packet.time) for packet in capture])
    assignments, total_duration = enumerate_weighted_assignments(
        frame_times, telemetry_rows, metadata
    )
    candidate_vectors = []
    candidate_weights = []
    candidate_rows = []
    original_recover = p4_analyzer.recover_frame_windows
    try:
        for candidate_index, (assignment, weight) in enumerate(assignments, start=1):
            def forced_assignment(
                _frame_times,
                _telemetry_rows,
                _run_metadata,
                assignment=assignment,
            ):
                return list(assignment), {
                    "alignment_status": "unique",
                    "exact_offset_representatives": 1,
                    "unique_packet_window_assignments": 1,
                    "offset_min_after_run_start_seconds": 0.0,
                    "offset_max_after_run_start_seconds": 0.0,
                }

            p4_analyzer.recover_frame_windows = forced_assignment
            features, _, _ = p4_analyzer.derive_p4_features(
                pcap_path, telemetry_rows, metadata
            )
            vector = np.asarray(
                [features[column] for column in p4_analyzer.P4_SAMPLE_FEATURES],
                dtype=float,
            )
            candidate_vectors.append(vector)
            candidate_weights.append(weight)
            candidate_rows.append(
                {
                    "candidate_assignment": candidate_index,
                    "feasible_offset_weight": weight,
                    **dict(zip(p4_analyzer.P4_SAMPLE_FEATURES, vector, strict=True)),
                }
            )
    finally:
        p4_analyzer.recover_frame_windows = original_recover

    stack = np.vstack(candidate_vectors)
    weights = np.asarray(candidate_weights, dtype=float)
    expected = np.average(stack, axis=0, weights=weights)
    variance = np.average((stack - expected) ** 2, axis=0, weights=weights)
    spread = np.ptp(stack, axis=0)
    features = dict(zip(p4_analyzer.P4_SAMPLE_FEATURES, expected, strict=True))
    uncertainty = [
        {
            "feature": feature,
            "candidate_assignment_count": len(assignments),
            "duration_weighted_mean": expected[index],
            "duration_weighted_std": math.sqrt(variance[index]),
            "candidate_min": float(np.min(stack[:, index])),
            "candidate_max": float(np.max(stack[:, index])),
        }
        for index, feature in enumerate(p4_analyzer.P4_SAMPLE_FEATURES)
    ]
    return features, {
        **diagnostics,
        "p4_reconstruction_method": "duration_weighted_counter_consistent_assignments",
        "counter_consistent_assignments": len(assignments),
        "feasible_offset_duration_seconds": total_duration,
        "varying_p4_features": int(np.sum(spread > 1e-10)),
    }, [
        {"candidate": row} for row in candidate_rows
    ] + [{"uncertainty": row} for row in uncertainty]


def load_samples(
    malware_runs: Path,
    benign_runs: Path,
    labels_path: Path,
    benign_manifest_path: Path,
    malware_membership: str = "training",
    require_exact_malware_labels: bool = True,
):
    labels = {
        row["sha256"].lower(): row
        for row in read_csv(labels_path)
        if row["telemetry_model_membership"] == malware_membership
    }
    manifest = {
        row["sample_artifact"]: row for row in read_csv(benign_manifest_path)
    }
    malware_dirs = index_run_dirs(malware_runs)
    benign_dirs = index_run_dirs(benign_runs)
    malware_artifacts = set(malware_dirs)
    malware_hashes = {Path(artifact).stem.lower() for artifact in malware_artifacts}
    benign_artifacts = set(benign_dirs)
    unlabelled = malware_hashes - set(labels)
    missing = set(labels) - malware_hashes
    if unlabelled or (require_exact_malware_labels and missing):
        raise ValueError(
            f"Malware run/label mismatch for {malware_membership}: "
            f"missing runs={len(missing)}, unlabelled runs={len(unlabelled)}"
        )
    if benign_artifacts != set(manifest):
        missing = set(manifest) - benign_artifacts
        extra = benign_artifacts - set(manifest)
        raise ValueError(
            f"Benign run/manifest mismatch: missing runs={len(missing)}, extra runs={len(extra)}"
        )

    examples = []
    diagnostics_rows = []
    candidate_rows = []
    uncertainty_rows = []
    raw_signal_fields: set[str] = set()
    event_names: set[str] = set()
    status_counts = Counter()
    failure_reasons = Counter()
    for label, run_dirs in ((1, malware_dirs), (0, benign_dirs)):
        for artifact, run_dir in sorted(run_dirs.items()):
            metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            telemetry_rows = read_csv(run_dir / "telemetry.csv")
            if not telemetry_rows:
                raise ValueError(f"No telemetry windows for {artifact}")
            signal_fields = {
                field
                for field in telemetry_rows[0]
                if field.startswith(("net_", "host_", "ebpf_"))
                and field != "ebpf_status"
            }
            raw_signal_fields.update(signal_fields)
            window_values = {
                field: [number for row in telemetry_rows if (number := numeric(row.get(field))) is not None]
                for field in signal_fields
            }
            row: dict[str, str | float | int] = {
                "sample_artifact": artifact,
                "sample_name": str(metadata.get("sample_name", artifact)),
                "label": label,
                "run_status": str(metadata.get("status", "")),
                "failure_reason": str(metadata.get("failure_reason") or ""),
                "ebpf_status": str(metadata.get("ebpf_status", "")),
                "packet_capture_status": str(metadata.get("packet_capture_status", "")),
                "window_count": len(telemetry_rows),
            }
            for field in sorted(signal_fields):
                for statistic, value in aggregate(window_values[field]).items():
                    row[f"telemetry__{field}__{statistic}"] = value

            event_path = run_dir / "ebpf_events.csv"
            event_by_window: dict[str, Counter[str]] = defaultdict(Counter)
            if event_path.exists():
                for event in read_csv(event_path):
                    name = event.get("event", "").strip()
                    if name:
                        event_names.add(name)
                        event_by_window[event.get("window_id", "")][name] += 1
            row["_event_counts"] = event_by_window
            row["_window_ids"] = [str(window.get("window_id", "")) for window in telemetry_rows]

            if label:
                digest = Path(artifact).stem.lower()
                if not HASH_PATTERN.fullmatch(digest):
                    raise ValueError(f"Malware artifact is not SHA-256 named: {artifact}")
                label_row = labels[digest]
                row.update(
                    {
                        "sha256": digest,
                        "attack_type": label_row["attack_type"],
                        "family_label": label_row["family_label"],
                        "multiclass_label": label_row["attack_type"],
                        "package_group": f"malware::{label_row['attack_type']}",
                        "workload_family": label_row["family_label"],
                        "group_id": f"malware::{digest}",
                    }
                )
            else:
                manifest_row = manifest[artifact]
                row.update(
                    {
                        "sha256": manifest_row["sha256"],
                        "attack_type": "benign",
                        "family_label": "benign",
                        "multiclass_label": "benign",
                        "package_group": manifest_row["package"],
                        "workload_family": manifest_row["workload_family"],
                        "group_id": manifest_row["group_id"],
                    }
                )

            p4_features, p4_diagnostics, details = reconstruct_p4(
                run_dir, telemetry_rows, metadata
            )
            row.update(p4_features)
            diagnostics_rows.append({"sample_artifact": artifact, **p4_diagnostics})
            for detail in details:
                if "candidate" in detail:
                    candidate_rows.append(
                        {
                            "sample_artifact": artifact,
                            **detail["candidate"],
                        }
                    )
                else:
                    uncertainty_rows.append(
                        {
                            "sample_artifact": artifact,
                            **detail["uncertainty"],
                        }
                    )
            examples.append(row)
            status_counts[f"{label}:{row['run_status']}"] += 1
            if row["failure_reason"]:
                failure_reasons[f"{label}:{row['failure_reason']}"] += 1

    if not raw_signal_fields:
        raise ValueError("No telemetry signal fields found")
    for row in examples:
        event_counts = row.pop("_event_counts")
        window_ids = row.pop("_window_ids")
        for event_name in sorted(event_names):
            slug = re.sub(r"[^a-zA-Z0-9]+", "_", event_name).strip("_").lower()
            event_values = [
                float(event_counts.get(window_id, {}).get(event_name, 0))
                for window_id in window_ids
            ]
            for statistic, value in aggregate(event_values).items():
                row[f"event__{slug}__{statistic}"] = value
    return (
        examples,
        sorted(raw_signal_fields),
        sorted(event_names),
        diagnostics_rows,
        candidate_rows,
        uncertainty_rows,
        status_counts,
        failure_reasons,
    )


def multiclass_metrics(y_true, y_pred, probabilities, classes, model_classes) -> dict:
    supported_classes = sorted(set(y_true))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )
    supported_indices = [classes.index(name) for name in supported_classes]
    result = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_precision": float(np.mean(precision[supported_indices])),
        "macro_recall": float(np.mean(recall[supported_indices])),
        "macro_f1": float(np.mean(f1[supported_indices])),
        "weighted_f1": float(
            precision_recall_fscore_support(
                y_true, y_pred, labels=classes, average="weighted", zero_division=0
            )[2]
        ),
        "classes": classes,
        "validation_supported_classes": supported_classes,
        "confusion_matrix_labels": classes,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
        "per_class": {},
        "macro_ovr_roc_auc": None,
    }
    result["per_class"] = {
        class_name: {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
        }
        for index, class_name in enumerate(classes)
    }
    model_class_index = {name: index for index, name in enumerate(model_classes)}
    if len(supported_classes) > 1 and all(
        name in model_class_index for name in supported_classes
    ):
        selected_probabilities = probabilities[
            :, [model_class_index[name] for name in supported_classes]
        ]
        try:
            result["macro_ovr_roc_auc"] = float(
                roc_auc_score(
                    y_true,
                    selected_probabilities,
                    labels=supported_classes,
                    multi_class="ovr",
                    average="macro",
                )
            )
        except ValueError:
            pass
    return result


def evaluate(examples, feature_sets, output_dir: Path, seed: int, attack_train_fraction: float):
    labels_binary = np.asarray([int(row["label"]) for row in examples], dtype=int)
    labels_multiclass = np.asarray([str(row["multiclass_label"]) for row in examples])
    classes = sorted(set(labels_multiclass.tolist()))
    attack_types = sorted({row["attack_type"] for row in examples if row["label"] == 1})
    rng = np.random.default_rng(seed)
    training_indices: list[int] = []
    validation_indices: list[int] = []
    attack_counts = {}
    by_attack: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(examples):
        if row["label"] == 1:
            by_attack[str(row["attack_type"])].append(index)
    for attack_type in attack_types:
        indices = np.asarray(by_attack[attack_type], dtype=int)
        if not len(indices):
            continue
        shuffled = rng.permutation(indices)
        training_count = min(
            len(shuffled),
            max(1, math.ceil(len(shuffled) * attack_train_fraction)),
        )
        training_indices.extend(shuffled[:training_count].tolist())
        validation_indices.extend(shuffled[training_count:].tolist())
        attack_counts[attack_type] = {
            "total": len(shuffled),
            "training": training_count,
            "validation": len(shuffled) - training_count,
        }

    benign_indices = np.flatnonzero(labels_binary == 0)
    benign_groups = np.asarray([examples[index]["package_group"] for index in benign_indices])
    group_split = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed)
    benign_train_relative, benign_validation_relative = next(
        group_split.split(np.zeros(len(benign_indices)), groups=benign_groups)
    )
    benign_training = benign_indices[benign_train_relative]
    benign_validation = benign_indices[benign_validation_relative]
    training_indices.extend(benign_training.tolist())
    validation_indices.extend(benign_validation.tolist())
    training_indices.sort()
    validation_indices.sort()

    if set(training_indices) & set(validation_indices):
        raise RuntimeError("A sample appears in both training and validation")
    if len(training_indices) + len(validation_indices) != len(examples):
        raise RuntimeError("Split does not cover every sample exactly once")
    training_groups = {examples[index]["package_group"] for index in benign_training}
    validation_groups = {examples[index]["package_group"] for index in benign_validation}
    if training_groups & validation_groups:
        raise RuntimeError("Benign package groups cross the training/validation boundary")
    if set(labels_multiclass[training_indices]) != set(classes):
        raise RuntimeError("Training split does not contain every attack type and benign class")

    output_dir.mkdir(parents=True, exist_ok=True)
    models_dir = output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "evaluation": "2026-10-17 revision-4 cohort; sample-held-out malware; benign package-group holdout",
        "random_seed": seed,
        "attack_train_fraction_per_type": attack_train_fraction,
        "benign_package_group_test_fraction": 0.5,
        "benign_package_groups_disjoint": True,
        "samples": len(examples),
        "training_samples": len(training_indices),
        "validation_samples": len(validation_indices),
        "training_class_counts": dict(Counter(labels_multiclass[training_indices].tolist())),
        "validation_class_counts": dict(Counter(labels_multiclass[validation_indices].tolist())),
        "attack_type_split_counts": attack_counts,
        "benign_runs": {
            "total": len(benign_indices),
            "training": len(benign_training),
            "validation": len(benign_validation),
            "training_package_groups": len(training_groups),
            "validation_package_groups": len(validation_groups),
        },
        "models": {},
    }
    predictions = []
    for feature_set_name, feature_names in feature_sets.items():
        matrix = numeric_matrix(examples, feature_names)
        multiclass_model = make_model(seed)
        multiclass_model.fit(matrix[training_indices], labels_multiclass[training_indices])
        multiclass_probabilities = multiclass_model.predict_proba(matrix[validation_indices])
        multiclass_model_classes = [str(value) for value in multiclass_model[-1].classes_]
        multiclass_predictions = multiclass_model.predict(matrix[validation_indices])
        multiclass_report = multiclass_metrics(
            labels_multiclass[validation_indices],
            multiclass_predictions,
            multiclass_probabilities,
            classes,
            multiclass_model_classes,
        )
        joblib.dump(multiclass_model, models_dir / f"{feature_set_name}_multiclass.joblib")

        binary_model = make_model(seed)
        binary_model.fit(matrix[training_indices], labels_binary[training_indices])
        binary_all_probabilities = binary_model.predict_proba(matrix[validation_indices])
        binary_classes = [int(value) for value in binary_model[-1].classes_]
        malware_index = binary_classes.index(1)
        binary_probabilities = binary_all_probabilities[:, malware_index]
        binary_predictions = (binary_probabilities >= 0.5).astype(int)
        binary_report = metrics_for(
            labels_binary[validation_indices], binary_predictions, binary_probabilities
        )
        binary_report["per_attack_type_detection"] = {}
        for attack_type in attack_types:
            positions = [
                position
                for position, sample_index in enumerate(validation_indices)
                if examples[sample_index]["attack_type"] == attack_type
            ]
            detected = sum(int(binary_predictions[position] == 1) for position in positions)
            binary_report["per_attack_type_detection"][attack_type] = {
                "support": len(positions),
                "detected": detected,
                "missed": len(positions) - detected,
                "recall": detected / len(positions) if positions else None,
            }
        joblib.dump(binary_model, models_dir / f"{feature_set_name}_binary.joblib")
        report["models"][feature_set_name] = {
            "feature_count": len(feature_names),
            "binary_malware_detection": binary_report,
            "multiclass_attack_type": multiclass_report,
        }
        multiclass_class_index = {
            name: index for index, name in enumerate(multiclass_model_classes)
        }
        for position, sample_index in enumerate(validation_indices):
            true_type = str(labels_multiclass[sample_index])
            predicted_type = str(multiclass_predictions[position])
            predictions.append(
                {
                    "feature_set": feature_set_name,
                    "sample_artifact": examples[sample_index]["sample_artifact"],
                    "sha256": examples[sample_index]["sha256"],
                    "true_attack_type": true_type,
                    "predicted_attack_type": predicted_type,
                    "predicted_attack_type_probability": float(
                        multiclass_probabilities[
                            position, multiclass_class_index[predicted_type]
                        ]
                    ),
                    "multiclass_correct": int(true_type == predicted_type),
                    "true_binary_label": int(labels_binary[sample_index]),
                    "probability_malware": float(binary_probabilities[position]),
                    "binary_prediction": int(binary_predictions[position]),
                    "binary_correct": int(binary_predictions[position] == labels_binary[sample_index]),
                }
            )

    split_by_index = {index: "training" for index in training_indices}
    split_by_index.update({index: "validation" for index in validation_indices})
    assignments = [
        {
            "sample_artifact": row["sample_artifact"],
            "sha256": row["sha256"],
            "split": split_by_index[index],
            "binary_label": int(labels_binary[index]),
            "attack_type": row["attack_type"],
            "family_label": row["family_label"],
            "benign_package_group": row["package_group"] if row["label"] == 0 else "",
        }
        for index, row in enumerate(examples)
    ]
    write_csv(output_dir / "split_assignments.csv", assignments, list(assignments[0]))
    excluded_metadata = {"_event_counts"}
    sample_fields = [field for field in examples[0] if field not in excluded_metadata]
    write_csv(
        output_dir / "training_dataset.csv",
        [{**examples[index], "split": "training"} for index in training_indices],
        sample_fields + ["split"],
    )
    write_csv(
        output_dir / "validation_dataset.csv",
        [{**examples[index], "split": "validation"} for index in validation_indices],
        sample_fields + ["split"],
    )
    write_csv(output_dir / "validation_predictions.csv", predictions, list(predictions[0]))
    (output_dir / "metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malware-runs", type=Path, default=DEFAULT_MALWARE_RUNS)
    parser.add_argument("--benign-runs", type=Path, default=DEFAULT_BENIGN_RUNS)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--benign-manifest", type=Path, default=DEFAULT_BENIGN_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--attack-train-fraction", type=float, default=0.2)
    args = parser.parse_args(argv)
    if not 0 < args.attack_train_fraction < 0.5:
        parser.error("--attack-train-fraction must be greater than 0 and less than 0.5")

    (
        examples,
        raw_signals,
        event_names,
        diagnostics,
        candidate_rows,
        uncertainty_rows,
        status_counts,
        failure_reasons,
    ) = load_samples(
        args.malware_runs,
        args.benign_runs,
        args.labels,
        args.benign_manifest,
    )
    network_features = [
        f"telemetry__{field}__{statistic}"
        for field in raw_signals
        if field.startswith("net_")
        for statistic in STATISTICS
    ]
    host_features = [
        f"telemetry__{field}__{statistic}"
        for field in raw_signals
        if field.startswith(("host_", "ebpf_"))
        for statistic in STATISTICS
    ]
    host_features.extend(
        f"event__{re.sub(r'[^a-zA-Z0-9]+', '_', event).strip('_').lower()}__{statistic}"
        for event in event_names
        for statistic in STATISTICS
    )
    p4_features = list(p4_analyzer.P4_SAMPLE_FEATURES)
    feature_sets = {
        "net_telemetry": network_features,
        "ebpf_host": host_features,
        "p4_network": p4_features,
        "network_all": network_features + p4_features,
        "full_hybrid": network_features + p4_features + host_features,
    }
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_fields = [field for field in examples[0] if field != "_event_counts"]
    write_csv(output_dir / "sample_features.csv", examples, sample_fields)
    (output_dir / "feature_columns.json").write_text(
        json.dumps(feature_sets, indent=2) + "\n", encoding="utf-8"
    )
    diagnostics_fields = list(diagnostics[0])
    write_csv(output_dir / "p4_alignment_diagnostics.csv", diagnostics, diagnostics_fields)
    if candidate_rows:
        write_csv(
            output_dir / "p4_ambiguous_candidates.csv",
            candidate_rows,
            list(candidate_rows[0]),
        )
    if uncertainty_rows:
        write_csv(
            output_dir / "p4_feature_uncertainty.csv",
            uncertainty_rows,
            list(uncertainty_rows[0]),
        )

    report = evaluate(
        examples,
        feature_sets,
        output_dir,
        args.seed,
        args.attack_train_fraction,
    )
    report["cohort_sources"] = {
        "malware_runs": str(args.malware_runs.resolve()),
        "benign_runs": str(args.benign_runs.resolve()),
        "malware_hash_labels": str(args.labels.resolve()),
        "benign_workload_manifest": str(args.benign_manifest.resolve()),
    }
    report["sensor_coverage"] = {
        "numeric_telemetry_base_signals": raw_signals,
        "numeric_telemetry_signal_count": len(raw_signals),
        "ebpf_event_categories": event_names,
        "p4_sample_feature_count": len(p4_features),
        "p4_unique_alignments": sum(
            row["p4_reconstruction_method"] == "unique_packet_window_assignment"
            for row in diagnostics
        ),
        "p4_ambiguous_samples_marginalized": sum(
            row["p4_reconstruction_method"]
            == "duration_weighted_counter_consistent_assignments"
            for row in diagnostics
        ),
        "p4_candidate_assignment_count": len(candidate_rows),
    }
    report["collection_status_counts_label_status"] = dict(status_counts)
    report["nonempty_run_failure_reasons_label_reason"] = dict(failure_reasons)
    report["scoring_notes"] = [
        "All 521 malware and 500 benign runs with complete telemetry, PCAP, and eBPF files were included regardless of process exit status.",
        "Execution status and failure reason were retained as audit metadata and excluded from model features.",
        "P4 features for ambiguous packet-window alignments are duration-weighted over exact-counter-compatible assignments; uncertainty is exported separately.",
        "The backdoor attack type has one sample; it is assigned to training and therefore has no independent validation support.",
    ]
    (output_dir / "metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    print(f"Full-cohort results: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())