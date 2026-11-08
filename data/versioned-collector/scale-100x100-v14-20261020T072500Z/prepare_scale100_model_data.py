#!/usr/bin/env python3
"""Build sample-level, family-grouped data from the validated scale-100x100 run."""

from __future__ import annotations

import csv
import json
import math
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

EXPERIMENT = Path(__file__).resolve().parent
STUDY_DIR = EXPERIMENT.parents[2]
SCHEMA = "2026-10-19.14"
RUNNER_SHA256 = "b366c337481e82e3118038ac966f3b35d5a5195123213a763a5ba2a8b1bf09d9"
NETWORK_GROUPS = ("network_runtime", "p4_network", "pcap_network_extras")
FOLDS = 5
SEED = 42

sys.path.insert(0, str(STUDY_DIR / "src"))
from build_dataset import STATISTICS, aggregate


def read_names(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_status(path: Path) -> str:
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("status="):
            return line.partition("=")[2].strip()
    return "unknown"


def load_family_maps() -> tuple[dict[str, str], dict[str, str]]:
    selection = json.loads((EXPERIMENT / "selection.json").read_text(encoding="utf-8"))
    malware_families = {row["sample"]: row["family"] for row in selection["malware"]}
    benign_families = {row["sample"]: row["family"] for row in selection["benign"]}
    for filename in ("continuation_selection.json", "completion_selection.json"):
        replacement = json.loads((EXPERIMENT / filename).read_text(encoding="utf-8"))
        malware_families.pop(replacement["replaced_sample"]["sample"])
        malware_families[replacement["replacement_sample"]["sample"]] = replacement[
            "replacement_sample"
        ]["family"]
    return malware_families, benign_families


def load_sample(
    cohort: str,
    sample: str,
    family: str,
    label: int,
    expected_groups: dict[str, list[str]] | None,
) -> tuple[dict[str, object] | None, dict[str, list[str]], dict[str, str] | None]:
    sample_dir = EXPERIMENT / "runs" / cohort / sample
    host_log = sample_dir / "host_run.txt"
    if not host_log.is_file() or read_status(host_log) != "completed":
        raise ValueError(f"{cohort}/{sample}: retrieval is not completed")
    run_paths = list((sample_dir / "output").rglob("run.json"))
    if len(run_paths) != 1:
        raise ValueError(f"{cohort}/{sample}: expected one run.json, found {len(run_paths)}")
    run_path = run_paths[0]
    metadata = json.loads(run_path.read_text(encoding="utf-8"))
    if metadata.get("telemetry_schema_version") != SCHEMA:
        raise ValueError(f"{cohort}/{sample}: schema mismatch")
    if metadata.get("malware_runner_sha256") != RUNNER_SHA256:
        raise ValueError(f"{cohort}/{sample}: runner hash mismatch")

    feature_groups = metadata.get("telemetry_feature_groups")
    if not isinstance(feature_groups, dict):
        raise ValueError(f"{cohort}/{sample}: missing feature groups")
    if expected_groups is not None and feature_groups != expected_groups:
        raise ValueError(f"{cohort}/{sample}: feature-group schema mismatch")
    features = [feature for values in feature_groups.values() for feature in values]
    if len(features) != 169 or len(set(features)) != 169:
        raise ValueError(f"{cohort}/{sample}: expected 169 unique telemetry features")

    if metadata.get("collection_quality_status") != "accepted":
        return None, feature_groups, metadata.get("collection_quality_reasons")

    telemetry_path = run_path.parent / "telemetry.csv"
    with telemetry_path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        rows = list(reader)
        columns = reader.fieldnames or []
    if len(rows) != 40 or any(feature not in columns for feature in features):
        raise ValueError(f"{cohort}/{sample}: telemetry shape/columns mismatch")
    window_ids = [row.get("window_id", "") for row in rows]
    if len(set(window_ids)) != len(rows):
        raise ValueError(f"{cohort}/{sample}: duplicate telemetry window IDs")

    example: dict[str, object] = {
        "sample_artifact": sample,
        "label": label,
        "class_name": "malware" if label else "benign",
        "group_id": f"{'malware' if label else 'benign'}::{family}",
        "family": family,
        "run_id": metadata.get("run_id", ""),
        "return_code": metadata.get("return_code"),
        "sample_artifact_type": metadata.get("sample_artifact_type", ""),
        "window_count": len(rows),
        "collection_quality_status": metadata["collection_quality_status"],
    }
    for feature in features:
        try:
            values = [float(row[feature]) for row in rows]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{cohort}/{sample}: nonnumeric {feature}") from error
        if not all(math.isfinite(value) for value in values):
            raise ValueError(f"{cohort}/{sample}: nonfinite {feature}")
        for statistic, value in aggregate(values).items():
            example[f"{feature}__{statistic}"] = value
    return example, feature_groups, None


def class_counts(labels: np.ndarray, indices: np.ndarray) -> dict[str, int]:
    return {
        "benign": int(np.count_nonzero(labels[indices] == 0)),
        "malware": int(np.count_nonzero(labels[indices] == 1)),
    }


def main() -> int:
    malware_names = read_names(EXPERIMENT / "manifests/malware-100-completion.txt")
    benign_names = read_names(EXPERIMENT / "manifests/benign-100.txt")
    malware_families, benign_families = load_family_maps()
    if len(malware_names) != 100 or len(set(malware_names)) != 100:
        raise ValueError("Final malware manifest must contain 100 unique samples")
    if set(malware_names) != set(malware_families):
        raise ValueError("Final malware manifest and replacement-adjusted family map differ")
    if len(benign_names) != 100 or len(set(benign_names)) != 100:
        raise ValueError("Benign manifest must contain 100 unique samples")
    if set(benign_names) != set(benign_families):
        raise ValueError("Benign manifest and family map differ")

    output_dir = EXPERIMENT / "modeling"
    output_dir.mkdir(parents=True, exist_ok=True)
    examples = []
    excluded = []
    schema_groups = None
    for cohort, names, family_map, label in (
        ("malware", malware_names, malware_families, 1),
        ("benign", benign_names, benign_families, 0),
    ):
        for sample in names:
            example, groups, rejection_reasons = load_sample(
                cohort, sample, family_map[sample], label, schema_groups
            )
            if schema_groups is None:
                schema_groups = groups
            if example is None:
                excluded.append(
                    {"sample": sample, "cohort": cohort, "reasons": rejection_reasons}
                )
            else:
                examples.append(example)

    labels = np.asarray([int(row["label"]) for row in examples], dtype=int)
    groups = np.asarray([str(row["group_id"]) for row in examples], dtype=str)
    if Counter(labels.tolist()) != Counter({0: 100, 1: 98}):
        raise ValueError(f"Unexpected accepted class counts: {dict(Counter(labels.tolist()))}")

    network_base = [
        feature
        for group_name in NETWORK_GROUPS
        for feature in schema_groups[group_name]
    ]
    host_base = [
        feature
        for group_name, feature_names in schema_groups.items()
        if group_name not in NETWORK_GROUPS
        for feature in feature_names
    ]
    if len(network_base) != 66 or len(host_base) != 103:
        raise ValueError("Unexpected network/host feature partition")
    feature_columns = {
        name: [f"{feature}__{statistic}" for feature in base for statistic in STATISTICS]
        for name, base in (("network", network_base), ("host", host_base))
    }
    feature_columns["hybrid"] = feature_columns["network"] + feature_columns["host"]
    reserved = {"sample_artifact", "label", "class_name", "group_id", "family"}
    if reserved.intersection(feature_columns["hybrid"]):
        raise ValueError("Metadata fields leaked into model feature columns")

    splits = list(
        StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED).split(
            np.zeros((len(labels), 1)), labels, groups
        )
    )
    fold_audit = []
    fold_by_sample: dict[str, int] = {}
    for fold_number, (train_indices, validation_indices) in enumerate(splits, start=1):
        train_groups = set(groups[train_indices])
        validation_groups = set(groups[validation_indices])
        if train_groups.intersection(validation_groups):
            raise ValueError(f"Fold {fold_number}: family group crosses train/validation")
        if set(labels[validation_indices]) != {0, 1}:
            raise ValueError(f"Fold {fold_number}: validation lacks one class")
        if set(labels[train_indices]) != {0, 1}:
            raise ValueError(f"Fold {fold_number}: training lacks one class")
        for index in validation_indices:
            fold_by_sample[str(examples[index]["sample_artifact"])] = fold_number
        fold_audit.append(
            {
                "fold": fold_number,
                "train_samples": len(train_indices),
                "validation_samples": len(validation_indices),
                "train_class_counts": class_counts(labels, train_indices),
                "validation_class_counts": class_counts(labels, validation_indices),
                "train_groups": len(train_groups),
                "validation_groups": len(validation_groups),
                "validation_group_ids": sorted(validation_groups),
            }
        )
    if len(fold_by_sample) != len(examples):
        raise ValueError("Every accepted sample must appear in exactly one validation fold")

    for example in examples:
        example["validation_fold"] = fold_by_sample[str(example["sample_artifact"])]
    dataset_path = output_dir / "accepted_sample_dataset.csv"
    with dataset_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(examples[0]))
        writer.writeheader()
        writer.writerows(examples)
    feature_path = output_dir / "accepted_sample_dataset.feature_columns.json"
    feature_path.write_text(json.dumps(feature_columns, indent=2) + "\n", encoding="utf-8")
    split_path = output_dir / "split_audit.json"
    split_path.write_text(
        json.dumps(
            {
                "strategy": "StratifiedGroupKFold",
                "folds": FOLDS,
                "seed": SEED,
                "grouping": "malware signature family and benign tool family; class-prefixed",
                "no_group_crosses_train_validation": True,
                "fold_assignments": fold_audit,
                "out_of_fold_sample_count": len(fold_by_sample),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    summary = {
        "schema_version": SCHEMA,
        "runner_sha256": RUNNER_SHA256,
        "accepted_samples": {"benign": int(np.count_nonzero(labels == 0)), "malware": int(np.count_nonzero(labels == 1))},
        "excluded_quality_rejections": excluded,
        "unique_groups": {
            "benign": len({str(row["group_id"]) for row in examples if row["label"] == 0}),
            "malware": len({str(row["group_id"]) for row in examples if row["label"] == 1}),
        },
        "base_features": {"network": len(network_base), "host": len(host_base)},
        "aggregated_features": {name: len(columns) for name, columns in feature_columns.items()},
        "telemetry_aggregation": list(STATISTICS),
        "dataset": dataset_path.name,
        "feature_columns": feature_path.name,
        "split_audit": split_path.name,
        "folds": fold_audit,
        "model_input_excludes": ["sample_artifact", "label", "class_name", "group_id", "family", "run_id", "return_code", "sample_artifact_type", "window_count", "collection_quality_status", "validation_fold"],
        "limitations": [
            "Exploratory cohort discrimination only; not a general malware detector estimate.",
            "Malware ELF artifacts and shell-driven benign scripts have different launch/artifact contexts.",
            "Family grouping prevents family overlap but does not remove workload, duration, or activity confounding.",
            "Network/P4-shaped fields are collected telemetry, not live P4 hardware measurements.",
        ],
    }
    summary_path = output_dir / "dataset_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: summary[key] for key in ("accepted_samples", "excluded_quality_rejections", "unique_groups", "base_features", "aggregated_features", "dataset", "feature_columns", "split_audit")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
