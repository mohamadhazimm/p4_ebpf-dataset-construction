#!/usr/bin/env python3
"""Train an eBPF host detector with simulated scenarios and 10% of each family."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def load_features(path: Path) -> dict[str, list[str]]:
    return json.loads(path.read_text(encoding="utf-8"))


def numeric_matrix(rows: list[dict[str, str]], features: list[str]) -> np.ndarray:
    matrix = np.full((len(rows), len(features)), np.nan, dtype=float)
    for row_index, row in enumerate(rows):
        for column_index, feature in enumerate(features):
            value = row.get(feature, "")
            if value != "":
                try:
                    matrix[row_index, column_index] = float(value)
                except ValueError:
                    pass
    return matrix


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def split_malware_by_family(
    rows: list[dict[str, str]], labels: np.ndarray, fraction: float, seed: int
) -> tuple[np.ndarray, np.ndarray, dict[str, dict[str, int]]]:
    by_family: dict[str, list[int]] = defaultdict(list)
    for index in np.flatnonzero(labels == 1):
        by_family[rows[index].get("workload_family") or "unassigned"].append(int(index))

    rng = np.random.default_rng(seed)
    training: list[int] = []
    unknown: list[int] = []
    counts = {}
    for family in sorted(by_family):
        indices = np.asarray(by_family[family], dtype=int)
        shuffled = rng.permutation(indices)
        training_count = (
            min(len(shuffled) - 1, max(1, math.floor(len(shuffled) * fraction)))
            if len(shuffled) > 1
            else 0
        )
        training.extend(shuffled[:training_count].tolist())
        unknown.extend(shuffled[training_count:].tolist())
        counts[family] = {
            "total": len(shuffled),
            "training": training_count,
            "unknown_test": len(shuffled) - training_count,
        }
    return np.asarray(sorted(training)), np.asarray(sorted(unknown)), counts


def metrics_for(labels: np.ndarray, predictions: np.ndarray, probabilities: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def detection_metrics(predictions: np.ndarray) -> dict[str, int | float | None]:
    count = len(predictions)
    detected = int(np.count_nonzero(predictions == 1))
    return {
        "samples": count,
        "detected": detected,
        "missed": count - detected,
        "detection_rate": detected / count if count else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--scenario-dataset", required=True, type=Path)
    parser.add_argument("--feature-columns", type=Path)
    parser.add_argument("--scenario-feature-columns", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--malware-train-fraction", type=float, default=0.10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if not 0 < args.malware_train_fraction < 0.5:
        parser.error("--malware-train-fraction must be between 0 and 0.5")

    feature_path = args.feature_columns or args.dataset.with_name(
        args.dataset.stem + ".feature_columns.json"
    )
    scenario_feature_path = args.scenario_feature_columns or args.scenario_dataset.with_name(
        args.scenario_dataset.stem + ".feature_columns.json"
    )
    rows = load_csv(args.dataset)
    scenarios = load_csv(args.scenario_dataset)
    columns = load_features(feature_path)
    scenario_columns = load_features(scenario_feature_path)
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    scenario_labels = np.asarray([int(row["label"]) for row in scenarios], dtype=int)
    if set(labels) != {0, 1} or set(scenario_labels) != {0, 1}:
        parser.error("Both datasets must contain label 0 and label 1")

    malware_host = columns["host"]
    scenario_host = scenario_columns["host"]
    if not set(scenario_host).issubset(malware_host):
        parser.error("Scenario host features are not all present in the malware feature contract")
    features = [feature for feature in malware_host if feature in set(scenario_host)]
    feature_families: dict[str, set[str]] = defaultdict(set)
    for feature in features:
        signal, separator, summary = feature.rpartition("__")
        if not separator:
            parser.error(f"Host feature lacks a summary suffix: {feature}")
        feature_families[signal].add(summary)
    if not feature_families or any(len(summaries) != 5 for summaries in feature_families.values()):
        parser.error("Shared host features must have five summaries per eBPF signal family")

    malware_training, malware_unknown, family_counts = split_malware_by_family(
        rows, labels, args.malware_train_fraction, args.seed
    )
    benign_indices = np.flatnonzero(labels == 0)
    package_groups = np.asarray([row.get("package_group", "") for row in rows], dtype=str)
    benign_split = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=args.seed)
    benign_train_relative, benign_test_relative = next(
        benign_split.split(benign_indices, groups=package_groups[benign_indices])
    )
    benign_training = benign_indices[benign_train_relative]
    benign_test = benign_indices[benign_test_relative]
    train_groups = set(package_groups[benign_training])
    test_groups = set(package_groups[benign_test])
    if train_groups & test_groups:
        raise RuntimeError("Benign package groups crossed the train/test boundary")

    malware_matrix = numeric_matrix(rows, features)
    scenario_matrix = numeric_matrix(scenarios, features)
    train_matrix = np.vstack(
        (malware_matrix[malware_training], malware_matrix[benign_training], scenario_matrix)
    )
    train_labels = np.concatenate(
        (labels[malware_training], labels[benign_training], scenario_labels)
    )
    test_indices = np.concatenate((malware_unknown, benign_test))
    test_matrix = malware_matrix[test_indices]
    test_labels = labels[test_indices]
    if set(train_labels) != {0, 1} or set(test_labels) != {0, 1}:
        parser.error("Combined train and test partitions must each contain both classes")

    model = make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=500,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=args.seed,
            n_jobs=-1,
        ),
    )
    model.fit(train_matrix, train_labels)
    probabilities = model.predict_proba(test_matrix)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)

    malware_test_mask = labels[test_indices] == 1
    seen_family_counts = {family: split["training"] > 0 for family, split in family_counts.items()}
    malware_test_seen_mask = np.asarray(
        [
            is_malware
            and seen_family_counts[rows[index].get("workload_family") or "unassigned"]
            for index, is_malware in zip(test_indices, malware_test_mask, strict=True)
        ],
        dtype=bool,
    )
    malware_test_unseen_mask = malware_test_mask & ~malware_test_seen_mask
    family_metrics = {}
    for family, split in sorted(family_counts.items()):
        family_indices = [
            position
            for position, dataset_index in enumerate(test_indices)
            if labels[dataset_index] == 1
            and (rows[dataset_index].get("workload_family") or "unassigned") == family
        ]
        detected = int(sum(predictions[position] == 1 for position in family_indices))
        family_metrics[family] = {
            **split,
            "training_fraction_actual": split["training"] / split["total"],
            "family_seen_in_training": seen_family_counts[family],
            "detected": detected,
            "missed": len(family_indices) - detected,
            "recall": detected / len(family_indices) if family_indices else None,
        }

    report = {
        "evaluation": "host-only; all v7 simulations plus family-stratified malware training",
        "seed": args.seed,
        "malware_train_fraction_requested": args.malware_train_fraction,
        "malware_training_fraction_actual": len(malware_training)
        / int(np.count_nonzero(labels == 1)),
        "malware_dataset": str(args.dataset.resolve()),
        "scenario_dataset": str(args.scenario_dataset.resolve()),
        "feature_count": len(features),
        "shared_host_signal_families": len(feature_families),
        "host_features": features,
        "malware_samples": len(np.flatnonzero(labels == 1)),
        "malware_training_samples": len(malware_training),
        "unknown_malware_test_samples": len(malware_unknown),
        "malware_test_family_seen_count": int(
            sum(
                seen_family_counts[rows[index].get("workload_family") or "unassigned"]
                for index in malware_unknown
            )
        ),
        "malware_test_unseen_family_count": int(
            sum(
                not seen_family_counts[rows[index].get("workload_family") or "unassigned"]
                for index in malware_unknown
            )
        ),
        "real_benign_training_samples": len(benign_training),
        "real_benign_test_samples": len(benign_test),
        "benign_package_groups_disjoint": True,
        "simulation_training_samples": len(scenarios),
        "simulation_training_label_counts": {
            str(label): int(count) for label, count in sorted(Counter(scenario_labels).items())
        },
        "training_samples_total": len(train_labels),
        "test_samples_total": len(test_labels),
        "test_metrics": metrics_for(test_labels, predictions, probabilities),
        "unknown_malware_metrics": detection_metrics(predictions[malware_test_mask]),
        "unknown_malware_seen_family_metrics": detection_metrics(
            predictions[malware_test_seen_mask]
        ),
        "unknown_malware_unseen_family_metrics": detection_metrics(
            predictions[malware_test_unseen_mask]
        ),
        "malware_family_split_rule": (
            "For families with at least two samples, train max(1, floor(fraction*n)) "
            "while retaining at least one test sample. Singleton families are test-only."
        ),
        "malware_family_counts": family_metrics,
        "simulations_are_training_only": True,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "host_sim_augmented_10pct_metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    prediction_rows = []
    for position, dataset_index in enumerate(test_indices):
        row = rows[dataset_index]
        is_malware = labels[dataset_index] == 1
        family = (row.get("workload_family") or "unassigned") if is_malware else ""
        prediction_rows.append(
            {
                "sample_artifact": row.get("sample_artifact", ""),
                "sample_role": "unknown_malware" if is_malware else "heldout_benign",
                "malware_family": family,
                "family_seen_in_training": int(seen_family_counts[family]) if is_malware else "",
                "label_for_evaluation_only": int(test_labels[position]),
                "probability_malware": float(probabilities[position]),
                "prediction": int(predictions[position]),
            }
        )
    write_csv(
        args.output_dir / "host_sim_augmented_10pct_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )

    assignments = []
    malware_train_set = set(malware_training.tolist())
    malware_test_set = set(malware_unknown.tolist())
    benign_train_set = set(benign_training.tolist())
    benign_test_set = set(benign_test.tolist())
    for index, row in enumerate(rows):
        is_malware = labels[index] == 1
        family = (row.get("workload_family") or "unassigned") if is_malware else ""
        role = (
            "malware_train_10pct"
            if index in malware_train_set
            else "unknown_malware_test"
            if index in malware_test_set
            else "real_benign_train"
            if index in benign_train_set
            else "heldout_benign_test"
        )
        assignments.append(
            {
                "source": "malware_dataset",
                "sample_artifact": row.get("sample_artifact", ""),
                "label": int(labels[index]),
                "malware_family": family,
                "role": role,
                "family_seen_in_training": int(seen_family_counts[family]) if is_malware else "",
            }
        )
    for row, label in zip(scenarios, scenario_labels, strict=True):
        assignments.append(
            {
                "source": "simulated_scenario",
                "sample_artifact": row.get("sample_artifact", ""),
                "label": int(label),
                "malware_family": "",
                "role": "simulation_train",
                "family_seen_in_training": "",
            }
        )
    write_csv(
        args.output_dir / "host_sim_augmented_10pct_assignments.csv",
        assignments,
        list(assignments[0]),
    )
    joblib.dump(
        {
            "model": model,
            "feature_names": features,
            "positive_label": "malware_or_attack_simulation",
            "threshold": 0.5,
            "seed": args.seed,
        },
        args.output_dir / "host_sim_augmented_10pct.joblib",
    )
    print(json.dumps(report, indent=2))
    print(f"Results written to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())