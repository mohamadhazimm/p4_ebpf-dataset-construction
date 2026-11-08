#!/usr/bin/env python3
"""Evaluate network, host, and hybrid models with simulation-augmented training."""

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


STUDY_DIR = Path(__file__).resolve().parents[1]
DEFAULT_P4_DATASET = (
    STUDY_DIR
    / "data/malware/revision4/full-cohort-feature-pool-20261016"
    / "p4_pcap_reconstructed_labeled_sample_dataset.csv"
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


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
        shuffled = rng.permutation(np.asarray(by_family[family], dtype=int))
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


def make_model(seed: int):
    return make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=500,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=-1,
        ),
    )


def classification_metrics(
    labels: np.ndarray, predictions: np.ndarray, probabilities: np.ndarray
) -> dict:
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


def detection_metrics(predictions: np.ndarray, probabilities: np.ndarray) -> dict:
    count = len(predictions)
    detected = int(np.count_nonzero(predictions == 1))
    return {
        "samples": count,
        "detected": detected,
        "missed": count - detected,
        "detection_rate": detected / count if count else None,
        "mean_probability_malware": float(np.mean(probabilities)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--scenario-dataset", type=Path, required=True)
    parser.add_argument("--feature-columns", type=Path)
    parser.add_argument("--scenario-feature-columns", type=Path)
    parser.add_argument("--p4-dataset", type=Path, default=DEFAULT_P4_DATASET)
    parser.add_argument("--p4-feature-columns", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--malware-train-fraction", type=float, default=0.10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if not 0 < args.malware_train_fraction < 0.5:
        parser.error("--malware-train-fraction must be between 0 and 0.5")

    feature_path = args.feature_columns or args.dataset.with_name(
        args.dataset.stem + ".feature_columns.json"
    )
    p4_feature_path = args.p4_feature_columns or args.p4_dataset.with_name(
        args.p4_dataset.stem + ".feature_columns.json"
    )
    scenario_feature_path = args.scenario_feature_columns or args.scenario_dataset.with_name(
        args.scenario_dataset.stem + ".feature_columns.json"
    )
    source_rows = load_csv(args.dataset)
    p4_rows = load_csv(args.p4_dataset)
    scenarios = load_csv(args.scenario_dataset)
    columns = load_features(feature_path)
    p4_columns = load_features(p4_feature_path)
    scenario_columns = load_features(scenario_feature_path)
    rows = [row for row in source_rows if int(row["label"]) == 1]
    benign_rows = [row for row in source_rows if int(row["label"]) == 0]
    labels = np.ones(len(rows), dtype=int)
    scenario_labels = np.asarray([int(row["label"]) for row in scenarios], dtype=int)
    if not rows or not benign_rows or set(scenario_labels) != {0, 1}:
        parser.error("Dataset must contain malware and benign samples; simulations must contain both labels")

    network_features = list(scenario_columns["network"])
    p4_rows_by_artifact = {row["sample_artifact"]: row for row in p4_rows}
    if len(p4_rows_by_artifact) != len(p4_rows):
        parser.error("P4 reconstruction dataset contains duplicate sample artifacts")
    missing_p4 = sorted(
        row["sample_artifact"]
        for row in source_rows
        if row["sample_artifact"] not in p4_rows_by_artifact
    )
    if missing_p4:
        parser.error(f"P4 reconstruction is missing malware artifacts: {missing_p4[:5]}")
    if not set(network_features).issubset(p4_columns["network"]):
        parser.error("Scenario P4 features are not all present in the reconstructed malware feature contract")
    malware_host_set = set(columns["host"])
    if not set(scenario_columns["host"]).issubset(malware_host_set):
        parser.error("Scenario host features are not all present in the malware feature contract")
    host_features = list(scenario_columns["host"])
    if len(host_features) != len(set(host_features)):
        parser.error("Scenario host feature list contains duplicate columns")

    malware_training, malware_unknown, family_counts = split_malware_by_family(
        rows, labels, args.malware_train_fraction, args.seed
    )
    benign_groups = np.asarray([row["package_group"] for row in benign_rows], dtype=str)
    benign_split = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=args.seed)
    benign_training, benign_unknown = next(
        benign_split.split(np.zeros(len(benign_rows)), groups=benign_groups)
    )
    benign_train_groups = set(benign_groups[benign_training])
    benign_test_groups = set(benign_groups[benign_unknown])
    if benign_train_groups & benign_test_groups:
        raise RuntimeError("Benign package groups crossed the train/test boundary")

    malware_p4_rows = [p4_rows_by_artifact[row["sample_artifact"]] for row in rows]
    benign_p4_rows = [p4_rows_by_artifact[row["sample_artifact"]] for row in benign_rows]
    malware_network = numeric_matrix(malware_p4_rows, network_features)
    malware_host = numeric_matrix(rows, host_features)
    benign_network = numeric_matrix(benign_p4_rows, network_features)
    benign_host = numeric_matrix(benign_rows, host_features)
    scenario_network = numeric_matrix(scenarios, network_features)
    scenario_host = numeric_matrix(scenarios, host_features)
    matrices = {
        "network": (malware_network, benign_network, scenario_network, network_features),
        "host": (malware_host, benign_host, scenario_host, host_features),
        "hybrid": (
            np.hstack((malware_network, malware_host)),
            np.hstack((benign_network, benign_host)),
            np.hstack((scenario_network, scenario_host)),
            network_features + host_features,
        ),
    }

    reports = {}
    prediction_rows = []
    family_reports = {}
    model_dir = args.output_dir / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    for model_index, (
        model_name,
        (malware_matrix, benign_matrix, scenario_matrix, features),
    ) in enumerate(matrices.items()):
        training_matrix = np.vstack(
            (
                malware_matrix[malware_training],
                benign_matrix[benign_training],
                scenario_matrix,
            )
        )
        training_labels = np.concatenate(
            (
                labels[malware_training],
                np.zeros(len(benign_training), dtype=int),
                scenario_labels,
            )
        )
        test_matrix = np.vstack((malware_matrix[malware_unknown], benign_matrix[benign_unknown]))
        test_labels = np.concatenate(
            (np.ones(len(malware_unknown), dtype=int), np.zeros(len(benign_unknown), dtype=int))
        )
        model = make_model(args.seed + model_index)
        model.fit(training_matrix, training_labels)
        probabilities = model.predict_proba(test_matrix)[:, 1]
        predictions = (probabilities >= 0.5).astype(int)
        malware_test_count = len(malware_unknown)
        benign_predictions = predictions[malware_test_count:]
        benign_false_positives = int(np.count_nonzero(benign_predictions == 1))
        reports[model_name] = {
            "feature_count": len(features),
            "test_metrics": classification_metrics(test_labels, predictions, probabilities),
            "unknown_malware_test_metrics": detection_metrics(
                predictions[:malware_test_count], probabilities[:malware_test_count]
            ),
            "heldout_real_benign_test_metrics": {
                "samples": len(benign_unknown),
                "false_positives": benign_false_positives,
                "true_negatives": len(benign_unknown) - benign_false_positives,
                "false_positive_rate": benign_false_positives / len(benign_unknown),
            },
            "training_label_counts": {
                str(label): int(count)
                for label, count in sorted(Counter(training_labels).items())
            },
        }

        model_families = {}
        for family, split in sorted(family_counts.items()):
            family_positions = [
                position
                for position, row_index in enumerate(malware_unknown)
                if (rows[row_index].get("workload_family") or "unassigned") == family
            ]
            detected = int(np.count_nonzero(predictions[family_positions] == 1))
            model_families[family] = {
                **split,
                "training_fraction_actual": split["training"] / split["total"],
                "family_seen_in_training": split["training"] > 0,
                "detected": detected,
                "missed": len(family_positions) - detected,
                "detection_rate": detected / len(family_positions)
                if family_positions
                else None,
            }
        family_reports[model_name] = model_families

        for position, row_index in enumerate(malware_unknown):
            row = rows[row_index]
            family = row.get("workload_family") or "unassigned"
            prediction_rows.append(
                {
                    "model": model_name,
                    "sample_artifact": row["sample_artifact"],
                    "sample_role": "unknown_malware",
                    "malware_family": family,
                    "family_seen_in_training": int(family_counts[family]["training"] > 0),
                    "label_for_evaluation_only": 1,
                    "probability_malware": float(probabilities[position]),
                    "prediction": int(predictions[position]),
                }
            )
        for position, row_index in enumerate(benign_unknown):
            row = benign_rows[row_index]
            test_position = malware_test_count + position
            prediction_rows.append(
                {
                    "model": model_name,
                    "sample_artifact": row["sample_artifact"],
                    "sample_role": "heldout_benign",
                    "malware_family": "",
                    "family_seen_in_training": "",
                    "label_for_evaluation_only": 0,
                    "probability_malware": float(probabilities[test_position]),
                    "prediction": int(predictions[test_position]),
                }
            )
        joblib.dump(
            {
                "model": model,
                "feature_names": features,
                "positive_label": "malware_or_attack_simulation",
                "threshold": 0.5,
                "seed": args.seed + model_index,
            },
            model_dir / f"{model_name}_sim_augmented_10pct.joblib",
        )

    training_attack_count = int(np.count_nonzero(scenario_labels == 1))
    training_control_count = int(np.count_nonzero(scenario_labels == 0))
    malware_total = int(np.count_nonzero(labels == 1))
    source_p4_rows = [p4_rows_by_artifact[row["sample_artifact"]] for row in source_rows]
    report = {
        "evaluation": "train on family-stratified malware, real benign training groups, and all self-generated simulations; test on remaining malware and held-out real benign groups",
        "seed": args.seed,
        "malware_train_fraction_requested": args.malware_train_fraction,
        "malware_training_fraction_actual": len(malware_training) / malware_total,
        "malware_samples_total": malware_total,
        "malware_training_samples": len(malware_training),
        "unknown_malware_test_samples": len(malware_unknown),
        "real_benign_samples_total": len(benign_rows),
        "real_benign_training_samples": len(benign_training),
        "real_benign_test_samples": len(benign_unknown),
        "benign_training_package_groups": len(benign_train_groups),
        "benign_test_package_groups": len(benign_test_groups),
        "benign_package_groups_disjoint": True,
        "malware_family_split_rule": (
            "For families with at least two samples, train max(1, floor(fraction*n)) "
            "while retaining at least one test sample. Singleton families are test-only."
        ),
        "malware_family_counts": family_counts,
        "simulation_training_samples": len(scenarios),
        "simulation_training_label_counts": {
            "attack_simulation": training_attack_count,
            "benign_control": training_control_count,
        },
        "training_samples_total": len(malware_training) + len(benign_training) + len(scenarios),
        "test_samples_total": len(malware_unknown) + len(benign_unknown),
        "test_contains_only_malware": False,
        "test_label_counts": {
            "malware": len(malware_unknown),
            "real_benign": len(benign_unknown),
        },
        "accuracy_interpretation": "Binary metrics use remaining malware and package-disjoint real benign test samples.",
        "false_positive_rate_available": True,
        "p4_reconstruction": {
            "source": "existing full-cohort P4 reconstruction; ambiguous packet/window assignments are duration-weighted over counter-consistent possibilities",
            "reconstruction_dataset": str(args.p4_dataset.resolve()),
            "real_samples_with_reconstructed_features": len(source_p4_rows),
            "reconstruction_methods": {
                method: int(count)
                for method, count in Counter(
                    row.get("p4_reconstruction_method", "unspecified")
                    for row in source_p4_rows
                ).items()
            },
            "network_feature_count": len(network_features),
        },
        "shared_host_feature_count": len(host_features),
        "models": reports,
        "per_family_test_metrics": family_reports,
        "malware_dataset": str(args.dataset.resolve()),
        "p4_dataset": str(args.p4_dataset.resolve()),
        "scenario_dataset": str(args.scenario_dataset.resolve()),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "simulated_models_10pct_metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(
        args.output_dir / "simulated_models_10pct_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )
    assignments = []
    training_set = set(malware_training.tolist())
    test_set = set(malware_unknown.tolist())
    for index, row in enumerate(rows):
        family = row.get("workload_family") or "unassigned"
        assignments.append(
            {
                "source": "malware_dataset",
                "sample_artifact": row["sample_artifact"],
                "label": int(labels[index]),
                "malware_family": family,
                "role": "malware_train_10pct" if index in training_set else "unknown_malware_test",
                "family_seen_in_training": int(family_counts[family]["training"] > 0),
                "package_group": "",
            }
        )
    benign_train_set = set(benign_training.tolist())
    for index, row in enumerate(benign_rows):
        assignments.append(
            {
                "source": "real_benign_dataset",
                "sample_artifact": row["sample_artifact"],
                "label": 0,
                "malware_family": "",
                "role": "real_benign_train" if index in benign_train_set else "heldout_real_benign_test",
                "family_seen_in_training": "",
                "package_group": row["package_group"],
            }
        )
    for row, label in zip(scenarios, scenario_labels, strict=True):
        assignments.append(
            {
                "source": "self_generated_simulation",
                "sample_artifact": row["sample_artifact"],
                "label": int(label),
                "malware_family": "",
                "role": "simulation_train",
                "family_seen_in_training": "",
                "package_group": "",
            }
        )
    write_csv(
        args.output_dir / "simulated_models_10pct_assignments.csv",
        assignments,
        list(assignments[0]),
    )
    p4_join_audit = [
        {
            "sample_artifact": row["sample_artifact"],
            "p4_reconstruction_method": p4_row.get("p4_reconstruction_method", ""),
            "p4_candidate_assignment_count": p4_row.get("p4_candidate_assignment_count", ""),
            "p4_feasible_offset_duration_seconds": p4_row.get(
                "p4_feasible_offset_duration_seconds", ""
            ),
        }
        for row, p4_row in zip(source_rows, source_p4_rows, strict=True)
    ]
    write_csv(
        args.output_dir / "malware_p4_reconstruction_join.csv",
        p4_join_audit,
        list(p4_join_audit[0]),
    )
    print(json.dumps(report, indent=2))
    print(f"Results written to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())