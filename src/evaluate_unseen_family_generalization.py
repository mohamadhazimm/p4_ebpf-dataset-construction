#!/usr/bin/env python3
"""Evaluate malware detection on families held out across all data sources."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupKFold

from compare_simulation_augmentation import (
    host_signal_indices,
    make_model,
    metrics_at_threshold,
    select_balanced_projection,
)
from evaluate_simulated_models_10pct import load_csv, load_features, numeric_matrix, write_csv


STUDY_DIR = Path(__file__).resolve().parents[1]
DATASET = (
    STUDY_DIR
    / "data/malware/revision4/full-cohort-feature-pool-20261016"
    / "p4_pcap_reconstructed_labeled_sample_dataset.csv"
)
FEATURE_COLUMNS = DATASET.with_name(DATASET.stem + ".feature_columns.json")
MALWAREBAZAAR_INVENTORY = (
    STUDY_DIR / "data/malware/malware_sample_inventory_all_expansions_20261014.csv"
)
TRIAGE_INVENTORY = (
    STUDY_DIR
    / "data/malware/revision4/triage-incoming/triage_sample_inventory_20261016.csv"
)
DEFAULT_OUTPUT = DATASET.parent / "unseen_family_group_cv_20261016"
SOURCE_CATEGORIES = ("MalwareBazaar", "Triage", "MalwareBazaar+Triage")


def normalize_artifact(value: str) -> str:
    return value.strip().lower().removesuffix(".zip").removesuffix(".elf")


def normalize_family(value: str) -> str:
    return value.strip().casefold() or "unassigned"


def load_source_inventory() -> tuple[dict[str, set[str]], dict[str, dict[str, str]], dict[str, int]]:
    source_map: dict[str, set[str]] = defaultdict(set)
    family_map: dict[str, dict[str, str]] = defaultdict(dict)
    included_counts = {}
    inventories = (
        ("MalwareBazaar", MALWAREBAZAAR_INVENTORY, "included_in_expanded_family_grouped_model"),
        ("Triage", TRIAGE_INVENTORY, "included_in_model"),
    )
    for source_name, path, include_field in inventories:
        records = load_csv(path)
        included = [record for record in records if record.get(include_field, "").lower() == "yes"]
        included_counts[source_name] = len(included)
        for record in included:
            artifact = normalize_artifact(record.get("sha256") or record.get("sample_artifact", ""))
            if not artifact:
                continue
            source_map[artifact].add(source_name)
            family_map[artifact][source_name] = normalize_family(record.get("malware_family", ""))
    return dict(source_map), dict(family_map), included_counts


def source_category(sources: set[str]) -> str:
    return "+".join(sorted(sources))


def family_recall(labels: np.ndarray, probabilities: np.ndarray, indices: np.ndarray) -> float:
    return float(np.mean(probabilities[indices] >= 0.5)) if len(indices) else float("nan")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET)
    parser.add_argument("--feature-columns", type=Path, default=FEATURE_COLUMNS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--trees", type=int, default=300)
    parser.add_argument(
        "--network-model-name",
        choices=("network_p4_offline", "network_p4_captured"),
        default="network_p4_offline",
        help="Label the network model according to the source of its P4 features.",
    )
    args = parser.parse_args()
    if args.folds < 2:
        parser.error("--folds must be at least 2")
    if args.trees < 1:
        parser.error("--trees must be positive")
    output_dir = args.output_dir.expanduser().resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        parser.error(f"Output directory must be empty: {output_dir}")

    rows = load_csv(args.dataset)
    columns = load_features(args.feature_columns)
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    if set(labels) != {0, 1}:
        parser.error("The feature dataset must contain malware and benign samples")

    network_features = list(columns["network"])
    host_features = [
        feature
        for feature in columns["host"]
        if feature.rpartition("__")[0] != "host__ebpf_unique_threads"
    ]
    if len(network_features) != 145 or len(host_features) != 170:
        parser.error("Expected the canonical 145 P4 and 170 observed eBPF feature columns")
    host_groups = host_signal_indices(host_features)
    network_groups = {feature.rpartition("__")[0] for feature in network_features}
    if len(network_groups) != 29 or len(host_groups) < len(network_groups):
        parser.error("The network and host feature families do not match the expected schema")

    source_map, source_family_map, source_inventory_counts = load_source_inventory()
    source_by_row = ["real_benign"] * len(rows)
    family_by_row = [""] * len(rows)
    source_counts = Counter()
    source_family_mismatches = []
    malware_indices = np.flatnonzero(labels == 1)
    benign_indices = np.flatnonzero(labels == 0)
    for index in malware_indices:
        row = rows[index]
        artifact = normalize_artifact(row["sample_artifact"])
        sources = source_map.get(artifact, set())
        if not sources:
            parser.error(f"No included source-inventory row for malware artifact: {row['sample_artifact']}")
        family = normalize_family(row.get("workload_family", ""))
        family_by_row[index] = family
        source_by_row[index] = source_category(sources)
        source_counts[source_by_row[index]] += 1
        for source_name in sources:
            inventory_family = source_family_map[artifact].get(source_name, "unassigned")
            if inventory_family != family:
                source_family_mismatches.append(
                    {
                        "sample_artifact": row["sample_artifact"],
                        "source": source_name,
                        "feature_family": family,
                        "inventory_family": inventory_family,
                    }
                )
    if source_family_mismatches:
        parser.error(f"Source and feature family labels disagree for {len(source_family_mismatches)} malware rows")

    for index in benign_indices:
        if not rows[index].get("package_group", "").strip():
            parser.error(f"Benign row has no package group: {rows[index]['sample_artifact']}")

    family_groups = np.asarray([family_by_row[index] for index in malware_indices], dtype=str)
    benign_groups = np.asarray([rows[index]["package_group"] for index in benign_indices], dtype=str)
    if len(set(family_groups)) < args.folds or len(set(benign_groups)) < args.folds:
        parser.error("There are fewer malware families or benign package groups than folds")
    malware_splits = list(
        GroupKFold(n_splits=args.folds).split(
            np.zeros((len(malware_indices), 1)), groups=family_groups
        )
    )
    benign_splits = list(
        GroupKFold(n_splits=args.folds).split(
            np.zeros((len(benign_indices), 1)), groups=benign_groups
        )
    )

    network_matrix = numeric_matrix(rows, network_features)
    host_matrix = numeric_matrix(rows, host_features)
    hybrid_matrix = np.hstack((network_matrix, host_matrix))
    network_model_name = args.network_model_name
    feature_matrices = {
        network_model_name: network_matrix,
        "host_ebpf_observed": host_matrix,
        "hybrid_full": hybrid_matrix,
        "hybrid_equal_signal_families": hybrid_matrix,
    }
    probabilities = {
        name: np.full(len(rows), np.nan, dtype=float) for name in feature_matrices
    }
    row_folds = np.zeros(len(rows), dtype=int)
    fold_metrics = {name: [] for name in feature_matrices}
    family_assignments = []
    host_selections = []
    fold_audits = []

    for fold, (malware_split, benign_split) in enumerate(
        zip(malware_splits, benign_splits, strict=True), start=1
    ):
        malware_train, malware_test = malware_split
        benign_train, benign_test = benign_split
        train_families = set(family_groups[malware_train])
        test_families = set(family_groups[malware_test])
        train_packages = set(benign_groups[benign_train])
        test_packages = set(benign_groups[benign_test])
        if train_families & test_families or train_packages & test_packages:
            raise RuntimeError(f"Group leakage in fold {fold}")

        train_indices = np.concatenate((malware_indices[malware_train], benign_indices[benign_train]))
        test_malware_indices = malware_indices[malware_test]
        test_benign_indices = benign_indices[benign_test]
        test_indices = np.concatenate((test_malware_indices, test_benign_indices))
        if set(labels[train_indices]) != {0, 1} or set(labels[test_indices]) != {0, 1}:
            raise RuntimeError(f"Fold {fold} does not contain both classes in train and test")
        row_folds[test_indices] = fold

        malware_source_counts = Counter(source_by_row[index] for index in test_malware_indices)
        fold_audits.append(
            {
                "fold": fold,
                "training_malware_samples": int(len(malware_train)),
                "test_malware_samples": int(len(malware_test)),
                "training_malware_families": int(len(train_families)),
                "heldout_malware_families": sorted(test_families),
                "training_benign_samples": int(len(benign_train)),
                "test_benign_samples": int(len(benign_test)),
                "training_benign_package_groups": int(len(train_packages)),
                "heldout_benign_package_groups": sorted(test_packages),
                "test_malware_source_counts": dict(malware_source_counts),
            }
        )
        for family in sorted(test_families):
            family_indices = malware_indices[family_groups == family]
            family_source_counts = Counter(source_by_row[index] for index in family_indices)
            family_assignments.append(
                {
                    "family": family,
                    "heldout_fold": fold,
                    "samples": int(len(family_indices)),
                    "malwarebazaar_only": int(family_source_counts["MalwareBazaar"]),
                    "triage_only": int(family_source_counts["Triage"]),
                    "present_in_both_sources": int(family_source_counts["MalwareBazaar+Triage"]),
                }
            )

        for model_name, matrix in feature_matrices.items():
            if model_name == "hybrid_equal_signal_families":
                selected_columns, selected_families = select_balanced_projection(
                    matrix[train_indices],
                    labels[train_indices],
                    len(network_features),
                    host_features,
                    host_groups,
                    len(network_groups),
                    args.seed + fold,
                )
                train_matrix = matrix[train_indices][:, selected_columns]
                test_matrix = matrix[test_indices][:, selected_columns]
                host_selections.extend(
                    {
                        "fold": fold,
                        "selection_rank": rank,
                        "host_signal_family": family,
                        "host_signal_budget": len(network_groups),
                        "p4_signal_budget": len(network_groups),
                    }
                    for rank, family in enumerate(selected_families, start=1)
                )
            else:
                train_matrix = matrix[train_indices]
                test_matrix = matrix[test_indices]

            model = make_model(args.seed + fold, args.trees)
            model.fit(train_matrix, labels[train_indices])
            fold_probabilities = model.predict_proba(test_matrix)[:, 1]
            probabilities[model_name][test_indices] = fold_probabilities
            fold_metrics[model_name].append(
                {
                    "fold": fold,
                    "test_samples": int(len(test_indices)),
                    "test_malware_families": int(len(test_families)),
                    **metrics_at_threshold(labels[test_indices], fold_probabilities, 0.5),
                }
            )

    if np.any(row_folds == 0):
        raise RuntimeError("Some dataset rows did not receive an out-of-fold prediction")

    per_family = {}
    family_recall_by_model = {name: {} for name in feature_matrices}
    for family in sorted(set(family_groups)):
        indices = malware_indices[family_groups == family]
        source_distribution = Counter(source_by_row[index] for index in indices)
        per_family[family] = {
            "samples": int(len(indices)),
            "source_counts": dict(source_distribution),
            "malware_detection_rate": {},
        }
        for model_name in feature_matrices:
            detected = int(np.count_nonzero(probabilities[model_name][indices] >= 0.5))
            recall = detected / len(indices)
            family_recall_by_model[model_name][family] = recall
            per_family[family]["malware_detection_rate"][model_name] = recall

    source_metrics = {}
    for model_name in feature_matrices:
        source_metrics[model_name] = {}
        for source in SOURCE_CATEGORIES:
            indices = np.asarray(
                [
                    index
                    for index in malware_indices
                    if source_by_row[index] == source
                ],
                dtype=int,
            )
            if len(indices):
                detected = int(np.count_nonzero(probabilities[model_name][indices] >= 0.5))
                source_metrics[model_name][source] = {
                    "samples": int(len(indices)),
                    "detected": detected,
                    "missed": int(len(indices) - detected),
                    "malware_detection_rate": detected / len(indices),
                }

    named_families = [family for family in sorted(set(family_groups)) if family != "unassigned"]
    family_deltas = np.asarray(
        [
            family_recall_by_model["hybrid_equal_signal_families"][family]
            - max(
                family_recall_by_model[network_model_name][family],
                family_recall_by_model["host_ebpf_observed"][family],
            )
            for family in named_families
        ],
        dtype=float,
    )
    rng = np.random.default_rng(args.seed)
    bootstrap = np.asarray(
        [
            np.mean(rng.choice(family_deltas, size=len(family_deltas), replace=True))
            for _ in range(10000)
        ]
    )
    models_report = {}
    for name, matrix in feature_matrices.items():
        feature_count = (
            len(network_features) + len(host_features)
            if name == "hybrid_full"
            else len(network_features) + len(network_groups) * 5
            if name == "hybrid_equal_signal_families"
            else len(network_features)
            if name == network_model_name
            else len(host_features)
        )
        models_report[name] = {
            "feature_count": feature_count,
            "pooled_oof": metrics_at_threshold(labels, probabilities[name], 0.5),
            "fold_metrics": fold_metrics[name],
            "malware_detection_by_source": source_metrics[name],
        }

    report = {
        "evaluation": "5-fold out-of-fold evaluation with entire malware families and benign package groups held out",
        "seed": args.seed,
        "folds": args.folds,
        "trees_per_random_forest": args.trees,
        "threshold": 0.5,
        "network_model_name": network_model_name,
        "network_feature_source": (
            "runner p4_network capture telemetry"
            if network_model_name == "network_p4_captured"
            else "offline PCAP reconstruction"
        ),
        "threshold_policy": "Fixed before scoring; no threshold tuning on held-out families or benign packages.",
        "dataset_samples": len(rows),
        "malware_samples": int(len(malware_indices)),
        "benign_samples": int(len(benign_indices)),
        "malware_family_groups": int(len(set(family_groups))),
        "named_malware_families": int(len(named_families)),
        "unassigned_malware_samples": int(np.count_nonzero(family_groups == "unassigned")),
        "benign_package_groups": int(len(set(benign_groups))),
        "source_inventory_included_rows": source_inventory_counts,
        "unique_malware_feature_rows_by_source": dict(source_counts),
        "source_family_label_caveat": "Malware family labels come from MalwareBazaar metadata or Triage signatures and are not independently verified runtime labels.",
        "feature_breadth": {
            "network_signal_families": len(network_groups),
            "network_columns": len(network_features),
            "host_signal_families": len(host_groups),
            "host_columns": len(host_features),
            "full_hybrid_columns": len(network_features) + len(host_features),
            "equal_family_hybrid_columns": len(network_features) + len(network_groups) * 5,
            "host_family_selection": "training-fold-only mean mutual information across five summaries per signal family",
        },
        "group_leakage_checks": {
            "malware_family_groups_disjoint_per_fold": True,
            "benign_package_groups_disjoint_per_fold": True,
            "every_sample_scored_out_of_fold_once": True,
        },
        "folds_detail": fold_audits,
        "models": models_report,
        "per_family_malware_detection_rate": per_family,
        "equal_family_hybrid_recall_delta_vs_best_single": {
            "mean_across_named_families": float(np.mean(family_deltas)),
            "family_bootstrap_95pct_interval": [
                float(np.quantile(bootstrap, 0.025)),
                float(np.quantile(bootstrap, 0.975)),
            ],
            "families": len(named_families),
            "comparison": "hybrid_equal_signal_families versus best of network-only and host-only recall for each family",
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "unseen_family_metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    prediction_rows = []
    for model_name, model_probabilities in probabilities.items():
        for index, probability in enumerate(model_probabilities):
            prediction_rows.append(
                {
                    "model": model_name,
                    "sample_artifact": rows[index]["sample_artifact"],
                    "source": source_by_row[index],
                    "label": int(labels[index]),
                    "malware_family": family_by_row[index],
                    "package_group": rows[index].get("package_group", ""),
                    "fold": int(row_folds[index]),
                    "probability_malware": float(probability),
                    "threshold": 0.5,
                    "prediction": int(probability >= 0.5),
                }
            )
    write_csv(
        output_dir / "out_of_fold_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )
    write_csv(
        output_dir / "family_fold_assignments.csv",
        family_assignments,
        list(family_assignments[0]),
    )
    write_csv(
        output_dir / "host_signal_family_selections.csv",
        host_selections,
        list(host_selections[0]),
    )
    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "source_counts": dict(source_counts),
                "folds": fold_audits,
                "models": {
                    name: result["pooled_oof"]
                    for name, result in models_report.items()
                },
                "equal_family_hybrid_recall_delta_vs_best_single": report[
                    "equal_family_hybrid_recall_delta_vs_best_single"
                ],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())