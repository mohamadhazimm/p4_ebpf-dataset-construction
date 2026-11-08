#!/usr/bin/env python3
"""Compare simulation augmentation and feature budgets with grouped validation."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
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
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.pipeline import make_pipeline

from evaluate_simulated_models_10pct import (
    load_csv,
    load_features,
    numeric_matrix,
    split_malware_by_family,
    write_csv,
)


STUDY_DIR = Path(__file__).resolve().parents[1]
DEFAULT_P4_DATASET = (
    STUDY_DIR
    / "data/malware/revision4/full-cohort-feature-pool-20261016"
    / "p4_pcap_reconstructed_labeled_sample_dataset.csv"
)


def make_model(seed: int, trees: int):
    return make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=trees,
            max_features="sqrt",
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=seed,
            n_jobs=-1,
        ),
    )


def host_signal_indices(host_features: list[str]) -> dict[str, list[int]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, feature in enumerate(host_features):
        signal, separator, _ = feature.rpartition("__")
        if not separator:
            raise ValueError(f"Host feature lacks a summary suffix: {feature}")
        groups[signal].append(index)
    if any(len(indices) != 5 for indices in groups.values()):
        raise ValueError("Each host signal family must contain exactly five summary features")
    return dict(groups)


def select_balanced_projection(
    train_matrix: np.ndarray,
    train_labels: np.ndarray,
    network_count: int,
    host_features: list[str],
    host_groups: dict[str, list[int]],
    host_family_budget: int,
    seed: int,
) -> tuple[list[int], list[str]]:
    if host_family_budget > len(host_groups):
        raise ValueError("Host pool is smaller than the requested family budget")
    host_train = SimpleImputer(strategy="median").fit_transform(
        train_matrix[:, network_count:]
    )
    scores = mutual_info_classif(host_train, train_labels, random_state=seed)
    family_scores = {
        family: float(np.mean(scores[indices]))
        for family, indices in host_groups.items()
    }
    selected_families = sorted(
        family_scores, key=lambda family: (-family_scores[family], family)
    )[:host_family_budget]
    selected_host_indices = [
        index
        for feature in selected_families
        for index in host_groups[feature]
    ]
    selected_columns = list(range(network_count)) + [
        network_count + index for index in selected_host_indices
    ]
    return selected_columns, selected_families


def project_matrices(
    model_name: str,
    train_matrix: np.ndarray,
    validation_matrix: np.ndarray,
    labels: np.ndarray,
    network_count: int,
    host_features: list[str],
    host_groups: dict[str, list[int]],
    host_family_budget: int,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    if model_name != "hybrid_balanced_50_50":
        return train_matrix, validation_matrix, []
    selected_columns, selected_families = select_balanced_projection(
        train_matrix,
        labels,
        network_count,
        host_features,
        host_groups,
        host_family_budget,
        seed,
    )
    return (
        train_matrix[:, selected_columns],
        validation_matrix[:, selected_columns],
        selected_families,
    )


def choose_threshold(labels: np.ndarray, probabilities: np.ndarray) -> tuple[float, float]:
    candidates = np.unique(np.concatenate(([0.0, 0.5, 1.0], probabilities)))
    scores = [
        balanced_accuracy_score(labels, probabilities >= threshold)
        for threshold in candidates
    ]
    best_score = max(scores)
    best_threshold = min(
        (float(threshold) for threshold, score in zip(candidates, scores, strict=True) if score == best_score),
        key=lambda threshold: (abs(threshold - 0.5), threshold),
    )
    return best_threshold, float(best_score)


def metrics_at_threshold(
    labels: np.ndarray, probabilities: np.ndarray, threshold: float
) -> dict:
    predictions = (probabilities >= threshold).astype(int)
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


def detection_metrics(labels: np.ndarray, predictions: np.ndarray) -> dict:
    positive = labels == 1
    negative = labels == 0
    detected = int(np.count_nonzero(predictions[positive] == 1))
    false_positives = int(np.count_nonzero(predictions[negative] == 1))
    positive_count = int(np.count_nonzero(positive))
    negative_count = int(np.count_nonzero(negative))
    return {
        "samples": positive_count + negative_count,
        "malware_samples": positive_count,
        "malware_detected": detected,
        "malware_missed": positive_count - detected,
        "malware_detection_rate": detected / positive_count if positive_count else None,
        "benign_samples": negative_count,
        "benign_false_positives": false_positives,
        "benign_true_negatives": negative_count - false_positives,
        "benign_false_positive_rate": false_positives / negative_count
        if negative_count
        else None,
    }


def fit_projected_model(
    model_name: str,
    train_matrix: np.ndarray,
    train_labels: np.ndarray,
    validation_matrix: np.ndarray,
    network_count: int,
    host_features: list[str],
    host_groups: dict[str, list[int]],
    host_family_budget: int,
    seed: int,
    trees: int,
):
    projected_train, projected_validation, selected_families = project_matrices(
        model_name,
        train_matrix,
        validation_matrix,
        train_labels,
        network_count,
        host_features,
        host_groups,
        host_family_budget,
        seed,
    )
    model = make_model(seed, trees)
    model.fit(projected_train, train_labels)
    probabilities = model.predict_proba(projected_validation)[:, 1]
    return model, probabilities, selected_families


def repeated_summary(seed_results: list[dict]) -> dict:
    metric_paths = {
        "test": ("test_metrics", ("accuracy", "balanced_accuracy", "precision", "recall", "f1", "roc_auc")),
        "malware": ("malware_metrics", ("detection_rate",)),
        "benign": ("benign_metrics", ("false_positive_rate",)),
        "threshold": ("calibration", ("threshold", "oof_balanced_accuracy")),
    }
    summary = {"repeats": len(seed_results), "per_seed": seed_results, "mean_std": {}}
    for section, (path, metrics) in metric_paths.items():
        summary["mean_std"][section] = {}
        for metric in metrics:
            values = [float(result[path][metric]) for result in seed_results]
            summary["mean_std"][section][metric] = {
                "mean": float(np.mean(values)),
                "std": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
                "values": values,
            }
    return summary


def run_source_separability_audit(
    seed: int,
    model_inputs: dict[str, tuple[np.ndarray, np.ndarray, list[str]]],
    malware_rows: list[dict[str, str]],
    scenario_rows: list[dict[str, str]],
    malware_training: np.ndarray,
    scenario_labels: np.ndarray,
    network_count: int,
    host_features: list[str],
    host_groups: dict[str, list[int]],
    host_family_budget: int,
    folds: int,
    trees: int,
) -> dict:
    attack_indices = np.flatnonzero(scenario_labels == 1)
    source_groups = np.asarray(
        [f"malware-family::{malware_rows[index].get('workload_family') or 'unassigned'}" for index in malware_training]
        + [f"scenario::{scenario_rows[index]['scenario_id']}" for index in attack_indices],
        dtype=str,
    )
    source_labels = np.asarray([0] * len(malware_training) + [1] * len(attack_indices), dtype=int)
    output = {}
    for model_index, (name, (malware_matrix, scenario_matrix, _)) in enumerate(
        model_inputs.items()
    ):
        features = np.vstack((malware_matrix[malware_training], scenario_matrix[attack_indices]))
        probabilities = np.full(len(source_labels), np.nan)
        splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
        for fold_index, (fit_indices, validation_indices) in enumerate(
            splitter.split(np.zeros(len(source_labels)), source_labels, source_groups),
            start=1,
        ):
            if len(set(source_labels[fit_indices])) != 2 or len(set(source_labels[validation_indices])) != 2:
                raise ValueError("Source-audit fold lacks one of its source classes")
            _, fold_probabilities, _ = fit_projected_model(
                name,
                features[fit_indices],
                source_labels[fit_indices],
                features[validation_indices],
                network_count,
                host_features,
                host_groups,
                host_family_budget,
                seed * 100000 + model_index * 1000 + fold_index,
                trees,
            )
            probabilities[validation_indices] = fold_probabilities
        if np.isnan(probabilities).any():
            raise RuntimeError(f"Missing out-of-fold source predictions for {name}")
        metrics = metrics_at_threshold(source_labels, probabilities, 0.5)
        output[name] = {
            "real_malware_samples": len(malware_training),
            "simulated_attack_samples": len(attack_indices),
            "source_label_1": "simulated_attack",
            "source_label_0": "real_malware",
            "grouped_oof_metrics": metrics,
        }
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--scenario-dataset", type=Path, required=True)
    parser.add_argument("--p4-dataset", type=Path, default=DEFAULT_P4_DATASET)
    parser.add_argument("--feature-columns", type=Path)
    parser.add_argument("--p4-feature-columns", type=Path)
    parser.add_argument("--scenario-feature-columns", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44, 45, 46])
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--trees", type=int, default=300)
    parser.add_argument("--malware-train-fraction", type=float, default=0.10)
    parser.add_argument("--benign-test-fraction", type=float, default=0.50)
    parser.add_argument("--host-signal-budget", type=int, default=29)
    args = parser.parse_args()
    if not 0 < args.malware_train_fraction < 0.5:
        parser.error("--malware-train-fraction must be between 0 and 0.5")
    if not 0 < args.benign_test_fraction < 1:
        parser.error("--benign-test-fraction must be between 0 and 1")
    if len(set(args.seeds)) != len(args.seeds) or not args.seeds:
        parser.error("--seeds must contain distinct seed values")

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
    scenario_rows = load_csv(args.scenario_dataset)
    columns = load_features(feature_path)
    p4_columns = load_features(p4_feature_path)
    scenario_columns = load_features(scenario_feature_path)
    malware_rows = [row for row in source_rows if int(row["label"]) == 1]
    benign_rows = [row for row in source_rows if int(row["label"]) == 0]
    scenario_labels = np.asarray([int(row["label"]) for row in scenario_rows], dtype=int)
    if not malware_rows or not benign_rows or set(scenario_labels) != {0, 1}:
        parser.error("Expected malware and benign real samples plus both simulation labels")
    if args.folds < 2:
        parser.error("--folds must be at least 2")

    network_features = list(scenario_columns["network"])
    host_features = list(scenario_columns["host"])
    if not set(network_features).issubset(p4_columns["network"]):
        parser.error("Scenario P4 features do not match the reconstructed malware feature pool")
    if not set(host_features).issubset(columns["host"]):
        parser.error("Scenario host features do not match the malware host feature pool")
    p4_by_artifact = {row["sample_artifact"]: row for row in p4_rows}
    if len(p4_by_artifact) != len(p4_rows):
        parser.error("Reconstructed P4 dataset contains duplicate sample artifacts")
    missing = [row["sample_artifact"] for row in source_rows if row["sample_artifact"] not in p4_by_artifact]
    if missing:
        parser.error(f"Reconstructed P4 dataset lacks real samples: {missing[:5]}")

    malware_labels = np.ones(len(malware_rows), dtype=int)
    malware_train, malware_test, family_counts = split_malware_by_family(
        malware_rows, malware_labels, args.malware_train_fraction, args.seeds[0]
    )
    if len(malware_train) == 0 or len(malware_test) == 0:
        parser.error("The malware split must leave samples for both training and testing")

    malware_network = numeric_matrix(
        [p4_by_artifact[row["sample_artifact"]] for row in malware_rows], network_features
    )
    benign_network = numeric_matrix(
        [p4_by_artifact[row["sample_artifact"]] for row in benign_rows], network_features
    )
    malware_host = numeric_matrix(malware_rows, host_features)
    benign_host = numeric_matrix(benign_rows, host_features)
    scenario_network = numeric_matrix(scenario_rows, network_features)
    scenario_host = numeric_matrix(scenario_rows, host_features)
    model_inputs = {
        "network": (
            malware_network,
            benign_network,
            scenario_network,
            network_features,
        ),
        "host": (malware_host, benign_host, scenario_host, host_features),
        "hybrid_full": (
            np.hstack((malware_network, malware_host)),
            np.hstack((benign_network, benign_host)),
            np.hstack((scenario_network, scenario_host)),
            network_features + host_features,
        ),
        "hybrid_balanced_50_50": (
            np.hstack((malware_network, malware_host)),
            np.hstack((benign_network, benign_host)),
            np.hstack((scenario_network, scenario_host)),
            network_features + host_features,
        ),
    }
    host_groups = host_signal_indices(host_features)
    if args.host_signal_budget > len(host_groups):
        parser.error("--host-signal-budget exceeds the available host signal families")

    augmentation_options = (False, True)
    config_names = list(model_inputs)
    results: dict[str, list[dict]] = {
        f"{name}__simulations_{'on' if use_simulations else 'off'}": []
        for name in config_names
        for use_simulations in augmentation_options
    }
    predictions = []
    assignments = []
    split_audits = []
    source_audit = None

    for repeat_index, seed in enumerate(args.seeds):
        seed_malware_train, seed_malware_test, seed_family_counts = split_malware_by_family(
            malware_rows, malware_labels, args.malware_train_fraction, seed
        )
        if seed_family_counts.keys() != family_counts.keys():
            raise RuntimeError("Malware family inventory changed across seeds")
        benign_groups = np.asarray([row["package_group"] for row in benign_rows], dtype=str)
        benign_split = GroupShuffleSplit(
            n_splits=1, test_size=args.benign_test_fraction, random_state=seed
        )
        benign_train, benign_test = next(
            benign_split.split(np.zeros(len(benign_rows)), groups=benign_groups)
        )
        benign_train_groups = set(benign_groups[benign_train])
        benign_test_groups = set(benign_groups[benign_test])
        if benign_train_groups & benign_test_groups:
            raise RuntimeError("Benign package groups crossed the train/test boundary")

        real_train_labels = np.concatenate(
            (np.ones(len(seed_malware_train), dtype=int), np.zeros(len(benign_train), dtype=int))
        )
        real_test_labels = np.concatenate(
            (np.ones(len(seed_malware_test), dtype=int), np.zeros(len(benign_test), dtype=int))
        )
        real_train_groups = np.asarray(
            [f"malware-sample::{malware_rows[index]['sample_artifact']}" for index in seed_malware_train]
            + [f"benign-package::{benign_rows[index]['package_group']}" for index in benign_train],
            dtype=str,
        )
        malware_test_seen = np.asarray(
            [seed_family_counts[malware_rows[index].get("workload_family") or "unassigned"]["training"] > 0 for index in seed_malware_test],
            dtype=bool,
        )
        malware_test_unseen = ~malware_test_seen

        assignments.extend(
            {
                "seed": seed,
                "source": "real_malware",
                "sample_artifact": row["sample_artifact"],
                "label": 1,
                "malware_family": row.get("workload_family") or "unassigned",
                "package_group": "",
                "role": "malware_train_10pct" if index in set(seed_malware_train) else "unknown_malware_test",
            }
            for index, row in enumerate(malware_rows)
        )
        assignments.extend(
            {
                "seed": seed,
                "source": "real_benign",
                "sample_artifact": row["sample_artifact"],
                "label": 0,
                "malware_family": "",
                "package_group": row["package_group"],
                "role": "real_benign_train" if index in set(benign_train) else "heldout_real_benign_test",
            }
            for index, row in enumerate(benign_rows)
        )
        assignments.extend(
            {
                "seed": seed,
                "source": "self_generated_simulation",
                "sample_artifact": row["sample_artifact"],
                "label": int(scenario_labels[index]),
                "malware_family": "",
                "package_group": "",
                "role": "simulation_train",
            }
            for index, row in enumerate(scenario_rows)
        )
        split_audits.append(
            {
                "seed": seed,
                "malware_train": len(seed_malware_train),
                "malware_test": len(seed_malware_test),
                "benign_train": len(benign_train),
                "benign_test": len(benign_test),
                "benign_train_package_groups": len(benign_train_groups),
                "benign_test_package_groups": len(benign_test_groups),
                "benign_group_overlap": len(benign_train_groups & benign_test_groups),
            }
        )

        for model_index, (model_name, (malware_matrix, benign_matrix, sim_matrix, feature_names)) in enumerate(
            model_inputs.items()
        ):
            real_train_matrix = np.vstack(
                (malware_matrix[seed_malware_train], benign_matrix[benign_train])
            )
            real_test_matrix = np.vstack(
                (malware_matrix[seed_malware_test], benign_matrix[benign_test])
            )
            calibration = StratifiedGroupKFold(
                n_splits=args.folds, shuffle=True, random_state=seed
            )
            oof_probabilities = np.full(len(real_train_labels), np.nan)
            oof_selected_families = []
            oof_probabilities_by_key = {
                f"{model_name}__simulations_{'on' if use_simulations else 'off'}": np.full(
                    len(real_train_labels), np.nan
                )
                for use_simulations in augmentation_options
            }
            for fold_index, (fit_indices, validation_indices) in enumerate(
                calibration.split(real_train_matrix, real_train_labels, real_train_groups),
                start=1,
            ):
                fit_labels = real_train_labels[fit_indices]
                validation_labels = real_train_labels[validation_indices]
                if len(set(fit_labels)) != 2 or len(set(validation_labels)) != 2:
                    raise ValueError(
                        f"Calibration fold {fold_index} for seed {seed} lacks one class"
                    )
                fit_matrix = real_train_matrix[fit_indices]
                if True:
                    pass
                selected_families = []
                if model_name == "hybrid_balanced_50_50":
                    projected_fit, projected_validation, selected_families = project_matrices(
                        model_name,
                        fit_matrix,
                        real_train_matrix[validation_indices],
                        fit_labels,
                        len(network_features),
                        host_features,
                        host_groups,
                        args.host_signal_budget,
                        seed + model_index + fold_index,
                    )
                else:
                    projected_fit = fit_matrix
                    projected_validation = real_train_matrix[validation_indices]

                for use_simulations in augmentation_options:
                    model_train = projected_fit
                    model_labels = fit_labels
                    if use_simulations:
                        sim_train = sim_matrix
                        sim_labels = scenario_labels
                        if model_name == "hybrid_balanced_50_50":
                            selected_columns, _ = select_balanced_projection(
                                np.vstack((fit_matrix, sim_matrix)),
                                np.concatenate((fit_labels, sim_labels)),
                                len(network_features),
                                host_features,
                                host_groups,
                                args.host_signal_budget,
                                seed + model_index + fold_index,
                            )
                            model_train = np.vstack((fit_matrix, sim_matrix))[:, selected_columns]
                            model_validation = real_train_matrix[validation_indices][:, selected_columns]
                        else:
                            model_train = np.vstack((fit_matrix, sim_train))
                            model_validation = real_train_matrix[validation_indices]
                        model_labels = np.concatenate((fit_labels, sim_labels))
                    else:
                        model_validation = projected_validation
                    model = make_model(seed * 100000 + model_index * 1000 + fold_index, args.trees)
                    model.fit(model_train, model_labels)
                    oof_probabilities_fold = model.predict_proba(model_validation)[:, 1]
                    key = f"{model_name}__simulations_{'on' if use_simulations else 'off'}"
                    oof_probabilities_by_key[key][validation_indices] = oof_probabilities_fold
                    if selected_families:
                        oof_selected_families.append(
                            {"fold": fold_index, "selected_host_signal_families": selected_families}
                        )

            for augmentation_index, use_simulations in enumerate(augmentation_options):
                key = f"{model_name}__simulations_{'on' if use_simulations else 'off'}"
                oof = oof_probabilities_by_key[key]
                if np.isnan(oof).any():
                    raise RuntimeError(f"Missing OOF calibration scores for {key} at seed {seed}")
                threshold, oof_balanced_accuracy = choose_threshold(real_train_labels, oof)

                final_train = real_train_matrix
                final_labels = real_train_labels
                if use_simulations:
                    final_train = np.vstack((real_train_matrix, sim_matrix))
                    final_labels = np.concatenate((real_train_labels, scenario_labels))
                final_selected_families = []
                if model_name == "hybrid_balanced_50_50":
                    selected_columns, final_selected_families = select_balanced_projection(
                        final_train,
                        final_labels,
                        len(network_features),
                        host_features,
                        host_groups,
                        args.host_signal_budget,
                        seed + model_index + 999,
                    )
                    final_train = final_train[:, selected_columns]
                    projected_test = real_test_matrix[:, selected_columns]
                    final_feature_count = len(selected_columns)
                else:
                    projected_test = real_test_matrix
                    final_feature_count = len(feature_names)
                model = make_model(seed * 100000 + model_index * 1000 + 999, args.trees)
                model.fit(final_train, final_labels)
                test_probabilities = model.predict_proba(projected_test)[:, 1]
                test_predictions = (test_probabilities >= threshold).astype(int)
                metrics = metrics_at_threshold(real_test_labels, test_probabilities, threshold)
                malware_count = len(seed_malware_test)
                malware_probabilities = test_probabilities[:malware_count]
                malware_predictions = test_predictions[:malware_count]
                malware_metrics = {
                    "samples": malware_count,
                    "detected": int(np.count_nonzero(malware_predictions == 1)),
                    "missed": int(np.count_nonzero(malware_predictions == 0)),
                    "detection_rate": float(np.mean(malware_predictions == 1)),
                }
                benign_predictions = test_predictions[malware_count:]
                benign_metrics = {
                    "samples": len(benign_test),
                    "false_positives": int(np.count_nonzero(benign_predictions == 1)),
                    "true_negatives": int(np.count_nonzero(benign_predictions == 0)),
                    "false_positive_rate": float(np.mean(benign_predictions == 1)),
                }
                known_mask = malware_test_seen
                unseen_mask = malware_test_unseen
                seed_result = {
                    "seed": seed,
                    "model": model_name,
                    "simulations_in_training": use_simulations,
                    "feature_count": final_feature_count,
                    "selected_host_signal_families": final_selected_families,
                    "calibration": {
                        "method": "5-fold StratifiedGroupKFold OOF on real training samples only; optimize balanced accuracy",
                        "threshold": threshold,
                        "oof_balanced_accuracy": oof_balanced_accuracy,
                        "oof_sample_count": len(real_train_labels),
                    },
                    "test_metrics": metrics,
                    "malware_metrics": malware_metrics,
                    "benign_metrics": benign_metrics,
                    "known_family_malware_metrics": {
                        "samples": int(np.count_nonzero(known_mask)),
                        "detected": int(np.count_nonzero(malware_predictions[known_mask] == 1)),
                        "detection_rate": float(np.mean(malware_predictions[known_mask] == 1))
                        if known_mask.any()
                        else None,
                    },
                    "unseen_family_malware_metrics": {
                        "samples": int(np.count_nonzero(unseen_mask)),
                        "detected": int(np.count_nonzero(malware_predictions[unseen_mask] == 1)),
                        "detection_rate": float(np.mean(malware_predictions[unseen_mask] == 1))
                        if unseen_mask.any()
                        else None,
                    },
                    "per_family": {},
                }
                for family, split in seed_family_counts.items():
                    family_mask = np.asarray(
                        [
                            (malware_rows[index].get("workload_family") or "unassigned") == family
                            for index in seed_malware_test
                        ],
                        dtype=bool,
                    )
                    seed_result["per_family"][family] = {
                        **split,
                        "detection_rate": float(np.mean(malware_predictions[family_mask] == 1))
                        if family_mask.any()
                        else None,
                    }
                results[key].append(seed_result)

                for position, row_index in enumerate(seed_malware_test):
                    row = malware_rows[row_index]
                    family = row.get("workload_family") or "unassigned"
                    predictions.append(
                        {
                            "seed": seed,
                            "model": model_name,
                            "simulations_in_training": int(use_simulations),
                            "threshold": threshold,
                            "sample_artifact": row["sample_artifact"],
                            "sample_role": "unknown_malware",
                            "malware_family": family,
                            "family_seen_in_training": int(seed_family_counts[family]["training"] > 0),
                            "label_for_evaluation_only": 1,
                            "probability_malware": float(malware_probabilities[position]),
                            "prediction": int(malware_predictions[position]),
                        }
                    )
                for position, row_index in enumerate(benign_test):
                    row = benign_rows[row_index]
                    test_position = malware_count + position
                    predictions.append(
                        {
                            "seed": seed,
                            "model": model_name,
                            "simulations_in_training": int(use_simulations),
                            "threshold": threshold,
                            "sample_artifact": row["sample_artifact"],
                            "sample_role": "heldout_real_benign",
                            "malware_family": "",
                            "family_seen_in_training": "",
                            "label_for_evaluation_only": 0,
                            "probability_malware": float(test_probabilities[test_position]),
                            "prediction": int(test_predictions[test_position]),
                        }
                    )

        if repeat_index == 0:
            source_audit = run_source_separability_audit(
                seed,
                {
                    name: (matrices[0], matrices[2], matrices[3])
                    for name, matrices in model_inputs.items()
                },
                malware_rows,
                scenario_rows,
                seed_malware_train,
                scenario_labels,
                len(network_features),
                host_features,
                host_groups,
                args.host_signal_budget,
                args.folds,
                args.trees,
            )

    aggregate_results = {
        key: repeated_summary(seed_results) for key, seed_results in results.items()
    }
    report = {
        "evaluation": "repeated simulation-augmentation comparison with grouped calibration and held-out real benign samples",
        "seeds": args.seeds,
        "folds_for_threshold_calibration": args.folds,
        "trees_per_random_forest": args.trees,
        "malware_train_fraction_requested": args.malware_train_fraction,
        "benign_test_fraction_requested": args.benign_test_fraction,
        "malware_split_rule": "Per family, train max(1, floor(fraction*n)) while retaining a test sample; singleton families remain test-only.",
        "benign_split_rule": "GroupShuffleSplit by package_group, independently repeated for each seed.",
        "threshold_rule": "Select threshold maximizing balanced accuracy on grouped OOF predictions for real training malware and real training benign samples only; ties prefer closest to 0.5.",
        "training_comparison": {
            "without_simulations": "10%-per-family real malware training subset plus real benign training groups",
            "with_simulations": "same real training split plus all 84 self-generated scenario rows",
            "simulation_label_counts": {
                "attack_simulation": int(np.count_nonzero(scenario_labels == 1)),
                "benign_control": int(np.count_nonzero(scenario_labels == 0)),
            },
        },
        "feature_sets": {
            "network": {"p4_signal_families": len(network_features) // 5, "columns": len(network_features)},
            "host": {"ebpf_signal_families": len(host_groups), "columns": len(host_features)},
            "hybrid_full": {"network_families": len(network_features) // 5, "host_families": len(host_groups), "columns": len(network_features) + len(host_features)},
            "hybrid_balanced_50_50": {
                "network_signal_families": args.host_signal_budget,
                "host_signal_families_selected": args.host_signal_budget,
                "host_selection": "training-only mean mutual information across each signal's five summaries",
                "columns": args.host_signal_budget * 10,
            },
        },
        "p4_reconstruction": {
            "dataset": str(args.p4_dataset.resolve()),
            "method_counts": {
                method: int(count)
                for method, count in Counter(
                    p4_by_artifact[row["sample_artifact"]].get("p4_reconstruction_method", "unspecified")
                    for row in source_rows
                ).items()
            },
            "network_features_reconstructed_offline_from_pcap": True,
        },
        "source_separability_audit": {
            "purpose": "Grouped OOF check whether the same numeric features distinguish real malware training samples from simulated attacks.",
            "metrics": source_audit,
        },
        "split_audits": split_audits,
        "comparisons": aggregate_results,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "simulation_augmentation_comparison.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(
        args.output_dir / "simulation_augmentation_predictions.csv",
        predictions,
        list(predictions[0]),
    )
    write_csv(
        args.output_dir / "simulation_augmentation_assignments.csv",
        assignments,
        list(assignments[0]),
    )
    print(json.dumps(report, indent=2))
    print(f"Results written to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())