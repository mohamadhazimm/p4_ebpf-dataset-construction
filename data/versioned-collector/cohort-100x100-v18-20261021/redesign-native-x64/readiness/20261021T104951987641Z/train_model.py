#!/usr/bin/env python3
"""Fit and score the frozen native-x64 .18 experiment protocol."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline


ATTEMPT_DIR = Path(__file__).resolve().parent
EXPERIMENT_DIR = ATTEMPT_DIR.parents[1]
STUDY_DIR = EXPERIMENT_DIR.parents[3]
WORKSPACE_DIR = STUDY_DIR.parents[1]
P4_DIR = WORKSPACE_DIR / "p4_ebpf"
ANALYSIS_DIR = ATTEMPT_DIR / "analysis"
PREPARATION_PATH = ANALYSIS_DIR / "preparation_audit.json"
DATASET_PATH = ANALYSIS_DIR / "eligible_dataset.csv"
PREREGISTRATION_PATH = ATTEMPT_DIR / "preregistration.json"
HOST_FEATURE_PATH = STUDY_DIR / "data/benign/revision3/labeled_sample_dataset.feature_columns.json"
RUNNER_SHA256 = "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49"
SEED = 42
FOLDS = 5
BOOTSTRAP_REPLICATES = 2000
LABEL_PERMUTATIONS = 100
THRESHOLD = 0.5
EXPECTED_MODELS = (
    "network_p4",
    "host_29_families",
    "hybrid_29_plus_29",
)

sys.path.insert(0, str(P4_DIR))
import analyze_p4_pcap_ablation as p4  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_data() -> tuple[list[dict], list[str], list[str], dict]:
    preparation = json.loads(PREPARATION_PATH.read_text(encoding="utf-8"))
    if preparation.get("status") != "prepared_for_modeling":
        raise ValueError("The data preparation audit has not passed")
    if preparation["quality_accepted_target_observed_classifier_cases"] != 194:
        raise ValueError("Prepared cohort size differs from the audited eligible population")
    if preparation["primary_common_aligned_cases"] != 176:
        raise ValueError("Prepared common-aligned population differs from the audit")
    preregistration = json.loads(PREREGISTRATION_PATH.read_text(encoding="utf-8"))
    if preregistration["schema"] != "2026-10-20.18":
        raise ValueError("Frozen preregistration schema mismatch")
    if preregistration["analysis"]["rf"] != {
        "class_weight": "balanced",
        "n_estimators": 500,
        "n_jobs": 1,
        "random_state": 42,
    }:
        raise ValueError("Frozen Random Forest settings differ from this implementation")
    if sha256(ANALYSIS_DIR / "eligibility_audit.csv") == "":
        raise ValueError("Eligibility audit is unavailable")

    host_features = list(json.loads(HOST_FEATURE_PATH.read_text(encoding="utf-8"))["host"])
    if len(host_features) != 175:
        raise ValueError("Expected 35 host candidate families x five summaries")
    with DATASET_PATH.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    if len(rows) != 194:
        raise ValueError(f"Expected 194 host-eligible rows, found {len(rows)}")
    for row in rows:
        row["label"] = int(row["label"])
        row["position"] = int(row["position"])
        row["post_target_lineage_raw_syscalls"] = int(
            row["post_target_lineage_raw_syscalls"]
        )
        row["return_code"] = row["return_code"] or "missing"
        for feature in host_features:
            row[feature] = float(row[feature])
        if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True":
            for feature in p4.P4_SAMPLE_FEATURES:
                row[feature] = float(row[feature])

    common = [
        row
        for row in rows
        if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True"
    ]
    if len(common) != 176:
        raise ValueError(f"Expected 176 common-aligned rows, found {len(common)}")
    return rows, common, host_features, preparation


def split_indices(records: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    training = np.asarray(
        [index for index, record in enumerate(records) if record["split"] == "training"],
        dtype=int,
    )
    validation = np.asarray(
        [index for index, record in enumerate(records) if record["split"] == "validation"],
        dtype=int,
    )
    if len(training) + len(validation) != len(records):
        raise ValueError("Classifier rows include a non-training/non-validation split")
    if {records[index]["label"] for index in training} != {0, 1}:
        raise ValueError("Training split must contain both classes")
    if {records[index]["label"] for index in validation} != {0, 1}:
        raise ValueError("Validation split must contain both classes")
    train_groups = {records[index]["group_id"] for index in training}
    validation_groups = {records[index]["group_id"] for index in validation}
    if train_groups & validation_groups:
        raise ValueError("Malware-signature or benign-project group crosses frozen split")
    return training, validation


def matrix(records: list[dict], features: list[str]) -> np.ndarray:
    values = np.asarray([[float(record[name]) for name in features] for record in records])
    if not np.isfinite(values).all():
        raise ValueError("Model feature matrix contains non-finite values")
    return values


def random_forest() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=500,
        class_weight="balanced",
        random_state=SEED,
        n_jobs=1,
    )


def feature_family_selection(
    host_matrix: np.ndarray,
    labels: np.ndarray,
    host_features: list[str],
) -> tuple[list[str], list[int], dict[str, float]]:
    family_indices = p4.feature_family_indices(host_features)
    imputed = SimpleImputer(strategy="median").fit_transform(host_matrix)
    scores = mutual_info_classif(imputed, labels, random_state=SEED)
    family_scores = {
        family: float(np.mean(scores[indices]))
        for family, indices in family_indices.items()
    }
    selected = sorted(family_scores, key=lambda family: (-family_scores[family], family))[:29]
    selected_indices = [
        index
        for index, feature in enumerate(host_features)
        if feature.rpartition("__")[0] in set(selected)
    ]
    if len(selected) != 29 or len(selected_indices) != 145:
        raise ValueError("Host selector must choose 29 complete families / 145 columns")
    return selected, selected_indices, family_scores


def model_pipeline() -> object:
    return make_pipeline(SimpleImputer(strategy="median"), random_forest())


def make_splits(labels: np.ndarray, groups: np.ndarray) -> list[tuple[np.ndarray, np.ndarray]]:
    splitter = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    splits = list(splitter.split(np.zeros((len(labels), 1)), labels, groups))
    for fold, (train, held_out) in enumerate(splits, start=1):
        if set(groups[train]) & set(groups[held_out]):
            raise ValueError(f"Training-only fold {fold} has group overlap")
        if set(labels[train]) != {0, 1}:
            raise ValueError(f"Training-only fold {fold} training partition is missing a class")
    return splits


def grouped_oof_main(
    records: list[dict],
    host_features: list[str],
    labels: np.ndarray,
    model_names: tuple[str, ...] = EXPECTED_MODELS,
) -> tuple[dict[str, np.ndarray], list[dict], list[dict]]:
    network_matrix = matrix(records, p4.P4_SAMPLE_FEATURES)
    host_matrix = matrix(records, host_features)
    groups = np.asarray([record["group_id"] for record in records])
    splits = make_splits(labels, groups)
    predictions = {name: np.full(len(records), np.nan) for name in model_names}
    selection_rows = []
    fold_rows = []

    for fold, (train, held_out) in enumerate(splits, start=1):
        y_train = labels[train]
        selected_families, selected_host, family_scores = feature_family_selection(
            host_matrix[train], y_train, host_features
        )
        selection_rows.extend(
            {
                "scope": "training_oof",
                "fold": fold,
                "family": family,
                "mean_mi_across_five_summaries": family_scores[family],
                "selected": int(family in set(selected_families)),
                "rank": rank,
            }
            for rank, family in enumerate(
                sorted(family_scores, key=lambda item: (-family_scores[item], item)),
                start=1,
            )
        )
        matrix_by_model = {
            "network_p4": (
                network_matrix[train],
                network_matrix[held_out],
            ),
            "host_29_families": (
                host_matrix[train][:, selected_host],
                host_matrix[held_out][:, selected_host],
            ),
            "hybrid_29_plus_29": (
                np.hstack((network_matrix[train], host_matrix[train][:, selected_host])),
                np.hstack((network_matrix[held_out], host_matrix[held_out][:, selected_host])),
            ),
        }
        for name in model_names:
            train_x, held_out_x = matrix_by_model[name]
            estimator = model_pipeline()
            estimator.fit(train_x, y_train)
            predictions[name][held_out] = estimator.predict_proba(held_out_x)[:, 1]
        fold_rows.append(
            {
                "fold": fold,
                "train_samples": len(train),
                "oof_samples": len(held_out),
                "train_groups": len(set(groups[train])),
                "oof_groups": len(set(groups[held_out])),
                "train_malware": int(np.count_nonzero(y_train == 1)),
                "train_benign": int(np.count_nonzero(y_train == 0)),
                "oof_malware": int(np.count_nonzero(labels[held_out] == 1)),
                "oof_benign": int(np.count_nonzero(labels[held_out] == 0)),
            }
        )

    if any(np.isnan(values).any() for values in predictions.values()):
        raise ValueError("Grouped training evaluation did not predict every training sample")
    return predictions, selection_rows, fold_rows


def grouped_oof_host(
    records: list[dict], host_features: list[str]
) -> tuple[np.ndarray, list[dict], list[dict]]:
    labels = np.asarray([record["label"] for record in records], dtype=int)
    groups = np.asarray([record["group_id"] for record in records])
    host_matrix = matrix(records, host_features)
    predictions = np.full(len(records), np.nan)
    selection_rows = []
    fold_rows = []
    for fold, (train, held_out) in enumerate(make_splits(labels, groups), start=1):
        selected_families, selected_indices, family_scores = feature_family_selection(
            host_matrix[train], labels[train], host_features
        )
        selection_rows.extend(
            {
                "scope": "host_all_eligible_training_oof",
                "fold": fold,
                "family": family,
                "mean_mi_across_five_summaries": family_scores[family],
                "selected": int(family in set(selected_families)),
                "rank": rank,
            }
            for rank, family in enumerate(
                sorted(family_scores, key=lambda item: (-family_scores[item], item)),
                start=1,
            )
        )
        estimator = model_pipeline()
        estimator.fit(host_matrix[train][:, selected_indices], labels[train])
        predictions[held_out] = estimator.predict_proba(
            host_matrix[held_out][:, selected_indices]
        )[:, 1]
        fold_rows.append({"fold": fold, "train_samples": len(train), "oof_samples": len(held_out)})
    if np.isnan(predictions).any():
        raise ValueError("Host-only sensitivity missed training OOF predictions")
    return predictions, selection_rows, fold_rows


def nuisance_rows(records: list[dict]) -> list[dict]:
    return [
        {
            "order_position": float(record["position"]),
            "execution_mode": record["mode"],
            "sample_return_code": str(record["return_code"]),
        }
        for record in records
    ]


def activity_matrix(records: list[dict]) -> np.ndarray:
    return np.log1p(
        np.asarray(
            [record["post_target_lineage_raw_syscalls"] for record in records], dtype=float
        )
    ).reshape(-1, 1)


def grouped_oof_auxiliary(records: list[dict], kind: str) -> tuple[np.ndarray, list[dict]]:
    labels = np.asarray([record["label"] for record in records], dtype=int)
    groups = np.asarray([record["group_id"] for record in records])
    predictions = np.full(len(records), np.nan)
    fold_rows = []
    for fold, (train, held_out) in enumerate(make_splits(labels, groups), start=1):
        if kind == "activity_only":
            train_x = activity_matrix(records)[train]
            held_out_x = activity_matrix(records)[held_out]
            estimator = model_pipeline()
        elif kind == "nuisance_only":
            vectorizer = DictVectorizer(sparse=False)
            feature_rows = nuisance_rows(records)
            train_x = vectorizer.fit_transform([feature_rows[index] for index in train])
            held_out_x = vectorizer.transform([feature_rows[index] for index in held_out])
            estimator = random_forest()
        else:
            raise ValueError(f"Unknown auxiliary model: {kind}")
        estimator.fit(train_x, labels[train])
        predictions[held_out] = estimator.predict_proba(held_out_x)[:, 1]
        fold_rows.append({"fold": fold, "train_samples": len(train), "oof_samples": len(held_out)})
    if np.isnan(predictions).any():
        raise ValueError(f"{kind} missed training OOF predictions")
    return predictions, fold_rows


def fit_final_models(
    train_records: list[dict],
    validation_records: list[dict],
    host_features: list[str],
    output_dir: Path,
    scope: str,
) -> tuple[dict[str, np.ndarray], list[dict], dict]:
    labels = np.asarray([record["label"] for record in train_records], dtype=int)
    network_train = matrix(train_records, p4.P4_SAMPLE_FEATURES)
    host_train = matrix(train_records, host_features)
    network_validation = matrix(validation_records, p4.P4_SAMPLE_FEATURES)
    host_validation = matrix(validation_records, host_features)
    selected_families, selected_indices, family_scores = feature_family_selection(
        host_train, labels, host_features
    )
    selection_rows = [
        {
            "scope": scope,
            "fold": "final_training_fit",
            "family": family,
            "mean_mi_across_five_summaries": family_scores[family],
            "selected": int(family in set(selected_families)),
            "rank": rank,
        }
        for rank, family in enumerate(
            sorted(family_scores, key=lambda item: (-family_scores[item], item)),
            start=1,
        )
    ]
    models = {
        "network_p4": (network_train, network_validation, "network_p4.joblib"),
        "host_29_families": (
            host_train[:, selected_indices],
            host_validation[:, selected_indices],
            "host_29_families.joblib",
        ),
        "hybrid_29_plus_29": (
            np.hstack((network_train, host_train[:, selected_indices])),
            np.hstack((network_validation, host_validation[:, selected_indices])),
            "hybrid_29_plus_29.joblib",
        ),
    }
    probabilities = {}
    for name, (train_x, validation_x, filename) in models.items():
        estimator = model_pipeline()
        estimator.fit(train_x, labels)
        probabilities[name] = estimator.predict_proba(validation_x)[:, 1]
        joblib.dump(estimator, output_dir / filename)
    details = {
        "selected_host_families": selected_families,
        "selected_host_features": [host_features[index] for index in selected_indices],
        "family_mutual_information": family_scores,
    }
    return probabilities, selection_rows, details


def fit_host_sensitivity(
    train_records: list[dict],
    validation_records: list[dict],
    host_features: list[str],
    output_dir: Path,
) -> tuple[np.ndarray, list[dict], dict]:
    train_x = matrix(train_records, host_features)
    validation_x = matrix(validation_records, host_features)
    labels = np.asarray([record["label"] for record in train_records], dtype=int)
    families, indices, scores = feature_family_selection(train_x, labels, host_features)
    estimator = model_pipeline()
    estimator.fit(train_x[:, indices], labels)
    probability = estimator.predict_proba(validation_x[:, indices])[:, 1]
    joblib.dump(estimator, output_dir / "host_29_all_eligible.joblib")
    rows = [
        {
            "scope": "host_all_eligible_final_training_fit",
            "fold": "final_training_fit",
            "family": family,
            "mean_mi_across_five_summaries": scores[family],
            "selected": int(family in set(families)),
            "rank": rank,
        }
        for rank, family in enumerate(
            sorted(scores, key=lambda item: (-scores[item], item)), start=1
        )
    ]
    return probability, rows, {"selected_host_families": families}


def fit_auxiliary_models(
    train_records: list[dict],
    validation_records: list[dict],
    output_dir: Path,
) -> dict[str, np.ndarray]:
    labels = np.asarray([record["label"] for record in train_records], dtype=int)
    probabilities = {}

    activity_train = activity_matrix(train_records)
    activity_validation = activity_matrix(validation_records)
    activity_model = model_pipeline()
    activity_model.fit(activity_train, labels)
    probabilities["activity_only"] = activity_model.predict_proba(activity_validation)[:, 1]
    joblib.dump(activity_model, output_dir / "activity_only.joblib")

    vectorizer = DictVectorizer(sparse=False)
    nuisance_train = vectorizer.fit_transform(nuisance_rows(train_records))
    nuisance_validation = vectorizer.transform(nuisance_rows(validation_records))
    nuisance_model = random_forest()
    nuisance_model.fit(nuisance_train, labels)
    probabilities["nuisance_only"] = nuisance_model.predict_proba(nuisance_validation)[:, 1]
    joblib.dump(
        {"vectorizer": vectorizer, "model": nuisance_model},
        output_dir / "nuisance_only.joblib",
    )
    return probabilities


def binary_metrics(
    labels: np.ndarray,
    probabilities: np.ndarray,
    sample_weight: np.ndarray | None = None,
) -> dict:
    predictions = (probabilities >= THRESHOLD).astype(int)
    matrix_values = confusion_matrix(
        labels, predictions, labels=[0, 1], sample_weight=sample_weight
    )
    tn, fp, fn, tp = matrix_values.ravel()
    return {
        "samples": int(len(labels)),
        "balanced_accuracy": float(
            balanced_accuracy_score(labels, predictions, sample_weight=sample_weight)
        ),
        "roc_auc": float(roc_auc_score(labels, probabilities, sample_weight=sample_weight)),
        "accuracy": float(accuracy_score(labels, predictions, sample_weight=sample_weight)),
        "precision_malware": float(
            precision_score(labels, predictions, sample_weight=sample_weight, zero_division=0)
        ),
        "recall_malware": float(
            recall_score(labels, predictions, sample_weight=sample_weight, zero_division=0)
        ),
        "confusion_matrix_tn_fp_fn_tp": [
            float(tn), float(fp), float(fn), float(tp)
        ],
    }


def equal_group_weights(records: list[dict]) -> np.ndarray:
    weights = np.zeros(len(records), dtype=float)
    labels = np.asarray([record["label"] for record in records])
    groups = np.asarray([record["group_id"] for record in records])
    for label in (0, 1):
        class_groups = sorted(set(groups[labels == label]))
        for group in class_groups:
            indices = np.flatnonzero((labels == label) & (groups == group))
            weights[indices] = 1.0 / len(class_groups) / len(indices)
    return weights


def bootstrap_weight_vectors(records: list[dict]) -> list[np.ndarray]:
    rng = np.random.default_rng(SEED)
    labels = np.asarray([record["label"] for record in records])
    groups = np.asarray([record["group_id"] for record in records])
    class_groups = {
        label: sorted(set(groups[labels == label])) for label in (0, 1)
    }
    vectors = []
    for _ in range(BOOTSTRAP_REPLICATES):
        weights = np.zeros(len(records), dtype=float)
        for label in (0, 1):
            values = class_groups[label]
            draws = rng.choice(values, size=len(values), replace=True)
            multiplicity = Counter(draws)
            for group, count in multiplicity.items():
                weights[groups == group] = float(count)
        vectors.append(weights)
    return vectors


def bootstrap_summary(
    labels: np.ndarray,
    probabilities: np.ndarray,
    weight_vectors: list[np.ndarray],
) -> dict:
    values = [binary_metrics(labels, probabilities, weights) for weights in weight_vectors]
    return {
        "replicates": len(values),
        "balanced_accuracy_95pct_cluster_bootstrap_interval": [
            float(np.quantile([row["balanced_accuracy"] for row in values], 0.025)),
            float(np.quantile([row["balanced_accuracy"] for row in values], 0.975)),
        ],
        "roc_auc_95pct_cluster_bootstrap_interval": [
            float(np.quantile([row["roc_auc"] for row in values], 0.025)),
            float(np.quantile([row["roc_auc"] for row in values], 0.975)),
        ],
    }


def group_permutation_null(
    records: list[dict], host_features: list[str], observed_training_ba: float
) -> dict:
    groups = sorted({record["group_id"] for record in records})
    group_labels = []
    for group in groups:
        values = {record["label"] for record in records if record["group_id"] == group}
        if len(values) != 1:
            raise ValueError(f"Group {group} contains mixed labels")
        group_labels.append(next(iter(values)))
    rng = np.random.default_rng(SEED)
    scores = []
    aucs = []
    rejected_assignments = 0
    attempts = 0
    while len(scores) < LABEL_PERMUTATIONS:
        attempts += 1
        if attempts > LABEL_PERMUTATIONS * 100:
            raise ValueError("Could not generate enough trainable grouped label permutations")
        permuted_group_labels = rng.permutation(group_labels)
        label_map = dict(zip(groups, permuted_group_labels, strict=True))
        labels = np.asarray([label_map[record["group_id"]] for record in records], dtype=int)
        group_array = np.asarray([record["group_id"] for record in records])
        try:
            make_splits(labels, group_array)
        except ValueError as error:
            if "training partition is missing a class" not in str(error):
                raise
            rejected_assignments += 1
            continue
        oof, _, _ = grouped_oof_main(
            records,
            host_features,
            labels,
            model_names=("hybrid_29_plus_29",),
        )
        scores.append(float(balanced_accuracy_score(labels, oof["hybrid_29_plus_29"] >= THRESHOLD)))
        aucs.append(float(roc_auc_score(labels, oof["hybrid_29_plus_29"])))
        if len(scores) % 10 == 0:
            print(f"Completed {len(scores)}/{LABEL_PERMUTATIONS} training-only group permutations", flush=True)
    return {
        "method": "permute labels among training groups; preserve each group as a unit; grouped OOF only",
        "permutations": LABEL_PERMUTATIONS,
        "assignments_attempted": attempts,
        "untrainable_assignments_rejected": rejected_assignments,
        "training_groups": len(groups),
        "malware_groups_before_permutation": sum(label == 1 for label in group_labels),
        "observed_hybrid_training_oof_balanced_accuracy": observed_training_ba,
        "null_balanced_accuracy_mean": float(np.mean(scores)),
        "null_balanced_accuracy_95pct_interval": [
            float(np.quantile(scores, 0.025)), float(np.quantile(scores, 0.975))
        ],
        "null_roc_auc_mean": float(np.mean(aucs)),
        "null_roc_auc_95pct_interval": [
            float(np.quantile(aucs, 0.025)), float(np.quantile(aucs, 0.975))
        ],
        "empirical_upper_tail_p": float(
            (1 + np.count_nonzero(np.asarray(scores) >= observed_training_ba))
            / (LABEL_PERMUTATIONS + 1)
        ),
        "individual_null_scores": scores,
    }


def save_predictions(
    path: Path,
    records: list[dict],
    probabilities: dict[str, np.ndarray],
    scope: str,
) -> list[dict]:
    rows = []
    for model_name, values in probabilities.items():
        predictions = (values >= THRESHOLD).astype(int)
        for record, probability, prediction in zip(records, values, predictions, strict=True):
            rows.append(
                {
                    "scope": scope,
                    "model": model_name,
                    "sample": record["sample"],
                    "split": record["split"],
                    "label": record["label"],
                    "group_id": record["group_id"],
                    "mode": record["mode"],
                    "return_code": record["return_code"],
                    "position": record["position"],
                    "post_target_lineage_raw_syscalls": record[
                        "post_target_lineage_raw_syscalls"
                    ],
                    "probability_malware": float(probability),
                    "prediction": int(prediction),
                }
            )
    if rows:
        write_csv(path, rows, list(rows[0]))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ANALYSIS_DIR / "model-fit-r3",
        help="New output directory; existing results are never overwritten.",
    )
    args = parser.parse_args()
    rows, common, host_features, preparation = load_data()
    training, validation = split_indices(common)
    common_train = [common[index] for index in training]
    common_validation = [common[index] for index in validation]
    all_train_indices, all_validation_indices = split_indices(rows)
    all_train = [rows[index] for index in all_train_indices]
    all_validation = [rows[index] for index in all_validation_indices]

    if {key: preparation["common_aligned_counts"]["validation"][key] for key in ("benign", "malware")} != {
        "benign": 30,
        "malware": 27,
    }:
        raise ValueError("Validation cohort counts differ from the prepared audit")
    if sha256(ANALYSIS_DIR / "preparation_audit.json") != sha256(PREPARATION_PATH):
        raise ValueError("Preparation audit is not readable")
    prep = json.loads(PREPARATION_PATH.read_text(encoding="utf-8"))
    if sha256(ANALYSIS_DIR / "eligible_dataset.csv") == "":
        raise ValueError("Prepared model dataset is missing")
    if prep["p4_extractor_sha256"] != sha256(P4_DIR / "analyze_p4_pcap_ablation.py"):
        raise ValueError("P4 extractor changed after the eligibility audit")
    if prep["host_feature_contract_sha256"] != sha256(HOST_FEATURE_PATH):
        raise ValueError("Host feature contract changed after the eligibility audit")
    if prep["collection_validation_sha256"] != sha256(ATTEMPT_DIR / "collection_validation.json"):
        raise ValueError("Collection audit changed after preparation")

    output_dir = args.output_dir.expanduser().resolve()
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing model results: {output_dir}")
    model_dir = output_dir / "models"
    model_dir.mkdir(parents=True)

    training_labels = np.asarray([record["label"] for record in common_train], dtype=int)
    training_groups = np.asarray([record["group_id"] for record in common_train])
    oof_probabilities, selection_rows, fold_rows = grouped_oof_main(
        common_train, host_features, training_labels
    )
    actual_oof_metrics = {
        name: binary_metrics(training_labels, probabilities)
        for name, probabilities in oof_probabilities.items()
    }

    host_all_oof, host_all_selection, host_all_folds = grouped_oof_host(
        all_train, host_features
    )
    all_train_labels = np.asarray([record["label"] for record in all_train], dtype=int)
    activity_oof, activity_folds = grouped_oof_auxiliary(common_train, "activity_only")
    nuisance_oof, nuisance_folds = grouped_oof_auxiliary(common_train, "nuisance_only")
    training_oof = {
        **oof_probabilities,
        "host_29_all_eligible_sensitivity": host_all_oof,
        "activity_only": activity_oof,
        "nuisance_only": nuisance_oof,
    }
    train_oof_records = save_predictions(
        output_dir / "training_grouped_oof_predictions.csv",
        common_train,
        {name: oof_probabilities[name] for name in EXPECTED_MODELS},
        "common_aligned_training_oof",
    )
    host_sensitivity_oof_rows = save_predictions(
        output_dir / "host_sensitivity_training_oof_predictions.csv",
        all_train,
        {"host_29_all_eligible_sensitivity": host_all_oof},
        "all_eligible_training_oof",
    )
    auxiliary_oof_rows = save_predictions(
        output_dir / "auxiliary_training_oof_predictions.csv",
        common_train,
        {"activity_only": activity_oof, "nuisance_only": nuisance_oof},
        "common_aligned_training_oof",
    )

    validation_probabilities, final_selection_rows, final_details = fit_final_models(
        common_train,
        common_validation,
        host_features,
        model_dir,
        "common_aligned_final_training_fit",
    )
    host_sensitivity_probability, host_sensitivity_selection, host_sensitivity_details = fit_host_sensitivity(
        all_train,
        all_validation,
        host_features,
        model_dir,
    )
    auxiliary_validation = fit_auxiliary_models(common_train, common_validation, model_dir)
    primary_validation_probabilities = {**validation_probabilities, **auxiliary_validation}
    validation_labels = np.asarray([record["label"] for record in common_validation], dtype=int)
    save_predictions(
        output_dir / "validation_predictions.csv",
        common_validation,
        primary_validation_probabilities,
        "frozen_validation_scored_once",
    )
    validation_metrics = {
        name: binary_metrics(validation_labels, probabilities)
        for name, probabilities in primary_validation_probabilities.items()
    }
    validation_group_weights = equal_group_weights(common_validation)
    validation_group_weighted = {
        name: binary_metrics(validation_labels, probabilities, validation_group_weights)
        for name, probabilities in primary_validation_probabilities.items()
    }
    bootstrap_weights = bootstrap_weight_vectors(common_validation)
    bootstrap_results = {
        name: bootstrap_summary(validation_labels, probabilities, bootstrap_weights)
        for name, probabilities in primary_validation_probabilities.items()
    }
    host_sensitivity_labels = np.asarray(
        [record["label"] for record in all_validation], dtype=int
    )
    host_sensitivity_validation_metrics = binary_metrics(
        host_sensitivity_labels, host_sensitivity_probability
    )
    host_sensitivity_group_weights = equal_group_weights(all_validation)
    host_sensitivity_group_weighted = binary_metrics(
        host_sensitivity_labels,
        host_sensitivity_probability,
        host_sensitivity_group_weights,
    )
    host_sensitivity_bootstrap = bootstrap_summary(
        host_sensitivity_labels,
        host_sensitivity_probability,
        bootstrap_weight_vectors(all_validation),
    )
    save_predictions(
        output_dir / "host_only_all_eligible_validation_predictions.csv",
        all_validation,
        {"host_29_all_eligible_sensitivity": host_sensitivity_probability},
        "host_only_all_quality_accepted_target_observed_validation",
    )

    linkage_metrics = {}
    for mode in sorted({record["mode"] for record in common_validation}):
        indices = [index for index, record in enumerate(common_validation) if record["mode"] == mode]
        labels = validation_labels[indices]
        linkage_metrics[mode] = {
            "samples": len(indices),
            "benign": int(np.count_nonzero(labels == 0)),
            "malware": int(np.count_nonzero(labels == 1)),
            "models": {},
        }
        if set(labels) == {0, 1}:
            for name, probabilities in primary_validation_probabilities.items():
                linkage_metrics[mode]["models"][name] = binary_metrics(
                    labels, probabilities[indices]
                )
        else:
            linkage_metrics[mode]["note"] = "Both classes are required for preregistered metrics."

    permutation_result = group_permutation_null(
        common_train,
        host_features,
        actual_oof_metrics["hybrid_29_plus_29"]["balanced_accuracy"],
    )

    selection_rows.extend(final_selection_rows)
    selection_rows.extend(host_all_selection)
    selection_rows.extend(host_sensitivity_selection)
    write_csv(
        output_dir / "host_family_selection.csv",
        selection_rows,
        list(selection_rows[0]),
    )
    write_csv(output_dir / "grouped_training_folds.csv", fold_rows, list(fold_rows[0]))
    write_csv(
        output_dir / "host_sensitivity_training_folds.csv",
        host_all_folds,
        list(host_all_folds[0]),
    )
    permutation_path = output_dir / "training_group_label_permutations.json"
    permutation_path.write_text(json.dumps(permutation_result, indent=2) + "\n", encoding="utf-8")

    metrics = {
        "status": "complete",
        "evaluation_protocol": {
            "frozen_split": "70 malware + 70 benign training; 30 malware + 30 benign validation, with whole signature/project groups disjoint",
            "primary_population": "quality-accepted, target-exec-observed, uniquely P4-aligned; low-activity cases retained",
            "validation_tuning": "none; all feature selection and model fitting use training records only",
            "threshold": THRESHOLD,
            "training_grouped_cv": {"folds": FOLDS, "seed": SEED},
            "random_forest": {
                "n_estimators": 500,
                "class_weight": "balanced",
                "random_state": SEED,
                "n_jobs": 1,
                "other_parameters": "scikit-learn defaults",
            },
        },
        "data_provenance": {
            "collection_validation_sha256": prep["collection_validation_sha256"],
            "preparation_audit_sha256": sha256(PREPARATION_PATH),
            "prepared_dataset_sha256": sha256(DATASET_PATH),
            "preregistration_sha256": sha256(PREREGISTRATION_PATH),
            "runner_schema": "2026-10-20.18",
            "runner_sha256": RUNNER_SHA256,
            "p4_source": "offline PCAP reconstruction; captured Ethernet bytes; nominal 0.5-second rates",
        },
        "excluded": {
            "quality_rejected_records": 1,
            "unretrieved_records": 2,
            "target_exec_not_observed_records": 3,
            "nonunique_p4_alignment_from_host_eligible": 18,
            "low_activity_records": 0,
            "null_controls": 6,
        },
        "sample_counts": {
            "common_aligned_training": {
                "total": len(common_train),
                "benign": int(np.count_nonzero(training_labels == 0)),
                "malware": int(np.count_nonzero(training_labels == 1)),
                "groups": len(set(record["group_id"] for record in common_train)),
            },
            "common_aligned_validation": {
                "total": len(common_validation),
                "benign": int(np.count_nonzero(validation_labels == 0)),
                "malware": int(np.count_nonzero(validation_labels == 1)),
                "groups": len(set(record["group_id"] for record in common_validation)),
            },
            "host_only_all_eligible_training": {
                "total": len(all_train),
                "benign": int(np.count_nonzero(all_train_labels == 0)),
                "malware": int(np.count_nonzero(all_train_labels == 1)),
            },
            "host_only_all_eligible_validation": {
                "total": len(all_validation),
                "benign": sum(record["label"] == 0 for record in all_validation),
                "malware": sum(record["label"] == 1 for record in all_validation),
            },
        },
        "feature_contract": {
            "network_p4_columns": 145,
            "host_candidate_families": 35,
            "host_selected_families": 29,
            "host_columns": 145,
            "hybrid_columns": 290,
            "host_selection": "training-only mutual information averaged across five summaries; refit per grouped fold and on full training split",
        },
        "training_grouped_oof": {
            "primary_models": actual_oof_metrics,
            "host_only_all_eligible_sensitivity": binary_metrics(all_train_labels, host_all_oof),
            "activity_only": binary_metrics(training_labels, activity_oof),
            "nuisance_only": binary_metrics(training_labels, nuisance_oof),
        },
        "held_out_validation": {
            "metrics": validation_metrics,
            "group_weighted_metrics": validation_group_weighted,
            "cluster_bootstrap": bootstrap_results,
            "by_linkage": linkage_metrics,
            "activity_or_nuisance_claim_gate_triggered": (
                validation_metrics["activity_only"]["balanced_accuracy"] >= 0.75
                or validation_metrics["nuisance_only"]["balanced_accuracy"] >= 0.75
            ),
            "host_only_all_eligible_sensitivity": {
                "metrics": host_sensitivity_validation_metrics,
                "group_weighted_metrics": host_sensitivity_group_weighted,
                "cluster_bootstrap": host_sensitivity_bootstrap,
            },
        },
        "training_only_group_label_permutation": permutation_result,
        "selected_host_families_final_primary_fit": final_details["selected_host_families"],
        "selected_host_families_all_eligible_sensitivity": host_sensitivity_details[
            "selected_host_families"
        ],
        "fold_audits": {
            "common_aligned": fold_rows,
            "host_only_all_eligible": host_all_folds,
            "activity_only": activity_folds,
            "nuisance_only": nuisance_folds,
        },
        "model_files": sorted(path.name for path in model_dir.glob("*.joblib")),
        "limitations": [
            "This is a small, purposively selected native-x86-64 cohort; held-out signatures/projects are disjoint but the split is not a blind external test.",
            "Malware source labels are acquisition labels, not independently verified malicious behavior.",
            "P4 features are offline PCAP reconstructions, not live-switch measurements.",
            "One training malware output was quality-rejected and one training plus one validation malware output were not retrieved; no retry or replacement was performed.",
            "The host-only all-eligible sensitivity has a different sample set from the primary P4/hybrid comparison.",
            "Confidence intervals with nine validation malware groups are expected to be wide; report them with the point estimates.",
        ],
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (output_dir / "feature_selection.json").write_text(
        json.dumps(
            {
                "primary_final_fit": final_details,
                "host_only_all_eligible_sensitivity": host_sensitivity_details,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    model_hashes = {
        path.name: sha256(path) for path in sorted(model_dir.glob("*.joblib"))
    }
    (output_dir / "model_sha256.json").write_text(
        json.dumps(model_hashes, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "output_dir": str(output_dir),
        "sample_counts": metrics["sample_counts"],
        "training_grouped_oof": metrics["training_grouped_oof"],
        "held_out_validation": {
            name: value["balanced_accuracy"]
            for name, value in validation_metrics.items()
        },
        "activity_or_nuisance_claim_gate_triggered": metrics["held_out_validation"][
            "activity_or_nuisance_claim_gate_triggered"
        ],
        "model_files": model_hashes,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())