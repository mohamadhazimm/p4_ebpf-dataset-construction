#!/usr/bin/env python3
"""Train one grouped-CV classifier shared by P4-only, eBPF-only, and hybrid arms."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from src.train_compare import class_names_for, make_model, metrics_for, numeric_matrix


ARMS = ("p4_only", "ebpf_only", "hybrid")
AVAILABILITY_FEATURES = (
    "arm__network_available",
    "arm__host_available",
)
METRIC_KEYS = (
    "accuracy",
    "balanced_accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "benign_false_positive_rate",
    "malware_miss_rate",
)
THRESHOLD = 0.5


def load_schema(path: Path) -> dict[str, list[str]]:
    feature_sets = json.loads(path.read_text(encoding="utf-8"))
    for name in ("network", "host", "hybrid"):
        names = feature_sets.get(name)
        if not isinstance(names, list) or not names or not all(
            isinstance(feature, str) and feature for feature in names
        ):
            raise ValueError(f"Feature schema must contain a non-empty {name!r} list")
        if len(names) != len(set(names)):
            raise ValueError(f"Feature schema contains duplicate names in {name!r}")

    network = feature_sets["network"]
    host = feature_sets["host"]
    hybrid = feature_sets["hybrid"]
    if set(network).intersection(host):
        raise ValueError("Network and host feature groups overlap")
    if set(hybrid) != set(network).union(host):
        raise ValueError("Hybrid features must be the union of network and host features")
    return {name: feature_sets[name] for name in ("network", "host", "hybrid")}


def load_examples(dataset_path: Path, feature_sets: dict[str, list[str]]) -> list[dict[str, str]]:
    with dataset_path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise ValueError(f"Dataset has no CSV header: {dataset_path}")
        missing = set(feature_sets["hybrid"]) - set(reader.fieldnames)
        required = {"label", "group_id", "class_name", "sample_artifact"}
        missing.update(required - set(reader.fieldnames))
        if missing:
            raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")
        examples = list(reader)

    if not examples:
        raise ValueError(f"Dataset has no sample rows: {dataset_path}")
    labels = {int(example["label"]) for example in examples}
    if labels != {0, 1}:
        raise ValueError("Dataset must contain both binary labels 0 and 1")
    if any(not example["group_id"].strip() for example in examples):
        raise ValueError("Every sample must have a non-empty group_id")
    class_names_for(examples)
    return examples


def augment_modalities(
    examples: list[dict[str, str]],
    feature_sets: dict[str, list[str]],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, list[str]]:
    """Create three arm views per sample while preserving its original group."""
    base_features = numeric_matrix(examples, feature_sets["hybrid"])
    network_indexes = [feature_sets["hybrid"].index(name) for name in feature_sets["network"]]
    host_indexes = [feature_sets["hybrid"].index(name) for name in feature_sets["host"]]

    rows: list[np.ndarray] = []
    labels: list[int] = []
    groups: list[str] = []
    arm_names: list[str] = []

    for index, example in enumerate(examples):
        for arm in ARMS:
            values = base_features[index].copy()
            network_available = arm != "ebpf_only"
            host_available = arm != "p4_only"

            if not network_available:
                values[network_indexes] = 0.0
            if not host_available:
                values[host_indexes] = 0.0

            rows.append(
                np.concatenate(
                    (
                        values,
                        np.asarray(
                            [float(network_available), float(host_available)],
                            dtype=float,
                        ),
                    )
                )
            )
            labels.append(int(example["label"]))
            groups.append(example["group_id"])
            arm_names.append(arm)

    return (
        np.vstack(rows),
        np.asarray(labels, dtype=int),
        np.asarray(groups, dtype=str),
        np.asarray(arm_names, dtype=str),
        feature_sets["hybrid"] + list(AVAILABILITY_FEATURES),
    )


def metrics_with_class_errors(
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float = THRESHOLD,
) -> dict[str, float | int]:
    predictions = (probabilities >= threshold).astype(int)
    result = metrics_for(labels, predictions, probabilities)
    true_negatives = int(result["tn"])
    false_positives = int(result["fp"])
    false_negatives = int(result["fn"])
    true_positives = int(result["tp"])
    result["benign_false_positive_rate"] = (
        false_positives / (true_negatives + false_positives)
        if true_negatives + false_positives
        else 0.0
    )
    result["malware_miss_rate"] = (
        false_negatives / (false_negatives + true_positives)
        if false_negatives + true_positives
        else 0.0
    )
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_output_dir(path: Path) -> None:
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(f"Refusing to overwrite non-empty output directory: {path}")
    path.mkdir(parents=True, exist_ok=True)


def train_and_evaluate(
    dataset_path: Path,
    feature_columns_path: Path,
    output_dir: Path,
    folds: int = 5,
    seed: int = 42,
) -> dict[str, Any]:
    feature_sets = load_schema(feature_columns_path)
    examples = load_examples(dataset_path, feature_sets)
    features, labels, groups, arms, feature_names = augment_modalities(
        examples, feature_sets
    )
    if folds < 2 or folds > len(set(groups.tolist())):
        raise ValueError("Fold count must be between 2 and the number of groups")

    splits = list(
        StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed).split(
            features, labels, groups
        )
    )
    for fold_number, (_, test_indexes) in enumerate(splits, start=1):
        if set(labels[test_indexes].tolist()) != {0, 1}:
            raise ValueError(f"Fold {fold_number} contains only one class")
    prepare_output_dir(output_dir)

    out_of_fold_probabilities = np.full(len(labels), np.nan, dtype=float)
    out_of_fold_folds = np.zeros(len(labels), dtype=int)
    fold_metrics: dict[str, list[dict[str, float | int]]] = {
        arm: [] for arm in ARMS
    }

    for fold_number, (train_indexes, test_indexes) in enumerate(splits, start=1):
        model = make_model(seed + fold_number)
        model.fit(features[train_indexes], labels[train_indexes])
        positive_index = int(np.flatnonzero(model[-1].classes_ == 1)[0])
        probabilities = model.predict_proba(features[test_indexes])[:, positive_index]
        out_of_fold_probabilities[test_indexes] = probabilities
        out_of_fold_folds[test_indexes] = fold_number

        test_arms = arms[test_indexes]
        for arm in ARMS:
            arm_mask = test_arms == arm
            fold_metrics[arm].append(
                metrics_with_class_errors(
                    labels[test_indexes][arm_mask], probabilities[arm_mask]
                )
            )

    if np.isnan(out_of_fold_probabilities).any():
        raise RuntimeError("Some augmented samples did not receive an out-of-fold prediction")

    summary: dict[str, Any] = {
        "dataset": str(dataset_path.resolve()),
        "dataset_sha256": sha256_file(dataset_path),
        "feature_columns": str(feature_columns_path.resolve()),
        "feature_columns_sha256": sha256_file(feature_columns_path),
        "original_samples": len(examples),
        "augmented_rows": len(labels),
        "groups": len(set(groups.tolist())),
        "folds": folds,
        "splitter": "StratifiedGroupKFold; all arm views of each group stay in one fold",
        "random_seed": seed,
        "threshold": THRESHOLD,
        "positive_label": "malware",
        "classifier": {
            "estimator": "RandomForestClassifier",
            "n_estimators": 500,
            "max_features": "sqrt",
            "min_samples_leaf": 2,
            "class_weight": "balanced_subsample",
            "imputer": "median",
        },
        "feature_count": len(feature_names),
        "modality_availability_features": list(AVAILABILITY_FEATURES),
        "arms": {},
    }

    for arm in ARMS:
        arm_mask = arms == arm
        probabilities = out_of_fold_probabilities[arm_mask]
        arm_labels = labels[arm_mask]
        pooled = metrics_with_class_errors(arm_labels, probabilities)
        metrics = fold_metrics[arm]
        summary["arms"][arm] = {
            "rows": int(arm_mask.sum()),
            "active_feature_count": (
                len(feature_sets["network"])
                if arm == "p4_only"
                else len(feature_sets["host"])
                if arm == "ebpf_only"
                else len(feature_sets["hybrid"])
            ),
            "pooled_oof": pooled,
            "fold_mean": {
                key: float(np.mean([fold[key] for fold in metrics]))
                for key in METRIC_KEYS
            },
            "fold_std": {
                key: float(np.std([fold[key] for fold in metrics], ddof=1))
                for key in METRIC_KEYS
            },
            "fold_metrics": metrics,
        }

    class_names = class_names_for(examples)
    final_model = make_model(seed)
    final_model.fit(features, labels)
    bundle = {
        "model": final_model,
        "feature_set": "shared_arm_masked_hybrid",
        "feature_names": feature_names,
        "network_feature_names": feature_sets["network"],
        "host_feature_names": feature_sets["host"],
        "modality_availability_features": list(AVAILABILITY_FEATURES),
        "arms": list(ARMS),
        "positive_label": class_names[1],
        "threshold": THRESHOLD,
        "random_seed": seed,
        "training_method": "grouped cross-validation with modality-masked arm augmentation",
    }

    model_path = output_dir / "random_forest_shared_arm.joblib"
    joblib.dump(bundle, model_path)
    summary["model_path"] = str(model_path.resolve())
    summary["model_sha256"] = sha256_file(model_path)

    (output_dir / "cv_metrics.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "feature_schema.json").write_text(
        json.dumps(
            {
                "feature_names": feature_names,
                "network_feature_names": feature_sets["network"],
                "host_feature_names": feature_sets["host"],
                "modality_availability_features": list(AVAILABILITY_FEATURES),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    prediction_rows = []
    for index, example in enumerate(examples):
        for arm_index, arm in enumerate(ARMS):
            augmented_index = index * len(ARMS) + arm_index
            probability = float(out_of_fold_probabilities[augmented_index])
            prediction_rows.append(
                {
                    "sample_artifact": example["sample_artifact"],
                    "group_id": example["group_id"],
                    "label": int(example["label"]),
                    "class_name": example["class_name"],
                    "arm": arm,
                    "fold": int(out_of_fold_folds[augmented_index]),
                    "probability_malware": probability,
                    "prediction": int(probability >= THRESHOLD),
                }
            )
    with (output_dir / "out_of_fold_predictions.csv").open(
        "w", newline="", encoding="utf-8"
    ) as destination:
        writer = csv.DictWriter(destination, fieldnames=list(prediction_rows[0]))
        writer.writeheader()
        writer.writerows(prediction_rows)

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--feature-columns", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    for path in (args.dataset, args.feature_columns):
        if not path.is_file():
            parser.error(f"Input file does not exist: {path}")

    output_dir = args.output_dir
    if output_dir is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_dir = (
            args.dataset.parent / "models" / f"shared-arm-masked-{timestamp}"
        )

    summary = train_and_evaluate(
        args.dataset,
        args.feature_columns,
        output_dir,
        folds=args.folds,
        seed=args.seed,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
