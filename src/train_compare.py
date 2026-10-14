#!/usr/bin/env python3
"""Compare network-only, host-only, and hybrid random forests."""

from __future__ import annotations

import argparse
import csv
import json
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
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline


def metrics_for(y_true, y_pred, y_score) -> dict[str, float | int]:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = matrix.ravel()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "tn": int(true_negative),
        "fp": int(false_positive),
        "fn": int(false_negative),
        "tp": int(true_positive),
    }


def class_names_for(examples):
    class_names = {}
    for example in examples:
        label = int(example["label"])
        class_name = example.get("class_name") or ("benign" if label == 0 else "malware")
        previous_name = class_names.setdefault(label, class_name)
        if previous_name != class_name:
            raise ValueError(f"Class label {label} maps to multiple class names")
    return class_names


def load_examples(dataset_path: Path, feature_path: Path):
    with dataset_path.open(newline="", encoding="utf-8-sig") as source:
        examples = list(csv.DictReader(source))
    feature_sets = json.loads(feature_path.read_text(encoding="utf-8"))
    if not examples:
        raise ValueError(f"No sample rows in {dataset_path}")
    labels = np.asarray([int(row["label"]) for row in examples], dtype=int)
    groups = np.asarray([row["group_id"] for row in examples], dtype=str)
    return examples, feature_sets, labels, groups


def numeric_matrix(examples, feature_names):
    matrix = np.empty((len(examples), len(feature_names)), dtype=float)
    matrix.fill(np.nan)
    for row_index, row in enumerate(examples):
        for column_index, name in enumerate(feature_names):
            value = row.get(name, "")
            if value != "":
                try:
                    matrix[row_index, column_index] = float(value)
                except ValueError:
                    pass
    return matrix


def make_model(seed: int):
    forest = RandomForestClassifier(
        n_estimators=500,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=seed,
        n_jobs=-1,
    )
    return make_pipeline(SimpleImputer(strategy="median"), forest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--feature-columns", type=Path)
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--models-dir", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    feature_path = args.feature_columns or args.dataset.with_name(
        args.dataset.stem + ".feature_columns.json"
    )
    examples, feature_sets, labels, groups = load_examples(args.dataset, feature_path)
    if set(labels.tolist()) != {0, 1}:
        parser.error("dataset must contain samples for both class labels 0 and 1")
    class_names = class_names_for(examples)
    if args.folds < 2 or args.folds > len(set(groups)):
        parser.error("fold count must be between 2 and the number of independent groups")

    splits = list(
        StratifiedGroupKFold(
            n_splits=args.folds, shuffle=True, random_state=args.seed
        ).split(np.zeros((len(labels), 1)), labels, groups)
    )
    for fold_index, (_, test_indices) in enumerate(splits, start=1):
        if len(set(labels[test_indices])) != 2:
            raise ValueError(f"Fold {fold_index} contains only one class; reduce folds or add data")

    args.reports_dir.mkdir(parents=True, exist_ok=True)
    args.models_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "dataset": str(args.dataset.resolve()),
        "samples": len(examples),
        "class_counts": {
            class_names[0]: int((labels == 0).sum()),
            class_names[1]: int((labels == 1).sum()),
        },
        "folds": args.folds,
        "splitter": "StratifiedGroupKFold; all samples sharing group_id stay in one fold",
        "random_seed": args.seed,
        "feature_sets": {},
    }
    prediction_rows = []
    importance_rows = []
    metrics_rows = []

    for feature_set_name in ("network", "host", "hybrid"):
        feature_names = feature_sets[feature_set_name]
        matrix = numeric_matrix(examples, feature_names)
        probabilities = np.full(len(labels), np.nan, dtype=float)
        fold_ids = np.zeros(len(labels), dtype=int)
        fold_metrics = []

        for fold_index, (train_indices, test_indices) in enumerate(splits, start=1):
            model = make_model(args.seed + fold_index)
            model.fit(matrix[train_indices], labels[train_indices])
            fold_probabilities = model.predict_proba(matrix[test_indices])[:, 1]
            fold_predictions = (fold_probabilities >= 0.5).astype(int)
            probabilities[test_indices] = fold_probabilities
            fold_ids[test_indices] = fold_index
            fold_metrics.append(
                metrics_for(labels[test_indices], fold_predictions, fold_probabilities)
            )

        if np.isnan(probabilities).any():
            raise RuntimeError(f"Not all samples received out-of-fold predictions for {feature_set_name}")
        predictions = (probabilities >= 0.5).astype(int)
        pooled_metrics = metrics_for(labels, predictions, probabilities)
        means = {
            key: float(np.mean([fold[key] for fold in fold_metrics]))
            for key in ("accuracy", "balanced_accuracy", "precision", "recall", "f1", "roc_auc")
        }
        deviations = {
            key: float(np.std([fold[key] for fold in fold_metrics], ddof=1))
            for key in means
        }
        summary["feature_sets"][feature_set_name] = {
            "feature_count": len(feature_names),
            "pooled_oof": pooled_metrics,
            "fold_mean": means,
            "fold_std": deviations,
            "fold_metrics": fold_metrics,
        }
        metrics_rows.append(
            {
                "feature_set": feature_set_name,
                "feature_count": len(feature_names),
                **pooled_metrics,
                **{f"fold_mean_{key}": value for key, value in means.items()},
                **{f"fold_std_{key}": value for key, value in deviations.items()},
            }
        )
        for index, example in enumerate(examples):
            prediction_rows.append(
                {
                    "feature_set": feature_set_name,
                    "sample_artifact": example["sample_artifact"],
                    "class_name": example["class_name"],
                    "label": labels[index],
                    "fold": fold_ids[index],
                    "probability_malware": probabilities[index],
                    "prediction": predictions[index],
                }
            )

        final_model = make_model(args.seed)
        final_model.fit(matrix, labels)
        bundle = {
            "model": final_model,
            "feature_set": feature_set_name,
            "feature_names": feature_names,
            "positive_label": class_names[1],
            "threshold": 0.5,
            "random_seed": args.seed,
        }
        joblib.dump(bundle, args.models_dir / f"random_forest_{feature_set_name}.joblib")
        forest = final_model[-1]
        for feature_name, importance in zip(feature_names, forest.feature_importances_, strict=True):
            importance_rows.append(
                {"feature_set": feature_set_name, "feature": feature_name, "importance": importance}
            )

    (args.reports_dir / "cv_metrics.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    for filename, rows in (
        ("cv_metrics.csv", metrics_rows),
        ("out_of_fold_predictions.csv", prediction_rows),
        ("feature_importance.csv", importance_rows),
    ):
        if rows:
            with (args.reports_dir / filename).open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())