#!/usr/bin/env python3
"""Evaluate attack-type-stratified training with benign package-group holdout."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from train_compare import make_model, metrics_for, numeric_matrix


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT / "data/malware/revision4/training521_holdout461_20261017"
DEFAULT_OUTPUT_DIR = DEFAULT_DATA_DIR / "attack_type_split_20pct_seed42"
HASH_PATTERN = __import__("re").compile(r"^[0-9a-f]{64}$")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def sample_hash(artifact: str) -> str:
    digest = Path(artifact).stem.lower()
    if not HASH_PATTERN.fullmatch(digest):
        raise ValueError(f"Malware artifact does not have a SHA-256 filename: {artifact}")
    return digest


def multiclass_metrics(y_true, y_pred, probabilities, classes: list[str]) -> dict:
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, zero_division=0
    )
    result = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_precision": float(np.mean(precision)),
        "macro_recall": float(np.mean(recall)),
        "macro_f1": float(np.mean(f1)),
        "weighted_f1": float(
            precision_recall_fscore_support(
                y_true, y_pred, labels=classes, average="weighted", zero_division=0
            )[2]
        ),
        "classes": classes,
        "confusion_matrix_labels": classes,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=classes).tolist(),
        "per_class": {},
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
    try:
        result["macro_ovr_roc_auc"] = float(
            roc_auc_score(
                y_true,
                probabilities,
                labels=classes,
                multi_class="ovr",
                average="macro",
            )
        )
    except ValueError:
        result["macro_ovr_roc_auc"] = None
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--labels", type=Path)
    parser.add_argument("--feature-columns", type=Path)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--attack-train-fraction", type=float, default=0.2)
    args = parser.parse_args(argv)
    if not 0 < args.attack_train_fraction < 0.5:
        parser.error("--attack-train-fraction must be greater than 0 and less than 0.5")

    labels_path = args.labels or args.data_dir / "malware_hash_labels.csv"
    feature_path = args.feature_columns or args.data_dir / "train_dataset.feature_columns.json"
    source_paths = {
        "training": args.data_dir / "train_dataset.csv",
        "validation": args.data_dir / "test_dataset.csv",
    }
    source_rows = [
        (split_name, row)
        for split_name, path in source_paths.items()
        for row in read_csv(path)
    ]
    label_rows = read_csv(labels_path)
    captured_labels = {
        row["sha256"].lower(): row
        for row in label_rows
        if row["telemetry_model_membership"] in {"training", "holdout"}
    }
    source_hashes = {
        sample_hash(row["sample_artifact"])
        for _, row in source_rows
        if row["label"] == "1"
    }
    if source_hashes != set(captured_labels):
        missing = source_hashes - set(captured_labels)
        unused = set(captured_labels) - source_hashes
        raise ValueError(
            f"Captured malware labels do not exactly match feature hashes; "
            f"missing={len(missing)}, unused={len(unused)}"
        )

    examples: list[dict[str, str]] = []
    artifacts: set[str] = set()
    for original_split, source_row in source_rows:
        artifact = source_row["sample_artifact"]
        if artifact in artifacts:
            raise ValueError(f"Duplicate sample in feature datasets: {artifact}")
        artifacts.add(artifact)
        row = dict(source_row)
        row["original_dataset_split"] = original_split
        if row["label"] == "1":
            digest = sample_hash(artifact)
            label = captured_labels[digest]
            row["sha256"] = digest
            row["family_label"] = label["family_label"]
            row["attack_type"] = label["attack_type"]
            row["multiclass_label"] = label["attack_type"]
        elif row["label"] == "0":
            if not row.get("package_group", "").strip():
                raise ValueError(f"Benign sample lacks package_group: {artifact}")
            row["sha256"] = ""
            row["family_label"] = "benign"
            row["attack_type"] = "benign"
            row["multiclass_label"] = "benign"
        else:
            raise ValueError(f"Unexpected binary label for {artifact}: {row['label']}")
        examples.append(row)

    labels_binary = np.asarray([int(row["label"]) for row in examples], dtype=int)
    labels_multiclass = np.asarray([row["multiclass_label"] for row in examples], dtype=str)
    attack_types = sorted({row["attack_type"] for row in examples if row["label"] == "1"})
    classes = sorted(set(labels_multiclass.tolist()))
    rng = np.random.default_rng(args.seed)
    training_indices: list[int] = []
    validation_indices: list[int] = []
    attack_type_counts = {}
    by_attack_type: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(examples):
        if row["label"] == "1":
            by_attack_type[row["attack_type"]].append(index)
    for attack_type in attack_types:
        indices = np.asarray(by_attack_type[attack_type], dtype=int)
        if len(indices) < 2:
            raise ValueError(f"Attack type {attack_type} needs at least two captured samples")
        shuffled = rng.permutation(indices)
        training_count = min(
            len(shuffled) - 1,
            max(1, math.ceil(len(shuffled) * args.attack_train_fraction)),
        )
        training_indices.extend(shuffled[:training_count].tolist())
        validation_indices.extend(shuffled[training_count:].tolist())
        attack_type_counts[attack_type] = {
            "total": len(shuffled),
            "training": training_count,
            "validation": len(shuffled) - training_count,
        }

    benign_indices = np.flatnonzero(labels_binary == 0)
    benign_groups = np.asarray([examples[index]["package_group"] for index in benign_indices])
    group_split = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=args.seed)
    benign_train_relative, benign_validation_relative = next(
        group_split.split(np.zeros(len(benign_indices)), groups=benign_groups)
    )
    benign_training = benign_indices[benign_train_relative]
    benign_validation = benign_indices[benign_validation_relative]
    training_indices.extend(benign_training.tolist())
    validation_indices.extend(benign_validation.tolist())
    training_indices = sorted(training_indices)
    validation_indices = sorted(validation_indices)

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
    if set(labels_multiclass[validation_indices]) != set(classes):
        raise RuntimeError("Validation split does not contain every attack type and benign class")

    feature_sets = json.loads(feature_path.read_text(encoding="utf-8"))
    output_dir = args.output_dir.expanduser().resolve()
    models_dir = output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "evaluation": "sample-held-out attack-type split; benign package-group holdout",
        "random_seed": args.seed,
        "attack_train_fraction_per_type": args.attack_train_fraction,
        "benign_package_group_test_fraction": 0.5,
        "benign_package_groups_disjoint": True,
        "samples": len(examples),
        "training_samples": len(training_indices),
        "validation_samples": len(validation_indices),
        "training_class_counts": dict(Counter(labels_multiclass[training_indices].tolist())),
        "validation_class_counts": dict(Counter(labels_multiclass[validation_indices].tolist())),
        "attack_type_split_counts": attack_type_counts,
        "benign_runs": {
            "total": len(benign_indices),
            "training": len(benign_training),
            "validation": len(benign_validation),
            "training_package_groups": len(training_groups),
            "validation_package_groups": len(validation_groups),
        },
        "models": {},
    }
    prediction_rows = []

    for feature_set_name in ("network", "host", "hybrid"):
        feature_names = feature_sets[feature_set_name]
        matrix = numeric_matrix(examples, feature_names)

        multiclass_model = make_model(args.seed)
        multiclass_model.fit(matrix[training_indices], labels_multiclass[training_indices])
        multiclass_probabilities = multiclass_model.predict_proba(matrix[validation_indices])
        multiclass_classes = [str(value) for value in multiclass_model[-1].classes_]
        multiclass_predictions = multiclass_model.predict(matrix[validation_indices])
        multiclass_report = multiclass_metrics(
            labels_multiclass[validation_indices],
            multiclass_predictions,
            multiclass_probabilities,
            classes,
        )
        multiclass_class_index = {name: index for index, name in enumerate(multiclass_classes)}
        joblib.dump(multiclass_model, models_dir / f"{feature_set_name}_multiclass.joblib")

        binary_model = make_model(args.seed)
        binary_model.fit(matrix[training_indices], labels_binary[training_indices])
        binary_probabilities_all = binary_model.predict_proba(matrix[validation_indices])
        binary_classes = [int(value) for value in binary_model[-1].classes_]
        positive_index = binary_classes.index(1)
        binary_probabilities = binary_probabilities_all[:, positive_index]
        binary_predictions = (binary_probabilities >= 0.5).astype(int)
        binary_report = metrics_for(
            labels_binary[validation_indices], binary_predictions, binary_probabilities
        )
        binary_report["per_attack_type_detection"] = {}
        for attack_type in attack_types:
            attack_validation = [
                position
                for position, sample_index in enumerate(validation_indices)
                if examples[sample_index]["attack_type"] == attack_type
            ]
            detected = sum(int(binary_predictions[position] == 1) for position in attack_validation)
            binary_report["per_attack_type_detection"][attack_type] = {
                "support": len(attack_validation),
                "detected": detected,
                "missed": len(attack_validation) - detected,
                "recall": detected / len(attack_validation) if attack_validation else None,
            }
        joblib.dump(binary_model, models_dir / f"{feature_set_name}_binary.joblib")

        report["models"][feature_set_name] = {
            "feature_count": len(feature_names),
            "multiclass_attack_type": multiclass_report,
            "binary_malware_detection": binary_report,
        }
        for position, sample_index in enumerate(validation_indices):
            true_type = str(labels_multiclass[sample_index])
            predicted_type = str(multiclass_predictions[position])
            type_probability = float(
                multiclass_probabilities[position, multiclass_class_index[predicted_type]]
            )
            prediction_rows.append(
                {
                    "feature_set": feature_set_name,
                    "sample_artifact": examples[sample_index]["sample_artifact"],
                    "sha256": examples[sample_index]["sha256"],
                    "true_attack_type": true_type,
                    "predicted_attack_type": predicted_type,
                    "predicted_attack_type_probability": type_probability,
                    "multiclass_correct": int(true_type == predicted_type),
                    "true_binary_label": int(labels_binary[sample_index]),
                    "probability_malware": float(binary_probabilities[position]),
                    "binary_prediction": int(binary_predictions[position]),
                    "binary_correct": int(binary_predictions[position] == labels_binary[sample_index]),
                }
            )

    assignment_rows = []
    split_by_index = {index: "training" for index in training_indices}
    split_by_index.update({index: "validation" for index in validation_indices})
    feature_fields = list(examples[0])
    for index, row in enumerate(examples):
        assignment_rows.append(
            {
                "sample_artifact": row["sample_artifact"],
                "sha256": row["sha256"],
                "split": split_by_index[index],
                "binary_label": int(labels_binary[index]),
                "attack_type": row["attack_type"],
                "family_label": row["family_label"],
                "original_dataset_split": row["original_dataset_split"],
                "benign_package_group": row.get("package_group", "") if row["label"] == "0" else "",
            }
        )
    write_csv(output_dir / "split_assignments.csv", assignment_rows, list(assignment_rows[0]))
    write_csv(
        output_dir / "training_dataset.csv",
        [{**examples[index], "split": "training"} for index in training_indices],
        feature_fields + ["split"],
    )
    write_csv(
        output_dir / "validation_dataset.csv",
        [{**examples[index], "split": "validation"} for index in validation_indices],
        feature_fields + ["split"],
    )
    write_csv(
        output_dir / "validation_predictions.csv",
        prediction_rows,
        list(prediction_rows[0]),
    )
    (output_dir / "metrics.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    print(f"Attack-type split results: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())