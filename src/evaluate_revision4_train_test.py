#!/usr/bin/env python3
"""Train on today's revision-4 training collections and test on today's holdout runs."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_revision4_full_cohort import (  # noqa: E402
    STATISTICS,
    load_samples,
    multiclass_metrics,
    p4_analyzer,
    read_csv,
    write_csv,
)
from train_compare import make_model, metrics_for, numeric_matrix  # noqa: E402

DEFAULT_TRAIN_MALWARE = ROOT / "data/malware/revision4/runs/training-535-20261017"
DEFAULT_TEST_MALWARE = ROOT / "data/malware/full-cohort-323/runs/p4-network-full-20261017"
DEFAULT_TRAIN_BENIGN = ROOT / "data/benign/revision4/expanded/runs/training-500-20261017"
DEFAULT_TEST_BENIGN = ROOT / "data/benign/revision4/expanded/runs/validation-138-20261017"
DEFAULT_LABELS = ROOT / "data/malware/revision4/training521_holdout461_20261017/malware_hash_labels.csv"
DEFAULT_TRAIN_BENIGN_MANIFEST = ROOT / "data/benign/revision4/expanded/training/workload_manifest.csv"
DEFAULT_TEST_BENIGN_MANIFEST = ROOT / "data/benign/revision4/expanded/validation/workload_manifest.csv"
DEFAULT_TEST_MALWARE_MANIFEST = ROOT / "data/malware/full-cohort-323/cohort_manifest.csv"
DEFAULT_OUTPUT = ROOT / "data/malware/revision4/train_test_full_signals_20261017"


def validate_today_runs(root: Path) -> tuple[int, str, str]:
    run_paths = sorted(root.rglob("run.json"))
    if not run_paths:
        raise ValueError(f"No run.json files under {root}")
    run_dates = []
    for run_path in run_paths:
        metadata = json.loads(run_path.read_text(encoding="utf-8"))
        started = str(metadata.get("started_at_utc", ""))
        if not started.startswith("2026-10-17"):
            raise ValueError(f"Non-October-17 run found: {run_path} ({started})")
        run_dates.append(started)
        for required in ("telemetry.csv", "ebpf_events.csv", "packet_capture.pcap"):
            if not (run_path.parent / required).is_file():
                raise ValueError(f"Missing {required} for {run_path.parent}")
    return len(run_paths), min(run_dates), max(run_dates)


def add_event_columns(examples: list[dict], event_names: list[str]) -> None:
    columns_by_name = {}
    for event_name in event_names:
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", event_name).strip("_").lower()
        if slug in columns_by_name and columns_by_name[slug] != event_name:
            raise ValueError(f"eBPF event names collide after normalization: {event_name}")
        columns_by_name[slug] = event_name
    for row in examples:
        for slug in columns_by_name:
            for statistic in STATISTICS:
                row.setdefault(f"event__{slug}__{statistic}", 0.0)


def project_sample(row: dict, feature_names: list[str], split: str) -> dict:
    metadata = (
        "sample_artifact",
        "sample_name",
        "sha256",
        "label",
        "attack_type",
        "family_label",
        "multiclass_label",
        "package_group",
        "workload_family",
        "group_id",
        "run_status",
        "failure_reason",
        "ebpf_status",
        "packet_capture_status",
        "window_count",
    )
    return {**{name: row.get(name, "") for name in metadata}, **{name: row[name] for name in feature_names}, "split": split}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-malware-runs", type=Path, default=DEFAULT_TRAIN_MALWARE)
    parser.add_argument("--test-malware-runs", type=Path, default=DEFAULT_TEST_MALWARE)
    parser.add_argument("--train-benign-runs", type=Path, default=DEFAULT_TRAIN_BENIGN)
    parser.add_argument("--test-benign-runs", type=Path, default=DEFAULT_TEST_BENIGN)
    parser.add_argument("--malware-labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--train-benign-manifest", type=Path, default=DEFAULT_TRAIN_BENIGN_MANIFEST)
    parser.add_argument("--test-benign-manifest", type=Path, default=DEFAULT_TEST_BENIGN_MANIFEST)
    parser.add_argument("--test-malware-manifest", type=Path, default=DEFAULT_TEST_MALWARE_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    source_roots = {
        "training_malware": args.train_malware_runs,
        "testing_malware": args.test_malware_runs,
        "training_benign": args.train_benign_runs,
        "testing_benign": args.test_benign_runs,
    }
    date_audit = {
        name: validate_today_runs(path)
        for name, path in source_roots.items()
    }
    labels_path = args.malware_labels
    train_examples, train_signals, train_events, train_diagnostics, train_candidates, train_uncertainty, train_status, train_failures = load_samples(
        args.train_malware_runs,
        args.train_benign_runs,
        labels_path,
        args.train_benign_manifest,
        malware_membership="training",
        require_exact_malware_labels=True,
    )
    test_examples, test_signals, test_events, test_diagnostics, test_candidates, test_uncertainty, test_status, test_failures = load_samples(
        args.test_malware_runs,
        args.test_benign_runs,
        labels_path,
        args.test_benign_manifest,
        malware_membership="holdout",
        require_exact_malware_labels=False,
    )

    test_manifest = {
        row["sample_artifact"]: row for row in read_csv(args.test_malware_manifest)
    }
    expected_test_artifacts = set(test_manifest)
    actual_test_artifacts = {
        row["sample_artifact"] for row in test_examples if row["label"] == 1
    }
    if not actual_test_artifacts <= expected_test_artifacts:
        raise ValueError("Today's malware test runs include artifacts outside the holdout manifest")
    holdout_labels = {
        row["sha256"].lower()
        for row in read_csv(labels_path)
        if row["telemetry_model_membership"] == "holdout"
    }
    if expected_test_artifacts != {f"{digest}.zip" for digest in holdout_labels}:
        raise ValueError("The holdout manifest and holdout hash-label set do not match")
    missing_test_artifacts = sorted(expected_test_artifacts - actual_test_artifacts)

    train_malware_hashes = {row["sha256"] for row in train_examples if row["label"] == 1}
    test_malware_hashes = {row["sha256"] for row in test_examples if row["label"] == 1}
    if train_malware_hashes & test_malware_hashes:
        raise ValueError("Malware hashes overlap between training and test runs")
    train_benign_groups = {row["package_group"] for row in train_examples if row["label"] == 0}
    test_benign_groups = {row["package_group"] for row in test_examples if row["label"] == 0}
    if train_benign_groups & test_benign_groups:
        raise ValueError("Benign package groups overlap between training and test runs")
    if {row["sample_artifact"] for row in train_examples} & {
        row["sample_artifact"] for row in test_examples
    }:
        raise ValueError("Sample artifacts overlap between training and test runs")

    common_signals = sorted(set(train_signals) & set(test_signals))
    if not common_signals:
        raise ValueError("No common numeric telemetry signals across today's train/test runs")
    test_only_signals = sorted(set(test_signals) - set(train_signals))
    train_only_signals = sorted(set(train_signals) - set(test_signals))
    event_names = sorted(set(train_events) | set(test_events))
    add_event_columns(train_examples, event_names)
    add_event_columns(test_examples, event_names)

    network_fields = [field for field in common_signals if field.startswith("net_")]
    host_fields = [
        field for field in common_signals if field.startswith(("host_", "ebpf_"))
    ]
    network_features = [
        f"telemetry__{field}__{statistic}"
        for field in network_fields
        for statistic in STATISTICS
    ]
    host_features = [
        f"telemetry__{field}__{statistic}"
        for field in host_fields
        for statistic in STATISTICS
    ]
    host_features.extend(
        f"event__{re.sub(r'[^a-zA-Z0-9]+', '_', name).strip('_').lower()}__{statistic}"
        for name in event_names
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
    classes = sorted(
        {str(row["multiclass_label"]) for row in train_examples}
        | {str(row["multiclass_label"]) for row in test_examples}
    )
    test_classes = {str(row["multiclass_label"]) for row in test_examples}
    unseen_test_classes = sorted(
        test_classes - {str(row["multiclass_label"]) for row in train_examples}
    )

    output_dir = args.output_dir.expanduser().resolve()
    models_dir = output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "feature_columns.json").write_text(
        json.dumps(feature_sets, indent=2) + "\n", encoding="utf-8"
    )
    metadata_fields = [
        "sample_artifact", "sample_name", "sha256", "label", "attack_type",
        "family_label", "multiclass_label", "package_group", "workload_family",
        "group_id", "run_status", "failure_reason", "ebpf_status",
        "packet_capture_status", "window_count",
    ]
    full_hybrid_features = feature_sets["full_hybrid"]
    dataset_fields = metadata_fields + full_hybrid_features + ["split"]
    write_csv(
        output_dir / "training_dataset.csv",
        [project_sample(row, full_hybrid_features, "training") for row in train_examples],
        dataset_fields,
    )
    write_csv(
        output_dir / "test_dataset.csv",
        [project_sample(row, full_hybrid_features, "test") for row in test_examples],
        dataset_fields,
    )
    write_csv(
        output_dir / "p4_alignment_diagnostics.csv",
        [
            {"split": split, **row}
            for split, rows in (("training", train_diagnostics), ("test", test_diagnostics))
            for row in rows
        ],
        ["split", *train_diagnostics[0].keys()],
    )
    candidate_rows = [
        {"split": split, **row}
        for split, rows in (("training", train_candidates), ("test", test_candidates))
        for row in rows
    ]
    if candidate_rows:
        write_csv(output_dir / "p4_ambiguous_candidates.csv", candidate_rows, list(candidate_rows[0]))
    uncertainty_rows = [
        {"split": split, **row}
        for split, rows in (("training", train_uncertainty), ("test", test_uncertainty))
        for row in rows
    ]
    if uncertainty_rows:
        write_csv(output_dir / "p4_feature_uncertainty.csv", uncertainty_rows, list(uncertainty_rows[0]))
    if missing_test_artifacts:
        write_csv(
            output_dir / "excluded_manifest_only_malware.csv",
            [test_manifest[artifact] for artifact in missing_test_artifacts],
            list(test_manifest[missing_test_artifacts[0]]),
        )

    y_train_binary = np.asarray([int(row["label"]) for row in train_examples], dtype=int)
    y_test_binary = np.asarray([int(row["label"]) for row in test_examples], dtype=int)
    y_train_type = np.asarray([str(row["multiclass_label"]) for row in train_examples])
    y_test_type = np.asarray([str(row["multiclass_label"]) for row in test_examples])
    predictions = []
    report = {
        "evaluation": "fixed October 17, 2026 train/test collections; no older runtime feature data",
        "random_seed": args.seed,
        "training_samples": len(train_examples),
        "test_samples": len(test_examples),
        "training_class_counts": dict(Counter(y_train_type.tolist())),
        "test_class_counts": dict(Counter(y_test_type.tolist())),
        "test_attack_types_unseen_in_training": unseen_test_classes,
        "training_malware": len(train_malware_hashes),
        "training_benign": sum(row["label"] == 0 for row in train_examples),
        "test_malware_captured_today": len(test_malware_hashes),
        "test_malware_manifest_total": len(expected_test_artifacts),
        "test_malware_missing_today": len(missing_test_artifacts),
        "test_benign": sum(row["label"] == 0 for row in test_examples),
        "malware_hashes_disjoint": True,
        "benign_package_groups_disjoint": True,
        "train_only_telemetry_signals_omitted": train_only_signals,
        "test_only_telemetry_signals_omitted": test_only_signals,
        "models": {},
    }

    for feature_set_name, feature_names in feature_sets.items():
        train_matrix = numeric_matrix(train_examples, feature_names)
        test_matrix = numeric_matrix(test_examples, feature_names)
        multiclass_model = make_model(args.seed)
        multiclass_model.fit(train_matrix, y_train_type)
        multiclass_probabilities = multiclass_model.predict_proba(test_matrix)
        model_classes = [str(value) for value in multiclass_model[-1].classes_]
        multiclass_predictions = multiclass_model.predict(test_matrix)
        multiclass_report = multiclass_metrics(
            y_test_type,
            multiclass_predictions,
            multiclass_probabilities,
            classes,
            model_classes,
        )
        joblib.dump(multiclass_model, models_dir / f"{feature_set_name}_multiclass.joblib")

        binary_model = make_model(args.seed)
        binary_model.fit(train_matrix, y_train_binary)
        all_probabilities = binary_model.predict_proba(test_matrix)
        binary_classes = [int(value) for value in binary_model[-1].classes_]
        malware_index = binary_classes.index(1)
        malware_probabilities = all_probabilities[:, malware_index]
        binary_predictions = (malware_probabilities >= 0.5).astype(int)
        binary_report = metrics_for(y_test_binary, binary_predictions, malware_probabilities)
        binary_report["per_attack_type_detection"] = {}
        for attack_type in sorted({row["attack_type"] for row in test_examples if row["label"] == 1}):
            indices = [
                index for index, row in enumerate(test_examples)
                if row["label"] == 1 and row["attack_type"] == attack_type
            ]
            detected = sum(int(binary_predictions[index] == 1) for index in indices)
            binary_report["per_attack_type_detection"][attack_type] = {
                "support": len(indices),
                "detected": detected,
                "missed": len(indices) - detected,
                "recall": detected / len(indices) if indices else None,
            }
        joblib.dump(binary_model, models_dir / f"{feature_set_name}_binary.joblib")
        report["models"][feature_set_name] = {
            "feature_count": len(feature_names),
            "binary_malware_detection": binary_report,
            "multiclass_attack_type": multiclass_report,
        }

        model_class_index = {name: index for index, name in enumerate(model_classes)}
        for index, row in enumerate(test_examples):
            predicted_type = str(multiclass_predictions[index])
            predictions.append(
                {
                    "feature_set": feature_set_name,
                    "sample_artifact": row["sample_artifact"],
                    "sha256": row["sha256"],
                    "true_attack_type": row["multiclass_label"],
                    "predicted_attack_type": predicted_type,
                    "predicted_attack_type_probability": float(
                        multiclass_probabilities[index, model_class_index[predicted_type]]
                    ),
                    "multiclass_correct": int(predicted_type == row["multiclass_label"]),
                    "true_binary_label": int(y_test_binary[index]),
                    "probability_malware": float(malware_probabilities[index]),
                    "binary_prediction": int(binary_predictions[index]),
                    "binary_correct": int(binary_predictions[index] == y_test_binary[index]),
                }
            )
    write_csv(output_dir / "test_predictions.csv", predictions, list(predictions[0]))

    diagnostics = train_diagnostics + test_diagnostics
    report["source_directories"] = {
        name: str(path.resolve()) for name, path in source_roots.items()
    }
    report["collection_dates_and_run_time_ranges_utc"] = {
        name: {"count": values[0], "first_started_at_utc": values[1], "last_started_at_utc": values[2]}
        for name, values in date_audit.items()
    }
    report["feature_audit"] = {
        "common_numeric_telemetry_signals": common_signals,
        "common_numeric_telemetry_signal_count": len(common_signals),
        "common_ebpf_event_categories": event_names,
        "p4_derived_sample_feature_count": len(p4_features),
        "p4_unique_alignments": sum(row["p4_reconstruction_method"] == "unique_packet_window_assignment" for row in diagnostics),
        "p4_ambiguous_samples_marginalized": sum(row["p4_reconstruction_method"] == "duration_weighted_counter_consistent_assignments" for row in diagnostics),
        "p4_candidate_assignment_vectors": len(train_candidates) + len(test_candidates),
        "test_only_raw_columns_not_used": test_only_signals,
    }
    report["run_status_counts"] = {
        "training": dict(train_status),
        "test": dict(test_status),
    }
    report["nonempty_failure_reason_counts"] = {
        "training": dict(train_failures),
        "test": dict(test_failures),
    }
    runner_path = ROOT / "src/malware_runner.py"
    runner_mtime = datetime.fromtimestamp(runner_path.stat().st_mtime, tz=timezone.utc)
    malware_test_last = datetime.fromisoformat(date_audit["testing_malware"][2])
    report["runner_revision_caveat"] = {
        "current_runner_path": str(runner_path.resolve()),
        "current_runner_mtime_utc": runner_mtime.isoformat(),
        "test_malware_last_run_utc": malware_test_last.isoformat(),
        "test_runs_predate_current_runner_mtime": malware_test_last < runner_mtime,
        "note": "The October 17 malware test runs finished before the current malware_runner.py file timestamp. Evaluation uses only signals shared with training and P4 signals reconstructed identically from today's PCAPs; the runner binary/version used by those earlier runs cannot be proven from run.json.",
    }
    report["scoring_notes"] = [
        "All model inputs come from the four October 17 raw-run directories listed in source_directories; no earlier collector CSV or feature dataset is loaded.",
        "Training uses every complete run from today's 521-malware and 500-benign training collections; testing uses every complete run from today's captured 319-malware and 138-benign holdout collections.",
        "Four malware hashes appear in the 323-item holdout manifest but have no October 17 raw run directory; they are excluded and listed in excluded_manifest_only_malware.csv.",
        "The 319 malware holdout telemetry has extra columns absent from training; only common raw telemetry signals, common eBPF event categories, and PCAP-reconstructed P4 features are used.",
        "No test samples are used for model fitting or threshold tuning. Binary threshold is 0.5 and Random Forest settings follow train_compare.py.",
        "Malware attack-type labels are metadata labels joined by SHA-256; they are not model features.",
    ]
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "metrics.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"Fixed train/test results: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
