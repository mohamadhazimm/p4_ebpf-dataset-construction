#!/usr/bin/env python3
"""Diagnose host separability using saved samples without executing workloads."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

STUDY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STUDY_ROOT / "src"))
from train_compare import make_model, metrics_for, numeric_matrix


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def evaluate(model, training, validation, train_labels, validation_labels):
    model.fit(training, train_labels)
    probabilities = model.predict_proba(validation)[:, 1]
    return metrics_for(validation_labels, probabilities >= 0.5, probabilities)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("Refusing to overwrite an existing diagnostic output")
    experiment = args.experiment_dir.resolve()
    source_report = json.loads((experiment / "metrics.json").read_text())
    columns = json.loads((experiment / "feature_columns.json").read_text())
    training = read_csv(experiment / "training_samples.csv")
    validation = read_csv(experiment / "validation_samples.csv")
    assignments = read_csv(experiment / "split_assignments.csv")
    assignment_by_id = {row["sample_artifact"]: row for row in assignments}
    assert len(assignment_by_id) == len(training) + len(validation)
    train_labels = np.array([int(row["label"]) for row in training])
    validation_labels = np.array([int(row["label"]) for row in validation])
    native = columns["hostmon_native_26"]
    corrected = Path(source_report["corrected_csv_root"])
    data_root = corrected.parent
    report = {
        "source_experiment": str(experiment),
        "sample_counts": {"training": len(training), "validation": len(validation)},
        "seed": 42,
        "limitations": [
            "Diagnostic analyses on an already-inspected 200-sample subset, not a new confirmatory test set",
            "Native HostMon raw syscall summaries have a confirmed process-filtering mismatch",
            "Grouped CV changes training size and split as well as withholding families/packages",
            "No raw per-syscall stream is present in ebpf_events.csv; aggregate sequence contamination cannot be removed from that file",
        ],
        "class_profiles": {},
        "fixed_split_controls": {},
        "single_feature_stumps": {},
        "first_window_controls": {},
        "grouped_cross_validation": {},
    }
    for split, rows in (("training", training), ("validation", validation)):
        for label in (0, 1):
            selected = [row for row in rows if int(row["label"]) == label]
            metadata_rows = []
            error_messages = Counter()
            raw_to_filtered = []
            for row in selected:
                run = next((data_root / "runs" / row["cohort"] / row["sample_artifact"] / "output").rglob("run.json"))
                metadata = json.loads(run.read_text())
                metadata_rows.append(metadata)
                diagnostics = metadata["ebpf_event_diagnostics"]
                raw_to_filtered.append({
                    "sample_artifact": row["sample_artifact"],
                    "raw_syscall_events": diagnostics["host_syscall_events"],
                    "accepted_specific_events": sum(diagnostics["accepted"].values()),
                    "untracked_specific_events": sum(diagnostics["untracked_tid"].values()),
                    "summed_native_syscalls": float(row["host_total_syscalls_total__sum"]),
                })
                stderr = run.parent / "sample.stderr.log"
                if stderr.exists():
                    for line in stderr.read_text(errors="replace").splitlines():
                        if "curl:" in line:
                            error_messages[line[:240]] += 1
            report["class_profiles"][f"{split}_{label}"] = {
                "runner_status": dict(Counter(row["runner_status"] for row in selected)),
                "ebpf_status": dict(Counter(row["ebpf_status"] for row in selected)),
                "window_count": dict(Counter(row["window_count"] for row in selected)),
                "return_code": dict(Counter(str(row.get("return_code")) for row in metadata_rows)),
                "curl_errors": dict(error_messages),
                "event_diagnostics": raw_to_filtered,
            }
    feature_controls = {
        "native_full_130": native,
        "native_max_only_26": [field for field in native if field.endswith("__max")],
        "sequence_shape_without_sums": [field for field in native if field.endswith(("__mean", "__max")) and field.startswith(("host_entropy_", "host_top_syscall_", "host_avg_run_", "host_max_run_", "host_rare_syscall_", "host_first50_", "host_first100_", "host_unique_syscalls_"))],
        "filtered_host_actions_only": [field for field in native if field.rpartition("__")[0] in {"host_exec_total", "host_open_total", "host_rename_total", "host_unlink_total", "host_connect_total", "host_unique_ip_total", "host_unique_port_total"}],
    }
    for name, features in feature_controls.items():
        report["fixed_split_controls"][name] = {
            "columns": features,
            "metrics": evaluate(make_model(42), numeric_matrix(training, features), numeric_matrix(validation, features), train_labels, validation_labels),
        }
        print(name, report["fixed_split_controls"][name]["metrics"], flush=True)
    shuffled = np.random.default_rng(42).permutation(train_labels)
    report["fixed_split_controls"]["shuffled_training_labels"] = {
        "metrics": evaluate(make_model(42), numeric_matrix(training, native), numeric_matrix(validation, native), shuffled, validation_labels)
    }
    for field in ("window_count", "ebpf_dup2_count__max", "host_entropy_mean__max", "host_avg_run_length_max__max", "ebpf_mprotect_count__max", "ebpf_mmap_count__max"):
        model = DecisionTreeClassifier(max_depth=1, random_state=42)
        train_matrix = numeric_matrix(training, [field])
        validation_matrix = numeric_matrix(validation, [field])
        result = {
            "metrics": evaluate(model, train_matrix, validation_matrix, train_labels, validation_labels),
            "training_threshold": float(model.tree_.threshold[0]),
            "training_leaf_classes": model.tree_.value.tolist(),
            "class_quantiles": {},
        }
        for split, matrix, labels in (("training", train_matrix, train_labels), ("validation", validation_matrix, validation_labels)):
            for label in (0, 1):
                result["class_quantiles"][f"{split}_{label}"] = np.quantile(matrix[labels == label, 0], [0, 0.25, 0.5, 0.75, 1]).tolist()
        report["single_feature_stumps"][field] = result
        print("stump", field, result["metrics"], "threshold", result["training_threshold"], flush=True)
    first_windows = []
    for rows in (training, validation):
        first_rows = []
        for row in rows:
            telemetry = read_csv(corrected / "telemetry" / row["cohort"] / row["sample_artifact"] / "telemetry.csv")
            assert int(telemetry[0]["window_id"]) == 0
            first_rows.append(telemetry[0])
        first_windows.append(first_rows)
    signals = source_report["feature_definition"]["signals_by_model"]
    for name in ("p4_network", "hostmon_native_26", "hybrid_p4_hostmon_native_55"):
        features = signals[name]
        report["first_window_controls"][name] = {
            "raw_signals": len(features),
            "metrics": evaluate(make_model(42), numeric_matrix(first_windows[0], features), numeric_matrix(first_windows[1], features), train_labels, validation_labels),
        }
        print("first_window", name, report["first_window_controls"][name]["metrics"], flush=True)
    pool = training + validation
    labels = np.concatenate((train_labels, validation_labels))
    groups = np.array([
        "malware::" + assignment_by_id[row["sample_artifact"]]["family_label"] if int(row["label"]) else "benign::" + row["benign_package_group"]
        for row in pool
    ])
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    folds = list(splitter.split(np.zeros((len(pool), 1)), labels, groups))
    for name in ("p4_network", "hostmon_native_26", "hybrid_p4_hostmon_native_55"):
        matrix = numeric_matrix(pool, columns[name])
        probabilities = np.full(len(pool), np.nan)
        details = []
        for fold, (train_indices, test_indices) in enumerate(folds):
            assert not set(groups[train_indices]) & set(groups[test_indices])
            assert set(labels[train_indices]) == {0, 1}
            model = make_model(42)
            model.fit(matrix[train_indices], labels[train_indices])
            probabilities[test_indices] = model.predict_proba(matrix[test_indices])[:, 1]
            details.append({"fold": fold, "training_samples": len(train_indices), "validation_samples": len(test_indices), "validation_groups": sorted(set(groups[test_indices]))})
        assert np.isfinite(probabilities).all()
        report["grouped_cross_validation"][name] = {
            "metrics": metrics_for(labels, probabilities >= 0.5, probabilities),
            "folds": details,
        }
        print("grouped_cv", name, report["grouped_cross_validation"][name]["metrics"], flush=True)
    signatures = defaultdict(list)
    for row, vector in zip(training, numeric_matrix(training, native), strict=True):
        signatures[tuple(vector)].append(row["sample_artifact"])
    overlaps = []
    for row, vector in zip(validation, numeric_matrix(validation, native), strict=True):
        matches = signatures.get(tuple(vector), [])
        if matches:
            overlaps.append({"validation_artifact": row["sample_artifact"], "training_artifacts": matches})
    report["exact_native_feature_overlap"] = overlaps
    args.output_dir.mkdir(parents=True)
    (args.output_dir / "diagnostics.json").write_text(json.dumps(report, indent=2) + "\n")
    print("REPORT", args.output_dir / "diagnostics.json")


if __name__ == "__main__":
    main()