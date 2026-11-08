#!/usr/bin/env python3
"""Audit and evaluate a frozen corrected-host pilot without running samples."""

from __future__ import annotations

import argparse
import csv
import hashlib
import heapq
import json
import math
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.tree import DecisionTreeClassifier

STUDY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STUDY / "src"))
from evaluate_versioned_hostmon_p4 import STATISTICS, aggregate_feature, numeric_matrix, read_csv, write_dataset
from train_compare import make_model, metrics_for


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_raw_syscalls(run_dir, metadata, telemetry):
    counts = Counter()
    commands = Counter()
    tracked = {metadata["sample_root_pid"]}
    with (run_dir / "syscall_events.csv").open(newline="") as raw_source, (run_dir / "ebpf_events.csv").open(newline="") as named_source:
        raw_rows = csv.DictReader(raw_source)
        named_rows = csv.DictReader(named_source)
        for row in heapq.merge(raw_rows, named_rows, key=lambda row: int(row["timestamp_ns"])):
            timestamp = int(row["timestamp_ns"])
            assert metadata["sample_started_monotonic_ns"] <= timestamp < metadata["observation_ended_monotonic_ns"]
            pid, tid = int(row["pid"]), int(row["tid"])
            if row["event"] == "fork":
                assert pid in tracked
                tracked.add(tid)
            else:
                assert pid in tracked or tid in tracked, f"Untracked raw/event PID: {pid}/{tid}"
            if row["event"] == "syscall":
                counts[int(row["window_id"])] += 1
                commands[row["comm"]] += 1
    assert sum(counts.values()) == metadata["raw_syscall_event_count"]
    for row in telemetry:
        assert counts[int(row["window_id"])] == int(float(row["host_total_syscalls_total"]))
    return dict(commands)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.data_root.resolve()
    output = root / "modeling"
    if output.exists():
        parser.error("Refusing to overwrite modeling outputs")
    manifest = json.loads((root / "pilot_manifest.json").read_text())
    rows_by_split = {"training": [], "validation": []}
    groups = None
    audits = []
    statuses = {}
    for cohort, definition in manifest["cohorts"].items():
        assert sha256(root / definition["manifest"]) == definition["sha256"]
        status_counts = Counter()
        for artifact in (root / definition["manifest"]).read_text().splitlines():
            sample = root / "runs" / cohort / artifact
            assert "status=completed" in (sample / "host_run.txt").read_text().splitlines()
            metadata_paths = list((sample / "output").rglob("run.json"))
            assert len(metadata_paths) == 1
            metadata_path = metadata_paths[0]
            metadata = json.loads(metadata_path.read_text())
            assert metadata["malware_runner_sha256"] == manifest["runner_sha256"]
            assert metadata["telemetry_schema_version"] == manifest["schema_version"]
            assert metadata["observation_mode"] == "fixed" and metadata["common_launch_wrapper"]
            assert metadata["ebpf_status"] == "active" and metadata["packet_capture_status"] == "active"
            assert metadata["windows"] == 10
            assert metadata["observation_ended_monotonic_ns"] - metadata["sample_started_monotonic_ns"] == 5_000_000_000
            if groups is None:
                groups = metadata["telemetry_feature_groups"]
            assert groups == metadata["telemetry_feature_groups"]
            telemetry = read_csv(metadata_path.parent / "telemetry.csv")
            assert len(telemetry) == 10
            commands = audit_raw_syscalls(metadata_path.parent, metadata, telemetry)
            trace_log = (metadata_path.parent / "ebpf_collector.log").read_text(errors="replace")
            loss_warnings = [line for line in trace_log.splitlines() if re.search(r"\b(lost|dropped)\b", line, re.I)]
            if definition["label"] == 0:
                assert metadata["status"] == "completed" and metadata["return_code"] == 0, f"Failed benign workload: {artifact}"
            example = {
                "sample_artifact": artifact, "sample_name": artifact, "cohort": cohort,
                "label": definition["label"], "runner_status": metadata["status"],
                "ebpf_status": metadata["ebpf_status"], "window_count": len(telemetry),
                "benign_package_group": "", "return_code": metadata["return_code"],
            }
            signals = list(dict.fromkeys(groups["p4_network"] + groups["hostmon_syscall_sequence"] + ["ebpf_dup2_count"]))
            for field in signals:
                example.update({f"{field}__{statistic}": value for statistic, value in aggregate_feature(telemetry, field).items()})
            rows_by_split[definition["split"]].append(example)
            status_counts[metadata["status"]] += 1
            audits.append({
                "cohort": cohort, "artifact": artifact, "metadata_sha256": sha256(metadata_path),
                "telemetry_sha256": sha256(metadata_path.parent / "telemetry.csv"),
                "syscall_events_sha256": sha256(metadata_path.parent / "syscall_events.csv"),
                "raw_syscall_count": metadata["raw_syscall_event_count"],
                "raw_syscall_commands": commands,
                "event_loss_warnings": loss_warnings,
                "rejected_before": metadata["ebpf_event_diagnostics"]["before_sample"],
                "rejected_after": metadata["ebpf_event_diagnostics"].get("after_sample", {}),
                "rejected_untracked": metadata["ebpf_event_diagnostics"]["untracked_tid"],
            })
        statuses[cohort] = dict(status_counts)
    training = rows_by_split["training"]
    validation = rows_by_split["validation"]
    assert len(training) == len(validation) == 20
    assert not {row["sample_artifact"] for row in training} & {row["sample_artifact"] for row in validation}
    assert all(sum(row["label"] == label for row in rows) == 10 for rows in (training, validation) for label in (0, 1))
    native = groups["hostmon_syscall_sequence"]
    p4 = groups["p4_network"]
    assert len(native) == 26 and len(p4) == 29
    signal_sets = {"p4_network": p4, "hostmon_native_26": native, "hybrid_native_55": p4 + native}
    feature_sets = {name: [f"{field}__{statistic}" for field in signals for statistic in STATISTICS] for name, signals in signal_sets.items()}
    train_labels = np.array([row["label"] for row in training])
    test_labels = np.array([row["label"] for row in validation])
    report = {
        "pilot_manifest_sha256": sha256(root / "pilot_manifest.json"),
        "runner_sha256": manifest["runner_sha256"], "schema_version": manifest["schema_version"],
        "training_samples": 20, "validation_samples": 20,
        "class_counts_per_split": {"benign": 10, "malware": 10},
        "statuses": statuses, "seed": 42, "threshold": 0.5,
        "models": {}, "single_feature_control": {}, "limitations": manifest["limitations"],
        "event_loss_warning_samples": [row["artifact"] for row in audits if row["event_loss_warnings"]],
        "event_loss_sensitivity": {},
        "audit_checks": {"sample_disjoint": True, "fixed_five_second_observation": True,
                         "raw_syscall_lineage_verified": True, "raw_syscall_window_counts_verified": True,
                         "all_benign_payloads_successful": True, "metadata_excluded_from_features": True},
    }
    staging = Path(tempfile.mkdtemp(prefix=".modeling-", dir=root))
    try:
        (staging / "models").mkdir()
        predictions = []
        importances = []
        for name, features in feature_sets.items():
            model = make_model(42)
            model.fit(numeric_matrix(training, features), train_labels)
            probabilities = model.predict_proba(numeric_matrix(validation, features))[:, 1]
            predicted = probabilities >= 0.5
            metrics = metrics_for(test_labels, predicted, probabilities)
            correct = metrics["tn"] + metrics["tp"]
            proportion = correct / len(validation)
            denominator = 1 + 1.96 ** 2 / len(validation)
            center = (proportion + 1.96 ** 2 / (2 * len(validation))) / denominator
            spread = 1.96 * math.sqrt(proportion * (1 - proportion) / len(validation) + 1.96 ** 2 / (4 * len(validation) ** 2)) / denominator
            report["models"][name] = {"raw_signal_count": len(signal_sets[name]), "aggregated_feature_count": len(features), "metrics": metrics, "accuracy_wilson_95_interval": [center - spread, center + spread]}
            lossy = set(report["event_loss_warning_samples"])
            if lossy:
                clean_training = [row for row in training if row["sample_artifact"] not in lossy]
                clean_validation = [row for row in validation if row["sample_artifact"] not in lossy]
                sensitivity = make_model(42)
                sensitivity.fit(numeric_matrix(clean_training, features), [row["label"] for row in clean_training])
                sensitivity_probabilities = sensitivity.predict_proba(numeric_matrix(clean_validation, features))[:, 1]
                report["event_loss_sensitivity"][name] = {
                    "training_samples": len(clean_training), "validation_samples": len(clean_validation),
                    "metrics": metrics_for([row["label"] for row in clean_validation], sensitivity_probabilities >= 0.5, sensitivity_probabilities),
                }
            joblib.dump({"model": model, "feature_names": features}, staging / "models" / f"{name}.joblib")
            for row, probability, prediction in zip(validation, probabilities, predicted, strict=True):
                predictions.append({"model": name, "sample_artifact": row["sample_artifact"], "true_label": row["label"], "prediction": int(prediction), "probability_malware": float(probability), "runner_status": row["runner_status"]})
            importances.extend({"model": name, "feature": field, "importance": float(value)} for field, value in zip(features, model[-1].feature_importances_, strict=True))
            print(name, metrics, flush=True)
        field = "ebpf_dup2_count__max"
        stump = DecisionTreeClassifier(max_depth=1, random_state=42)
        stump.fit(numeric_matrix(training, [field]), train_labels)
        probabilities = stump.predict_proba(numeric_matrix(validation, [field]))[:, 1]
        report["single_feature_control"] = {"field": field, "training_threshold": float(stump.tree_.threshold[0]), "metrics": metrics_for(test_labels, probabilities >= 0.5, probabilities), "class_values": {f"{split}_{label}": sorted(row[field] for row in rows if row["label"] == label) for split, rows in rows_by_split.items() for label in (0, 1)}}
        all_features = sorted({field for fields in feature_sets.values() for field in fields} | {field})
        write_dataset(staging / "training_samples.csv", training, all_features)
        write_dataset(staging / "validation_samples.csv", validation, all_features)
        for filename, rows in (("validation_predictions.csv", predictions), ("feature_importances.csv", sorted(importances, key=lambda row: (row["model"], -row["importance"])))):
            with (staging / filename).open("w", newline="") as destination:
                writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
        for filename, payload in (("metrics.json", report), ("feature_columns.json", feature_sets), ("capture_audit.json", audits)):
            (staging / filename).write_text(json.dumps(payload, indent=2) + "\n")
        os.replace(staging, output)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print("RESULTS", output)


if __name__ == "__main__":
    main()