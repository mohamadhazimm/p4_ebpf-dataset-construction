#!/usr/bin/env python3
"""Audit saved classifier inputs without operating guests or changing captures."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parent


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def scores(labels, predictions, probabilities=None):
    result = {
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "confusion_tn_fp_fn_tp": confusion_matrix(labels, predictions, labels=[0, 1]).ravel().tolist(),
    }
    if probabilities is not None:
        result["roc_auc"] = float(roc_auc_score(labels, probabilities))
    return result


def evaluate(matrix, features, labels, folds, trees=500, select_families=False):
    probabilities = np.full(len(labels), np.nan)
    for fold in sorted(set(folds)):
        train = folds != fold
        selected = list(range(matrix.shape[1]))
        if select_families:
            information = mutual_info_classif(matrix[train], labels[train], random_state=42 + int(fold))
            families = defaultdict(list)
            for index, feature in enumerate(features):
                families[feature.rpartition("__")[0]].append(index)
            ranked = sorted(families, key=lambda family: (-float(np.mean(information[families[family]])), family))[:29]
            selected = [index for index, feature in enumerate(features) if feature.rpartition("__")[0] in ranked]
        model = RandomForestClassifier(
            n_estimators=trees, max_features="sqrt", min_samples_leaf=2,
            class_weight="balanced_subsample", random_state=42 + int(fold), n_jobs=1,
        )
        model.fit(matrix[train][:, selected], labels[train])
        probabilities[~train] = model.predict_proba(matrix[~train][:, selected])[:, 1]
    assert np.isfinite(probabilities).all()
    return {**scores(labels, probabilities >= .5, probabilities), "trees": trees,
            "candidate_columns": len(features), "training_fold_family_selection": select_families}, probabilities


def run_controls(rows, host, host_features, labels, folds, host_saved):
    controls = {}
    baseline, probabilities = evaluate(host, host_features, labels, folds, select_families=True)
    saved_probabilities = {row["sample_artifact"]: float(row["probability_malware"]) for row in host_saved}
    expected = np.array([saved_probabilities[row["sample_artifact"]] for row in rows])
    baseline["max_saved_probability_error"] = float(np.max(np.abs(expected - probabilities)))
    assert np.allclose(expected, probabilities, rtol=0, atol=1e-12)
    controls["reproduced_original_host29"] = baseline
    startup_signals = {"dup2", "dup3", "execve", "execveat", "openat", "openat_success", "close", "mmap", "mprotect", "fork", "exit", "event", "unique_threads"}
    families = [feature.removeprefix("host__ebpf_").rpartition("__")[0].removesuffix("_count") for feature in host_features]
    masks = {
        "without_dup2": ["dup2" not in feature for feature in host_features],
        "without_process_startup_families": [family not in startup_signals for family in families],
        "mean_and_max_only": [feature.endswith(("__mean", "__max")) for feature in host_features],
        "presence_only": [True] * len(host_features),
    }
    for name, mask in masks.items():
        indices = np.flatnonzero(mask)
        matrix = host[:, indices]
        if name == "presence_only":
            matrix = (matrix > 0).astype(float)
        controls[name] = evaluate(matrix, [host_features[index] for index in indices], labels, folds, select_families=True)[0]
    startup_indices = [index for index, family in enumerate(families) if family in startup_signals]
    controls["process_startup_families_only"] = evaluate(
        host[:, startup_indices], [host_features[index] for index in startup_indices], labels, folds,
    )[0]
    successful = np.array([int(row["sample_status"]) == 0 for row in rows])
    controls["exit_zero_only"] = {
        **evaluate(host[successful], host_features, labels[successful], folds[successful], select_families=True)[0],
        "class_counts": {str(label): int(np.count_nonzero(labels[successful] == label)) for label in (0, 1)},
        "limitation": "Exit 0 is not proof of attack activation or successful benign work; original folds restricted to this subset.",
    }
    telemetry_by_sample = []
    experiment = ROOT.parents[1]
    for row in rows:
        directory = experiment / "runs" / row["class_name"] / row["sample_artifact"] / "output"
        paths = list(directory.rglob("telemetry.csv"))
        assert len(paths) == 1
        telemetry_by_sample.append(read_csv(paths[0]))
    for name, start, end in (("first_window_only", 0, 1), ("after_first_window", 1, 40), ("after_two_seconds", 4, 40)):
        matrix = np.zeros_like(host)
        for row_index, telemetry in enumerate(telemetry_by_sample):
            for feature_index, feature in enumerate(host_features):
                signal, statistic = feature.removeprefix("host__").rsplit("__", 1)
                values = np.array([float(window[signal]) for window in telemetry[start:end]])
                summaries = {"mean": values.mean(), "max": values.max(), "sum": values.sum(),
                             "std": values.std(), "active_windows": np.count_nonzero(values)}
                matrix[row_index, feature_index] = summaries[statistic]
        result = evaluate(matrix, host_features, labels, folds, select_families=True)[0]
        result["all_zero_samples_by_class"] = {str(label): int(np.count_nonzero(np.all(matrix[labels == label] == 0, axis=1))) for label in (0, 1)}
        controls[name] = result
    permutation_results = []
    for seed in range(20):
        shuffled = np.random.default_rng(1000 + seed).permutation(labels)
        result = evaluate(host, host_features, shuffled, folds, trees=100, select_families=True)[0]
        permutation_results.append({"seed": 1000 + seed, **result})
    controls["label_permutations"] = {
        "scheme": "Shuffle sample labels globally; keep original group-disjoint folds; refit MI selector and RF using shuffled training labels; score shuffled validation labels.",
        "repeats": permutation_results,
        "balanced_accuracy_mean": float(np.mean([item["balanced_accuracy"] for item in permutation_results])),
        "balanced_accuracy_range": [min(item["balanced_accuracy"] for item in permutation_results), max(item["balanced_accuracy"] for item in permutation_results)],
        "limitation": "Diagnostic sample-level permutations are not a group-level inferential significance test; duplicate vectors remain within folds.",
    }
    return controls


def trace_events(rows, host_features):
    experiment = ROOT.parents[1]
    records = []
    failures = []
    representative_raw = []
    artifact_types = defaultdict(Counter)
    base_signals = sorted({feature.removeprefix("host__").rsplit("__", 1)[0] for feature in host_features})
    summaries_checked = 0
    root_setup_samples = Counter()
    named_outside_lineage = 0
    named_outside_observation = 0
    helper_named_events = 0
    helper_named_samples = []
    for row in rows:
        sample = row["sample_artifact"]
        directory = experiment / "runs" / row["class_name"] / sample / "output"
        run_path = next(directory.rglob("run.json"))
        directory = run_path.parent
        metadata = json.loads(run_path.read_text())
        assert metadata["malware_runner_sha256"] == "b366c337481e82e3118038ac966f3b35d5a5195123213a763a5ba2a8b1bf09d9"
        assert metadata["common_launch_wrapper"] and metadata["observation_mode"] == "fixed"
        artifact_types[row["class_name"]][metadata["sample_artifact_type"]] += 1
        telemetry = read_csv(directory / "telemetry.csv")
        for feature in host_features:
            signal, statistic = feature.removeprefix("host__").rsplit("__", 1)
            values = np.array([float(window[signal]) for window in telemetry])
            independent = {"mean": values.mean(), "max": values.max(), "sum": values.sum(),
                           "std": values.std(), "active_windows": np.count_nonzero(values)}[statistic]
            assert np.isclose(independent, float(row[feature]), rtol=1e-12, atol=1e-12)
            summaries_checked += 1
        root_pid = int(metadata["sample_root_pid"])
        start = int(metadata["sample_started_monotonic_ns"])
        end = int(metadata["observation_ended_monotonic_ns"])
        tracked = {root_pid}
        named_counts = Counter()
        dup2_by_comm = Counter()
        dup2_by_window = Counter()
        initial_setup = []
        root_exit_ms = []
        sequence = []
        helper_counts = Counter()
        last_ns = -1
        for event in read_csv(directory / "ebpf_events.csv"):
            timestamp = int(event["timestamp_ns"])
            assert timestamp >= last_ns
            last_ns = timestamp
            pid, tid = int(event["pid"]), int(event["tid"])
            if event["event"] == "fork" and pid in tracked:
                tracked.add(tid)
            if pid not in tracked and tid not in tracked:
                named_outside_lineage += 1
            if not start <= timestamp < end:
                named_outside_observation += 1
            if event["comm"] in {"sudo", "tcpdump", "bpftrace"}:
                helper_named_events += 1
                helper_counts[event["comm"]] += 1
            named_counts[event["event"]] += 1
            if event["event"] == "dup2":
                dup2_by_comm[event["comm"]] += 1
                dup2_by_window[event["window_id"]] += 1
                if pid == root_pid and event["comm"] == "python3":
                    initial_setup.append((timestamp - start) / 1e6)
            if event["event"] in {"dup2", "execve", "fork"} and len(sequence) < 30:
                sequence.append({"ms_from_launch": (timestamp - start) / 1e6, "pid": pid,
                                 "tid": tid, "comm": event["comm"], "event": event["event"], "detail": event["detail"]})
            if event["event"] == "exit":
                if tid == root_pid:
                    root_exit_ms.append((timestamp - start) / 1e6)
                tracked.discard(tid)
        fallback = metadata["ebpf_event_diagnostics"].get("raw_syscall_feature_fallbacks", {})
        for signal in base_signals:
            if signal in {"ebpf_unique_threads", "ebpf_event_count", "ebpf_file_write_bytes"}:
                continue
            event_name = signal.removeprefix("ebpf_").removesuffix("_count")
            expected = named_counts[event_name] + fallback.get(event_name, 0)
            actual = sum(float(window[signal]) for window in telemetry)
            if actual != expected:
                failures.append({"sample": sample, "feature": signal, "expected": expected, "telemetry": actual})
        root_setup_samples[row["class_name"]] += int(len(initial_setup) == 3)
        record = {
            "sample": sample, "class_name": row["class_name"], "artifact_type": metadata["sample_artifact_type"],
            "return_code": metadata["return_code"], "root_pid": root_pid,
            "run_path": str(directory.relative_to(experiment)),
            "dup2_by_comm": dict(dup2_by_comm), "dup2_by_window": dict(dup2_by_window),
            "root_python3_dup2_ms": initial_setup,
            "root_exit_ms": root_exit_ms,
            "execve_named": named_counts["execve"], "execve_fallback": fallback.get("execve", 0),
            "event_sequence": sequence,
            "host_active_windows": sum(any(float(window[signal]) > 0 for signal in base_signals) for window in telemetry),
            "first_window_named_event_fraction": float(telemetry[0]["ebpf_event_count"]) / max(sum(float(window["ebpf_event_count"]) for window in telemetry), 1),
        }
        records.append(record)
        if helper_counts:
            helper_named_samples.append({"sample": sample, "class_name": row["class_name"],
                                         "comm_counts": dict(helper_counts), "root_pid": root_pid,
                                         "attribution": "Within reconstructed workload descendants; comm alone does not imply collector-helper contamination."})
        if sum(item["class_name"] == row["class_name"] for item in representative_raw) < 2:
            raw_counts = Counter()
            raw_setup = []
            for event in read_csv(directory / "syscall_events.csv"):
                if int(event["pid"]) == root_pid and event["comm"] in {"python3", "bash", "benign_training"}:
                    raw_counts[(event["comm"], event["detail"])] += 1
                    if event["detail"] in {"id=33", "id=59"} and len(raw_setup) < 30:
                        raw_setup.append({"comm": event["comm"], "syscall": event["detail"],
                                          "ms_from_launch": (int(event["timestamp_ns"]) - start) / 1e6})
            representative_raw.append({"sample": sample, "class_name": row["class_name"], "root_launch_syscalls": raw_setup})
    assert not failures, failures[:3]
    assert named_outside_lineage == named_outside_observation == 0
    benign_root_exits = [record["root_exit_ms"][0] for record in records if record["class_name"] == "benign"]
    assert len(benign_root_exits) == 91 and max(benign_root_exits) < 500
    return {
        "host_summary_cells_independently_recomputed": summaries_checked,
        "named_plus_fallback_counter_mismatches": failures,
        "artifact_types": {label: dict(counts) for label, counts in artifact_types.items()},
        "samples_with_exactly_three_root_python3_dup2": dict(root_setup_samples),
        "benign_root_exit_ms_range": [min(benign_root_exits), max(benign_root_exits)],
        "named_events_outside_reconstructed_lineage": named_outside_lineage,
        "named_events_outside_observation": named_outside_observation,
        "named_events_with_helper_like_comm": helper_named_events,
        "helper_like_comm_attribution": helper_named_samples,
        "representative_raw_checks": representative_raw,
        "records": records,
        "limits": "Archived named-event ancestry and timing checks cannot detect never-recorded events; exec path arguments are absent from generic raw syscall records. No causal intervention or matched ELF counterfactual was collected.",
    }


def selection_sensitivity(rows, host_features):
    from run_scale100_p4_29x29 import load_family_maps

    experiment = ROOT.parents[1]
    maps = dict(zip(("malware", "benign"), load_family_maps()))
    existing = {row["sample_artifact"] for row in rows}
    expanded = list(rows)
    for cohort, family_map in maps.items():
        for sample, family in family_map.items():
            if sample in existing:
                continue
            run_path = next((experiment / "runs" / cohort / sample / "output").rglob("run.json"))
            metadata = json.loads(run_path.read_text())
            if metadata["collection_quality_status"] != "accepted":
                continue
            telemetry = read_csv(run_path.parent / "telemetry.csv")
            row = {"sample_artifact": sample, "label": int(cohort == "malware"),
                   "group_id": family if cohort == "malware" else f"benign::{family}"}
            for feature in host_features:
                signal, statistic = feature.removeprefix("host__").rsplit("__", 1)
                values = np.array([float(window[signal]) for window in telemetry])
                row[feature] = {"mean": values.mean(), "max": values.max(), "sum": values.sum(),
                                "std": values.std(), "active_windows": np.count_nonzero(values)}[statistic]
            expanded.append(row)
    matrix = np.array([[float(row[feature]) for feature in host_features] for row in expanded])
    labels = np.array([int(row["label"]) for row in expanded])
    groups = np.array([row["group_id"] for row in expanded])
    fold_ids = np.zeros(len(labels), dtype=int)
    for fold, (train, test) in enumerate(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(matrix, labels, groups), 1):
        assert not set(groups[train]) & set(groups[test])
        fold_ids[test] = fold
    result = evaluate(matrix, host_features, labels, fold_ids, select_families=True)[0]
    assert len(labels) == 198
    return {**result, "samples": len(labels), "restored_alignment_exclusions": len(labels) - len(rows),
            "class_counts": {str(label): int(np.count_nonzero(labels == label)) for label in (0, 1)},
            "limitation": "Host-only sensitivity on 198 accepted samples with newly computed group folds; not a replacement for aligned P4/hybrid evaluation."}


def main():
    rows = read_csv(ROOT / "aligned_p4_host_candidate_dataset.csv")
    contract = json.loads((ROOT / "feature_columns.json").read_text())
    host_features = contract["host_candidate_pool"]
    network_features = contract["network_p4"]
    saved = read_csv(ROOT / "oof_predictions.csv")
    host_saved = [row for row in saved if row["model"] == "host_ebpf_family_balanced"]
    fold_map = {row["sample_artifact"]: int(row["fold"]) for row in host_saved}
    labels = np.array([int(row["label"]) for row in rows])
    folds = np.array([fold_map[row["sample_artifact"]] for row in rows])
    groups = np.array([row["group_id"] for row in rows])
    host = np.array([[float(row[feature]) for feature in host_features] for row in rows])
    network = np.array([[float(row[feature]) for feature in network_features] for row in rows])
    assert len(rows) == len(fold_map) == 183
    assert np.isfinite(host).all() and np.isfinite(network).all()
    assert all(feature.startswith("host__ebpf_") for feature in host_features)
    split_audit = []
    for fold in sorted(set(folds)):
        train = folds != fold
        test = ~train
        overlap = sorted(set(groups[train]) & set(groups[test]))
        assert not overlap
        split_audit.append({"fold": int(fold), "train": int(train.sum()), "test": int(test.sum()), "group_overlap": overlap})
    duplicate_audit = {}
    for name, matrix in (("host", host), ("network", network)):
        buckets = defaultdict(list)
        for index, vector in enumerate(matrix):
            buckets[tuple(vector)].append(index)
        duplicate_audit[name] = {
            "unique_vectors": len(buckets),
            "duplicate_groups": [
                {"samples": [rows[index]["sample_artifact"] for index in indices],
                 "folds": sorted(set(int(folds[index]) for index in indices)),
                 "labels": sorted(set(int(labels[index]) for index in indices))}
                for indices in buckets.values() if len(indices) > 1
            ],
        }
    stumps = []
    for feature_index, feature in enumerate(host_features):
        predictions = np.zeros(len(labels), dtype=int)
        thresholds = []
        matrix = host[:, [feature_index]]
        for fold in sorted(set(folds)):
            train = folds != fold
            model = DecisionTreeClassifier(max_depth=1, random_state=42).fit(matrix[train], labels[train])
            predictions[~train] = model.predict(matrix[~train])
            thresholds.append(float(model.tree_.threshold[0]))
        stumps.append({
            "feature": feature,
            **scores(labels, predictions),
            "training_thresholds": thresholds,
            "class_quantiles": {
                str(label): np.quantile(matrix[labels == label], [0, .25, .5, .75, 1]).tolist()
                for label in (0, 1)
            },
        })
    stumps.sort(key=lambda row: (-row["balanced_accuracy"], row["feature"]))
    results = {
        "dataset_sha256": hashlib.sha256((ROOT / "aligned_p4_host_candidate_dataset.csv").read_bytes()).hexdigest(),
        "original_model_script_sha256": hashlib.sha256((ROOT / "run_scale100_p4_29x29.py").read_bytes()).hexdigest(),
        "original_metrics_sha256": hashlib.sha256((ROOT / "metrics.json").read_bytes()).hexdigest(),
        "class_counts": dict(Counter(row["class_name"] for row in rows)),
        "host_candidate_columns": len(host_features),
        "network_columns": len(network_features),
        "finite_inputs": True,
        "explicit_host_allowlist_ebpf_only": True,
        "split_audit": split_audit,
        "exact_duplicate_vectors": duplicate_audit,
        "single_feature_grouped_stumps": stumps,
    }
    print("Input audit passed; running baseline reproduction, ablations, and 20 label permutations.", flush=True)
    results["controls"] = run_controls(rows, host, host_features, labels, folds, host_saved)
    print("Model controls passed; reconciling host summaries and archived event provenance.", flush=True)
    results["event_provenance"] = trace_events(rows, host_features)
    results["host_only_alignment_selection_sensitivity"] = selection_sensitivity(rows, host_features)
    (ROOT / "perfect_score_investigation.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results["controls"], indent=2))


if __name__ == "__main__":
    main()