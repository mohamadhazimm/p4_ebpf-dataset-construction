#!/usr/bin/env python3
"""Evaluate controlled scenarios with offline P4-shaped PCAP features."""

from __future__ import annotations

import argparse
import ast
import csv
import importlib.util
import json
import re
import statistics
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
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline


STUDY_DIR = Path(__file__).resolve().parents[1]
HAZIM_DIR = STUDY_DIR.parent.parent
P4_REPO = HAZIM_DIR / "p4_ebpf"
P4_ANALYZER_PATH = P4_REPO / "analyze_p4_pcap_ablation.py"
P4_COLLECTOR_PATH = P4_REPO / "hybrid_collector.py"
P4_INGRESS_PATH = P4_REPO / "thesis-hybrid-ebpf-p4" / "ingress.p4"
P4_READER_PATH = (
    P4_REPO / "thesis-hybrid-ebpf-p4" / "python" / "read_registers_with_index.py"
)
HOST_METADATA_FIELDS = {"ebpf_status", "ebpf_unique_threads"}
P4_SIGNAL_CONTRACT = {
    "net_flow_count_seen": (
        "active index rows returned by the BFRT reader",
        "Count active hashed buckets retained through the collector's active-flow TTL.",
    ),
    "net_pkts_total_delta": (
        "reg_pkts cumulative counter",
        "Sum per-index packet-counter differences for the current window.",
    ),
    "net_bytes_total_delta": (
        "reg_bytes cumulative counter",
        "Sum per-index byte-counter differences for the current window.",
    ),
    "net_pkts_ab_delta": (
        "reg_pkts_ab cumulative counter",
        "Sum per-index A-to-B packet-counter differences for the current window.",
    ),
    "net_bytes_ab_delta": (
        "reg_bytes_ab cumulative counter",
        "Sum per-index A-to-B byte-counter differences for the current window.",
    ),
    "net_pkts_ba_delta": (
        "reg_pkts minus reg_pkts_ab",
        "Difference of derived B-to-A cumulative packets for the current window.",
    ),
    "net_bytes_ba_delta": (
        "reg_bytes minus reg_bytes_ab",
        "Difference of derived B-to-A cumulative bytes for the current window.",
    ),
    "net_min_len_mean": (
        "reg_min_len across active indices",
        "Mean of each active bucket's cumulative minimum packet length.",
    ),
    "net_max_len_mean": (
        "reg_max_len across active indices",
        "Mean of each active bucket's cumulative maximum packet length.",
    ),
    "net_min_len_min": (
        "reg_min_len across active indices",
        "Minimum bucket-level cumulative minimum packet length.",
    ),
    "net_max_len_max": (
        "reg_max_len across active indices",
        "Maximum bucket-level cumulative maximum packet length.",
    ),
    "net_avg_pkt_size_delta": (
        "net_bytes_total_delta / net_pkts_total_delta",
        "Current-window total bytes per packet, with zero on a zero denominator.",
    ),
    "net_avg_pkt_size_ab_delta": (
        "net_bytes_ab_delta / net_pkts_ab_delta",
        "Current-window A-to-B bytes per packet, with zero on a zero denominator.",
    ),
    "net_avg_pkt_size_ba_delta": (
        "net_bytes_ba_delta / net_pkts_ba_delta",
        "Current-window B-to-A bytes per packet, with zero on a zero denominator.",
    ),
    "net_flow_duration_mean": (
        "reg_last_ts minus reg_first_ts",
        "Mean duration among active buckets with valid timestamps.",
    ),
    "net_flow_duration_max": (
        "reg_last_ts minus reg_first_ts",
        "Maximum duration among active buckets with valid timestamps.",
    ),
    "net_bytes_per_sec_delta": (
        "net_bytes_total_delta / window_seconds",
        "Current-window bytes per second.",
    ),
    "net_pkts_per_sec_delta": (
        "net_pkts_total_delta / window_seconds",
        "Current-window packets per second.",
    ),
    "net_down_up_ratio_delta": (
        "net_bytes_ba_delta / net_bytes_ab_delta",
        "Current-window B-to-A/A-to-B byte ratio, with zero on a zero denominator.",
    ),
    "net_ab_ratio_pkt_delta": (
        "net_pkts_ab_delta / net_pkts_total_delta",
        "Current-window A-to-B packet fraction.",
    ),
    "net_ba_ratio_pkt_delta": (
        "net_pkts_ba_delta / net_pkts_total_delta",
        "Current-window B-to-A packet fraction.",
    ),
    "net_ab_ratio_byte_delta": (
        "net_bytes_ab_delta / net_bytes_total_delta",
        "Current-window A-to-B byte fraction.",
    ),
    "net_ba_ratio_byte_delta": (
        "net_bytes_ba_delta / net_bytes_total_delta",
        "Current-window B-to-A byte fraction.",
    ),
    "net_syn_delta": (
        "reg_syn cumulative counter",
        "Sum per-index SYN counter differences for the current window.",
    ),
    "net_ack_delta": (
        "reg_ack cumulative counter",
        "Sum per-index ACK counter differences for the current window.",
    ),
    "net_rst_delta": (
        "reg_rst cumulative counter",
        "Sum per-index RST counter differences for the current window.",
    ),
    "net_flows_with_ab": (
        "reg_pkts_ab cumulative counter",
        "Count active buckets with any cumulative A-to-B packet or byte activity.",
    ),
    "net_flows_with_ba": (
        "reg_pkts and reg_pkts_ab cumulative counters",
        "Count active buckets with any derived cumulative B-to-A packet or byte activity.",
    ),
    "net_dir_valid_count": (
        "reg_dir_valid",
        "Count active buckets whose first-seen direction reference is initialized.",
    ),
}
HOST_SIGNAL_CONTRACT = {
    "host_active_processes": ("nonempty HostMon process rows", "Count process rows with activity in the window."),
    "host_exec_total": ("EXEC", "Sum execution events over process rows."),
    "host_open_total": ("OPEN", "Sum open events over process rows."),
    "host_rename_total": ("REN", "Sum rename events over process rows."),
    "host_unlink_total": ("DEL", "Sum unlink/delete events over process rows."),
    "host_connect_total": ("CONN", "Sum connect events over process rows."),
    "host_unique_ip_total": ("UNIQIP", "Sum per-process distinct IPv4 destination counts."),
    "host_unique_port_total": ("UNIQPRT", "Sum per-process distinct destination-port counts."),
    "host_total_syscalls_total": ("TOTAL_SYSCALLS", "Sum syscall-entry events over process rows."),
    "host_unique_syscalls_mean": ("UNIQUE_SYSCALLS", "Mean per-process distinct syscall IDs."),
    "host_unique_syscalls_max": ("UNIQUE_SYSCALLS", "Maximum per-process distinct syscall IDs."),
    "host_entropy_mean": ("ENTROPY", "Mean per-process syscall-ID entropy in bits."),
    "host_entropy_max": ("ENTROPY", "Maximum per-process syscall-ID entropy in bits."),
    "host_top_syscall_freq_mean": ("TOP_SYSCALL_FREQ", "Mean per-process top-syscall fraction."),
    "host_top_syscall_freq_max": ("TOP_SYSCALL_FREQ", "Maximum per-process top-syscall fraction."),
    "host_avg_run_length_mean": ("AVG_RUN_LENGTH", "Mean per-process consecutive-syscall run length."),
    "host_avg_run_length_max": ("AVG_RUN_LENGTH", "Maximum per-process consecutive-syscall run length."),
    "host_max_run_length_mean": ("MAX_RUN_LENGTH", "Mean per-process maximum consecutive-syscall run length."),
    "host_max_run_length_max": ("MAX_RUN_LENGTH", "Maximum per-process maximum consecutive-syscall run length."),
    "host_transition_count_total": ("TRANSITION_COUNT", "Sum adjacent syscall-ID changes over process rows."),
    "host_rare_syscall_ratio_mean": ("RARE_SYSCALL_RATIO", "Mean per-process singleton syscall-event ratio."),
    "host_rare_syscall_ratio_max": ("RARE_SYSCALL_RATIO", "Maximum per-process singleton syscall-event ratio."),
    "host_first50_unique_mean": ("FIRST50_UNIQUE", "Mean distinct syscall IDs in each process's first 50 events."),
    "host_first50_unique_max": ("FIRST50_UNIQUE", "Maximum distinct syscall IDs in each process's first 50 events."),
    "host_first100_unique_mean": ("FIRST100_UNIQUE", "Mean distinct syscall IDs in each process's first 100 events."),
    "host_first100_unique_max": ("FIRST100_UNIQUE", "Maximum distinct syscall IDs in each process's first 100 events."),
}


def load_p4_analyzer(path: Path):
    spec = importlib.util.spec_from_file_location("p4_pcap_analyzer", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load offline P4 analyzer: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def numeric(value: str | None) -> float:
    if value in (None, ""):
        raise ValueError("A required telemetry feature is missing")
    return float(value)


def sample_summaries(rows: list[dict[str, str]], fields: list[str]) -> dict[str, float]:
    result = {}
    for field in fields:
        values = [numeric(row.get(field)) for row in rows]
        prefix = f"host__{field}__"
        result[prefix + "mean"] = statistics.mean(values)
        result[prefix + "max"] = max(values)
        result[prefix + "sum"] = sum(values)
        result[prefix + "std"] = float(np.std(values))
        result[prefix + "active_windows"] = float(sum(value != 0 for value in values))
    return result


def read_collector_schema(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in {"HOST_ZERO", "NET_ZERO"}:
                values[target.id] = ast.literal_eval(node.value)
    if set(values) != {"HOST_ZERO", "NET_ZERO"}:
        raise ValueError(f"Could not read HOST_ZERO/NET_ZERO from {path}")
    return set(values["HOST_ZERO"]), set(values["NET_ZERO"])


def read_reader_registers(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "REG_NAMES" for target in node.targets):
            return set(ast.literal_eval(node.value))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if "REG_NAMES" not in node.value:
            continue
        embedded_tree = ast.parse(node.value)
        for embedded_node in embedded_tree.body:
            if not isinstance(embedded_node, ast.Assign):
                continue
            if any(
                isinstance(target, ast.Name) and target.id == "REG_NAMES"
                for target in embedded_node.targets
            ):
                return set(ast.literal_eval(embedded_node.value))
    raise ValueError(f"Could not read REG_NAMES from {path}")


def declared_registers(path: Path) -> set[str]:
    source = path.read_text(encoding="utf-8")
    return set(re.findall(r"\)\s*(reg_[a-z0-9_]+)\s*;", source))


def read_cohort(
    cohort_name: str,
    manifest_path: Path,
    runs_dir: Path,
    analyzer,
    host_fields: list[str] | None,
) -> tuple[list[dict], list[dict], list[dict], list[str]]:
    manifest_rows = load_csv(manifest_path)
    if not manifest_rows:
        raise ValueError(f"Scenario manifest is empty: {manifest_path}")
    examples = []
    alignment_rows = []
    headers = None

    for item in manifest_rows:
        artifact = item["sample_artifact"]
        sample_dir = runs_dir / artifact
        run_dirs = list((sample_dir / "output").glob("*/"))
        if len(run_dirs) != 1:
            raise ValueError(f"Expected one run output for {artifact}, found {len(run_dirs)}")
        run_dir = run_dirs[0]
        required_files = ("telemetry.csv", "run.json", "packet_capture.pcap")
        if any(not (run_dir / filename).is_file() for filename in required_files):
            raise ValueError(f"Missing telemetry, run metadata, or PCAP for {artifact}")
        telemetry_rows = load_csv(run_dir / "telemetry.csv")
        if not telemetry_rows:
            raise ValueError(f"No telemetry windows for {artifact}")
        current_headers = set(telemetry_rows[0])
        headers = current_headers if headers is None else headers & current_headers
        metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        features, _, diagnostics = analyzer.derive_p4_features(
            run_dir / "packet_capture.pcap",
            telemetry_rows,
            metadata,
        )
        run_status = metadata.get("status", "missing")
        ebpf_status = metadata.get("ebpf_status", "missing")
        capture_status = metadata.get("packet_capture_status", "missing")
        diagnostics = {
            **diagnostics,
            "run_status": run_status,
            "ebpf_status": ebpf_status,
            "packet_capture_status": capture_status,
        }
        aligned = diagnostics["alignment_status"] == "unique"
        sensors_active = (
            run_status == "completed"
            and ebpf_status == "active"
            and capture_status == "active"
        )
        pair_id = f"{cohort_name}::{item['pair_id']}"
        alignment_rows.append(
            {
                "cohort": cohort_name,
                "sample_artifact": artifact,
                "pair_id": pair_id,
                "scenario_id": item.get("scenario_id", item.get("workload_family", "")),
                "condition": item["condition"],
                "alignment_status": diagnostics["alignment_status"],
                "sensors_active": int(sensors_active),
                "pcap_frame_count": diagnostics.get("pcap_frame_count", ""),
                "telemetry_packet_count": diagnostics.get("telemetry_packet_count", ""),
                "p4_eligible_packets_in_windows": diagnostics.get(
                    "p4_eligible_packets_in_windows", ""
                ),
                "p4_eligible_behavior_packet": int(
                    item["condition"] in {"attack_simulation", "benign_network_only"}
                    and int(float(diagnostics.get("p4_eligible_packets_in_windows") or 0)) > 0
                ),
                "included": 0,
            }
        )
        examples.append(
            {
                "cohort": cohort_name,
                "manifest": item,
                "pair_id": pair_id,
                "telemetry": telemetry_rows,
                "p4_features": features if aligned else {},
                "diagnostics": diagnostics,
                "sensors_active": sensors_active,
            }
        )

    if headers is None:
        raise ValueError(f"No telemetry schema available for {cohort_name}")
    observed_host_fields = sorted(
        field
        for field in headers
        if field.startswith("ebpf_") and field not in HOST_METADATA_FIELDS
    )
    if host_fields is not None and observed_host_fields != host_fields:
        raise ValueError(f"eBPF field schema differs between cohorts: {cohort_name}")
    return examples, alignment_rows, manifest_rows, observed_host_fields


def metrics_for(labels: np.ndarray, predictions: np.ndarray, probabilities: np.ndarray) -> dict:
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


def numeric_matrix(rows: list[dict], features: list[str]) -> np.ndarray:
    return np.asarray([[float(row[feature]) for feature in features] for row in rows], dtype=float)


def family_columns(features: list[str]) -> dict[str, list[int]]:
    groups = defaultdict(list)
    for index, feature in enumerate(features):
        family, separator, _ = feature.rpartition("__")
        if not separator:
            raise ValueError(f"Feature has no summary suffix: {feature}")
        groups[family].append(index)
    return dict(groups)


def run_models(
    rows: list[dict],
    network_features: list[str],
    host_features: list[str],
    signal_budget: int,
    folds: int,
    seed: int,
) -> tuple[dict, list[dict], list[dict]]:
    labels = np.asarray([int(row["label"]) for row in rows], dtype=int)
    groups = np.asarray([row["group_id"] for row in rows], dtype=str)
    if len(set(groups)) < folds:
        raise ValueError("There are fewer independent families than cross-validation folds")
    network_matrix = numeric_matrix(rows, network_features)
    host_matrix = numeric_matrix(rows, host_features)
    host_groups = family_columns(host_features)
    if len(host_groups) < signal_budget:
        raise ValueError("Host sensor has fewer raw signal families than the P4 signal budget")
    splits = list(
        StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed).split(
            np.zeros((len(labels), 1)), labels, groups
        )
    )
    for fold_index, (_, test_indices) in enumerate(splits, start=1):
        if set(labels[test_indices]) != {0, 1}:
            raise ValueError(f"Fold {fold_index} contains only one class")

    variants = (
        "network_p4_offline",
        "host_ebpf_observed",
        "hybrid_full",
        "hybrid_equal_signal_families",
    )
    probabilities = {name: np.full(len(rows), np.nan) for name in variants}
    fold_ids = {name: np.zeros(len(rows), dtype=int) for name in variants}
    fold_metrics = {name: [] for name in variants}
    selected_rows = []

    for fold_index, (train_indices, test_indices) in enumerate(splits, start=1):
        imputer = SimpleImputer(strategy="median").fit(host_matrix[train_indices])
        train_host = imputer.transform(host_matrix[train_indices])
        test_host = imputer.transform(host_matrix[test_indices])
        scores = mutual_info_classif(
            train_host,
            labels[train_indices],
            random_state=seed + fold_index,
        )
        family_scores = {
            family: float(np.mean(scores[indices]))
            for family, indices in host_groups.items()
        }
        selected_families = sorted(
            family_scores,
            key=lambda family: (-family_scores[family], family),
        )[:signal_budget]
        selected_set = set(selected_families)
        selected_indices = [
            index
            for index, feature in enumerate(host_features)
            if feature.rpartition("__")[0] in selected_set
        ]
        if len(selected_indices) != signal_budget * len(next(iter(host_groups.values()))):
            raise RuntimeError("Signal-family selection did not preserve a balanced feature budget")
        selected_rows.extend(
            {
                "fold": fold_index,
                "host_signal": family,
                "mean_summary_mutual_information": family_scores[family],
                "selection_rank": rank,
                "host_signal_budget": signal_budget,
                "p4_signal_budget": signal_budget,
            }
            for rank, family in enumerate(selected_families, start=1)
        )
        matrices = {
            "network_p4_offline": (network_matrix[train_indices], network_matrix[test_indices]),
            "host_ebpf_observed": (train_host, test_host),
            "hybrid_full": (
                np.hstack((train_host, network_matrix[train_indices])),
                np.hstack((test_host, network_matrix[test_indices])),
            ),
            "hybrid_equal_signal_families": (
                np.hstack((train_host[:, selected_indices], network_matrix[train_indices])),
                np.hstack((test_host[:, selected_indices], network_matrix[test_indices])),
            ),
        }
        for name, (train_matrix, test_matrix) in matrices.items():
            model = make_pipeline(
                SimpleImputer(strategy="median"),
                RandomForestClassifier(
                    n_estimators=500,
                    max_features="sqrt",
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    random_state=seed + fold_index,
                    n_jobs=-1,
                ),
            )
            model.fit(train_matrix, labels[train_indices])
            fold_probabilities = model.predict_proba(test_matrix)[:, 1]
            predictions = (fold_probabilities >= 0.5).astype(int)
            probabilities[name][test_indices] = fold_probabilities
            fold_ids[name][test_indices] = fold_index
            fold_metrics[name].append(
                metrics_for(labels[test_indices], predictions, fold_probabilities)
            )

    summary = {"folds": folds, "splitter": "StratifiedGroupKFold by scenario family", "seed": seed, "feature_sets": {}}
    prediction_rows = []
    for name in variants:
        if np.isnan(probabilities[name]).any():
            raise RuntimeError(f"Missing out-of-fold probabilities for {name}")
        predictions = (probabilities[name] >= 0.5).astype(int)
        summary["feature_sets"][name] = {
            "derived_column_count": len(network_features)
            if name == "network_p4_offline"
            else len(host_features)
            if name == "host_ebpf_observed"
            else len(host_features) + len(network_features)
            if name == "hybrid_full"
            else signal_budget * 5 + len(network_features),
            "pooled_oof": metrics_for(labels, predictions, probabilities[name]),
            "fold_metrics": fold_metrics[name],
            "fold_std_balanced_accuracy": float(
                np.std([metric["balanced_accuracy"] for metric in fold_metrics[name]], ddof=1)
            ),
        }
        for index, row in enumerate(rows):
            prediction_rows.append(
                {
                    "feature_set": name,
                    "sample_artifact": row["sample_artifact"],
                    "scenario_id": row["scenario_id"],
                    "label": labels[index],
                    "fold": fold_ids[name][index],
                    "probability_attack": probabilities[name][index],
                    "prediction": predictions[index],
                }
            )

    group_names = sorted(set(groups))
    per_group = {}
    for name in variants:
        per_group[name] = {
            group: float(balanced_accuracy_score(labels[groups == group], predictions[groups == group]))
            for group in group_names
            for predictions in [(probabilities[name] >= 0.5).astype(int)]
        }
    comparator = "hybrid_equal_signal_families"
    best_single = {
        group: max(
            per_group["network_p4_offline"][group],
            per_group["host_ebpf_observed"][group],
        )
        for group in group_names
    }
    deltas = np.asarray(
        [per_group[comparator][group] - best_single[group] for group in group_names]
    )
    rng = np.random.default_rng(seed)
    bootstrap = np.asarray(
        [np.mean(rng.choice(deltas, size=len(deltas), replace=True)) for _ in range(10000)]
    )
    summary["family_balanced_accuracy_delta_vs_best_single"] = {
        "mean": float(np.mean(deltas)),
        "family_bootstrap_95pct_interval": [
            float(np.quantile(bootstrap, 0.025)),
            float(np.quantile(bootstrap, 0.975)),
        ],
        "families": len(group_names),
        "comparison": comparator,
    }
    summary["per_family_balanced_accuracy"] = per_group
    return summary, prediction_rows, selected_rows


def main() -> int:
    default_legacy_manifest = STUDY_DIR / "data/hybrid_scenarios/scenario_manifest.csv"
    default_legacy_runs = STUDY_DIR / "data/hybrid_scenarios/runs/scenario-v1-20261013"
    default_v7_manifest = STUDY_DIR / "data/hybrid_scenarios/v7/scenario_manifest.csv"
    default_v7_runs = STUDY_DIR / "data/hybrid_scenarios/v7/runs/p4-additions-sinkon"
    default_output = STUDY_DIR / "data/hybrid_scenarios/v7/p4_family_breadth_20261014"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-manifest", type=Path, default=default_legacy_manifest)
    parser.add_argument("--legacy-runs", type=Path, default=default_legacy_runs)
    parser.add_argument("--new-manifest", type=Path, default=default_v7_manifest)
    parser.add_argument("--new-runs", type=Path, default=default_v7_runs)
    parser.add_argument("--p4-repo", type=Path, default=P4_REPO)
    parser.add_argument("--output-dir", type=Path, default=default_output)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    analyzer = load_p4_analyzer(args.p4_repo / "analyze_p4_pcap_ablation.py")
    collector_path = args.p4_repo / "hybrid_collector.py"
    ingress_path = args.p4_repo / "thesis-hybrid-ebpf-p4" / "ingress.p4"
    reader_path = args.p4_repo / "thesis-hybrid-ebpf-p4" / "python" / "read_registers_with_index.py"
    host_contract, net_contract = read_collector_schema(collector_path)
    if set(P4_SIGNAL_CONTRACT) != net_contract:
        raise ValueError("The documented P4 feature contract does not cover NET_ZERO exactly")
    if set(HOST_SIGNAL_CONTRACT) != host_contract:
        raise ValueError("The documented HostMon feature contract does not cover HOST_ZERO exactly")
    analyzer_feature_set = set(analyzer.P4_FEATURES)
    if analyzer_feature_set != net_contract:
        raise ValueError(
            "Offline P4 feature names differ from hybrid_collector.py NET_ZERO: "
            f"collector-only={sorted(net_contract - analyzer_feature_set)}, "
            f"analyzer-only={sorted(analyzer_feature_set - net_contract)}"
        )

    examples = []
    alignment_rows = []
    manifest_rows_by_pair = defaultdict(dict)
    host_fields = None
    cohort_args = (
        ("legacy-v1", args.legacy_manifest, args.legacy_runs),
        ("p4-additions-v7", args.new_manifest, args.new_runs),
    )
    alignment_counts = Counter()
    for cohort_name, manifest_path, runs_dir in cohort_args:
        loaded, audits, manifests, current_host_fields = read_cohort(
            cohort_name,
            manifest_path,
            runs_dir,
            analyzer,
            host_fields,
        )
        host_fields = current_host_fields
        examples.extend(loaded)
        alignment_rows.extend(audits)
        for example in loaded:
            manifest_rows_by_pair[example["pair_id"]][example["manifest"]["condition"]] = example
            alignment_counts[example["diagnostics"]["alignment_status"]] += 1

    if host_fields is None or not host_fields:
        raise ValueError("No numeric eBPF signal fields were found")
    pair_audit_rows = []
    included_pairs = []
    for pair_id, conditions in sorted(manifest_rows_by_pair.items()):
        required = {"attack_simulation", "benign_file_only", "benign_network_only"}
        complete = set(conditions) == required
        aligned = complete and all(
            sample["diagnostics"]["alignment_status"] == "unique"
            and sample["sensors_active"]
            for sample in conditions.values()
        )
        behavior_packets_visible = complete and all(
            int(float(conditions[condition]["diagnostics"].get(
                "p4_eligible_packets_in_windows"
            ) or 0)) > 0
            for condition in ("attack_simulation", "benign_network_only")
        )
        aligned = aligned and behavior_packets_visible
        if aligned:
            included_pairs.append((pair_id, conditions))
            for audit in alignment_rows:
                if audit["pair_id"] == pair_id:
                    audit["included"] = 1
        if complete:
            attack = conditions["attack_simulation"]
            file_only = conditions["benign_file_only"]
            network_only = conditions["benign_network_only"]
            host_attack = sample_summaries(attack["telemetry"], host_fields)
            host_file = sample_summaries(file_only["telemetry"], host_fields)
            host_names = list(host_attack)
            network_attack = attack["p4_features"]
            network_control = network_only["p4_features"]
            p4_names = sorted(network_attack)
            host_equal = sum(
                np.isclose(host_attack[name], host_file[name], rtol=0, atol=1e-12)
                for name in host_names
            ) / len(host_names)
            p4_equal = (
                sum(
                    np.isclose(network_attack[name], network_control.get(name, np.nan), rtol=0, atol=1e-12)
                    for name in p4_names
                ) / len(p4_names)
                if network_attack and network_control
                else 0.0
            )
            file_match = all(
                host_attack[f"host__{field}__sum"] == host_file[f"host__{field}__sum"]
                for field in (
                    "ebpf_file_write_success_count",
                    "ebpf_file_write_bytes",
                )
                if f"host__{field}__sum" in host_attack
            )
        else:
            host_equal = ""
            p4_equal = ""
            file_match = ""
        pair_audit_rows.append(
            {
                "pair_id": pair_id,
                "scenario_id": next(iter(conditions.values()))["manifest"].get("scenario_id", "") if conditions else "",
                "condition_count": len(conditions),
                "included_complete_triplet": int(aligned),
                "attack_and_network_control_p4_visible": int(behavior_packets_visible),
                "host_summary_exact_fraction_attack_vs_file_only": host_equal,
                "p4_summary_exact_fraction_attack_vs_network_only": p4_equal,
                "file_write_counters_match": file_match,
            }
        )

    if not included_pairs:
        raise ValueError("No complete, uniquely aligned triplets are available")
    dataset_rows = []
    network_features = list(analyzer.P4_SAMPLE_FEATURES)
    host_features = [
        f"host__{field}__{stat}"
        for field in host_fields
        for stat in analyzer.P4_WINDOW_STATS
    ]
    for pair_id, conditions in included_pairs:
        for condition in ("attack_simulation", "benign_file_only", "benign_network_only"):
            example = conditions[condition]
            manifest = example["manifest"]
            row = {
                "cohort": example["cohort"],
                "sample_artifact": manifest["sample_artifact"],
                "label": int(manifest["label"]),
                "class_name": manifest.get("class_name", ""),
                "scenario_id": manifest.get("scenario_id", manifest.get("workload_family", "")),
                "condition": condition,
                "pair_id": pair_id,
                "group_id": f"scenario::{manifest.get('scenario_id', manifest.get('workload_family', 'unknown'))}",
                "alignment_status": example["diagnostics"]["alignment_status"],
                "p4_eligible_packets_in_windows": example["diagnostics"].get(
                    "p4_eligible_packets_in_windows", ""
                ),
            }
            row.update(example["p4_features"])
            row.update(sample_summaries(example["telemetry"], host_fields))
            dataset_rows.append(row)

    model_summary, predictions, selection_rows = run_models(
        dataset_rows,
        network_features,
        host_features,
        len(analyzer.P4_FEATURES),
        args.folds,
        args.seed,
    )
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    contract_rows = []
    for signal, (raw_source, definition) in P4_SIGNAL_CONTRACT.items():
        contract_rows.append(
            {
                "sensor": "P4 canonical network collector",
                "signal": signal,
                "raw_source": raw_source,
                "definition": definition,
                "summary_statistics": ";".join(analyzer.P4_WINDOW_STATS),
                "sample_feature_pattern": f"network__p4_{signal}__<statistic>",
                "observed_directly_in_scenario_run": "no; reconstructed from PCAP",
                "live_p4_target_measurement": "no",
            }
        )
    for signal, (raw_source, definition) in HOST_SIGNAL_CONTRACT.items():
        contract_rows.append(
            {
                "sensor": "HostMon canonical host collector",
                "signal": signal,
                "raw_source": raw_source,
                "definition": definition,
                "summary_statistics": ";".join(analyzer.P4_WINDOW_STATS),
                "sample_feature_pattern": f"host__{signal}__<statistic>",
                "observed_directly_in_scenario_run": "no; HostMon was not run",
                "live_p4_target_measurement": "not_applicable",
            }
        )
    for field in host_fields:
        contract_rows.append(
            {
                "sensor": "Observed eBPF scenario host telemetry",
                "signal": field,
                "raw_source": f"telemetry.csv:{field}",
                "definition": "Captured eBPF syscall/event counter or byte value; semantics follow the source field name.",
                "summary_statistics": ";".join(analyzer.P4_WINDOW_STATS),
                "sample_feature_pattern": f"host__{field}__<statistic>",
                "observed_directly_in_scenario_run": "yes",
                "live_p4_target_measurement": "not_applicable",
            }
        )
    write_csv(
        output_dir / "feature_contract.csv",
        contract_rows,
        list(contract_rows[0]),
    )
    metadata_fields = [
        "cohort", "sample_artifact", "label", "class_name", "scenario_id", "condition",
        "pair_id", "group_id", "alignment_status", "p4_eligible_packets_in_windows",
    ]
    write_csv(
        output_dir / "p4_emulated_scenario_dataset.csv",
        dataset_rows,
        metadata_fields + network_features + host_features,
    )
    feature_columns = {
        "network": network_features,
        "host": host_features,
        "hybrid": host_features + network_features,
    }
    (output_dir / "p4_emulated_scenario_dataset.feature_columns.json").write_text(
        json.dumps(feature_columns, indent=2) + "\n", encoding="utf-8"
    )
    write_csv(
        output_dir / "pcap_alignment_audit.csv",
        alignment_rows,
        list(alignment_rows[0]),
    )
    write_csv(
        output_dir / "paired_control_audit.csv",
        pair_audit_rows,
        list(pair_audit_rows[0]),
    )
    write_csv(
        output_dir / "host_signal_family_selections.csv",
        selection_rows,
        list(selection_rows[0]),
    )
    write_csv(
        output_dir / "out_of_fold_predictions.csv",
        predictions,
        list(predictions[0]),
    )

    declared = declared_registers(ingress_path)
    requested = read_reader_registers(reader_path)
    source_metadata = {
        "analysis_type": "offline PCAP-derived P4-shaped feature emulation",
        "live_p4_target_validated": False,
        "tofino_sde_available": False,
        "p4_register_hash_buckets": 65536,
        "offline_flow_key": "exact IPv4/protocol/sorted-endpoint tuple",
        "p4_registers_declared": sorted(declared),
        "reader_registers_not_declared_in_current_ingress": sorted(requested - declared),
        "canonical_collector_p4_signal_families": len(net_contract),
        "offline_analyzer_p4_signal_families": len(analyzer_feature_set),
        "p4_feature_names_exact_match": analyzer_feature_set == net_contract,
        "canonical_hostmon_window_features": len(host_contract),
        "observed_ebpf_host_signal_families": len(host_fields),
        "hostmon_output_not_collected_in_scenario_runs": True,
        "summary_statistics": list(analyzer.P4_WINDOW_STATS),
    }
    breadth_rows = [
        {
            "sensor": "P4 network canonical collector",
            "base_signal_families": len(net_contract),
            "sample_model_columns": len(network_features),
            "measurement": "offline PCAP-derived emulation; names exactly match NET_ZERO",
        },
        {
            "sensor": "HostMon canonical collector",
            "base_signal_families": len(host_contract),
            "sample_model_columns": len(host_contract) * len(analyzer.P4_WINDOW_STATS),
            "measurement": "source schema only; HostMon output was not collected for this cohort",
        },
        {
            "sensor": "Observed eBPF scenario telemetry",
            "base_signal_families": len(host_fields),
            "sample_model_columns": len(host_features),
            "measurement": "captured Linux syscall/event counters; not identical to HostMon",
        },
        {
            "sensor": "Full observed hybrid",
            "base_signal_families": len(host_fields) + len(net_contract),
            "sample_model_columns": len(host_features) + len(network_features),
            "measurement": "observed eBPF plus offline P4-shaped features",
        },
        {
            "sensor": "Equal-signal-family hybrid",
            "base_signal_families": 2 * len(net_contract),
            "sample_model_columns": 2 * len(net_contract) * len(analyzer.P4_WINDOW_STATS),
            "measurement": "29 host eBPF families selected within each training fold plus 29 P4 families",
        },
    ]
    write_csv(output_dir / "feature_breadth.csv", breadth_rows, list(breadth_rows[0]))
    model_summary.update(
        {
            "source_samples": len(examples),
            "included_samples": len(dataset_rows),
            "included_complete_triplets": len(included_pairs),
            "excluded_samples_due_to_alignment_sensor_or_packet_visibility": len(examples) - len(dataset_rows),
            "family_count": len({row["group_id"] for row in dataset_rows}),
            "class_counts": {
                "benign_control": sum(int(row["label"]) == 0 for row in dataset_rows),
                "attack_simulation": sum(int(row["label"]) == 1 for row in dataset_rows),
            },
            "alignment_status_counts": dict(alignment_counts),
            "host_signal_family_count": len(host_fields),
            "p4_signal_family_count": len(net_contract),
            "feature_breadth": breadth_rows,
            "feature_contract": "feature_contract.csv; field-by-field source and transform mapping",
            "source_parity_audit": source_metadata,
            "outputs": str(output_dir),
            "interpretation": (
                "Controlled safe simulations only. P4 network signals are reconstructed from PCAPs; "
                "they are not readings from a live P4 target. Observed host signals are eBPF telemetry, "
                "not HostMon output."
            ),
        }
    )
    (output_dir / "analysis_report.json").write_text(
        json.dumps(model_summary, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(model_summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())