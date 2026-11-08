#!/usr/bin/env python3
"""Extract and evaluate the p4_ebpf 29-by-29 feature protocol on scale-100x100."""

from __future__ import annotations

import csv
import json
import math
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline

EXPERIMENT = Path(__file__).resolve().parents[2]
STUDY_DIR = EXPERIMENT.parents[2]
P4_DIR = STUDY_DIR.parents[1] / "p4_ebpf"
OUTPUT_DIR = Path(__file__).resolve().parent
HOST_ALLOWLIST = STUDY_DIR / "data/benign/revision3/labeled_sample_dataset.feature_columns.json"
FOLDS = 5
SEED = 42

sys.path.insert(0, str(STUDY_DIR / "src"))
sys.path.insert(0, str(P4_DIR))
from analyze_p4_pcap_ablation import (
    P4_FEATURES,
    P4_SAMPLE_FEATURES,
    P4_WINDOW_STATS,
    derive_p4_features,
    feature_family_indices,
    load_telemetry_rows,
    metrics_for,
    numeric_matrix,
)
from build_dataset import aggregate


def read_names(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_retrieval_status(path: Path) -> str:
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("status="):
            return line.partition("=")[2].strip()
    return "unknown"


def load_family_maps() -> tuple[dict[str, str], dict[str, str]]:
    selection = json.loads((EXPERIMENT / "selection.json").read_text(encoding="utf-8"))
    malware_families = {row["sample"]: row["family"] for row in selection["malware"]}
    benign_families = {row["sample"]: row["family"] for row in selection["benign"]}
    for filename in ("continuation_selection.json", "completion_selection.json"):
        replacement = json.loads((EXPERIMENT / filename).read_text(encoding="utf-8"))
        malware_families.pop(replacement["replaced_sample"]["sample"])
        malware_families[replacement["replacement_sample"]["sample"]] = replacement[
            "replacement_sample"
        ]["family"]
    return malware_families, benign_families


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def class_counts(labels: np.ndarray, indices: np.ndarray) -> dict[str, int]:
    return {
        "benign": int(np.count_nonzero(labels[indices] == 0)),
        "malware": int(np.count_nonzero(labels[indices] == 1)),
    }


def main() -> int:
    host_contract = json.loads(HOST_ALLOWLIST.read_text(encoding="utf-8"))
    host_features = list(host_contract["host"])
    host_families = feature_family_indices(host_features)
    if len(P4_FEATURES) != 29 or len(host_families) != 35:
        raise ValueError("Unexpected p4_ebpf 29-P4 / 35-host candidate contract")
    if len(P4_SAMPLE_FEATURES) != 29 * len(P4_WINDOW_STATS):
        raise ValueError("P4 sample feature contract must contain 29 families x five summaries")
    if any(len(indices) != len(P4_WINDOW_STATS) for indices in host_families.values()):
        raise ValueError("Each host candidate family must contain the five p4_ebpf summaries")

    malware_names = read_names(EXPERIMENT / "manifests/malware-100-completion.txt")
    benign_names = read_names(EXPERIMENT / "manifests/benign-100.txt")
    malware_families, benign_families = load_family_maps()
    if set(malware_names) != set(malware_families) or len(malware_names) != 100:
        raise ValueError("Final malware manifest and replacement-adjusted family map differ")
    if set(benign_names) != set(benign_families) or len(benign_names) != 100:
        raise ValueError("Benign manifest and family map differ")

    examples = []
    alignment_rows = []
    quality_exclusions = []
    alignment_exclusions = []
    parity_comparisons = 0
    parity_mismatches = []
    expected_p4_set = set(P4_FEATURES)

    for cohort, names, family_map, label in (
        ("malware", malware_names, malware_families, 1),
        ("benign", benign_names, benign_families, 0),
    ):
        for sample in names:
            sample_dir = EXPERIMENT / "runs" / cohort / sample
            host_log = sample_dir / "host_run.txt"
            if not host_log.is_file() or read_retrieval_status(host_log) != "completed":
                raise ValueError(f"{cohort}/{sample}: retrieval is not complete")
            run_paths = list((sample_dir / "output").rglob("run.json"))
            if len(run_paths) != 1:
                raise ValueError(f"{cohort}/{sample}: expected exactly one run.json")
            metadata = json.loads(run_paths[0].read_text(encoding="utf-8"))
            if metadata.get("telemetry_schema_version") != "2026-10-19.14":
                raise ValueError(f"{cohort}/{sample}: telemetry schema mismatch")
            if metadata.get("collection_quality_status") != "accepted":
                item = {
                    "cohort": cohort,
                    "sample_artifact": sample,
                    "status": "quality_rejected",
                    "reasons": metadata.get("collection_quality_reasons", []),
                }
                alignment_rows.append(item)
                quality_exclusions.append(item)
                continue

            telemetry = load_telemetry_rows(sample_dir)
            if len(telemetry) != 40:
                raise ValueError(f"{cohort}/{sample}: expected 40 telemetry windows")
            p4_group = metadata.get("telemetry_feature_groups", {}).get("p4_network", [])
            if set(p4_group) != expected_p4_set:
                raise ValueError(f"{cohort}/{sample}: stored P4 signal names differ from p4_ebpf")
            raw_fields = set(telemetry[0])
            host_base_fields = {
                feature.removeprefix("host__").rsplit("__", 1)[0]
                for feature in host_features
            }
            if not host_base_fields.issubset(raw_fields):
                raise ValueError(f"{cohort}/{sample}: host candidate fields are missing")

            packet_captures = list(sample_dir.rglob("packet_capture.pcap"))
            if len(packet_captures) != 1:
                raise ValueError(f"{cohort}/{sample}: expected one packet_capture.pcap")
            extracted_p4, _, diagnostics = derive_p4_features(
                packet_captures[0],
                telemetry,
                metadata,
                byte_layer="ethernet",
                rate_window="nominal",
            )
            alignment = diagnostics["alignment_status"]
            audit = {
                "cohort": cohort,
                "sample_artifact": sample,
                "status": alignment,
                "pcap_frames": diagnostics.get("pcap_frame_count", ""),
                "telemetry_packets": diagnostics.get("telemetry_packet_count", ""),
                "counter_error": diagnostics.get("pcap_telemetry_packet_count_abs_error", ""),
                "p4_byte_layer": diagnostics.get("p4_byte_layer", ""),
                "p4_rate_window": diagnostics.get("p4_rate_window", ""),
            }
            alignment_rows.append(audit)
            if alignment != "unique":
                alignment_exclusions.append(audit)
                continue

            summaries_by_signal = {}
            for signal in host_base_fields | expected_p4_set:
                values = [float(row[signal]) for row in telemetry]
                summaries_by_signal[signal] = aggregate(values)
            for signal in P4_FEATURES:
                for statistic in P4_WINDOW_STATS:
                    stored = summaries_by_signal[signal][statistic]
                    extracted = extracted_p4[f"network__p4_{signal}__{statistic}"]
                    parity_comparisons += 1
                    if not math.isclose(stored, extracted, rel_tol=1e-9, abs_tol=1e-9):
                        parity_mismatches.append(
                            {
                                "sample_artifact": sample,
                                "signal": signal,
                                "statistic": statistic,
                                "stored": stored,
                                "p4_extracted": extracted,
                            }
                        )
            if parity_mismatches:
                raise ValueError(
                    "The P4 extraction does not match stored telemetry under Ethernet/nominal "
                    f"compatibility settings; first mismatch: {parity_mismatches[0]}"
                )

            family = family_map[sample]
            example: dict[str, object] = {
                "sample_artifact": sample,
                "label": label,
                "class_name": "malware" if label else "benign",
                "group_id": family if label else f"benign::{family}",
                "workload_family": family,
                "sample_status": metadata.get("return_code"),
                "run_id": metadata.get("run_id", ""),
            }
            example.update(extracted_p4)
            for feature in host_features:
                signal, statistic = feature.removeprefix("host__").rsplit("__", 1)
                example[feature] = summaries_by_signal[signal][statistic]
            examples.append(example)

    if parity_mismatches:
        raise ValueError(f"P4 stored/extracted parity failures: {len(parity_mismatches)}")
    labels = np.asarray([int(row["label"]) for row in examples], dtype=int)
    groups = np.asarray([str(row["group_id"]) for row in examples], dtype=str)
    if Counter(labels.tolist()) != Counter({0: 91, 1: 92}):
        raise ValueError(f"Unexpected aligned class counts: {dict(Counter(labels.tolist()))}")

    network_features = list(P4_SAMPLE_FEATURES)
    network_matrix = numeric_matrix(examples, network_features)
    host_matrix = numeric_matrix(examples, host_features)
    splits = list(
        StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED).split(
            np.zeros((len(labels), 1)), labels, groups
        )
    )
    fold_audit = []
    for fold_number, (train_indices, validation_indices) in enumerate(splits, start=1):
        if set(groups[train_indices]).intersection(groups[validation_indices]):
            raise ValueError(f"Fold {fold_number}: family group crosses train/validation")
        if set(labels[train_indices]) != {0, 1} or set(labels[validation_indices]) != {0, 1}:
            raise ValueError(f"Fold {fold_number}: one class is missing")
        fold_audit.append(
            {
                "fold": fold_number,
                "train_samples": len(train_indices),
                "validation_samples": len(validation_indices),
                "train_class_counts": class_counts(labels, train_indices),
                "validation_class_counts": class_counts(labels, validation_indices),
                "train_groups": len(set(groups[train_indices])),
                "validation_groups": len(set(groups[validation_indices])),
            }
        )

    model_names = ("network_p4", "host_ebpf_family_balanced", "family_balanced_hybrid")
    probabilities = {name: np.full(len(labels), np.nan) for name in model_names}
    fold_ids = {name: np.zeros(len(labels), dtype=int) for name in model_names}
    fold_metrics = {name: [] for name in model_names}
    selection_rows = []
    importance_rows = []

    for fold_number, (train_indices, validation_indices) in enumerate(splits, start=1):
        host_imputer = SimpleImputer(strategy="median").fit(host_matrix[train_indices])
        train_host = host_imputer.transform(host_matrix[train_indices])
        validation_host = host_imputer.transform(host_matrix[validation_indices])
        mutual_information = mutual_info_classif(
            train_host,
            labels[train_indices],
            random_state=SEED + fold_number,
        )
        family_scores = {
            family: float(np.mean(mutual_information[indices]))
            for family, indices in feature_family_indices(host_features).items()
        }
        selected_families = sorted(
            family_scores,
            key=lambda family: (-family_scores[family], family),
        )[: len(P4_FEATURES)]
        selected_family_set = set(selected_families)
        selected_host_indices = [
            index
            for index, feature in enumerate(host_features)
            if feature.rpartition("__")[0] in selected_family_set
        ]
        if len(selected_host_indices) != len(P4_FEATURES) * len(P4_WINDOW_STATS):
            raise ValueError(f"Fold {fold_number}: host selector did not select 29 whole families")
        for rank, family in enumerate(selected_families, start=1):
            selection_rows.append(
                {
                    "fold": fold_number,
                    "host_signal_family": family,
                    "mean_summary_mutual_information": family_scores[family],
                    "selection_rank": rank,
                    "host_signal_family_budget": len(P4_FEATURES),
                    "p4_signal_family_budget": len(P4_FEATURES),
                }
            )

        train_network = network_matrix[train_indices]
        validation_network = network_matrix[validation_indices]
        train_host_selected = train_host[:, selected_host_indices]
        validation_host_selected = validation_host[:, selected_host_indices]
        matrices = {
            "network_p4": (train_network, validation_network, network_features),
            "host_ebpf_family_balanced": (
                train_host_selected,
                validation_host_selected,
                [host_features[index] for index in selected_host_indices],
            ),
            "family_balanced_hybrid": (
                np.hstack((train_host_selected, train_network)),
                np.hstack((validation_host_selected, validation_network)),
                [host_features[index] for index in selected_host_indices] + network_features,
            ),
        }
        for model_name, (train_matrix, validation_matrix, feature_names) in matrices.items():
            model = make_pipeline(
                SimpleImputer(strategy="median"),
                RandomForestClassifier(
                    n_estimators=500,
                    max_features="sqrt",
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    random_state=SEED + fold_number,
                    n_jobs=-1,
                ),
            )
            model.fit(train_matrix, labels[train_indices])
            fold_probabilities = model.predict_proba(validation_matrix)[:, 1]
            fold_predictions = (fold_probabilities >= 0.5).astype(int)
            probabilities[model_name][validation_indices] = fold_probabilities
            fold_ids[model_name][validation_indices] = fold_number
            fold_metrics[model_name].append(
                metrics_for(labels[validation_indices], fold_predictions, fold_probabilities)
            )
            importance_rows.extend(
                {
                    "model": model_name,
                    "fold": fold_number,
                    "feature": feature,
                    "importance": float(importance),
                }
                for feature, importance in zip(
                    feature_names, model[-1].feature_importances_, strict=True
                )
            )

    prediction_rows = []
    metrics = {
        "samples": len(examples),
        "class_counts": {"benign": int(np.count_nonzero(labels == 0)), "malware": int(np.count_nonzero(labels == 1))},
        "validation": "StratifiedGroupKFold",
        "folds": FOLDS,
        "seed": SEED,
        "feature_contract": {
            "p4_signal_families": len(P4_FEATURES),
            "host_candidate_signal_families": len(host_families),
            "host_signal_families_selected_per_fold": len(P4_FEATURES),
            "summaries_per_signal_family": len(P4_WINDOW_STATS),
            "network_feature_count": len(P4_SAMPLE_FEATURES),
            "host_feature_count": len(P4_FEATURES) * len(P4_WINDOW_STATS),
            "hybrid_feature_count": 2 * len(P4_FEATURES) * len(P4_WINDOW_STATS),
            "host_selection": "top 29 candidate families by training-fold mean mutual information across their five summaries",
            "p4_source": "p4_ebpf PCAP reconstruction with collector-compatible Ethernet bytes and nominal window rates",
        },
        "quality_rejected_exclusions": quality_exclusions,
        "nonunique_p4_alignment_exclusions": alignment_exclusions,
        "p4_alignment_status_counts": dict(Counter(row["status"] for row in alignment_rows)),
        "p4_stored_extracted_parity": {
            "comparisons": parity_comparisons,
            "mismatches": len(parity_mismatches),
            "byte_layer": "captured Ethernet bytes (collector compatibility)",
            "rate_window": "nominal 0.5-second windows (collector compatibility)",
        },
        "fold_audit": fold_audit,
        "feature_sets": {},
        "warning": "Exploratory cohort discrimination only; source labels, artifact/launch form, workload, activity, and duration remain confounded.",
    }
    for model_name in model_names:
        if np.isnan(probabilities[model_name]).any():
            raise ValueError(f"Missing out-of-fold predictions for {model_name}")
        predictions = (probabilities[model_name] >= 0.5).astype(int)
        metrics["feature_sets"][model_name] = {
            "feature_count": (
                len(network_features)
                if model_name == "network_p4"
                else len(P4_FEATURES) * len(P4_WINDOW_STATS)
                if model_name == "host_ebpf_family_balanced"
                else 2 * len(P4_FEATURES) * len(P4_WINDOW_STATS)
            ),
            "pooled_oof": metrics_for(labels, predictions, probabilities[model_name]),
            "fold_metrics": fold_metrics[model_name],
        }
        for index, example in enumerate(examples):
            prediction_rows.append(
                {
                    "model": model_name,
                    "sample_artifact": example["sample_artifact"],
                    "class_name": example["class_name"],
                    "label": labels[index],
                    "group_id": example["group_id"],
                    "fold": fold_ids[model_name][index],
                    "probability_malware": probabilities[model_name][index],
                    "prediction": predictions[index],
                }
            )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    dataset_fields = list(examples[0])
    write_csv(OUTPUT_DIR / "aligned_p4_host_candidate_dataset.csv", examples, dataset_fields)
    alignment_fields = list(dict.fromkeys(key for row in alignment_rows for key in row))
    write_csv(OUTPUT_DIR / "p4_alignment_audit.csv", alignment_rows, alignment_fields)
    write_csv(OUTPUT_DIR / "host_family_selection_by_fold.csv", selection_rows, list(selection_rows[0]))
    write_csv(OUTPUT_DIR / "oof_predictions.csv", prediction_rows, list(prediction_rows[0]))
    write_csv(OUTPUT_DIR / "fold_feature_importance.csv", importance_rows, list(importance_rows[0]))
    (OUTPUT_DIR / "feature_columns.json").write_text(
        json.dumps(
            {
                "network_p4": network_features,
                "host_candidate_pool": host_features,
                "host_selected_families_per_fold": "host_family_selection_by_fold.csv",
                "model_feature_counts": {name: metrics["feature_sets"][name]["feature_count"] for name in model_names},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "samples": metrics["samples"],
                "class_counts": metrics["class_counts"],
                "p4_alignment_status_counts": metrics["p4_alignment_status_counts"],
                "p4_stored_extracted_parity": metrics["p4_stored_extracted_parity"],
                "feature_counts": {
                    name: result["feature_count"]
                    for name, result in metrics["feature_sets"].items()
                },
                "pooled_oof": {
                    name: result["pooled_oof"]
                    for name, result in metrics["feature_sets"].items()
                },
                "output_dir": str(OUTPUT_DIR),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
