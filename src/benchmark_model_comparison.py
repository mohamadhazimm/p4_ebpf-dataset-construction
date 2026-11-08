#!/usr/bin/env python3
"""Compare grouped-CV detection quality and Random Forest runtime."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import time
from pathlib import Path

import numpy as np
import sklearn
from sklearn.model_selection import StratifiedGroupKFold

from train_compare import load_examples, make_model, metrics_for, numeric_matrix


METRIC_NAMES = ("accuracy", "balanced_accuracy", "precision", "recall", "f1", "roc_auc")


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def measure_inference(
    model,
    test_matrix: np.ndarray,
    batch_repeats: int,
    single_repeats: int,
) -> tuple[list[float], list[float]]:
    batch_latencies = []
    single_latencies = []
    model.predict_proba(test_matrix)
    for _ in range(batch_repeats):
        start = time.perf_counter()
        model.predict_proba(test_matrix)
        batch_latencies.append(time.perf_counter() - start)

    single_row = test_matrix[:1]
    model.predict_proba(single_row)
    for _ in range(single_repeats):
        start = time.perf_counter()
        model.predict_proba(single_row)
        single_latencies.append(time.perf_counter() - start)
    return batch_latencies, single_latencies


def main() -> int:
    study_dir = Path(__file__).resolve().parents[1]
    revision_dir = (
        study_dir
        / "data/malware/revision4/family-heldout-balanced-224-v1-20261014"
    )
    balanced_feature_path = (
        revision_dir.parent
        / "family-heldout-stable-151-v1-20261014/feature_breadth_comparison"
        / "balanced_9network_9host_feature_columns.json"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=revision_dir / "labeled_sample_dataset_full_35host_9network.csv",
    )
    parser.add_argument("--feature-columns", type=Path, default=balanced_feature_path)
    parser.add_argument(
        "--reference-metrics",
        type=Path,
        default=revision_dir
        / "reports/balanced_9network_9host/recomputed_20261015/cv_metrics.json",
    )
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-repeats", type=int, default=12)
    parser.add_argument("--single-repeats", type=int, default=20)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.folds < 2 or args.batch_repeats < 1 or args.single_repeats < 1:
        parser.error("fold and repeat counts must be positive; folds must be at least 2")

    examples, feature_sets, labels, groups = load_examples(
        args.dataset, args.feature_columns
    )
    splits = list(
        StratifiedGroupKFold(
            n_splits=args.folds, shuffle=True, random_state=args.seed
        ).split(np.zeros((len(labels), 1)), labels, groups)
    )
    for fold_index, (_, test_indices) in enumerate(splits, start=1):
        if len(set(labels[test_indices])) != 2:
            parser.error(f"Fold {fold_index} contains only one class")

    reference = None
    if args.reference_metrics.is_file():
        reference = json.loads(args.reference_metrics.read_text(encoding="utf-8"))
        for name in ("network", "host", "hybrid"):
            expected_count = reference["feature_sets"][name]["feature_count"]
            if len(feature_sets[name]) != expected_count:
                parser.error(
                    f"{name} feature contract has {len(feature_sets[name])} columns; "
                    f"reference expects {expected_count}"
                )

    results = {}
    for feature_set_name in ("network", "host", "hybrid"):
        feature_names = feature_sets[feature_set_name]
        matrix = numeric_matrix(examples, feature_names)
        probabilities = np.full(len(labels), np.nan, dtype=float)
        fit_seconds = []
        first_batch_seconds = []
        inference_samples = {
            "all_cores": {"batch_latencies": [], "single_latencies": []},
            "single_worker": {"batch_latencies": [], "single_latencies": []},
        }
        batch_sample_count_by_mode = {"all_cores": 0, "single_worker": 0}
        fold_metrics = []

        for fold_index, (train_indices, test_indices) in enumerate(splits, start=1):
            model = make_model(args.seed + fold_index)
            fit_start = time.perf_counter()
            model.fit(matrix[train_indices], labels[train_indices])
            fit_seconds.append(time.perf_counter() - fit_start)

            test_matrix = matrix[test_indices]
            prediction_start = time.perf_counter()
            fold_probabilities = model.predict_proba(test_matrix)[:, 1]
            first_batch_seconds.append(time.perf_counter() - prediction_start)
            probabilities[test_indices] = fold_probabilities
            fold_metrics.append(
                metrics_for(
                    labels[test_indices],
                    (fold_probabilities >= 0.5).astype(int),
                    fold_probabilities,
                )
            )

            for mode, jobs in (("all_cores", -1), ("single_worker", 1)):
                model[-1].n_jobs = jobs
                batch, single = measure_inference(
                    model, test_matrix, args.batch_repeats, args.single_repeats
                )
                inference_samples[mode]["batch_latencies"].extend(batch)
                inference_samples[mode]["single_latencies"].extend(single)
                batch_sample_count_by_mode[mode] += len(test_indices) * len(batch)

        if np.isnan(probabilities).any():
            raise RuntimeError(f"Incomplete out-of-fold predictions for {feature_set_name}")
        pooled_metrics = metrics_for(
            labels, (probabilities >= 0.5).astype(int), probabilities
        )
        fold_summary = {
            metric: {
                "mean": statistics.mean(fold[metric] for fold in fold_metrics),
                "std": statistics.stdev(fold[metric] for fold in fold_metrics),
            }
            for metric in METRIC_NAMES
        }
        reference_match = None
        reference_deltas = None
        if reference:
            reference_metrics = reference["feature_sets"][feature_set_name]["pooled_oof"]
            reference_deltas = {
                metric: pooled_metrics[metric] - reference_metrics[metric]
                for metric in METRIC_NAMES
            }
            reference_match = all(abs(delta) < 1e-12 for delta in reference_deltas.values())

        runtime_by_mode = {}
        for mode, timing in inference_samples.items():
            batch_latencies = timing["batch_latencies"]
            single_latencies = timing["single_latencies"]
            batch_total_seconds = sum(batch_latencies)
            runtime_by_mode[mode] = {
                "warm_batch_latency_ms_p50": statistics.median(batch_latencies) * 1000,
                "warm_batch_latency_ms_p95": percentile(batch_latencies, 0.95) * 1000,
                "warm_batch_throughput_samples_per_second": (
                    batch_sample_count_by_mode[mode] / batch_total_seconds
                    if batch_total_seconds
                    else 0.0
                ),
                "single_sample_latency_ms_p50": statistics.median(single_latencies) * 1000,
                "single_sample_latency_ms_p95": percentile(single_latencies, 0.95) * 1000,
                "batch_repeats_per_fold": args.batch_repeats,
                "single_sample_repeats_per_fold": args.single_repeats,
            }
        results[feature_set_name] = {
            "feature_count": len(feature_names),
            "pooled_oof_metrics": pooled_metrics,
            "fold_metric_summary": fold_summary,
            "matches_reference_metrics": reference_match,
            "reference_metric_deltas": reference_deltas,
            "runtime": {
                "fit_seconds_by_fold": fit_seconds,
                "fit_seconds_total": sum(fit_seconds),
                "fit_seconds_median_per_fold": statistics.median(fit_seconds),
                "first_batch_latency_ms_median": statistics.median(first_batch_seconds) * 1000,
                "inference_modes": runtime_by_mode,
            },
        }

    output = {
                "dataset": str(args.dataset.resolve()),
                "feature_columns": str(args.feature_columns.resolve()),
                "samples": len(examples),
                "class_counts": {
                    "benign": int((labels == 0).sum()),
                    "malware": int((labels == 1).sum()),
                },
                "validation": "StratifiedGroupKFold",
                "folds": args.folds,
                "seed": args.seed,
                "model": "RandomForestClassifier; 500 trees; max_features=sqrt; min_samples_leaf=2; balanced_subsample; n_jobs=-1",
                "runtime_scope": "Classifier fit and inference only; excludes P4/eBPF collection, feature extraction, and network I/O.",
                "environment": {
                    "python": platform.python_version(),
                    "scikit_learn": sklearn.__version__,
                    "logical_cpus": os.cpu_count(),
                },
                "results": results,
            }
    output_json = json.dumps(output, indent=2)
    if args.output:
        output_path = args.output.expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output_json + "\n", encoding="utf-8")
    print(output_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())