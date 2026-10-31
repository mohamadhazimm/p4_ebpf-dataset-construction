from __future__ import annotations

import math
import time
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np


ARMS = ("p4_only", "ebpf_only", "hybrid")
STATISTICS = ("mean", "max", "sum", "std", "active_windows")
AVAILABILITY_FEATURES = (
    "arm__network_available",
    "arm__host_available",
)


def build_live_feature_vector(
    windows: Sequence[Mapping[str, Mapping[str, object]]],
    arm: str,
    feature_names: Sequence[str],
) -> np.ndarray:
    if arm not in ARMS:
        raise ValueError(f"Unknown arm: {arm}")
    if not windows:
        raise ValueError("At least one synchronized telemetry window is required")
    if tuple(feature_names[-2:]) != AVAILABILITY_FEATURES:
        raise ValueError("Model feature schema must end with the two arm availability features")

    network_available = arm != "ebpf_only"
    host_available = arm != "p4_only"
    vector: list[float] = []

    for feature_name in feature_names[:-2]:
        parts = feature_name.split("__")
        if len(parts) != 3 or parts[0] not in {"network", "host"}:
            raise ValueError(f"Invalid model feature name: {feature_name}")
        modality, metric, statistic = parts
        if statistic not in STATISTICS:
            raise ValueError(f"Unsupported statistic in model feature: {feature_name}")

        available = network_available if modality == "network" else host_available
        if not available:
            vector.append(0.0)
            continue

        values: list[float] = []
        for window_index, window in enumerate(windows):
            metrics = window.get(modality)
            if not isinstance(metrics, Mapping) or metric not in metrics:
                raise ValueError(
                    f"Window {window_index} is missing required {modality} metric {metric!r}"
                )
            try:
                value = float(metrics[metric])
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"Window {window_index} has non-numeric {modality} metric {metric!r}"
                ) from error
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"Window {window_index} has invalid {modality} metric {metric!r}: {value}"
                )
            values.append(value)

        if statistic == "mean":
            vector.append(float(np.mean(values)))
        elif statistic == "max":
            vector.append(float(np.max(values)))
        elif statistic == "sum":
            vector.append(float(np.sum(values)))
        elif statistic == "std":
            vector.append(float(np.std(values, ddof=0)))
        else:
            vector.append(float(sum(value != 0.0 for value in values)))

    vector.extend((float(network_available), float(host_available)))
    result = np.asarray(vector, dtype=float)
    if result.shape != (len(feature_names),) or not np.isfinite(result).all():
        raise RuntimeError("Live feature vector does not match the model schema")
    return result


def infer_live_arm(
    model_bundle: Mapping[str, Any],
    windows: Sequence[Mapping[str, Mapping[str, object]]],
    arm: str,
) -> dict[str, float | int | str]:
    if arm not in model_bundle.get("arms", ()):
        raise ValueError(f"Model bundle does not support arm {arm!r}")
    feature_names = model_bundle.get("feature_names")
    if not isinstance(feature_names, list) or not all(
        isinstance(name, str) for name in feature_names
    ):
        raise ValueError("Model bundle has no valid feature_names list")

    threshold = model_bundle.get("threshold")
    if not isinstance(threshold, (int, float)) or not math.isfinite(threshold):
        raise ValueError("Model bundle has no finite probability threshold")
    if not 0 <= threshold <= 1:
        raise ValueError(f"Model threshold is outside [0, 1]: {threshold}")

    model = model_bundle.get("model")
    if model is None or not hasattr(model, "predict_proba") or not hasattr(model, "classes_"):
        raise ValueError("Model bundle does not contain a probability-capable classifier")
    class_indexes = np.flatnonzero(np.asarray(model.classes_) == 1)
    if len(class_indexes) != 1:
        raise ValueError("Classifier must expose exactly one positive class labeled 1")

    features = build_live_feature_vector(windows, arm, feature_names).reshape(1, -1)
    inference_started = time.perf_counter()
    probabilities = np.asarray(model.predict_proba(features), dtype=float)
    inference_ms = (time.perf_counter() - inference_started) * 1000.0
    if probabilities.shape != (1, len(model.classes_)) or not np.isfinite(probabilities).all():
        raise RuntimeError("Classifier returned invalid probabilities")

    probability = float(probabilities[0, int(class_indexes[0])])
    return {
        "arm": arm,
        "probability_malware": probability,
        "prediction": int(probability >= threshold),
        "threshold": float(threshold),
        "inference_ms": inference_ms,
    }
