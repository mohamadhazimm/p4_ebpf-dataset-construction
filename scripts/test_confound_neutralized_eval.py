#!/usr/bin/env python3
"""Confound-neutralised host-vs-network test on the launch-matched pilot.

This is the controlled "small malware sample" test. The pilot contains 20 train
+ 20 validation samples where benign controls are ELF binaries launched exactly
like malware ELFs, so the .sh-vs-ELF launch confound is already removed. Here we
additionally test the *duration/activity* confound:

  * host_full        - all host_* aggregate features (what the study reports)
  * network_full     - all net_* aggregate features
  * duration_only    - window_count + every *__active_windows column + the
                       host_active_processes family (pure "how long/how busy")
  * host_no_duration - host_* features with __sum and __active_windows dropped,
                       i.e. intensity (mean/max/std) rather than accumulation

If duration_only alone reproduces host_full, the matched-pilot host score is the
duration confound. If host_no_duration collapses toward 0.5, little behavioural
host signal survives once launch and duration are controlled.

Usage:
    python3 scripts/test_confound_neutralized_eval.py \
        --pilot-dir data/versioned-collector/telemetry-2026-10-18.1-pilot40-nativenames-20261018/modeling
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, roc_auc_score


def load(path: Path):
    with path.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    return rows


def to_float(value):
    try:
        f = float(value)
        return f if np.isfinite(f) else 0.0
    except (TypeError, ValueError):
        return 0.0


def matrix(rows, cols):
    return np.array([[to_float(r.get(c, 0)) for c in cols] for r in rows], dtype=float)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot-dir", required=True)
    args = ap.parse_args()
    base = Path(args.pilot_dir)

    train = load(base / "training_samples.csv")
    val = load(base / "validation_samples.csv")
    all_cols = list(train[0].keys())

    meta = {"label", "sample_artifact", "sample_name", "cohort", "runner_status",
            "ebpf_status", "benign_package_group"}
    feat_cols = [c for c in all_cols if c not in meta]

    host = [c for c in feat_cols if c.startswith("host_")]
    network = [c for c in feat_cols if c.startswith("net_")]
    duration_only = (
        [c for c in feat_cols if c == "window_count"]
        + [c for c in feat_cols if c.endswith("__active_windows")]
        + [c for c in feat_cols if c.startswith("host_active_processes")]
    )
    host_no_duration = [
        c for c in host
        if not c.endswith("__active_windows")
        and not c.endswith("__sum")
        and not c.startswith("host_active_processes")
    ]

    ytr = np.array([int(r["label"]) for r in train])
    yva = np.array([int(r["label"]) for r in val])

    def run(name, cols):
        if not cols:
            return {"model": name, "n_features": 0, "balanced_accuracy": None, "roc_auc": None}
        xtr, xva = matrix(train, cols), matrix(val, cols)
        clf = RandomForestClassifier(n_estimators=400, random_state=42, n_jobs=-1)
        clf.fit(xtr, ytr)
        pred = clf.predict(xva)
        proba = clf.predict_proba(xva)[:, 1]
        return {
            "model": name,
            "n_features": len(cols),
            "balanced_accuracy": round(float(balanced_accuracy_score(yva, pred)), 4),
            "roc_auc": round(float(roc_auc_score(yva, proba)), 4) if len(set(yva)) > 1 else None,
        }

    results = [
        run("host_full", host),
        run("network_full", network),
        run("duration_only", duration_only),
        run("host_no_duration", host_no_duration),
    ]
    out = {
        "pilot_dir": str(base),
        "train_n": len(train),
        "val_n": len(val),
        "train_class_counts": {"benign": int((ytr == 0).sum()), "malware": int((ytr == 1).sum())},
        "val_class_counts": {"benign": int((yva == 0).sum()), "malware": int((yva == 1).sum())},
        "results": results,
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
