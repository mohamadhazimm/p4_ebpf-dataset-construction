#!/usr/bin/env python3
"""Quantify how much of the host/eBPF model's accuracy is explained by the
benign-vs-malware *launch/workload confound* rather than malicious behaviour.

The hypothesis under test: benign samples are 100% bash (.sh) coreutils
workloads while malware samples are 100% ELF binaries. The host feature set
(filesystem watchdog, mmap/mprotect, syscall mix) therefore separates the two
populations by *how a process is launched and what workload it runs*, not by
whether it is malicious.

Probes
------
1. Artifact-type purity: can a single boolean (is .sh) reproduce the labels?
2. Confound-only classifier: a 3-feature rule {host_file_events, mmap, is_sh}
   trained with a tiny decision tree -- if it matches the full host model, the
   host signal is the confound.
3. Behaviour-only view: among malware families that *do* write files / beacon,
   does any host separation survive? (sanity on whether real behaviour exists.)

Usage:
    python3 scripts/diagnose_host_bias.py \
        --train data/.../training_dataset.csv \
        --test  data/.../test_dataset.csv
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


def load(path: str) -> list[dict]:
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def to_float(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def is_sh(row: dict) -> int:
    name = (row.get("sample_name") or row.get("sample_artifact") or "").lower()
    return 1 if name.endswith(".sh") else 0


def auc(pos: list[float], neg: list[float]) -> float:
    combined = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    n = len(combined)
    i = 0
    sum_rank_pos = 0.0
    while i < n:
        j = i
        while j < n and combined[j][0] == combined[i][0]:
            j += 1
        avg = (i + 1 + j) / 2.0
        for k in range(i, j):
            if combined[k][1] == 1:
                sum_rank_pos += avg
        i = j
    n1, n0 = len(pos), len(neg)
    if n1 == 0 or n0 == 0:
        return float("nan")
    u = sum_rank_pos - n1 * (n1 + 1) / 2.0
    return u / (n1 * n0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    args = ap.parse_args()

    train = load(args.train)
    test = load(args.test)

    report: dict = {}

    # ---- Probe 1: artifact-type purity -------------------------------------
    purity = {}
    for name, rows in (("train", train), ("test", test)):
        sh_by_label = defaultdict(Counter)
        for r in rows:
            sh_by_label[r["label"]][is_sh(r)] += 1
        # accuracy of the rule "is_sh => benign"
        correct = sum(
            (is_sh(r) == 1 and r["label"] == "0")
            or (is_sh(r) == 0 and r["label"] == "1")
            for r in rows
        )
        purity[name] = {
            "rule_is_sh_eq_benign_accuracy": round(correct / len(rows), 4),
            "sh_counts_by_label": {k: dict(v) for k, v in sh_by_label.items()},
        }
    report["probe1_artifact_type_purity"] = purity

    # ---- Probe 2: confound-only decision rule ------------------------------
    # Features that encode launch/workload rather than malice.
    confound_feats = [
        "telemetry__host_file_events_total__sum",
        "event__mmap__sum",
        "event__mprotect__sum",
    ]

    def confound_vec(r):
        return [to_float(r.get(c, 0)) for c in confound_feats] + [is_sh(r)]

    # tiny greedy single-threshold ensemble: pick the best threshold on each
    # feature on train, majority vote on test. No sklearn dependency needed.
    def best_threshold(rows, idx):
        pos = sorted(confound_vec(r)[idx] for r in rows if r["label"] == "1")
        neg = sorted(confound_vec(r)[idx] for r in rows if r["label"] == "0")
        vals = sorted(set(pos + neg))
        best = (0.0, None, None)
        for t in vals:
            # direction A: value <= t => malware
            accA = sum(
                (confound_vec(r)[idx] <= t and r["label"] == "1")
                or (confound_vec(r)[idx] > t and r["label"] == "0")
                for r in rows
            ) / len(rows)
            if accA > best[0]:
                best = (accA, t, "le")
            accB = 1 - accA
            if accB > best[0]:
                best = (accB, t, "gt")
        return best

    rules = []
    for idx, feat in enumerate(confound_feats + ["is_sh"]):
        acc, t, direction = best_threshold(train, idx)
        rules.append((idx, feat, t, direction, acc))

    def predict(r):
        votes = 0
        for idx, _feat, t, direction, _acc in rules:
            v = confound_vec(r)[idx]
            mal = (v <= t) if direction == "le" else (v > t)
            votes += 1 if mal else -1
        return 1 if votes >= 0 else 0

    def eval_rules(rows):
        tp = fp = tn = fn = 0
        for r in rows:
            p = predict(r)
            y = int(r["label"])
            if p == 1 and y == 1:
                tp += 1
            elif p == 1 and y == 0:
                fp += 1
            elif p == 0 and y == 0:
                tn += 1
            else:
                fn += 1
        n = len(rows)
        rec = tp / (tp + fn) if tp + fn else 0
        spec = tn / (tn + fp) if tn + fp else 0
        return {
            "accuracy": round((tp + tn) / n, 4),
            "balanced_accuracy": round((rec + spec) / 2, 4),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        }

    report["probe2_confound_only_classifier"] = {
        "features": confound_feats + ["is_sh"],
        "learned_rules": [
            {"feature": f, "threshold": t, "direction": d, "train_acc": round(a, 4)}
            for _i, f, t, d, a in rules
        ],
        "train": eval_rules(train),
        "test": eval_rules(test),
    }

    # ---- Probe 3: per-family host-feature degeneracy -----------------------
    fam_stats = defaultdict(lambda: {"n": 0, "file_sum": 0.0, "mmap_sum": 0.0})
    for r in train:
        fam = r.get("attack_type") or ("benign" if r["label"] == "0" else "malware")
        s = fam_stats[fam]
        s["n"] += 1
        s["file_sum"] += to_float(r.get("telemetry__host_file_events_total__sum", 0))
        s["mmap_sum"] += to_float(r.get("event__mmap__sum", 0))
    report["probe3_family_host_means"] = {
        fam: {
            "n": s["n"],
            "mean_host_file_events": round(s["file_sum"] / s["n"], 3),
            "mean_mmap": round(s["mmap_sum"] / s["n"], 3),
        }
        for fam, s in sorted(fam_stats.items(), key=lambda kv: -kv[1]["n"])
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
