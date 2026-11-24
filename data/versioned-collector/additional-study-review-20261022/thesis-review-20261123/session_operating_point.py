"""Recall at a fixed false-alarm rate on the session base dataset (end of the 20-s and 80-s program windows).

Offline, exploratory, on already-examined data (2026-11-23). The counterpart of thesis-review-20261122/
operating_point.py (first collection) for the session base dataset, so that both datasets have the same operating
points. Protocol as the base: RF500 balanced, StratifiedGroupKFold(5, shuffle, seed), fold seeds 42 and 0-8; host,
network, concatenated. In every fold assignment the threshold of each detector is the smallest score that keeps the
share of flagged benign rows at or below the target (set after scoring: a point on the curve, not a deployable
threshold). Balanced accuracy at 0.5 must equal the base's.

Usage: python3 session_operating_point.py out.json
"""
import csv
import hashlib
import json
import os
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from activity_strata import oof_job  # noqa: E402
from learning_curve import FOLD_SEEDS, SESSION, WS, load  # noqa: E402

TARGETS = (0.01, 0.05, 0.10)
MAL = ("malware_dataset99", "malware_triage", "malware_dataset_extra")


def at_rate(p, y, target):
    """Threshold with at most `target` of the benign rows flagged; returns (threshold, flagged mask)."""
    b = np.sort(p[y == 0])[::-1]
    k = int(np.floor(target * len(b)))  # benign rows allowed above the threshold
    thr = b[k] if k < len(b) else -np.inf
    flagged = p > thr  # strictly above the (k+1)-th largest benign score
    return float(thr), flagged


def main():
    out = {"protocol": __doc__, "spans": {}}
    for span in ("20s", "80s"):
        path = SESSION.with_name("base_relaxed_sessions_%s.csv" % span)
        Xh, Xn, y, g = load(path, "group")
        kind = np.asarray([r["stratum"] for r in csv.DictReader(open(path, newline=""))])
        with Pool(len(FOLD_SEEDS)) as pool:
            res = pool.map(oof_job, [(Xh, Xn, y, g, s) for s in FOLD_SEEDS])
        P = {d: np.stack([r[d] for r in res]) for d in ("host", "network", "concat")}
        rec = {"rows": int(len(y)), "at_0.5": {}, "targets": {}}
        print("\nsession base dataset, %s: %d malicious, %d benign" % (span, y.sum(), (y == 0).sum()))
        for d in P:
            ba = [0.5 * ((p[y == 1] >= 0.5).mean() + (p[y == 0] < 0.5).mean()) for p in P[d]]
            rec["at_0.5"][d] = {"ba_mean": float(np.mean(ba)),
                                "benign_flagged": float(np.mean([(p[y == 0] >= 0.5).mean() for p in P[d]])),
                                "recall": float(np.mean([(p[y == 1] >= 0.5).mean() for p in P[d]]))}
        print("  at 0.5: " + "; ".join("%s BA %.3f, recall %.2f, benign flagged %.2f" % (
            d, v["ba_mean"], v["recall"], v["benign_flagged"]) for d, v in rec["at_0.5"].items()))
        mal, att = np.isin(kind, MAL), kind == "attack"
        for t in TARGETS:
            row = {}
            for d in P:
                allr, malr, attr, fa = [], [], [], []
                for p in P[d]:
                    _, f = at_rate(p, y, t)
                    allr.append(f[y == 1].mean()); malr.append(f[mal].mean()); attr.append(f[att].mean())
                    fa.append(f[y == 0].mean())
                row[d] = {"recall_all": float(np.mean(allr)), "recall_malware": float(np.mean(malr)),
                          "recall_attacks": float(np.mean(attr)), "benign_flagged": float(np.mean(fa)),
                          "recall_all_sd": float(np.std(allr, ddof=1))}
            rec["targets"]["%g" % t] = row
            print("  at most %2.0f%% of benign flagged: " % (100 * t) + "; ".join(
                "%s %.2f (malware %.2f, attacks %.2f)" % (d, v["recall_all"], v["recall_malware"], v["recall_attacks"])
                for d, v in row.items()))
        out["spans"][span] = rec
    out["sources"] = {os.path.relpath(p, WS): hashlib.sha256(Path(p).read_bytes()).hexdigest()
                      for p in (SESSION, SESSION.with_name("base_relaxed_sessions_80s.csv"), Path(__file__).resolve())}
    json.dump(out, open(sys.argv[1], "w"), indent=1)


if __name__ == "__main__":
    main()
