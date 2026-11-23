#!/usr/bin/env python3
"""Recall at a fixed false-alarm rate for the four detectors of the combined pool (Table V), with and without the 49
executions that left a connection unanswered (the laboratory cue). Offline; scikit-learn 1.7 (the release pins <1.8).

- published: the cached out-of-fold probabilities of the Table V protocol (committee-eval cache/cv_published_k40.npz,
  10 fold assignments), checked against the published mean BA;
- cue-free: the same protocol retrained on the 191 executions without the cue (the committee's step D, whose mean BA
  this run must reproduce), from the cue classes of committee-eval cue/run_flows.csv.

For every assignment the threshold is set on that assignment's own benign scores so that at most floor(f x benign)
benign executions score above it (a point on the ROC curve, chosen after scoring: descriptive, not a deployable
threshold). Writes operating_point.json next to this script.
"""
import csv
import hashlib
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
CE = HERE.parent / "committee-eval-20261113"
sys.path.insert(0, str(CE))
import common as C   # noqa: E402

RATES = (0.01, 0.05, 0.10)
PUBLISHED_BA = {"host": 0.784, "network": 0.756, "concat": 0.812, "stacked": 0.823}


def recall_at(y, p, rate):
    neg = np.sort(p[y == 0])[::-1]
    k = int(np.floor(rate * len(neg)))
    thr = neg[k] if k < len(neg) else -np.inf
    return float((p[y == 1] > thr).mean()), float(((p[y == 0] > thr).mean()))


def table(y, P):
    out = {}
    for d in C.DETECTORS:
        out[d] = {}
        for rate in RATES:
            rec = [recall_at(y, P[d][s], rate)[0] for s in range(P[d].shape[0])]
            far = [recall_at(y, P[d][s], rate)[1] for s in range(P[d].shape[0])]
            out[d]["%g" % rate] = {"recall_mean": round(float(np.mean(rec)), 3),
                                   "recall_sd": round(float(np.std(rec, ddof=1)), 3),
                                   "false_alarm_mean": round(float(np.mean(far)), 4)}
        ba = [C.metrics(y, P[d][s])["balanced_accuracy"] for s in range(P[d].shape[0])]
        out[d]["ba_at_0.5"] = float(np.mean(ba))
    return out


def main():
    rows, hc, nc = C.load()
    y = C.labels(rows)
    groups = C.groups_published(rows)
    Xh, Xn = C.matrix(rows, hc), C.matrix(rows, nc)
    z = np.load(CE / "cache/cv_published_k40.npz")
    P = {d: z[d] for d in C.DETECTORS}
    pub = table(y, P)
    for d, ba in PUBLISHED_BA.items():
        assert abs(pub[d]["ba_at_0.5"] - ba) < 0.0006, (d, pub[d]["ba_at_0.5"], ba)

    cls = {r["execution_id"]: r["class"] for r in csv.DictReader(open(CE / "cue/run_flows.csv"))}
    cue = np.asarray([cls[r["execution_id"]] in ("some_unanswered", "none_answered") for r in rows])
    keep = np.flatnonzero(~cue)
    Pk, _ = C.cv_all(Xh[keep], Xn[keep], y[keep], groups[keep])
    saved = json.load(open(CE / "results/unanswered_cue.json"))["D_cue_free_table_v"]["ba_mean"]
    free = table(y[keep], Pk)
    for d in C.DETECTORS:
        assert abs(free[d]["ba_at_0.5"] - saved[d]) < 1e-9, (d, free[d]["ba_at_0.5"], saved[d])

    out = {"published_240": {"malicious": int(y.sum()), "benign": int((y == 0).sum()), "detectors": pub},
           "cue_free_191": {"malicious": int(y[keep].sum()), "benign": int((y[keep] == 0).sum()), "detectors": free},
           "sources": {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in (CE / "cache/cv_published_k40.npz", CE / "cue/run_flows.csv",
                                 CE / "results/unanswered_cue.json", Path(__file__))}}
    (HERE / "operating_point.json").write_text(json.dumps(out, indent=1))
    for name in ("published_240", "cue_free_191"):
        print(name, {d: (v["ba_at_0.5"], v["0.05"]["recall_mean"], v["0.01"]["recall_mean"], v["0.1"]["recall_mean"])
                     for d, v in out[name]["detectors"].items()})


if __name__ == "__main__":
    main()
