#!/usr/bin/env python3
"""Cluster-bootstrap interval of the hybrids' lead over host-only on the session dataset (base/20261117c, relaxed
rule, sessions view, 20 s and 80 s), the statistic of Table V: the mean over the 10 fold assignments of each
assignment's balanced-accuracy difference. Offline; rows, groups, folds and seeds are build_base.py's (as in
session-lab/cue_split.py, whose loader this reuses), and the BA of every detector must reproduce base.json.

The bootstrap resamples whole groups (families, attack instances, benign projects) with replacement, malicious and
benign groups apart, 2,000 times, with the out-of-fold probabilities fixed (the models are not retrained), as the
thesis's other cluster-bootstrap intervals do. Writes session_ci.json next to this script.
"""
import hashlib
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
SL = HERE.parent / "session-lab"
sys.path.insert(0, str(SL))
import with_runs as WR   # noqa: E402

BB = WR.BB
DETS = ("host", "network", "concat", "stacked")
DRAWS, SEED = 2000, 20261122


def ba_weighted(y, pred, w):
    tp = (w * ((pred == 1) & (y == 1))).sum(); fn = (w * ((pred == 0) & (y == 1))).sum()
    tn = (w * ((pred == 0) & (y == 0))).sum(); fp = (w * ((pred == 1) & (y == 0))).sum()
    return 0.5 * (tp / (tp + fn) + tn / (tn + fp))


def main():
    base = SL / "base/20261117c"
    saved = json.loads((base / "base.json").read_text())
    for name, att in saved["runs"].items():
        if name not in BB.RUNS:
            WR.register(name, att)
    WR.patch()
    import score_netbenign as S   # noqa: E402  the row builder of the scorer and the base
    rows, *_ = S.all_rows(list(saved["runs"]))
    y = np.asarray([BB.CS.label(s) for s in rows])
    g = np.asarray([s["group"] for s in rows])
    out = {"rows": len(rows), "malicious": int(y.sum()), "draws": DRAWS, "seed": SEED, "spans": {}}
    rng = np.random.default_rng(SEED)
    gm, gb = sorted(set(g[y == 1])), sorted(set(g[y == 0]))
    members = {k: np.flatnonzero(g == k) for k in set(g)}
    picks = [(rng.choice(len(gm), len(gm)), rng.choice(len(gb), len(gb))) for _ in range(DRAWS)]
    for span in ("20s", "80s"):
        Xh, Xn, *_ = BB.matrices(rows, BB.SPANS[span])
        sc, P = BB.CS.grouped_cv_P(Xh, Xn, y, g)
        ref = saved["rules"]["relaxed"]["views"]["sessions"][span]["scores"]
        for d in DETS:
            assert abs(sc[d]["ba_mean"] - ref[d]["ba_mean"]) < 1e-9, (span, d, sc[d]["ba_mean"], ref[d]["ba_mean"])
        pred = {d: (np.asarray(P[d]) >= 0.5).astype(int) for d in DETS}
        A = pred["host"].shape[0]
        point = {d: float(np.mean([ba_weighted(y, pred[d][a], np.ones(len(y))) - ba_weighted(y, pred["host"][a],
                                                                                              np.ones(len(y)))
                                   for a in range(A)])) for d in ("concat", "stacked", "network")}
        boot = {d: [] for d in point}
        for im, ib in picks:
            w = np.zeros(len(y))
            for j in im:
                w[members[gm[j]]] += 1
            for j in ib:
                w[members[gb[j]]] += 1
            for d in point:
                boot[d].append(np.mean([ba_weighted(y, pred[d][a], w) - ba_weighted(y, pred["host"][a], w)
                                        for a in range(A)]))
        out["spans"][span] = {
            "ba_mean": {d: round(sc[d]["ba_mean"], 4) for d in DETS},
            "minus_host": {d: {"point": round(point[d], 4),
                               "ci95": [round(float(np.percentile(boot[d], 2.5)), 4),
                                        round(float(np.percentile(boot[d], 97.5)), 4)],
                               "share_of_draws_above_0": round(float(np.mean(np.asarray(boot[d]) > 0)), 4)}
                           for d in point}}
        print(span, json.dumps(out["spans"][span]), flush=True)
    out["sources"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in (base / "base.json", Path(__file__))}
    (HERE / "session_ci.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
