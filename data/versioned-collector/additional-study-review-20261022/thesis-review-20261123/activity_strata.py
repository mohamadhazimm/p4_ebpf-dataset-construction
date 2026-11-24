"""Detection split by how much the program did: flag rates by the program's own system-call count.

Offline, exploratory, on already-examined data (2026-11-23). No VM, no sample execution, no new model for pool A.

Question: the thesis's balanced accuracy is about 0.8. Is that a uniform 0.8, or a mix of programs that ran (and are
classified well) and programs that did almost nothing (where there is little to classify)?

Pool A  first collection, 240 released rows: the cached out-of-fold probabilities of the published Table V protocol
        (committee-eval cache/cv_published_k40.npz; 10 fold assignments; host, network, concatenated, stacked).
        Activity = the release's syscall_count column (the lineage's calls after the launch prologue).
Pool S  session base dataset, primary view, 20 s (435 rows): out-of-fold probabilities recomputed here with the same
        protocol (RF500 balanced, StratifiedGroupKFold(5, shuffle, seed), seeds 42 and 0-8; host, network,
        concatenated); fraction-1.0 scores must equal the base's (0.814, 0.735, 0.870).
        Activity = host_total_syscalls_total__sum of the program's own 20 s.

Bins fixed before looking at pool S: [0,100), [100,300), [300,1000), [1000,inf); "quiet" = under 300 calls,
"active" = 300 or more. (The 300 boundary was first seen on pool A on 2026-11-12, so for pool A it is post hoc.)

Usage: python3 activity_strata.py out.json
"""
import csv
import hashlib
import json
import os
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent))
from learning_curve import FEATURES, FOLD_SEEDS, SESSION, WS, load, rf  # noqa: E402

ASR = Path(__file__).resolve().parent.parent
CACHE = ASR / "committee-eval-20261113" / "cache" / "cv_published_k40.npz"
BINS = [(0, 100), (100, 300), (300, 1000), (1000, float("inf"))]


def oof_job(args):
    Xh, Xn, y, g, seed = args
    X = {"host": Xh, "network": Xn, "concat": np.hstack([Xh, Xn])}
    out = {d: np.zeros(len(y)) for d in X}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        for d in X:
            out[d][te] = rf().fit(X[d][tr], y[tr]).predict_proba(X[d][te])[:, 1]
    return out


def table(name, P, y, kind, calls, classes):
    """P: detector -> (assignments, rows) probabilities. kind: row class names. classes: (malicious kinds, benign kinds)."""
    dets = list(P)
    res = {"detectors": dets, "bins": {}, "strata": {}, "other": {}}
    mal, ben = classes
    print("\n%s" % name)
    print("  share flagged (mean over the fold assignments)")
    print("  %-22s %-12s %4s  " % ("class", "calls", "n") + " ".join("%-8s" % d for d in dets))
    for label, kinds in (("malware", mal), ("benign programs", ben)):
        for lo, hi in BINS:
            m = np.isin(kind, kinds) & (calls >= lo) & (calls < hi)
            rates = {d: float((P[d][:, m] >= 0.5).mean()) if m.any() else None for d in dets}
            res["bins"]["%s [%g,%g)" % (label, lo, hi)] = {"n": int(m.sum()), "flagged": rates}
            print("  %-22s %-12s %4d  " % (label, "[%g,%g)" % (lo, hi), m.sum())
                  + " ".join("%-8s" % ("%.2f" % rates[d] if m.any() else "-") for d in dets))
    for sname, lo, hi in (("quiet (<300 calls)", 0, 300), ("active (>=300 calls)", 300, float("inf"))):
        mm = np.isin(kind, mal) & (calls >= lo) & (calls < hi)
        bb = np.isin(kind, ben) & (calls >= lo) & (calls < hi)
        rec = {"malware": int(mm.sum()), "benign": int(bb.sum())}
        cells = []
        for d in dets:
            tpr = (P[d][:, mm] >= 0.5).mean(axis=1)
            tnr = (P[d][:, bb] < 0.5).mean(axis=1)
            ba = 0.5 * (tpr + tnr)
            rec[d] = {"recall": float(tpr.mean()), "specificity": float(tnr.mean()),
                      "ba_mean": float(ba.mean()), "ba_sd": float(ba.std(ddof=1))}
            cells.append("%s BA %.3f (recall %.2f, spec %.2f)" % (d, ba.mean(), tpr.mean(), tnr.mean()))
        res["strata"][sname] = rec
        print("  %-22s malware %d, benign %d: %s" % (sname, mm.sum(), bb.sum(), "; ".join(cells)))
    for k in sorted(set(kind) - set(mal) - set(ben)):
        m = kind == k
        res["other"][k] = {"n": int(m.sum()), "median_calls": float(np.median(calls[m])),
                           "flagged": {d: float((P[d][:, m] >= 0.5).mean()) for d in dets}}
        print("  %-22s n=%d median calls %.0f: " % (k, m.sum(), np.median(calls[m]))
              + " ".join("%s %.2f" % (d, res["other"][k]["flagged"][d]) for d in dets))
    return res


def main():
    out = {"protocol": __doc__, "bins": [[lo, hi if hi != float("inf") else None] for lo, hi in BINS]}
    # ---- pool A: cached Table V out-of-fold probabilities
    rows = list(csv.DictReader(open(FEATURES, newline="")))
    y = np.asarray([int(r["label"]) for r in rows])
    z = np.load(CACHE, allow_pickle=True)
    P = {d: z[d] for d in ("host", "network", "concat", "stacked")}
    for d, want in (("host", 0.784), ("network", 0.756), ("concat", 0.812), ("stacked", 0.823)):
        ba = np.mean([0.5 * ((p[y == 1] >= 0.5).mean() + (p[y == 0] < 0.5).mean()) for p in P[d]])
        assert abs(ba - want) < 0.0006, (d, ba)
    kind = np.asarray([r["category"] for r in rows])
    calls = np.asarray([float(r["syscall_count"]) for r in rows])
    out["A_first_collection_240"] = table("A first collection (published Table V out-of-fold probabilities)",
                                          P, y, kind, calls, (["malware"], ["benign"]))
    # ---- pool S: recomputed
    if SESSION.exists():
        Xh, Xn, ys, g = load(SESSION, "group")
        srows = list(csv.DictReader(open(SESSION, newline="")))
        with Pool(len(FOLD_SEEDS)) as p:
            res = p.map(oof_job, [(Xh, Xn, ys, g, s) for s in FOLD_SEEDS])
        PS = {d: np.stack([r[d] for r in res]) for d in ("host", "network", "concat")}
        for d, want in (("host", 0.814), ("network", 0.735), ("concat", 0.870)):
            ba = np.mean([0.5 * ((p[ys == 1] >= 0.5).mean() + (p[ys == 0] < 0.5).mean()) for p in PS[d]])
            assert abs(ba - want) < 0.0006, (d, ba)
        skind = np.asarray([r["stratum"] for r in srows])
        scalls = np.asarray([float(r["host_total_syscalls_total__sum"]) for r in srows])
        out["S_session_base_435_20s"] = table(
            "S session base dataset, 20 s (recomputed; equals the base's scores)", PS, ys, skind, scalls,
            (["malware_dataset99", "malware_triage", "malware_dataset_extra"], ["benign_cli", "benign_network"]))
    out["sources"] = {os.path.relpath(p, WS): hashlib.sha256(Path(p).read_bytes()).hexdigest()
                      for p in (FEATURES, CACHE, SESSION, Path(__file__).resolve()) if Path(p).exists()}
    json.dump(out, open(sys.argv[1], "w"), indent=1)


if __name__ == "__main__":
    main()
