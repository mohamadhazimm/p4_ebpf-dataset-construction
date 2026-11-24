"""Controls for activity_strata.py: inside the quiet and active groups, how far do simple cues go?

Offline, exploratory (2026-11-23). For each pool and each group (quiet: under 300 system calls; active: 300 or more),
this reports (a) the AUC of three raw cues without any training, and (b) the balanced accuracy of a forest trained on
each cue alone with the thesis's protocol (whole groups held out, StratifiedGroupKFold(5), fold seeds 42 and 0-8,
RF500 balanced, threshold 0.5), scored inside the group. Cues:
  lifetime   number of windows with any host activity (host_total_syscalls_total__active_windows)
  late       host activity in the last 10 windows (the last 5 s): sum over windows 30-39 is not in the rows, so the
             proxy is lifetime itself; reported only as lifetime
  activity   log(1 + total host system calls) (host_total_syscalls_total__sum)
  traffic    log(1 + packets) (net_pkts_total_delta__sum)
The detectors' own scores inside the groups are in activity_strata.json.

Usage: python3 activity_strata_controls.py out.json
"""
import csv
import hashlib
import json
import os
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent))
from learning_curve import FEATURES, FOLD_SEEDS, SESSION, WS, rf  # noqa: E402

CUES = {
    "lifetime": lambda r: float(r["host_total_syscalls_total__active_windows"]),
    "activity": lambda r: float(np.log1p(float(r["host_total_syscalls_total__sum"]))),
    "traffic": lambda r: float(np.log1p(float(r["net_pkts_total_delta__sum"]))),
}


def job(args):
    X, y, g, seed = args
    p = np.zeros(len(y))
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, g):
        p[te] = rf().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    return p


def pool_report(name, rows, group_col, kind_col, mal_kinds, ben_kinds, calls):
    y = np.asarray([int(r["label"]) for r in rows])
    g = np.asarray([r[group_col] for r in rows])
    kind = np.asarray([r[kind_col] for r in rows])
    gm = np.isin(kind, mal_kinds + ben_kinds)
    strata = {"quiet": gm & (calls < 300), "active": gm & (calls >= 300)}
    out = {}
    print("\n%s" % name)
    for cue, f in CUES.items():
        X = np.asarray([[f(r)] for r in rows])
        with Pool(len(FOLD_SEEDS)) as pool:
            P = np.stack(pool.map(job, [(X, y, g, s) for s in FOLD_SEEDS]))
        out[cue] = {}
        for sname, m in strata.items():
            mm, bb = m & (y == 1), m & (y == 0)
            auc = roc_auc_score(y[m], X[m, 0])
            ba = [0.5 * ((p[mm] >= 0.5).mean() + (p[bb] < 0.5).mean()) for p in P]
            out[cue][sname] = {"auc_raw": float(auc), "ba_trained_mean": float(np.mean(ba)),
                               "ba_trained_sd": float(np.std(ba, ddof=1)),
                               "median_malware": float(np.median(X[mm, 0])), "median_benign": float(np.median(X[bb, 0]))}
            print("  %-9s %-6s raw AUC %.3f  trained BA %.3f+-%.3f  median malware %.2f benign %.2f" % (
                cue, sname, auc, np.mean(ba), np.std(ba, ddof=1), np.median(X[mm, 0]), np.median(X[bb, 0])))
    return out


def main():
    out = {"protocol": __doc__}
    rows = list(csv.DictReader(open(FEATURES, newline="")))
    calls = np.asarray([float(r["syscall_count"]) for r in rows])
    out["A_first_collection_240"] = pool_report("A first collection", rows, "cv_group", "category",
                                                ["malware"], ["benign"], calls)
    if SESSION.exists():
        srows = list(csv.DictReader(open(SESSION, newline="")))
        scalls = np.asarray([float(r["host_total_syscalls_total__sum"]) for r in srows])
        out["S_session_base_435_20s"] = pool_report(
            "S session base dataset, 20 s", srows, "group", "stratum",
            ["malware_dataset99", "malware_triage", "malware_dataset_extra"], ["benign_cli", "benign_network"], scalls)
    out["sources"] = {os.path.relpath(p, WS): hashlib.sha256(Path(p).read_bytes()).hexdigest()
                      for p in (FEATURES, SESSION, Path(__file__).resolve()) if Path(p).exists()}
    json.dump(out, open(sys.argv[1], "w"), indent=1)


if __name__ == "__main__":
    main()
