"""Window-length test on the paper's 240-run combined-surface pool (Table V), 20-s observations.

Rebuilds every run's 18 host and 29 network window features from its raw data (syscall_events.csv and the packet
capture, with the release repository's host_model.py / switch_model.py) at window lengths 0.5, 1, 2, 5 and 10 s
(40, 20, 10, 4 and 2 windows over the 20 s), summarizes them as the paper does (90 + 145 columns), and scores them
with the unchanged Table V procedure of paper-check-20261028/repro_table5.py (10 fold assignments, RF500, stacked
hybrid, plus concatenated, activity-only and return-code-only).

Checks before scoring: at 0.5 s the rebuilt windows equal each run's stored telemetry, and the rebuilt 235 columns
equal the pool's stored values, so W = 0.5 s reproduces Table V. Offline; no VM, no promotion, no merge.

    /usr/bin/python3 window_length_pool240.py OUTDIR [--jobs N]
"""

import argparse
import csv
import glob
import hashlib
import json
import os
import sys
import time
from multiprocessing import Pool

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "paper-check-20261028"))
sys.path.insert(0, HERE)
_argv, sys.argv = sys.argv, [sys.argv[0], os.path.join(HERE, "paper-check-20261028")]  # repro_table5 reads argv[1]
import repro_table5 as rt  # noqa: E402
sys.argv = _argv
import window_length_test as wl  # noqa: E402  (feature code, event reader)

host_model, switch_model, summary = wl.host_model, wl.switch_model, wl.summary
WINDOWS = [0.5, 1.0, 2.0, 5.0, 10.0]
OBS = 20.0
TOL = 1e-9


def pool_with_dirs():
    orig = rt.record

    def record(run_dir, name, label, stratum, group):
        r = orig(run_dir, name, label, stratum, group)
        r["run_dir"] = str(run_dir)
        return r
    rt.record = record
    try:
        return rt.build()
    finally:
        rt.record = orig


def vector(windows, features, prefix, columns):
    s = summary.summarize(windows, features)
    return [s[c[len(prefix):]] for c in columns]


def extract(item):
    r = item
    run = glob.glob(os.path.join(r["run_dir"], "output", "run_*"))[0]
    meta = json.load(open(os.path.join(run, "run.json")))
    start_us = int(meta["sample_started_wall_us"])
    events = wl.read_events(os.path.join(run, "syscall_events.csv"))
    pcap = os.path.join(run, "packet_capture.pcap")
    stored = list(csv.DictReader(open(os.path.join(run, "telemetry.csv"), newline="", encoding="utf-8-sig")))
    out = {"sample": r["sample"], "n_events": len(events)}
    vecs = {}
    host_cols = [c.replace("host__", "", 1) for c in rt.HOSTCOLS]          # "<feature>__<stat>"
    net_cols = [c.replace("network__p4_", "", 1) for c in rt.P4COLS]
    for w in WINDOWS:
        k = int(round(w / 0.5)); n = int(round(OBS / w))
        hw = host_model.window_features([(win // k, pid, sid) for win, pid, sid in events], n)
        nw = switch_model.window_features(pcap, start_us, w, n)
        if w == 0.5:
            hm = wl.matrix(hw, host_model.FEATURES); hs = wl.matrix(stored, host_model.FEATURES)
            nm = wl.matrix(nw, switch_model.FEATURES); ns = wl.matrix(stored, switch_model.FEATURES)
            out["host_cells_off"] = int((np.abs(hm - hs) / np.maximum(1, np.abs(hs)) > TOL).sum())
            out["net_cells_off"] = int((np.abs(nm - ns) / np.maximum(1, np.abs(ns)) > TOL).sum())
        sh = summary.summarize(hw, host_model.FEATURES); sn = summary.summarize(nw, switch_model.FEATURES)
        vecs[w] = ([sh[c] for c in host_cols], [sn[c] for c in net_cols])
        if w == 0.5:
            ref = np.array([r[c] for c in rt.HOSTCOLS] + [r[c] for c in rt.P4COLS])
            got = np.array(vecs[w][0] + vecs[w][1])
            out["columns_off"] = int((np.abs(got - ref) / np.maximum(1, np.abs(ref)) > 1e-9).sum())
    return out, vecs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir"); ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=False)
    t0 = time.time()
    pool, dropped = pool_with_dirs()
    with Pool(args.jobs) as p:
        res = p.map(extract, pool, chunksize=2)
    checks = [c for c, _ in res]
    off = {k: sum(c[k] for c in checks) for k in ("host_cells_off", "net_cells_off", "columns_off")}
    print("pool %d (dropped %d), extraction %.0f s, 0.5 s checks %s" % (len(pool), len(dropped), time.time() - t0, off))
    y = np.asarray([r["label"] for r in pool]); g = np.asarray([r["group"] for r in pool])
    Xa = np.log1p(np.asarray([[r["syscalls"]] for r in pool], dtype=float))
    Xr = np.asarray([[float(r["rc"] if r["rc"] is not None else 0)] for r in pool])
    jobs = []
    for w in WINDOWS:
        Xh = np.asarray([v[w][0] for _, v in res]); Xp = np.asarray([v[w][1] for _, v in res])
        jobs += [(w, (s, Xh, Xp, Xa, Xr, y, g)) for s in rt.SEEDS]
    with Pool(args.jobs) as p:
        cv = p.map(_run, jobs, chunksize=1)
    by = {}
    for w, r in cv:
        by.setdefault(w, []).append(r)
    summary_rows = {}
    for w, runs in by.items():
        summary_rows[str(w)] = {}
        for det in ("host", "p4", "hybrid", "concat235", "activity", "returncode"):
            for m in ("BA", "auc", "recall", "specificity"):
                v = np.array([x[det][m] for x in runs])
                summary_rows[str(w)]["%s_%s_mean" % (det, m)] = float(v.mean())
                summary_rows[str(w)]["%s_%s_sd" % (det, m)] = float(v.std(ddof=1))
    strata = [r["stratum"] for r in pool]
    json.dump({"script_sha256": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
               "windows": WINDOWS, "observation": OBS, "seeds": rt.SEEDS, "dropped": dropped,
               "checks": checks, "check_totals": off, "summary": summary_rows,
               "per_seed": {str(w): runs for w, runs in by.items()}, "strata": strata,
               "samples": [r["sample"] for r in pool]},
              open(os.path.join(outdir, "pool240_windows.json"), "w"))
    print("%-5s %-26s %-26s %-26s %-26s" % ("W", "host BA/AUC", "network BA/AUC", "hybrid BA/AUC", "concat BA/AUC"))
    for w in WINDOWS:
        s = summary_rows[str(w)]
        print("%-5g " % w + " ".join("%.3f+-%.3f / %.3f    " % (s[d + "_BA_mean"], s[d + "_BA_sd"], s[d + "_auc_mean"])
                                       for d in ("host", "p4", "hybrid", "concat235")))
    print("activity BA %.3f, return code BA %.3f (window-independent controls)"
          % (summary_rows["0.5"]["activity_BA_mean"], summary_rows["0.5"]["returncode_BA_mean"]))


def _run(job):
    w, args = job
    return w, rt.run_seed(args)


if __name__ == "__main__":
    main()
