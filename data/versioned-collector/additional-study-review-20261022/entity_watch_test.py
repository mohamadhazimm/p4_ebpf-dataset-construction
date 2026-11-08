"""Triggered per-process watch test: watch every new process from the read window it appears in, score it at
checkpoints, and alert a run if any of its processes is flagged.

Design under test (the advisor's suggestion with today's 10-s read interval):
- read grid: 10-s windows from sample start (each 10-s window = 20 consecutive 0.5-s windows of the raw events);
- unit: one process (pid), watched from the 10-s window of its first recorded system call;
- features: the paper's 18 host window features (features/host_model.py) of that process alone, summarized over the
  watched windows (features/summary.py: mean, max, sum, std, non-zero windows) = 90 columns;
- checkpoints T: the process's first T seconds (1 window at 10 s, ...), cut at the end of the observation;
- run verdict at T: the highest process score of the run (alert if >= 0.5); alert-once policy over checkpoints.
Host only per process: these runs do not record which flow belongs to which process.

Comparison: the whole-execution host detector (all processes of the run combined, as in the paper) over the first
T seconds of the run, on the same grid.

Weights: each run has total weight 1 (spread over its processes), then classes are balanced, so a run that forks
2,591 processes counts as much as a benign run with one. Labels come from the run. Grouped CV holds out whole
malware families / benign programs (StratifiedGroupKFold(5)), RF300, ten fold assignments (seeds 42, 0-8).
Offline; no VM, no model promotion, no merge.

    /usr/bin/python3 entity_watch_test.py OUTDIR [--jobs N]
"""

import argparse
import csv
import glob
import hashlib
import json
import os
import sys
import time
from collections import defaultdict
from multiprocessing import Pool

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import window_length_test as wl  # noqa: E402  (load_cases, release feature code)
import window_length_pool240 as wp  # noqa: E402  (240-run pool with run folders)

host_model, summary = wl.host_model, wl.summary
READ = 10.0
K = int(round(READ / 0.5))
SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
OUTDIR = None
DATASETS = {
    "five_minute": {"observation": 300.0, "checkpoints": [10.0, 20.0, 60.0, 120.0, 180.0, 300.0]},
    "pool240": {"observation": 20.0, "checkpoints": [10.0, 20.0]},
}


def runs_five_minute():
    cases, _ = wl.load_cases(os.path.join(HERE, "scale-5min/20261105T224558731619Z"))
    out = []
    for c in cases:
        if c["label"] not in ("malware", "benign"):
            continue                                  # nulls are not classified in the 5-minute analysis
        group = ("fam:" + c["family"]) if c["label"] == "malware" else ("prog:" + c["program"])
        out.append({"sample": c["sample"], "run": c["run_dir"], "y": int(c["label"] == "malware"), "group": group,
                    "kind": c["label"]})
    return out


def runs_pool240():
    pool, _ = wp.pool_with_dirs()
    out = []
    for r in pool:
        run = glob.glob(os.path.join(r["run_dir"], "output", "run_*"))[0]
        out.append({"sample": r["sample"], "run": run, "y": int(r["label"]), "group": r["group"],
                    "kind": r["stratum"]})
    return out


def read_events(path):
    ev = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["event"] == "syscall":
                ev.append((int(row["window_id"]) // K, int(row["pid"]), int(row["detail"][3:])))
    return ev


def summarize(windows):
    s = summary.summarize(windows, host_model.FEATURES)
    return [s["%s__%s" % (f, st)] for f in host_model.FEATURES for st in summary.STATISTICS]


def features(job):
    run, n, checkpoints = job
    ev = read_events(os.path.join(run["run"], "syscall_events.csv"))
    per_pid = defaultdict(list)
    for w, pid, sid in ev:
        if 0 <= w < n:
            per_pid[pid].append((w, pid, sid))
    tree = host_model.window_features(ev, n)            # whole execution, all processes combined
    out = {"tree": {t: summarize(tree[:int(round(t / READ))]) for t in checkpoints}, "proc": [],
           "n_events": len(ev)}
    for pid, e in sorted(per_pid.items()):
        w0 = min(w for w, _, _ in e)
        win = host_model.window_features(e, n)
        calls = len(e)
        out["proc"].append({"pid": pid, "start_window": w0, "calls": calls,
                            "x": {t: summarize(win[w0:min(n, w0 + int(round(t / READ)))]) for t in checkpoints}})
    return out


def fit_predict(job):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedGroupKFold
    name, X, y, w, run_idx, run_y, run_groups, seed = job
    p = np.zeros(len(y))
    for tr_runs, te_runs in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(
            np.zeros(len(run_y)), run_y, run_groups):
        tr = np.isin(run_idx, tr_runs); te = np.isin(run_idx, te_runs)
        clf = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=1)
        clf.fit(X[tr], y[tr], sample_weight=w[tr])
        p[te] = clf.predict_proba(X[te])[:, 1]
    return name, seed, p


def metrics(y, score, w=None):
    from sklearn.metrics import roc_auc_score
    pred = score >= 0.5
    w = np.ones(len(y)) if w is None else w
    rec = (w * (pred & (y == 1))).sum() / (w * (y == 1)).sum()
    fa = (w * (pred & (y == 0))).sum() / (w * (y == 0)).sum()
    return {"auc": float(roc_auc_score(y, score, sample_weight=w)), "recall": float(rec), "false_alarm": float(fa),
            "ba": float((rec + 1 - fa) / 2)}


def run_dataset(name, cfg, jobs):
    runs = runs_five_minute() if name == "five_minute" else runs_pool240()
    n = int(round(cfg["observation"] / READ)); cps = cfg["checkpoints"]
    with Pool(jobs) as pool:
        feats = pool.map(features, [(r, n, cps) for r in runs], chunksize=1)
    run_y = np.array([r["y"] for r in runs]); run_groups = np.array([r["group"] for r in runs])
    n_cls = {c: int((run_y == c).sum()) for c in (0, 1)}
    # process rows
    rows = [(i, p) for i, f in enumerate(feats) for p in f["proc"]]
    run_idx = np.array([i for i, _ in rows])
    py = run_y[run_idx]
    nproc = np.array([len(feats[i]["proc"]) for i in run_idx])
    pw = (1.0 / nproc) * np.array([len(runs) / (2.0 * n_cls[c]) for c in py])
    tw = np.array([len(runs) / (2.0 * n_cls[c]) for c in run_y])
    work = []
    for t in cps:
        Xp = np.array([p["x"][t] for _, p in rows]); Xt = np.array([f["tree"][t] for f in feats])
        for seed in SEEDS:
            work.append(("proc|%g" % t, Xp, py, pw, run_idx, run_y, run_groups, seed))
            work.append(("tree|%g" % t, Xt, run_y, tw, np.arange(len(runs)), run_y, run_groups, seed))
    with Pool(jobs) as pool:
        res = pool.map(fit_predict, work, chunksize=1)
    pred = defaultdict(dict)
    for key, seed, p in res:
        pred[key][seed] = p
    table = []
    for seed in SEEDS:
        alerted = np.zeros(len(runs), bool)          # alert-once over checkpoints (per-process watch)
        for t in cps:
            pp = pred["proc|%g" % t][seed]
            run_max = np.array([pp[run_idx == i].max() for i in range(len(runs))])
            alerted |= run_max >= 0.5
            table.append({"seed": seed, "checkpoint": t,
                          "process": metrics(py, pp, pw),
                          "run_any_process": metrics(run_y, run_max),
                          "run_alert_once": {"recall": float(alerted[run_y == 1].mean()),
                                             "false_alarm": float(alerted[run_y == 0].mean())},
                          "tree": metrics(run_y, pred["tree|%g" % t][seed])})
    calls = np.array([p["calls"] for _, p in rows])
    np.savez_compressed(os.path.join(OUTDIR, name + "_oof.npz"), run_idx=run_idx, run_y=run_y,
                        run_groups=run_groups, nproc=np.array([len(f["proc"]) for f in feats]),
                        **{k.replace("|", "_") + "_s%d" % s: v for k, d in pred.items() for s, v in d.items()})
    return {"runs": len(runs), "malware_runs": n_cls[1], "benign_runs": n_cls[0],
            "groups": len(set(run_groups)), "processes": len(rows),
            "processes_malware": int((py == 1).sum()), "processes_benign": int((py == 0).sum()),
            "processes_under_20_calls": int((calls < 20).sum()),
            "processes_starting_after_first_window": int(sum(p["start_window"] > 0 for _, p in rows)),
            "per_seed": table, "kinds": sorted({r["kind"] for r in runs})}


def mean_over_seeds(table, path):
    out = defaultdict(list)
    for r in table:
        v = r
        for k in path:
            v = v[k]
        out[r["checkpoint"]].append(v)
    return {t: (float(np.mean(v)), float(np.std(v, ddof=1))) for t, v in out.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir"); ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    global OUTDIR
    outdir = os.path.abspath(args.outdir); os.makedirs(outdir, exist_ok=False)
    OUTDIR = outdir
    t0 = time.time(); results = {}
    for name, cfg in DATASETS.items():
        results[name] = run_dataset(name, cfg, args.jobs)
        r = results[name]
        print("\n== %s: %d runs (%d malware / %d benign, %d groups), %d processes (%d malware / %d benign), "
              "%d under 20 calls, %d start after the first window"
              % (name, r["runs"], r["malware_runs"], r["benign_runs"], r["groups"], r["processes"],
                 r["processes_malware"], r["processes_benign"], r["processes_under_20_calls"],
                 r["processes_starting_after_first_window"]))
        cols = [("process AUC", ("process", "auc")), ("run AUC (any proc)", ("run_any_process", "auc")),
                ("run recall", ("run_any_process", "recall")), ("run false alarm", ("run_any_process", "false_alarm")),
                ("alert-once recall", ("run_alert_once", "recall")),
                ("alert-once FA", ("run_alert_once", "false_alarm")), ("whole-run AUC", ("tree", "auc")),
                ("whole-run BA", ("tree", "ba"))]
        print("%-6s" % "T" + "".join("%22s" % c for c, _ in cols))
        means = {c: mean_over_seeds(r["per_seed"], p) for c, p in cols}
        for t in DATASETS[name]["checkpoints"]:
            print("%-6g" % t + "".join("%22s" % ("%.3f+-%.3f" % means[c][t]) for c, _ in cols))
        r["means"] = {c: {str(t): v for t, v in m.items()} for c, m in means.items()}
    results["script_sha256"] = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
    results["read_interval"] = READ; results["seeds"] = SEEDS
    json.dump(results, open(os.path.join(outdir, "entity_watch.json"), "w"), default=float)
    print("\n%.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
