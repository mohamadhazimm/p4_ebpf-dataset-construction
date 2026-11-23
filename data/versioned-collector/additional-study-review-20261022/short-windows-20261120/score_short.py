#!/usr/bin/env python3
"""Scores with 0.25-s and 0.1-s windows: the paper's 240 rows (Table IV and Table V protocols) and the session
dataset (build_base.py's grouped CV), with the four detectors (host, network, concatenated, stacked) as the
committee analysis and the thesis report them. Offline. Run after build_short.py and build_session_short.py.

    /usr/bin/python3 score_short.py RUNDIR [--part paper|session|all]

Paper rows (RUNDIR/features_<ms>ms_<host>.csv; 0.5 s = the release's features.csv itself):
  variants   0.5 s published; at W = 0.25 s and 0.1 s:
               matched        host and network at W
               mixed          host at 0.5 s (the published columns), network at W, over the same 20 s
               prologue-free  host without the launch prologue, at W (and at 0.5 s for reference), network at W
  Table IV   held-out split (150 train / 54 test): RF seed 42 (confusion), forest seeds 42, 0-9 (mean, sd)
  Table V    grouped 5-fold CV over the 10 fold assignments (committee common.cv_all), per category flag rates,
             detector minus host per assignment
  baselines  lifetime: host active windows, and network active windows, alone, at the variant's windows
  gate       0.5 s published reproduces the cached Table V out-of-fold probabilities of all four detectors
             exactly (committee cache/cv_published_k40.npz) and Table IV's published confusions
Session rows (the primary view of base/20261117c): host at 0.5 s, network at W; spans 20 s and 80 s from the
injection; compare_session_lab.grouped_cv_P, per stratum, minus host, the C2 subset, the network lifetime baseline.
  gate       0.5 s reproduces base/20261117c's base.json scores exactly.
"""
import argparse
import csv
import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
COMMITTEE = HERE.parent / "committee-eval-20261113"
sys.path.insert(0, str(COMMITTEE))
import common as C  # noqa: E402

ROWS, HOST_COLS, NET_COLS = C.load()
Y = C.labels(ROWS)
G = C.groups_published(ROWS)
RF_SEEDS = [42] + list(range(10))
TABLE4 = {"network": (28, 0, 13, 13), "host": (24, 4, 0, 26), "concat": (26, 2, 2, 24), "stacked": (27, 1, 1, 25)}
METRICS = ("balanced_accuracy", "auc", "recall", "specificity", "precision", "f1")
CATEGORIES = ("malware", "network_attack", "benign", "network_benign", "null")


def read(path, cols):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    assert [r["execution_id"] for r in rows] == [r["execution_id"] for r in ROWS], path
    return np.asarray([[float(r[c]) for c in cols] for r in rows])


def paper_variants(rundir):
    pub_h, pub_n = C.matrix(ROWS, HOST_COLS), C.matrix(ROWS, NET_COLS)
    f = lambda ms, v, cols: read(rundir / ("features_%dms_%s.csv" % (ms, v)), cols)  # noqa: E731
    out = {"0.5 s published": (pub_h, pub_n, 500),
           "0.5 s prologue-free": (f(500, "prologuefree", HOST_COLS), pub_n, 500)}
    for ms in (250, 100):
        w = "%.2g s" % (ms / 1000)
        n = f(ms, "ascollected", NET_COLS)
        out[w + " matched"] = (f(ms, "ascollected", HOST_COLS), n, ms)
        out[w + " mixed"] = (pub_h, n, ms)
        out[w + " prologue-free"] = (f(ms, "prologuefree", HOST_COLS), n, ms)
    return out


def _table4_job(args):
    Xh, Xn, tr, te, seed = args
    return seed, C.fit_predict(Xh, Xn, Y, G, tr, te, rf_seed=seed)


def table4(Xh, Xn):
    split = np.asarray([r["split"] for r in ROWS])
    sub = np.isin(np.asarray([r["category"] for r in ROWS]), ("malware", "benign"))
    tr, te = np.flatnonzero(sub & (split == "train")), np.flatnonzero(sub & (split == "test"))
    with Pool(len(RF_SEEDS)) as pool:
        res = dict(pool.map(_table4_job, [(Xh, Xn, tr, te, s) for s in RF_SEEDS]))
    out = {}
    for d in C.DETECTORS:
        m42 = C.metrics(Y[te], res[42][d])
        bas = [C.metrics(Y[te], res[s][d])["balanced_accuracy"] for s in RF_SEEDS]
        out[d] = {"seed42": m42, "ba_mean_11_seeds": float(np.mean(bas)), "ba_sd_11_seeds": float(np.std(bas, ddof=1))}
    return out


def table5(P):
    out = {}
    cat = np.asarray([r["category"] for r in ROWS])
    for d, p in P.items():
        per = [C.metrics(Y, p[k]) for k in range(p.shape[0])]
        out[d] = {m: {"mean": float(np.mean([x[m] for x in per])), "sd": float(np.std([x[m] for x in per], ddof=1))}
                  for m in METRICS}
        out[d]["per_assignment_ba"] = [x["balanced_accuracy"] for x in per]
        out[d]["flagged_share"] = {c: float((p[:, cat == c] >= 0.5).mean()) for c in CATEGORIES}
    for d in C.DETECTORS[1:]:
        diff = np.asarray(out[d]["per_assignment_ba"]) - np.asarray(out["host"]["per_assignment_ba"])
        out[d]["minus_host"] = {"mean": float(diff.mean()), "sd": float(diff.std(ddof=1)), "positive": int((diff > 0).sum())}
    return out


def lifetime(X, cols, signal):
    x = X[:, [cols.index(signal + "__active_windows")]]
    P, _ = C.cv_all(x, x, Y, G, detectors=("host",), jobs=10)
    t5 = [C.metrics(Y, P["host"][k])["balanced_accuracy"] for k in range(P["host"].shape[0])]
    split = np.asarray([r["split"] for r in ROWS])
    sub = np.isin(np.asarray([r["category"] for r in ROWS]), ("malware", "benign"))
    tr, te = np.flatnonzero(sub & (split == "train")), np.flatnonzero(sub & (split == "test"))
    p4 = C.fit_predict(x, x, Y, G, tr, te, detectors=("host",))["host"]
    return {"table5_ba_mean": float(np.mean(t5)), "table5_ba_sd": float(np.std(t5, ddof=1)),
            "table4_ba": C.metrics(Y[te], p4)["balanced_accuracy"]}


def score_paper(rundir):
    out = {}
    cache = np.load(COMMITTEE / "cache" / "cv_published_k40.npz", allow_pickle=False)
    for name, (Xh, Xn, ms) in paper_variants(rundir).items():
        t0 = time.time()
        P, _F = C.cv_all(Xh, Xn, Y, G, jobs=10)
        res = {"window_ms": ms, "table5": table5(P), "table4": table4(Xh, Xn),
               "baselines": {"host_lifetime": lifetime(Xh, HOST_COLS, "host_total_syscalls_total"),
                             "network_lifetime": lifetime(Xn, NET_COLS, "net_pkts_total_delta")}}
        if name == "0.5 s published":
            res["gate"] = {
                "table5_oof_equal_to_cache": {d: bool(np.array_equal(P[d], cache[d])) for d in C.DETECTORS},
                "table4_confusions_equal": {d: (res["table4"][d]["seed42"]["tn"], res["table4"][d]["seed42"]["fp"],
                                                res["table4"][d]["seed42"]["fn"], res["table4"][d]["seed42"]["tp"])
                                            == TABLE4[d] for d in C.DETECTORS}}
            ok = all(res["gate"]["table5_oof_equal_to_cache"].values()) and all(res["gate"]["table4_confusions_equal"].values())
            res["gate"]["passed"] = bool(ok)
            if not ok:
                print("[paper] GATE FAILED", res["gate"], flush=True)
                sys.exit(1)
        res["seconds"] = round(time.time() - t0, 1)
        out[name] = res
        t5, t4 = res["table5"], res["table4"]
        print("[paper] %-22s Table V BA " % name
              + "  ".join("%s %.3f+-%.3f" % (d, t5[d]["balanced_accuracy"]["mean"], t5[d]["balanced_accuracy"]["sd"])
                          for d in C.DETECTORS)
              + " | Table IV seed42 " + "  ".join("%s %.3f" % (d, t4[d]["seed42"]["balanced_accuracy"]) for d in C.DETECTORS)
              + " | lifetime h %.3f n %.3f  (%.0f s)" % (res["baselines"]["host_lifetime"]["table5_ba_mean"],
                                                        res["baselines"]["network_lifetime"]["table5_ba_mean"],
                                                        res["seconds"]), flush=True)
    return out


def score_session(rundir):
    import build_session_short as BS   # loads the base's sessions (session-lab code, unchanged)
    BB, CS = BS.BB, BS.CS
    ref = json.loads((BS.BASE / "base.json").read_text())["rules"]["relaxed"]["views"]["sessions"]
    y = np.asarray([CS.label(s) for s in BS.PS])
    g = np.asarray([s["group"] for s in BS.PS])
    nsig = BS.NET_SIGNALS
    pk = nsig.index("net_pkts_total_delta")
    c2 = np.asarray([(s["kind"] == "malware" and s["family"].lower() in BB.C2_FAMILIES) or s["kind"] in ("benign", "null")
                     for s in BS.PS])
    out = {}
    for span, n in BS.SPANS.items():
        Xh, Xn05, pi, _hc, _nc = BB.matrices(BS.PS, n)
        for ms in BS.MS:
            t0 = time.time()
            r = 500 // ms
            Nw = np.load(rundir / "session" / ("session_windows_%dms.npz" % ms), allow_pickle=False)["N"][:, :n * r]
            Xn = C.summarize(Nw)
            name = "%s, network %.2g s" % (span, ms / 1000)
            sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
            res = {"span": span, "window_ms": ms, "scores": sc, "per_stratum": BB.stratum_recall(BS.PS, P),
                   "minus_host": CS.paired(y, P),
                   "network_lifetime_baseline": CS.baseline_cv((Nw[:, :, pk] > 0).sum(1), y, g)}
            sc2, P2 = CS.grouped_cv_P(Xh[c2], Xn[c2], y[c2], g[c2])
            res["c2_subset"] = {"n_implant": int(y[c2].sum()), "n_benign": int((y[c2] == 0).sum()), "scores": sc2}
            if P2 is not None:
                res["c2_subset"]["minus_host"] = CS.paired(y[c2], P2)
            if ms == 500:
                same = bool(np.array_equal(Xn, Xn05))
                diffs = {d: abs(sc[d]["ba_mean"] - ref[span]["scores"][d]["ba_mean"]) for d in C.DETECTORS}
                res["gate"] = {"network_matrix_equal": same, "ba_abs_diff_vs_base_json": diffs,
                               "passed": same and max(diffs.values()) == 0.0}
                if not res["gate"]["passed"]:
                    print("[session] GATE FAILED", res["gate"], flush=True)
                    sys.exit(1)
            res["seconds"] = round(time.time() - t0, 1)
            out[name] = res
            print("[session] %-22s BA " % name + "  ".join(
                "%s %.3f+-%.3f" % (d, sc[d]["ba_mean"], sc[d]["ba_sd"]) for d in C.DETECTORS)
                + " | C2 subset " + "  ".join("%s %.3f" % (d, sc2[d]["ba_mean"]) for d in C.DETECTORS)
                + " | net lifetime %.3f (%.0f s)" % (res["network_lifetime_baseline"].get("ba_mean", float("nan")),
                                                     res["seconds"]), flush=True)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rundir")
    ap.add_argument("--part", default="all", choices=("paper", "session", "all"))
    a = ap.parse_args()
    rundir = Path(a.rundir).resolve()
    path = rundir / "scores.json"
    result = json.loads(path.read_text()) if path.is_file() else {}
    if a.part in ("paper", "all"):
        result["paper"] = score_paper(rundir)
        path.write_text(json.dumps(result, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)))
    if a.part in ("session", "all"):
        result["session"] = score_session(rundir)
        path.write_text(json.dumps(result, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)))
    print("wrote", path)


if __name__ == "__main__":
    main()
