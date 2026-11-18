"""Score the toolchain-matched benign collection (collect_toolchain21.py) against the paper's detectors. Offline.

Rows of the new runs are built exactly as the dataset's: the 18 host and 29 network window signals from each run's
telemetry.csv, summarized by mean, max, sum, std and active windows (common.per_window / common.summarize). Only
runs the collection's validation accepted are used. Groups: benign_project::<project> (the dataset's labels, so a
project stays whole across its old and new builds); splits: the dataset's split of the project, the proposal's for
new (Go) projects.

  A transfer:    the paper's detectors trained on the 240 released rows, applied to the new benign programs
  B replacement: Table V protocol with the 87 static benign rows replaced by the new runs (10 fold assignments)
  C held-out:    Table IV protocol (the released split) with the same replacement; forest seeds 42 and 0-9
  D mixed:       Table V protocol with the new runs added to all 240 rows
In every pool also the five start-up flags alone (rseq, getrandom, set_robust_list, prlimit64, set_tid_address in
the target's first 50 calls), the check that showed the toolchain confound.

  /usr/bin/python3 toolchain/score_toolchain.py ../toolchain21-collect/<attempt>
"""
import collections
import csv
import json
import sys
from pathlib import Path

import os

import numpy as np

HERE = Path(__file__).resolve().parent
QUICK = os.environ.get("SCORE_QUICK") == "1"  # self-test only: one fold assignment, one forest seed
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "evasion"))
import common as C  # noqa: E402
import fasthost as FH  # noqa: E402
from startup_check import STARTUP  # noqa: E402


def flags_from(p, s, root, pro, mode):
    first = s[(p == root) & ~pro][:50]
    abi = "i386" if "i386" in mode else "amd64"
    return [float((first == num).any()) for num in STARTUP[abi].values()]


def new_run(out, mode, hs, ns):
    tel = list(csv.DictReader(open(out / "telemetry.csv", newline="", encoding="utf-8-sig")))
    assert len(tel) == 40, out
    H = np.asarray([[float(x[s]) for s in hs] for x in tel])
    N = np.asarray([[float(x[s]) for s in ns] for x in tel])
    meta = json.loads((out / "run.json").read_text())
    root = int(meta["sample_root_pid"])
    succ = [int(e["timestamp_ns"]) for e in csv.DictReader(open(out / "exec_events.csv"))
            if e["event"] == "exec_success" and int(e["pid"]) == root]
    cut = succ[1] if len(succ) >= 2 else None
    p, s, pro = [], [], []
    for r in csv.DictReader(open(out / "syscall_events.csv")):
        if r["event"] != "syscall":
            continue
        try:
            sid = int(r["detail"].split("id=")[1].split()[0])
        except (IndexError, ValueError):
            continue
        p.append(int(r["pid"])); s.append(sid)
        pro.append(cut is not None and int(r["pid"]) == root and int(r["timestamp_ns"]) < cut)
    flags = flags_from(np.asarray(p), np.asarray(s), root, np.asarray(pro, bool), mode)
    return H, N, flags


def summarize_runs(P, y, cats, label):
    """BA mean/sd/min/max over fold assignments, plus flag rates per category."""
    out = {}
    for d, M in P.items():
        bas = [C.metrics(y, M[k])["balanced_accuracy"] for k in range(M.shape[0])]
        bas = bas if len(bas) > 1 else bas * 2  # sd of one assignment: 0
        aucs = [C.metrics(y, M[k])["auc"] for k in range(M.shape[0])]
        out[d] = {"ba_mean": round(float(np.mean(bas)), 3), "ba_sd": round(float(np.std(bas, ddof=1)), 3),
                  "ba_min": round(float(np.min(bas)), 3), "ba_max": round(float(np.max(bas)), 3),
                  "auc_mean": round(float(np.mean(aucs)), 3),
                  "flagged_by_category": {c: round(float((M[:, cats == c] >= .5).mean()), 3)
                                          for c in sorted(set(cats))}}
    return out


def main():
    attempt = Path(sys.argv[1]).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    vals = sorted(attempt.glob("validation-*.json"))
    assert vals, "run collect_toolchain21.py --validate first"
    accepted = {r["sample"] for r in json.loads(vals[-1].read_text())["cases"] if r["status"] == "accepted"}
    rows, hc, nc = C.load()
    hs, ns = C.signals(hc), C.signals(nc)
    H, N, _, _ = C.per_window(rows, hc, nc)
    Xh_d, Xn_d = C.summarize(H), C.summarize(N)
    y_d = C.labels(rows)
    g_d = C.groups_published(rows)
    cats_d = np.asarray([r["category"] for r in rows])
    mode_d = np.asarray([r["mode"] for r in rows])
    split_d = np.asarray([r["split"] for r in rows])
    flags_d = []
    for i, r in enumerate(rows):
        w, p, s, root, pro = FH.load_events(i)
        flags_d.append(flags_from(p, s, root, pro, r["mode"]))
    flags_d = np.asarray(flags_d)
    project_split = {r["project"]: r["split"] for r in rows if r["category"] == "benign"}

    new = []
    for c in protocol["cases"]:
        if c["label"] != "benign" or c["sample"] not in accepted:
            continue
        runs = sorted((attempt / "runs" / c["sample"] / "output").glob("run_*"))
        Hn, Nn, fl = new_run(runs[-1], c["mode"], hs, ns)
        split = project_split.get(c["project"]) or ("train" if c.get("split_suggestion") == "train" else "test")
        new.append({"case": c, "H": Hn, "N": Nn, "flags": fl, "split": split})
    n = len(new)
    Xh_t = C.summarize(np.stack([x["H"] for x in new]))
    Xn_t = C.summarize(np.stack([x["N"] for x in new]))
    flags_t = np.asarray([x["flags"] for x in new])
    g_t = np.asarray(["benign_project::" + x["case"]["project"] for x in new])
    cls_t = np.asarray([x["case"]["toolchain_class"] for x in new])
    mode_t = np.asarray([x["case"]["mode"].replace("native_", "") for x in new])
    split_t = np.asarray([x["split"] for x in new])
    res = {"attempt": str(attempt), "new_benign_runs": n,
           "new_by_mode_class": {"%s %s" % k: v for k, v in sorted(collections.Counter(zip(mode_t, cls_t)).items())},
           "startup_flags_rate": {
               "dataset_static_benign": np.round(flags_d[(cats_d == "benign") & (mode_d != "amd64_dynamic")].mean(0), 3).tolist(),
               "dataset_static_malware": np.round(flags_d[(cats_d == "malware") & (mode_d != "amd64_dynamic")].mean(0), 3).tolist(),
               "new_benign": np.round(flags_t.mean(0), 3).tolist(),
               "order": list(STARTUP["amd64"].keys())}}

    # A: transfer of the paper's detectors (trained on all 240 rows)
    Xh = np.vstack([Xh_d, Xh_t]); Xn = np.vstack([Xn_d, Xn_t])
    y = np.concatenate([y_d, np.zeros(n, int)]); g = np.concatenate([g_d, g_t])
    tr, te = np.arange(len(rows)), np.arange(len(rows), len(rows) + n)
    P = C.fit_predict(Xh, Xn, y, g, tr, te)
    flagger = C.rf(42).fit(flags_d, y_d)
    P["five_flags"] = flagger.predict_proba(flags_t)[:, 1]
    res["A_transfer_flag_rate"] = {d: {"all": round(float((p >= .5).mean()), 3),
                                       "by_class": {k: round(float((p[cls_t == k] >= .5).mean()), 3)
                                                    for k in sorted(set(cls_t))}} for d, p in P.items()}

    # B: Table V with the 87 static benign rows replaced
    keep = ~((cats_d == "benign") & (mode_d != "amd64_dynamic"))
    Xh_b = np.vstack([Xh_d[keep], Xh_t]); Xn_b = np.vstack([Xn_d[keep], Xn_t])
    y_b = np.concatenate([y_d[keep], np.zeros(n, int)]); g_b = np.concatenate([g_d[keep], g_t])
    cats_b = np.concatenate([cats_d[keep], np.asarray(["benign_toolchain"] * n)])
    fl_b = np.vstack([flags_d[keep], flags_t])
    seeds = [42] if QUICK else C.FOLD_SEEDS
    P_b, _ = C.cv_all(Xh_b, Xn_b, y_b, g_b, seeds=seeds)
    P_f, _ = C.cv_all(fl_b, fl_b, y_b, g_b, seeds=seeds, detectors=("host",))
    P_b["five_flags"] = P_f["host"]
    res["B_replacement_table_v"] = {"rows": int(len(y_b)), **summarize_runs(P_b, y_b, cats_b, "B")}

    # C: Table IV split with the same replacement
    gen_b = np.isin(cats_b, ["malware", "benign", "benign_toolchain"])
    split_b = np.concatenate([split_d[keep], split_t])
    trc = np.flatnonzero(gen_b & (split_b == "train")); tec = np.flatnonzero(gen_b & (split_b == "test"))
    res["C_heldout"] = {"train": int(len(trc)), "test": int(len(tec)),
                        "test_benign_toolchain": int((cats_b[tec] == "benign_toolchain").sum())}
    for seed in ([42] if QUICK else [42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]):
        Pc = C.fit_predict(Xh_b, Xn_b, y_b, g_b, trc, tec, rf_seed=seed)
        Pc["five_flags"] = C.rf(seed).fit(fl_b[trc], y_b[trc]).predict_proba(fl_b[tec])[:, 1]
        for d, p in Pc.items():
            m = C.metrics(y_b[tec], p)
            res["C_heldout"].setdefault(d, {"ba_by_seed": [], "auc_by_seed": []})
            res["C_heldout"][d]["ba_by_seed"].append(round(m["balanced_accuracy"], 3))
            res["C_heldout"][d]["auc_by_seed"].append(round(m["auc"], 3))
            if seed == 42:
                res["C_heldout"][d]["seed42"] = {k: m[k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")}
    for d in list(res["C_heldout"]):
        if isinstance(res["C_heldout"][d], dict) and "ba_by_seed" in res["C_heldout"][d]:
            v = res["C_heldout"][d]["ba_by_seed"]
            res["C_heldout"][d]["ba_mean_sd"] = [round(float(np.mean(v)), 3), round(float(np.std(v, ddof=1)), 3)]

    # D: mixed pool (all 240 + the new runs)
    cats_m = np.concatenate([cats_d, np.asarray(["benign_toolchain"] * n)])
    P_m, _ = C.cv_all(Xh, Xn, y, g, seeds=seeds)
    P_fm, _ = C.cv_all(np.vstack([flags_d, flags_t]), np.vstack([flags_d, flags_t]), y, g, seeds=seeds,
                       detectors=("host",))
    P_m["five_flags"] = P_fm["host"]
    res["D_mixed_table_v"] = {"rows": int(len(y)), **summarize_runs(P_m, y, cats_m, "D")}

    out = HERE.parent / "results" / ("toolchain_scores_selftest.json" if QUICK else "toolchain_scores.json")
    C.write_json(out, res)
    print(json.dumps({k: v for k, v in res.items() if k != "attempt"}, indent=1))


if __name__ == "__main__":
    main()
