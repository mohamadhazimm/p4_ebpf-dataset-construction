"""Does the thesis host detector key on the C-library / runtime start-up rather than on behaviour? Offline.

The baselines found that n-grams of a program's first 50 calls alone match the full n-gram detector, because the
benign builds share a few toolchains while the malware comes from many. Here:
  1 how often the target process's first 50 own calls contain well-known glibc start-up calls, by category;
  2 the thesis detectors retrained with each process's first M own calls removed (M = 50, 100), on top of the
    launcher prologue (removed too: it is identical in every run), Table IV and Table V protocols.

    /usr/bin/python3 startup_check.py
"""
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "evasion"))
import common as C  # noqa: E402
import fasthost as FH  # noqa: E402

# x86-64 / i386 numbers of glibc start-up calls (2.35 and later begin with these after the loader)
STARTUP = {"amd64": {"rseq": 334, "getrandom": 318, "set_robust_list": 273, "prlimit64": 302, "set_tid_address": 218},
           "i386": {"rseq": 386, "getrandom": 355, "set_robust_list": 311, "prlimit64": 340, "set_tid_address": 258}}


def own_events(i):
    w, p, s, root, pro = FH.load_events(i)
    return w, p, s, root, pro


def drop_first(w, p, s, pro, M):
    """Remove the prologue and the first M own calls of every process (in call order)."""
    keep = ~pro
    idx = np.flatnonzero(keep)
    if M and len(idx):
        sub_p = p[idx]
        order = np.argsort(sub_p, kind="stable")
        sp = sub_p[order]
        starts = np.r_[0, np.flatnonzero(sp[1:] != sp[:-1]) + 1]
        rank = np.arange(len(sp)) - np.repeat(starts, np.diff(np.r_[starts, len(sp)]))
        early = np.zeros(len(idx), bool)
        early[order[rank < M]] = True
        keep[idx[early]] = False
    return w[keep], p[keep], s[keep]


def main():
    rows, hc, nc = C.load()
    y = C.labels(rows)
    cats = np.asarray([r["category"] for r in rows])
    out = {"startup_calls_in_first_50": {}}
    # 1 descriptive: the target (root) process's first 50 own calls
    have = {name: [] for name in STARTUP["amd64"]}
    for i, r in enumerate(rows):
        w, p, s, root, pro = own_events(i)
        first = s[(p == root) & ~pro][:50]
        abi = "i386" if r["mode"].startswith("i386") else "amd64"
        for name, num in STARTUP[abi].items():
            have[name].append(bool((first == num).any()))
    for name, v in have.items():
        v = np.asarray(v)
        out["startup_calls_in_first_50"][name] = {c: round(float(v[cats == c].mean()), 3)
                                                  for c in ("malware", "benign", "network_attack", "network_benign", "null")}
    # 2 retrain without the start-up
    Xn = C.matrix(rows, nc)
    g = C.groups_published(rows)
    gen = np.asarray([r["category"] in ("malware", "benign") for r in rows])
    split = np.asarray([r["split"] for r in rows])
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    for M in (0, 50, 100):
        Xh = []
        empty = 0
        for i in range(len(rows)):
            w, p, s, root, pro = own_events(i)
            ww, pp, ss = drop_first(w, p, s, pro, M)
            empty += len(ss) == 0
            Xh.append(FH.to_columns(FH.host_windows(ww, pp, ss), hc))
        Xh = np.asarray(Xh)
        P4 = C.fit_predict(Xh, Xn, y, g, tr, te)
        PV, _ = C.cv_all(Xh, Xn, y, g)
        res = {"runs_left_without_any_call": int(empty),
               "runs_left_without_any_call_by_category": {c: int(sum(1 for i in range(len(rows)) if cats[i] == c and not Xh[i].any()))
                                                          for c in ("malware", "benign", "network_attack", "network_benign", "null")},
               "table_iv": {d: {k: round(C.metrics(y[te], p)[k], 3) for k in ("balanced_accuracy", "auc")} for d, p in P4.items()},
               "table_v": {}}
        for d in C.DETECTORS:
            bas = [C.metrics(y, PV[d][s])["balanced_accuracy"] for s in range(len(C.FOLD_SEEDS))]
            aucs = [C.metrics(y, PV[d][s])["auc"] for s in range(len(C.FOLD_SEEDS))]
            rec = {c: round(float((PV[d][:, cats == c] >= .5).mean()), 3) for c in ("malware", "benign")}
            res["table_v"][d] = {"ba_mean": round(float(np.mean(bas)), 3), "ba_sd": round(float(np.std(bas, ddof=1)), 3),
                                 "auc_mean": round(float(np.mean(aucs)), 3), "malware_recall": rec["malware"],
                                 "benign_false_alarms": rec["benign"]}
        out["drop_first_%d" % M] = res
        print("M=%3d  empty runs %3d  | Table IV BA host %.3f concat %.3f stacked %.3f | Table V BA host %.3f concat %.3f stacked %.3f"
              % (M, empty, res["table_iv"]["host"]["balanced_accuracy"], res["table_iv"]["concat"]["balanced_accuracy"],
                 res["table_iv"]["stacked"]["balanced_accuracy"], res["table_v"]["host"]["ba_mean"],
                 res["table_v"]["concat"]["ba_mean"], res["table_v"]["stacked"]["ba_mean"]))
    C.write_json(C.HERE / "results" / "startup_check.json", out)
    for name, v in out["startup_calls_in_first_50"].items():
        print("%-16s in the target's first 50 calls: %s" % (name, v))


if __name__ == "__main__":
    main()
