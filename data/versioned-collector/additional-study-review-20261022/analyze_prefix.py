"""Observation-length prefix analysis: does host/network/hybrid separation improve from 20 s to 5 min?

Scores the SAME captures at prefixes of their 600 windows: K in {40,120,240,360,600} = 20 s / 1 / 2 / 3 / 5 min (the
first 40 windows reproduce the 20 s protocol). For each prefix, each per-window feature is aggregated over the first K
windows (mean/max/sum/std/active), split into host = hostmon_syscall_sequence (the ADFA sequence descriptors) and
network = p4_network (the P4 flow features), hybrid = both. Grouped CV holds out whole malware families and whole
benign programs. Reports balanced accuracy / AUC vs K per detector, plus the descriptive fraction of activity after
20 s. Offline; no VM, no model promotion, no merge. Run with /usr/bin/python3 (needs user-site scikit-learn).
"""

import csv
import glob
import json
import math
import sys
from collections import defaultdict

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

PREFIXES = [40, 120, 240, 360, 600]
HOST_GROUP = "hostmon_syscall_sequence"
NET_GROUP = "p4_network"


def load_cases(attempt):
    proto = json.load(open(attempt + "/protocol.json"))
    meta = {c["sample"]: c for c in proto["cases"]}
    cases = []
    for rj in sorted(glob.glob(attempt + "/runs/*/output/run_*/run.json")):
        sample = rj.split("/runs/")[1].split("/")[0]
        c = meta.get(sample)
        if not c or c["label"] == "null":
            continue
        d = json.load(open(rj))
        if d.get("collection_quality_status") != "accepted":
            continue
        groups = d["telemetry_feature_groups"]
        rows = list(csv.DictReader(open(rj.replace("run.json", "telemetry.csv"))))
        if len(rows) != 600:
            continue
        host_cols, net_cols = groups[HOST_GROUP], groups[NET_GROUP]
        H = np.array([[float(r[c]) for c in host_cols] for r in rows])   # 600 x n_host
        N = np.array([[float(r[c]) for c in net_cols] for r in rows])    # 600 x n_net
        group = ("fam:" + c["family"]) if c["label"] == "malware" else ("prog:" + (c.get("program") or c.get("variant")))
        host_ts = np.array([float(r["host_total_syscalls_total"]) for r in rows])      # 600, total host syscalls/window
        net_pk = np.array([float(r["net_packets_sent"]) + float(r["net_packets_recv"]) for r in rows])
        cases.append({"sample": sample, "y": 1 if c["label"] == "malware" else 0, "group": group,
                      "label": c["label"], "family": c.get("family"), "program": c.get("program"),
                      "H": H, "N": N, "host_ts": host_ts, "net_pk": net_pk})
    return cases, host_cols, net_cols


def descriptive(cases):
    """Per class: median fraction of host syscalls and net packets occurring AFTER the 20 s mark (window 40), and the
    median last active window. This is the behaviour-growth signal independent of any detector."""
    out = {}
    for lab in ("malware", "benign"):
        grp = [c for c in cases if c["label"] == lab]
        if not grp:
            continue
        def frac_after(key):
            fr = []
            for c in grp:
                tot = c[key].sum()
                if tot > 0:
                    fr.append((c[key][40:].sum()) / tot)
            return float(np.median(fr)) if fr else 0.0
        last = [int(np.max(np.nonzero(c["host_ts"])[0])) if c["host_ts"].any() else -1 for c in grp]
        out[lab] = {"n": len(grp), "median_host_frac_after_20s": round(frac_after("host_ts"), 3),
                    "median_net_frac_after_20s": round(frac_after("net_pk"), 3),
                    "median_last_active_window": int(np.median(last))}
    return out


def agg(mat, k):
    """5-stat aggregate of each column over the first k windows -> 1 x (5*ncol)."""
    m = mat[:k]
    mean = m.mean(0); mx = m.max(0); sm = m.sum(0)
    std = m.std(0); act = (m > 0).sum(0)
    return np.concatenate([mean, mx, sm, std, act])


def grouped_cv_scores(X, y, groups, seed=42, n_splits=5):
    y = np.array(y); groups = np.array(groups)
    n_groups = len(set(groups))
    splits = min(n_splits, n_groups, int(min(np.bincount(y))))
    if splits < 2:
        return None
    oof = np.zeros(len(y))
    skf = StratifiedGroupKFold(n_splits=splits, shuffle=True, random_state=seed)
    for tr, te in skf.split(X, y, groups):
        clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=1)
        clf.fit(X[tr], y[tr])
        oof[te] = clf.predict_proba(X[te])[:, 1]
    pred = (oof >= 0.5).astype(int)
    return {"ba": balanced_accuracy_score(y, pred), "auc": roc_auc_score(y, oof),
            "tp": int(((pred == 1) & (y == 1)).sum()), "fp": int(((pred == 1) & (y == 0)).sum()),
            "tn": int(((pred == 0) & (y == 0)).sum()), "fn": int(((pred == 0) & (y == 1)).sum())}


def main():
    attempt = sys.argv[1].rstrip("/")
    cases, host_cols, net_cols = load_cases(attempt)
    y = [c["y"] for c in cases]; groups = [c["group"] for c in cases]
    nmal = sum(y); nben = len(y) - sum(y)
    print(f"accepted classifier cases: {len(cases)} ({nmal} malware / {nben} benign), "
          f"{len(set(groups))} groups")

    desc = descriptive(cases)
    print("\n=== behaviour after the 20 s mark (descriptive, median per class) ===")
    for lab, s in desc.items():
        print(f"  {lab:8} n={s['n']:3d}  host %after20s={s['median_host_frac_after_20s']*100:3.0f}%  "
              f"net %after20s={s['median_net_frac_after_20s']*100:3.0f}%  last active win={s['median_last_active_window']}/599")

    print("\n=== detector balanced accuracy / AUC vs observation length (grouped CV) ===")
    print(f"{'windows(sec)':14}{'host BA/AUC':>18}{'net BA/AUC':>18}{'hybrid BA/AUC':>18}")
    result = {"attempt": attempt, "n_malware": nmal, "n_benign": nben, "n_groups": len(set(groups)),
              "descriptive": desc, "prefixes": {}, "host_group": HOST_GROUP, "net_group": NET_GROUP}
    for k in PREFIXES:
        Hx = np.array([agg(c["H"], k) for c in cases])
        Nx = np.array([agg(c["N"], k) for c in cases])
        Xy = np.concatenate([Hx, Nx], 1)
        sh = grouped_cv_scores(Hx, y, groups)
        sn = grouped_cv_scores(Nx, y, groups)
        shy = grouped_cv_scores(Xy, y, groups)
        sec = k * 0.5
        lab = f"{k}({sec:g}s)" if sec < 60 else f"{k}({sec/60:g}m)"

        def fmt(s):
            return f"{s['ba']:.3f}/{s['auc']:.3f}" if s else "n/a"
        print(f"{lab:14}{fmt(sh):>18}{fmt(sn):>18}{fmt(shy):>18}")
        result["prefixes"][k] = {"seconds": sec, "host": sh, "network": sn, "hybrid": shy}

    out = attempt + "/prefix_analysis.json"
    json.dump(result, open(out, "w"), indent=2)
    print("\nsaved", out)


if __name__ == "__main__":
    main()
