"""E2: unseen attack types, related-family sensitivity, five fusion rules, bootstrap uncertainty.

    /usr/bin/python3 e2_fusion_uncertainty.py [--jobs 10]

Reuses the released evaluation code (common.py) unchanged: random forests (500 trees, balanced, seed 42),
the ten fold seeds, inner seed 7, and the logistic stacker. Writes e2_results.json and prints a summary.
Before reporting anything new it reproduces the released Table IV and Table V means.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "evaluation"))
from common import labels, load, matrix, metrics, random_forest  # noqa: E402

HERE = Path(__file__).resolve().parent
FOLD_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
INNER_SEED = 7
DETECTORS = ("host", "network", "concat", "stacked", "mean")
TABLE_IV = {"network": (0.750, 28, 0, 13, 13), "host": (0.929, 24, 4, 0, 26), "hybrid": (0.926, 26, 2, 2, 24)}
TABLE_V_BA = {"host": 0.784, "network": 0.756, "stacked": 0.823}


def stacker_fit(Xh, Xn, y, groups, idx):
    ih, inn = np.zeros(len(idx)), np.zeros(len(idx))
    inner = StratifiedGroupKFold(min(5, len(set(groups[idx]))), shuffle=True, random_state=INNER_SEED)
    for a, b in inner.split(Xh[idx], y[idx], groups[idx]):
        fit, out = idx[a], idx[b]
        ih[b] = random_forest().fit(Xh[fit], y[fit]).predict_proba(Xh[out])[:, 1]
        inn[b] = random_forest().fit(Xn[fit], y[fit]).predict_proba(Xn[out])[:, 1]
    return LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inn]), y[idx])


def cv_assignment(args):
    seed, Xh, Xn, Xc, y, groups = args
    oof = {d: np.zeros(len(y)) for d in DETECTORS}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, groups):
        h = random_forest().fit(Xh[tr], y[tr]).predict_proba(Xh[te])[:, 1]
        n = random_forest().fit(Xn[tr], y[tr]).predict_proba(Xn[te])[:, 1]
        c = random_forest().fit(Xc[tr], y[tr]).predict_proba(Xc[te])[:, 1]
        s = stacker_fit(Xh, Xn, y, groups, tr).predict_proba(np.column_stack([h, n]))[:, 1]
        oof["host"][te], oof["network"][te], oof["concat"][te] = h, n, c
        oof["stacked"][te], oof["mean"][te] = s, (h + n) / 2
    return oof


def table_v(results, y):
    out = {}
    for d in DETECTORS:
        ms = [metrics(y, r[d]) for r in results]
        out[d] = {k: [float(np.mean([m[k] for m in ms])), float(np.std([m[k] for m in ms], ddof=1))]
                  for k in ("balanced_accuracy", "recall", "specificity", "precision", "f1", "auc")}
    return out


def run_cv(rows, host, network, groups, jobs):
    y = labels(rows)
    Xh, Xn, Xc = matrix(rows, host), matrix(rows, network), matrix(rows, host + network)
    with Pool(jobs) as pool:
        return pool.map(cv_assignment, [(s, Xh, Xn, Xc, y, groups) for s in FOLD_SEEDS]), y


def group_bootstrap_ba(y, probs_a, probs_b, groups, n=2000, seed=42):
    """Bootstrap BA of A, of B, and of (A-B), resampling whole groups."""
    rng = np.random.default_rng(seed)
    uniq = np.array(sorted(set(groups)))
    idx_by = {g: np.where(groups == g)[0] for g in uniq}
    a, b, d = [], [], []
    for _ in range(n):
        pick = rng.choice(uniq, len(uniq), replace=True)
        sel = np.concatenate([idx_by[g] for g in pick])
        ya = y[sel]
        if ya.min() == ya.max():
            continue
        ba_a = metrics(ya, probs_a[sel])["balanced_accuracy"]
        ba_b = metrics(ya, probs_b[sel])["balanced_accuracy"]
        a.append(ba_a); b.append(ba_b); d.append(ba_a - ba_b)
    pct = lambda v: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
    return {"a_ci": pct(a), "b_ci": pct(b), "diff_ci": pct(d), "diff_mean": float(np.mean(d))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=10)
    args = ap.parse_args()
    rows, host, network = load()
    out = {"created_utc": datetime.now(timezone.utc).isoformat()}

    # --- reproduce released Table IV (held-out split) ---
    mb = [r for r in rows if r["category"] in ("malware", "benign")]
    train = [r for r in mb if r["split"] == "train"]
    test = [r for r in mb if r["split"] == "test"]
    ytr, yte = labels(train), labels(test)
    t4 = {}
    for name, cols in (("network", network), ("host", host), ("hybrid", host + network)):
        m = metrics(yte, random_forest().fit(matrix(train, cols), ytr).predict_proba(matrix(test, cols))[:, 1])
        t4[name] = m
        ref = TABLE_IV[name]
        assert (round(m["balanced_accuracy"], 3), m["tn"], m["fp"], m["fn"], m["tp"]) == ref, (name, m)
    out["table4_reproduced"] = {k: {kk: v[kk] for kk in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")} for k, v in t4.items()}

    # --- E2b + default Table V (per-run attack groups) with five detectors ---
    groups_run = np.array([r["cv_group"] for r in rows])
    res_run, y = run_cv(rows, host, network, groups_run, args.jobs)
    out["E2b_five_detectors_tableV"] = table_v(res_run, y)
    for d, ref in TABLE_V_BA.items():
        assert abs(out["E2b_five_detectors_tableV"][d]["balanced_accuracy"][0] - ref) < 0.0005, (d, out["E2b_five_detectors_tableV"][d])

    # --- E2a: attacks grouped by type ---
    groups_type = np.array([("attack::" + r["attack_type"]) if r["category"] == "network_attack" else r["cv_group"] for r in rows])
    res_type, _ = run_cv(rows, host, network, groups_type, args.jobs)
    out["E2a_attack_type_grouped_tableV"] = table_v(res_type, y)
    # recall per attack type (mean over assignments), stacked and network
    at_idx = {}
    for t in ("syn_flood", "udp_flood", "slowloris", "goldeneye"):
        at_idx[t] = [i for i, r in enumerate(rows) if r["attack_type"] == t]
    out["E2a_attack_recall"] = {}
    for t, idx in at_idx.items():
        idx = np.array(idx)
        out["E2a_attack_recall"][t] = {"runs": len(idx)}
        for d in DETECTORS:
            correct = sum(int((r[d][i] >= 0.5)) for r in res_type for i in idx)  # all are malicious (label 1)
            out["E2a_attack_recall"][t][d] = "%d/%d" % (correct, len(idx) * len(res_type))

    # --- E2c: related-family sensitivity ---
    remap = {"Tsunami": "malware_signature::Kaiten", "RapperBot": "malware_signature::Mirai"}
    groups_lin = np.array([remap.get(r["family"], r["cv_group"]) for r in rows])
    res_lin, _ = run_cv(rows, host, network, groups_lin, args.jobs)
    out["E2c_lineage_merged_tableV"] = table_v(res_lin, y)
    # Table IV without Tsunami/RapperBot test samples
    test_nolin = [r for r in test if r["family"] not in ("Tsunami", "RapperBot")]
    yte2 = labels(test_nolin)
    out["E2c_table4_without_lineage_test"] = {"test_malware": int(yte2.sum()), "test_benign": int(len(yte2) - yte2.sum())}
    for name, cols in (("network", network), ("host", host), ("hybrid", host + network)):
        m = metrics(yte2, random_forest().fit(matrix(train, cols), ytr).predict_proba(matrix(test_nolin, cols))[:, 1])
        out["E2c_table4_without_lineage_test"][name] = {k: m[k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")}

    # --- E2d: bootstrap uncertainty ---
    # Table IV: resample test groups; hybrid vs host
    ph = random_forest().fit(matrix(train, host), ytr).predict_proba(matrix(test, host))[:, 1]
    phy = random_forest().fit(matrix(train, host + network), ytr).predict_proba(matrix(test, host + network))[:, 1]
    g_test = np.array([r["cv_group"] for r in test])
    out["E2d_table4_bootstrap_hybrid_vs_host"] = group_bootstrap_ba(yte, phy, ph, g_test)
    # Table V: mean OOF over assignments, stacked vs host
    mean_stacked = np.mean([r["stacked"] for r in res_run], axis=0)
    mean_host = np.mean([r["host"] for r in res_run], axis=0)
    out["E2d_tableV_bootstrap_stacked_vs_host"] = group_bootstrap_ba(y, mean_stacked, mean_host, groups_run)

    (HERE / "e2_results.json").write_text(json.dumps(out, indent=1, default=float) + "\n")
    # summary
    print("Table IV reproduced:", {k: round(v["balanced_accuracy"], 3) for k, v in out["table4_reproduced"].items()})
    print("\nE2b five detectors (Table V BA mean+/-sd):")
    for d in DETECTORS:
        c = out["E2b_five_detectors_tableV"][d]["balanced_accuracy"]
        print("  %-9s %.3f +/- %.3f" % (d, c[0], c[1]))
    print("\nE2a attacks grouped by type (Table V BA):")
    for d in DETECTORS:
        c = out["E2a_attack_type_grouped_tableV"][d]["balanced_accuracy"]
        print("  %-9s %.3f +/- %.3f" % (d, c[0], c[1]))
    print("  recall by attack type (stacked / network):")
    for t, v in out["E2a_attack_recall"].items():
        print("    %-10s stacked %s  network %s" % (t, v["stacked"], v["network"]))
    print("\nE2c lineage merged (Table V BA): stacked %.3f, host %.3f" % (
        out["E2c_lineage_merged_tableV"]["stacked"]["balanced_accuracy"][0],
        out["E2c_lineage_merged_tableV"]["host"]["balanced_accuracy"][0]))
    lv = out["E2c_table4_without_lineage_test"]
    print("  Table IV without Tsunami/RapperBot test (%d mal/%d ben): host %.3f, hybrid %.3f" % (
        lv["test_malware"], lv["test_benign"], lv["host"]["balanced_accuracy"], lv["hybrid"]["balanced_accuracy"]))
    print("\nE2d bootstrap 95%% CI:")
    b4 = out["E2d_table4_bootstrap_hybrid_vs_host"]
    print("  Table IV hybrid %.2f-%.2f, host %.2f-%.2f, hybrid-host diff %.3f [%.3f, %.3f]" % (
        *b4["a_ci"], *b4["b_ci"], b4["diff_mean"], *b4["diff_ci"]))
    bv = out["E2d_tableV_bootstrap_stacked_vs_host"]
    print("  Table V stacked %.2f-%.2f, host %.2f-%.2f, stacked-host diff %.3f [%.3f, %.3f]" % (
        *bv["a_ci"], *bv["b_ci"], bv["diff_mean"], *bv["diff_ci"]))
    print("\nwritten", HERE / "e2_results.json")


if __name__ == "__main__":
    main()
