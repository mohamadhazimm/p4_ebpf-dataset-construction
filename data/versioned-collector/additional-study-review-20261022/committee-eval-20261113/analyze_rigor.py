"""Rigor tables for committee item 2, from the caches written by compute_oof.py. Offline.

Writes results/rigor.json and results/RIGOR.md:
  A. Table IV (held-out) with both hybrids, eleven forest seeds, cluster-bootstrap CIs, McNemar tests
  B. Table V (ten fold assignments) with both hybrids, cluster-bootstrap CIs of the mean, paired differences,
     McNemar per assignment, artifact baselines (activity, return code, mode, lifetime)
  C. Per-family / per-category flag rates and which view misses which family
  D. Network attacks grouped by attack type and by implementation (Python tools held out together)
  E. Time to detection (retrained per observation length), both protocols
  F. Streaming model: any-time false alarms and detection latency

    /usr/bin/python3 analyze_rigor.py
"""
import json
from collections import defaultdict
from multiprocessing import Pool

import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

import common as C

OUT = C.HERE / "results"
NAMES = {"host": "Host-only", "network": "Network-only", "concat": "Hybrid (concatenated)",
         "stacked": "Hybrid (stacked)"}
PAIRS = [("stacked", "host"), ("concat", "host"), ("stacked", "network"), ("concat", "network"),
         ("host", "network"), ("stacked", "concat")]
PREFIX_SECONDS = {1: 0.5, 2: 1, 4: 2, 6: 3, 10: 5, 16: 8, 20: 10, 30: 15, 40: 20}
B_BA, B_AUC = 4000, 1000


def load_cv(name, k=40):
    z = np.load(C.CACHE / ("cv_%s_k%d.npz" % (name, k)))
    return {d: z[d] for d in C.DETECTORS}, z["folds"]


def r3(x):
    return None if x is None or (isinstance(x, float) and np.isnan(x)) else round(float(x), 3)


def ms(v):
    v = np.asarray(v, float)
    return {"mean": r3(v.mean()), "sd": r3(v.std(ddof=1)) if len(v) > 1 else None,
            "min": r3(v.min()), "max": r3(v.max())}


# ------------------------------------------------------------------------------------------ A. Table IV
def table_iv(rows, y, groups):
    z = np.load(C.CACHE / "heldout_k40.npz")
    te = z["te"]
    yt, gt = y[te], groups[te]
    rf_seeds = sorted({int(k.split("__rf")[1]) for k in z.files if "__rf" in k})
    res = {"n_test": int(len(te)), "test_malware": int(yt.sum()), "test_groups": int(len(set(gt)))}
    res["rf42"] = {d: C.metrics(yt, z["%s__rf42" % d]) for d in C.DETECTORS}
    res["rf_seed_robustness"] = {}
    for d in C.DETECTORS:
        bas = [C.metrics(yt, z["%s__rf%d" % (d, s)])["balanced_accuracy"] for s in rf_seeds]
        aucs = [C.metrics(yt, z["%s__rf%d" % (d, s)])["auc"] for s in rf_seeds]
        res["rf_seed_robustness"][d] = {"balanced_accuracy": ms(bas), "auc": ms(aucs), "rf_seeds": rf_seeds}
    # cluster bootstrap at rf42
    P = {d: z["%s__rf42" % d] for d in C.DETECTORS}
    pred = {d: (P[d] >= 0.5).astype(int) for d in C.DETECTORS}
    boot_ba = defaultdict(list); boot_auc = defaultdict(list)
    for i, idx in enumerate(C.cluster_bootstrap_indices(yt, gt, 10000, seed=1)):
        yy = yt[idx]
        for d in C.DETECTORS:
            boot_ba[d].append(C.ba(yy, pred[d][idx]))
            if i < 2000:
                boot_auc[d].append(roc_auc_score(yy, P[d][idx]))
    res["bootstrap_ci95"] = {d: {"balanced_accuracy": [r3(np.percentile(boot_ba[d], 2.5)), r3(np.percentile(boot_ba[d], 97.5))],
                                 "auc": [r3(np.percentile(boot_auc[d], 2.5)), r3(np.percentile(boot_auc[d], 97.5))]}
                             for d in C.DETECTORS}
    res["paired"] = {}
    for a, b in PAIRS:
        diff = np.asarray(boot_ba[a]) - np.asarray(boot_ba[b])
        res["paired"]["%s-%s" % (a, b)] = {
            "ba_diff": r3(C.ba(yt, pred[a]) - C.ba(yt, pred[b])),
            "ba_diff_ci95": [r3(np.percentile(diff, 2.5)), r3(np.percentile(diff, 97.5))],
            "p_boot_diff_gt0": r3((diff > 0).mean()),
            "mcnemar": C.mcnemar_exact(yt, pred[a], pred[b])}
    return res


# ------------------------------------------------------------------------------------------ B. Table V
def table_v(y, groups, P, label="published"):
    nseed = P["host"].shape[0]
    pred = {d: (P[d] >= 0.5).astype(int) for d in C.DETECTORS}
    per = {d: [C.metrics(y, P[d][i]) for i in range(nseed)] for d in C.DETECTORS}
    res = {"grouping": label, "per_detector": {}}
    for d in C.DETECTORS:
        res["per_detector"][d] = {m: ms([x[m] for x in per[d]]) for m in
                                  ("balanced_accuracy", "auc", "recall", "specificity", "precision", "f1")}
    # cluster bootstrap of the mean over assignments
    boot = defaultdict(list); boot_auc = defaultdict(list)
    for i, idx in enumerate(C.cluster_bootstrap_indices(y, groups, B_BA, seed=2)):
        yy = y[idx]
        for d in C.DETECTORS:
            boot[d].append(np.mean([C.ba(yy, pred[d][s][idx]) for s in range(nseed)]))
            if i < B_AUC:
                boot_auc[d].append(np.mean([roc_auc_score(yy, P[d][s][idx]) for s in range(nseed)]))
    for d in C.DETECTORS:
        res["per_detector"][d]["ba_mean_ci95"] = [r3(np.percentile(boot[d], 2.5)), r3(np.percentile(boot[d], 97.5))]
        res["per_detector"][d]["auc_mean_ci95"] = [r3(np.percentile(boot_auc[d], 2.5)), r3(np.percentile(boot_auc[d], 97.5))]
    res["paired"] = {}
    for a, b in PAIRS:
        diffs = np.asarray([per[a][s]["balanced_accuracy"] - per[b][s]["balanced_accuracy"] for s in range(nseed)])
        bd = np.asarray(boot[a]) - np.asarray(boot[b])
        mc = [C.mcnemar_exact(y, pred[a][s], pred[b][s]) for s in range(nseed)]
        res["paired"]["%s-%s" % (a, b)] = {
            "ba_diff_mean": r3(diffs.mean()), "ba_diff_sd": r3(diffs.std(ddof=1)),
            "a_better_in_assignments": int((diffs > 0).sum()), "ties": int((diffs == 0).sum()),
            "ba_diff_ci95": [r3(np.percentile(bd, 2.5)), r3(np.percentile(bd, 97.5))],
            "p_boot_diff_gt0": r3((bd > 0).mean()),
            "mcnemar_p_median": r3(np.median([m["p"] for m in mc])),
            "mcnemar_p_lt_0.05": int(sum(m["p"] < 0.05 for m in mc)),
            "mcnemar_only_a_correct": [m["only_a_correct"] for m in mc],
            "mcnemar_only_b_correct": [m["only_b_correct"] for m in mc]}
    return res


def _baseline_job(args):
    seed, X, y, groups = args
    oof = np.zeros(len(y))
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, groups):
        oof[te] = C.rf().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    return oof


def baselines_v(rows, y, groups, Xh_full, hc):
    act = np.log1p(np.asarray([[float(r["syscall_count"])] for r in rows]))
    rc = np.asarray([[float(r["return_code"])] for r in rows])
    mode = DictVectorizer(sparse=False).fit_transform([{"mode": r["mode"]} for r in rows])
    life = Xh_full[:, [hc.index("host_total_syscalls_total__active_windows")]]
    out = {}
    with Pool(10) as pool:
        for name, X in (("activity", act), ("return_code", rc), ("mode", mode), ("lifetime", life)):
            oofs = pool.map(_baseline_job, [(s, X, y, groups) for s in C.FOLD_SEEDS])
            out[name] = {"balanced_accuracy": ms([C.metrics(y, o)["balanced_accuracy"] for o in oofs]),
                         "auc": ms([C.metrics(y, o)["auc"] for o in oofs])}
    return out


# ---------------------------------------------------------------------------------- C. per-family rates
def unit_of(r):
    c = r["category"]
    if c == "malware":
        return "malware::" + r["family"]
    if c == "network_attack":
        return "attack::" + r["attack_type"]
    if c == "benign":
        return "benign::" + r["project"]
    return c + "::" + r["cv_group"]


def flag_rates(rows, y, P):
    units = np.asarray([unit_of(r) for r in rows])
    pred = {d: (P[d] >= 0.5) for d in C.DETECTORS}
    out = {}
    for u in sorted(set(units)):
        m = units == u
        out[u] = {"n": int(m.sum()), "label": int(y[m][0])}
        for d in C.DETECTORS:
            out[u][d] = r3(pred[d][:, m].mean())  # mean over assignments and members
    return out


def misses(rates):
    """For malicious units: which detectors flag them in most cases (rate >= 0.5)."""
    groups = defaultdict(list)
    for u, v in rates.items():
        if v["label"] != 1:
            continue
        h, n, c, s = (v[d] >= 0.5 for d in ("host", "network", "concat", "stacked"))
        key = ("host+network" if h and n else "host only" if h else "network only" if n else "neither view")
        key += "; stacked %s, concat %s" % ("catches" if s else "misses", "catches" if c else "misses")
        groups[key].append("%s (%d)" % (u, v["n"]))
    return dict(groups)


def per_category(rows, y, P):
    cats = np.asarray([r["category"] for r in rows])
    pred = {d: (P[d] >= 0.5) for d in C.DETECTORS}
    return {c: {d: r3(pred[d][:, cats == c].mean()) for d in C.DETECTORS} for c in sorted(set(cats))}


# ---------------------------------------------------------------------------------------- F. streaming
def streaming(rows, y):
    z = np.load(C.CACHE / "stream.npz")
    prefixes = list(z["prefixes"])
    secs = [PREFIX_SECONDS[k] for k in prefixes]
    cats = np.asarray([r["category"] for r in rows])
    out = {"prefix_seconds": secs, "detectors": {}}
    for d in C.DETECTORS:
        S = z[d]  # seeds x prefixes x rows
        res = {"at_threshold_0.5": {}, "threshold_sweep": []}
        anytime = np.maximum.accumulate(S >= 0.5, axis=1)  # flagged at or before each prefix
        for j, s in enumerate(secs):
            res["at_threshold_0.5"][str(s)] = {
                "pointwise_ba": r3(np.mean([C.ba(y, (S[i, j] >= 0.5).astype(int)) for i in range(S.shape[0])])),
                "cumulative_detection_malicious": r3(anytime[:, j, y == 1].mean()),
                "cumulative_detection_malware": r3(anytime[:, j, cats == "malware"].mean()),
                "cumulative_detection_attacks": r3(anytime[:, j, cats == "network_attack"].mean()),
                "anytime_false_alarm_benign": r3(anytime[:, j, y == 0].mean())}
        # first detection time of malicious rows at 0.5
        first = np.where(anytime[:, :, y == 1].any(1), np.argmax(anytime[:, :, y == 1], axis=1), -1)
        t = np.asarray(secs)[first[first >= 0]]
        res["median_detection_seconds_among_detected"] = r3(np.median(t)) if len(t) else None
        res["share_detected_by_2s"] = r3((t <= 2).sum() / first.size)
        for thr in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
            at = np.maximum.accumulate(S >= thr, axis=1)
            fa = at[:, -1, y == 0].mean()
            det = at[:, -1, y == 1].mean()
            fm = np.where(at[:, :, y == 1].any(1), np.argmax(at[:, :, y == 1], axis=1), -1)
            tt = np.asarray(secs)[fm[fm >= 0]]
            res["threshold_sweep"].append({"threshold": thr, "anytime_false_alarm_20s": r3(fa),
                                           "detected_by_20s": r3(det),
                                           "median_latency_s": r3(np.median(tt)) if len(tt) else None})
        out["detectors"][d] = res
    return out


# ------------------------------------------------------------------------------------------------ main
def main():
    rows, hc, nc = C.load()
    y = C.labels(rows)
    g_pub = C.groups_published(rows)
    Xh = C.matrix(rows, hc)
    R = {}
    R["A_table_iv"] = table_iv(rows, y, g_pub)
    P, F = load_cv("published", 40)
    R["B_table_v"] = table_v(y, g_pub, P)
    R["B_baselines_table_v"] = baselines_v(rows, y, g_pub, Xh, hc)
    R["C_flag_rates"] = flag_rates(rows, y, P)
    R["C_misses"] = misses(R["C_flag_rates"])
    R["C_per_category"] = per_category(rows, y, P)
    # Table IV per-family (rf42 and mean over rf seeds)
    z = np.load(C.CACHE / "heldout_k40.npz"); te = z["te"]
    rf_seeds = sorted({int(k.split("__rf")[1]) for k in z.files if "__rf" in k})
    units = np.asarray([unit_of(r) for r in rows])[te]
    t4 = {}
    for u in sorted(set(units)):
        m = units == u
        t4[u] = {"n": int(m.sum()), "label": int(y[te][m][0])}
        for d in C.DETECTORS:
            t4[u][d] = r3(np.mean([(z["%s__rf%d" % (d, s)][m] >= 0.5).mean() for s in rf_seeds]))
    R["C_table_iv_units_mean_over_rf_seeds"] = t4
    # D. attack groupings
    R["D_attack_groupings"] = {}
    for name in ("published", "attacktype", "implementation"):
        Pg, _ = load_cv(name, 40)
        gg = {"published": C.groups_published, "attacktype": C.groups_by_attack_type,
              "implementation": C.groups_by_implementation}[name](rows)
        rates = flag_rates(rows, y, Pg)
        R["D_attack_groupings"][name] = {
            "overall": {d: {m: ms([C.metrics(y, Pg[d][i])[m] for i in range(len(C.FOLD_SEEDS))])
                            for m in ("balanced_accuracy", "auc")} for d in C.DETECTORS},
            "attack_recall": {u: v for u, v in rates.items() if u.startswith("attack::")},
            "category": per_category(rows, y, Pg)}
    # E. time to detection
    R["E_time_to_detection"] = {"cv": {}, "heldout": {}}
    for k in sorted(PREFIX_SECONDS):
        p = C.CACHE / ("cv_published_k%d.npz" % k)
        if p.exists():
            Pk, _ = load_cv("published", k)
            R["E_time_to_detection"]["cv"][str(PREFIX_SECONDS[k])] = {
                d: {m: ms([C.metrics(y, Pk[d][i])[m] for i in range(len(C.FOLD_SEEDS))])
                    for m in ("balanced_accuracy", "auc")} for d in C.DETECTORS}
            R["E_time_to_detection"]["cv"][str(PREFIX_SECONDS[k])]["category"] = per_category(rows, y, Pk)
        h = C.CACHE / ("heldout_k%d.npz" % k)
        if h.exists():
            zz = np.load(h)
            R["E_time_to_detection"]["heldout"][str(PREFIX_SECONDS[k])] = {
                d: {m: r3(C.metrics(y[zz["te"]], zz["%s__rf42" % d])[m]) for m in ("balanced_accuracy", "auc")}
                for d in C.DETECTORS}
    if (C.CACHE / "stream.npz").exists():
        R["F_streaming"] = streaming(rows, y)
    C.write_json(OUT / "rigor.json", R)
    print("wrote", OUT / "rigor.json")


if __name__ == "__main__":
    main()
