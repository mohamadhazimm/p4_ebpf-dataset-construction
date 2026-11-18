#!/usr/bin/env python3
"""Train on LID-DS 2021, test on our dataset; and train on our dataset, test on LID-DS 2021.

    /usr/bin/python3 cross_eval.py OURS_DIR OUT_DIR

Protocol (fixed before any row was scored; written to protocol.json first):

Data, both 10-s observations of 20 windows of 0.5 s with the paper's 235 columns:
  LID-DS: the 15 scenarios' rows from lidds-external (prepare_lidds.py); attack windows (label 1) and
          normal windows (label 0) of the test recordings; end-control windows only scored, never trained
          on; recordings whose extraction failed left out (as evaluate_lidds.py).
  ours:   the 240 rows of the release's dataset/features.csv cut to their first 20 windows
          (build_ours_10s.py); malicious = malware + DoS runs (label 1), benign = benign programs,
          network-active benign, null runs (label 0).
  Primary: our rows without the launch prologue (LID-DS servers are observed already running, so they
  have no launcher). Secondary: our rows as collected.
Models, as in the paper and evaluate_lidds.py: random forests of 500 trees, balanced class weights,
seed 42, on host (90), network (145) and both (235, "concatenated"); the stacked hybrid is a balanced
logistic regression on inner out-of-fold probabilities of the host and network forests (inner folds: 5,
seed 7; LID-DS stratified by scenario and label, ours grouped by cv_group). Baseline: a forest on
activity alone (log1p of the calls and of the packets in the 10 s, host_total_syscalls_total__sum and
net_pkts_total_delta__sum, the same definition on both sides).
Decisions: threshold 0.5 (primary); and thresholds set on the target's own benign rows only (2%, 5%
and 10% of them flagged), i.e. a site that records some of its own normal activity first.
References: in-domain scores of each side at 10 s (ours: grouped nested CV of evaluation/combined.py,
10 fold assignments; LID-DS: the stored E1/E2 results at the same 10 s).
Diagnostic: how well a forest tells the two datasets apart (5-fold, AUC), and medians of activity.
"""
import csv
import hashlib
import json
import math
import sys
import time
from multiprocessing import Pool
from pathlib import Path

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "evaluation"))
import numpy as np  # noqa: E402
import sklearn  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold  # noqa: E402

import combined  # noqa: E402
import common  # noqa: E402

HERE = Path(__file__).resolve().parent
LIDDS = HERE.parent / "lidds-external"
LIDDS_PREPARED = [LIDDS / "runs/20261105T213222Z/prepared", LIDDS / "runs/20261106T004530Z-batch2/prepared"]
LIDDS_RESULTS = LIDDS / "runs/20261106T004530Z-batch2/evaluation-20261106T011514Z/results.json"
THRESHOLD = 0.5
FA_TARGETS = (0.02, 0.05, 0.10)
MODELS = ("host-only", "network-only", "hybrid", "concatenated", "activity-only")
CALLS, PKTS = "host_total_syscalls_total__sum", "net_pkts_total_delta__sum"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def forest():
    return RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=common.SEED, n_jobs=12)


def load_lidds():
    rows = []
    for p in LIDDS_PREPARED:
        rows += json.load(open(p / "rows.json"))
    failed = {(r["scenario"], r["recording"]) for r in rows if r.get("error")}
    rows = [r for r in rows if (r["scenario"], r["recording"]) not in failed]
    return rows, sorted(failed)


def matrices(rows, host_cols, net_cols):
    host = np.asarray([[float(r[c]) for c in host_cols] for r in rows])
    net = np.asarray([[float(r[c]) for c in net_cols] for r in rows])
    act = np.asarray([[math.log1p(float(r[CALLS])), math.log1p(float(r[PKTS]))] for r in rows])
    return {"host": host, "net": net, "both": np.hstack([host, net]), "act": act}


def train_predict(Xtr, ytr, inner_splits, tests):
    """Probabilities on each test matrix set for every model trained once on (Xtr, ytr)."""
    outs = [{} for _ in tests]
    for name, key in (("host-only", "host"), ("network-only", "net"), ("concatenated", "both"), ("activity-only", "act")):
        model = forest().fit(Xtr[key], ytr)
        for o, Xte in zip(outs, tests):
            o[name] = model.predict_proba(Xte[key])[:, 1]
    ih, inet = np.zeros(len(ytr)), np.zeros(len(ytr))
    for a, b in inner_splits:
        ih[b] = forest().fit(Xtr["host"][a], ytr[a]).predict_proba(Xtr["host"][b])[:, 1]
        inet[b] = forest().fit(Xtr["net"][a], ytr[a]).predict_proba(Xtr["net"][b])[:, 1]
    stacker = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inet]), ytr)
    for o in outs:
        o["hybrid"] = stacker.predict_proba(np.column_stack([o["host-only"], o["network-only"]]))[:, 1]
    info = {"coef_host": float(stacker.coef_[0][0]), "coef_net": float(stacker.coef_[0][1]),
            "intercept": float(stacker.intercept_[0])}
    return outs, info


def score(y, p, thr=THRESHOLD):
    pred = p >= thr
    pos, neg = y == 1, y == 0
    rec = float(pred[pos].mean()) if pos.any() else None
    fa = float(pred[neg].mean()) if neg.any() else None
    return {"recall": rec, "false_alarm": fa,
            "balanced_accuracy": (rec + 1 - fa) / 2 if rec is not None and fa is not None else None,
            "auc": float(roc_auc_score(y, p)) if pos.any() and neg.any() else None,
            "positives": int(pos.sum()), "negatives": int(neg.sum())}


def threshold_at(p_neg, fa):
    """Smallest threshold that flags at most a fraction fa of these benign scores."""
    s = np.sort(p_neg)[::-1]
    k = int(math.floor(fa * len(s)))
    return float(np.nextafter(s[k], np.inf)) if k < len(s) else 0.0


def enrolled(y, p, groups=None):
    """Recall when the threshold is set on the target's own benign rows (pooled, or per group)."""
    out = {}
    for fa in FA_TARGETS:
        if groups is None:
            t = threshold_at(p[y == 0], fa)
            out["%g" % fa] = {"threshold": t, **score(y, p, t)}
        else:
            per = {}
            for g in sorted(set(groups)):
                s = groups == g
                t = threshold_at(p[s & (y == 0)], fa)
                per[g] = {"threshold": t, **score(y[s], p[s], t)}
            out["%g" % fa] = {"per_group": per,
                              "mean_recall": float(np.mean([v["recall"] for v in per.values()])),
                              "mean_false_alarm": float(np.mean([v["false_alarm"] for v in per.values()]))}
    return out


def ours_report(rows, y, probs):
    cats = np.asarray([r["category"] for r in rows])
    general = np.isin(cats, ["malware", "benign"])
    rep = {}
    for m in MODELS:
        p = probs[m]
        rep[m] = {"all_240": score(y, p), "malware_vs_benign_204": score(y[general], p[general]),
                  "flagged_at_0.5": {c: float((p[cats == c] >= THRESHOLD).mean()) for c in sorted(set(cats))},
                  "mean_probability": {c: float(p[cats == c].mean()) for c in sorted(set(cats))},
                  "enrolled_all_240": enrolled(y, p)}
    return rep


def lidds_report(rows, probs, prim, ctrl):
    y = np.asarray([r["label"] for r in rows])
    scen = np.asarray([r["scenario"] for r in rows])
    rep = {}
    for m in MODELS:
        p = probs[m]
        e = {"pooled": score(y[prim], p[prim]), "end_control_flagged": float((p[ctrl] >= THRESHOLD).mean()),
             "per_scenario": {}, "enrolled_pooled": enrolled(y[prim], p[prim]),
             "enrolled_per_scenario": enrolled(y[prim], p[prim], scen[prim])}
        for s in sorted(set(scen)):
            sel = prim & (scen == s)
            e["per_scenario"][s] = score(y[sel], p[sel])
        e["mean_over_scenarios"] = {k: float(np.mean([v[k] for v in e["per_scenario"].values()]))
                                    for k in ("balanced_accuracy", "recall", "false_alarm", "auc")}
        rep[m] = e
    return rep


def in_domain_ours(path):
    rows, host, net = common.load(path)
    y = common.labels(rows)
    groups = np.asarray([r["cv_group"] for r in rows])
    jobs = [(s, common.matrix(rows, host), common.matrix(rows, net), y, groups) for s in combined.FOLD_SEEDS]
    with Pool(10) as pool:
        res = pool.map(combined.run, jobs)
    return {m: {k: {"mean": float(np.mean([r[m][k] for r in res])), "sd": float(np.std([r[m][k] for r in res], ddof=1))}
                for k in ("balanced_accuracy", "auc", "recall", "specificity")}
            for m in ("host-only", "network-only", "hybrid")}


def medians(rows, label_of):
    groups = {}
    for r in rows:
        groups.setdefault(label_of(r), []).append(r)
    keys = (CALLS, PKTS, "net_flow_count_seen__max", "host_unique_syscalls_max__max", "host_entropy_max__max",
            "host_total_syscalls_total__active_windows", "net_pkts_total_delta__active_windows")
    return {g: {"n": len(rs), **{k: float(np.median([float(r[k]) for r in rs])) for k in keys}} for g, rs in groups.items()}


def main():
    ours_dir, out_root = Path(sys.argv[1]), Path(sys.argv[2])
    out = out_root / ("cross-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    out.mkdir(parents=True)
    variants = {"prologuefree": ours_dir / "features_10s_prologuefree.csv",
                "ascollected": ours_dir / "features_10s_ascollected.csv"}
    lidds, failed = load_lidds()
    _, host_cols, net_cols = common.load()
    protocol = {"description": __doc__, "threshold": THRESHOLD, "fa_targets": FA_TARGETS, "models": MODELS,
                "primary_variant": "prologuefree", "lidds_rows": len(lidds),
                "lidds_kinds": {k: sum(r["kind"] == k for r in lidds) for k in ("attack", "normal", "end_control")},
                "lidds_scenarios": sorted({r["scenario"] for r in lidds}),
                "lidds_recordings_left_out": [list(f) for f in failed],
                "inputs_sha256": {**{str(p / "rows.json"): sha256(p / "rows.json") for p in LIDDS_PREPARED},
                                  **{str(p): sha256(p) for p in variants.values()},
                                  str(LIDDS_RESULTS): sha256(LIDDS_RESULTS),
                                  str(REL / "dataset/features.csv"): sha256(REL / "dataset/features.csv")},
                "code_sha256": {"cross_eval.py": sha256(__file__), "build_ours_10s.py": sha256(HERE / "build_ours_10s.py"),
                                "common.py": sha256(REL / "evaluation/common.py"),
                                "combined.py": sha256(REL / "evaluation/combined.py")},
                "python": sys.version.split()[0], "numpy": np.__version__, "sklearn": sklearn.__version__}
    with open(out / "protocol.json", "x") as f:
        json.dump(protocol, f, indent=1)
    result = {"protocol_sha256": sha256(out / "protocol.json")}

    lid_prim = np.asarray([r["kind"] in ("attack", "normal") for r in lidds])
    lid_ctrl = ~lid_prim
    Xl = matrices(lidds, host_cols, net_cols)
    yl = np.asarray([r["label"] for r in lidds])
    tr = np.where(lid_prim)[0]
    Xl_tr = {k: v[tr] for k, v in Xl.items()}
    strata = np.asarray(["%s|%d" % (lidds[i]["scenario"], lidds[i]["label"]) for i in tr])
    inner_l = list(StratifiedKFold(5, shuffle=True, random_state=7).split(np.zeros(len(tr)), strata))

    ours = {v: list(csv.DictReader(open(p, newline=""))) for v, p in variants.items()}
    for v, rows in ours.items():
        assert [r["execution_id"] for r in rows] == [r["execution_id"] for r in ours["prologuefree"]]

    # A: train on LID-DS (all 15 scenarios), test on our 240 rows
    print("[A] training on %d LID-DS rows" % len(tr), flush=True)
    t0 = time.time()
    A = {}
    names = list(ours)
    Xos = [matrices(ours[v], host_cols, net_cols) for v in names]
    outs, info = train_predict(Xl_tr, yl[tr], inner_l, Xos)
    for v, probs in zip(names, outs):
        A[v] = {"stacker": info, **ours_report(ours[v], common.labels(ours[v]), probs)}
        A[v]["_probs"] = {m: probs[m].tolist() for m in MODELS}
        print("[A] %s: %s (%.0fs)" % (v, {m: round(A[v][m]["all_240"]["balanced_accuracy"], 3) for m in MODELS},
                                       time.time() - t0), flush=True)
    result["A_train_lidds_test_ours"] = {v: {k: x for k, x in d.items() if k != "_probs"} for v, d in A.items()}

    # B: train on our 240 rows, test on LID-DS
    B = {}
    for v, rows in ours.items():
        Xo = matrices(rows, host_cols, net_cols)
        yo = common.labels(rows)
        groups = np.asarray([r["cv_group"] for r in rows])
        inner_o = list(StratifiedGroupKFold(5, shuffle=True, random_state=7).split(np.zeros(len(yo)), yo, groups))
        (probs,), info = train_predict(Xo, yo, inner_o, [Xl])
        B[v] = {"stacker": info, **lidds_report(lidds, probs, lid_prim, lid_ctrl)}
        B[v]["_probs"] = {m: probs[m].tolist() for m in MODELS}
        print("[B] %s: %s" % (v, {m: round(B[v][m]["pooled"]["balanced_accuracy"], 3) for m in MODELS}), flush=True)
    result["B_train_ours_test_lidds"] = {v: {k: x for k, x in d.items() if k != "_probs"} for v, d in B.items()}

    # references: in-domain at 10 s
    result["reference_in_domain"] = {"ours_10s_grouped_cv_10_assignments": {v: in_domain_ours(p) for v, p in variants.items()}}
    stored = json.load(open(LIDDS_RESULTS))
    result["reference_in_domain"]["lidds_10s_stored"] = {
        "E2_seen_attack_types": {m: stored["E2_pooled_5fold"]["pooled"][m] for m in ("host-only", "network-only", "hybrid", "concatenated", "activity-only")},
        "E1_unseen_service_mean": {m: stored["E1_leave_one_scenario_out"]["mean_over_scenarios"][m]
                                   for m in ("host-only", "network-only", "hybrid", "concatenated", "activity-only")}}
    print("[ref] in-domain done", flush=True)

    # diagnostic: can a forest tell the datasets apart?
    rows_o = ours["prologuefree"]
    Xo = matrices(rows_o, host_cols, net_cols)
    dom = {}
    for key in ("host", "net", "both", "act"):
        Xd = np.vstack([Xl[key][tr], Xo[key]])
        yd = np.r_[np.zeros(len(tr)), np.ones(len(rows_o))]
        p = np.zeros(len(yd))
        for a, b in StratifiedKFold(5, shuffle=True, random_state=42).split(Xd, yd):
            p[b] = forest().fit(Xd[a], yd[a]).predict_proba(Xd[b])[:, 1]
        dom[key] = float(roc_auc_score(yd, p))
    result["dataset_origin_auc"] = dom
    result["medians"] = {"lidds": medians([lidds[i] for i in tr], lambda r: "lidds_" + r["kind"]),
                         "ours_prologuefree": medians(rows_o, lambda r: "ours_" + r["category"])}

    with open(out / "results.json", "x") as f:
        json.dump(result, f, indent=1)
    np.savez_compressed(out / "probabilities.npz",
                        **{"A_%s_%s" % (v, m): np.asarray(A[v]["_probs"][m]) for v in A for m in MODELS},
                        **{"B_%s_%s" % (v, m): np.asarray(B[v]["_probs"][m]) for v in B for m in MODELS})
    print("wrote", out)


if __name__ == "__main__":
    main()
