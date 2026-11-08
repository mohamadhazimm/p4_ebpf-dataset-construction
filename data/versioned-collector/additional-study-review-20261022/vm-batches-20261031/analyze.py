"""Analyses P1, P2, B1 and B2 of PROTOCOL.md.

    /usr/bin/python3 analyze.py [--python <attempt>] [--background <attempt>] [--jobs 10]

Uses the release's data and models unchanged (evaluation/common.py: random forests with 500 trees,
balanced class weights, seed 42; Table V's fold seeds and stacker). Before scoring new runs it checks
that the same code reproduces Table IV and the Table V means of the paper. Writes results/<stamp>.json.
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
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
DETECTORS = ("host-only", "network-only", "hybrid")
TABLE_IV = {"network-only": (0.750, 28, 0, 13, 13), "host-only": (0.929, 24, 4, 0, 26), "hybrid": (0.926, 26, 2, 2, 24)}
TABLE_V_BA = {"host-only": 0.784, "network-only": 0.756, "hybrid": 0.823}


def stacker_fit(X_host, X_net, y, groups, idx):
    """Logistic regression on inner out-of-fold probabilities of the training indices idx (Table V)."""
    inner_host, inner_net = np.zeros(len(idx)), np.zeros(len(idx))
    inner = StratifiedGroupKFold(min(5, len(set(groups[idx]))), shuffle=True, random_state=INNER_SEED)
    for itr, ite in inner.split(X_host[idx], y[idx], groups[idx]):
        fit_idx, out_idx = idx[itr], idx[ite]
        inner_host[ite] = random_forest().fit(X_host[fit_idx], y[fit_idx]).predict_proba(X_host[out_idx])[:, 1]
        inner_net[ite] = random_forest().fit(X_net[fit_idx], y[fit_idx]).predict_proba(X_net[out_idx])[:, 1]
    return LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([inner_host, inner_net]), y[idx])


def cv_assignment(args):
    """One Table V fold assignment. Returns out-of-fold probabilities of the pool and, for every pool
    run that has a twin (index into twin matrices), the twin's probabilities from the same fold's models."""
    seed, X_host, X_net, y, groups, twin_of, T_host, T_net = args
    oof = {d: np.zeros(len(y)) for d in DETECTORS}
    twin = {d: np.full(len(T_host), np.nan) for d in DETECTORS}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X_host, y, groups):
        host = random_forest().fit(X_host[tr], y[tr])
        net = random_forest().fit(X_net[tr], y[tr])
        stack = stacker_fit(X_host, X_net, y, groups, tr)
        oof["host-only"][te] = host.predict_proba(X_host[te])[:, 1]
        oof["network-only"][te] = net.predict_proba(X_net[te])[:, 1]
        oof["hybrid"][te] = stack.predict_proba(np.column_stack([oof["host-only"][te], oof["network-only"][te]]))[:, 1]
        tw = [(i, twin_of[i]) for i in te if i in twin_of]
        if tw:
            pool_idx, t_idx = zip(*tw)
            t_idx = np.asarray(t_idx)
            ph = host.predict_proba(T_host[t_idx])[:, 1]
            pn = net.predict_proba(T_net[t_idx])[:, 1]
            twin["host-only"][t_idx] = ph
            twin["network-only"][t_idx] = pn
            twin["hybrid"][t_idx] = stack.predict_proba(np.column_stack([ph, pn]))[:, 1]
    return {"oof": oof, "twin": twin}


def read_batch(attempt):
    with open(Path(attempt) / "features.csv", newline="") as f:
        return list(csv.DictReader(f))


def table_v_summary(results, y):
    out = {}
    for d in DETECTORS:
        ms = [metrics(y, r["oof"][d]) for r in results]
        out[d] = {k: [float(np.mean([m[k] for m in ms])), float(np.std([m[k] for m in ms], ddof=1))]
                  for k in ("balanced_accuracy", "recall", "specificity", "precision", "f1")}
    return out


def correct_counts(results, key, y, index_sets):
    """Correct decisions per detector and subset, summed over assignments; also per-run counts."""
    out = {}
    for name, idx in index_sets.items():
        idx = np.asarray(idx, dtype=int)
        out[name] = {"runs": int(len(idx)), "predictions": int(len(idx) * len(results))}
        for d in DETECTORS:
            per_run = sum(((r[key][d][idx] >= 0.5).astype(int) == y[idx]).astype(int) for r in results)
            out[name][d] = int(per_run.sum())
    return out


def analysis_python(rows, host, network, py_rows, jobs):
    y = labels(rows)
    groups = np.asarray([r["cv_group"] for r in rows])
    X_host, X_net = matrix(rows, host), matrix(rows, network)
    P_host, P_net = matrix(py_rows, host), matrix(py_rows, network)
    # P1: models fitted on all 240 executions
    h = random_forest().fit(X_host, y).predict_proba(P_host)[:, 1]
    n = random_forest().fit(X_net, y).predict_proba(P_net)[:, 1]
    s = stacker_fit(X_host, X_net, y, groups, np.arange(len(y))).predict_proba(np.column_stack([h, n]))[:, 1]
    probs = {"host-only": h, "network-only": n, "hybrid": s}
    p1 = {"runs": [{"sample": r["sample"], "network_workload": r["network_workload"],
                    **{d: round(float(probs[d][i]), 4) for d in DETECTORS}} for i, r in enumerate(py_rows)]}
    for part, sel in (("all", [True] * len(py_rows)), ("network", [r["network_workload"] == "True" for r in py_rows]),
                      ("local", [r["network_workload"] != "True" for r in py_rows])):
        sel = np.asarray(sel)
        p1[part] = {d: {"n": int(sel.sum()), "flagged": int((probs[d][sel] >= 0.5).sum()),
                        "mean_probability": float(probs[d][sel].mean())} for d in DETECTORS}
    # P2: Table V cross-validation with and without the Python runs
    ext = rows + [{**r, "label": "0"} for r in py_rows]
    y2 = labels(ext)
    g2 = np.asarray([r["cv_group"] for r in ext])
    X2_host, X2_net = matrix(ext, host), matrix(ext, network)
    empty = np.zeros((0, X_host.shape[1])), np.zeros((0, X_net.shape[1]))
    with Pool(jobs) as pool:
        base = pool.map(cv_assignment, [(sd, X_host, X_net, y, groups, {}, *empty) for sd in FOLD_SEEDS])
        added = pool.map(cv_assignment, [(sd, X2_host, X2_net, y2, g2, {}, *empty) for sd in FOLD_SEEDS])
    def subsets(rs):
        return {"slowloris": [i for i, r in enumerate(rs) if r.get("attack_type") == "slowloris"],
                "goldeneye": [i for i, r in enumerate(rs) if r.get("attack_type") == "goldeneye"],
                "python_benign": [i for i, r in enumerate(rs) if r.get("batch") == "python"]}
    p2 = {"without_python": {"table_v": table_v_summary(base, y), "subsets": correct_counts(base, "oof", y, subsets(rows))},
          "with_python": {"table_v": table_v_summary(added, y2), "subsets": correct_counts(added, "oof", y2, subsets(ext))}}
    return {"P1": p1, "P2": p2}, base


def analysis_background(rows, host, network, bg_rows, jobs, base=None):
    by_id = {r["execution_id"]: i for i, r in enumerate(bg_rows)}
    T_host, T_net = matrix(bg_rows, host), matrix(bg_rows, network)
    # B1: Table IV setting
    mb = [r for r in rows if r["category"] in ("malware", "benign")]
    train = [r for r in mb if r["split"] == "train"]
    test = [r for r in mb if r["split"] == "test"]
    y_train, y_test = labels(train), labels(test)
    paired = [i for i, r in enumerate(test) if r["execution_id"] in by_id]
    twin_rows = [bg_rows[by_id[test[i]["execution_id"]]] for i in paired]
    cols = {"network-only": network, "host-only": host, "hybrid": host + network}
    b1 = {"paired_runs": len(paired), "unpaired": [test[i]["execution_id"] for i in range(len(test)) if i not in paired]}
    for d, c in cols.items():
        model = random_forest().fit(matrix(train, c), y_train)
        p_orig = model.predict_proba(matrix(test, c))[:, 1]
        m = metrics(y_test, p_orig)
        ref = TABLE_IV[d]
        assert (round(m["balanced_accuracy"], 3), m["tn"], m["fp"], m["fn"], m["tp"]) == ref, (d, m)
        p_twin = model.predict_proba(matrix(twin_rows, c))[:, 1] if twin_rows else np.zeros(0)
        y_p = y_test[paired]
        changed = [test[paired[k]]["execution_id"] for k in range(len(paired))
                   if (p_orig[paired[k]] >= 0.5) != (p_twin[k] >= 0.5)]
        b1[d] = {"original_all54": m, "original_paired": metrics(y_p, p_orig[paired]),
                 "background_paired": metrics(y_p, p_twin), "decisions_changed": changed}
    # B2: Table V setting
    y = labels(rows)
    groups = np.asarray([r["cv_group"] for r in rows])
    X_host, X_net = matrix(rows, host), matrix(rows, network)
    twin_of = {i: by_id[r["execution_id"]] for i, r in enumerate(rows) if r["execution_id"] in by_id}
    with Pool(jobs) as pool:
        res = pool.map(cv_assignment, [(sd, X_host, X_net, y, groups, twin_of, T_host, T_net) for sd in FOLD_SEEDS])
    classes = defaultdict(list)
    for i in twin_of:
        classes[rows[i]["category"]].append(i)
    b2 = {"table_v_check": table_v_summary(res, y)}
    for cat, idx in sorted(classes.items()):
        entry = {"runs": len(idx), "predictions": len(idx) * len(res)}
        for d in DETECTORS:
            orig = sum(int((r["oof"][d][i] >= 0.5) == y[i]) for r in res for i in idx)
            tw = sum(int((r["twin"][d][twin_of[i]] >= 0.5) == y[i]) for r in res for i in idx)
            flips = sum(1 for i in idx if any((r["oof"][d][i] >= 0.5) != (r["twin"][d][twin_of[i]] >= 0.5) for r in res))
            entry[d] = {"original_correct": orig, "background_correct": tw, "runs_changed_in_any_assignment": flips}
        b2[cat] = entry
    return {"B1": b1, "B2": b2}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--python")
    parser.add_argument("--background")
    parser.add_argument("--jobs", type=int, default=10)
    parser.add_argument("--quick", action="store_true", help="plumbing test: one fold assignment, no Table V check")
    args = parser.parse_args()
    if args.quick:
        FOLD_SEEDS[:] = FOLD_SEEDS[:1]
    rows, host, network = load()
    out = {"created_utc": datetime.now(timezone.utc).isoformat(), "python_attempt": args.python,
           "background_attempt": args.background}
    if args.python:
        res, base = analysis_python(rows, host, network, read_batch(args.python), args.jobs)
        for d, ref in TABLE_V_BA.items():
            got = res["P2"]["without_python"]["table_v"][d]["balanced_accuracy"][0]
            assert args.quick or abs(got - ref) < 0.0005, ("Table V not reproduced", d, got)
        out.update(res)
    if args.background:
        res = analysis_background(rows, host, network, read_batch(args.background), args.jobs)
        for d, ref in TABLE_V_BA.items():
            got = res["B2"]["table_v_check"][d]["balanced_accuracy"][0]
            assert args.quick or abs(got - ref) < 0.0005, ("Table V not reproduced", d, got)
        out.update(res)
    results_dir = HERE / ("results-quick" if args.quick else "results")
    results_dir.mkdir(exist_ok=True)
    path = results_dir / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    path.write_text(json.dumps(out, indent=1, default=float) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k in ("P1", "B1")}, indent=1, default=float)[:6000])
    print("written", path)


if __name__ == "__main__":
    main()
