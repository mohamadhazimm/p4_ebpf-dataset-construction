#!/usr/bin/env python3
"""Host-only, network-only and hybrid detection on LID-DS 2021 rows (output of prepare_lidds.py).

Protocol (fixed before any LID-DS row was scored; written to protocol.json first):

Rows: one 10-s observation (20 windows of 0.5 s) per recording. Positives: attack recordings, window
starting 2 s before the logged attack time. Negatives: normal recordings, window placed by the same rule
around a pseudo attack time. Controls: a second window of every normal recording placed near its end the
way attack windows are; never trained on, only scored.

Models, as in the paper (evaluation/common.py, evaluation/combined.py): random forests of 500 trees with
balanced class weights and seed 42 on the 90 host columns (host-only) and on the 145 network columns
(network-only); the hybrid is a logistic regression (balanced) stacked on inner out-of-fold probabilities
of the two forests. A random forest on all 235 columns is reported as a reference. Threshold 0.5.

E1, unseen attack type (primary): leave one scenario out. Each scenario is a different service and
exploit; the inner folds of the stacking are also one scenario each.
E2, seen attack types: 5-fold cross-validation over the pooled scenarios, stratified by scenario and label.

Baselines in both: a random forest on activity alone (log of calls and frames in the window), and one on
window position alone (time from the recording's start to the window, and from the window to the end).

    python3 -I evaluate_lidds.py PREPARED_DIR [PREPARED_DIR ...] [--out DIR]
    (several prepared folders are merged; recordings whose extraction failed are left out and counted)
"""

import argparse
import hashlib
import json
import math
import site
import sys
import time
from pathlib import Path

RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(RELEASE / "evaluation"))
if site.getusersitepackages() not in sys.path:
    sys.path.append(site.getusersitepackages())

import numpy as np  # noqa: E402
import sklearn  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402
from sklearn.model_selection import StratifiedKFold  # noqa: E402

import common  # noqa: E402

HERE = Path(__file__).resolve().parent
THRESHOLD = 0.5
MODELS = ("host-only", "network-only", "hybrid", "concatenated", "activity-only", "position-only")


def forest():
    return RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=common.SEED, n_jobs=12)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fit_predict(train, test, X, y, inner_folds):
    """Probabilities on `test` for every model, trained on `train`."""
    host, net, both, act, pos = X
    out = {}
    for name, M in (("host-only", host), ("network-only", net), ("concatenated", both), ("activity-only", act),
                    ("position-only", pos)):
        out[name] = forest().fit(M[train], y[train]).predict_proba(M[test])[:, 1]
    inner_host, inner_net = np.zeros(len(train)), np.zeros(len(train))
    for fit_idx, out_idx in inner_folds(train):
        a, b = train[fit_idx], train[out_idx]
        inner_host[out_idx] = forest().fit(host[a], y[a]).predict_proba(host[b])[:, 1]
        inner_net[out_idx] = forest().fit(net[a], y[a]).predict_proba(net[b])[:, 1]
    stacker = LogisticRegression(max_iter=2000, class_weight="balanced")
    stacker.fit(np.column_stack([inner_host, inner_net]), y[train])
    out["hybrid"] = stacker.predict_proba(np.column_stack([out["host-only"], out["network-only"]]))[:, 1]
    return out


def score(y, p):
    pred = p >= THRESHOLD
    pos, neg = y == 1, y == 0
    recall = float(pred[pos].mean()) if pos.any() else None
    false_alarm = float(pred[neg].mean()) if neg.any() else None
    out = {"recall": recall, "false_alarm": false_alarm,
           "balanced_accuracy": (recall + 1 - false_alarm) / 2 if recall is not None and false_alarm is not None else None,
           "auc": float(roc_auc_score(y, p)) if pos.any() and neg.any() else None,
           "positives": int(pos.sum()), "negatives": int(neg.sum())}
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("prepared", type=Path, nargs="+")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    rows, recordings = [], {}
    for prepared in args.prepared:
        rows += json.load(open(prepared / "rows.json"))
        recordings.update({(r["scenario"], r["recording"]): r for r in json.load(open(prepared / "recordings.json"))})
    failed = sorted({(r["scenario"], r["recording"]) for r in rows if r.get("error")})
    rows = [r for r in rows if (r["scenario"], r["recording"]) not in set(failed)]
    _, host_cols, net_cols = common.load()
    assert all(c in rows[0] for c in host_cols + net_cols)

    out_dir = (args.out or args.prepared[0]) / ("evaluation-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    out_dir.mkdir(parents=True)
    protocol = {"description": __doc__, "threshold": THRESHOLD, "models": MODELS,
                "rows": len(rows), "kinds": {k: sum(r["kind"] == k for r in rows) for k in ("attack", "normal", "end_control")},
                "scenarios": sorted({r["scenario"] for r in rows}),
                "code_sha256": {p.name: sha256(p) for p in (HERE / "prepare_lidds.py", HERE / "evaluate_lidds.py",
                                                            HERE / "lidds_zip.py", RELEASE / "features/host_model.py",
                                                            RELEASE / "features/switch_model.py", RELEASE / "features/summary.py",
                                                            RELEASE / "evaluation/common.py")},
                "prepared": [str(p) for p in args.prepared],
                "rows_sha256": [sha256(p / "rows.json") for p in args.prepared],
                "recordings_left_out_extraction_failed": [list(f) for f in failed],
                "python": sys.version.split()[0], "numpy": np.__version__, "sklearn": sklearn.__version__}
    with open(out_dir / "protocol.json", "x") as f:
        json.dump(protocol, f, indent=1)

    primary = [r for r in rows if r["kind"] in ("attack", "normal")]
    control = [r for r in rows if r["kind"] == "end_control"]
    allrows = primary + control

    def matrix(rs):
        host = np.asarray([[r[c] for c in host_cols] for r in rs])
        net = np.asarray([[r[c] for c in net_cols] for r in rs])
        act = np.asarray([[math.log1p(r["calls_in_window"]), math.log1p(r["frames_in_window"])] for r in rs])
        pos = []
        for r in rs:
            rec = recordings[(r["scenario"], r["recording"])]
            pos.append([(r["window_start_us"] - rec["start_us"]) / 1e6,
                        (rec["end_us"] - r["window_start_us"]) / 1e6 - 10.0])
        return host, net, np.hstack([host, net]), act, np.asarray(pos)

    X = matrix(allrows)
    y = np.asarray([r["label"] for r in allrows])
    scenario = np.asarray([r["scenario"] for r in allrows])
    is_control = np.asarray([r["kind"] == "end_control" for r in allrows])
    n_primary = len(primary)
    result = {"protocol_sha256": sha256(out_dir / "protocol.json")}

    # E1: leave one scenario out (inner folds: one training scenario each)
    e1 = {"per_scenario": {}}
    pooled = {m: np.full(len(allrows), np.nan) for m in MODELS}
    for held in sorted(set(scenario)):
        train = np.where((scenario != held) & ~is_control)[0]
        test = np.where(scenario == held)[0]

        def inner(tr):
            for s in sorted(set(scenario[tr])):
                yield np.where(scenario[tr] != s)[0], np.where(scenario[tr] == s)[0]
        probs = fit_predict(train, test, X, y, inner)
        e1["per_scenario"][held] = {}
        for m in MODELS:
            pooled[m][test] = probs[m]
            prim = ~is_control[test]
            entry = score(y[test][prim], probs[m][prim])
            entry["end_control_false_alarm"] = float((probs[m][~prim] >= THRESHOLD).mean())
            e1["per_scenario"][held][m] = entry
        print("E1 held out %s: %s" % (held, {m: round(e1["per_scenario"][held][m]["balanced_accuracy"], 3) for m in MODELS}), flush=True)
    e1["mean_over_scenarios"] = {m: {k: float(np.mean([e1["per_scenario"][s][m][k] for s in e1["per_scenario"]]))
                                     for k in ("balanced_accuracy", "recall", "false_alarm", "auc", "end_control_false_alarm")}
                                 for m in MODELS}
    result["E1_leave_one_scenario_out"] = e1

    # E2: 5-fold stratified by scenario and label over pooled primary rows; controls follow their recording
    strata = np.asarray(["%s|%d" % (s, l) for s, l in zip(scenario[:n_primary], y[:n_primary])])
    fold_of = np.zeros(n_primary, dtype=int)
    for k, (_, te) in enumerate(StratifiedKFold(5, shuffle=True, random_state=common.SEED).split(np.zeros(n_primary), strata)):
        fold_of[te] = k
    rec_fold = {(allrows[i]["scenario"], allrows[i]["recording"]): fold_of[i] for i in range(n_primary)}
    folds_all = np.asarray([rec_fold[(r["scenario"], r["recording"])] for r in allrows])
    e2_probs = {m: np.full(len(allrows), np.nan) for m in MODELS}
    for k in range(5):
        train = np.where((folds_all != k) & ~is_control)[0]
        test = np.where(folds_all == k)[0]

        def inner(tr):
            st = np.asarray(["%s|%d" % (s, l) for s, l in zip(scenario[tr], y[tr])])
            yield from StratifiedKFold(5, shuffle=True, random_state=7).split(np.zeros(len(tr)), st)
        probs = fit_predict(train, test, X, y, inner)
        for m in MODELS:
            e2_probs[m][test] = probs[m]
        print("E2 fold %d done" % k, flush=True)
    e2 = {"pooled": {}, "per_scenario": {}}
    prim = ~is_control
    for m in MODELS:
        entry = score(y[prim], e2_probs[m][prim])
        entry["end_control_false_alarm"] = float((e2_probs[m][is_control] >= THRESHOLD).mean())
        e2["pooled"][m] = entry
    for s in sorted(set(scenario)):
        sel = (scenario == s)
        e2["per_scenario"][s] = {}
        for m in MODELS:
            entry = score(y[sel & prim], e2_probs[m][sel & prim])
            entry["end_control_false_alarm"] = float((e2_probs[m][sel & is_control] >= THRESHOLD).mean())
            e2["per_scenario"][s][m] = entry
    result["E2_pooled_5fold"] = e2

    with open(out_dir / "results.json", "x") as f:
        json.dump(result, f, indent=1)
    with open(out_dir / "scores.json", "x") as f:
        json.dump([{"scenario": r["scenario"], "recording": r["recording"], "kind": r["kind"],
                    **{"E1_" + m: float(pooled[m][i]) for m in MODELS},
                    **{"E2_" + m: float(e2_probs[m][i]) for m in MODELS}} for i, r in enumerate(allrows)], f)
    print(json.dumps({"E1_mean": e1["mean_over_scenarios"], "E2_pooled": {m: e2["pooled"][m] for m in MODELS}}, indent=1))
    print("wrote", out_dir)


if __name__ == "__main__":
    main()
