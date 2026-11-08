#!/usr/bin/env python3
"""Test 1 of the LID-DS check (E2, seen attack types) repeated over 10 fold assignments.

Protocol (fixed before running; written to protocol.json first):

Same rows, models, inner folds and threshold as E2 in evaluate_lidds.py: 5-fold StratifiedKFold over the
pooled attack and normal windows, stratified by scenario and label; end-control windows follow their
recording's fold and are never trained on; inner folds of the stacking StratifiedKFold(5, seed 7);
forests of 500 trees, balanced, seed 42. Only the outer fold seed changes: 42 (the existing result,
which must be reproduced exactly) and 0-8, the fold seeds of the paper's Table V repeat.

Per assignment, on the pooled out-of-fold scores:
- balanced accuracy, recall, false alarms on normal windows, AUC, and false alarms on end-control
  windows, at threshold 0.5;
- recall at matched false-alarm rates of 0.1, 1, 2 and 5% of normal windows (the rule of the report's
  table: threshold = the k-th highest normal score, k = floor(rate * normals), recall = share of attack
  scores above it), and the gain of the hybrid and of the concatenated forest over the better single
  sensor at each rate;
- per-scenario balanced accuracy, and the number of scenarios where the hybrid is at least as good as
  the better single sensor.

Summary: mean, sample SD, min and max over the 10 assignments.

    python3 -I repeat_e2_lidds.py EVALUATION_DIR [--jobs N]
"""

import argparse
import json
import math
import site
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
if site.getusersitepackages() not in sys.path:
    sys.path.append(site.getusersitepackages())

import numpy as np  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.model_selection import StratifiedKFold  # noqa: E402

import evaluate_lidds as ev  # noqa: E402

FOLD_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
INNER_SEED = 7
FA_RATES = (0.001, 0.01, 0.02, 0.05)
SENSORS = ("host-only", "network-only")
FUSED = ("hybrid", "concatenated")


def recall_at(p, y, rate):
    neg = np.sort(p[~y])[::-1]
    k = int(np.floor(rate * len(neg)))
    thr = neg[k] if k < len(neg) else -1
    return float((p[y] > thr).mean())


def load(evaluation):
    """Rows and matrices exactly as evaluate_lidds.main builds them for this evaluation."""
    protocol = json.load(open(evaluation / "protocol.json"))
    rows, recordings = [], {}
    for prepared, digest in zip(protocol["prepared"], protocol["rows_sha256"]):
        prepared = Path(prepared)
        assert ev.sha256(prepared / "rows.json") == digest, "rows.json changed: %s" % prepared
        rows += json.load(open(prepared / "rows.json"))
        recordings.update({(r["scenario"], r["recording"]): r for r in json.load(open(prepared / "recordings.json"))})
    failed = sorted({(r["scenario"], r["recording"]) for r in rows if r.get("error")})
    rows = [r for r in rows if (r["scenario"], r["recording"]) not in set(failed)]
    _, host_cols, net_cols = ev.common.load()
    primary = [r for r in rows if r["kind"] in ("attack", "normal")]
    control = [r for r in rows if r["kind"] == "end_control"]
    allrows = primary + control
    host = np.asarray([[r[c] for c in host_cols] for r in allrows])
    net = np.asarray([[r[c] for c in net_cols] for r in allrows])
    act = np.asarray([[math.log1p(r["calls_in_window"]), math.log1p(r["frames_in_window"])] for r in allrows])
    pos = []
    for r in allrows:
        rec = recordings[(r["scenario"], r["recording"])]
        pos.append([(r["window_start_us"] - rec["start_us"]) / 1e6, (rec["end_us"] - r["window_start_us"]) / 1e6 - 10.0])
    X = (host, net, np.hstack([host, net]), act, np.asarray(pos))
    return protocol, allrows, len(primary), X


def e2_probabilities(seed, allrows, n_primary, X, y, scenario, is_control):
    """evaluate_lidds.py E2 with the outer fold seed as a parameter."""
    strata = np.asarray(["%s|%d" % (s, l) for s, l in zip(scenario[:n_primary], y[:n_primary])])
    fold_of = np.zeros(n_primary, dtype=int)
    for k, (_, te) in enumerate(StratifiedKFold(5, shuffle=True, random_state=seed).split(np.zeros(n_primary), strata)):
        fold_of[te] = k
    rec_fold = {(allrows[i]["scenario"], allrows[i]["recording"]): fold_of[i] for i in range(n_primary)}
    folds_all = np.asarray([rec_fold[(r["scenario"], r["recording"])] for r in allrows])
    probs = {m: np.full(len(allrows), np.nan) for m in ev.MODELS}
    for k in range(5):
        train = np.where((folds_all != k) & ~is_control)[0]
        test = np.where(folds_all == k)[0]

        def inner(tr):
            st = np.asarray(["%s|%d" % (s, l) for s, l in zip(scenario[tr], y[tr])])
            yield from StratifiedKFold(5, shuffle=True, random_state=INNER_SEED).split(np.zeros(len(tr)), st)
        out = ev.fit_predict(train, test, X, y, inner)
        for m in ev.MODELS:
            probs[m][test] = out[m]
    assert all(not np.isnan(p).any() for p in probs.values())
    return probs


def assignment_metrics(probs, y, scenario, is_control):
    prim = ~is_control
    yb = y[prim].astype(bool)
    out = {"pooled": {}, "recall_at_fa": {}, "gain_over_better_sensor": {}, "per_scenario_ba": {}}
    for m in ev.MODELS:
        entry = ev.score(y[prim], probs[m][prim])
        entry["end_control_false_alarm"] = float((probs[m][is_control] >= ev.THRESHOLD).mean())
        out["pooled"][m] = entry
        out["recall_at_fa"][m] = {str(r): recall_at(probs[m][prim], yb, r) for r in FA_RATES}
    for m in FUSED:
        out["gain_over_better_sensor"][m] = {
            str(r): out["recall_at_fa"][m][str(r)] - max(out["recall_at_fa"][s][str(r)] for s in SENSORS) for r in FA_RATES}
    at_least_better = 0
    for s in sorted(set(scenario)):
        sel = (scenario == s) & prim
        out["per_scenario_ba"][s] = {m: ev.score(y[sel], probs[m][sel])["balanced_accuracy"] for m in ev.MODELS}
        ba = out["per_scenario_ba"][s]
        at_least_better += ba["hybrid"] >= max(ba[x] for x in SENSORS)
    out["hybrid_at_least_better_sensor_scenarios"] = int(at_least_better)
    return out


def describe(values):
    v = np.asarray(values, dtype=float)
    return {"mean": float(v.mean()), "sd": float(v.std(ddof=1)), "min": float(v.min()), "max": float(v.max())}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("evaluation", type=Path)
    parser.add_argument("--jobs", type=int, default=12)
    args = parser.parse_args()
    evaluation = args.evaluation.resolve()
    # same forest as evaluate_lidds.forest; n_jobs does not change a seeded forest's trees
    ev.forest = lambda: RandomForestClassifier(n_estimators=500, class_weight="balanced",
                                               random_state=ev.common.SEED, n_jobs=args.jobs)

    out_dir = evaluation.parent / ("repeat-e2-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    out_dir.mkdir()
    source, allrows, n_primary, X = load(evaluation)
    protocol = {"description": __doc__, "fold_seeds": FOLD_SEEDS, "inner_seed": INNER_SEED, "fa_rates": FA_RATES,
                "threshold": ev.THRESHOLD, "models": ev.MODELS, "evaluation": str(evaluation),
                "evaluation_protocol_sha256": ev.sha256(evaluation / "protocol.json"),
                "prepared": source["prepared"], "rows_sha256": source["rows_sha256"], "rows": len(allrows),
                "code_sha256": {p.name: ev.sha256(p) for p in (HERE / "repeat_e2_lidds.py", HERE / "evaluate_lidds.py",
                                                               ev.RELEASE / "evaluation/common.py")},
                "jobs": args.jobs, "python": sys.version.split()[0], "numpy": np.__version__}
    with open(out_dir / "protocol.json", "x") as f:
        json.dump(protocol, f, indent=1)

    y = np.asarray([r["label"] for r in allrows])
    scenario = np.asarray([r["scenario"] for r in allrows])
    is_control = np.asarray([r["kind"] == "end_control" for r in allrows])
    per_seed = []
    for seed in FOLD_SEEDS:
        t0 = time.time()
        probs = e2_probabilities(seed, allrows, n_primary, X, y, scenario, is_control)
        np.savez_compressed(out_dir / ("oof_seed%d.npz" % seed), **{m: probs[m] for m in ev.MODELS})
        metrics = assignment_metrics(probs, y, scenario, is_control)
        metrics["seed"] = seed
        if seed == 42:   # must reproduce the existing E2 result
            # forests add their trees' votes in thread-completion order, so probabilities may differ in
            # the last bits between runs; decisions at the threshold must be identical
            saved = json.load(open(evaluation / "scores.json"))
            assert [(s["scenario"], s["recording"], s["kind"]) for s in saved] == \
                   [(r["scenario"], r["recording"], r["kind"]) for r in allrows]
            old = {m: np.asarray([s["E2_" + m] for s in saved]) for m in ev.MODELS}
            diff = max(float(np.max(np.abs(probs[m] - old[m]))) for m in ev.MODELS)
            decisions = all(((probs[m] >= ev.THRESHOLD) == (old[m] >= ev.THRESHOLD)).all() for m in ev.MODELS)
            earlier = json.load(open(evaluation / "results.json"))["E2_pooled_5fold"]["pooled"]
            same = all(metrics["pooled"][m][k] == earlier[m][k] for m in ev.MODELS
                       for k in ("balanced_accuracy", "recall", "false_alarm", "end_control_false_alarm")) and \
                all(abs(metrics["pooled"][m]["auc"] - earlier[m]["auc"]) < 1e-6 for m in ev.MODELS)
            metrics["reproduces_existing_e2"] = {"max_abs_probability_difference": diff,
                                                 "same_decisions": bool(decisions), "pooled_metrics_equal": bool(same)}
            print("seed 42 reproduces the existing E2:", diff, decisions, same, flush=True)
            assert diff < 1e-9 and decisions and same
        per_seed.append(metrics)
        with open(out_dir / "per_seed.jsonl", "a") as f:
            f.write(json.dumps(metrics) + "\n")
        print("seed %d done in %.0f s: BA %s" % (seed, time.time() - t0,
              {m: round(metrics["pooled"][m]["balanced_accuracy"], 4) for m in ev.MODELS}), flush=True)

    summary = {"pooled": {}, "recall_at_fa": {}, "gain_over_better_sensor": {}, "per_scenario_ba": {}}
    for m in ev.MODELS:
        summary["pooled"][m] = {k: describe([s["pooled"][m][k] for s in per_seed])
                                for k in ("balanced_accuracy", "recall", "false_alarm", "auc", "end_control_false_alarm")}
        summary["recall_at_fa"][m] = {str(r): describe([s["recall_at_fa"][m][str(r)] for s in per_seed]) for r in FA_RATES}
    for m in FUSED:
        summary["gain_over_better_sensor"][m] = {
            str(r): describe([s["gain_over_better_sensor"][m][str(r)] for s in per_seed]) for r in FA_RATES}
        summary["gain_over_better_sensor"][m + "_positive_in_assignments"] = {
            str(r): int(sum(s["gain_over_better_sensor"][m][str(r)] > 0 for s in per_seed)) for r in FA_RATES}
    for sc in sorted(set(scenario)):
        summary["per_scenario_ba"][sc] = {m: describe([s["per_scenario_ba"][sc][m] for s in per_seed]) for m in ev.MODELS}
    summary["hybrid_at_least_better_sensor_scenarios"] = describe([s["hybrid_at_least_better_sensor_scenarios"] for s in per_seed])
    result = {"protocol_sha256": ev.sha256(out_dir / "protocol.json"), "assignments": len(per_seed), "summary": summary}
    with open(out_dir / "results.json", "x") as f:
        json.dump(result, f, indent=1)
    print(json.dumps({m: summary["pooled"][m]["balanced_accuracy"] for m in ev.MODELS}, indent=1))
    print("wrote", out_dir)


if __name__ == "__main__":
    main()
