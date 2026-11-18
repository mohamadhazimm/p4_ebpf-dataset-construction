"""LID-DS fusion gain with and without the scenarios that carry the unanswered-connection cue. Offline, no fitting.

cue/lidds_cue_check.py found that the rule "flag a window with an unanswered flow" separates attack from normal
windows in two of the 15 scenarios (CVE-2020-23839: balanced accuracy 0.909, AUC 0.994; CWE-89-SQL-injection:
0.714, AUC 1.000) and is near chance in the others. This script reuses the saved out-of-fold scores of the
10 fold assignments of the LID-DS E2 repeat (repeat-e2-20261106T080251Z/oof_seed*.npz; no model is refitted) and
recomputes, on the same rule as that repeat (recall at 0.1/1/2/5% false alarms on normal windows, gain of the
hybrid and the concatenated forest over the better single sensor), for:
  all      : the 15 scenarios (must reproduce the repeat's saved summary),
  drop2    : without CVE-2020-23839 and CWE-89-SQL-injection,
  drop4    : also without the two weaker cases (rule balanced accuracy >= 0.6 or AUC of the count >= 0.6:
             CVE-2017-12635_6 and Juice-Shop).
The scenario sets were chosen after seeing lidds_cue_check.json, so this is a sensitivity check.

    nice -n 19 /usr/bin/python3 cue/lidds_gain_without_cue.py
"""
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
LIDDS = EVAL.parent / "lidds-external"
sys.path.insert(0, str(LIDDS))
import repeat_e2_lidds as rep  # noqa: E402
import evaluate_lidds as ev  # noqa: E402

EVALUATION = LIDDS / "runs" / "20261106T004530Z-batch2" / "evaluation-20261106T011514Z"
REPEAT = LIDDS / "runs" / "20261106T004530Z-batch2" / "repeat-e2-20261106T080251Z"
OUT = EVAL / "results" / "lidds_gain_without_cue.json"
SETS = {"all": [],
        "drop2": ["CVE-2020-23839.zip", "CWE-89-SQL-injection.zip"],
        "drop4": ["CVE-2020-23839.zip", "CWE-89-SQL-injection.zip", "CVE-2017-12635_6.zip", "Juice-Shop.zip"]}


def subset_metrics(probs, y, scenario, is_control, keep):
    prim = (~is_control) & keep
    yb = y[prim].astype(bool)
    rec = {m: {str(r): rep.recall_at(probs[m][prim], yb, r) for r in rep.FA_RATES} for m in ev.MODELS}
    gain = {m: {str(r): rec[m][str(r)] - max(rec[s][str(r)] for s in rep.SENSORS) for r in rep.FA_RATES}
            for m in rep.FUSED}
    better = {str(r): max(rep.SENSORS, key=lambda s: rec[s][str(r)]) for r in rep.FA_RATES}
    ba = {m: ev.score(y[prim], probs[m][prim])["balanced_accuracy"] for m in ev.MODELS}
    return {"recall_at_fa": rec, "gain_over_better_sensor": gain, "better_sensor": better, "pooled_ba": ba,
            "attack_windows": int(yb.sum()), "normal_windows": int((~yb).sum())}


def main():
    protocol, allrows, n_primary, X = rep.load(EVALUATION)
    y = np.asarray([r["label"] for r in allrows])
    scenario = np.asarray([r["scenario"] for r in allrows])
    is_control = np.asarray([r["kind"] == "end_control" for r in allrows])
    saved = json.load(open(REPEAT / "results.json"))
    per_seed = [json.loads(line) for line in open(REPEAT / "per_seed.jsonl")]
    out = {"sets": SETS, "per_set": {}}
    for name, drop in SETS.items():
        keep = ~np.isin(scenario, drop)
        runs = []
        for seed in rep.FOLD_SEEDS:
            z = np.load(REPEAT / ("oof_seed%d.npz" % seed))
            probs = {m: z[m] for m in ev.MODELS}
            m = subset_metrics(probs, y, scenario, is_control, keep)
            if name == "all":   # same numbers as the saved repeat
                s = next(x for x in per_seed if x["seed"] == seed)
                for mm in rep.FUSED:
                    for r in rep.FA_RATES:
                        assert abs(m["gain_over_better_sensor"][mm][str(r)] - s["gain_over_better_sensor"][mm][str(r)]) < 1e-12
                for mm in ev.MODELS:
                    assert abs(m["pooled_ba"][mm] - s["pooled"][mm]["balanced_accuracy"]) < 1e-12
            m["seed"] = seed
            runs.append(m)
        summ = {"attack_windows": runs[0]["attack_windows"], "normal_windows": runs[0]["normal_windows"],
                "pooled_ba": {mm: rep.describe([x["pooled_ba"][mm] for x in runs]) for mm in ev.MODELS},
                "recall_at_fa": {mm: {str(r): rep.describe([x["recall_at_fa"][mm][str(r)] for x in runs])
                                      for r in rep.FA_RATES} for mm in ev.MODELS},
                "gain_over_better_sensor": {mm: {str(r): rep.describe([x["gain_over_better_sensor"][mm][str(r)]
                                                                       for x in runs]) for r in rep.FA_RATES}
                                            for mm in rep.FUSED},
                "gain_positive_in_assignments": {mm: {str(r): int(sum(x["gain_over_better_sensor"][mm][str(r)] > 0
                                                                     for x in runs)) for r in rep.FA_RATES}
                                                 for mm in rep.FUSED},
                "better_sensor_by_rate": {str(r): sorted({x["better_sensor"][str(r)] for x in runs})
                                          for r in rep.FA_RATES}}
        out["per_set"][name] = summ
    out["inputs"] = {"evaluation_protocol_sha256": ev.sha256(EVALUATION / "protocol.json"),
                     "repeat_results_sha256": ev.sha256(REPEAT / "results.json"),
                     "oof_sha256": {s: ev.sha256(REPEAT / ("oof_seed%d.npz" % s)) for s in rep.FOLD_SEEDS},
                     "cue_check_sha256": ev.sha256(EVAL / "results" / "lidds_cue_check.json")}
    OUT.write_text(json.dumps(out, indent=1) + "\n")
    assert abs(out["per_set"]["all"]["gain_over_better_sensor"]["hybrid"]["0.02"]["mean"]
               - saved["summary"]["gain_over_better_sensor"]["hybrid"]["0.02"]["mean"]) < 1e-12
    for name, s in out["per_set"].items():
        print("%-6s attack %4d normal %5d | BA host %.3f net %.3f hyb %.3f concat %.3f" % (
            name, s["attack_windows"], s["normal_windows"], *(s["pooled_ba"][m]["mean"] for m in
                                                              ("host-only", "network-only", "hybrid", "concatenated"))))
        for mm in rep.FUSED:
            print("        %-12s gain over better sensor at FA 0.1/1/2/5%%: %s  positive %s  (better sensor %s)" % (
                mm, " ".join("%+.3f" % s["gain_over_better_sensor"][mm][str(r)]["mean"] for r in rep.FA_RATES),
                [s["gain_positive_in_assignments"][mm][str(r)] for r in rep.FA_RATES],
                [s["better_sensor_by_rate"][str(r)] for r in rep.FA_RATES]))
        print("        recall at 2%% FA: host %.3f net %.3f hyb %.3f concat %.3f" % tuple(
            s["recall_at_fa"][m]["0.02"]["mean"] for m in ("host-only", "network-only", "hybrid", "concatenated")))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
