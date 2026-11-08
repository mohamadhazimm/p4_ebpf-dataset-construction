#!/usr/bin/env python3
"""Write the LID-DS 2021 results for the thesis (data/lab/lidds2021.json) from the saved run artifacts.

Reads, never refits: the first-batch and the all-scenario evaluations (results.json, scores.json,
protocol.json), the extracted rows and recordings of both batches, and the ten-fold-assignment repeat
(repeat_e2_lidds.py). Recomputes from the saved out-of-fold scores, with the rules of the report: recall
at matched false-alarm rates (Test 1, seed 42) and the per-service threshold diagnostic (Test 2), and
checks them against the values already reported.

    python3 -I export_lidds_thesis_json.py REPEAT_DIR OUT.json
"""

import hashlib
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

import site
sys.path.append(site.getusersitepackages())
import numpy as np  # noqa: E402

HERE = Path(__file__).resolve().parent
FIRST = HERE / "runs/20261105T213222Z"
SECOND = HERE / "runs/20261106T004530Z-batch2"
EVALUATION = SECOND / "evaluation-20261106T011514Z"
FIRST_EVALUATION = FIRST / "prepared/evaluation-20261105T213514Z"
MODELS = ("host-only", "network-only", "hybrid", "concatenated", "activity-only", "position-only")
CORE = ("host-only", "network-only", "hybrid", "concatenated")
NAMES = {"Bruteforce_CWE-307": "Password brute force", "CVE-2012-2122": "MySQL authentication bypass",
         "CVE-2014-0160": "Heartbleed", "CVE-2017-12635_6": "CouchDB privilege escalation and RCE",
         "CVE-2017-7529": "nginx range-filter overflow", "CVE-2018-3760": "Sprockets path traversal",
         "CVE-2019-5418": "Rails file disclosure", "CVE-2020-13942": "Apache Unomi RCE",
         "CVE-2020-23839": "CVE-2020-23839", "CVE-2020-9484": "Tomcat session deserialization",
         "CWE-89-SQL-injection": "SQL injection", "EPS_CWE-434": "EPS file upload", "Juice-Shop": "OWASP Juice Shop",
         "PHP_CWE-434": "PHP web shell upload", "ZipSlip": "ZipSlip archive path traversal"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def recall_at(p, y, rate):
    neg = np.sort(p[~y])[::-1]
    k = int(np.floor(rate * len(neg)))
    thr = neg[k] if k < len(neg) else -1
    return float((p[y] > thr).mean())


def scenario_key(name):
    return next(k for k in NAMES if name.startswith(k) or k in name)


def main():
    repeat, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
    protocol = json.load(open(EVALUATION / "protocol.json"))
    results = json.load(open(EVALUATION / "results.json"))
    scores = json.load(open(EVALUATION / "scores.json"))
    first = json.load(open(FIRST_EVALUATION / "results.json"))
    rep_protocol = json.load(open(repeat / "protocol.json"))
    rep = json.load(open(repeat / "results.json"))
    per_seed = [json.loads(line) for line in open(repeat / "per_seed.jsonl")]
    assert rep_protocol["evaluation_protocol_sha256"] == sha256(EVALUATION / "protocol.json")
    assert per_seed[0]["seed"] == 42 and per_seed[0]["reproduces_existing_e2"]["same_decisions"]

    # data description
    recs, rows = [], []
    for prepared in (FIRST / "prepared", SECOND / "prepared"):
        recs += json.load(open(prepared / "recordings.json"))
        rows += json.load(open(prepared / "rows.json"))
    scenarios = {}
    for s in sorted({r["scenario"] for r in recs}):
        rs = [r for r in recs if r["scenario"] == s]
        ws = [r for r in rows if r["scenario"] == s]
        scenarios[s] = {"name": NAMES[scenario_key(s)], "recordings": len(rs),
                        "attack_windows": sum(r["kind"] == "attack" for r in ws),
                        "normal_windows": sum(r["kind"] == "normal" for r in ws),
                        "end_control_windows": sum(r["kind"] == "end_control" for r in ws),
                        "skipped_shorter_than_window": sum(r.get("skipped") == "shorter than the window" for r in rs),
                        "skipped_attack_recordings": sum(bool(r.get("skipped")) and r["exploit"] for r in rs)}
    folders = Counter(r["folder"].split("/", 1)[-1] for r in recs)
    usable = sorted((r["end_us"] - r["start_us"]) / 1e6 for r in recs if not r.get("skipped"))
    offsets = sorted((r["attack_us"] - r["start_us"]) / 1e6 for r in recs if r["exploit"] and r["attack_us"] and not r.get("skipped"))
    windows = defaultdict(lambda: defaultdict(list))
    for r in rows:
        windows[r["kind"]]["calls"].append(r["calls_in_window"])
        windows[r["kind"]]["frames"].append(r["frames_in_window"])
    seen, dropped = set(), Counter()
    for r in rows:
        if (r["scenario"], r["recording"]) not in seen:
            seen.add((r["scenario"], r["recording"]))
            dropped.update({k: v for k, v in (r.get("dropped_names") or {}).items() if k != "_resorted"})

    def pct(values, q):
        return sorted(values)[int(q * len(values))]

    # Test 1, seed 42: matched false alarms from the saved out-of-fold scores
    prim = [s for s in scores if s["kind"] in ("attack", "normal")]
    y = np.array([s["kind"] == "attack" for s in prim])
    matched = {m: {str(r): recall_at(np.array([s["E2_" + m] for s in prim]), y, r) for r in (0.001, 0.01, 0.02, 0.05)}
               for m in CORE}
    for m, v in zip(CORE, (84.4, 89.5, 94.3, 94.5)):    # the values in the report's table
        assert round(100 * matched[m]["0.02"], 1) == v, (m, matched[m]["0.02"])
    gains = {m: {r: matched[m][r] - max(matched["host-only"][r], matched["network-only"][r]) for r in matched[m]}
             for m in ("hybrid", "concatenated")}

    # Test 2: per-service threshold diagnostic (threshold on the held-out service's own normal windows)
    diagnostic = {}
    for rate in (0.02, 0.05):
        values = {m: [] for m in CORE}
        for sc in sorted({s["scenario"] for s in prim}):
            sel = np.array([s["scenario"] == sc for s in prim])
            for m in CORE:
                values[m].append(recall_at(np.array([s["E1_" + m] for s in prim])[sel], y[sel], rate))
        diagnostic[str(rate)] = {m: float(np.mean(v)) for m, v in values.items()}
    for m, v in zip(CORE, (36.9, 34.4, 32.2, 37.4)):
        assert round(100 * diagnostic["0.02"][m], 1) == v, (m, diagnostic["0.02"][m])

    def short(entry):
        return {k: entry[k] for k in ("balanced_accuracy", "recall", "false_alarm", "end_control_false_alarm", "auc")}

    result = {
        "description": ("LID-DS 2021 external check (2026-11-05/06): the thesis's 90 host and 145 network columns rebuilt from "
                        "LID-DS 2021 with features/host_model.py and features/switch_model.py (unchanged), one 10-s "
                        "observation (20 windows of 0.5 s) per recording, detectors as in the thesis trained on LID-DS. "
                        "Test 1 (E2): attack types seen in training, 5-fold CV stratified by scenario and label, 10 fold "
                        "assignments. Test 2 (E1): leave one scenario (service) out. See lidds2021.md."),
        "dataset": {"citation": "Grimmer et al., Dataset Report: LID-DS 2021, CRITIS 2022, LNCS 13723, pp. 63-73, Springer 2023, "
                                "doi:10.1007/978-3-031-35190-7_6",
                    "recordings": len(recs), "skipped_shorter_than_window": sum(bool(r.get("skipped")) for r in recs),
                    "windows": {k: len(v["calls"]) for k, v in windows.items()},
                    "lidds_folders": dict(folders), "scenarios": scenarios,
                    "usable_recording_seconds": {"median": statistics.median(usable), "p10": pct(usable, 0.1), "min": usable[0]},
                    "first_exploit_offset_seconds": {"median": statistics.median(offsets), "min": offsets[0], "max": offsets[-1]},
                    "per_window": {k: {"calls_median": statistics.median(v["calls"]), "calls_p90": pct(v["calls"], 0.9),
                                       "frames_median": statistics.median(v["frames"]), "frames_p90": pct(v["frames"], 0.9)}
                                   for k, v in windows.items()},
                    "sysdig_events_left_out": dict(dropped)},
        "test1_seed42": {"pooled": {m: short(results["E2_pooled_5fold"]["pooled"][m]) for m in MODELS},
                         "recall_at_false_alarm_rate": matched, "gain_over_better_sensor": gains,
                         "per_scenario": {s: {m: short(results["E2_pooled_5fold"]["per_scenario"][s][m]) for m in MODELS}
                                          for s in results["E2_pooled_5fold"]["per_scenario"]}},
        "test1_ten_assignments": {"fold_seeds": rep_protocol["fold_seeds"], "summary": rep["summary"],
                                  "per_seed_pooled": [{"seed": s["seed"], **{m: short(s["pooled"][m]) for m in MODELS}}
                                                      for s in per_seed],
                                  "seed42_reproduces_original": per_seed[0]["reproduces_existing_e2"]},
        "test2_leave_one_scenario_out": {"mean": {m: results["E1_leave_one_scenario_out"]["mean_over_scenarios"][m] for m in MODELS},
                                         "per_scenario": {s: {m: short(results["E1_leave_one_scenario_out"]["per_scenario"][s][m])
                                                              for m in MODELS}
                                                          for s in results["E1_leave_one_scenario_out"]["per_scenario"]},
                                         "per_service_threshold_recall": diagnostic},
        "first_batch_five_scenarios": {"scenarios": json.load(open(FIRST_EVALUATION / "protocol.json"))["scenarios"],
                                       "test1_pooled": {m: short(first["E2_pooled_5fold"]["pooled"][m]) for m in MODELS},
                                       "test2_mean": first["E1_leave_one_scenario_out"]["mean_over_scenarios"],
                                       "test2_per_scenario": {s: {m: short(first["E1_leave_one_scenario_out"]["per_scenario"][s][m])
                                                                  for m in MODELS}
                                                              for s in first["E1_leave_one_scenario_out"]["per_scenario"]}},
        "provenance": {"evaluation": str(EVALUATION), "evaluation_protocol_sha256": sha256(EVALUATION / "protocol.json"),
                       "evaluation_results_sha256": sha256(EVALUATION / "results.json"),
                       "evaluation_scores_sha256": sha256(EVALUATION / "scores.json"),
                       "first_batch_results_sha256": sha256(FIRST_EVALUATION / "results.json"),
                       "repeat": str(repeat), "repeat_results_sha256": sha256(repeat / "results.json"),
                       "rows_sha256": protocol["rows_sha256"], "code_sha256": protocol["code_sha256"],
                       "exporter_sha256": sha256(Path(__file__)), "python": protocol["python"],
                       "numpy": protocol["numpy"], "sklearn": protocol["sklearn"]},
    }
    with open(out, "w") as f:
        json.dump(result, f, indent=1)
    print("wrote", out)


if __name__ == "__main__":
    main()
