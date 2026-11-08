"""Compare the in-kernel monitor with the dataset collector on the matched workloads of a kernel-check run.

    /usr/bin/python3 compare_kernel.py <attempt>

For each workload and 0.5-s window, the 18 host window features are computed (a) from the collector's
per-window statistics (the dataset path) and (b) from the monitor's per-process rows with the release's
host_model.combine. Window cells count as equal within 1e-6 (the monitor's print precision). The 90-column
execution vectors are compared, and both are scored by the host-only detector fitted on all 240 dataset
executions. Writes <attempt>/comparison.json.
"""
import json
import math
import sys
import tarfile
from pathlib import Path

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
sys.path.insert(0, str(REL / "evaluation"))
import host_model, summary  # noqa: E402
from common import labels, load, matrix, random_forest  # noqa: E402

WINDOWS = 40


def main(attempt):
    attempt = Path(attempt).resolve()
    run = attempt / "run"
    out = run / "results"
    if not out.is_dir():
        with tarfile.open(run / "results.tgz") as tar:
            tar.extractall(run, filter="data")
    guest = json.loads((out / "guest_result.json").read_text())
    rows, host, _ = load()
    model = random_forest().fit(matrix(rows, host), labels(rows))
    report = {"runner_sha256": guest["runner_sha256"], "workloads": []}
    for w in guest["workloads"]:
        entry = {"name": w["name"]}
        if "error" in w:
            entry["error"] = w["error"]
            report["workloads"].append(entry)
            continue
        monitor_lines = (out / (w["name"] + ".monitor.txt")).read_text().splitlines()
        health = [l for l in monitor_lines if l.startswith("HOSTMON_HEALTH")]
        entry["monitor_health"] = health[-1] if health else None
        entry["collector_lost_events"] = w["collector_lost_events"]
        entry["exit"] = w.get("exit")
        mon_windows = [host_model.combine(p) for p in host_model.parse_monitor(monitor_lines, WINDOWS)]
        col_windows = [{f: float(cw.get(f, 0)) for f in host_model.FEATURES} for cw in w["collector_windows"]]
        cells = [(f, i, c[f], m[f]) for i, (c, m) in enumerate(zip(col_windows, mon_windows)) for f in host_model.FEATURES]
        # The monitor prints entropy, top frequency, run length and rare ratio with 6 decimals.
        diff = [(f, i, a, b) for f, i, a, b in cells if not math.isclose(a, b, rel_tol=0, abs_tol=1e-6)]
        entry["window_cells"] = len(cells)
        entry["window_cells_differing"] = len(diff)
        entry["features_differing"] = sorted({f for f, *_ in diff})
        entry["examples"] = [{"feature": f, "window": i, "collector": a, "monitor": b} for f, i, a, b in diff[:4]]
        entry["calls_collector"] = sum(c["host_total_syscalls_total"] for c in col_windows)
        entry["calls_monitor"] = sum(m["host_total_syscalls_total"] for m in mon_windows)
        sc, sm = summary.summarize(col_windows, host_model.FEATURES), summary.summarize(mon_windows, host_model.FEATURES)
        vc = [[sc[c] for c in host]]
        vm = [[sm[c] for c in host]]
        entry["vector_max_abs_diff"] = max(abs(sc[c] - sm[c]) for c in host)
        entry["host_only_probability"] = {"collector": float(model.predict_proba(vc)[0, 1]),
                                          "monitor": float(model.predict_proba(vm)[0, 1])}
        report["workloads"].append(entry)
    done = [e for e in report["workloads"] if "error" not in e]
    report["summary"] = {
        "workloads": len(report["workloads"]), "compared": len(done),
        "identical_vectors": sum(e["window_cells_differing"] == 0 for e in done),
        "window_cells": sum(e["window_cells"] for e in done),
        "window_cells_differing": sum(e["window_cells_differing"] for e in done),
        "same_decision": sum((e["host_only_probability"]["collector"] >= 0.5) == (e["host_only_probability"]["monitor"] >= 0.5) for e in done),
        "max_probability_difference": max((abs(e["host_only_probability"]["collector"] - e["host_only_probability"]["monitor"]) for e in done), default=None),
    }
    (attempt / "comparison.json").write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report["summary"], indent=1))
    for e in report["workloads"]:
        print("%-24s %s" % (e["name"], e.get("error") or "cells differing %d/%d  calls %d/%d  p %.3f/%.3f  lost %s  %s" % (
            e["window_cells_differing"], e["window_cells"], e["calls_collector"], e["calls_monitor"],
            e["host_only_probability"]["collector"], e["host_only_probability"]["monitor"], e["collector_lost_events"],
            ",".join(e["features_differing"][:4]))))


if __name__ == "__main__":
    main(sys.argv[1])
