"""Accept or reject each run of a batch attempt (PROTOCOL.md) and write the accepted runs as dataset rows.

    /usr/bin/python3 assess.py <attempt>

Writes <attempt>/assessment.json and <attempt>/features.csv (same columns as dataset/features.csv, plus
the batch's own identifiers). Network features are taken from the run's telemetry and cross-checked
against the release's software switch model on the packet capture.
"""
import csv
import glob
import json
import math
import sys
from pathlib import Path

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
import host_model, summary, switch_model  # noqa: E402

DATASET = REL / "dataset" / "features.csv"
WINDOWS = 40


def bg_requests_in_window(pcap, start_us, window_s):
    """Number of marked background HTTP requests whose capture time lies inside the feature windows."""
    end_us = start_us + int(WINDOWS * window_s * 1_000_000)
    return sum(1 for t, _, frame in switch_model.read_pcap(pcap)
               if start_us <= t < end_us and b"GET /bg/" in frame)


def assess(attempt, repeat=False):
    """repeat=True: the failed first background attempt, used as a rerun without background traffic
    (PROTOCOL.md, Amendment 1); the background-traffic requirement is replaced by requiring none."""
    attempt = Path(attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    kind = protocol["kind"]
    header = next(csv.reader(open(DATASET)))
    feature_columns = [c for c in header if c.startswith(("host_", "net_"))]
    results, rows = [], []
    for position, case in enumerate(protocol["cases"], 1):
        r = {"position": position, "sample": case["sample"], "category": case["category"], "reasons": []}
        # A continuation (PROTOCOL.md, Amendment 2) writes the cases it reran to runs-continuation/.
        runs = [p for sub in ("runs", "runs-continuation")
                for p in glob.glob(str(attempt / sub / case["sample"] / "output" / "run_*" / "run.json"))]
        if len(runs) != 1:
            r["reasons"].append("no retrieved run.json (%d)" % len(runs))
            r["accepted"] = False
            results.append(r)
            continue
        d = Path(runs[0]).parent
        meta = json.loads((d / "run.json").read_text())
        r["return_code"] = meta.get("return_code")
        if meta.get("collection_quality_status") != "accepted":
            r["reasons"].append("quality %s: %s" % (meta.get("collection_quality_status"), meta.get("collection_quality_reasons")))
        if (meta.get("target_exec") or {}).get("status") != "observed":
            r["reasons"].append("target exec %s" % (meta.get("target_exec") or {}).get("status"))
        tel = list(csv.DictReader(open(d / "telemetry.csv", newline="", encoding="utf-8-sig")))
        cells = [float(t[f]) for t in tel for f in host_model.FEATURES + switch_model.FEATURES]
        if len(tel) != WINDOWS or not all(math.isfinite(x) for x in cells):
            r["reasons"].append("telemetry %d windows / non-finite" % len(tel))
        start_us, window_s = int(meta["sample_started_wall_us"]), float(meta["window_seconds"])
        if kind == "python":
            out = (d / "sample.stdout.log").read_text().strip().splitlines()
            try:
                summary_line = json.loads(out[-1])
            except (IndexError, json.JSONDecodeError):
                summary_line = None
            r["workload_summary"] = summary_line
            succeeded = bool(summary_line) and bool(summary_line.get("ok")) and meta.get("return_code") == 0
            if not succeeded:
                r["reasons"].append("workload did not report success (rc %s)" % meta.get("return_code"))
        else:
            r["bg_requests_in_window"] = bg_requests_in_window(d / "packet_capture.pcap", start_us, window_s)
            if repeat and r["bg_requests_in_window"] != 0:
                r["reasons"].append("background traffic present in a no-background repeat")
            if not repeat and r["bg_requests_in_window"] == 0:
                r["reasons"].append("no background traffic in the feature windows")
        if len(tel) == WINDOWS:
            net = switch_model.window_features(d / "packet_capture.pcap", start_us, window_s, WINDOWS)
            r["switch_model_cells_differing"] = sum(float(t[f]) != w[f] for t, w in zip(tel, net) for f in switch_model.FEATURES)
            if r["switch_model_cells_differing"]:
                r["reasons"].append("telemetry network features differ from the switch model")
        r["accepted"] = not r["reasons"]
        results.append(r)
        if r["accepted"]:
            values = summary.summarize(tel, host_model.FEATURES) | summary.summarize(tel, switch_model.FEATURES)
            row = {"batch": kind, "sample": case["sample"], "category": case["category"],
                   "label": 1 if case["label"] == "malicious" else 0, "execution_id": case.get("execution_id", case["sample"][:-4]),
                   "cv_group": case.get("cv_group", "benign_project::python-workloads"),
                   "network_workload": case.get("network", ""), "return_code": meta.get("return_code"),
                   "run": str(d.relative_to(attempt))}
            row.update({c: values[c] for c in feature_columns})
            rows.append(row)
    accepted = sum(r["accepted"] for r in results)
    report = {"attempt": attempt.name, "kind": kind, "cases": len(results), "accepted": accepted,
              "rejected": [r for r in results if not r["accepted"]], "runs": results}
    (attempt / "assessment.json").write_text(json.dumps(report, indent=1) + "\n")
    if rows:
        with open(attempt / "features.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
    print("%s: %d of %d accepted" % (kind, accepted, len(results)))
    for r in report["rejected"]:
        print("  rejected", r["sample"], r["reasons"])


if __name__ == "__main__":
    assess(sys.argv[1], repeat="--repeat" in sys.argv[2:])
