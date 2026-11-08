#!/usr/bin/env python3
"""Read-only validation of the schema .15 exec-success known-answer runs."""
import csv
import hashlib
import io
import json
import math
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = json.loads((ROOT / "experiment_manifest.json").read_text())
EXPECTED = {
    "md5sum": {"status": "observed", "match": "exact", "root_successes": 2, "failures": 0,
               "min_post_root": 1, "min_descendant": 0},
    "ka_static_ldconfig": {"status": "observed", "match": "exact", "root_successes": 2, "failures": 0,
                           "min_post_root": 1, "min_descendant": 0},
    "ka_script.sh": {"status": "observed", "match": "exact", "root_successes": 2, "failures": 0,
                     "min_post_root": 1, "min_descendant": 2},
    "ka_truncated_elf": {"status": "not_observed", "match": None, "root_successes": 1, "failures": 1,
                         "min_post_root": None, "min_descendant": 0},
}
EXEC_EVENTS = {"exec_success", "exec_return"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


errors, results = [], {}
for sample, want in EXPECTED.items():
    sample_dir = ROOT / "runs" / "known-answer" / sample
    host = dict(line.split("=", 1) for line in (sample_dir / "host_run.txt").read_text().split() if "=" in line)
    run_dir = next((sample_dir / "output").glob("run_*"))
    meta = json.loads((run_dir / "run.json").read_text())
    exec_summary = meta["target_exec"]
    problems = []

    def check(condition, message):
        if not condition:
            problems.append(message)

    check(host.get("status") == "completed", "retrieval not completed")
    check(meta["telemetry_schema_version"] == MANIFEST["schema_version"], "schema mismatch")
    check(meta["malware_runner_sha256"] == MANIFEST["runner_sha256"], "runner hash mismatch")
    check(meta["ebpf_status"] == "active", "eBPF inactive")
    check(meta["collection_quality_status"] == "accepted", "quality not accepted")
    check(meta.get("ebpf_lost_event_count") == 0, "eBPF loss")
    check(meta.get("packet_capture_dropped_by_kernel") == 0, "PCAP kernel drops")
    check(meta.get("packet_capture_counter_discrepancy") == 0, "PCAP counter discrepancy")

    check(exec_summary["status"] == want["status"], f"target status {exec_summary['status']}")
    check(exec_summary["match"] == want["match"], f"match {exec_summary['match']}")
    check(exec_summary["root_exec_success_count"] == want["root_successes"], "root success count")
    check(exec_summary["root_exec_successes"][0]["filename"] == "/bin/bash", "wrapper exec not first")
    check(exec_summary["root_exec_failure_count"] == want["failures"], "failure count")
    if want["failures"]:
        check(all(item["errno"] > 0 for item in exec_summary["root_exec_failures"]), "failure errno")
    if want["min_post_root"] is None:
        check(exec_summary["post_target_root_raw_syscalls"] is None, "post-target count should be null")
    else:
        check((exec_summary["post_target_root_raw_syscalls"] or 0) >= want["min_post_root"], "no post-target activity")
    check(exec_summary["descendant_exec_success_count"] >= want["min_descendant"], "descendant execs")

    # Exec diagnostics must be separate from the feature event stream.
    with (run_dir / "ebpf_events.csv").open(newline="") as handle:
        named_events = {row["event"] for row in csv.DictReader(handle)}
    check(not (named_events & EXEC_EVENTS), "exec diagnostics leaked into ebpf_events.csv")
    with (run_dir / "exec_events.csv").open(newline="") as handle:
        exec_rows = list(csv.DictReader(handle))
    check({row["event"] for row in exec_rows} <= EXEC_EVENTS and exec_rows, "exec_events.csv content")
    root_pid = meta["sample_root_pid"]
    root_success = sum(1 for row in exec_rows if row["event"] == "exec_success" and int(row["pid"]) == root_pid)
    check(root_success == exec_summary["root_exec_success_count"], "CSV/metadata root success mismatch")

    with (run_dir / "telemetry.csv").open(newline="") as handle:
        telemetry = list(csv.DictReader(handle))
    features = [name for group in meta["telemetry_feature_groups"].values() for name in group]
    check(len(features) == 169, f"feature count {len(features)}")
    check(len(telemetry) == 16, f"telemetry rows {len(telemetry)}")
    check(all(math.isfinite(float(row[name])) for row in telemetry for name in features), "non-finite features")
    check(not any("exec_success" in key or "exec_return" in key for key in telemetry[0]), "exec column in telemetry")

    member_count = 0
    with tarfile.open(sample_dir / "output.tgz") as archive:
        for member in archive.getmembers():
            name = Path(member.name)
            check(not name.is_absolute() and ".." not in name.parts, f"unsafe member {member.name}")
            if member.isfile():
                member_count += 1
                host_file = sample_dir / "output" / name
                check(host_file.is_file() and sha(archive.extractfile(member).read()) == sha(host_file.read_bytes()),
                      f"archive mismatch {member.name}")
    check(any(Path(m).name == "exec_events.csv" for m in tarfile.open(sample_dir / "output.tgz").getnames()),
          "exec_events.csv not archived")

    results[sample] = {"problems": problems, "process_status": meta["status"], "exec_rows": len(exec_rows),
                       "archive_files": member_count, "target_exec": exec_summary,
                       "pcap_received": meta.get("packet_capture_packets_received_by_filter"),
                       "pcap_captured": meta.get("packet_capture_packets_captured")}
    errors += [f"{sample}: {p}" for p in problems]

report = {"schema_version": MANIFEST["schema_version"], "runner_sha256": MANIFEST["runner_sha256"],
          "status": "accepted" if not errors else "rejected", "errors": errors, "runs": results}
(ROOT / "exec_validation.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"status": report["status"], "errors": errors,
                  "runs": {k: (v["process_status"], v["exec_rows"], v["archive_files"]) for k, v in results.items()}}, indent=1))
sys.exit(0 if not errors else 1)
