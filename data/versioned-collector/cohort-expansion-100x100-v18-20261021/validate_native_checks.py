#!/usr/bin/env python3
"""Validate saved native checks using the actual schema-.18 raw export contract."""

from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path

from scapy.utils import RawPcapReader

import run_native_checks as checks


def csv_rows(path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def validate_case(attempt, protocol, case):
    sample = attempt / "runs" / case["sample"]
    paths = list((sample / "output").glob("run_*/run.json"))
    if len(paths) != 1 or "status=completed" not in (sample / "host_run.txt").read_text().split():
        raise ValueError("retrieval incomplete or ambiguous")
    run = paths[0].parent
    meta = json.loads(paths[0].read_text())
    if meta["telemetry_schema_version"] != protocol["schema"] or meta["malware_runner_sha256"] != protocol["production_hashes"]["src/malware_runner.py"]:
        raise ValueError("runner provenance differs")
    if meta["ebpf_status"] != "active" or meta["packet_capture_status"] != "active":
        raise ValueError("inactive sensor")
    if meta["collection_quality_status"] != "accepted" or any(meta.get(key) != 0 for key in (
        "ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel",
    )):
        raise ValueError("sensor quality rejected")
    artifact, execution = meta["target_artifact"], meta["target_exec"]
    expected_mode = "native_compat" if case["arch"] == "i386" else "native"
    if artifact["e_machine"] != case["machine"] or artifact["linkage"] != "static" or artifact["execution_mode"] != expected_mode:
        raise ValueError("not the expected static native target")
    if execution["status"] != "observed" or execution["match"] != "exact" or meta["return_code"] != 0:
        raise ValueError("known-answer execution failed")
    telemetry = csv_rows(run / "telemetry.csv")
    features = [name for group in meta["telemetry_feature_groups"].values() for name in group]
    if len(features) != 169 or len(set(features)) != 169 or len(telemetry) != 40:
        raise ValueError("feature/row contract differs")
    if not all(math.isfinite(float(row[name])) for row in telemetry for name in features):
        raise ValueError("nonfinite features")
    diagnostic = meta["ebpf_event_diagnostics"]
    if diagnostic["raw_syscalls_unresolved_abi"] != 0:
        raise ValueError("unresolved collector ABI")
    for name, counts in diagnostic["named_vs_raw_syscalls"].items():
        field = f"ebpf_{name}_count"
        if field in features and sum(float(row[field]) for row in telemetry) < counts["raw"]:
            raise ValueError("feature below raw count: " + name)
    raw = csv_rows(run / "syscall_events.csv")
    if len(raw) != meta["raw_syscall_event_count"]:
        raise ValueError("raw rows do not reconcile")
    targets = [int(row["timestamp_ns"]) for row in csv_rows(run / "exec_events.csv")
               if row["event"] == "exec_success" and int(row["pid"]) == meta["sample_root_pid"]
               and ("filename=" + execution["expected_path"]) in row["detail"].split()]
    if len(targets) != 1:
        raise ValueError("missing or ambiguous target-exec boundary")
    after = [row for row in raw if int(row["timestamp_ns"]) > targets[0]]
    if len(after) != execution["post_target_lineage_raw_syscalls"]:
        raise ValueError("post-target lineage count differs")
    numbers = [int(row["detail"].removeprefix("id=")) for row in after]
    if not numbers:
        raise ValueError("no target syscalls")
    if case["workload"] == "file":
        if (run / "workspace/bb_file_workload.txt").read_bytes() != b"299\n":
            raise ValueError("file output differs")
        if numbers.count(4 if case["arch"] == "i386" else 1) != 300:
            raise ValueError("300 known-answer writes not observed")
    if case["workload"] == "net":
        body = (run / "workspace/bb_net_workload.html").read_bytes()
        if not body.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
            raise ValueError("no saved HTTP 200 response")
        if not set(numbers) & ({102, 362} if case["arch"] == "i386" else {42}):
            raise ValueError("no expected native network syscall")
    with RawPcapReader(str(run / "packet_capture.pcap")) as capture:
        packets = sum(1 for _packet in capture)
    statistics = meta["packet_capture_statistics"]
    if packets != statistics["packets_captured"] or packets != statistics["packets_received_by_filter"]:
        raise ValueError("PCAP counters differ")
    archived = checks.previous_readiness.verify_output_archive(sample)
    return {**case, "run": str(run.relative_to(attempt)), "post_target_syscalls": len(after),
            "archive_members": archived, "pcap_records": packets,
            "known_answer_write_count": numbers.count(4 if case["arch"] == "i386" else 1),
            "named_vs_raw_syscalls": diagnostic["named_vs_raw_syscalls"],
            "raw_syscalls_unresolved_abi": diagnostic["raw_syscalls_unresolved_abi"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    parser.add_argument("--output-name", default="validation-derived.json")
    args = parser.parse_args()
    if Path(args.output_name).name != args.output_name:
        raise ValueError("output name must be a filename")
    attempt = args.attempt.resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    builder = checks.prepare_inventory.load_builder()
    for name, expected in protocol["input_hashes"].items():
        if builder.sha256_file(checks.STUDY / name) != expected:
            raise ValueError("frozen input changed: " + name)
    rows, errors = [], []
    for case in protocol["cases"]:
        try:
            rows.append(validate_case(attempt, protocol, case))
        except (ValueError, FileNotFoundError, KeyError) as error:
            errors.append(case["sample"] + ": " + str(error))
    maxima = {}
    for arch in ("amd64", "i386"):
        nulls = [row["post_target_syscalls"] for row in rows if row["arch"] == arch and row["workload"] == "null"]
        if not nulls:
            errors.append("missing accepted null: " + arch)
        else:
            maxima[arch] = max(nulls)
    for row in rows:
        row["activity_floor"] = maxima.get(row["arch"], 0) + 25
        row["progressed"] = row["post_target_syscalls"] > row["activity_floor"]
        if row["workload"] != "null" and not row["progressed"]:
            errors.append(row["sample"] + ": known-answer activity criterion not met")
    result = {
        "status": "accepted" if not errors else "not_accepted", "errors": errors,
        "i386_gate_passed": not errors and len(rows) == 12,
        "collection_ready": False, "full_collection_started": False, "malware_executions": 0,
        "null_maxima": maxima, "cases": rows,
        "archive_members": sum(row["archive_members"] for row in rows),
        "pcap_records": sum(row["pcap_records"] for row in rows),
        "validator_sha256": builder.sha256_file(Path(__file__)),
        "protocol_sha256": builder.sha256_file(attempt / "protocol.json"),
        "audit_correction": "The frozen driver incorrectly expected ABI tags in syscall_events.csv and native rather than native_compat for i386. .18 strips ABI tags after parsing; this derived audit uses exact target exec plus controlled static same-architecture BusyBox descendants, unresolved-ABI diagnostics and architecture-specific execution mode.",
        "limitations": protocol["limitations"] + [
            "Exported raw rows retain IDs but not the kernel ABI flag; per-event ABI cannot be independently recovered for arbitrary mixed-ABI processes from this CSV.",
            "The original frozen audit failure is retained; captures and production code are unchanged.",
        ],
    }
    output = attempt / args.output_name
    if output.exists():
        raise FileExistsError("preserve existing derived validation")
    checks.write_json(output, result)
    print(json.dumps({key: value for key, value in result.items() if key != "cases"}, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()