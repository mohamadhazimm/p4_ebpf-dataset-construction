#!/usr/bin/env python3
"""Audit saved partial performance evidence without executing another workload."""

import argparse
import copy
import csv
import datetime
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import struct
import tarfile

import check_scoped_performance as gate


def require(condition, message):
    if not condition:
        raise ValueError(message)


def members(path, maximum_total):
    result = {}
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            require(member.isfile() and not name.is_absolute() and ".." not in name.parts
                    and str(name) == member.name and member.name not in result,
                    "Unsafe, duplicate or nonregular evidence member")
            total += member.size
            require(0 <= member.size <= 64 * 1024 * 1024 and total <= maximum_total,
                    "Evidence member or total exceeds bound")
            with archive.extractfile(member) as stream:
                content = stream.read(member.size + 1)
            require(len(content) == member.size, "Truncated evidence member")
            result[member.name] = content
    return result


def packet_count(content):
    formats = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
               b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    require(len(content) >= 24 and content[:4] in formats, "Invalid classic PCAP header")
    endian = formats[content[:4]]
    major, minor, _zone, _sigfigs, snaplen, link = struct.unpack_from(endian + "HHiiii", content, 4)
    require((major, minor) == (2, 4) and 0 < snaplen <= 16 * 1024 * 1024 and link == 1,
            "Unsupported PCAP version, snaplen or Ethernet link")
    offset = 24
    count = 0
    while offset < len(content):
        require(offset + 16 <= len(content), "Truncated PCAP record header")
        _seconds, _fraction, captured, original = struct.unpack_from(endian + "IIII", content, offset)
        require(captured <= snaplen and captured <= original and offset + 16 + captured <= len(content),
                "Invalid or truncated PCAP packet")
        offset += 16 + captured
        count += 1
    return count


def quality_findings(metadata, case, captured):
    if case["condition"] == "baseline":
        require(metadata["ebpf_status"] == "disabled" and metadata["packet_capture_status"] == "disabled",
                "Baseline unexpectedly enabled a sensor")
        require(captured is None, "Baseline unexpectedly has a PCAP")
        return []
    require(metadata["ebpf_status"] == "active" and metadata["packet_capture_status"] == "active",
            "Original sensors inactive")
    target = metadata["target_exec"]
    require(target["status"] == "observed" and target["match"] == "exact", "Target exec not exactly observed")
    for key in ("ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel"):
        require(metadata[key] == 0, "Observed sensor loss or packet-counter gap")
    statistics = metadata["packet_capture_statistics"]
    require(captured == statistics["packets_captured"] == statistics["packets_received_by_filter"]
            and statistics["dropped_by_kernel"] == 0, "PCAP record/counter discrepancy")
    reasons = metadata["collection_quality_reasons"]
    require((metadata["collection_quality_status"] == "accepted") == (not reasons),
            "Collection quality status contradicts recorded reasons")
    if reasons:
        require(reasons == ["packet_capture_interface_no_traffic"] and captured == 0,
                "Unexpected quality failure")
        deltas = metadata["packet_capture_interface_counter_deltas"]
        require(deltas["rx_packets"] == deltas["tx_packets"] == 0,
                "No-traffic rejection disagrees with NIC evidence")
    return reasons


def validate_usage(usage, pid):
    require(usage["pid"] == pid and usage["returncode"] == 0, "Measured PID or exit differs")
    require(usage["wall_ns"] == usage["exit_observed_ns"] - usage["begin_ns"] > 0,
            "Actual task wall boundary differs")
    for key in ("user_seconds", "system_seconds", "peak_rss_kib"):
        require(type(usage[key]) in (int, float) and math.isfinite(usage[key]) and usage[key] >= 0,
                "Invalid actual task resource measurement")


def audit(attempt):
    protocol = json.loads((attempt / "protocol.json").read_text())
    for field in ("files", "source_hashes"):
        for name, expected in protocol[field].items():
            path = attempt / name if field == "files" else Path(name)
            require(gate.identity.digest(path) == expected, "Frozen file/source hash changed: " + name)
    manifest = json.loads((attempt / "manifest.json").read_text())
    require(manifest["cases"] == gate.plan(), "Frozen counterbalanced case order differs")
    payload = members(attempt / "payload.tgz", 256 * 1024 * 1024)
    for name, expected in manifest["files"].items():
        require(hashlib.sha256(payload[name]).hexdigest() == expected, "Frozen payload identity changed: " + name)
    evidence = members(attempt / "evidence.tgz", 2 * 1024 * 1024 * 1024)
    require(evidence["guest_result.json"] == (attempt / "guest_result.json").read_bytes(),
            "Retrieved/archive guest report differs")
    guest = json.loads(evidence["guest_result.json"])
    require(guest["status"] == "failed_preserved" and not guest["collection_ready"]
            and guest["malware_executions"] == 0, "This auditor requires a failed, preserved benign attempt")
    directories = sorted(name.rsplit("/", 1)[0] for name in evidence if name.endswith("/run.json"))
    require(0 < len(directories) <= len(manifest["cases"]), "Unexpected run count")
    cases = []
    cells = 0
    total_packets = 0
    rejection = None
    first_instrumented = None
    for index, directory in enumerate(directories):
        case = manifest["cases"][index]
        require(directory.split("/")[0] == "output-" + case["mode"], "Executed order is not a frozen prefix")
        entry = lambda name: evidence[directory + "/" + name]
        metadata = json.loads(entry("run.json"))
        require(metadata["telemetry_schema_version"] == gate.performance.SCHEMA
                and metadata["malware_runner_sha256"] == manifest["files"]["integrated_runner.py"]
                and metadata["return_code"] == 0, "Actual runner provenance/exit differs")
        receipt = json.loads(entry("sample.stdout.log"))
        require(receipt == {"status": "accepted", "task": case["task"], "pid": metadata["sample_root_pid"],
                           "pointer_bits": 32 if case["abi"] == "i386" else 64,
                           "file_bytes": 16777216 if case["task"] == "file" else 0,
                           "actual_udp_echoes": 64 if case["task"] == "network" else 0},
                "Actual application receipt/ABI differs")
        usage = json.loads(entry("task-usage.json"))
        validate_usage(usage, receipt["pid"])
        if case["task"] == "file":
            block = bytes((offset * 37 + 11) % 251 for offset in range(65536))
            require(entry("workspace/roundtrip.bin") == block * 256, "Owned 16MiB roundtrip bytes differ")
        pcaps = [content for name, content in evidence.items() if name.startswith(directory + "/") and name.endswith(".pcap")]
        require(len(pcaps) == (0 if case["condition"] == "baseline" else 1), "PCAP count differs")
        captured = packet_count(pcaps[0]) if pcaps else None
        findings = quality_findings(metadata, case, captured)
        total_packets += captured or 0
        if case["condition"] != "baseline":
            features = [name for names in metadata["telemetry_feature_groups"].values() for name in names]
            require(len(features) == len(set(features)) == 169, "Feature contract differs")
            rows = list(csv.DictReader(io.StringIO(entry("telemetry.csv").decode())))
            require(len(rows) == 40, "Observation window count differs")
            for row in rows:
                for name in features:
                    require(math.isfinite(float(row[name])), "Missing/nonfinite instrumented feature")
                    cells += 1
            first_instrumented = first_instrumented or (metadata, case, captured)
        if case["condition"] == "full":
            records = [json.loads(line) for line in entry("attribution.jsonl").decode().splitlines()]
            gate.identity.audit_records(records)
            gate.identity.exec_identity.validate_receipts(json.loads(entry("exec-identity.json")), receipt["pid"],
                                                          manifest["files"][case["binary"]], records)
            recorder = json.loads(entry("recorder-usage.json"))
            validate_usage(recorder, recorder["pid"])
            require(metadata["attribution"]["temporary_cgroup_removed"], "Full cgroup cleanup missing")
        else:
            require(metadata["benchmark_cgroup"]["temporary_cgroup_removed"], "Baseline/original cgroup cleanup missing")
        if findings:
            require(index == len(directories) - 1 and rejection is None, "Execution continued after rejection")
            rejection = {"case": case, "reasons": findings, "packets": captured,
                         "link": metadata["packet_capture_interface_link_state_before_sample"],
                         "interface_deltas": metadata["packet_capture_interface_counter_deltas"]}
        else:
            row = guest["measurements"][index]
            require(all(row[key] == value for key, value in case.items()) and row["usage"] == usage,
                    "Archived usage/case differs from guest report")
        cases.append({"case": case, "usage": usage, "quality_findings": findings})
    require(rejection is not None and len(guest["measurements"]) == len(cases) - 1,
            "Missing preserved quality rejection")
    state = json.loads((attempt / "final_vm_state.json").read_text())
    require(state["guest"]["VMState"].strip('"') == "poweroff"
            and state["guest"]["CurrentSnapshotName"].strip('"') == "clean-tls-paired-2026-10-19"
            and state["sink"]["VMState"].strip('"') == "running", "Saved final VM state differs")
    for machine in state.values():
        require(machine["nic1"].strip('"') == "intnet" and machine["intnet1"].strip('"') == "malnet"
                and all(machine["nic" + str(index)].strip('"') == "none" for index in range(2, 9)),
                "Saved isolation differs")
    guards = []
    for key in ("ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel"):
        changed = copy.deepcopy(first_instrumented[0])
        changed[key] = 1
        try:
            quality_findings(changed, first_instrumented[1], first_instrumented[2])
        except ValueError:
            guards.append(key)
        else:
            raise AssertionError("Positive counter guard failed")
    modified = copy.deepcopy(usage)
    modified["wall_ns"] += 1
    try:
        validate_usage(modified, modified["pid"])
    except ValueError:
        guards.append("changed_task_wall_boundary")
    else:
        raise AssertionError("Task wall corruption accepted")
    return {"status": "partial_evidence_audited_not_performance_accepted", "collection_ready": False,
            "performance_accepted": False, "malware_executions": 0, "safe_members": len(evidence),
            "instrumented_finite_cells": cells, "pcap_records": total_packets, "cases": cases,
            "rejection": rejection, "negative_guards": guards,
            "input_hashes": {name: gate.identity.digest(attempt / name) for name in
                             ("protocol.json", "manifest.json", "payload.tgz", "guest_result.json", "evidence.tgz", "final_vm_state.json")},
            "limitations": "Unscored warmups are not scored performance acceptance. No scored full/original pair completed; neither i386 nor network tasks ran. Zero traffic with link up does not prove connectivity or loss completeness. Baseline sensors were intentionally disabled and their original quality rejection remains unchanged."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    options = parser.parse_args()
    result = audit(options.attempt.resolve())
    result["auditor_sha256"] = gate.identity.digest(__file__)
    name = "partial-audit-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
    gate.identity.save(options.attempt / name, result)
    print(json.dumps({key: value for key, value in result.items() if key not in ("cases", "input_hashes")}, indent=2))