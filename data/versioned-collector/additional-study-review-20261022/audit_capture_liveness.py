#!/usr/bin/env python3
"""Saved-only V2 audit; never invoke a VM, workload, benchmark or collector."""

import argparse
import copy
import csv
import hashlib
import io
import json
import math
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import capture_liveness as checks
import integrated_exec_identity as identity


require = checks.require


def audit_interface(metadata, quiet_rejection):
        link = metadata["packet_capture_interface_link_state_before_sample"]
        require(link == {"carrier": 1, "operstate": "up"}, "Pre-capture interface link differs")
        after_link = metadata["attribution"]["link_state_after"]
        require(after_link["carrier"] == 1 and after_link["operstate"] == "up" and
                        type(after_link["monotonic_ns"]) is int, "Post-capture interface receipt missing/down")
        before = metadata["packet_capture_interface_counters_before_sample"]
        after = metadata["packet_capture_interface_counters_after_capture"]
        delta = metadata["packet_capture_interface_counter_deltas"]
        for name in ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_dropped", "tx_dropped"):
                require(type(before[name]) is int and type(after[name]) is int and
                                0 <= delta[name] == after[name] - before[name], "Interface counter join differs: " + name)
        require(delta["rx_dropped"] == delta["tx_dropped"] == 0, "Observed NIC loss")
        no_traffic = metadata["packet_capture_statistics"]["packets_captured"] == delta["rx_packets"] == delta["tx_packets"] == 0
        require(not no_traffic or quiet_rejection, "Original no-traffic rejection promoted to accepted")
        require(not quiet_rejection or no_traffic, "Quiet rejection does not match original no-traffic predicate")


def audit_case(read, prefix, manifest, case):
    metadata = json.loads(read(prefix + "/run.json"))
    require(metadata["telemetry_schema_version"] == checks.SCHEMA and metadata["malware_runner_sha256"] == manifest["runner_sha256"],
            "Candidate schema/runner identity differs")
    require(metadata["sample_arguments"] == checks.ARGUMENTS and metadata["return_code"] == 0 and
            metadata["target_exec"]["status"] == "observed" and metadata["target_exec"]["match"] == "exact",
            "Exact null execution/argv/exit differs")
    require(metadata["target_artifact"]["elf_class"] == 64 and metadata["target_artifact"]["e_machine"] == 62 and
            metadata["target_artifact"]["linkage"] == "static", "Null ABI/linkage differs")
    require(metadata["packet_capture_status"] == metadata["ebpf_status"] == "active", "Original sensors not active")
    for field in ("packet_capture_dropped_by_kernel", "packet_capture_counter_discrepancy", "ebpf_lost_event_count"):
        require(metadata[field] == 0, "Positive or missing sensor counter: " + field)
    require(metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] == 0, "Unresolved event ABI")
    require(metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"], "Capture buffer not restored")
    reasons = metadata["collection_quality_reasons"]
    quiet_rejection = (case["helper_transactions"] == 0 and metadata["collection_quality_status"] == "rejected" and
                       reasons == ["packet_capture_interface_no_traffic"])
    require((metadata["collection_quality_status"] == "accepted" and not reasons) or quiet_rejection,
            "Unexpected original quality rejection: " + repr(reasons))
    audit_interface(metadata, quiet_rejection)
    rows = list(csv.DictReader(io.StringIO(read(prefix + "/telemetry.csv").decode())))
    groups = metadata["telemetry_feature_groups"]
    features = [name for values in groups.values() for name in values]
    require(len(rows) == 40 and len(features) == 169 and len(set(features)) == 169, "Original telemetry dimensions differ")
    require(all(math.isfinite(float(row[name])) for row in rows for name in features), "Nonfinite telemetry")
    data = read(prefix + "/packet_capture.pcap")
    packets = checks.pcap_records(data)
    statistics = metadata["packet_capture_statistics"]
    require(statistics["packets_received_by_filter"] == statistics["packets_captured"] == len(packets) and
            statistics["dropped_by_kernel"] == 0, "Independent PCAP counters differ")
    if quiet_rejection:
        require(not packets, "Quiet no-traffic rejection has packets")
    broker = json.loads(read(prefix + "/attribution-result.json"))
    require(broker["status"] == "accepted" and broker["temporary_cgroup_removed"], "Broker or cgroup cleanup failed")
    require(metadata["attribution"] == broker and broker["sample_sha256"] == checks.TARGET_SHA256,
            "Published broker/null identity differs")
    receipts = json.loads(read(prefix + "/liveness-lifecycle.json"))
    checks.validate_lifecycle(receipts, case["condition"] == "full", case["helper_transactions"] == 1)
    require(receipts["observation_start_ns"] == metadata["sample_started_monotonic_ns"] and
            receipts["original_observation_end_ns"] == metadata["observation_ended_monotonic_ns"] and
            receipts["observation_end_ns"] >= receipts["original_observation_end_ns"], "Observation clock join differs")
    stdout = list(csv.DictReader(io.StringIO(read(prefix + "/sample.stdout.log").decode())))
    require(len(stdout) == 1 and stdout[0]["event"] == "start" and stdout[0]["value"] == "liveness_null" and
            int(stdout[0]["pid"]) == metadata["sample_root_pid"], "Actual null application receipt differs")
    result = {"case": case["case"], "condition": case["condition"], "prefix": prefix,
              "quality_status": metadata["collection_quality_status"], "quality_reasons": reasons,
              "boot_id": broker["boot_id"], "pcap_records": len(packets), "finite_cells": 40 * 169,
              "null_pid": metadata["sample_root_pid"], "collection_ready": False, "performance_accepted": False}
    if case["condition"] == "full":
        observations = [json.loads(line) for line in read(prefix + "/attribution.jsonl").decode().splitlines()]
        result["v6"] = identity.audit_records(observations)
        facts = identity.exec_identity.validate_receipts(json.loads(read(prefix + "/exec-identity.json")),
                                                         metadata["sample_root_pid"], checks.TARGET_SHA256, observations)
        require(facts == broker["executable_identity"] == metadata["executable_identity"], "Independent inode receipt differs")
        for name, field in (("attached", "attached_ns"), ("detaching", "detach_ns")):
            matches = [row for row in observations if row.get("record") == name]
            require(len(matches) == 1 and matches[0]["monotonic_ns"] == receipts[field], "Actual attachment/detachment receipt differs")
        request = json.loads(read(prefix + "/attribution-request.json"))
        require(request["sensor_sha256"] == manifest["files"]["attribution-diagnostic"] and
                request["object_sha256"] == manifest["files"]["lifecycle.bpf.o"], "Recorded sensor identity differs")
        require(not any(row.get("pid") == case.get("helper_pid", -1) for row in observations if row.get("record") == "observation"),
                "Helper entered full target observation scope")
        result["executed_inode"] = facts
    if case["helper_transactions"]:
        receipt = json.loads(read(prefix + "/helper-receipt.json"))
        context = broker["capture_context"]
        require(receipt["network_namespace"] == context["network_namespace"] and
                receipt["process_namespace"] == context["process_namespace"], "Capture/helper namespaces differ")
        require(Path(broker["cgroup"]).name not in receipt["cgroup_membership"], "Helper entered target cgroup")
        require(receipt["helper_start_ns"] == receipts["helper_start_ns"] and receipt["helper_end_ns"] == receipts["helper_end_ns"],
                "Helper clock join differs")
        result["transaction"] = checks.audit_transaction(data, receipt, read(prefix + "/helper-request.bin"),
                                                         read(prefix + "/helper-response.bin"), case["transaction"])
        if case["condition"] == "full":
            require(not any(row.get("pid") == receipt["pid"] for row in observations if row.get("record") == "observation"),
                    "Helper observed in target cgroup")
    return result


def audit(attempt):
    manifest = json.loads((attempt / "manifest.json").read_text())
    protocol = json.loads((attempt / "protocol.json").read_text())
    for path, expected in protocol["source_hashes"].items():
        require(checks.digest(path) == expected, "Frozen source changed: " + path)
    for name, expected in protocol["files"].items():
        require(checks.digest(attempt / name) == expected, "Frozen transport changed: " + name)
    report = json.loads((attempt / "guest_result.json").read_text())
    with tarfile.open(attempt / "evidence.tgz", "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) <= 256 and len({member.name for member in members}) == len(members), "Evidence member count/duplicates")
        require(sum(member.size for member in members) <= 256 * 1024 * 1024, "Evidence total bound")
        require(all(member.isfile() and not PurePosixPath(member.name).is_absolute() and
                    ".." not in PurePosixPath(member.name).parts and member.size <= 64 * 1024 * 1024 for member in members),
                "Unsafe or oversized evidence member")
        names = {member.name for member in members}

        def read(name):
            require(name in names, "Missing evidence member: " + name)
            with archive.extractfile(name) as stream:
                return stream.read()

        require(json.loads(read("guest_result.json")) == report, "Retrieved/archive report differs")
        rows = []
        for case in manifest["cases"]:
            prefixes = [name.rsplit("/", 1)[0] for name in names if name.startswith("output-" + case["case"] + "/") and name.endswith("/run.json")]
            if not prefixes:
                break
            require(len(prefixes) == 1, "Ambiguous case run directory")
            rows.append(audit_case(read, prefixes[0], manifest, case))
        require(len(rows) == len(manifest["cases"]) == 6 and report["status"].startswith("accepted_"), "Incomplete diagnostic; preserve prefix, no acceptance")
        require(len({row["boot_id"] for row in rows}) == 1, "Cases crossed guest boots")
        require([row["case"] for row in rows] == [case["case"] for case in manifest["cases"]], "Diagnostic order differs")
        require(sum("transaction" in row for row in rows) == 4, "Transaction budget differs")
        require(not any("helper-" in name for name in names if any(name.startswith("output-" + case["case"] + "/")
                    for case in manifest["cases"] if not case["helper_transactions"])), "Quiet case contains helper evidence")
    final = json.loads((attempt / "final_vm_state.json").read_text())
    require(final["guest"]["VMState"] == '"poweroff"' and final["guest"]["CurrentSnapshotName"] == '"clean-tls-paired-2026-10-19"' and
            final["sink"]["VMState"] == '"running"', "Saved VM cleanup differs")
    quiet = [row for row in rows if row["case"].endswith("quiet")]
    return {"status": "positive_controls_passed_quiet_interval_unresolved" if any(row["quality_status"] == "rejected" for row in quiet)
            else "positive_controls_recovered_quiet_captures_passed_original_gate_not_completeness_proof",
            "schema": checks.SCHEMA, "cases": rows, "evidence_members": len(members),
            "evidence_sha256": checks.digest(attempt / "evidence.tgz"), "auditor_sha256": checks.digest(__file__),
            "protocol_sha256": checks.digest(attempt / "protocol.json"), "collection_ready": False,
            "performance_accepted": False, "malware_executions": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    options = parser.parse_args()
    result = audit(options.attempt.resolve())
    output = options.attempt / ("audit-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    identity.save(output, result)
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "output": str(output),
                      "collection_ready": False, "performance_accepted": False}, indent=2))