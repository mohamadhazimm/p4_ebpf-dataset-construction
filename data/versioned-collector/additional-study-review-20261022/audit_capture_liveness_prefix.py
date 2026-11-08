#!/usr/bin/env python3
"""Independently audit the stopped V2 prefix without changing measured sources."""

import argparse
import copy
import csv
import io
import json
import math
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import audit_capture_liveness as original
import capture_liveness as checks
import integrated_exec_identity as identity


require = checks.require


def cleanup(state):
    require(state["guest"]["VMState"] == '"poweroff"' and
            state["guest"]["CurrentSnapshotName"] == '"clean-tls-paired-2026-10-19"' and
            state["sink"]["VMState"] == '"running"', "Saved power/snapshot cleanup differs")
    for side in ("guest", "sink"):
        require(state[side]["nic1"] == '"intnet"' and state[side]["intnet1"] == '"malnet"' and
                all(state[side]["nic" + str(index)] == '"none"' for index in range(2, 9)),
                "Saved NIC isolation differs")


def audit(attempt):
    manifest = json.loads((attempt / "manifest.json").read_text())
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(manifest["schema"] == checks.SCHEMA and len(manifest["cases"]) == 6, "Frozen diagnostic differs")
    for path, expected in protocol["source_hashes"].items():
        require(checks.digest(path) == expected, "Frozen source changed: " + path)
    for name, expected in protocol["files"].items():
        require(checks.digest(attempt / name) == expected, "Frozen transport changed: " + name)
    report = json.loads((attempt / "guest_result.json").read_text())
    require(report["status"] == "failed_preserved" and len(report["cases"]) == 1 and
            report["malware_executions"] == 0 and not report["collection_ready"], "Stopped report differs")
    with tarfile.open(attempt / "evidence.tgz", "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) <= 256 and len({member.name for member in members}) == len(members) and
                sum(member.size for member in members) <= 256 * 1024 * 1024, "Evidence bounds/duplicates")
        require(all(member.isfile() and not PurePosixPath(member.name).is_absolute() and
                    ".." not in PurePosixPath(member.name).parts and member.size <= 64 * 1024 * 1024
                    for member in members), "Unsafe evidence member")
        names = {member.name for member in members}

        def read(name):
            require(name in names, "Missing saved member: " + name)
            return archive.extractfile(name).read()

        require(json.loads(read("guest_result.json")) == report, "Retrieved/archive report differs")
        prefixes = sorted(name.rsplit("/", 1)[0] for name in names if name.endswith("/run.json"))
        require(len(prefixes) == 2 and all(prefix.startswith("output-" + case["case"] + "/")
                    for prefix, case in zip(prefixes, manifest["cases"])), "Executed prefix/order differs")
        first_case, quiet_case = manifest["cases"][:2]
        first_prefix, quiet_prefix = prefixes
        accepted = original.audit_case(read, first_prefix, manifest, first_case)
        require(accepted == report["cases"][0], "First positive result does not independently reproduce")
        try:
            original.audit_case(read, quiet_prefix, manifest, quiet_case)
        except ValueError as error:
            require(report["error"] == "ValueError: " + str(error), "Saved quiet rejection differs")
        else:
            raise AssertionError("Failed quiet case unexpectedly accepted")
        metadata = json.loads(read(quiet_prefix + "/run.json"))
        require(metadata["collection_quality_status"] == "rejected" and metadata["collection_quality_reasons"] ==
                ["capture_liveness_failed:Finish request deadline"], "Original rejection changed")
        require(metadata["telemetry_schema_version"] == checks.SCHEMA and
                metadata["malware_runner_sha256"] == manifest["runner_sha256"] and
                metadata["sample_arguments"] == checks.ARGUMENTS and metadata["return_code"] == 0 and
                metadata["target_exec"]["status"] == "observed" and metadata["target_exec"]["match"] == "exact",
                "Quiet target/schema/argv/exit differs")
        require(metadata["packet_capture_status"] == metadata["ebpf_status"] == "active" and
                all(metadata[field] == 0 for field in ("packet_capture_dropped_by_kernel",
                    "packet_capture_counter_discrepancy", "ebpf_lost_event_count")) and
                metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] == 0 and
                metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"],
                "Quiet original sensor/counter/restoration evidence differs")
        broker = json.loads(read(quiet_prefix + "/attribution-result.json"))
        require(metadata["attribution"] == broker and broker["status"] == "accepted" and
                broker["temporary_cgroup_removed"] and broker["sample_sha256"] == checks.TARGET_SHA256 and
                broker["boot_id"] == accepted["boot_id"], "Quiet broker/boot/cleanup identity differs")
        original.audit_interface(metadata, False)
        packets = checks.pcap_records(read(quiet_prefix + "/packet_capture.pcap"))
        statistics = metadata["packet_capture_statistics"]
        require(len(packets) == statistics["packets_received_by_filter"] == statistics["packets_captured"] and
                statistics["dropped_by_kernel"] == 0, "Quiet independent PCAP counts differ")
        rows = list(csv.DictReader(io.StringIO(read(quiet_prefix + "/telemetry.csv").decode())))
        features = [name for values in metadata["telemetry_feature_groups"].values() for name in values]
        require(len(rows) == 40 and len(features) == len(set(features)) == 169 and
                all(math.isfinite(float(row[name])) for row in rows for name in features), "Quiet finite cells differ")
        require(not any("helper-" in name for name in names if name.startswith(quiet_prefix + "/")),
                "Quiet case contains intentional helper evidence")
        require(quiet_prefix + "/liveness-lifecycle.json" not in names, "Unexpected failed-case lifecycle receipt")
        guards = []
        mutations = [(first_prefix + "/run.json", "packet_capture_counter_discrepancy", 1),
                     (first_prefix + "/liveness-lifecycle.json", "finish_request_ns",
                      json.loads(read(first_prefix + "/liveness-lifecycle.json"))["observation_end_ns"] + 4 * checks.SECOND)]
        for filename, field, value in mutations:
            altered = copy.deepcopy(json.loads(read(filename)))
            altered[field] = value
            try:
                original.audit_case(lambda name: json.dumps(altered).encode() if name == filename else read(name),
                                    first_prefix, manifest, first_case)
            except ValueError:
                guards.append(field)
            else:
                raise AssertionError("Corruption accepted: " + field)
        hashes = {name: __import__("hashlib").sha256(read(name)).hexdigest() for name in sorted(names)}
    cleanup(json.loads((attempt / "final_vm_state.json").read_text()))
    return {"status": "failed_prefix_audited_not_liveness_or_collection_accepted", "schema": checks.SCHEMA,
            "accepted_prefix": [accepted], "failed_case": quiet_case["case"], "unexecuted_cases":
            [case["case"] for case in manifest["cases"][2:]], "quiet_pcap_records": len(packets),
            "finite_cells": accepted["finite_cells"] + len(rows) * len(features), "evidence_members": len(members),
            "evidence_member_sha256": hashes, "corruption_guards": guards, "quiet_case_quality_preserved": True,
            "limitations": ["Quiet actual observation-end/FINISH clocks were not published before validation failed",
                            "No full-condition case ran; no attachment-lifetime conclusion",
                            "Original sensor shutdown precedes FINISH; its allowed waits exceed V2's three-second allowance",
                            "Reported finish-deadline rejection is preserved, not independently reconstructed"],
            "input_sha256": {name: checks.digest(attempt / name) for name in
                              ("protocol.json", "manifest.json", "guest_result.json", "evidence.tgz", "final_vm_state.json")},
            "auditor_sha256": checks.digest(__file__), "collection_ready": False,
            "performance_accepted": False, "malware_executions": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    options = parser.parse_args()
    result = audit(options.attempt.resolve())
    output = options.attempt / ("partial-audit-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    identity.save(output, result)
    print(json.dumps({"status": result["status"], "output": str(output), "finite_cells": result["finite_cells"],
                      "evidence_members": result["evidence_members"], "collection_ready": False}, indent=2))