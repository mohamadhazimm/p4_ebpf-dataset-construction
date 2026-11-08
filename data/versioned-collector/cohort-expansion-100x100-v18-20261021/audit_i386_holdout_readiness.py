#!/usr/bin/env python3
"""Re-audit saved amended release evidence without operating the guest."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import check_i386_holdout_release as gates


def audit(attempt):
    release = attempt.parent.parent
    readiness = json.loads((attempt / "readiness.json").read_text())
    protocol = json.loads((release / "protocol.json").read_text())
    manifest = json.loads((release / "manifest.json").read_text())
    gate_protocol = json.loads((attempt / "gate_protocol.json").read_text())
    if not readiness["collection_ready"] or readiness["malware_executions"] != 0 or readiness["full_collection_started"]:
        raise ValueError("no accepted readiness-only release")
    for name, key in (("collection_preflight.json", "guest_preflight_sha256"),
                      ("sensor_validation.json", "sensor_validation_sha256"),
                      ("gate_protocol.json", "gate_protocol_sha256")):
        if gates.digest(attempt / name) != readiness[key]:
            raise ValueError("evidence hash differs: " + name)
    if gates.digest(release / "protocol.json") != readiness["protocol_sha256"]:
        raise ValueError("release protocol differs")
    if gates.digest(Path(gates.__file__)) != gate_protocol["driver_sha256"]:
        raise ValueError("gate driver changed")
    for name, expected in protocol["input_hashes"].items():
        if gates.digest(gates.STUDY / name) != expected:
            raise ValueError("frozen input changed: " + name)
    gates.HELPER.verify_production()
    cases = protocol["cases"]
    ordered = json.loads((release / "case_order.json").read_text())
    if [row["sample"] for row in ordered] != (release / "all-cases.txt").read_text().splitlines():
        raise ValueError("order differs")
    if len(cases) != 204 or {row["sample"] for row in cases} != {row["sample"] for row in ordered}:
        raise ValueError("case identities differ")
    for label in ("benign", "malware"):
        training = [row for row in cases if row["label"] == label and row["split"] == "training"]
        validation = [row for row in cases if row["label"] == label and row["split"] == "validation"]
        if len(training) != 70 or len(validation) != 30 or len({row["sha256"] for row in training + validation}) != 100:
            raise ValueError("split/hash budget differs")
        if {row["group_id"] for row in training} & {row["group_id"] for row in validation}:
            raise ValueError("whole-group leakage")
        if Counter(row["arch"] for row in training) != {"amd64": 49, "i386": 21} or any(row["arch"] != "i386" for row in validation):
            raise ValueError("mode budget differs")
    benign = json.loads((attempt / "collection_preflight.json").read_text())
    if benign["status"] != "accepted" or benign["accepted"] != 100 or any(row["returncode"] != 0 for row in benign["cases"]):
        raise ValueError("benign collection-form workload checks incomplete")
    protocol["fixture_hashes"] = manifest["fixtures"]
    measured = gates.audit(attempt, release, protocol)
    stored = json.loads((attempt / "sensor_validation.json").read_text())
    if measured != stored:
        raise ValueError("saved sensor audit does not reproduce")
    original_loads = json.loads
    negatives = {}
    for key in ("packet_capture_counter_discrepancy", "ebpf_lost_event_count", "target_exec"):
        def changed_loads(text, *args, **kwargs):
            value = original_loads(text, *args, **kwargs)
            if isinstance(value, dict) and "telemetry_schema_version" in value:
                if key == "target_exec":
                    value["target_exec"]["status"] = "not_observed"
                else:
                    value[key] = 1
            return value

        with patch.object(gates.json, "loads", side_effect=changed_loads):
            try:
                gates.audit(attempt, release, protocol)
            except ValueError:
                negatives[key] = "rejected"
            else:
                raise ValueError("negative quality probe was accepted: " + key)
    current = {"guest": gates.HELPER.isolated(gates.HELPER.VM), "sink": gates.HELPER.isolated("Sink")}
    if (current["guest"]["VMState"] != '"poweroff"'
            or current["guest"]["CurrentSnapshotName"] != '"' + gates.HELPER.ORIGINAL + '"'
            or current["sink"]["VMState"] != '"running"'):
        raise ValueError("fresh safety check failed")
    competing = gates.subprocess.run(["pgrep", "-af", "[v]box_malware_batch|[s]tage_versioned_runner|[r]un_readiness.py|[c]heck_i386_holdout_release.py"],
                                    capture_output=True, text=True, check=False)
    if competing.returncode != 1:
        raise ValueError("collector/stager/release process remains")
    return {"status": "accepted_readiness_release", "collection_ready": True,
            "full_collection_started": False, "malware_executions": 0,
            "snapshot": readiness["snapshot"], "snapshot_uuid": json.loads((attempt / "staged_snapshot.json").read_text())["CurrentSnapshotUUID"],
            "readiness_sha256": gates.digest(attempt / "readiness.json"),
            "protocol_sha256": gates.digest(release / "protocol.json"),
            "order_sha256": gates.digest(release / "case_order.json"),
            "preregistration_sha256": gates.digest(release / "preregistration.json"),
            "allocation_sha256": gates.digest(release.parent.parent / "allocation.json"),
            "auditor_sha256": gates.digest(Path(__file__)),
            "benign_workloads_accepted": 100, "dry_run_cases": 204,
            "smoke_cases": len(measured["cases"]),
            "pcap_records": sum(row["pcap_records"] for row in measured["cases"]),
            "archive_members": sum(row["archive_members"] for row in measured["cases"]),
            "finite_cells": sum(row["finite_cells"] for row in measured["cases"]),
            "activity_floors": measured["activity_floors"], "negative_audit_probes": negatives,
            "current_vm_state": current, "limitations": protocol["limitations"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate_attempt", type=Path)
    parser.add_argument("--output-name", default="release_assessment.json")
    args = parser.parse_args()
    if Path(args.output_name).name != args.output_name:
        raise ValueError("output name must be a basename")
    attempt = args.gate_attempt.resolve()
    output = attempt / args.output_name
    if output.exists():
        raise FileExistsError("preserve previous audit output")
    report = audit(attempt)
    gates.native.write_json(output, report)
    print(json.dumps({key: value for key, value in report.items() if key not in {"current_vm_state", "limitations"}}, indent=2))


if __name__ == "__main__":
    main()