#!/usr/bin/env python3
"""Reproduce saved readiness evidence without a VM operation or sample execution."""

import argparse
import copy
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import ready_matched45 as ready


def package_check(release):
    ready.verify_release(release)
    manifest = ready.load(release / "manifest.json")
    cases = manifest["cases"]
    order = ready.load(release / "case_order.json")
    if len(cases) != 96 or len({row["sample"] for row in cases}) != 96:
        raise ValueError("Release count/unique transport contract differs")
    if Counter(row["label"] for row in cases) != {"malware": 45, "benign": 45, "null": 6}:
        raise ValueError("Release label budgets differ")
    expected = Counter({("training", "native_amd64_dynamic"): 5,
        ("training", "native_amd64_static"): 16, ("training", "native_i386_static"): 6,
        ("validation", "native_amd64_static"): 3, ("validation", "native_i386_static"): 15})
    for label in ("malware", "benign"):
        if Counter((row["split"], row["mode"]) for row in cases if row["label"] == label) != expected:
            raise ValueError("Matched mode/split quotas differ")
    if {row["sample"] for row in order} != {row["sample"] for row in cases}:
        raise ValueError("Frozen order and manifest differ")
    import hashlib
    import io
    import tarfile
    import zipfile
    with tarfile.open(release / "payload.tgz", "r:gz") as archive:
        members = archive.getmembers()
        if len({member.name for member in members}) != len(members):
            raise ValueError("Duplicate package entries")
        for member in members:
            if member.name.startswith("/") or ".." in Path(member.name).parts or not (member.isfile() or member.isdir()):
                raise ValueError("Unsafe package entry")
        for case in cases:
            data = archive.extractfile("samples/" + case["sample"]).read()
            if hashlib.sha256(data).hexdigest() != case["transport_sha256"]:
                raise ValueError("Packaged transport changed")
            arguments = json.load(archive.extractfile("arguments/" + case["sample"] + ".json"))
            if arguments != case["collection_arguments"]:
                raise ValueError("Packaged collection arguments changed")
            if case["label"] in {"benign", "null"}:
                with zipfile.ZipFile(io.BytesIO(data)) as transport:
                    if transport.namelist() != [case["program"]]:
                        raise ValueError("Original executable basename changed")
                    binary = transport.read(case["program"])
                    if hashlib.sha256(binary).hexdigest() != case["sha256"] or not binary.startswith(b"\x7fELF"):
                        raise ValueError("Packaged benign/null ELF identity changed")
        for case in cases:
            if case["label"] == "benign":
                for name, expected_hash in case["fixture_hashes"].items():
                    path = "fixtures/" + case["case_id"] + "/" + name
                    if hashlib.sha256(archive.extractfile(path).read()).hexdigest() != expected_hash:
                        raise ValueError("Fixture identity changed")
    return {"status": "accepted_package", "cases": 96, "malware_executions": 0}


def audit(attempt):
    release = attempt.parent.parent
    package = package_check(release)
    accepted = ready.load(attempt / "readiness.json")
    if not accepted["collection_ready"] or accepted["full_collection_started"] or accepted["malware_executions"]:
        raise ValueError("Saved readiness status does not permit a bounded release")
    if ready.digest(release / "protocol.json") != accepted["protocol_sha256"]:
        raise ValueError("Saved release protocol changed")
    for name, expected in accepted["evidence_hashes"].items():
        if ready.digest(attempt / name) != expected:
            raise ValueError("Saved evidence changed: " + name)
    evidence = ready.audit(attempt, release)
    if evidence != ready.load(attempt / "sensor_validation.json"):
        raise ValueError("Sensor report does not reproduce")
    guest = ready.load(attempt / "guest_preflight.json")
    if guest["accepted"] != 45 or guest["total"] != 45 or guest["status"] != "accepted":
        raise ValueError("All45 guest checks required")
    final = ready.load(attempt / "final_vm_state.json")
    for name in ("guest", "sink"):
        state = final[name]
        if state["nic1"] != '"intnet"' or state["intnet1"] != '"malnet"' or any(state["nic" + str(index)] != '"none"' for index in range(2, 9)):
            raise ValueError("Saved isolation differs")
    if final["guest"]["VMState"] != '"poweroff"' or final["guest"]["CurrentSnapshotName"] != '"' + ready.helper.ORIGINAL + '"':
        raise ValueError("Saved original clean powered-off state differs")
    first = (release / "benign-smoke.txt").read_text().splitlines()[0]
    metadata_path = next((attempt / "runs" / first / "output").glob("run_*/run.json"))
    original_load = ready.load
    negative_probes = {}
    for label in ("packet_discrepancy", "ebpf_loss", "target_exec_absent"):
        modified = copy.deepcopy(original_load(metadata_path))
        if label == "packet_discrepancy":
            modified["packet_capture_counter_discrepancy"] = 1
        elif label == "ebpf_loss":
            modified["ebpf_lost_event_count"] = 1
        else:
            modified["target_exec"]["status"] = "not_observed"

        def injected_load(path):
            return modified if Path(path) == metadata_path else original_load(path)

        with patch.object(ready, "load", side_effect=injected_load):
            try:
                ready.audit(attempt, release)
            except ValueError:
                negative_probes[label] = "rejected"
            else:
                raise ValueError("Readiness accepted negative probe: " + label)
    return {"status": "accepted_saved_readiness", "package": package, "negative_probes": negative_probes,
        "sensor_cases": len(evidence["cases"]), "guest_workloads": guest["accepted"],
        "finite_cells": sum(row["finite_cells"] for row in evidence["cases"]),
        "archive_members": sum(row["archive_members"] for row in evidence["cases"]),
        "pcap_records": sum(row["pcap_records"] for row in evidence["cases"]),
        "activity_floors": evidence["activity_floors"], "readiness_sha256": ready.digest(attempt / "readiness.json"),
        "release_protocol_sha256": ready.digest(release / "protocol.json"),
        "auditor_sha256": ready.digest(Path(__file__)), "vm_operations": 0, "sample_executions": 0,
        "limitations": evidence["limitations"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--package-only", action="store_true")
    args = parser.parse_args()
    path = args.path.resolve()
    if args.package_only:
        print(json.dumps(package_check(path), indent=2))
        return
    report = audit(path)
    output = path / ("readiness-recheck-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    ready.save(output, report)
    print(json.dumps({**report, "report": str(output)}, indent=2))


if __name__ == "__main__":
    main()