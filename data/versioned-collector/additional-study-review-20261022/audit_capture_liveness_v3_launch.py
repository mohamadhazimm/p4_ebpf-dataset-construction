#!/usr/bin/env python3
"""Audit a preserved V3 pre-control staging failure without operating a VM."""

import argparse
import ast
import hashlib
import io
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import capture_liveness as checks


def cleanup(state):
    checks.require(state["guest"]["VMState"] == '"poweroff"' and
                   state["guest"]["CurrentSnapshotName"] == '"clean-tls-paired-2026-10-19"' and
                   state["guest"]["CurrentSnapshotUUID"] == '"72de0a02-2e71-42b8-85e2-78c21d6b00f9"' and
                   state["sink"]["VMState"] == '"running"', "Saved clean VM state differs")
    for kind in ("guest", "sink"):
        checks.require(state[kind]["nic1"] == '"intnet"' and state[kind]["intnet1"] == '"malnet"' and
                       all(state[kind]["nic" + str(number)] == '"none"' for number in range(2, 9)),
                       "Saved NIC isolation differs: " + kind)


def audit(attempt):
    protocol = json.loads((attempt / "protocol.json").read_text())
    manifest = json.loads((attempt / "manifest.json").read_text())
    checks.require(protocol["schema"] == manifest["schema"] == "2026-10-23.23-capture-liveness-lifecycle-diagnostic",
                   "Not the preserved V3 launch")
    for path, expected in protocol["source_hashes"].items():
        checks.require(checks.digest(path) == expected, "Frozen source changed: " + path)
    for name, expected in protocol["files"].items():
        checks.require(checks.digest(attempt / name) == expected, "Frozen transport changed: " + name)
    failure = json.loads((attempt / "failure.json").read_text())
    checks.require(failure == {"error": "ValueError: Guest login event timed out", "collection_ready": False},
                   "Unexpected failure boundary")
    checks.require(not any((attempt / name).exists() for name in
                          ("guest-probe.log", "guest_result.json", "evidence.tgz")),
                   "Control invocation/evidence exists; this zero-control audit does not apply")
    checks.require("Time out or interruption" in (attempt / "guest-login.log").read_text(), "Missing original timeout log")
    checks.require("Created verified runner snapshot: " + manifest["snapshot"] in (attempt / "staging.log").read_text(),
                   "Snapshot staging did not complete")
    staged = json.loads((attempt / "staged_snapshot.json").read_text())
    checks.require(staged["CurrentSnapshotName"] == '"' + manifest["snapshot"] + '"', "Staged child differs")
    with tarfile.open(attempt / "payload.tgz", "r:gz") as archive:
        members = archive.getmembers()
        checks.require(len(members) <= 32 and len({item.name for item in members}) == len(members) and
                       sum(item.size for item in members) <= 32 * 1024 * 1024, "Payload member bounds differ")
        checks.require(all(item.isfile() and Path(item.name).name == item.name and item.size < 16 * 1024 * 1024
                           for item in members), "Unsafe payload member")
        payload = {item.name: archive.extractfile(item).read() for item in members}
    checks.require(set(payload) == set(manifest["files"]) | {"manifest.json"} and
                   json.loads(payload["manifest.json"]) == manifest, "Payload manifest differs")
    for name, expected in manifest["files"].items():
        checks.require(hashlib.sha256(payload[name]).hexdigest() == expected, "Payload member hash differs: " + name)
        if name.endswith(".py"):
            compile(payload[name], name, "exec")
    case_ids = ["original-pre", "original-quiet", "original-post", "full-pre", "full-quiet", "full-post"]
    checks.require([case["case"] for case in manifest["cases"]] == case_ids and
                   sum(case["helper_transactions"] for case in manifest["cases"]) == 4, "Prospective order/budget differs")
    for case in manifest["cases"]:
        checks.validate_arguments(case["target_arguments"])
    base = ast.parse((Path(__file__).resolve().parents[3] / "src/malware_runner.py").read_text())
    generated = ast.parse(payload["integrated_runner.py"])
    helper_asts = lambda tree: {node.name: ast.dump(node) for node in tree.body
                               if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    checks.require(helper_asts(base) == helper_asts(generated), "Original helper ASTs changed")
    for name in ("initial_vm_state.json", "final_vm_state.json"):
        cleanup(json.loads((attempt / name).read_text()))
    for kind in ("guest", "sink"):
        state = json.loads((attempt / "final_vm_state.json").read_text())
        state[kind]["nic1"] = '"nat"'
        try:
            cleanup(state)
        except ValueError:
            pass
        else:
            raise AssertionError("Altered isolation accepted")
    return {"status": "failed_before_control_invocation_audited_not_liveness_or_collection_accepted",
            "schema": manifest["schema"], "snapshot": manifest["snapshot"],
            "snapshot_uuid": staged["CurrentSnapshotUUID"], "failure": failure,
            "diagnostic_controls_invoked_by_launcher": 0, "positive_transactions_invoked_by_launcher": 0,
            "payload_members": len(members), "frozen_source_hashes_checked": len(protocol["source_hashes"]),
            "saved_isolation_corruption_guards": 2, "collection_ready": False, "performance_accepted": False,
            "malware_executions": 0, "auditor_sha256": checks.digest(__file__),
            "artifact_hashes": {name: checks.digest(attempt / name) for name in
                               ("protocol.json", "manifest.json", "payload.tgz", "failure.json", "guest-login.log",
                                "staging.log", "staged_snapshot.json", "initial_vm_state.json", "final_vm_state.json")},
            "limitations": "No actual V3 control, FINISH timing, recorder attachment or six-case evidence. Timeout does not prove guest unavailability or its cause. Saved cleanup is not a later fresh inspection."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    options = parser.parse_args()
    result = audit(options.attempt.resolve())
    output = options.attempt / ("launch-audit-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    with output.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "output": str(output), "collection_ready": False}, indent=2))