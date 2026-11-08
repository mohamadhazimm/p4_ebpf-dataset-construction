#!/usr/bin/env python3
"""Check four actual expansion controls through the pinned batch collector."""

from __future__ import annotations

import argparse
import base64
import csv
import fcntl
import hashlib
import io
import json
import math
import subprocess
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import prepare_native_guest_preflight as preparation
import run_native_checks as native_checks


ROOT = preparation.ROOT
STUDY = preparation.STUDY
WORKLOAD_ATTEMPT = ROOT / "operational-readiness/20261021T195042849982Z"
HELPER = native_checks.previous_readiness


def freeze():
    HELPER.verify_production()
    source_report = WORKLOAD_ATTEMPT / "guest_preflight.json"
    if preparation.digest(source_report) != "a1bc66240428dc91ac96974924e8f729c3b9e0f5e03d08d530f564e4f2e33814":
        raise ValueError("accepted guest workload report changed")
    report = json.loads(source_report.read_text())
    manifest = json.loads((WORKLOAD_ATTEMPT / "manifest.json").read_text())
    if report["status"] != "accepted" or report["accepted"] != 100:
        raise ValueError("all 100 guest workloads must pass first")
    for name, expected in manifest["inputs"].items():
        if preparation.digest(STUDY / name) != expected:
            raise ValueError("frozen workload input differs: " + name)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "operational-readiness" / (run_id + "-sensors")
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/native-control-sensors-" + run_id
    fixture = preparation.PREPARATION / "x64-workspace-seed/fixture.txt"
    fixture_data = fixture.read_bytes()
    if preparation.digest(fixture) != manifest["fixtures"]["fixture.txt"]:
        raise ValueError("workload fixture changed")
    cases = []
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        def add(name, data):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), 0o644
            archive.addfile(member, io.BytesIO(data))

        add("fixture.txt", fixture_data)
        for row in manifest["cases"]:
            if row["program"] not in {"b2sum", "sha1sum"}:
                continue
            data = (STUDY / row["source"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != row["sha256"]:
                raise ValueError("control identity changed")
            packed = io.BytesIO()
            with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as transport:
                member = zipfile.ZipInfo(row["program"])
                member.external_attr = 0o100755 << 16
                transport.writestr(member, data)
            sample = row["case_id"] + ".zip"
            add("samples/" + sample, packed.getvalue())
            arguments = [guest_root + "/fixture.txt"]
            add("arguments/" + sample + ".json", json.dumps(arguments).encode())
            expected = (hashlib.blake2b(fixture_data).hexdigest() if row["program"] == "b2sum"
                        else hashlib.sha1(fixture_data).hexdigest())
            cases.append({**row, "sample": sample, "arguments": arguments,
                          "transport_sha256": hashlib.sha256(packed.getvalue()).hexdigest(),
                          "expected_stdout": expected + "  " + arguments[0] + "\n"})
    if len(cases) != 4:
        raise ValueError("expected four actual native controls")
    (attempt / "payload.tgz").write_bytes(payload.getvalue())
    setup = '''#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64, hashlib, io, tarfile
from pathlib import Path
root = Path(GUEST_ROOT)
data = base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest() != EXPECTED_HASH:
    raise SystemExit('existing guest path or changed sensor payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    seen = set()
    for member in archive:
        target = root / member.name
        if not member.isfile() or member.name in seen or not target.resolve().is_relative_to(root):
            raise SystemExit('unsafe sensor payload')
        seen.add(member.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.extractfile(member).read())
        target.chmod(0o644)
print('Four actual benign native sensor controls staged; no sample executed')
PY
'''
    setup = setup.replace("GUEST_ROOT", repr(guest_root)).replace("PAYLOAD", repr(base64.b64encode(payload.getvalue()).decode()))
    setup = setup.replace("EXPECTED_HASH", repr(preparation.digest(attempt / "payload.tgz")))
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "benign-only.txt").write_text("".join(row["sample"] + "\n" for row in cases))
    protocol = {"cases": cases, "schema": HELPER.SCHEMA, "production_hashes": HELPER.PINNED,
                "baseline": manifest["snapshot"], "snapshot": "clean-native-control-sensors-v18-" + run_id,
                "guest_root": guest_root, "collection_ready": False, "malware_executions": 0,
                "input_hashes": {str(path.relative_to(STUDY)): preparation.digest(path) for path in
                                 (source_report, WORKLOAD_ATTEMPT / "manifest.json", Path(__file__),
                                  attempt / "payload.tgz", attempt / "setup_guest.sh", attempt / "benign-only.txt")},
                "limitations": ["Four actual benign controls, not all-100 sensor validation or stress certification.",
                                "No new null calibration, grouped split or full collection release."]}
    native_checks.write_json(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "cases": len(cases), "collection_ready": False}), flush=True)
    return attempt, protocol


def audit(attempt, protocol):
    from scapy.utils import RawPcapReader

    results = []
    for case in protocol["cases"]:
        sample = attempt / "runs" / case["sample"]
        paths = list((sample / "output").glob("run_*/run.json"))
        if len(paths) != 1 or "status=completed" not in (sample / "host_run.txt").read_text().split():
            raise ValueError("retrieval incomplete: " + case["sample"])
        metadata = json.loads(paths[0].read_text())
        if metadata["telemetry_schema_version"] != HELPER.SCHEMA or metadata["malware_runner_sha256"] != HELPER.PINNED["src/malware_runner.py"]:
            raise ValueError("runner provenance differs")
        if metadata["collection_quality_status"] != "accepted" or any(metadata.get(key) != 0 for key in (
                "ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel")):
            raise ValueError("sensor quality failed")
        if metadata["ebpf_status"] != "active" or metadata["packet_capture_status"] != "active":
            raise ValueError("sensor inactive")
        execution, artifact = metadata["target_exec"], metadata["target_artifact"]
        expected_mode = "native_compat" if case["arch"] == "i386" else "native"
        if (execution["status"] != "observed" or execution["match"] != "exact" or metadata["return_code"] != 0
                or Path(execution["expected_path"]).name != case["program"]
                or artifact["e_machine"] != case["machine"] or artifact["linkage"] != "static"
                or artifact["execution_mode"] != expected_mode):
            raise ValueError("target exec/mode differs")
        features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
        with (paths[0].parent / "telemetry.csv").open(newline="") as source:
            telemetry = list(csv.DictReader(source))
        if len(features) != 169 or len(set(features)) != 169 or len(telemetry) != 40:
            raise ValueError("feature/observation contract differs")
        if not all(math.isfinite(float(row[name])) for row in telemetry for name in features):
            raise ValueError("missing or nonfinite features")
        if (paths[0].parent / "sample.stdout.log").read_text() != case["expected_stdout"]:
            raise ValueError("sensor workload digest output differs")
        with RawPcapReader(str(paths[0].parent / "packet_capture.pcap")) as reader:
            records = sum(1 for packet in reader)
        statistics = metadata["packet_capture_statistics"]
        if records != statistics["packets_captured"] or records != statistics["packets_received_by_filter"]:
            raise ValueError("PCAP record counts differ")
        results.append({"sample": case["sample"], "arch": case["arch"], "status": "accepted",
                        "pcap_records": records, "archive_members": HELPER.verify_output_archive(sample),
                        "finite_cells": len(telemetry) * len(features),
                        "post_target_syscalls": execution["post_target_lineage_raw_syscalls"]})
    return {"status": "accepted_bounded_actual_controls", "cases": results,
            "collection_ready": False, "malware_executions": 0,
            "limitations": protocol["limitations"]}


def execute(attempt, protocol):
    HELPER.verify_production()
    initial = {"guest": HELPER.isolated(HELPER.VM), "sink": HELPER.isolated("Sink")}
    if initial["guest"]["VMState"] != '"poweroff"' or initial["sink"]["VMState"] != '"running"':
        raise ValueError("guest must be off and isolated Sink running")
    competing = subprocess.run(["pgrep", "-af", "[v]box_malware_batch|[s]tage_versioned_runner|[r]un_versioned_cohorts|[r]un_readiness.py|[p]repare_native_guest_preflight.py"],
                              capture_output=True, text=True, check=False)
    if competing.returncode != 1:
        raise ValueError("competing collector or stager exists")
    native_checks.write_json(attempt / "initial_vm_state.json", initial)
    try:
        with (attempt / "staging.log").open("w") as log:
            subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", HELPER.VM,
                            "--guest-user", HELPER.GUEST_USER, "--baseline-snapshot", protocol["baseline"],
                            "--new-snapshot", protocol["snapshot"], "--schema-version", HELPER.SCHEMA,
                            "--guest-setup", str(attempt / "setup_guest.sh")],
                           stdout=log, stderr=subprocess.STDOUT, cwd=STUDY, check=True)
        staged = HELPER.isolated(HELPER.VM)
        if staged["CurrentSnapshotName"] != '"' + protocol["snapshot"] + '"':
            raise ValueError("staged sensor snapshot differs")
        native_checks.write_json(attempt / "staged_snapshot.json", staged)
        command = ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"), "--vm", HELPER.VM,
                   "--guest-user", HELPER.GUEST_USER, "--guest-malware-dir", protocol["guest_root"] + "/samples",
                   "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", protocol["snapshot"],
                   "--sample-list", str(attempt / "benign-only.txt"), "--schema-version", HELPER.SCHEMA,
                   "--guest-arguments-dir", protocol["guest_root"] + "/arguments", "--timeout", "20",
                   "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf", "--fixed-observation", "--common-launch-wrapper"]
        for dry in (True, False):
            with (attempt / ("dry-run.log" if dry else "collection.log")).open("w") as log:
                subprocess.run(command + ["--output-dir", str(attempt / ("dry-run" if dry else "runs"))]
                               + (["--dry-run"] if dry else []), stdout=log, stderr=subprocess.STDOUT,
                               cwd=STUDY, check=True)
            if dry and (attempt / "dry-run.log").read_text().count("Validated sample: ") != 4:
                raise ValueError("four-control dry-run incomplete")
        HELPER.verify_production()
        for name, expected in protocol["input_hashes"].items():
            if preparation.digest(STUDY / name) != expected:
                raise ValueError("frozen sensor input changed: " + name)
        result = audit(attempt, protocol)
        native_checks.write_json(attempt / "validation.json", result)
        print(json.dumps(result, indent=2), flush=True)
    finally:
        if HELPER.vm_info(HELPER.VM)["VMState"] != '"poweroff"':
            HELPER.vbox("controlvm", HELPER.VM, "poweroff")
        HELPER.vbox("snapshot", HELPER.VM, "restore", HELPER.ORIGINAL)
        final = {"guest": HELPER.isolated(HELPER.VM), "sink": HELPER.isolated("Sink")}
        native_checks.write_json(attempt / "final_vm_state.json", final)
        if final["guest"]["VMState"] != '"poweroff"' or final["guest"]["CurrentSnapshotName"] != '"' + HELPER.ORIGINAL + '"':
            raise ValueError("sensor cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-benign-checks", action="store_true")
    args = parser.parse_args()
    with (prepare_inventory_path := preparation.prepare_inventory.PREPARATION / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt, protocol = freeze()
        if args.execute_benign_checks:
            try:
                execute(attempt, protocol)
            except Exception as error:
                native_checks.write_json(attempt / "failure.json", {
                    "status": "not_accepted", "error": str(error), "collection_ready": False})
                raise


if __name__ == "__main__":
    main()