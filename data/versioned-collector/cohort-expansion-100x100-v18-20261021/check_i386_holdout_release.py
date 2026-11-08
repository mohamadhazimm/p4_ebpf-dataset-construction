#!/usr/bin/env python3
"""Verify the amended common snapshot without launching malware collection."""

from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import math
import os
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import prepare_i386_holdout_collection as preparation


ROOT = preparation.ROOT
STUDY = preparation.STUDY
HELPER = preparation.HELPER
native = preparation.guest_checks.native
digest = preparation.validation_checks.allocation.digest


def audit(attempt, release, protocol):
    from scapy.utils import RawPcapReader

    names = (release / "benign-smoke.txt").read_text().splitlines()
    cases = {row["sample"]: row for row in protocol["cases"]}
    results = []
    null_counts = {"amd64": [], "i386": []}
    for name in names:
        case = cases[name]
        if case["label"] not in {"benign", "null"}:
            raise ValueError("malware forbidden in readiness smoke")
        sample = attempt / "runs" / name
        paths = list((sample / "output").glob("run_*/run.json"))
        if len(paths) != 1 or "status=completed" not in (sample / "host_run.txt").read_text().split():
            raise ValueError("retrieval incomplete")
        metadata = json.loads(paths[0].read_text())
        if metadata["telemetry_schema_version"] != HELPER.SCHEMA or metadata["malware_runner_sha256"] != HELPER.PINNED["src/malware_runner.py"]:
            raise ValueError("runner provenance differs")
        if metadata["collection_quality_status"] != "accepted" or any(metadata.get(key) != 0 for key in (
                "ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel")):
            raise ValueError("sensor quality failed")
        if metadata["ebpf_status"] != "active" or metadata["packet_capture_status"] != "active":
            raise ValueError("sensor inactive")
        execution, artifact = metadata["target_exec"], metadata["target_artifact"]
        mode = "native_compat" if case["arch"] == "i386" else "native"
        if (execution["status"] != "observed" or execution["match"] != "exact" or metadata["return_code"] != 0
                or Path(execution["expected_path"]).name != case["program"]
                or artifact["e_machine"] != case["machine"] or artifact["linkage"] != "static"
                or artifact["execution_mode"] != mode):
            raise ValueError("target exec/mode differs: " + name)
        features = [feature for group in metadata["telemetry_feature_groups"].values() for feature in group]
        with (paths[0].parent / "telemetry.csv").open(newline="") as stream:
            telemetry = list(csv.DictReader(stream))
        if len(features) != 169 or len(set(features)) != 169 or len(telemetry) != 40:
            raise ValueError("feature/observation contract differs")
        if not all(math.isfinite(float(row[feature])) for row in telemetry for feature in features):
            raise ValueError("nonfinite features")
        stdout = (paths[0].parent / "sample.stdout.log").read_text()
        if case["label"] == "null":
            if stdout:
                raise ValueError("null emitted stdout")
            null_counts[case["arch"]].append(execution["post_target_lineage_raw_syscalls"])
        elif case["program"] == "tput":
            if stdout != "80\n":
                raise ValueError("terminal fixture unavailable in collector")
        elif case["program"] == "unshar":
            data = (paths[0].parent / "workspace/fixture.txt").read_bytes()
            expected = protocol["fixture_hashes"]["validation"]["fixture.txt"]
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("collector extraction content differs")
        elif case["program"] == "mke2fs":
            with (paths[0].parent / "workspace/created.img").open("rb") as stream:
                stream.seek(1080)
                if stream.read(2) != b"\x53\xef":
                    raise ValueError("collector filesystem image invalid")
        with RawPcapReader(str(paths[0].parent / "packet_capture.pcap")) as reader:
            records = sum(1 for packet in reader)
        statistics = metadata["packet_capture_statistics"]
        if records != statistics["packets_captured"] or records != statistics["packets_received_by_filter"]:
            raise ValueError("PCAP counts differ")
        if metadata["ebpf_event_diagnostics"].get("raw_syscalls_unresolved_abi") != 0:
            raise ValueError("unresolved ABI")
        results.append({"sample": name, "arch": case["arch"], "label": case["label"], "status": "accepted",
                        "archive_members": HELPER.verify_output_archive(sample), "pcap_records": records,
                        "finite_cells": len(features) * len(telemetry),
                        "post_target_syscalls": execution["post_target_lineage_raw_syscalls"]})
    if any(len(counts) != 2 for counts in null_counts.values()):
        raise ValueError("per-mode null repeats incomplete")
    return {"status": "accepted_bounded_benign_null_smoke", "cases": results,
            "null_maxima": {arch: max(counts) for arch, counts in null_counts.items()},
            "activity_floors": {arch: max(counts) + 25 for arch, counts in null_counts.items()},
            "malware_executions": 0, "full_collection_started": False,
            "limitations": ["Seven benign/null cases, not all-case sensor/stress certification.",
                            "Activity floors are descriptive, not primary exclusions or delivery tests."]}


def execute(release):
    HELPER.verify_production()
    protocol = json.loads((release / "protocol.json").read_text())
    manifest = json.loads((release / "manifest.json").read_text())
    for name, expected in protocol["input_hashes"].items():
        if digest(STUDY / name) != expected:
            raise ValueError("frozen input changed: " + name)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = release / "gates" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    snapshot = "clean-native-heldout-gates-v18-" + run_id
    native.write_json(attempt / "gate_protocol.json", {"release_protocol_sha256": digest(release / "protocol.json"),
        "driver_sha256": digest(Path(__file__)), "snapshot": snapshot, "malware_executions": 0,
        "scope": "100 benign direct checks, 204 dry-runs, seven benign/null captures; no malware execution."})
    initial = {"guest": HELPER.isolated(HELPER.VM), "sink": HELPER.isolated("Sink")}
    if initial["guest"]["VMState"] != '"poweroff"' or initial["sink"]["VMState"] != '"running"':
        raise ValueError("guest must be off and Sink isolated/running")
    competing = subprocess.run(["pgrep", "-af", "[v]box_malware_batch|[s]tage_versioned_runner|[r]un_versioned_cohorts|[r]un_readiness.py"],
                               capture_output=True, text=True, check=False)
    if competing.returncode != 1:
        raise ValueError("competing collector/stager")
    native.write_json(attempt / "initial_vm_state.json", initial)
    try:
        with (attempt / "staging.log").open("w") as log:
            subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
                            "--vm", HELPER.VM, "--guest-user", HELPER.GUEST_USER,
                            "--baseline-snapshot", HELPER.BASELINE, "--new-snapshot", snapshot,
                            "--schema-version", HELPER.SCHEMA, "--guest-setup", str(release / "setup_guest.sh")],
                           stdout=log, stderr=subprocess.STDOUT, cwd=STUDY, check=True)
        staged = HELPER.isolated(HELPER.VM)
        if staged["CurrentSnapshotName"] != '"' + snapshot + '"':
            raise ValueError("snapshot differs")
        native.write_json(attempt / "staged_snapshot.json", staged)
        with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-release-auth-") as password:
            os.chmod(password.name, 0o600)
            password.write(HELPER.credentials())
            password.flush()
            auth = ["--username", HELPER.GUEST_USER, "--passwordfile", password.name]
            with (attempt / "guest_ready.log").open("w") as log:
                for probe in range(3):
                    waiter = subprocess.Popen(["VBoxManage", "guestproperty", "wait", HELPER.VM,
                        "/VirtualBox/GuestInfo/OS/LoggedInUsers", "--timeout", "120000", "--fail-on-timeout"],
                        stdout=log, stderr=subprocess.STDOUT)
                    try:
                        if probe == 0:
                            HELPER.vbox("startvm", HELPER.VM, "--type", "headless")
                        if waiter.wait(timeout=150):
                            raise RuntimeError("guest readiness event timed out")
                    finally:
                        if waiter.poll() is None:
                            waiter.terminate()
                            waiter.wait()
                    ready = HELPER.vbox("guestcontrol", HELPER.VM, "run", *auth, "--exe", "/bin/true",
                        "--wait-stdout", "--wait-stderr", "--timeout", "5000", "--", check=False)
                    log.write(ready.stdout + ready.stderr)
                    log.flush()
                    if ready.returncode == 0:
                        break
                else:
                    raise RuntimeError("Guest Control not ready")
            print("Checking 100 benign workloads with exact collection arguments", flush=True)
            result = HELPER.vbox("guestcontrol", HELPER.VM, "run", *auth, "--exe", "/usr/bin/python3",
                "--wait-stdout", "--wait-stderr", "--timeout", "900000", "--",
                protocol["guest_root"] + "/collection_check.py", check=False)
            (attempt / "collection_preflight.log").write_text(result.stdout + result.stderr)
            HELPER.vbox("guestcontrol", HELPER.VM, "copyfrom", *auth,
                        protocol["guest_root"] + "/collection_preflight.json", str(attempt / "collection_preflight.json"))
            report = json.loads((attempt / "collection_preflight.json").read_text())
            if (result.returncode or report["status"] != "accepted" or report["accepted"] != 100
                    or {row["case_id"]: row["sha256"] for row in report["cases"]} != {
                        row["case_id"]: row["sha256"] for row in protocol["cases"] if row["label"] == "benign"}):
                raise RuntimeError("collection-form benign workloads did not all pass")
        HELPER.vbox("controlvm", HELPER.VM, "poweroff")
        HELPER.vbox("snapshot", HELPER.VM, "restore", snapshot)
        command = ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"), "--vm", HELPER.VM,
                   "--guest-user", HELPER.GUEST_USER, "--guest-malware-dir", protocol["guest_root"] + "/samples",
                   "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", snapshot,
                   "--schema-version", HELPER.SCHEMA, "--guest-arguments-dir", protocol["guest_root"] + "/arguments",
                   "--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
                   "--fixed-observation", "--common-launch-wrapper"]
        for dry in (True, False):
            names = release / ("all-cases.txt" if dry else "benign-smoke.txt")
            if not dry:
                cases = {row["sample"]: row for row in protocol["cases"]}
                if any(cases[name]["label"] not in {"benign", "null"} for name in names.read_text().splitlines()):
                    raise ValueError("malware forbidden in readiness")
            print("Validating all 204 transports" if dry else "Collecting seven benign/null sensor cases", flush=True)
            with (attempt / ("dry-run.log" if dry else "collection.log")).open("w") as log:
                subprocess.run(command + ["--sample-list", str(names), "--output-dir",
                    str(attempt / ("dry-run" if dry else "runs"))] + (["--dry-run"] if dry else []),
                    stdout=log, stderr=subprocess.STDOUT, cwd=STUDY, check=True)
            if dry and (attempt / "dry-run.log").read_text().count("Validated sample: ") != 204:
                raise ValueError("all-case dry-run incomplete")
        protocol["fixture_hashes"] = manifest["fixtures"]
        validation = audit(attempt, release, protocol)
        native.write_json(attempt / "sensor_validation.json", validation)
        HELPER.verify_production()
        for name, expected in protocol["input_hashes"].items():
            if digest(STUDY / name) != expected:
                raise ValueError("frozen input changed during readiness")
        native.write_json(attempt / "readiness.json", {"collection_ready": True, "full_collection_started": False,
            "malware_executions": 0, "snapshot": snapshot, "release": str(release.relative_to(STUDY)),
            "production_hashes": HELPER.PINNED, "guest_preflight_sha256": digest(attempt / "collection_preflight.json"),
            "sensor_validation_sha256": digest(attempt / "sensor_validation.json"),
            "protocol_sha256": digest(release / "protocol.json"), "gate_protocol_sha256": digest(attempt / "gate_protocol.json"),
            "activity_floors": validation["activity_floors"], "limitations": protocol["limitations"]})
        print(json.dumps({"attempt": str(attempt), "collection_ready": True, "malware_executions": 0}), flush=True)
    except Exception as error:
        native.write_json(attempt / "failure.json", {"error": str(error), "collection_ready": False,
                                                   "malware_executions": 0})
        raise
    finally:
        if HELPER.vm_info(HELPER.VM)["VMState"] != '"poweroff"':
            HELPER.vbox("controlvm", HELPER.VM, "poweroff")
        HELPER.vbox("snapshot", HELPER.VM, "restore", HELPER.ORIGINAL)
        final = {"guest": HELPER.isolated(HELPER.VM), "sink": HELPER.isolated("Sink")}
        native.write_json(attempt / "final_vm_state.json", final)
        if final["guest"]["VMState"] != '"poweroff"' or final["guest"]["CurrentSnapshotName"] != '"' + HELPER.ORIGINAL + '"':
            raise ValueError("cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    parser.add_argument("--execute-benign-checks", action="store_true", required=True)
    args = parser.parse_args()
    with (preparation.validation_checks.allocation.prepare_inventory.PREPARATION / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        execute(args.release.resolve())


if __name__ == "__main__":
    main()