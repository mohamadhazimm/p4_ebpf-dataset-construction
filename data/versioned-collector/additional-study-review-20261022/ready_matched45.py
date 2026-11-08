#!/usr/bin/env python3
"""Freeze/test the matched extension; never execute malware or train models."""

import argparse
import base64
import csv
import fcntl
import io
import json
import math
import os
import random
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matched45_workloads as workloads
from audit_original_cohorts import elf_header
from prepare_matched45 import EXPANSION, NATIVE, ROOT, STUDY, digest, load


sys.path.insert(0, str(NATIVE))
import run_readiness as helper


IDENTITIES = ROOT / "matched45-identities/20261022T070700658382Z"
NATIVE_NULLS = EXPANSION / "native-checks/20261021T150457461296Z"
OLD_X64 = NATIVE / "readiness/20261021T104951987641Z"
SMOKE_PROGRAMS = {"ginstall", "env", "groups", "id", "lesskey", "lemon", "mkfifo",
                  "uuidgen", "e2undo", "blkid", "who", "resize2fs", "ipmaddr"}


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def packed_binary(name, content):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo(name)
        member.external_attr = 0o100755 << 16
        archive.writestr(member, content)
    return output.getvalue()


def null_binaries():
    protocol = load(NATIVE_NULLS / "protocol.json")
    result = {}
    with tarfile.open(NATIVE_NULLS / "payload.tgz", "r:gz") as archive:
        for arch in ("amd64", "i386"):
            case = next(row for row in protocol["cases"] if row["arch"] == arch and row["workload"] == "null")
            members = [member for member in archive.getmembers() if member.isfile() and member.name.endswith("/" + case["sample"])]
            if len(members) != 1:
                raise ValueError("Null transport ambiguous")
            encoded = archive.extractfile(members[0]).read()
            if __import__("hashlib").sha256(encoded).hexdigest() != case["transport_sha256"]:
                raise ValueError("Null transport differs")
            with zipfile.ZipFile(io.BytesIO(encoded)) as transport:
                names = transport.namelist()
                if len(names) != 1 or Path(names[0]).name != "busybox":
                    raise ValueError("Null binary basename differs")
                content = transport.read(names[0])
            if __import__("hashlib").sha256(content).hexdigest() != case["binary_sha256"]:
                raise ValueError("Null binary identity differs")
            result["native_" + arch + "_static"] = ("busybox", content, ["true"], case)
    with tarfile.open(OLD_X64 / "payload.tgz", "r:gz") as archive:
        content = archive.extractfile("samples/null-dynamic-01").read()
    expected = "b821a352d320baf9de8610ff0895e8c47bee60781674f5d9defa2c3ec9891b37"
    if __import__("hashlib").sha256(content).hexdigest() != expected:
        raise ValueError("Existing dynamic null changed")
    result["native_amd64_dynamic"] = ("null-dynamic", content, [], {"sha256": expected,
        "provenance": str(OLD_X64.relative_to(STUDY)), "fixture": "Previously validated source-built null C program"})
    for mode, (_program, content, _arguments, _provenance) in result.items():
        if elf_header(content)["mode"] != mode:
            raise ValueError("Null ELF mode differs")
    return result


def freeze(host):
    helper.verify_production()
    source_manifest = load(host / "manifest.json")
    host_report = load(host / "host_preflight.json")
    if (host_report["status"] != "accepted" or host_report["accepted"] != 45
            or source_manifest["checker_sha256"] != digest(Path(workloads.__file__))):
        raise ValueError("Need accepted current host workload checks")
    identities = load(IDENTITIES / "identity-readiness.json")
    if digest(IDENTITIES / "identity-readiness.json") != source_manifest["identity_readiness_sha256"]:
        raise ValueError("Identity allocation changed")
    for relative, expected in identities["input_hashes"].items():
        if digest(STUDY / relative) != expected:
            raise ValueError("Frozen identity input changed: " + relative)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    release = ROOT / "matched45-readiness" / stamp
    release.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/matched45-release-" + stamp
    cases = []
    for row in source_manifest["cases"]:
        case = {**row, "sample": row["case_id"].replace("+", "-plus-") + ".zip"}
        case["collection_arguments"] = [value.replace("{F}", guest_root + "/fixtures/" + case["case_id"])
                                        for value in case["argument_template"]]
        cases.append(case)
    for row in load(IDENTITIES / "malware-selection.json"):
        cases.append({**row, "label": "malware", "case_id": "malware-" + row["sha256"],
                      "sample": row["sha256"] + ".zip", "collection_arguments": []})
    nulls = null_binaries()
    for mode, (program, content, arguments, provenance) in sorted(nulls.items()):
        for repeat in (1, 2):
            cases.append({"label": "null", "split": "calibration", "mode": mode, "repeat": repeat,
                "program": program, "case_id": "null-" + mode + "-r" + str(repeat),
                "sample": "null-" + mode + "-r" + str(repeat) + ".zip",
                "sha256": __import__("hashlib").sha256(content).hexdigest(),
                "collection_arguments": arguments, "null_provenance": provenance})
    generator = random.Random(42)
    ordered = [case for case in cases if case["label"] == "null" and case["repeat"] == 1]
    for split in ("training", "validation"):
        for mode in sorted(nulls):
            benign = [case for case in cases if case["label"] == "benign" and case["split"] == split and case["mode"] == mode]
            malware = [case for case in cases if case["label"] == "malware" and case["split"] == split and case["mode"] == mode]
            if len(benign) != len(malware):
                raise ValueError("Per-mode label budgets differ")
            generator.shuffle(benign)
            generator.shuffle(malware)
            for pair in zip(benign, malware):
                pair = list(pair)
                generator.shuffle(pair)
                ordered.extend(pair)
    ordered.extend(case for case in cases if case["label"] == "null" and case["repeat"] == 2)
    if len(ordered) != 96 or len({case["sample"] for case in ordered}) != 96:
        raise ValueError("Expected 90 unique study cases and six null repetitions")
    if not all(re.fullmatch(r"[A-Za-z0-9._-]+", case["sample"]) for case in ordered):
        raise ValueError("Transport basename violates the pinned batch contract")
    for position, case in enumerate(ordered, 1):
        case["position"] = position
    manifest = {**source_manifest, "cases": cases, "guest_root": guest_root,
        "settings_required": identities["settings_required"], "collection_ready": False,
        "driver_sha256": digest(Path(__file__)), "full_collection_started": False, "malware_executions": 0}
    with tarfile.open(release / "payload.tgz", "w:gz") as archive:
        def add(name, data, mode=0o644):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), mode
            archive.addfile(member, io.BytesIO(data))

        for directory in ("fixtures", "binaries"):
            for path in sorted((host / directory).rglob("*")):
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise ValueError("Unsafe fixture/package entry")
                archive.add(path, arcname=str(path.relative_to(host)), recursive=False)
        for case in cases:
            if case["label"] == "benign":
                source = host / case["payload_path"]
                if digest(source) != case["sha256"]:
                    raise ValueError("Benign payload changed")
                content = packed_binary(case["program"], source.read_bytes())
            elif case["label"] == "malware":
                source = STUDY / case["source_archive_path"]
                if digest(source) != case["source_archive_sha256"]:
                    raise ValueError("Malware source changed")
                content = source.read_bytes()
                if content.startswith(b"\x7fELF"):
                    content = packed_binary(Path(case["source_archive_path"]).name, content)
            else:
                program, raw, _arguments, _provenance = nulls[case["mode"]]
                content = packed_binary(program, raw)
            case["transport_sha256"] = __import__("hashlib").sha256(content).hexdigest()
            add("samples/" + case["sample"], content, 0o600)
            add("arguments/" + case["sample"] + ".json", json.dumps(case["collection_arguments"]).encode())
        add("matched45_workloads.py", Path(workloads.__file__).read_bytes())
        add("manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode())
    save(release / "manifest.json", manifest)
    save(release / "case_order.json", ordered)
    (release / "all-cases.txt").write_text("".join(case["sample"] + "\n" for case in ordered))
    smoke = [case for case in ordered if case["label"] == "null" or
             (case["label"] == "benign" and case["program"] in SMOKE_PROGRAMS)]
    (release / "benign-smoke.txt").write_text("".join(case["sample"] + "\n" for case in smoke))
    preregistration = {**identities["protocol_inherited"], "frozen_utc": datetime.now(timezone.utc).isoformat(),
        "counts": {"training_per_label": 27, "validation_per_label": 18, "nulls": 6},
        "role": "Exploratory extension of the joint cohort; inherit group roles and global exclusions; no fresh confirmatory claim",
        "activation": "Fresh per-mode null maximum plus 25; descriptive only, retain low-activity primary cases",
        "sampling": "Frozen cap10 family/mode/hash allocation; no outcome-based malware filtering",
        "retries": "No automatic full-cohort retry, replacement, resume or model fitting",
        "quality": identities["settings_required"], "post_capture": identities["pending_gates"][-1],
        "benign_concentration": "All27 new training controls are Coreutils, not independent projects",
        "malware_executions": 0, "full_collection_started": False}
    save(release / "preregistration.json", preregistration)
    setup = """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(GUEST_ROOT)
data=base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest()!=EXPECTED:
    raise SystemExit('existing root or changed payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    seen=set()
    for member in archive:
        target=root/member.name
        if member.name in seen or not target.resolve().is_relative_to(root) or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe payload member')
        seen.add(member.name)
        if member.isdir():
            target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
            target.chmod(member.mode & 0o777)
print('96 transports staged; no target executed')
PY
"""
    setup = setup.replace("GUEST_ROOT", repr(guest_root)).replace("PAYLOAD", repr(base64.b64encode((release / "payload.tgz").read_bytes()).decode()))
    setup = setup.replace("EXPECTED", repr(digest(release / "payload.tgz")))
    (release / "setup_guest.sh").write_text(setup)
    inputs = {str(path.relative_to(STUDY)): digest(path) for path in (
        Path(__file__), Path(workloads.__file__), host / "manifest.json", host / "host_preflight.json",
        IDENTITIES / "identity-readiness.json", IDENTITIES / "malware-selection.json", IDENTITIES / "benign-executables.json",
        NATIVE_NULLS / "protocol.json", NATIVE_NULLS / "payload.tgz", OLD_X64 / "payload.tgz", Path(helper.__file__))}
    save(release / "protocol.json", {"guest_root": guest_root, "production_hashes": helper.PINNED,
        "input_hashes": inputs, "scope": "45 benign direct checks, 96 transport dry-runs and 19 benign/null captures only",
        "release_hashes": {name: digest(release / name) for name in (
            "manifest.json", "payload.tgz", "case_order.json", "all-cases.txt", "benign-smoke.txt", "preregistration.json", "setup_guest.sh")},
        "collection_ready": False, "malware_executions": 0, "full_collection_started": False})
    print(json.dumps({"release": str(release), "cases": 96, "smoke_cases": len(smoke), "collection_ready": False}), flush=True)
    return release


def verify_release(release):
    helper.verify_production()
    protocol = load(release / "protocol.json")
    for name, checksum in protocol["input_hashes"].items():
        if digest(STUDY / name) != checksum:
            raise ValueError("Frozen release input changed: " + name)
    for name, checksum in protocol["release_hashes"].items():
        if digest(release / name) != checksum:
            raise ValueError("Release payload/order changed: " + name)
    return protocol


def audit(attempt, release):
    from scapy.utils import RawPcapReader
    manifest = load(release / "manifest.json")
    cases = {case["sample"]: case for case in manifest["cases"]}
    results, null_counts = [], defaultdict(list)
    for name in (release / "benign-smoke.txt").read_text().splitlines():
        case = cases[name]
        if case["label"] not in {"benign", "null"}:
            raise ValueError("Malware forbidden in sensor readiness")
        sample = attempt / "runs" / name
        paths = list((sample / "output").glob("run_*/run.json"))
        if len(paths) != 1 or "status=completed" not in (sample / "host_run.txt").read_text().split():
            raise ValueError("Incomplete benign/null retrieval")
        metadata = load(paths[0])
        for key, value in manifest["settings_required"].items():
            if metadata.get(key) != value:
                raise ValueError("Sensor setting/quality differs: " + name + ":" + key)
        expected_machine = 3 if case["mode"] == "native_i386_static" else 62
        artifact, execution = metadata["target_artifact"], metadata["target_exec"]
        if (execution["status"] != "observed" or execution["match"] != "exact" or metadata["return_code"] != 0
                or artifact["e_machine"] != expected_machine
                or artifact["linkage"] != ("dynamic" if case["mode"].endswith("dynamic") else "static")
                or artifact["execution_mode"] != ("native_compat" if expected_machine == 3 else "native")
                or Path(execution["expected_path"]).name != case["program"]):
            raise ValueError("Exact target exec/architecture/linkage failed: " + name)
        if metadata["ebpf_event_diagnostics"].get("raw_syscalls_unresolved_abi") != 0:
            raise ValueError("Unresolved syscall ABI")
        if (metadata["packet_capture_rmem_max_before"] != metadata["packet_capture_rmem_max_after_capture"]
                or metadata["packet_capture_rmem_max_during_capture"] != 134217728):
            raise ValueError("Buffer restoration differs")
        link = metadata["packet_capture_interface_link_state_before_sample"]
        if link != {"operstate": "up", "carrier": 1}:
            raise ValueError("Interface link evidence differs")
        features = [feature for group in metadata["telemetry_feature_groups"].values() for feature in group]
        with (paths[0].parent / "telemetry.csv").open(newline="") as stream:
            telemetry = list(csv.DictReader(stream))
        if (len(telemetry) != 40 or len(set(features)) != 169 or len(features) != 169
                or not all(math.isfinite(float(row[feature])) for row in telemetry for feature in features)):
            raise ValueError("Finite 40x169 telemetry contract differs")
        with RawPcapReader(str(paths[0].parent / "packet_capture.pcap")) as reader:
            count = sum(1 for _packet in reader)
        statistics = metadata["packet_capture_statistics"]
        if count != statistics["packets_captured"] or count != statistics["packets_received_by_filter"]:
            raise ValueError("PCAP record/counter disagreement")
        stdout = (paths[0].parent / "sample.stdout.log").read_text()
        work = paths[0].parent / "workspace"
        if case["label"] == "null":
            if stdout:
                raise ValueError("Null emitted output")
            null_counts[case["mode"]].append(execution["post_target_lineage_raw_syscalls"])
        elif case["program"] == "ginstall":
            if (work / "installed.txt").read_bytes() != workloads.CONTENT:
                raise ValueError("Collected installed content differs")
        elif case["program"] == "env":
            if stdout != "ready\n":
                raise ValueError("Collected environment delivery differs")
        elif case["program"] == "lesskey":
            if not (work / "keys.bin").read_bytes().startswith(b"\x00M+G"):
                raise ValueError("Collected key compilation differs")
        elif case["program"] == "lemon":
            if "NUMBER" not in (work / "parser.h").read_text() or "Parse" not in (work / "parser.c").read_text():
                raise ValueError("Collected parser compilation differs")
        results.append({"sample": name, "mode": case["mode"], "label": case["label"],
            "archive_members": helper.verify_output_archive(sample), "pcap_records": count,
            "finite_cells": 40 * 169, "post_target_syscalls": execution["post_target_lineage_raw_syscalls"]})
    if set(null_counts) != {"native_amd64_static", "native_i386_static", "native_amd64_dynamic"} or any(len(counts) != 2 for counts in null_counts.values()):
        raise ValueError("Fresh per-stratum null calibration incomplete")
    return {"status": "accepted_bounded_benign_smoke", "cases": results,
        "null_maxima": {mode: max(counts) for mode, counts in null_counts.items()},
        "activity_floors": {mode: max(counts) + 25 for mode, counts in null_counts.items()},
        "malware_executions": 0, "full_collection_started": False,
        "limitations": ["19 short benign/null cases do not certify arbitrary malware or stress/loss completeness",
            "Outside-workspace mutations are semantically attested by direct guest checks, not claimed archived",
            "Activity is descriptive, not attack activation, delivery or a primary exclusion"]}


def execute(release):
    protocol = verify_release(release)
    manifest = load(release / "manifest.json")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = release / "gates" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    snapshot = "clean-matched45-v18-" + stamp
    initial = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
    if (initial["guest"]["VMState"] != '"poweroff"' or initial["sink"]["VMState"] != '"running"'
            or initial["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"'):
        raise ValueError("Expected original powered-off guest and running isolated Sink")
    from export_original_sources import check_competitors
    check_competitors()
    save(attempt / "initial_vm_state.json", initial)
    save(attempt / "gate_protocol.json", {"scope": protocol["scope"], "snapshot": snapshot,
        "driver_sha256": digest(Path(__file__)), "release_protocol_sha256": digest(release / "protocol.json"),
        "malware_executions": 0, "full_collection_started": False})
    try:
        print("Staging common payload on a fresh isolated child snapshot; no targets run", flush=True)
        with (attempt / "staging.log").open("x") as log:
            subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
                "--vm", helper.VM, "--guest-user", helper.GUEST_USER, "--baseline-snapshot", helper.BASELINE,
                "--new-snapshot", snapshot, "--schema-version", helper.SCHEMA,
                "--guest-setup", str(release / "setup_guest.sh")], cwd=STUDY, stdout=log, stderr=subprocess.STDOUT, check=True)
        staged = helper.isolated(helper.VM)
        if staged["CurrentSnapshotName"] != '"' + snapshot + '"':
            raise ValueError("Staged snapshot name differs")
        save(attempt / "staged_snapshot.json", staged)
        with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-matched45-auth-") as password:
            os.chmod(password.name, 0o600)
            password.write(helper.credentials())
            password.flush()
            auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
            with (attempt / "guest_ready.log").open("x") as log:
                for probe in range(3):
                    waiter = subprocess.Popen(["VBoxManage", "guestproperty", "wait", helper.VM,
                        "/VirtualBox/GuestInfo/OS/LoggedInUsers", "--timeout", "120000", "--fail-on-timeout"],
                        stdout=log, stderr=subprocess.STDOUT)
                    try:
                        if probe == 0:
                            helper.vbox("startvm", helper.VM, "--type", "headless")
                        if waiter.wait(timeout=150):
                            raise RuntimeError("Guest login event timed out")
                    finally:
                        if waiter.poll() is None:
                            waiter.terminate()
                            waiter.wait()
                    ready = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/bin/true",
                        "--wait-stdout", "--wait-stderr", "--timeout", "5000", "--", check=False)
                    log.write(ready.stdout + ready.stderr)
                    log.flush()
                    if ready.returncode == 0:
                        break
                else:
                    raise RuntimeError("Guest Control not ready")
            print("Running all45 benign guest workloads; malware execution disabled", flush=True)
            result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                "--wait-stdout", "--wait-stderr", "--timeout", "900000", "--",
                manifest["guest_root"] + "/matched45_workloads.py", "--guest-site", manifest["guest_root"], check=False)
            (attempt / "guest_preflight.log").write_text(result.stdout + result.stderr)
            helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth,
                manifest["guest_root"] + "/guest_preflight.json", str(attempt / "guest_preflight.json"))
            report = load(attempt / "guest_preflight.json")
            expected = {case["case_id"]: case["sha256"] for case in manifest["cases"] if case["label"] == "benign"}
            if (result.returncode or report["status"] != "accepted" or report["accepted"] != 45
                    or {row["case_id"]: row["sha256"] for row in report["cases"]} != expected):
                raise ValueError("Not all45 exact benign guest workloads passed")
        helper.vbox("controlvm", helper.VM, "poweroff")
        helper.vbox("snapshot", helper.VM, "restore", snapshot)
        command = ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"), "--vm", helper.VM,
            "--guest-user", helper.GUEST_USER, "--guest-malware-dir", manifest["guest_root"] + "/samples",
            "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", snapshot,
            "--schema-version", helper.SCHEMA, "--guest-arguments-dir", manifest["guest_root"] + "/arguments",
            "--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
            "--fixed-observation", "--common-launch-wrapper"]
        for dry in (True, False):
            names = release / ("all-cases.txt" if dry else "benign-smoke.txt")
            if not dry:
                lookup = {case["sample"]: case for case in manifest["cases"]}
                if any(lookup[name]["label"] not in {"benign", "null"} for name in names.read_text().splitlines()):
                    raise ValueError("Malware forbidden in readiness sample list")
            print("Validating all96 transports without execution" if dry else "Collecting 19 benign/null sensor cases", flush=True)
            with (attempt / ("dry-run.log" if dry else "collection.log")).open("x") as log:
                subprocess.run(command + ["--sample-list", str(names), "--output-dir",
                    str(attempt / ("dry-run" if dry else "runs"))] + (["--dry-run"] if dry else []),
                    cwd=STUDY, stdout=log, stderr=subprocess.STDOUT, check=True)
            if dry and (attempt / "dry-run.log").read_text().count("Validated sample: ") != 96:
                raise ValueError("96-case transport dry-run incomplete")
        validation = audit(attempt, release)
        save(attempt / "sensor_validation.json", validation)
        verify_release(release)
    except Exception as error:
        save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error),
            "collection_ready": False, "malware_executions": 0})
        raise
    finally:
        if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
            helper.vbox("controlvm", helper.VM, "poweroff")
        helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
        final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        save(attempt / "final_vm_state.json", final)
        if (final["guest"]["VMState"] != '"poweroff"'
                or final["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"'):
            raise RuntimeError("Guest cleanup did not restore original powered-off snapshot")
    readiness = {"collection_ready": True, "full_collection_started": False, "malware_executions": 0,
        "release": str(release.relative_to(STUDY)), "gate_attempt": str(attempt.relative_to(STUDY)),
        "snapshot": snapshot, "snapshot_uuid": staged["CurrentSnapshotUUID"], "production_hashes": helper.PINNED,
        "activity_floors": validation["activity_floors"], "scope": protocol["scope"],
        "evidence_hashes": {name: digest(attempt / name) for name in (
            "guest_preflight.json", "sensor_validation.json", "gate_protocol.json", "final_vm_state.json", "dry-run.log", "collection.log")},
        "protocol_sha256": digest(release / "protocol.json"),
        "limitations": validation["limitations"] + ["All27 additional training controls are Coreutils",
            "Consumed inherited validation remains exploratory; no confirmatory or superiority claim",
            "Full collection still needs separate explicit authorization and fresh safety/hash checks",
            "Post-capture quality/exec/unique recorded-window Ethernet/nominal P4 parity gates still apply"]}
    save(attempt / "readiness.json", readiness)
    print(json.dumps({"attempt": str(attempt), "collection_ready": True, "malware_executions": 0}, indent=2), flush=True)
    return attempt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-attempt", type=Path)
    parser.add_argument("--release", type=Path)
    parser.add_argument("--execute-benign-checks", action="store_true")
    args = parser.parse_args()
    with (NATIVE / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        release = freeze(args.host_attempt.resolve()) if args.host_attempt else args.release.resolve()
        verify_release(release)
        if args.execute_benign_checks:
            execute(release)


if __name__ == "__main__":
    main()