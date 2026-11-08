#!/usr/bin/env python3
"""Run bounded benign native-ABI checks only; never launch malware or the full cohort."""

from __future__ import annotations

import argparse
import base64
import csv
import fcntl
import io
import json
import math
import subprocess
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import prepare_inventory


ROOT = Path(__file__).resolve().parent
STUDY = prepare_inventory.STUDY
PILOT = ROOT.parent / "exec-mode-pilot-v16-20261020T204233Z"
sys.path.insert(0, str(prepare_inventory.PREPARATION))
import run_readiness as previous_readiness


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def freeze():
    previous_readiness.verify_production()
    builder = prepare_inventory.load_builder()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "native-checks" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    provenance = json.loads((PILOT / "artifact_provenance.json").read_text())
    cases = []
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for repeat in (1, 2):
            for workload in ("null", "file", "net"):
                for arch, machine, abi in (("amd64", 62, 0), ("i386", 3, 1)):
                    source = PILOT / "artifacts" / f"busybox-{arch}-static"
                    record = next(row for row in provenance["artifacts"] if row["file"] == source.name)
                    if builder.sha256_file(source) != record["binary_sha256"]:
                        raise ValueError("known-answer executable hash changed")
                    if builder.inspect_elf(source.read_bytes(), strict_linkage=True)[0] != (
                        "native_x86_64_static" if arch == "amd64" else "native_i386_static"
                    ):
                        raise ValueError("known-answer native mode changed")
                    sample = f"{arch}_{workload}_r{repeat}.zip"
                    arguments = {
                        "null": ["true"],
                        "file": ["sh", "-c", "i=0; while [ $i -lt 300 ]; do echo $i > bb_file_workload.txt; read v < bb_file_workload.txt; i=$((i+1)); done"],
                        "net": ["sh", "-c", 'printf "GET / HTTP/1.0\\r\\nHost: 10.0.0.1\\r\\n\\r\\n" | "$0" nc -w 3 10.0.0.1 80 > bb_net_workload.html', "/tmp/malware-lab/extracted/busybox"],
                    }[workload]
                    packed = io.BytesIO()
                    with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as transport:
                        entry = zipfile.ZipInfo("busybox")
                        entry.external_attr = 0o100755 << 16
                        transport.writestr(entry, source.read_bytes())
                    for name, data in (("samples/" + sample, packed.getvalue()),
                                       ("arguments/" + sample + ".json", json.dumps(arguments).encode())):
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.mode = len(data), 0o644
                        archive.addfile(entry, io.BytesIO(data))
                    cases.append({"sample": sample, "arch": arch, "machine": machine, "abi": abi,
                                  "workload": workload, "repeat": repeat, "arguments": arguments,
                                  "binary_sha256": record["binary_sha256"],
                                  "package_sha256": record["deb_sha256"], "package_version": record["version"],
                                  "transport_sha256": builder.sha256_bytes(packed.getvalue())})
    package = payload.getvalue()
    (attempt / "payload.tgz").write_bytes(package)
    guest_root = "/home/csci/Downloads/native-abi-check-" + run_id
    setup = '''#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64, hashlib, io, shutil, tarfile
from pathlib import Path
root = Path(GUEST_ROOT)
data = base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest() != EXPECTED_HASH:
    raise SystemExit('existing guest path or changed payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    seen = set()
    for member in archive:
        path = root / member.name
        if not member.isfile() or member.name in seen or not path.resolve().is_relative_to(root):
            raise SystemExit('unsafe or duplicate payload entry')
        seen.add(member.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(member) as source, path.open('wb') as output:
            shutil.copyfileobj(source, output)
        path.chmod(0o644)
print('Benign ABI fixtures staged; no workload executed')
PY
'''
    setup = setup.replace("GUEST_ROOT", repr(guest_root)).replace("PAYLOAD", repr(base64.b64encode(package).decode()))
    setup = setup.replace("EXPECTED_HASH", repr(builder.sha256_bytes(package)))
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "benign-only.txt").write_text("".join(row["sample"] + "\n" for row in cases))
    protocol = {
        "frozen_utc": datetime.now(timezone.utc).isoformat(), "schema": previous_readiness.SCHEMA,
        "production_hashes": previous_readiness.PINNED, "snapshot": "clean-native-abi-v18-" + run_id,
        "baseline": previous_readiness.BASELINE, "guest_root": guest_root, "cases": cases,
        "timeout_s": 20, "window_s": 0.5, "full_collection_started": False, "malware_executions": 0,
        "quality": "All cases require exact runner hash, active sensors, accepted quality, zero drops/discrepancy/eBPF loss, archive hashes and finite 40x169 features.",
        "exec": "All targets must be observed, static native with matching e_machine, and exit zero.",
        "file": "300 expected-ABI write calls and final file content 299 newline.",
        "network": "Explicit same-architecture busybox nc, expected-ABI connect/socketcall, and saved HTTP 200 response.",
        "abi": "Zero unresolved ABI and no feature totals below diagnostic raw counts; raw event CSV row count must reconcile.",
        "activation": "Per-architecture null max plus margin 25; report activity independently of output and quality.",
        "limitations": ["Two static BusyBox builds, repeated twice per workload; not 12 independent programs.",
                        "No malware compatibility or general loss-free capture certification.",
                        "Source package provenance is reused from the existing authenticated pilot."],
    }
    protocol["input_hashes"] = {str(path.relative_to(STUDY)): builder.sha256_file(path) for path in (
        Path(__file__), PILOT / "artifact_provenance.json", attempt / "payload.tgz", attempt / "setup_guest.sh",
        attempt / "benign-only.txt", prepare_inventory.PREPARATION / "run_readiness.py",
        prepare_inventory.PREPARATION / "prepare_workloads.py",
    )}
    write_json(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "snapshot": protocol["snapshot"], "benign_cases": len(cases)}, indent=2), flush=True)
    return attempt, protocol


def audit(attempt, protocol):
    from scapy.utils import RawPcapReader

    rows = []
    for case in protocol["cases"]:
        sample_root = attempt / "runs" / case["sample"]
        paths = list((sample_root / "output").glob("run_*/run.json"))
        if len(paths) != 1:
            raise ValueError("missing or ambiguous output: " + case["sample"])
        run = paths[0].parent
        meta = json.loads(paths[0].read_text())
        if "status=completed" not in (sample_root / "host_run.txt").read_text().split():
            raise ValueError("retrieval incomplete")
        if meta["telemetry_schema_version"] != protocol["schema"] or meta["malware_runner_sha256"] != protocol["production_hashes"]["src/malware_runner.py"]:
            raise ValueError("runner provenance differs")
        if meta["ebpf_status"] != "active" or meta["packet_capture_status"] != "active":
            raise ValueError("inactive sensor")
        if meta["collection_quality_status"] != "accepted" or any(meta.get(key) != 0 for key in (
            "ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel",
        )):
            raise ValueError("sensor quality rejected: " + case["sample"])
        artifact, execution = meta["target_artifact"], meta["target_exec"]
        if artifact["e_machine"] != case["machine"] or artifact["linkage"] != "static" or artifact["execution_mode"] != "native":
            raise ValueError("not the expected native target")
        if execution["status"] != "observed" or execution["match"] != "exact" or meta["return_code"] != 0:
            raise ValueError("known-answer target execution failed")
        with (run / "telemetry.csv").open(newline="") as source:
            telemetry = list(csv.DictReader(source))
        features = [name for group in meta["telemetry_feature_groups"].values() for name in group]
        if len(features) != 169 or len(set(features)) != 169 or len(telemetry) != 40:
            raise ValueError("feature/row contract differs")
        if not all(math.isfinite(float(row[name])) for row in telemetry for name in features):
            raise ValueError("nonfinite features")
        diagnostics = meta["ebpf_event_diagnostics"]
        if diagnostics["raw_syscalls_unresolved_abi"] != 0:
            raise ValueError("unresolved syscall ABI")
        for name, counts in diagnostics["named_vs_raw_syscalls"].items():
            field = f"ebpf_{name}_count"
            if field in features and sum(float(row[field]) for row in telemetry) < counts["raw"]:
                raise ValueError("feature deficit: " + name)
        with (run / "syscall_events.csv").open(newline="") as source:
            raw = list(csv.DictReader(source))
        if len(raw) != meta["raw_syscall_event_count"]:
            raise ValueError("raw rows do not reconcile")
        expected = [row for row in raw if f"abi={case['abi']}" in row["detail"].split()]
        numbers = [int(dict(part.split("=", 1) for part in row["detail"].split() if "=" in part)["id"]) for row in expected]
        if not numbers:
            raise ValueError("no expected-ABI raw events")
        if case["workload"] == "file":
            if (run / "workspace/bb_file_workload.txt").read_bytes() != b"299\n":
                raise ValueError("file workload output differs")
            if numbers.count(4 if case["abi"] else 1) != 300:
                raise ValueError("known-answer write count differs")
        if case["workload"] == "net":
            body = (run / "workspace/bb_net_workload.html").read_bytes()
            if not body.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")):
                raise ValueError("no saved HTTP 200 response")
            if not set(numbers) & ({102, 362} if case["abi"] else {42}):
                raise ValueError("no expected-ABI network syscall")
        with RawPcapReader(str(run / "packet_capture.pcap")) as capture:
            packets = sum(1 for _packet in capture)
        counters = meta["packet_capture_statistics"]
        if packets != counters["packets_captured"] or packets != counters["packets_received_by_filter"]:
            raise ValueError("PCAP record counters differ")
        archived = previous_readiness.verify_output_archive(sample_root)
        rows.append({**case, "run": str(run.relative_to(attempt)), "archive_members": archived,
                     "post_target_syscalls": execution["post_target_lineage_raw_syscalls"],
                     "expected_abi_raw_events": len(expected), "pcap_records": packets,
                     "named_vs_raw_syscalls": diagnostics["named_vs_raw_syscalls"]})
    floors = {arch: max(row["post_target_syscalls"] for row in rows if row["arch"] == arch and row["workload"] == "null")
              for arch in ("amd64", "i386")}
    for row in rows:
        row["activity_floor"] = floors[row["arch"]] + 25
        row["progressed"] = row["post_target_syscalls"] > row["activity_floor"]
        if row["workload"] != "null" and not row["progressed"]:
            raise ValueError("known-answer workload below frozen activity criterion")
    return {"status": "accepted_bounded_native_compatibility", "i386_gate_passed": True,
            "collection_ready": False, "malware_executions": 0, "cases": rows, "null_maxima": floors,
            "archive_members": sum(row["archive_members"] for row in rows),
            "pcap_records": sum(row["pcap_records"] for row in rows),
            "limitations": protocol["limitations"]}


def execute(attempt, protocol):
    previous_readiness.verify_production()
    initial = previous_readiness.isolated(previous_readiness.VM)
    sink = previous_readiness.isolated("Sink")
    if initial["VMState"] != '"poweroff"' or sink["VMState"] != '"running"':
        raise ValueError("guest must be off and Sink running")
    competing = subprocess.run(["pgrep", "-af", "[v]box_malware_batch|[s]tage_versioned_runner|[r]un_versioned_cohorts|[r]un_readiness.py"], capture_output=True, text=True)
    if competing.returncode == 0:
        raise ValueError("competing collector or stager exists")
    write_json(attempt / "initial_vm_state.json", {"guest": initial, "sink": sink})
    try:
        with (attempt / "staging.log").open("w") as output:
            subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
                            "--vm", previous_readiness.VM, "--guest-user", "csci",
                            "--baseline-snapshot", protocol["baseline"], "--new-snapshot", protocol["snapshot"],
                            "--schema-version", protocol["schema"], "--guest-setup", str(attempt / "setup_guest.sh")],
                           stdout=output, stderr=subprocess.STDOUT, check=True, cwd=STUDY)
        staged = previous_readiness.isolated(previous_readiness.VM)
        if staged["CurrentSnapshotName"] != '"' + protocol["snapshot"] + '"':
            raise ValueError("staged snapshot differs")
        write_json(attempt / "staged_snapshot.json", staged)
        arguments = ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"), "--vm", previous_readiness.VM,
                     "--guest-user", "csci", "--guest-malware-dir", protocol["guest_root"] + "/samples",
                     "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", protocol["snapshot"],
                     "--sample-list", str(attempt / "benign-only.txt"), "--schema-version", protocol["schema"],
                     "--guest-arguments-dir", protocol["guest_root"] + "/arguments", "--timeout", "20",
                     "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf", "--fixed-observation", "--common-launch-wrapper"]
        for dry in (True, False):
            print("Running benign-only " + ("dry-run" if dry else "12-case sensor checks"), flush=True)
            with (attempt / ("dry-run.log" if dry else "collection.log")).open("w") as output:
                subprocess.run(arguments + ["--output-dir", str(attempt / ("dry-run" if dry else "runs"))]
                               + (["--dry-run", "--guest-arch-diagnostics"] if dry else []),
                               stdout=output, stderr=subprocess.STDOUT, check=True, cwd=STUDY)
            if dry and (attempt / "dry-run.log").read_text().count("Validated sample: ") != 12:
                raise ValueError("not all 12 benign cases passed dry-run")
        previous_readiness.verify_production()
        builder = prepare_inventory.load_builder()
        if any(builder.sha256_file(STUDY / name) != expected for name, expected in protocol["input_hashes"].items()):
            raise ValueError("frozen input changed")
        result = audit(attempt, protocol)
        write_json(attempt / "validation.json", result)
        print(json.dumps({key: result[key] for key in ("status", "i386_gate_passed", "collection_ready", "null_maxima", "archive_members", "pcap_records")}, indent=2), flush=True)
    finally:
        if previous_readiness.vm_info(previous_readiness.VM)["VMState"] != '"poweroff"':
            previous_readiness.vbox("controlvm", previous_readiness.VM, "poweroff")
        previous_readiness.vbox("snapshot", previous_readiness.VM, "restore", previous_readiness.ORIGINAL)
        final = previous_readiness.isolated(previous_readiness.VM)
        sink = previous_readiness.isolated("Sink")
        write_json(attempt / "final_vm_state.json", {"guest": final, "sink": sink})
        if final["VMState"] != '"poweroff"' or final["CurrentSnapshotName"] != '"' + previous_readiness.ORIGINAL + '"':
            raise ValueError("cleanup did not restore powered-off original snapshot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-benign-checks", action="store_true")
    args = parser.parse_args()
    with (prepare_inventory.PREPARATION / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt, protocol = freeze()
        if args.execute_benign_checks:
            try:
                execute(attempt, protocol)
            except Exception as error:
                write_json(attempt / "failure.json", {"status": "not_accepted", "error": str(error), "collection_ready": False})
                raise


if __name__ == "__main__":
    main()