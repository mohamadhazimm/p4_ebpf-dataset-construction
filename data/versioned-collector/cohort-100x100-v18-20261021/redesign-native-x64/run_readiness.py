#!/usr/bin/env python3
"""Prepare and test readiness only. This command never launches malware cases."""

from __future__ import annotations

import argparse
import base64
import csv
import fcntl
import hashlib
import io
import json
import math
import os
import random
import shlex
import subprocess
import tarfile
import tempfile
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import prepare_workloads


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[3]
VM = "Ubuntu-Clean-24.04"
GUEST_USER = "csci"
GUEST_ROOT = prepare_workloads.GUEST_ROOT
ORIGINAL = "clean-tls-paired-2026-10-19"
BASELINE = "clean-current-runner-2026-10-18.1-malware"
SCHEMA = "2026-10-20.18"
PINNED = {
    "src/malware_runner.py": "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49",
    "scripts/vbox_malware_batch.sh": "4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f",
    "scripts/stage_versioned_runner_snapshot.sh": "5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def verify_production():
    for name, expected in PINNED.items():
        if digest(STUDY / name) != expected:
            raise ValueError("production provenance changed: " + name)


def vbox(*arguments, check=True):
    return subprocess.run(["VBoxManage", *arguments], capture_output=True, text=True, check=check)


def vm_info(name):
    return dict(line.split("=", 1) for line in vbox("showvminfo", name, "--machinereadable").stdout.splitlines() if "=" in line)


def isolated(name):
    info = vm_info(name)
    if info.get("nic1") != '"intnet"' or info.get("intnet1") != '"malnet"':
        raise ValueError(name + " is not on isolated malnet")
    if any(info.get("nic" + str(index)) != '"none"' for index in range(2, 9)):
        raise ValueError(name + " has another enabled NIC")
    return info


def freeze_attempt():
    verify_production()
    workloads = json.loads((ROOT / "manifests/benign-workloads.json").read_text())
    malware = json.loads((ROOT / "manifests/malware-selection.json").read_text())
    if workloads["generator_sha256"] != digest(ROOT / "prepare_workloads.py"):
        raise ValueError("workload generator changed after profile preparation")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "readiness" / run_id
    attempt.mkdir(parents=True)
    snapshot = "clean-cohort-native-v18-" + run_id
    generator = random.Random(42)
    cases = []
    for split in ("training", "validation"):
        for mode in ("static", "dynamic"):
            benign_rows = [{"sample": row["sample"], "class": "benign", "split": split,
                            "mode": mode, "group_id": "benign_project::" + row["project"]}
                           for row in workloads["cases"] if row["split"] == split and row["mode"] == mode]
            malware_rows = [{"sample": row["sample"], "class": "malware", "split": split,
                             "mode": mode, "group_id": row["group_id"]}
                            for row in malware["malware_" + split] if row["execution_mode"] == "native_x86_64_" + mode]
            if len(benign_rows) != len(malware_rows):
                raise ValueError("unmatched split/linkage quotas")
            generator.shuffle(benign_rows)
            generator.shuffle(malware_rows)
            first = generator.randrange(2)
            for benign_case, malware_case in zip(benign_rows, malware_rows):
                cases.extend([benign_case, malware_case] if first == 0 else [malware_case, benign_case])
    if len(cases) != 200 or len({row["sample"] for row in cases}) != 200:
        raise ValueError("case count or sample identities differ")
    for index, control in enumerate(workloads["null_controls"]):
        cases.insert(round(index * len(cases) / 6), {"sample": control["sample"], "class": "null", "split": "calibration",
                                                   "mode": control["mode"], "group_id": "null_control"})
    for index, case in enumerate(cases, 1):
        case["position"] = index
    with (attempt / "case_order.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=["position", "sample", "class", "split", "mode", "group_id"])
        writer.writeheader()
        writer.writerows(cases)
    (attempt / "ordered-206.txt").write_text("".join(row["sample"] + "\n" for row in cases))
    smoke = [row["sample"] for row in workloads["null_controls"]] + ["cp", "jq"] + [
        row["sample"] for row in workloads["cases"] if row.get("collection_container_sha256")]
    (attempt / "smoke-benign-only.txt").write_text("\n".join(smoke) + "\n")
    payload = ROOT / "payload"
    (payload / "guest_preflight.py").write_bytes((ROOT / "guest_preflight.py").read_bytes())
    (payload / "fixture_services.py").write_bytes((ROOT / "fixture_services.py").read_bytes())
    package = attempt / "payload.tgz"
    with tarfile.open(package, "w:gz") as archive:
        for path in sorted(payload.rglob("*")):
            if (path.is_file() or path.is_dir()) and not path.is_symlink():
                archive.add(path, arcname=str(path.relative_to(payload)), recursive=False)
        for split in ("training", "validation"):
            for row in malware["malware_" + split]:
                path = STUDY / row["source_archive_path"]
                if digest(path) != row["source_archive_sha256"] or Path(row["sample"]).name != row["sample"]:
                    raise ValueError("malware archive identity changed")
                archive.add(path, arcname="samples/" + row["sample"], recursive=False)
                data = b"[]\n"
                member = tarfile.TarInfo("arguments/" + row["sample"] + ".json")
                member.size = len(data)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(data))
    encoded = base64.b64encode(package.read_bytes()).decode("ascii")
    setup = """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64, hashlib, io, os, shutil, subprocess, tarfile
from pathlib import Path
root = Path(GUEST_PLACEHOLDER)
if root.exists():
    raise SystemExit('refusing to overwrite an existing experiment directory')
data = base64.b64decode(PAYLOAD_PLACEHOLDER)
if hashlib.sha256(data).hexdigest() != HASH_PLACEHOLDER:
    raise SystemExit('payload hash differs')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    seen = set()
    for member in archive:
        path = root / member.name
        if not (member.isfile() or member.isdir()) or member.name in seen or not path.resolve().is_relative_to(root):
            raise SystemExit('unsafe or duplicate payload member')
        seen.add(member.name)
        if member.isdir():
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(member) as source, path.open('wb') as output:
            shutil.copyfileobj(source, output)
        path.chmod(0o755 if member.mode & 0o111 else 0o644)
shutil.copytree(root / 'workspace-seed', root / 'workspace')
cron = subprocess.run(['/usr/bin/crontab', '-l'], capture_output=True, text=True)
if cron.returncode not in (0, 1) or 'cohort-native-fixtures' in cron.stdout:
    raise SystemExit('unexpected existing fixture cron state')
line = '@reboot /usr/bin/python3 ' + str(root / 'fixture_services.py') + ' ' + str(root) + ' > ' + str(root / 'fixture-services.log') + ' 2>&1 # cohort-native-fixtures'
subprocess.run(['/usr/bin/crontab', '-'], input=cron.stdout.rstrip() + '\\n' + line + '\\n', text=True, check=True)
print('Staged common payload; no workload executed')
PY
"""
    setup = setup.replace("GUEST_PLACEHOLDER", repr(GUEST_ROOT)).replace("PAYLOAD_PLACEHOLDER", repr(encoded)).replace("HASH_PLACEHOLDER", repr(digest(package)))
    (attempt / "setup_guest.sh").write_text(setup)
    protocol = {
        "frozen_utc": datetime.now(timezone.utc).isoformat(), "phase": "readiness_before_full_collection",
        "snapshot": snapshot, "clean_parent": BASELINE, "schema": SCHEMA, "production_sha256": PINNED,
        "full_collection_started": False, "malware_execution_in_readiness": False,
        "common_fixture_services": "loopback FTP 65015 and WHOIS 65014; same user startup on both labels; guest NSS unchanged",
        "readiness_smoke": smoke,
        "counts": {"malware": 100, "benign": 100, "null": 6}, "seed": 42,
        "collection_settings": {"timeout": 20, "window_sec": 0.5, "iface": "enp0s3", "ebpf": True,
                                "fixed_observation": True, "common_launch_wrapper": True,
                                "packet_capture_buffer_kb": 65536, "packet_capture_drain_ms": 1000,
                                "bpftrace_perf_rb_pages": 16384, "watch_path": GUEST_ROOT + "/workspace"},
        "activation": {"algorithm": "target exec observed and post-target lineage raw syscalls > matching-linkage null maximum + 25",
                       "margin": 25, "meaning": "activity, not maliciousness or delivery", "primary_exclusion_for_low_activity": False},
        "quality": "strict .18 gate; provenance/sensor failures rejected; retrieval and target exec checked separately",
        "retries": "no automatic full-collection retries or replacements; preserve all attempted cases and failures",
        "analysis": {"p4_columns": 145, "host_columns": 145, "hybrid_columns": 290,
                     "host_selection": "29 of 35 complete families by training-only mean mutual information over five summaries; refit inside grouped training folds",
                     "rf": {"n_estimators": 500, "class_weight": "balanced", "random_state": 42, "n_jobs": 1},
                     "threshold": 0.5, "validation": "score once after training-only grouped evaluation; no validation tuning",
                     "p4": "offline PCAP, Ethernet bytes, nominal rates, unique alignment and stored parity",
                     "primary": "quality accepted and target observed; common aligned set; report host-only all-eligible sensitivity",
                     "reports": ["BA", "ROC-AUC", "confusion matrices", "linkage strata", "group-weighted metrics", "2000 group bootstrap replicates"],
                     "negative_controls": ["nuisance-only model", "100 training-only group-respecting label permutations"],
                     "claim_gate": "nuisance BA >= 0.75 or activity-only BA >= 0.75 blocks a malicious-behavior interpretation"},
        "limitations": ["native x86-64 only", "purposive source selection", "some held-out signatures previously explored; not blind",
                        "Mirai/Qilin concentration", "build/toolchain/task/activity shortcuts may remain", "P4 is offline reconstruction"],
    }
    write_json(attempt / "preregistration.json", protocol)
    frozen = {str(path.relative_to(ROOT)): digest(path) for path in [
        ROOT / "prepare_workloads.py", ROOT / "guest_preflight.py", ROOT / "fixture_services.py", Path(__file__),
        ROOT / "manifests/benign-workloads.json", ROOT / "manifests/benign-executables.json",
        ROOT / "manifests/malware-selection.json", ROOT / "benign-project-plan.json",
        attempt / "case_order.csv", attempt / "ordered-206.txt", attempt / "smoke-benign-only.txt",
        attempt / "preregistration.json", attempt / "payload.tgz", attempt / "setup_guest.sh"]}
    write_json(attempt / "frozen_hashes.json", frozen)
    write_json(ROOT / "readiness-current.json", {"attempt": str(attempt.relative_to(ROOT)), "collection_ready": False})
    print(json.dumps({"attempt": str(attempt), "snapshot": snapshot, "package_bytes": package.stat().st_size, "frozen_cases": len(cases)}, indent=2), flush=True)
    return attempt, protocol


def credentials():
    secret = os.environ.get("VBOX_GUEST_PASSWORD", "")
    if not secret:
        env_path = Path(os.environ.get("ENV_FILE", str(STUDY.parents[1] / ".env")))
        for raw in env_path.read_text().splitlines():
            line = raw.strip().removeprefix("export ")
            key, separator, value = line.partition("=")
            if separator and key.strip() in {"VBOX_GUEST_PASSWORD", "GUEST_PASSWORD", "guest_password"}:
                values = shlex.split(value, comments=True)
                if len(values) != 1:
                    raise ValueError("invalid protected credential configuration")
                secret = values[0]
                break
    if not secret:
        raise ValueError("protected guest credential is unavailable")
    return secret


def verify_output_archive(sample_root):
    seen = set()
    output = (sample_root / "output").resolve()
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            target = (output / member.name).resolve()
            if not member.isfile() or not target.is_relative_to(output) or target in seen:
                raise ValueError("unsafe or duplicate output archive member")
            seen.add(target)
            with archive.extractfile(member) as source:
                if not target.is_file() or hashlib.sha256(source.read()).hexdigest() != digest(target):
                    raise ValueError("output archive/host hash mismatch")
    if not seen:
        raise ValueError("empty output archive")
    return len(seen)


def smoke_audit(attempt, workloads):
    rows = []
    null_samples = {row["sample"]: row["mode"] for row in workloads["null_controls"]}
    null_values = {"static": [], "dynamic": []}
    transported = {row["sample"]: row for row in workloads["cases"] if row.get("collection_container_sha256")}
    for sample in [*null_samples, "cp", "jq", *transported]:
        sample_root = attempt / "sensor-smoke" / sample
        metadata_paths = list(sample_root.rglob("run.json"))
        if len(metadata_paths) != 1:
            raise ValueError("missing or ambiguous sensor-smoke output: " + sample)
        metadata = json.loads(metadata_paths[0].read_text())
        if metadata["telemetry_schema_version"] != SCHEMA or metadata["malware_runner_sha256"] != PINNED["src/malware_runner.py"]:
            raise ValueError("sensor-smoke runner provenance differs")
        if metadata["collection_quality_status"] != "accepted" or metadata["target_exec"]["status"] != "observed":
            raise ValueError("sensor quality or target exec failed: " + sample)
        groups = metadata["telemetry_feature_groups"]
        features = [field for fields in groups.values() for field in fields]
        if len(features) != 169 or len(set(features)) != 169:
            raise ValueError("sensor feature contract differs")
        with (metadata_paths[0].parent / "telemetry.csv").open(newline="") as source:
            telemetry = list(csv.DictReader(source))
        if len(telemetry) != 40 or not all(math.isfinite(float(row[name])) for row in telemetry for name in features):
            raise ValueError("sensor telemetry incomplete: " + sample)
        count = metadata["target_exec"]["post_target_lineage_raw_syscalls"]
        if not isinstance(count, int) or count < 0:
            raise ValueError("missing activation calibration count")
        if sample in null_samples:
            null_values[null_samples[sample]].append(count)
        members = verify_output_archive(sample_root)
        if sample == "cp":
            copies = list(metadata_paths[0].parent.rglob("copied.txt"))
            if len(copies) != 1 or digest(copies[0]) != workloads["fixtures_sha256"]["workspace-seed/input.txt"]:
                raise ValueError("sensor-smoke copy content differs")
        if sample in transported:
            chosen = dict(line.split("=", 1) for line in (sample_root / "chosen.txt").read_text().splitlines() if "=" in line)
            if Path(chosen.get("chosen_executable", "")).name != transported[sample]["program"]:
                raise ValueError("transport selected the wrong executable")
            if metadata["target_exec"]["expected_path"].split("/")[-1] != transported[sample]["program"]:
                raise ValueError("transport target basename differs")
        rows.append({"sample": sample, "target_exec": "observed", "quality": "accepted",
                 "post_target_lineage_raw_syscalls": count, "verified_archive_members": members})
    if any(len(values) != 3 for values in null_values.values()):
        raise ValueError("null calibration is incomplete")
    return {"status": "accepted", "cases": rows,
            "activation_floors": {mode: max(values) + 25 for mode, values in null_values.items()}}


def run_guest_checks(attempt, protocol):
    verify_production()
    if isolated(VM)["VMState"] != '"poweroff"' or isolated("Sink")["VMState"] != '"running"':
        raise ValueError("guest must be powered off and Sink running")
    competing = subprocess.run(["pgrep", "-af", "[v]box_malware_batch|[r]un_versioned_cohorts|[s]tage_versioned_runner"], capture_output=True, text=True)
    if competing.returncode == 0:
        raise ValueError("competing collector/staging process exists")
    with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-guest-auth-") as password:
        os.chmod(password.name, 0o600)
        password.write(credentials())
        password.flush()
        auth = ["--username", GUEST_USER, "--passwordfile", password.name]

        def guest(executable, arguments, timeout=180000, check=True):
            result = vbox("guestcontrol", VM, "run", *auth, "--exe", executable,
                          "--wait-stdout", "--wait-stderr", "--timeout", str(timeout), "--", *arguments, check=check)
            return result

        touched = False
        try:
            touched = True
            with (attempt / "staging.log").open("w") as output:
                subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
                                "--vm", VM, "--guest-user", GUEST_USER, "--baseline-snapshot", BASELINE,
                                "--new-snapshot", protocol["snapshot"], "--schema-version", SCHEMA,
                                "--guest-setup", str(attempt / "setup_guest.sh")],
                               stdout=output, stderr=subprocess.STDOUT, check=True, cwd=STUDY)
            staged_info = isolated(VM)
            if staged_info["CurrentSnapshotName"] != '"' + protocol["snapshot"] + '"':
                raise ValueError("staged snapshot identity differs")
            write_json(attempt / "staged_snapshot.json", {"name": protocol["snapshot"], "uuid": staged_info["CurrentSnapshotUUID"].strip('"')})
            vbox("startvm", VM, "--type", "headless")
            for readiness_attempt in range(90):
                readiness = vbox("guestcontrol", VM, "run", *auth, "--exe", "/bin/true",
                                 "--wait-stdout", "--wait-stderr", "--timeout", "5000", "--", check=False)
                (attempt / "guest_ready.log").write_text(readiness.stdout + readiness.stderr)
                if readiness.returncode == 0:
                    break
                threading.Event().wait(1)
            else:
                raise RuntimeError("Guest Control did not become ready; see guest_ready.log")
            result = guest("/usr/bin/python3", [GUEST_ROOT + "/guest_preflight.py", GUEST_ROOT], timeout=180000, check=False)
            (attempt / "guest_preflight.log").write_text(result.stdout + result.stderr)
            vbox("guestcontrol", VM, "copyfrom", *auth, GUEST_ROOT + "/guest_preflight.json", str(attempt / "guest_preflight.json"))
            guest_report = json.loads((attempt / "guest_preflight.json").read_text())
            if result.returncode:
                raise RuntimeError("guest checker exited early; see guest_preflight.log and partial JSON")
            print(json.dumps({"guest_workloads": guest_report["accepted"], "total": 100, "status": guest_report["status"]}), flush=True)
            if guest_report["status"] != "accepted" or guest_report["accepted"] != 100:
                raise ValueError("benign workload preflight rejected; inspect preserved report")
            vbox("controlvm", VM, "poweroff")
            with (attempt / "dry-run.log").open("w") as output:
                subprocess.run(["bash", str(STUDY / "scripts/vbox_malware_batch.sh"),
                                "--vm", VM, "--guest-user", GUEST_USER, "--guest-malware-dir", GUEST_ROOT + "/samples",
                                "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", protocol["snapshot"],
                                "--output-dir", str(attempt / "dry-run"), "--sample-list", str(attempt / "ordered-206.txt"),
                                "--schema-version", SCHEMA, "--dry-run"], stdout=output, stderr=subprocess.STDOUT,
                               check=True, cwd=STUDY)
            if (attempt / "dry-run.log").read_text().count("Validated sample: ") != 206:
                raise ValueError("batch dry-run did not validate every planned sample")
            with (attempt / "smoke.log").open("w") as output:
                subprocess.run(["bash", str(STUDY / "scripts/vbox_malware_batch.sh"),
                                "--vm", VM, "--guest-user", GUEST_USER, "--guest-malware-dir", GUEST_ROOT + "/samples",
                                "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", protocol["snapshot"],
                                "--output-dir", str(attempt / "sensor-smoke"), "--sample-list", str(attempt / "smoke-benign-only.txt"),
                                "--guest-arguments-dir", GUEST_ROOT + "/arguments", "--schema-version", SCHEMA,
                                "--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
                                "--fixed-observation", "--common-launch-wrapper", "--watch-path", GUEST_ROOT + "/workspace"],
                               stdout=output, stderr=subprocess.STDOUT, check=True, cwd=STUDY)
            workloads = json.loads((ROOT / "manifests/benign-workloads.json").read_text())
            sensor = smoke_audit(attempt, workloads)
            write_json(attempt / "sensor_validation.json", sensor)
            return guest_report, sensor
        finally:
            if touched:
                if vm_info(VM)["VMState"] == '"running"':
                    vbox("controlvm", VM, "poweroff")
                vbox("snapshot", VM, "restore", ORIGINAL)
                info = isolated(VM)
                isolated("Sink")
                if info["VMState"] != '"poweroff"' or info["CurrentSnapshotName"] != '"' + ORIGINAL + '"':
                    raise ValueError("guest cleanup did not restore the original powered-off snapshot")
                write_json(attempt / "final_vm_state.json", info)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    with (ROOT / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt, protocol = freeze_attempt()
        if args.build_only:
            return
        try:
            guest_report, sensor = run_guest_checks(attempt, protocol)
            verify_production()
            frozen = json.loads((attempt / "frozen_hashes.json").read_text())
            if any(digest(ROOT / name) != expected for name, expected in frozen.items()):
                raise ValueError("frozen input changed during readiness testing")
            result = {"status": "ready_for_authorized_full_collection", "collection_ready": True,
                      "attempt": str(attempt.relative_to(ROOT)), "snapshot": protocol["snapshot"],
                      "benign_workloads_accepted": guest_report["accepted"], "sensor_validation": sensor,
                      "full_collection_started": False, "malware_executions": 0,
                      "frozen_hashes_sha256": digest(attempt / "frozen_hashes.json"),
                      "evidence_sha256": {name: digest(attempt / name) for name in
                                          ("guest_preflight.json", "sensor_validation.json", "staged_snapshot.json", "final_vm_state.json")}}
            write_json(attempt / "readiness.json", result)
            write_json(ROOT / "readiness-current.json", result)
            print(json.dumps(result, indent=2), flush=True)
        except Exception as error:
            write_json(attempt / "readiness.json", {"status": "not_ready", "collection_ready": False,
                                                   "error": str(error), "full_collection_started": False})
            print("Readiness not accepted; outputs retained at " + str(attempt), flush=True)
            raise


if __name__ == "__main__":
    main()