#!/usr/bin/env python3
"""Collect an interleaved 10-benign/10-malware ELF watch-path pilot."""

from __future__ import annotations

import csv
import hashlib
import json
import random
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STUDY = Path(__file__).resolve().parents[1]
OUTPUT = STUDY / "data/versioned-collector/paired-elf-watchpath-pilot-v4-20261018"
VM = "Ubuntu-Clean-24.04"
SINK = "Sink"
GUEST_USER = "csci"
BASELINE_SNAPSHOT = "clean-fixcheck-watchpath-20261018"
PILOT_SNAPSHOT = "clean-paired-elf-watchpath-pilot-v4-20261018"
GUEST_RUNNER = "/home/csci/Downloads/malware_runner.py"
GUEST_BENIGN_DIR = "/home/csci/Downloads/paired-elf-watchpath-pilot-20261018/benign"
GUEST_ARGUMENTS_DIR = "/home/csci/Downloads/paired-elf-watchpath-pilot-20261018/arguments"
WATCH_PATH = "/home/csci/Downloads/paired-elf-watchpath-pilot-20261018/watch"
TIMEOUT_SECONDS = "8"
WINDOW_SECONDS = "0.5"

MALWARE = [
    ("000643f6cc436583fbe0ce5deb5c16eb2ede8924baa089ff064e6ec69d9f0ab4.zip", "Mirai"),
    ("0004b57f7671cb3dbc993e632279e883d138ea72a271b3ab84637c918e391023.zip", "Gafgyt"),
    ("071ff332e77bc80d4e43660d73792af2e73e0442c66d74edfec3740b7691b299.zip", "JackSkid"),
    ("0ee1d284ed663073872012c7bde7fac5ca1121403f1a5d2d5411317df282796c.zip", "Akira"),
    ("15249d8fcd6c59755622790123259c8a06a0a10d8ce4de66e394609cef2abb2b.zip", "Qilin"),
    ("121f7a1da6b5d74209a64dfaa42f56d5ce7c52181f49fb256f8bdbdf7c00222f.zip", "Katana"),
    ("2f4eeacd76caf8f4a31cb22e4cbffea3b370c0f30c9d68d51934c13512a5a9f7.zip", "unassigned"),
    ("0fecfec4dc0cef15a2d4ae68bfe25d06ab0656039d46ee303c79254d0bea5012.zip", "MossadProxy"),
    ("8124f4ac27a1afb25d2479da9bf5f06c52e3e9cf25d4d514ec386f05e264dd14.zip", "CoinMiner"),
    ("4dc06ecee904b9165fa699b026045c1b6408cc7061df3d2a7bc2b7b4f0879f4d.zip", "LockBit"),
]
BENIGN = ["ping", "openssl", "vmstat", "tail", "md5sum", "dd", "find", "tar", "curl", "wget"]
COHORT_MANIFEST = STUDY / "data/malware/revision4/family-heldout-balanced-224-v1-20261014/labeled_sample_dataset_full_35host_9network.csv"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def vm_info(name: str) -> dict[str, str]:
    result = subprocess.run(
        ["VBoxManage", "showvminfo", name, "--machinereadable"],
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        key: value.strip().strip('"')
        for line in result.stdout.splitlines()
        if "=" in line
        for key, value in [line.split("=", 1)]
    }


def snapshot_exists(name: str) -> bool:
    result = subprocess.run(
        ["VBoxManage", "snapshot", VM, "list", "--machinereadable"],
        check=True,
        capture_output=True,
        text=True,
    )
    return f'="{name}"' in result.stdout


def require_isolated_vm(name: str, must_be_running: bool | None = None) -> None:
    info = vm_info(name)
    for key, value in info.items():
        if key.startswith("nic") and key[3:].isdigit() and value not in {"none", "null", "intnet"}:
            raise RuntimeError(f"Host-connected NIC refused for {name}: {key}={value}")
    if must_be_running is True and info.get("VMState") != "running":
        raise RuntimeError(f"{name} must already be running; refusing to change sink state")
    if must_be_running is False and info.get("VMState") != "poweroff":
        raise RuntimeError(f"{name} must be powered off before staging/collection")


def validate_malware_selection() -> None:
    with COHORT_MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
        rows = {row["sample_artifact"]: row for row in csv.DictReader(handle)}
    for artifact, family in MALWARE:
        row = rows.get(artifact)
        if row is None or row["label"] != "1" or row["workload_family"] != family:
            raise RuntimeError(f"Malware assignment does not match cohort manifest: {artifact}/{family}")


def run_logged(command: list[str], log_path: Path) -> None:
    with log_path.open("a", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=STUDY, stdout=log, stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}); inspect {log_path}")


def main() -> None:
    validate_malware_selection()
    runner = STUDY / "src/malware_runner.py"
    guest_setup = STUDY / "scripts/prepare_paired_elf_watchpath_pilot_guest.sh"
    batch_script = STUDY / "scripts/vbox_malware_batch.sh"
    stage_script = STUDY / "scripts/stage_versioned_runner_snapshot.sh"
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "logs").mkdir(exist_ok=True)
    (OUTPUT / "runs/benign").mkdir(parents=True, exist_ok=True)
    (OUTPUT / "runs/malware").mkdir(parents=True, exist_ok=True)

    require_isolated_vm(VM, must_be_running=False)
    require_isolated_vm(SINK, must_be_running=True)

    rng = random.Random(20261018)
    schedule = []
    for index, (malware, benign) in enumerate(zip(MALWARE, BENIGN), start=1):
        pair = [
            {"label": "benign", "artifact": benign, "family": "benign_native_elf"},
            {"label": "malware", "artifact": malware[0], "family": malware[1]},
        ]
        if rng.choice((False, True)):
            pair.reverse()
        schedule.extend({**entry, "pair": index} for entry in pair)

    manifest_path = OUTPUT / "pilot_manifest.json"
    provenance = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "runner_sha256": sha256(runner),
        "guest_setup_sha256": sha256(guest_setup),
        "batch_script_sha256": sha256(batch_script),
        "cohort_manifest_sha256": sha256(COHORT_MANIFEST),
        "baseline_snapshot": BASELINE_SNAPSHOT,
        "pilot_snapshot": PILOT_SNAPSHOT,
        "timeout_seconds": int(TIMEOUT_SECONDS),
        "window_seconds": float(WINDOW_SECONDS),
        "observation_mode": "fixed",
        "interface": "enp0s3",
        "ebpf": True,
        "watch_path": WATCH_PATH,
        "benign_artifacts": BENIGN,
        "malware_artifacts": [{"artifact": artifact, "family": family} for artifact, family in MALWARE],
        "interleaved_schedule": schedule,
        "completed_batches": [],
    }
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
        for key in (
            "runner_sha256", "guest_setup_sha256", "batch_script_sha256",
            "snapshot", "watch_path", "timeout_seconds", "window_seconds",
            "interleaved_schedule",
        ):
            if previous.get(key) != provenance[key]:
                raise RuntimeError(f"Existing pilot manifest differs at {key}; refusing to mix runs")
        provenance = previous
    else:
        manifest_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    if not snapshot_exists(PILOT_SNAPSHOT):
        run_logged(
            [
                "bash", str(stage_script),
                "--vm", VM,
                "--guest-user", GUEST_USER,
                "--baseline-snapshot", BASELINE_SNAPSHOT,
                "--new-snapshot", PILOT_SNAPSHOT,
                "--guest-setup", str(guest_setup),
            ],
            OUTPUT / "logs/stage.log",
        )

    completed_keys = {
        (entry["label"], entry["artifact"])
        for entry in provenance.get("completed_batches", [])
        if entry.get("return_code") == 0
    }
    for position, entry in enumerate(schedule, start=1):
        key = (entry["label"], entry["artifact"])
        if key in completed_keys:
            print(f"[{position:02d}/20] already collected {entry['label']} {entry['artifact']}", flush=True)
            continue
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as sample_list:
            sample_list.write(entry["artifact"] + "\n")
            sample_list_path = Path(sample_list.name)
        try:
            guest_dir = GUEST_BENIGN_DIR if entry["label"] == "benign" else "/home/csci/Downloads/malware_full_cohort_323"
            run_dir = OUTPUT / "runs" / entry["label"]
            log_path = OUTPUT / "logs" / f"{position:02d}-{entry['label']}-{entry['artifact']}.log"
            command = [
                "bash", str(batch_script),
                "--vm", VM,
                "--guest-user", GUEST_USER,
                "--guest-malware-dir", guest_dir,
                "--guest-runner", GUEST_RUNNER,
                "--snapshot", PILOT_SNAPSHOT,
                "--output-dir", str(run_dir),
                "--sample-list", str(sample_list_path),
                "--timeout", TIMEOUT_SECONDS,
                "--window-sec", WINDOW_SECONDS,
                "--iface", "enp0s3",
                "--ebpf",
                "--fixed-observation",
                "--common-launch-wrapper",
                "--watch-path", WATCH_PATH,
                "--resume",
            ]
            if entry["label"] == "benign":
                command.extend(["--guest-arguments-dir", GUEST_ARGUMENTS_DIR])
            print(f"[{position:02d}/20] collecting {entry['label']} {entry['artifact']}", flush=True)
            run_logged(command, log_path)
            sample_dir = run_dir / entry["artifact"]
            metadata_paths = list((sample_dir / "output").rglob("run.json"))
            if not metadata_paths:
                raise RuntimeError(f"Runner produced no run.json for {entry['artifact']}; inspect {log_path}")
            metadata = json.loads(metadata_paths[0].read_text(encoding="utf-8"))
            watch_paths = metadata.get("filesystem_watch_paths", [])
            watch_verified = WATCH_PATH in watch_paths
            if not watch_verified:
                raise RuntimeError(f"Runner did not monitor {WATCH_PATH}; inspect {log_path}")
        finally:
            sample_list_path.unlink(missing_ok=True)
        host_status_path = run_dir / entry["artifact"] / "host_run.txt"
        host_status = host_status_path.read_text(encoding="utf-8").strip() if host_status_path.exists() else "status=missing_host_status"
        provenance.setdefault("completed_batches", []).append({
            "position": position,
            "label": entry["label"],
            "artifact": entry["artifact"],
            "family": entry["family"],
            "return_code": 0,
            "runner_status": metadata.get("status", host_status.removeprefix("status=")),
            "sample_return_code": metadata.get("return_code"),
            "watch_path_verified": watch_verified,
            "log": str(log_path.relative_to(OUTPUT)),
        })
        manifest_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    provenance["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(f"Pilot complete: {OUTPUT}", flush=True)


if __name__ == "__main__":
    main()
