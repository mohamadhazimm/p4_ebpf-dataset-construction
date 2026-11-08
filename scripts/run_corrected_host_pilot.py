#!/usr/bin/env python3
"""Freeze and optionally collect a separate 40-run corrected-host pilot."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

STUDY = Path(__file__).resolve().parents[1]
OLD_ROOT = STUDY / "data/versioned-collector/telemetry-2026-10-17.2-20261017T220948Z"
NATIVE_COMMANDS = ("sha256sum", "sort", "find", "gzip", "tar", "grep", "head", "ls", "curl", "cmp", "sha512sum", "uniq", "wc", "bzip2", "du", "cut", "tail", "stat", "od", "wget")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vm_info(name):
    result = subprocess.run(["VBoxManage", "showvminfo", name, "--machinereadable"], check=True, capture_output=True, text=True)
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--reuse-malware-from", type=Path)
    args = parser.parse_args()
    root = args.output_dir.resolve()
    runner = STUDY / "src/malware_runner.py"
    manifest_path = root / "pilot_manifest.json"
    if not manifest_path.exists():
        root.mkdir(parents=True, exist_ok=False)
        (root / "manifests").mkdir()
        (root / "logs").mkdir()
        assignments = []
        rng = np.random.default_rng(42)
        for split in ("training", "validation"):
            with (OLD_ROOT / "modeling/hostmon-native26-small200-20261018" / f"{split}_samples.csv").open(newline="") as source:
                candidates = [row for row in csv.DictReader(source) if row["label"] == "1" and row["cohort"] == "malware-training-535"]
            indices = rng.choice(len(candidates), size=10, replace=False)
            selected = [candidates[int(index)] for index in indices]
            for row in selected:
                assignments.append({"artifact": row["sample_artifact"], "label": 1, "split": split, "source_cohort": row["cohort"], "prior_status": row["runner_status"]})
            native_indices = range(1, 11) if split == "training" else range(11, 21)
            assignments.extend({"artifact": NATIVE_COMMANDS[index - 1], "label": 0, "split": split, "source_cohort": "native-Ubuntu-executable-control"} for index in native_indices)
        assert len(assignments) == len({row["artifact"] for row in assignments}) == 40
        cohorts = {}
        for split in ("training", "validation"):
            for label, kind in ((0, "benign"), (1, "malware")):
                name = f"{kind}-{split}"
                path = root / "manifests" / f"{name}.txt"
                selected = [row["artifact"] for row in assignments if row["split"] == split and row["label"] == label]
                path.write_text("".join(artifact + "\n" for artifact in sorted(selected)))
                cohorts[name] = {"label": label, "split": split, "manifest": str(path.relative_to(root)), "sha256": digest(path)}
        manifest = {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "runner_sha256": digest(runner), "schema_version": "2026-10-18.1",
            "guest_setup_sha256": digest(STUDY / "scripts/prepare_corrected_host_pilot_guest.sh"),
            "malware_capture_source": str(args.reuse_malware_from.resolve()) if args.reuse_malware_from else None,
            "snapshot": "clean-" + root.name,
            "baseline": "clean-versioned-telemetry-20261017.2-malware-full",
            "fixed_observation_seconds": 5, "window_seconds": 0.5,
            "cohorts": cohorts, "assignments": assignments,
            "limitations": ["Pilot only: 20 held-out samples", "Native benign control differs from old shell workloads", "Benign commands have package overlap across splits", "Multiple collection changes prevent attributing accuracy changes to filtering alone"],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    manifest = json.loads(manifest_path.read_text())
    assert digest(runner) == manifest["runner_sha256"], "Runner changed after pilot was frozen"
    if "guest_setup_sha256" in manifest:
        assert digest(STUDY / "scripts/prepare_corrected_host_pilot_guest.sh") == manifest["guest_setup_sha256"]
    for definition in manifest["cohorts"].values():
        assert digest(root / definition["manifest"]) == definition["sha256"]
    print("PILOT_ROOT", root, flush=True)
    if manifest.get("malware_capture_source"):
        source_root = Path(manifest["malware_capture_source"])
        source_manifest = json.loads((source_root / "pilot_manifest.json").read_text())
        assert source_manifest["runner_sha256"] == manifest["runner_sha256"]
        for name, definition in manifest["cohorts"].items():
            if definition["label"] != 1:
                continue
            for artifact in (root / definition["manifest"]).read_text().splitlines():
                source = source_root / "runs" / name / artifact
                destination = root / "runs" / name / artifact
                assert "status=completed" in (source / "host_run.txt").read_text().splitlines()
                metadata = json.loads(next((source / "output").rglob("run.json")).read_text())
                assert metadata["malware_runner_sha256"] == manifest["runner_sha256"]
                assert metadata["windows"] == 10 and metadata["observation_mode"] == "fixed"
                if not destination.exists():
                    shutil.copytree(source, destination)
    if not args.collect:
        print("Frozen 40 unique assignments; use --collect to stage and execute only inside the isolated VM.")
        return
    for name in ("Ubuntu-Clean-24.04", "Sink"):
        info = vm_info(name)
        assert all(value.strip('"') in {"none", "null", "intnet"} for key, value in info.items() if key.startswith("nic") and key[3:].isdigit()), "Host-connected NIC detected"
    assert vm_info("Ubuntu-Clean-24.04")["VMState"] == '"poweroff"'
    sink_started = vm_info("Sink")["VMState"] == '"poweroff"'
    if sink_started:
        subprocess.run(["VBoxManage", "startvm", "Sink", "--type", "headless"], check=True)
    try:
        snapshots = subprocess.run(["VBoxManage", "snapshot", "Ubuntu-Clean-24.04", "list", "--machinereadable"], check=True, capture_output=True, text=True).stdout
        if f'="{manifest["snapshot"]}"' not in snapshots:
            subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", "Ubuntu-Clean-24.04", "--guest-user", "csci", "--baseline-snapshot", manifest["baseline"], "--new-snapshot", manifest["snapshot"], "--guest-setup", str(STUDY / "scripts/prepare_corrected_host_pilot_guest.sh")], check=True)
        for name, definition in manifest["cohorts"].items():
            guest_dir = "/home/csci/Downloads/corrected-host-pilot-20261018/benign" if definition["label"] == 0 else "/home/csci/Downloads/model training"
            command = ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"), "--vm", "Ubuntu-Clean-24.04", "--guest-user", "csci", "--guest-malware-dir", guest_dir, "--snapshot", manifest["snapshot"], "--output-dir", str(root / "runs" / name), "--sample-list", str(root / definition["manifest"]), "--timeout", "5", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf", "--fixed-observation", "--common-launch-wrapper", "--resume"]
            if definition["label"] == 0:
                command += ["--guest-arguments-dir", "/home/csci/Downloads/corrected-host-pilot-20261018/arguments"]
            with (root / "logs" / f"{name}.log").open("a") as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            print("COLLECTED", name, flush=True)
    finally:
        if sink_started:
            subprocess.run(["VBoxManage", "controlvm", "Sink", "poweroff"], check=False)


if __name__ == "__main__":
    main()