#!/usr/bin/env python3
"""Prepare an exploratory i386-only held-out amendment, without collection."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import prepare_inventory


ROOT = Path(__file__).resolve().parent
STUDY = prepare_inventory.STUDY
GUEST_ATTEMPT = ROOT / "operational-readiness/20261021T195042849982Z"
VALIDATION_PROJECT_SLOTS = {
    "e2fsprogs": 10,
    "ncurses": 5,
    "net-tools": 5,
    "bc": 2,
    "ed": 1,
    "m4": 1,
    "cpio": 1,
    "sharutils": 2,
    "make-dfsg": 1,
    "file": 1,
    "sqlite3": 1,
}
MALWARE_QUOTAS = {
    "training": {
        ("native_x86_64_static", "Mirai"): 49,
        ("native_i386_static", "Mirai"): 13,
        ("native_i386_static", "Gafgyt"): 6,
        ("native_i386_static", "DDoSAgent"): 1,
        ("native_i386_static", "Katana"): 1,
    },
    "validation": {
        ("native_i386_static", "XorDDoS"): 28,
        ("native_i386_static", "BillGates"): 1,
        ("native_i386_static", "ChinaZ"): 1,
    },
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare():
    inventory_path = ROOT / "inventory.json"
    if digest(inventory_path) != "e9d940b3c84f9ab1800c0e8ad63ca26ba229e6fc7a4de869810d526d385f5f94":
        raise ValueError("accepted additional inventory changed")
    inventory = json.loads(inventory_path.read_text())
    guest_report_path = GUEST_ATTEMPT / "guest_preflight.json"
    if digest(guest_report_path) != "a1bc66240428dc91ac96974924e8f729c3b9e0f5e03d08d530f564e4f2e33814":
        raise ValueError("accepted workload evidence changed")
    guest_report = json.loads(guest_report_path.read_text())
    manifest_path = GUEST_ATTEMPT / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if guest_report["status"] != "accepted" or guest_report["accepted"] != 100:
        raise ValueError("actual guest workloads were not accepted")
    previous_benign_path = prepare_inventory.PREPARATION / "manifests/benign-executables.json"
    previous_benign = json.loads(previous_benign_path.read_text())["executables"]
    previous_programs = {(row["project"], row["program"]) for row in previous_benign}
    previous_hashes = {row["sha256"] for row in previous_benign}
    accepted = {row["case_id"]: row["sha256"] for row in guest_report["cases"]
                if row["status"] == "accepted"}
    eligible = []
    rejected_program_reuse = []
    for row in manifest["cases"]:
        if accepted.get(row["case_id"]) != row["sha256"]:
            raise ValueError("guest evidence does not bind candidate")
        if (row["project"], row["program"]) in previous_programs:
            rejected_program_reuse.append(row["case_id"])
            continue
        if row["sha256"] in previous_hashes or digest(STUDY / row["source"]) != row["sha256"]:
            raise ValueError("previous or changed benign executable")
        eligible.append(row)
    benign_training = [row for row in eligible if row["arch"] == "amd64"]
    for project, count in (("coreutils", 15), ("util-linux", 6)):
        pool = sorted((row for row in eligible if row["arch"] == "i386" and row["project"] == project),
                      key=lambda row: row["program"])
        if len(pool) < count:
            raise ValueError("insufficient accepted additional i386 training controls")
        benign_training.extend(pool[:count])
    if len(benign_training) != 70 or Counter(row["arch"] for row in benign_training) != {"amd64": 49, "i386": 21}:
        raise ValueError("benign training quotas not met")
    previous_malware_path = prepare_inventory.PREPARATION / "manifests/malware-selection.json"
    previous_malware = json.loads(previous_malware_path.read_text())
    previous_malware_hashes = {row["sha256"] for split in ("training", "validation")
                               for row in previous_malware["malware_" + split]}
    malware = {}
    for split, quotas in MALWARE_QUOTAS.items():
        rows = []
        for (mode, signature), count in quotas.items():
            candidates = sorted((row for row in inventory["malware_candidates"]
                                 if row["execution_mode"] == mode
                                 and row["group_id"] == "malware_signature::" + signature),
                                key=lambda row: row["sha256"])
            if len(candidates) < count:
                raise ValueError("malware quota unavailable: " + signature)
            for row in candidates[:count]:
                if row["sha256"] in previous_malware_hashes:
                    raise ValueError("prior malware identity reused")
                if digest(STUDY / row["source_archive_path"]) != row["source_archive_sha256"]:
                    raise ValueError("source archive hash changed")
                rows.append(row)
        malware[split] = rows
    if len(malware["training"]) != 70 or len(malware["validation"]) != 30:
        raise ValueError("malware split counts differ")
    if {row["group_id"] for row in malware["training"]} & {row["group_id"] for row in malware["validation"]}:
        raise ValueError("malware signature leakage")
    if len({row["sha256"] for rows in malware.values() for row in rows}) != 100:
        raise ValueError("malware identities are not unique")
    training_projects = {row["project"] for row in benign_training}
    if training_projects & VALIDATION_PROJECT_SLOTS.keys() or sum(VALIDATION_PROJECT_SLOTS.values()) != 30:
        raise ValueError("benign project allocation invalid")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "i386-heldout-amendment" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    plan = {
        "status": "allocation_feasible_validation_controls_pending",
        "dataset_role": "exploratory_family_project_heldout_native_i386_transfer",
        "authorization": "User approved revised allocation after recommendation of x64-training-only and i386-held-out evaluation.",
        "collection_ready": False, "collection_started": False, "malware_executions": 0,
        "training_mode_counts_per_label": {"native_x86_64_static": 49, "native_i386_static": 21},
        "validation_mode_counts_per_label": {"native_i386_static": 30},
        "malware_training": malware["training"], "malware_validation": malware["validation"],
        "benign_training": benign_training,
        "benign_validation_project_slots": VALIDATION_PROJECT_SLOTS,
        "rejected_previous_project_program_cases": rejected_program_reuse,
        "validation_artifacts_identified": 0,
        "selection_rule": "Lexicographic hashes within malware mode/signature quotas; program order for accepted benign training controls; no runtime-outcome selection.",
        "input_hashes": {str(path.relative_to(STUDY)): digest(path) for path in (
            inventory_path, guest_report_path, manifest_path, previous_benign_path,
            previous_malware_path, Path(__file__),
        )},
        "pending_gates": [
            "Authenticate sources and identify 30 distinct i386 validation programs absent from the preceding program manifest.",
            "Build static ELF32 controls, verify original basenames, arguments, fixtures and substantive semantic outputs.",
            "Preflight changed controls in the common isolated guest; verify sensor/null evidence without rerunning accepted cases unnecessarily.",
            "Freeze exact benign/malware manifests, protocol, per-mode reporting, interleaved order and release hashes before collection.",
        ],
        "limitations": [
            "Validation is native static i386 only; no held-out x64 performance claim is permitted.",
            "Only four training malware signatures and three validation signatures; validation is 28 XorDDoS plus two singleton groups.",
            "Signatures are acquisition labels, not independently established behavioral families.",
            "Groups were previously explored; this is not a blind or confirmatory evaluation.",
            "Cross-architecture builds of a program are not independent software families; projects remain whole across this split.",
            "Prior consumed validation and frozen captures remain untouched; missing controls are slots, not executable identities.",
        ],
    }
    (attempt / "allocation.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"attempt": str(attempt), "status": plan["status"],
                      "malware": {split: len(rows) for split, rows in malware.items()},
                      "benign_training": len(benign_training), "validation_slots": 30,
                      "rejected_previous_program_cases": rejected_program_reuse,
                      "collection_ready": False}, indent=2))
    return attempt, plan


if __name__ == "__main__":
    prepare()