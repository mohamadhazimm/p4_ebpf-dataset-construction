#!/usr/bin/env python3
"""Inventory additional identities without executing samples or modifying prior cohorts."""

from __future__ import annotations

import csv
import importlib.util
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
PREVIOUS = ROOT.parent / "cohort-100x100-v18-20261021"
PREPARATION = PREVIOUS / "redesign-native-x64"


def load_builder():
    spec = importlib.util.spec_from_file_location("previous_selection", PREVIOUS / "prepare_selection.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load existing static ELF parser")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def main():
    builder = load_builder()
    previous_path = PREPARATION / "manifests/malware-selection.json"
    previous = json.loads(previous_path.read_text())
    previous_malware = {
        row["sha256"] for split in ("training", "validation")
        for row in previous[f"malware_{split}"]
    }
    benign_path = PREPARATION / "manifests/benign-executables.json"
    previous_benign_rows = json.loads(benign_path.read_text())["executables"]
    previous_benign = {row["sha256"] for row in previous_benign_rows}
    previous_programs = {(row["project"], row["program"]) for row in previous_benign_rows}
    if len(previous_malware) != 100 or len(previous_benign) != 100:
        raise ValueError("expected 100 previous identities per label")
    cohort_path = STUDY / "data/malware/full-cohort-323/cohort_manifest.csv"
    catalog_path = STUDY / "data/malware/catalog/archive_manifest.csv"
    archives = {}
    with cohort_path.open(newline="", encoding="utf-8-sig") as source:
        for row in csv.DictReader(source):
            sample = row["sample_artifact"]
            archives[Path(sample).stem] = (
                STUDY / "data/malware/full-cohort-323/samples" / sample, row, None,
            )
    with catalog_path.open(newline="", encoding="utf-8-sig") as source:
        for row in csv.DictReader(source):
            archives.setdefault(row["sample_sha256"], (
                STUDY / row["storage_path"], row, row["archive_sha256"],
            ))
    malware = []
    unsupported = Counter()
    for sample_hash, (path, row, expected_hash) in sorted(archives.items()):
        if sample_hash in previous_malware:
            continue
        if expected_hash and builder.sha256_file(path) != expected_hash:
            raise ValueError(f"catalog archive hash mismatch: {sample_hash}")
        observed = builder.inspect_archive(f"{sample_hash}.zip", row, path, strict_linkage=True)
        if observed["execution_mode"] == "unsupported":
            unsupported[observed["execution_mode"]] += 1
            continue
        malware.append(observed)
    report_path = PREPARATION / "preparation-audit.json"
    audit = json.loads(report_path.read_text())
    benign = []
    seen = set(previous_benign)
    for row in audit["verified_build_candidates"]:
        if row["sha256"] in seen:
            continue
        path = PREPARATION / row["path"]
        if builder.sha256_file(path) != row["sha256"]:
            raise ValueError(f"benign candidate hash changed: {path}")
        mode, little_endian = builder.inspect_elf(path.read_bytes(), strict_linkage=True)
        if mode != f"native_x86_64_{row['mode']}" or not little_endian:
            raise ValueError(f"benign candidate mode changed: {path}")
        seen.add(row["sha256"])
        benign.append({
            **row,
            "path": str(path.relative_to(STUDY)),
            "program": path.name,
            "execution_mode": mode,
            "same_project_program_in_previous_cohort": (row["project"], path.name) in previous_programs,
            "workload_status": "not_preflighted_for_expansion",
        })
    groups = defaultdict(Counter)
    for row in malware:
        groups[row["execution_mode"]][row["group_id"]] += 1
    native = [row for row in malware if row["execution_mode"].startswith("native_x86_64_")]
    distinct_programs = [row for row in benign if not row["same_project_program_in_previous_cohort"]]
    result = {
        "status": "inventory_only_design_not_frozen",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "collection_ready": False,
        "full_collection_started": False,
        "sample_executions": 0,
        "previous_malware_identity_count": len(previous_malware),
        "previous_benign_identity_count": len(previous_benign),
        "malware_candidates": malware,
        "benign_build_candidates": benign,
        "malware_mode_counts": dict(Counter(row["execution_mode"] for row in malware)),
        "malware_mode_groups": {mode: dict(counts) for mode, counts in groups.items()},
        "native_x64_malware_count": len(native),
        "benign_new_hash_count": len(benign),
        "benign_new_project_program_count": len({(row["project"], row["program"]) for row in distinct_programs}),
        "benign_new_program_mode_counts": dict(Counter(row["execution_mode"] for row in distinct_programs)),
        "unsupported_malware_count": sum(unsupported.values()),
        "input_hashes": {str(path.relative_to(STUDY)): builder.sha256_file(path) for path in (
            previous_path, benign_path, cohort_path, catalog_path, report_path,
            PREVIOUS / "prepare_selection.py", Path(__file__),
        )},
        "pending_gates": [
            "Decide expansion role without reusing the consumed holdout as confirmatory evidence.",
            "Select 100 additional distinct identities per label with matched modes and project/signature groups.",
            "Verify benign source/build provenance and safe noninteractive workloads, not merely distinct build hashes.",
            "Freeze a separate protocol, manifests, interleaved order, nulls and common snapshot.",
            "Separately authorize guest preflight and collection; this inventory does not operate a VM.",
        ],
        "limitations": [
            "Additional means absent from the preceding 100x100 identity manifests, not never explored historically.",
            "Different linkage/builds of the same project/program do not count as new programs automatically.",
            "Source signatures and acquisition categories are not verified malicious behavior.",
            "Build inventory is not safe-workload or guest-runtime readiness evidence.",
        ],
    }
    if previous_malware & {row["sha256"] for row in malware}:
        raise ValueError("previous malware identity leaked into additional inventory")
    if previous_benign & {row["sha256"] for row in benign}:
        raise ValueError("previous benign identity leaked into additional inventory")
    output = ROOT / "inventory.json"
    if output.exists():
        raise FileExistsError("preserve inventory.json; use a new preparation attempt")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: result[key] for key in (
        "status", "collection_ready", "native_x64_malware_count", "malware_mode_counts",
        "malware_mode_groups", "benign_new_hash_count", "benign_new_project_program_count",
        "benign_new_program_mode_counts",
    )}, indent=2))


if __name__ == "__main__":
    main()