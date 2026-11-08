#!/usr/bin/env python3
"""Build the offline malware split and matched benign mode quotas."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
STUDY_ROOT = ROOT.parents[2]
SOURCE_ROOT = STUDY_ROOT / "data/malware/full-cohort-323"
PILOT_ROOT = STUDY_ROOT / "data/versioned-collector/malware-native-static-v18-20261021"
OUTPUT_ROOT = ROOT / "manifests"
DYNAMIC_VALIDATION_GROUPS = {
    "malware_signature::Bert",
    "malware_signature::CatStorm",
    "malware_signature::DDoSAgent",
    "malware_signature::Gunra",
    "malware_signature::INC",
    "malware_signature::LockBit",
}
ARMEL_VALIDATION_GROUPS = {
    "malware_signature::DDoSTF",
    "malware_signature::FlylegitBot",
    "malware_signature::JackSkid",
    "malware_signature::Kimwolf",
    "malware_signature::MossadProxy",
    "malware_signature::Vibenet",
}
ARMEL_TRAIN_GROUPS = {
    "malware_signature::Gafgyt",
    "malware_signature::Katana",
}
I386_TRAIN_GROUPS = {
    "malware_signature::BillGates",
    "malware_signature::ChinaZ",
    "malware_signature::Gafgyt",
    "malware_signature::Katana",
    "malware_signature::Mirai",
    "malware_signature::unassigned",
}
I386_VALIDATION_GROUP = "malware_signature::XorDDoS"
PILOT_TRAIN_MODE = "native_x86_64_static"
ADDITIONAL_X64_TRAIN_MODE = "native_x86_64_static"
X64_DYNAMIC_MODE = "native_x86_64_dynamic"
ARMEL_MODE = "qemu_armel_static"
NATIVE_STATIC_HOLDOUT_COUNTS = {
    "malware_signature::Qilin": 13,
    "malware_signature::BrickStorm": 4,
    "malware_signature::DeskRAT": 3,
    "malware_signature::PromptLock": 1,
}
NATIVE_DYNAMIC_HOLDOUT_GROUPS = DYNAMIC_VALIDATION_GROUPS | {"malware_signature::RedGoBot"}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_elf(data: bytes, strict_linkage: bool = False) -> tuple[str, bool]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("archive member is not a complete ELF header")
    elf_class, data_encoding = data[4], data[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2}:
        raise ValueError("unsupported ELF class or byte order")
    endian = "<" if data_encoding == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    if elf_class == 2:
        phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
    else:
        phoff = struct.unpack_from(endian + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
    if phentsize < 4 or phoff + phentsize * phnum > len(data):
        raise ValueError("invalid ELF program-header table")
    program_types = [
        struct.unpack_from(endian + "I", data, phoff + index * phentsize)[0]
        for index in range(phnum)
    ]
    if strict_linkage and 2 in program_types and 3 not in program_types:
        return "unsupported", data_encoding == 1
    dynamic = 2 in program_types or 3 in program_types
    if machine == 62 and elf_class == 2:
        return "native_x86_64_dynamic" if dynamic else "native_x86_64_static", data_encoding == 1
    if machine == 3 and elf_class == 1 and not dynamic:
        return "native_i386_static", data_encoding == 1
    if machine == 40 and elf_class == 1 and data_encoding == 1 and not dynamic:
        return "qemu_armel_static", True
    return "unsupported", data_encoding == 1


def inspect_archive(
    sample: str,
    row: dict[str, str],
    archive_path: Path | None = None,
    strict_linkage: bool = False,
) -> dict[str, Any]:
    archive_path = archive_path or SOURCE_ROOT / "samples" / sample
    if not archive_path.is_file():
        raise FileNotFoundError(f"missing source archive: {archive_path}")
    result = subprocess.run(
        ["7z", "x", "-so", "-pinfected", str(archive_path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    member_digest = sha256_bytes(result.stdout)
    if member_digest != Path(sample).stem:
        raise ValueError(f"member hash does not match archive name: {sample}")
    mode, little_endian = inspect_elf(result.stdout, strict_linkage=strict_linkage)
    return {
        "sample": sample,
        "sha256": Path(sample).stem,
        "source_archive_path": str(archive_path.resolve().relative_to(STUDY_ROOT)),
        "source_archive_sha256": sha256_file(archive_path),
        "member_sha256": member_digest,
        "group_id": row.get("group_id") or f"malware_signature::{row['malware_family']}",
        "attack_type_label": row.get("attack_type_label") or row.get("malware_type", ""),
        "source_cohort": row.get("source_cohort") or row.get("source_collection", "catalog_expansion"),
        "source_classification_confidence": row.get("classification_confidence", ""),
        "execution_mode": mode,
        "little_endian": little_endian,
    }


def round_robin(records: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in sorted(records, key=lambda item: item["sample"]):
        by_group[record["group_id"]].append(record)
    selected: list[dict[str, Any]] = []
    group_names = sorted(by_group)
    while len(selected) < count:
        added = False
        for group_name in group_names:
            if by_group[group_name] and len(selected) < count:
                selected.append(by_group[group_name].pop(0))
                added = True
        if not added:
            raise ValueError(f"only {len(selected)} candidates available; need {count}")
    return selected


def write_lines(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(f"{record['sample']}\n" for record in records), encoding="ascii")


def select_native_x64(
    candidates: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    holdout_groups = set(NATIVE_STATIC_HOLDOUT_COUNTS) | NATIVE_DYNAMIC_HOLDOUT_GROUPS
    validation = []
    for group_id, count in NATIVE_STATIC_HOLDOUT_COUNTS.items():
        pool = [record for record in candidates[PILOT_TRAIN_MODE] if record["group_id"] == group_id]
        validation.extend(round_robin(pool, count))
    dynamic_holdout = [
        record for record in candidates[X64_DYNAMIC_MODE]
        if record["group_id"] in NATIVE_DYNAMIC_HOLDOUT_GROUPS
    ]
    if len(dynamic_holdout) != 9:
        raise ValueError(f"expected nine interpreter-linked native holdouts, found {len(dynamic_holdout)}")
    validation.extend(dynamic_holdout)
    training = []
    for mode, count in ((PILOT_TRAIN_MODE, 63), (X64_DYNAMIC_MODE, 7)):
        pool = [record for record in candidates[mode]
                if record["group_id"] not in holdout_groups | {"malware_signature::unassigned"}]
        training.extend(round_robin(pool, count))
    return sorted(training, key=lambda record: record["sample"]), sorted(validation, key=lambda record: record["sample"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--design", choices=("original", "native-x64"), default="native-x64")
    args = parser.parse_args()
    with (SOURCE_ROOT / "cohort_manifest.csv").open(newline="", encoding="utf-8") as source:
        source_rows = list(csv.DictReader(source))
    if len(source_rows) != 323:
        raise ValueError(f"expected 323 source manifest rows, found {len(source_rows)}")
    source_by_sample = {row["sample_artifact"]: row for row in source_rows}
    if len(source_by_sample) != len(source_rows):
        raise ValueError("source manifest contains duplicate artifact names")
    catalog_path = STUDY_ROOT / "data/malware/malware_sample_source_catalog.csv"
    with catalog_path.open(newline="", encoding="utf-8-sig") as source:
        catalog_by_hash = {row["sha256"]: row for row in csv.DictReader(source)}
    archive_manifest_path = STUDY_ROOT / "data/malware/catalog/archive_manifest.csv"
    with archive_manifest_path.open(newline="", encoding="utf-8-sig") as source:
        archive_rows = sorted(
            csv.DictReader(source),
            key=lambda row: (row["sample_sha256"], row["storage_path"]),
        )
    archive_by_hash: dict[str, dict[str, str]] = {}
    for row in archive_rows:
        existing = archive_by_hash.get(row["sample_sha256"])
        identity = (row["malware_family"], row["malware_type"])
        if existing and (existing["malware_family"], existing["malware_type"]) != identity:
            raise ValueError(f"conflicting catalog family/type metadata for {row['sample_sha256']}")
        archive_by_hash.setdefault(row["sample_sha256"], row)

    pilot_names = [
        line.strip()
        for line in (PILOT_ROOT / "manifests/malware-20.txt").read_text(encoding="ascii").splitlines()
        if line.strip()
    ]
    if len(pilot_names) != 20 or len(set(pilot_names)) != 20:
        raise ValueError("pilot manifest must contain 20 unique malware artifacts")

    candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    source_hashes = {sample.removesuffix(".zip") for sample in source_by_sample}
    for sample, row in source_by_sample.items():
        record = inspect_archive(sample, row, strict_linkage=args.design == "native-x64")
        catalog = catalog_by_hash.get(record["sha256"], {})
        record["malwarebazaar_category"] = catalog.get("malwarebazaar_category", "")
        record["malwarebazaar_tags"] = catalog.get("malwarebazaar_tags", "")
        record["family_type_metadata"] = catalog.get("family_type", "") or row.get("attack_type_label", "")
        if record["execution_mode"] != "unsupported":
            candidates[record["execution_mode"]].append(record)

    catalog_extra_records = []
    for sample_hash, row in archive_by_hash.items():
        if sample_hash in source_hashes:
            continue
        archive_path = STUDY_ROOT / row["storage_path"]
        archive_digest = sha256_file(archive_path)
        if archive_digest != row["archive_sha256"]:
            raise ValueError(f"catalog archive hash mismatch for {sample_hash}")
        record = inspect_archive(f"{sample_hash}.zip", row, archive_path, strict_linkage=args.design == "native-x64")
        catalog = catalog_by_hash.get(sample_hash, {})
        record["malwarebazaar_category"] = catalog.get("malwarebazaar_category", "") or row["malware_type"]
        record["malwarebazaar_tags"] = catalog.get("malwarebazaar_tags", "") or row["malware_type"]
        record["family_type_metadata"] = catalog.get("family_type", "") or row["malware_type"]
        record["origin"] = "catalog_expansion_to_collect_under_v18"
        catalog_extra_records.append(record)
        if record["execution_mode"] != "unsupported":
            candidates[record["execution_mode"]].append(record)

    if args.design == "native-x64":
        training, validation = select_native_x64(candidates)
        training_groups = {record["group_id"] for record in training}
        validation_groups = {record["group_id"] for record in validation}
        if len(training) != 70 or len(validation) != 30 or training_groups & validation_groups:
            raise ValueError("native redesign must have 70/30 whole-family-disjoint samples")
        if len({record["sha256"] for record in training + validation}) != 100:
            raise ValueError("native redesign requires 100 unique member hashes")
        quotas = {
            "training": {PILOT_TRAIN_MODE: 63, X64_DYNAMIC_MODE: 7},
            "validation": {PILOT_TRAIN_MODE: 21, X64_DYNAMIC_MODE: 9},
        }
        for split, records in (("training", training), ("validation", validation)):
            if Counter(record["execution_mode"] for record in records) != Counter(quotas[split]):
                raise ValueError(f"native {split} quotas disagree")
            for record in records:
                record["origin"] = "fresh_collection_required_native_redesign"
        output_root = ROOT / "redesign-native-x64" / "manifests"
        output_root.mkdir(parents=True, exist_ok=True)
        selection = {
            "status": "candidate_native_redesign_benign_builds_and_preflight_pending",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "design": "native-x64",
            "mode_counts": quotas,
            "training_signature_groups": sorted(training_groups),
            "validation_signature_groups": sorted(validation_groups),
            "malware_training": training,
            "malware_validation": validation,
            "source_hashes": {
                "cohort_manifest_sha256": sha256_file(SOURCE_ROOT / "cohort_manifest.csv"),
                "source_catalog_sha256": sha256_file(catalog_path),
                "archive_manifest_sha256": sha256_file(archive_manifest_path),
                "builder_sha256": sha256_file(Path(__file__)),
            },
            "limitations": [
                "All cases require fresh interleaved collection from one common clean snapshot; no automatic pilot reuse.",
                "Native x86-64 only; no i386 or qemu generalization claim.",
                "Exclude PT_DYNAMIC without PT_INTERP (including static PIE); dynamic means a declared runtime interpreter.",
                "Source signatures are imperfect family labels; source malware types are not verified behavior.",
                "Some held-out families were explored previously; this is not a previously unseen blind test.",
                "Train/validation linkage proportions differ; match each split across labels and report per-linkage metrics.",
            ],
        }
        benign = {
            "status": "candidate_native_mode_quotas_builds_and_preflight_pending",
            "target_benign_total": 100,
            **quotas,
            "requirements": [
                "100 distinct executable member hashes; no multicall aliases or repeated workload profiles as extra samples.",
                "84 static and 16 interpreter-linked dynamic native x86-64 executables; verify ELF headers rather than names.",
                "Use authenticated distro packages or verified upstream sources with recorded build recipes and hashes.",
                "Keep whole upstream software projects in one split, including all static/dynamic build variants.",
                "Balance build toolchain/runtime provenance across labels where possible and audit remaining confounds.",
                "Freeze exact executable IDs, safe workload arguments, and a balanced interleaved case order before collection.",
                "No collection until source verification, dependencies, activation/null controls, and preflight pass.",
            ],
        }
        (output_root / "malware-selection.json").write_text(json.dumps(selection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (output_root / "benign-mode-quotas.json").write_text(json.dumps(benign, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        write_lines(output_root / "malware-training.txt", training)
        write_lines(output_root / "malware-validation.txt", validation)
        write_lines(output_root / "malware-to-collect.txt", training + validation)
        print(json.dumps({"malware_training": len(training), "malware_validation": len(validation),
                          "training_groups": len(training_groups), "validation_groups": len(validation_groups),
                          "mode_counts": quotas, "status": selection["status"], "manifest_dir": str(output_root)}, indent=2))
        return

    pilot_records = []
    for sample in pilot_names:
        if sample not in source_by_sample:
            raise ValueError(f"pilot sample absent from 323-artifact inventory: {sample}")
        record = next(
            (item for item in candidates[PILOT_TRAIN_MODE] if item["sample"] == sample),
            None,
        )
        if record is None:
            raise ValueError(f"pilot sample is not in the expected mode: {sample}")
        record["origin"] = "existing_v18_pilot_requires_compatibility_audit"
        pilot_records.append(record)

    pilot_groups = {record["group_id"] for record in pilot_records}
    extra_x64 = [
        record
        for record in candidates[ADDITIONAL_X64_TRAIN_MODE]
        if record["group_id"] in pilot_groups | {"malware_signature::unassigned"}
        and record["sample"] not in set(pilot_names)
    ]
    extra_x64 = round_robin(extra_x64, 20)
    for record in extra_x64:
        record["origin"] = "existing_archive_to_collect_under_v18"

    dynamic_train_pool = [
        record
        for record in candidates[X64_DYNAMIC_MODE]
        if record["group_id"] not in DYNAMIC_VALIDATION_GROUPS
    ]
    if len(dynamic_train_pool) < 10:
        raise ValueError(
            f"need ten x86-64 dynamic training candidates outside held-out groups, found {len(dynamic_train_pool)}"
        )
    dynamic_train = round_robin(dynamic_train_pool, 10)
    for record in dynamic_train:
        record["origin"] = "existing_archive_to_collect_under_v18"

    armel_train_pool = [
        record
        for record in candidates[ARMEL_MODE]
        if record["group_id"] in ARMEL_TRAIN_GROUPS
    ]
    armel_train = round_robin(armel_train_pool, 6)
    for record in armel_train:
        record["origin"] = "existing_archive_to_collect_under_v18"

    i386_train_pool = [
        record
        for record in candidates["native_i386_static"]
        if record["group_id"] in I386_TRAIN_GROUPS
    ]
    i386_train = round_robin(i386_train_pool, 14)
    for record in i386_train:
        record["origin"] = "existing_archive_to_collect_under_v18"

    armel_validation_pool = [
        record
        for record in candidates[ARMEL_MODE]
        if record["group_id"] in ARMEL_VALIDATION_GROUPS
    ]
    if {record["group_id"] for record in armel_validation_pool} != ARMEL_VALIDATION_GROUPS:
        raise ValueError("all six preregistered ARMEL validation groups must be represented")
    armel_validation = round_robin(armel_validation_pool, 6)
    for record in armel_validation:
        record["origin"] = "existing_archive_to_collect_under_v18"

    i386_validation_pool = [
        record
        for record in catalog_extra_records
        if record["execution_mode"] == "native_i386_static"
        and record["group_id"] == I386_VALIDATION_GROUP
    ]
    if len(i386_validation_pool) < 15:
        raise ValueError(f"need 15 catalog XorDDoS i386 samples, found {len(i386_validation_pool)}")
    i386_validation = round_robin(i386_validation_pool, 15)
    for record in i386_validation:
        record["origin"] = "catalog_expansion_to_collect_under_v18"

    dynamic_validation_pool = [
        record
        for record in candidates[X64_DYNAMIC_MODE]
        if record["group_id"] in DYNAMIC_VALIDATION_GROUPS
    ]
    if len(dynamic_validation_pool) != 9:
        raise ValueError(
            f"expected nine x86-64 dynamic validation candidates across six groups, found {len(dynamic_validation_pool)}"
        )
    dynamic_validation = round_robin(dynamic_validation_pool, 9)
    for record in dynamic_validation:
        record["origin"] = "existing_archive_to_collect_under_v18"

    training = sorted(
        pilot_records + extra_x64 + dynamic_train + armel_train + i386_train,
        key=lambda item: item["sample"],
    )
    validation = sorted(armel_validation + i386_validation + dynamic_validation, key=lambda item: item["sample"])
    training_groups = {record["group_id"] for record in training}
    validation_groups = {record["group_id"] for record in validation}
    if len(training) != 70 or len(validation) != 30:
        raise ValueError("malware split must contain exactly 70 training and 30 validation cases")
    if training_groups & validation_groups:
        raise ValueError(f"signature groups cross the split: {sorted(training_groups & validation_groups)}")
    expected_validation_groups = DYNAMIC_VALIDATION_GROUPS | ARMEL_VALIDATION_GROUPS | {I386_VALIDATION_GROUP}
    if len(validation_groups) != 13 or validation_groups != expected_validation_groups:
        raise ValueError("validation must contain exactly the thirteen preregistered signature groups")
    if Counter(record["execution_mode"] for record in training) != Counter(
        {
            PILOT_TRAIN_MODE: 40,
            X64_DYNAMIC_MODE: 10,
            "native_i386_static": 14,
            ARMEL_MODE: 6,
        }
    ):
        raise ValueError("training mode counts do not match the planned 40/10/14/6 quotas")
    if Counter(record["execution_mode"] for record in validation) != Counter(
        {ARMEL_MODE: 6, X64_DYNAMIC_MODE: 9, "native_i386_static": 15}
    ):
        raise ValueError("validation mode counts do not match the planned 21/9 quotas")
    if len({record["sample"] for record in training + validation}) != 100:
        raise ValueError("malware selection contains duplicate samples")

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    to_collect = [
        record
        for record in training + validation
        if record["origin"] != "existing_v18_pilot_requires_compatibility_audit"
    ]
    selection = {
        "status": "candidate_split_needs_review",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target_malware_total": 100,
        "split": {
            "training": 70,
            "validation": 30,
            "unit": "whole MalwareBazaar signature group",
            "training_signature_groups": sorted(training_groups),
            "validation_signature_groups": sorted(validation_groups),
        },
        "mode_counts": {
            "training": dict(Counter(record["execution_mode"] for record in training)),
            "validation": dict(Counter(record["execution_mode"] for record in validation)),
        },
        "source_hashes": {
            "cohort_manifest_sha256": sha256_file(SOURCE_ROOT / "cohort_manifest.csv"),
            "source_catalog_sha256": sha256_file(catalog_path),
            "archive_manifest_sha256": sha256_file(archive_manifest_path),
            "pilot_manifest_sha256": sha256_file(PILOT_ROOT / "manifests/malware-20.txt"),
        },
        "selection_rule": (
            "Use the 20 existing .18 pilot malware only in training; add 20 native x86-64 static "
            "samples round-robin from pilot signature groups plus unassigned; add ten x86-64 dynamic "
            "samples outside the six held-out groups, six armel static samples from Gafgyt and Katana, and "
            "14 native i386 static samples from BillGates, ChinaZ, Gafgyt, Katana, Mirai, and unassigned. "
            "Reserve 15 catalog XorDDoS i386 static samples, six armel static samples across DDoSTF, "
            "FlylegitBot, JackSkid, Kimwolf, MossadProxy, and Vibenet, and nine x86-64 dynamic samples "
            "across Bert, CatStorm, DDoSAgent, Gunra, INC, and LockBit for validation. "
            "Selection uses archive identity, signature, and ELF headers only, not prior runtime outcomes."
        ),
        "validation_scope": "family-held-out native-i386-static, qemu-armel-static, and native-x86-64-dynamic strata; category metadata is incomplete and must be reported as such",
        "reuse_gate": "Audit each existing pilot run's runner hash, schema, settings, quality, and capture provenance before reuse.",
        "malware_training": training,
        "malware_validation": validation,
    }
    (OUTPUT_ROOT / "malware-selection.json").write_text(
        json.dumps(selection, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_lines(OUTPUT_ROOT / "malware-training.txt", training)
    write_lines(OUTPUT_ROOT / "malware-validation.txt", validation)
    write_lines(OUTPUT_ROOT / "malware-to-collect.txt", to_collect)

    benign_quotas = {
        "status": "candidate_mode_quotas_binary_sources_pending",
        "target_benign_total": 100,
        "training": {
            PILOT_TRAIN_MODE: 40,
            X64_DYNAMIC_MODE: 10,
            "native_i386_static": 14,
            ARMEL_MODE: 6,
        },
        "validation": {ARMEL_MODE: 6, "native_i386_static": 15, X64_DYNAMIC_MODE: 9},
        "requirements": [
            "One distinct benign executable per case; do not inflate sample count with repeated profiles.",
            "Match ELF architecture, static linkage, and runner execution mode to the malware case.",
            "Keep software-project groups entirely within training or validation.",
            "Use signed distro packages or verified upstream releases; record package/version/source URL and SHA-256.",
            "The 8 synthetic controls and 3 nulls from the existing pilot do not count toward this set.",
        ],
        "pending": "Exact benign artifact IDs and package provenance must be acquired and verified before collection.",
    }
    (OUTPUT_ROOT / "benign-mode-quotas.json").write_text(
        json.dumps(benign_quotas, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "malware_training": len(training),
                "malware_validation": len(validation),
                "malware_new_collection": len(to_collect),
                "training_groups": len(training_groups),
                "validation_groups": len(validation_groups),
                "mode_counts": selection["mode_counts"],
                "manifest_dir": str(OUTPUT_ROOT),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()