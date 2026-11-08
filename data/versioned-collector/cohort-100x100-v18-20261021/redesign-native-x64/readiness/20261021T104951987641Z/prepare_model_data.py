#!/usr/bin/env python3
"""Prepare accepted .18 records for the preregistered held-out analysis."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

import numpy as np


ATTEMPT_DIR = Path(__file__).resolve().parent
EXPERIMENT_DIR = ATTEMPT_DIR.parents[1]
STUDY_DIR = EXPERIMENT_DIR.parents[3]
WORKSPACE_DIR = STUDY_DIR.parents[1]
P4_DIR = WORKSPACE_DIR / "p4_ebpf"
OUTPUT_DIR = ATTEMPT_DIR / "analysis"
CASE_ORDER_PATH = ATTEMPT_DIR / "case_order.csv"
COLLECTION_DIR = ATTEMPT_DIR / "collection" / "runs"
VALIDATION_PATH = ATTEMPT_DIR / "collection_validation.json"
PREREGISTRATION_PATH = ATTEMPT_DIR / "preregistration.json"
HOST_FEATURE_PATH = STUDY_DIR / "data/benign/revision3/labeled_sample_dataset.feature_columns.json"
RUNNER_SHA256 = "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49"
SCHEMA = "2026-10-20.18"

sys.path.insert(0, str(STUDY_DIR / "src"))
sys.path.insert(0, str(P4_DIR))

import analyze_p4_pcap_ablation as p4  # noqa: E402
from build_dataset import aggregate  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def host_status(sample_dir: Path) -> str:
    path = sample_dir / "host_run.txt"
    if not path.is_file():
        return "missing_host_run"
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("status="):
            return line.partition("=")[2].strip()
    return "unknown"


def one_file(sample_dir: Path, name: str) -> Path:
    paths = list(sample_dir.rglob(name))
    if len(paths) != 1:
        raise ValueError(f"Expected exactly one {name} under {sample_dir}, found {len(paths)}")
    return paths[0]


def read_case_order() -> list[dict[str, str]]:
    with CASE_ORDER_PATH.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    if len(rows) != 206 or len({row["sample"] for row in rows}) != len(rows):
        raise ValueError("Frozen case order must contain 206 unique sample names")
    expected = {
        "calibration": Counter({"null": 6}),
        "training": Counter({"benign": 70, "malware": 70}),
        "validation": Counter({"benign": 30, "malware": 30}),
    }
    for split, counts in expected.items():
        actual = Counter(row["class"] for row in rows if row["split"] == split)
        if actual != counts:
            raise ValueError(f"Frozen {split} split changed: {dict(actual)}")
    train_groups = {row["group_id"] for row in rows if row["split"] == "training"}
    validation_groups = {row["group_id"] for row in rows if row["split"] == "validation"}
    if train_groups & validation_groups:
        raise ValueError("A malware signature or benign project crosses the frozen split")
    return rows


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    validation = json.loads(VALIDATION_PATH.read_text(encoding="utf-8"))
    manifest = json.loads((ATTEMPT_DIR / "collection_manifest.json").read_text(encoding="utf-8"))
    preregistration = json.loads(PREREGISTRATION_PATH.read_text(encoding="utf-8"))
    if manifest["status"] != "completed_with_exceptions":
        raise ValueError("Collection manifest is not finalized")
    if sha256(VALIDATION_PATH) != manifest["validation_report_sha256"]:
        raise ValueError("Collection audit hash does not match the frozen manifest")
    if preregistration["schema"] != SCHEMA or preregistration["analysis"]["threshold"] != 0.5:
        raise ValueError("Unexpected frozen analysis protocol")

    host_contract = json.loads(HOST_FEATURE_PATH.read_text(encoding="utf-8"))
    host_features = list(host_contract["host"])
    host_families = p4.feature_family_indices(host_features)
    if len(host_features) != 175 or len(host_families) != 35:
        raise ValueError("Host contract must contain 35 complete families x five summaries")
    if len(p4.P4_FEATURES) != 29 or len(p4.P4_SAMPLE_FEATURES) != 145:
        raise ValueError("P4 contract differs from the frozen 29-family protocol")

    cases = read_case_order()
    eligibility_rows = []
    alignment_rows = []
    host_eligible = []
    common_aligned = []
    accepted_count = 0
    parity_comparisons = 0

    for case in cases:
        sample = case["sample"]
        sample_dir = COLLECTION_DIR / sample
        status = host_status(sample_dir)
        run_paths = list(sample_dir.rglob("run.json")) if sample_dir.is_dir() else []
        audit_row = {
            **case,
            "host_status": status,
            "quality_status": "unavailable",
            "target_exec_status": "unavailable",
            "p4_alignment_status": "not_attempted",
            "primary_host_eligible": 0,
            "primary_common_aligned": 0,
            "exclusion_reason": "",
        }

        if len(run_paths) == 0:
            audit_row["exclusion_reason"] = "output_not_retrieved_or_run_metadata_missing"
            eligibility_rows.append(audit_row)
            continue
        if len(run_paths) != 1:
            raise ValueError(f"{sample}: expected one run.json, found {len(run_paths)}")

        metadata_path = run_paths[0]
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("telemetry_schema_version") != SCHEMA:
            raise ValueError(f"{sample}: schema mismatch")
        if metadata.get("malware_runner_sha256") != RUNNER_SHA256:
            raise ValueError(f"{sample}: runner hash mismatch")
        quality = metadata.get("collection_quality_status")
        audit_row["quality_status"] = quality or "unavailable"
        if quality != "accepted":
            audit_row["exclusion_reason"] = "collection_quality_not_accepted"
            eligibility_rows.append(audit_row)
            continue
        accepted_count += 1

        if case["class"] == "null":
            audit_row["exclusion_reason"] = "calibration_control_not_classifier_sample"
            eligibility_rows.append(audit_row)
            continue

        target_exec = metadata.get("target_exec", {})
        target_status = target_exec.get("status", "unavailable")
        audit_row["target_exec_status"] = target_status
        if target_status != "observed":
            audit_row["exclusion_reason"] = "target_exec_not_observed"
            eligibility_rows.append(audit_row)
            continue

        telemetry = p4.load_telemetry_rows(sample_dir)
        if len(telemetry) != 40:
            raise ValueError(f"{sample}: expected 40 telemetry windows, found {len(telemetry)}")
        stored_p4 = set(metadata.get("telemetry_feature_groups", {}).get("p4_network", []))
        if stored_p4 != set(p4.P4_FEATURES):
            raise ValueError(f"{sample}: stored P4 feature names differ from the canonical contract")
        available = set(telemetry[0])
        host_signals = {
            feature.removeprefix("host__").rsplit("__", 1)[0]
            for feature in host_features
        }
        if not host_signals.issubset(available) or not set(p4.P4_FEATURES).issubset(available):
            raise ValueError(f"{sample}: one or more required telemetry signals are absent")
        for row in telemetry:
            for feature in host_signals | set(p4.P4_FEATURES):
                value = float(row[feature])
                if not math.isfinite(value):
                    raise ValueError(f"{sample}: non-finite required telemetry value {feature}")

        summary_by_signal = {
            signal: aggregate([float(row[signal]) for row in telemetry])
            for signal in host_signals | set(p4.P4_FEATURES)
        }
        host_values = {
            feature: summary_by_signal[feature.removeprefix("host__").rsplit("__", 1)[0]][
                feature.rsplit("__", 1)[1]
            ]
            for feature in host_features
        }
        record = {
            "sample": sample,
            "class": case["class"],
            "label": 1 if case["class"] == "malware" else 0,
            "split": case["split"],
            "mode": case["mode"],
            "group_id": case["group_id"],
            "position": int(case["position"]),
            "run_id": metadata.get("run_id", ""),
            "return_code": metadata.get("return_code"),
            "post_target_lineage_raw_syscalls": int(
                target_exec.get("post_target_lineage_raw_syscalls", 0)
            ),
            "host_features": host_values,
            "p4_alignment_status": "not_attempted",
            "p4_features": {},
        }
        audit_row["primary_host_eligible"] = 1
        audit_row["exclusion_reason"] = ""

        pcap_path = one_file(sample_dir, "packet_capture.pcap")
        extracted, _, diagnostics = p4.derive_p4_features(
            pcap_path,
            telemetry,
            metadata,
            byte_layer="ethernet",
            rate_window="nominal",
        )
        alignment = str(diagnostics["alignment_status"])
        record["p4_alignment_status"] = alignment
        audit_row["p4_alignment_status"] = alignment
        alignment_row = {
            "sample": sample,
            "class": case["class"],
            "split": case["split"],
            "group_id": case["group_id"],
            **diagnostics,
        }
        alignment_rows.append(alignment_row)

        if alignment == "unique":
            for signal in p4.P4_FEATURES:
                for statistic, stored_value in summary_by_signal[signal].items():
                    feature = f"network__p4_{signal}__{statistic}"
                    extracted_value = float(extracted[feature])
                    parity_comparisons += 1
                    if not math.isclose(
                        float(stored_value), extracted_value, rel_tol=1e-9, abs_tol=1e-9
                    ):
                        raise ValueError(
                            f"{sample}: stored/extracted P4 mismatch for {feature}: "
                            f"{stored_value} != {extracted_value}"
                        )
            record["p4_features"] = extracted
            record["p4_parity"] = True
            audit_row["primary_common_aligned"] = 1
            common_aligned.append(record)
        else:
            record["p4_parity"] = False
            audit_row["exclusion_reason"] = "p4_alignment_not_unique"
        host_eligible.append(record)
        eligibility_rows.append(audit_row)

    if accepted_count != validation["quality_counts"]["accepted"] + validation["quality_counts"]["rejected"] - 1:
        # The six nulls are included in this accepted-count check; rejected data is excluded.
        raise ValueError(f"Unexpected number of retrieved quality-accepted records: {accepted_count}")
    if len(host_eligible) != 194:
        raise ValueError(f"Expected 194 quality-accepted, target-observed classifier cases; found {len(host_eligible)}")
    if len(common_aligned) == 0:
        raise ValueError("No quality-accepted, target-observed cases have unique P4 alignment")

    for records, name in ((host_eligible, "host-only"), (common_aligned, "common-aligned")):
        for split in ("training", "validation"):
            split_labels = {record["label"] for record in records if record["split"] == split}
            if split_labels != {0, 1}:
                print(f"WARNING: {name} {split} split does not contain both classes: {split_labels}")
        train_groups = {record["group_id"] for record in records if record["split"] == "training"}
        validation_groups = {
            record["group_id"] for record in records if record["split"] == "validation"
        }
        if train_groups & validation_groups:
            raise ValueError(f"{name}: group crosses the frozen training/validation split")

    write_csv(OUTPUT_DIR / "eligibility_audit.csv", eligibility_rows, list(eligibility_rows[0]))
    write_csv(OUTPUT_DIR / "p4_alignment_audit.csv", alignment_rows, list(alignment_rows[0]))
    feature_fields = [*host_features, *p4.P4_SAMPLE_FEATURES]
    dataset_rows = []
    for record in host_eligible:
        row = {key: value for key, value in record.items() if key not in {"host_features", "p4_features"}}
        row.update(record["host_features"])
        row.update(record["p4_features"])
        dataset_rows.append(row)
    dataset_fields = [
        "sample", "class", "label", "split", "mode", "group_id", "position", "run_id",
        "return_code", "post_target_lineage_raw_syscalls", "p4_alignment_status", "p4_parity",
        *feature_fields,
    ]
    write_csv(OUTPUT_DIR / "eligible_dataset.csv", dataset_rows, dataset_fields)

    def counts(records: list[dict]) -> dict:
        result = {}
        for split in ("training", "validation"):
            subset = [record for record in records if record["split"] == split]
            result[split] = {
                "samples": len(subset),
                "benign": sum(record["label"] == 0 for record in subset),
                "malware": sum(record["label"] == 1 for record in subset),
                "groups": len({record["group_id"] for record in subset}),
                "malware_groups": len({record["group_id"] for record in subset if record["label"] == 1}),
                "benign_groups": len({record["group_id"] for record in subset if record["label"] == 0}),
            }
        return result

    p4_counts = Counter(row["alignment_status"] for row in alignment_rows)
    report = {
        "status": "prepared_for_modeling",
        "collection_validation_sha256": sha256(VALIDATION_PATH),
        "collection_manifest_sha256": sha256(ATTEMPT_DIR / "collection_manifest.json"),
        "preregistration_sha256": sha256(PREREGISTRATION_PATH),
        "case_order_sha256": sha256(CASE_ORDER_PATH),
        "host_feature_contract_sha256": sha256(HOST_FEATURE_PATH),
        "p4_extractor_sha256": sha256(P4_DIR / "analyze_p4_pcap_ablation.py"),
        "preparation_script_sha256": sha256(Path(__file__).resolve()),
        "collection_schema": SCHEMA,
        "runner_sha256": RUNNER_SHA256,
        "rejected_records_used": 0,
        "missing_output_records_used": 0,
        "null_controls_used_as_classifiers": 0,
        "quality_accepted_records": accepted_count,
        "quality_accepted_target_observed_classifier_cases": len(host_eligible),
        "primary_common_aligned_cases": len(common_aligned),
        "host_only_all_eligible_counts": counts(host_eligible),
        "common_aligned_counts": counts(common_aligned),
        "p4_alignment_status_counts": dict(sorted(p4_counts.items())),
        "p4_stored_extracted_parity": {
            "comparisons": parity_comparisons,
            "mismatches": 0,
            "byte_layer": "captured Ethernet",
            "rate_window": "nominal 0.5 seconds",
        },
        "feature_contract": {
            "host_candidate_families": len(host_families),
            "host_candidate_columns": len(host_features),
            "p4_families": len(p4.P4_FEATURES),
            "p4_columns": len(p4.P4_SAMPLE_FEATURES),
            "host_selected_families": preregistration["analysis"]["host_columns"] // 5,
            "summaries_per_family": len(p4.P4_WINDOW_STATS),
        },
        "training_validation_group_overlap": 0,
        "limitations": [
            "The primary population is quality-accepted and target-observed; it excludes no-activation cases per preregistration, but includes low-activity cases.",
            "P4 features are reconstructed offline from PCAPs, not measured on a live P4 target.",
            "The host-only all-eligible sensitivity includes cases without unique P4 alignment; it is not directly comparable to the common aligned set without noting selection.",
        ],
    }
    (OUTPUT_DIR / "preparation_audit.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({
        "status": report["status"],
        "quality_accepted_target_observed_classifier_cases": len(host_eligible),
        "primary_common_aligned_cases": len(common_aligned),
        "host_only_all_eligible_counts": report["host_only_all_eligible_counts"],
        "common_aligned_counts": report["common_aligned_counts"],
        "p4_alignment_status_counts": report["p4_alignment_status_counts"],
        "p4_stored_extracted_parity": report["p4_stored_extracted_parity"],
        "output_dir": str(OUTPUT_DIR),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())