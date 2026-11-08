#!/usr/bin/env python3
"""Review and analyze retrieved captures without rerunning the frozen collection."""

from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import subprocess
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import run_i386_holdout_collection as frozen


RUN = frozen.RELEASE / "collection"
ORDER = frozen.RELEASE / "case_order.json"


def review():
    cases = json.loads(ORDER.read_text())
    failures, exceptions = [], []
    counts = Counter()
    for case in cases:
        directory = RUN / "runs" / case["sample"]
        status_file = directory / "host_run.txt"
        status_lines = status_file.read_text().splitlines() if status_file.exists() else []
        status = next((line.partition("=")[2] for line in status_lines if line.startswith("status=")), "missing")
        counts["retrieval_" + status] += 1
        paths = list(directory.glob("output/run_*/run.json"))
        if len(paths) != 1:
            members = []
            archive = directory / "output.tgz"
            archive_error = None
            if archive.exists():
                try:
                    with tarfile.open(archive, "r:gz") as stream:
                        members = [{"name": member.name, "bytes": member.size} for member in stream.getmembers()]
                except (OSError, tarfile.TarError) as error:
                    archive_error = str(error)
            evidence = {}
            for log in directory.rglob("*.log"):
                text = log.read_text(errors="replace")
                selected = [line for line in text.splitlines() if any(
                    marker in line for marker in ("Error", "Exception", "Killed", "Permission", "No such", "not found", "failed"))]
                if selected:
                    evidence[str(log.relative_to(directory))] = selected[-8:]
            failures.append({"sample": case["sample"], "label": case["label"], "split": case["split"],
                "host_status": status, "local_run_metadata_count": len(paths), "archive_members": members,
                "archive_error": archive_error, "error_lines": evidence,
                "recoverable_complete_metadata": any(Path(member["name"]).name == "run.json" for member in members)})
            continue
        metadata = json.loads(paths[0].read_text())
        counts["quality_" + metadata.get("collection_quality_status", "unavailable")] += 1
        artifact = metadata.get("target_artifact", {})
        if artifact.get("linkage") not in ("static", None):
            archive = frozen.STUDY / case["source_archive_path"]
            if frozen.digest(archive) != case["source_archive_sha256"]:
                raise ValueError("Source archive hash differs")
            result = subprocess.run(["7z", "x", "-so", "-pinfected", str(archive)],
                capture_output=True, check=True, timeout=60)
            header = result.stdout
            if hashlib.sha256(header).hexdigest() != case["sha256"] or header[:4] != b"\x7fELF":
                raise ValueError("Source member identity differs")
            order = "little" if header[5] == 1 else "big"
            exceptions.append({"sample": case["sample"], "split": case["split"], "arch": case["arch"],
                "planned_mode": case.get("execution_mode"), "recorded_artifact": artifact,
                "independent_elf_e_type": int.from_bytes(header[16:18], order),
                "independent_elf_machine": int.from_bytes(header[18:20], order),
                "archive_sha256": frozen.digest(archive), "member_sha256": hashlib.sha256(header).hexdigest(),
                "decision": "exclude_linkage_outside_frozen_static_contract"})
    return {"counts": dict(counts), "failed_cases": failures, "linkage_exceptions": exceptions,
            "scope": "offline_review_only_no_extraction_to_disk_or_execution",
            "frozen_order_sha256": frozen.digest(ORDER), "original_run_status": json.loads((RUN / "status.json").read_text())}


def prepare():
    launch = json.loads((RUN / "launch_manifest.json").read_text())
    frozen.verify_hashes(launch["workflow_hashes"])
    report = review()
    if any(case["recoverable_complete_metadata"] for case in report["failed_cases"]):
        raise ValueError("Recoverable metadata requires review before excluding a failed case")
    attempt = RUN / "derived-analysis" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    frozen.write_json(attempt / "recovery_review.json", report)
    exceptions = {case["sample"]: case for case in report["linkage_exceptions"]}
    source_hashes = {str(path.relative_to(frozen.STUDY)): frozen.digest(path)
                     for path in (Path(__file__), RUN / "status.json", RUN / "launch_manifest.json")}
    captures = attempt / "runs"
    captures.mkdir()
    for case in json.loads(ORDER.read_text()):
        source = RUN / "runs" / case["sample"]
        if case["sample"] not in exceptions and source.is_dir():
            (captures / case["sample"]).symlink_to(source, target_is_directory=True)
    frozen.write_json(attempt / "derived_manifest.json", {
        "authorization": "User asked to inspect failures, leave unrecoverable cases and train retrieved data",
        "source_collection": str(RUN.relative_to(frozen.STUDY)), "source_hashes": source_hashes,
        "frozen_workflow_hashes": launch["workflow_hashes"],
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "selection_rule": "Original order/splits/groups; omit per-case linkage exceptions without relaxing static-only contract",
        "linkage_exclusions": sorted(exceptions), "recovery_review_sha256": frozen.digest(attempt / "recovery_review.json"),
        "capture_or_sample_execution": False, "original_data_modified": False})
    protocol = json.loads((frozen.RELEASE / "protocol.json").read_text())
    host, common, features, preparation = frozen.prepare_data(attempt, protocol, attempt / "analysis")
    audit_path = attempt / "analysis/eligibility_audit.csv"
    with audit_path.open(newline="") as source:
        audits = list(csv.DictReader(source))
    for row in audits:
        if row["sample"] in exceptions:
            metadata_path = next((RUN / "runs" / row["sample"]).glob("output/run_*/run.json"))
            metadata = json.loads(metadata_path.read_text())
            row.update(host_status="completed", quality_status=metadata["collection_quality_status"],
                       target_exec_status=metadata["target_exec"]["status"],
                       exclusion_reason="linkage_outside_frozen_static_contract")
    trainer, _, _ = frozen.dependencies()
    trainer.write_csv(audit_path, audits, list(audits[0]))
    preparation["source_status_counts"] = report["counts"]
    preparation["exclusions"] = dict(Counter(row["exclusion_reason"] for row in audits if row["exclusion_reason"]))
    preparation["totals"]["unretrieved"] = len(report["failed_cases"])
    preparation["totals"]["linkage_excluded"] = len(exceptions)
    preparation["analysis_note"] = "Archives/features/PCAP totals cover the derived view; source retrieval counts include the separately reviewed linkage exception"
    preparation["data_hashes"] = {name: frozen.digest(attempt / "analysis" / name)
        for name in ("eligible_dataset.csv", "eligibility_audit.csv", "p4_alignment_audit.csv")}
    preparation["mode_counts"] = {split: dict(Counter(row["mode"] for row in host if row["split"] == split))
                                  for split in ("training", "validation")}
    frozen.write_json(attempt / "analysis/preparation_audit.json", preparation)
    frozen.write_json(attempt / "status.json", {"stage": "prepared", "preparation": preparation})
    print(json.dumps({"attempt": str(attempt), "preparation": preparation}, indent=2), flush=True)
    return attempt


def train(attempt):
    attempt = attempt.resolve()
    if not attempt.is_relative_to((RUN / "derived-analysis").resolve()):
        raise ValueError("Refusing to train outside the new derived analysis root")
    manifest = json.loads((attempt / "derived_manifest.json").read_text())
    frozen.verify_hashes(manifest["frozen_workflow_hashes"])
    for path, checksum in manifest["source_hashes"].items():
        if frozen.digest(frozen.STUDY / path) != checksum:
            raise ValueError("Derived input/source changed: " + path)
    preparation = json.loads((attempt / "analysis/preparation_audit.json").read_text())
    for name, checksum in preparation["data_hashes"].items():
        if frozen.digest(attempt / "analysis" / name) != checksum:
            raise ValueError("Prepared derived data changed: " + name)
    trainer, data, _ = frozen.dependencies()
    features = list(json.loads(trainer.HOST_FEATURE_PATH.read_text())["host"])
    with (attempt / "analysis/eligible_dataset.csv").open(newline="") as source:
        rows = list(csv.DictReader(source))
    for row in rows:
        for name in ("label", "position", "post_target_lineage_raw_syscalls"):
            row[name] = int(row[name])
        for name in features:
            row[name] = float(row[name])
        if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True":
            for name in data.p4.P4_SAMPLE_FEATURES:
                row[name] = float(row[name])
    common = [row for row in rows if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True"]
    if len(rows) != preparation["host_eligible"] or len(common) != preparation["common_aligned"]:
        raise ValueError("Prepared population differs from audit")
    excluded = set(manifest["linkage_exclusions"])
    if any(row["sample"] in excluded or row["class"] == "null" for row in rows):
        raise ValueError("Excluded case reached model input")
    frozen.write_json(attempt / "status.json", {"stage": "training", "started_utc": datetime.now(timezone.utc).isoformat()})
    try:
        frozen.fit_models(attempt, rows, common, features, preparation)
        frozen.verify_hashes(manifest["frozen_workflow_hashes"])
        metrics = attempt / "analysis/model-fit/metrics.json"
        frozen.write_json(attempt / "status.json", {"stage": "complete", "finished_utc": datetime.now(timezone.utc).isoformat(),
            "metrics_sha256": frozen.digest(metrics), "validation_consumed": True})
        print("COMPLETE: " + str(metrics), flush=True)
    except BaseException as error:
        frozen.write_json(attempt / "status.json", {"stage": "stopped_requires_review", "error": str(error)})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--review-only", action="store_true")
    actions.add_argument("--prepare-only", action="store_true")
    actions.add_argument("--train", type=Path)
    args = parser.parse_args()
    lock_path = frozen.gates.preparation.validation_checks.allocation.prepare_inventory.PREPARATION / "readiness.lock"
    with lock_path.open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.review_only:
            print(json.dumps(review(), indent=2))
        elif args.prepare_only:
            prepare()
        else:
            train(args.train)


if __name__ == "__main__":
    main()