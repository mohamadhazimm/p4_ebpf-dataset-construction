#!/usr/bin/env python3
"""Reconstruct P4 features without changing archived collector outputs."""

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

STUDY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STUDY / "src"))
sys.path.insert(0, str(STUDY.parents[1] / "p4_ebpf"))

from analyze_p4_pcap_ablation import P4_FEATURES, derive_p4_features as derive_live_p4_features
from evaluate_versioned_hostmon_p4 import DEFAULT_DATA_ROOT, host_status, read_csv


def derive_p4_features(pcap_path, telemetry_rows, run_metadata, active_ttl_windows=3):
    """Preserve the frozen runner's Ethernet bytes and nominal-window rates."""
    return derive_live_p4_features(pcap_path, telemetry_rows, run_metadata,
                                   active_ttl_windows, byte_layer="ethernet", rate_window="nominal")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.data_root.resolve()
    output = args.output_dir.resolve()
    if output.exists():
        parser.error(f"Refusing to overwrite {output}")
    manifest_path = root / "collection_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    provenance = [
        "cohort", "record_type", "sample_artifact", "sample_name",
        "sample_status", "source_file", "run_id", "ebpf_status",
    ]
    reports = []
    cohort_reports = {}
    try:
        (staging / "exports").mkdir()
        for cohort, definition in manifest["cohorts"].items():
            manifest_file = root / definition["manifest"]
            if digest(manifest_file) != definition["manifest_sha256"]:
                raise ValueError(f"Frozen manifest changed: {cohort}")
            artifacts = manifest_file.read_text().splitlines()
            if len(artifacts) != definition["expected_samples"]:
                raise ValueError(f"Manifest sample count mismatch: {cohort}")
            audit = json.loads((root / "summaries" / f"{cohort}.json").read_text())
            statuses = Counter()
            accepted = []
            export_fields = list(provenance)
            for artifact in artifacts:
                sample = root / "runs" / cohort / artifact
                status = host_status(sample / "host_run.txt")
                statuses[status] += 1
                if status != "completed":
                    continue
                paths = list((sample / "output").rglob("run.json"))
                if len(paths) != 1 or not (sample / "output.tgz").is_file():
                    raise ValueError(f"Invalid completed output: {sample}")
                metadata = json.loads(paths[0].read_text())
                if (
                    metadata.get("telemetry_schema_version") != manifest["telemetry_schema_version"]
                    or metadata.get("malware_runner_sha256") != manifest["malware_runner_sha256"]
                    or metadata.get("telemetry_feature_groups", {}).get("p4_network") != P4_FEATURES
                ):
                    raise ValueError(f"Runner provenance/schema mismatch: {sample}")
                run_dir = paths[0].parent
                telemetry_path = run_dir / "telemetry.csv"
                pcap_path = run_dir / "packet_capture.pcap"
                rows = read_csv(telemetry_path)
                _, windows, diagnostics = derive_p4_features(pcap_path, rows, metadata)
                if diagnostics["alignment_status"] != "unique" or len(windows) != len(rows):
                    raise ValueError(f"PCAP window alignment failed: {sample}: {diagnostics}")
                changed = sum(
                    float(row[field]) != float(window[field])
                    for row, window in zip(rows, windows, strict=True)
                    for field in P4_FEATURES
                )
                for row, window in zip(rows, windows, strict=True):
                    for field in P4_FEATURES:
                        row[field] = window[field]
                corrected = staging / "telemetry" / cohort / artifact / "telemetry.csv"
                corrected.parent.mkdir(parents=True)
                with corrected.open("w", newline="", encoding="utf-8") as destination:
                    writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
                    writer.writeheader()
                    writer.writerows(rows)
                sources = [corrected, run_dir / "ebpf_events.csv"]
                for source in sources:
                    with source.open(newline="", encoding="utf-8-sig") as handle:
                        for field in next(csv.reader(handle)):
                            if field not in export_fields:
                                export_fields.append(field)
                accepted.append((artifact, metadata, run_dir, sources))
                reports.append({
                    "cohort": cohort,
                    "sample_artifact": artifact,
                    "source_run_json_sha256": digest(paths[0]),
                    "source_telemetry_sha256": digest(telemetry_path),
                    "source_pcap_sha256": digest(pcap_path),
                    "corrected_telemetry_sha256": digest(corrected),
                    "changed_p4_cells": changed,
                    "windows": len(rows),
                    **diagnostics,
                })
            if statuses != Counter(audit["status_counts"]):
                raise ValueError(f"Host statuses differ from audit: {cohort}")
            counts = Counter()
            with (staging / "exports" / f"{cohort}.csv").open(
                "w", newline="", encoding="utf-8"
            ) as destination:
                writer = csv.DictWriter(destination, fieldnames=export_fields)
                writer.writeheader()
                for artifact, metadata, run_dir, sources in accepted:
                    for source in sources:
                        kind = "telemetry_window" if source.name == "telemetry.csv" else "ebpf_event"
                        with source.open(newline="", encoding="utf-8-sig") as handle:
                            for row in csv.DictReader(handle):
                                row.update({
                                    "cohort": cohort,
                                    "record_type": kind,
                                    "sample_artifact": artifact,
                                    "sample_name": metadata.get("sample_name") or artifact,
                                    "sample_status": metadata.get("status", ""),
                                    "source_file": (run_dir / source.name).relative_to(root).as_posix(),
                                    "run_id": row.get("run_id") or metadata.get("run_id", ""),
                                    "ebpf_status": row.get("ebpf_status") or metadata.get("ebpf_status", ""),
                                })
                                writer.writerow(row)
                                counts[kind] += 1
            cohort_reports[cohort] = {"samples": len(accepted), "rows": dict(counts)}
            print(cohort, cohort_reports[cohort], flush=True)
        with (staging / "reconstruction_audit.csv").open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=list(reports[0]))
            writer.writeheader()
            writer.writerows(reports)
        summary = {
            "source_collection": str(root),
            "source_collection_manifest_sha256": digest(manifest_path),
            "original_runner_sha256": manifest["malware_runner_sha256"],
            "original_telemetry_schema_version": manifest["telemetry_schema_version"],
            "reconstruction_method": "chronological PCAP replay; exact sample-start packet window alignment",
            "reconstruction_implementation": "p4_ebpf/analyze_p4_pcap_ablation.py:derive_p4_features",
            "implementation_sha256": digest(STUDY.parents[1] / "p4_ebpf/analyze_p4_pcap_ablation.py"),
            "rebuild_script_sha256": digest(Path(__file__)),
            "replaced_fields": P4_FEATURES,
            "cohorts": cohort_reports,
            "samples_with_changed_p4_values": sum(row["changed_p4_cells"] > 0 for row in reports),
            "changed_p4_cells": sum(row["changed_p4_cells"] for row in reports),
            "original_inputs_modified": False,
        }
        (staging / "reconstruction_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        os.replace(staging, output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    print(f"Corrected CSVs: {output}")


if __name__ == "__main__":
    main()