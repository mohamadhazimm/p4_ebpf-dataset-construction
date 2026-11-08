#!/usr/bin/env python3
"""Merge one sensor-complete run for each malware in the 323-sample cohort."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from merge_collector_csvs import merge_csvs


ROOT = Path(__file__).resolve().parents[1]
COHORT_DIR = ROOT / "data/malware/revision4/full-cohort-feature-pool-20261016"
AUDIT_PATH = COHORT_DIR / "sample_label_audit.csv"
KNOWN_SELECTION_PATH = COHORT_DIR / "old_capture_source_selection.csv"
TRIAGE_RUNS_DIR = ROOT / "data/malware/revision4/runs/triage-x86_64-108-20261016"
DEFAULT_OUTPUT = ROOT / "data/malware/full-cohort-323/combined_collector_323.csv"
MANIFEST_FIELDS = [
    "sample_artifact",
    "source_cohort",
    "group_id",
    "attack_type_label",
    "run_id",
    "sample_status",
    "packet_capture_status",
    "ebpf_status",
]


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def sample_id(value: str) -> str:
    name = Path(value).name.lower()
    for suffix in (".zip", ".elf"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def sample_artifact(value: str) -> str:
    return f"{sample_id(value)}.zip"


def build_source_selection() -> tuple[set[str], dict[str, Path], dict[str, dict[str, str]]]:
    audit_rows = [row for row in read_rows(AUDIT_PATH) if row.get("label") == "1"]
    audit_by_id = {sample_id(row["sample_artifact"]): row for row in audit_rows}
    target_ids = set(audit_by_id)
    if len(target_ids) != 323 or len(audit_rows) != 323:
        raise ValueError(f"Expected 323 unique malware rows in {AUDIT_PATH}")

    known_sources: dict[str, Path] = {}
    for row in read_rows(KNOWN_SELECTION_PATH):
        identifier = sample_id(row["sample_artifact"])
        pcap_path = Path(row["selected_pcap"]).expanduser()
        if identifier in known_sources:
            raise ValueError(f"Duplicate known-cohort source for {identifier}")
        if not pcap_path.is_file():
            raise ValueError(f"Selected PCAP is missing for {identifier}: {pcap_path}")
        known_sources[identifier] = pcap_path.parent

    if len(known_sources) != 224 or not set(known_sources) <= target_ids:
        raise ValueError("Expected 224 selected known-cohort samples from the 323-sample audit")

    unknown_ids = target_ids - set(known_sources)
    triage_sources: dict[str, Path] = {}
    for telemetry_path in TRIAGE_RUNS_DIR.rglob("telemetry.csv"):
        identifiers = [sample_id(part) for part in telemetry_path.parts if part.lower().endswith(".zip")]
        if not identifiers or identifiers[-1] not in unknown_ids:
            continue
        identifier = identifiers[-1]
        if identifier in triage_sources:
            raise ValueError(f"Multiple primary Triage runs found for {identifier}")
        triage_sources[identifier] = telemetry_path.parent

    if len(unknown_ids) != 99 or set(triage_sources) != unknown_ids:
        missing = sorted(unknown_ids - set(triage_sources))
        raise ValueError(f"Expected one primary Triage run for each of 99 unknown samples; missing={len(missing)}")

    sources = {**known_sources, **triage_sources}
    manifest_rows: dict[str, dict[str, str]] = {}
    for identifier, run_dir in sources.items():
        required_files = ("telemetry.csv", "ebpf_events.csv", "run.json")
        missing_files = [name for name in required_files if not (run_dir / name).is_file()]
        if missing_files:
            raise ValueError(f"Missing {', '.join(missing_files)} for {identifier} in {run_dir}")
        try:
            metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Invalid run metadata for {identifier}: {error}") from error
        if metadata.get("packet_capture_status") != "active" or metadata.get("ebpf_status") != "active":
            raise ValueError(f"Packet capture and eBPF must both be active for {identifier}")

        audit = audit_by_id[identifier]
        manifest_rows[identifier] = {
            "sample_artifact": sample_artifact(identifier),
            "source_cohort": "known_224" if identifier in known_sources else "triage_unknown_x86_64_99",
            "group_id": audit.get("group_id", ""),
            "attack_type_label": audit.get("attack_type_label", ""),
            "run_id": str(metadata.get("run_id", "")),
            "sample_status": str(metadata.get("status", "")),
            "packet_capture_status": str(metadata.get("packet_capture_status", "")),
            "ebpf_status": str(metadata.get("ebpf_status", "")),
        }

    return target_ids, sources, manifest_rows


def write_manifest(path: Path, rows: dict[str, dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(path.name + ".tmp")
    try:
        with temporary_path.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=MANIFEST_FIELDS)
            writer.writeheader()
            writer.writerows(rows[identifier] for identifier in sorted(rows))
        temporary_path.replace(path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def merge_cohort(output_path: Path) -> tuple[int, int, int]:
    target_ids, sources, manifest_rows = build_source_selection()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with TemporaryDirectory(prefix="malware-cohort-323-") as temporary_directory:
        staging_dir = Path(temporary_directory)
        for identifier, run_dir in sources.items():
            cohort = manifest_rows[identifier]["source_cohort"]
            staged_run = staging_dir / cohort / f"{identifier}.zip" / "output" / run_dir.name
            staged_run.mkdir(parents=True)
            for filename in ("telemetry.csv", "ebpf_events.csv", "run.json"):
                (staged_run / filename).symlink_to((run_dir / filename).resolve())

        row_counts, source_count = merge_csvs(staging_dir, output_path)

    if source_count != 2 * len(target_ids):
        raise ValueError(f"Expected two collector CSVs per sample, found {source_count} sources")

    observed_ids: set[str] = set()
    with output_path.open(newline="", encoding="utf-8-sig") as merged:
        for row in csv.DictReader(merged):
            observed_ids.add(sample_id(row.get("sample_artifact", "")))
    if observed_ids != target_ids:
        raise ValueError("Merged CSV sample IDs do not match the 323-sample cohort")

    write_manifest(output_path.parent / "cohort_manifest.csv", manifest_rows)
    return len(observed_ids), row_counts["telemetry_window"], row_counts["ebpf_event"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output_path = args.output.expanduser().resolve()

    try:
        sample_count, telemetry_rows, ebpf_rows = merge_cohort(output_path)
    except (OSError, csv.Error, ValueError) as error:
        parser.error(str(error))

    print(f"Merged {sample_count} unique malware samples: {telemetry_rows} telemetry windows, {ebpf_rows} eBPF events.")
    print(f"CSV: {output_path}")
    print(f"Manifest: {output_path.parent / 'cohort_manifest.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())