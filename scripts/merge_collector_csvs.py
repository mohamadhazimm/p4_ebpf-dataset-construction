#!/usr/bin/env python3
"""Merge per-sample telemetry windows and eBPF event CSVs."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from pathlib import Path


INPUT_CSV_NAMES = {"telemetry.csv", "ebpf_events.csv"}
PROVENANCE_COLUMNS = [
    "record_type",
    "sample_artifact",
    "sample_name",
    "sample_status",
    "source_file",
    "run_id",
    "ebpf_status",
]


def read_metadata(run_dir: Path) -> dict[str, str]:
    metadata_path = run_dir / "run.json"
    try:
        with metadata_path.open(encoding="utf-8") as metadata_file:
            metadata = json.load(metadata_file)
    except (OSError, json.JSONDecodeError):
        return {}

    return {
        "run_id": str(metadata.get("run_id", "")),
        "sample_name": str(metadata.get("sample_name", "")),
        "sample_status": str(metadata.get("status", "")),
        "ebpf_status": str(metadata.get("ebpf_status", "")),
    }


def csv_header(csv_path: Path) -> list[str]:
    with csv_path.open("r", newline="", encoding="utf-8-sig") as source_file:
        return next(csv.reader(source_file), [])


def merge_csvs(input_dir: Path, output_path: Path) -> tuple[Counter[str], int]:
    sources = sorted(
        (
            path
            for path in input_dir.rglob("*.csv")
            if path.name in INPUT_CSV_NAMES and path.resolve() != output_path.resolve()
        ),
        key=lambda path: path.as_posix(),
    )
    if not sources:
        raise ValueError(f"No telemetry.csv or ebpf_events.csv files found under {input_dir}")

    fieldnames = list(PROVENANCE_COLUMNS)
    known_fields = set(fieldnames)
    for source in sources:
        for field in csv_header(source):
            if field not in known_fields:
                fieldnames.append(field)
                known_fields.add(field)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(output_path.name + ".tmp")
    row_counts: Counter[str] = Counter()

    try:
        with temporary_path.open("w", newline="", encoding="utf-8") as merged_file:
            writer = csv.DictWriter(merged_file, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()

            for source in sources:
                run_dir = source.parent
                metadata = read_metadata(run_dir)
                sample_artifact = (
                    source.parents[2].name if len(source.parents) > 2 else run_dir.name
                )
                record_type = (
                    "telemetry_window" if source.name == "telemetry.csv" else "ebpf_event"
                )

                with source.open("r", newline="", encoding="utf-8-sig") as source_file:
                    for row in csv.DictReader(source_file):
                        if None in row:
                            raise ValueError(f"Unexpected extra columns in {source}")
                        row["record_type"] = record_type
                        row["sample_artifact"] = sample_artifact
                        row["sample_name"] = (
                            metadata.get("sample_name") or row.get("label") or sample_artifact
                        )
                        row["sample_status"] = metadata.get("sample_status", "")
                        row["source_file"] = source.relative_to(input_dir).as_posix()
                        row.setdefault("run_id", metadata.get("run_id", ""))
                        if not row.get("ebpf_status"):
                            row["ebpf_status"] = metadata.get("ebpf_status", "")
                        writer.writerow(row)
                        row_counts[record_type] += 1

        os.replace(temporary_path, output_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    return row_counts, len(sources)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Combine telemetry windows and eBPF events into one CSV. "
            "Rows are tagged by record_type; non-applicable columns are blank."
        )
    )
    parser.add_argument("input_dir", type=Path, help="Batch output directory to scan recursively")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output CSV (default: <input_dir>/combined_collector.csv)",
    )
    args = parser.parse_args()

    input_dir = args.input_dir.expanduser().resolve()
    if not input_dir.is_dir():
        parser.error(f"input directory does not exist: {input_dir}")

    output_path = (
        args.output.expanduser().resolve()
        if args.output
        else input_dir / "combined_collector.csv"
    )

    try:
        row_counts, source_count = merge_csvs(input_dir, output_path)
    except (OSError, csv.Error, ValueError) as error:
        parser.error(str(error))

    print(
        f"Merged {source_count} source CSVs: "
        f"{row_counts['telemetry_window']} telemetry windows, "
        f"{row_counts['ebpf_event']} eBPF events."
    )
    print(f"Output: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())