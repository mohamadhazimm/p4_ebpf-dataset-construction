#!/usr/bin/env python3
"""Aggregate window telemetry into labeled sample-level modeling data."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


NETWORK_FIELDS = {
    "net_packets_captured",
    "net_bytes_captured",
    "net_flow_count",
}
EBPF_MODEL_FIELDS = {
    "ebpf_connect_count",
    "ebpf_sendto_count",
    "ebpf_socket_count",
    "ebpf_openat_success_count",
    "ebpf_openat2_success_count",
    "ebpf_file_write_success_count",
    "ebpf_file_pwrite64_success_count",
    "ebpf_file_writev_success_count",
    "ebpf_file_write_bytes",
}
STATISTICS = ("mean", "max", "sum", "std", "active_windows")


def numeric(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def aggregate(values: list[float]) -> dict[str, float]:
    if not values:
        return {stat: 0.0 for stat in STATISTICS}
    mean_value = sum(values) / len(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    return {
        "mean": mean_value,
        "max": max(values),
        "sum": sum(values),
        "std": variance**0.5,
        "active_windows": float(sum(value != 0 for value in values)),
    }


def read_manifest(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        rows = list(csv.DictReader(source))
    return {row["sample_artifact"]: row for row in rows}


def read_malware_family_metadata(paths: Path | list[Path]) -> dict[str, str]:
    if isinstance(paths, Path):
        paths = [paths]
    families = {}
    for path in paths:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                record = json.loads(line)
                sha256 = str(record.get("sha256") or "").strip().lower()
                if not sha256:
                    raise ValueError(f"Malware metadata line {line_number} has no sha256")
                family = str(record.get("signature") or "").strip()
                if family.lower() in {"", "none", "unknown"}:
                    family = "unassigned"
                artifact = f"{sha256}.zip"
                previous = families.setdefault(artifact, family)
                if previous != family:
                    raise ValueError(f"Conflicting malware families for {artifact}")
    return families


def assign_malware_family_groups(examples, family_by_artifact) -> None:
    missing = sorted(
        example["sample_artifact"]
        for example in examples
        if example["sample_artifact"] not in family_by_artifact
    )
    if missing:
        raise ValueError(f"Malware metadata is missing {len(missing)} sample artifacts")
    for example in examples:
        family = family_by_artifact[example["sample_artifact"]]
        example["workload_family"] = family
        example["group_id"] = f"malware_signature::{family}"


def load_telemetry(path: Path, label_value: int | None, class_name: str | None, manifest=None):
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        fieldnames = set(reader.fieldnames or [])
        rows_by_sample = defaultdict(list)
        metadata_by_sample = {}
        for row in reader:
            if row.get("record_type") != "telemetry_window":
                continue
            artifact = row.get("sample_artifact", "")
            if not artifact:
                continue
            rows_by_sample[artifact].append(row)
            metadata_by_sample[artifact] = row

    network_fields = sorted(field for field in NETWORK_FIELDS if field in fieldnames)
    host_fields = sorted(
        field
        for field in fieldnames
        if field in EBPF_MODEL_FIELDS
    )
    feature_groups = {"network": network_fields, "host": host_fields}
    examples = []

    for artifact, sample_rows in sorted(rows_by_sample.items()):
        row = metadata_by_sample[artifact]
        sample_label = label_value
        sample_class_name = class_name
        package = "malware"
        workload_family = "malware"
        if manifest is not None:
            entry = manifest.get(artifact)
            if entry is None:
                raise ValueError(f"No workload manifest entry for benign artifact {artifact}")
            package = entry.get("package", "scenario")
            workload_family = entry.get("workload_family", "unknown")
            group_id = entry.get("group_id", f"{package}::{workload_family}")
            if sample_label is None:
                try:
                    sample_label = int(entry["label"])
                    sample_class_name = entry["class_name"]
                except (KeyError, ValueError) as error:
                    raise ValueError(f"Scenario manifest has invalid labels for {artifact}") from error
                if sample_label not in {0, 1}:
                    raise ValueError(f"Scenario label must be 0 or 1 for {artifact}")
        else:
            group_id = f"malware::{artifact}"

        example = {
            "sample_artifact": artifact,
            "sample_name": row.get("sample_name") or row.get("label") or artifact,
            "label": sample_label,
            "class_name": sample_class_name,
            "package_group": package,
            "workload_family": workload_family,
            "group_id": group_id,
            "sample_status": row.get("sample_status", ""),
            "window_count": len(sample_rows),
        }
        if manifest is not None and label_value is None:
            for field in ("scenario_id", "condition", "pair_id", "variant"):
                example[field] = entry.get(field, "")
        for prefix, columns in feature_groups.items():
            for column in columns:
                values = [number for item in sample_rows if (number := numeric(item.get(column))) is not None]
                stats = aggregate(values)
                for statistic, value in stats.items():
                    example[f"{prefix}__{column}__{statistic}"] = value
        examples.append(example)

    return examples, feature_groups


def load_telemetry_files(paths: list[Path], label_value: int, class_name: str):
    examples = []
    feature_groups = None
    for path in paths:
        file_examples, file_features = load_telemetry(path, label_value, class_name)
        if feature_groups is not None and file_features != feature_groups:
            raise ValueError(f"Malware telemetry files expose different sensor features: {path}")
        feature_groups = file_features
        examples.extend(file_examples)
    if feature_groups is None:
        raise ValueError("At least one malware telemetry CSV is required")
    return examples, feature_groups


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malware-csv", type=Path, action="append")
    parser.add_argument("--benign-csv", type=Path)
    parser.add_argument("--benign-manifest", type=Path)
    parser.add_argument("--malware-family-metadata", type=Path, action="append")
    parser.add_argument("--scenario-csv", type=Path)
    parser.add_argument("--scenario-manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    scenario_mode = args.scenario_csv is not None or args.scenario_manifest is not None
    if scenario_mode:
        if args.scenario_csv is None or args.scenario_manifest is None:
            parser.error("scenario mode requires both --scenario-csv and --scenario-manifest")
        if any((args.malware_csv, args.benign_csv, args.benign_manifest, args.malware_family_metadata)):
            parser.error("scenario mode cannot be combined with malware/benign cohort inputs")
        scenario_manifest = read_manifest(args.scenario_manifest)
        scenario_rows, scenario_features = load_telemetry(
            args.scenario_csv, None, None, scenario_manifest
        )
        seen_artifacts = {row["sample_artifact"] for row in scenario_rows}
        missing_artifacts = sorted(set(scenario_manifest) - seen_artifacts)
        if missing_artifacts:
            raise ValueError(f"Scenario telemetry is missing {len(missing_artifacts)} manifest samples")
        labels_by_group = defaultdict(set)
        for row in scenario_rows:
            labels_by_group[row["group_id"]].add(row["label"])
        if any(labels != {0, 1} for labels in labels_by_group.values()):
            raise ValueError("Every held-out scenario group must contain attack and benign samples")
        samples = scenario_rows
        malware_features = benign_features = scenario_features
    else:
        if not all((args.malware_csv, args.benign_csv, args.benign_manifest)):
            parser.error("provide malware/benign cohort inputs or scenario mode inputs")
        benign_manifest = read_manifest(args.benign_manifest)
        malware_rows, malware_features = load_telemetry_files(args.malware_csv, 1, "malware")
        if args.malware_family_metadata is not None:
            family_by_artifact = read_malware_family_metadata(args.malware_family_metadata)
            assign_malware_family_groups(malware_rows, family_by_artifact)
        benign_rows, benign_features = load_telemetry(
            args.benign_csv, 0, "benign", benign_manifest
        )
        samples = malware_rows + benign_rows

    if malware_features != benign_features:
        raise ValueError("Malware and benign telemetry do not expose identical sensor features")
    if not samples or {row["label"] for row in samples} != {0, 1}:
        raise ValueError("Both benign and malware samples are required")
    if len({row["sample_artifact"] for row in samples}) != len(samples):
        raise ValueError("Sample artifact names must be unique across the two cohorts")

    feature_columns = {
        name: [
            key
            for key in samples[0]
            if key.startswith(f"{name}__")
        ]
        for name in ("network", "host")
    }
    feature_columns["hybrid"] = feature_columns["network"] + feature_columns["host"]
    if not feature_columns["network"] or not feature_columns["host"]:
        raise ValueError("The source data is missing network or host sensor features")

    output_path = args.output.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(samples[0])
    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(samples)
    feature_path = output_path.with_name(output_path.stem + ".feature_columns.json")
    feature_path.write_text(json.dumps(feature_columns, indent=2) + "\n", encoding="utf-8")
    summary = {
        "samples": len(samples),
        "network_features": len(feature_columns["network"]),
        "host_features": len(feature_columns["host"]),
        "output": str(output_path),
        "feature_columns": str(feature_path),
    }
    if scenario_mode:
        summary["attack_simulations"] = sum(row["label"] == 1 for row in samples)
        summary["benign_controls"] = sum(row["label"] == 0 for row in samples)
    else:
        summary["malware"] = len(malware_rows)
        summary["benign"] = len(benign_rows)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())