#!/usr/bin/env python3
"""Build a full-signal dataset and validate stable summaries against it."""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path

from build_dataset import STATISTICS, aggregate, numeric


def read_examples(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def read_features(path: Path) -> dict[str, list[str]]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--collector", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    examples = read_examples(args.dataset)
    if not examples:
        parser.error("dataset contains no samples")
    stable_features_path = args.dataset.with_name(args.dataset.stem + ".feature_columns.json")
    stable_features = read_features(stable_features_path)
    values_by_artifact: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    raw_fields: set[str] | None = None

    for collector_path in args.collector:
        with collector_path.open(newline="", encoding="utf-8-sig") as source:
            reader = csv.DictReader(source)
            fields = set(reader.fieldnames or [])
            fields = {
                field
                for field in fields
                if field.startswith("net_")
                or (field.startswith("ebpf_") and field != "ebpf_status")
            }
            if raw_fields is None:
                raw_fields = fields
            elif fields != raw_fields:
                raise ValueError(f"Collector raw signal fields differ: {collector_path}")

            for row in reader:
                if row.get("record_type") != "telemetry_window":
                    continue
                artifact = row.get("sample_artifact", "")
                if not artifact:
                    raise ValueError(f"Telemetry window has no sample_artifact: {collector_path}")
                for field in fields:
                    value = numeric(row.get(field))
                    if value is not None:
                        values_by_artifact[artifact][field].append(value)

    if raw_fields is None:
        parser.error("at least one collector is required")
    dataset_artifacts = {example["sample_artifact"] for example in examples}
    collector_artifacts = set(values_by_artifact)
    if dataset_artifacts != collector_artifacts:
        missing = sorted(dataset_artifacts - collector_artifacts)
        extra = sorted(collector_artifacts - dataset_artifacts)
        raise ValueError(f"Dataset/collector samples differ; missing={missing[:3]}, extra={extra[:3]}")

    network_fields = sorted(field for field in raw_fields if field.startswith("net_"))
    host_fields = sorted(field for field in raw_fields if field.startswith("ebpf_"))
    feature_sets = {
        "network": [f"network__{field}__{stat}" for field in network_fields for stat in STATISTICS],
        "host": [f"host__{field}__{stat}" for field in host_fields for stat in STATISTICS],
    }
    feature_sets["hybrid"] = feature_sets["network"] + feature_sets["host"]
    stable_columns = set(stable_features["network"] + stable_features["host"])
    output_rows = []

    for example in examples:
        artifact = example["sample_artifact"]
        row = dict(example)
        for prefix, fields in (("network", network_fields), ("host", host_fields)):
            for field in fields:
                stats = aggregate(values_by_artifact[artifact][field])
                for statistic, value in stats.items():
                    column = f"{prefix}__{field}__{statistic}"
                    if column in stable_columns:
                        previous = float(example[column])
                        if not math.isclose(previous, value, rel_tol=1e-12, abs_tol=1e-12):
                            raise ValueError(
                                f"Stable summary mismatch for {artifact}, {column}: "
                                f"saved={previous}, recomputed={value}"
                            )
                    row[column] = value
        output_rows.append(row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(output_rows[0])
    with args.output.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    wide_features_path = args.output.with_name(args.output.stem + ".feature_columns.json")
    wide_features_path.write_text(json.dumps(feature_sets, indent=2) + "\n", encoding="utf-8")
    narrow_features_path = args.output.with_name(args.output.stem + ".narrow_feature_columns.json")
    narrow_features_path.write_text(json.dumps(stable_features, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "samples": len(examples),
                "network_base_signals": len(network_fields),
                "host_base_signals": len(host_fields),
                "network_model_columns": len(feature_sets["network"]),
                "host_model_columns": len(feature_sets["host"]),
                "stable_summaries_validated": len(stable_columns),
                "output": str(args.output),
                "wide_features": str(wide_features_path),
                "narrow_features": str(narrow_features_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())