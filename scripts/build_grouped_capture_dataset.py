#!/usr/bin/env python3
"""Build the family/package-held-out feature dataset from versioned captures."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


STATISTICS = ("mean", "max", "sum", "std", "active_windows")
EXPECTED_NETWORK_SIGNALS = 29
EXPECTED_HOST_SIGNALS = 34
EXPECTED_SCHEMA = "2026-10-18.1"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def read_host_status(path: Path) -> str:
    if not path.is_file():
        return "missing_host_status"
    return next(
        (
            line.split("=", 1)[1]
            for line in path.read_text(errors="replace").splitlines()
            if line.startswith("status=")
        ),
        "missing_status",
    )


def select_feature_fields(groups: dict[str, list[str]]) -> tuple[list[str], list[str]]:
    network_fields = list(groups.get("p4_network", []))
    host_fields = [
        field
        for field in groups.get("ebpf_syscall_counts", [])
        if field != "ebpf_unique_threads"
    ]
    if len(network_fields) != EXPECTED_NETWORK_SIGNALS:
        raise ValueError(f"Expected {EXPECTED_NETWORK_SIGNALS} P4 signals, found {len(network_fields)}")
    if len(host_fields) != EXPECTED_HOST_SIGNALS:
        raise ValueError(f"Expected {EXPECTED_HOST_SIGNALS} eBPF signals, found {len(host_fields)}")
    if len(set(network_fields + host_fields)) != len(network_fields) + len(host_fields):
        raise ValueError("P4 and eBPF signal fields must be unique")
    return network_fields, host_fields


def aggregate(rows: list[dict[str, str]], field: str) -> dict[str, float]:
    values = []
    for row in rows:
        try:
            value = float(row[field])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(value):
            values.append(value)
    if not values:
        return {statistic: 0.0 for statistic in STATISTICS}
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return {
        "mean": mean,
        "max": max(values),
        "sum": sum(values),
        "std": math.sqrt(variance),
        "active_windows": float(sum(value != 0 for value in values)),
    }


def audit_openat_events(path: Path) -> dict[str, int]:
    counts = {
        "raw_openat": 0,
        "openat_with_path_field": 0,
        "openat_nonempty_path": 0,
        "openat_success": 0,
        "raw_openat2": 0,
        "openat2_with_path_field": 0,
        "openat2_nonempty_path": 0,
        "openat2_success": 0,
    }
    for row in read_csv(path):
        event = row.get("event", "")
        if event in {"openat", "openat2"}:
            counts["raw_" + event] += 1
            detail = row.get("detail", "")
            path_value = detail.partition(" flags=")[0].removeprefix("path=").strip()
            if detail.startswith("path="):
                counts[event + "_with_path_field"] += 1
                if path_value:
                    counts[event + "_nonempty_path"] += 1
        elif event in {"openat_success", "openat2_success"}:
            counts[event] += 1
    return counts


def build_feature_row(
    artifact: str,
    manifest_row: dict[str, str],
    run_metadata: dict,
    telemetry_rows: list[dict[str, str]],
    network_fields: list[str],
    host_fields: list[str],
) -> dict:
    label = int(manifest_row["label"])
    if label not in {0, 1}:
        raise ValueError(f"Invalid label for {artifact}: {label}")
    if label == 1 and not manifest_row.get("workload_family", "").strip():
        raise ValueError(f"Malware sample has no family group: {artifact}")
    if label == 0 and not manifest_row.get("package_group", "").strip():
        raise ValueError(f"Benign sample has no package group: {artifact}")
    row = {
        "sample_artifact": artifact,
        "sample_name": str(run_metadata.get("sample_name") or artifact),
        "label": label,
        "class_name": manifest_row.get("class_name", ""),
        "package_group": manifest_row.get("package_group", ""),
        "workload_family": manifest_row.get("workload_family", ""),
        "group_id": manifest_row.get("group_id", ""),
        "sample_status": str(run_metadata.get("status", "unknown")),
        "ebpf_status": str(run_metadata.get("ebpf_status", "unknown")),
        "window_count": len(telemetry_rows),
    }
    for field in network_fields:
        for statistic, value in aggregate(telemetry_rows, field).items():
            row[f"network__p4_{field}__{statistic}"] = value
    for field in host_fields:
        for statistic, value in aggregate(telemetry_rows, field).items():
            row[f"host__{field}__{statistic}"] = value
    return row


def load_sample(
    artifact: str,
    manifest_row: dict[str, str],
    runs_root: Path,
    expected_runner_hash: str,
    expected_fields: tuple[list[str], list[str]] | None,
):
    sample_dir = runs_root / artifact
    host_status = read_host_status(sample_dir / "host_run.txt")
    if host_status != "completed":
        return None, host_status, expected_fields, None

    run_jsons = list((sample_dir / "output").rglob("run.json"))
    if len(run_jsons) != 1:
        raise ValueError(f"{artifact}: expected one run.json, found {len(run_jsons)}")
    run_json = run_jsons[0]
    metadata = json.loads(run_json.read_text(encoding="utf-8"))
    if metadata.get("telemetry_schema_version") != EXPECTED_SCHEMA:
        raise ValueError(f"{artifact}: telemetry schema mismatch")
    if metadata.get("malware_runner_sha256") != expected_runner_hash:
        raise ValueError(f"{artifact}: runner SHA-256 mismatch")

    network_fields, host_fields = select_feature_fields(
        metadata.get("telemetry_feature_groups", {})
    )
    fields = (network_fields, host_fields)
    if expected_fields is not None and fields != expected_fields:
        raise ValueError(f"{artifact}: telemetry feature groups differ from other runs")

    telemetry_path = run_json.parent / "telemetry.csv"
    telemetry_rows = read_csv(telemetry_path)
    if not telemetry_rows:
        raise ValueError(f"{artifact}: telemetry.csv contains no windows")
    openat_audit = audit_openat_events(run_json.parent / "ebpf_events.csv")
    missing = set(network_fields + host_fields) - set(telemetry_rows[0])
    if missing:
        raise ValueError(f"{artifact}: telemetry is missing fields {sorted(missing)}")
    row = build_feature_row(
        artifact, manifest_row, metadata, telemetry_rows, network_fields, host_fields
    )
    return row, host_status, fields, openat_audit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--malware-runs", type=Path, required=True)
    parser.add_argument("--benign-runs", type=Path, required=True)
    parser.add_argument("--runner-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest_rows = read_csv(args.manifest.expanduser().resolve())
    manifest = {row["sample_artifact"]: row for row in manifest_rows}
    if len(manifest) != len(manifest_rows):
        parser.error("Cohort manifest contains duplicate sample_artifact values")
    if {row.get("label") for row in manifest_rows} != {"0", "1"}:
        parser.error("Cohort manifest must contain both labels 0 and 1")

    expected_runner_hash = hashlib.sha256(
        args.runner_source.expanduser().resolve().read_bytes()
    ).hexdigest()
    run_roots = {
        0: args.benign_runs.expanduser().resolve(),
        1: args.malware_runs.expanduser().resolve(),
    }
    rows = []
    statuses = {0: Counter(), 1: Counter()}
    excluded = []
    openat_audits = []
    expected_fields = None
    for artifact, manifest_row in sorted(manifest.items()):
        label = int(manifest_row["label"])
        row, status, expected_fields, openat_audit = load_sample(
            artifact,
            manifest_row,
            run_roots[label],
            expected_runner_hash,
            expected_fields,
        )
        statuses[label][status] += 1
        if row is None:
            excluded.append({"sample_artifact": artifact, "label": label, "status": status})
        else:
            rows.append(row)
            openat_audits.append(
                {"sample_artifact": artifact, "label": label, **openat_audit}
            )

    if not rows or {row["label"] for row in rows} != {0, 1}:
        parser.error("No complete captures for both labels were found")
    network_features = [key for key in rows[0] if key.startswith("network__")]
    host_features = [key for key in rows[0] if key.startswith("host__")]
    if len(network_features) != 145 or len(host_features) != 170:
        parser.error(
            f"Unexpected feature widths: network={len(network_features)}, host={len(host_features)}"
        )
    feature_columns = {
        "network": network_features,
        "host": host_features,
        "hybrid": network_features + host_features,
    }

    output_path = args.output.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    output_path.with_name(output_path.stem + ".feature_columns.json").write_text(
        json.dumps(feature_columns, indent=2) + "\n", encoding="utf-8"
    )
    audit = {
        "manifest_samples": len(manifest_rows),
        "included_samples": len(rows),
        "included_by_label": dict(Counter(str(row["label"]) for row in rows)),
        "host_run_status_by_label": {str(label): dict(counts) for label, counts in statuses.items()},
        "sample_status_by_label": {
            str(label): dict(Counter(row["sample_status"] for row in rows if row["label"] == label))
            for label in (0, 1)
        },
        "ebpf_status_by_label": {
            str(label): dict(Counter(row["ebpf_status"] for row in rows if row["label"] == label))
            for label in (0, 1)
        },
        "window_counts_by_label": {
            str(label): dict(Counter(row["window_count"] for row in rows if row["label"] == label))
            for label in (0, 1)
        },
        "excluded_samples": excluded,
        "runner_sha256": expected_runner_hash,
        "telemetry_schema_version": EXPECTED_SCHEMA,
        "p4_signal_count": EXPECTED_NETWORK_SIGNALS,
        "ebpf_signal_count_excluding_unique_threads": EXPECTED_HOST_SIGNALS,
        "feature_widths": {"network": len(network_features), "host": len(host_features)},
        "openat_event_audit": {
            "included_samples": len(openat_audits),
            "counts": {
                key: sum(sample[key] for sample in openat_audits)
                for key in (
                    "raw_openat",
                    "openat_with_path_field",
                    "openat_nonempty_path",
                    "openat_success",
                    "raw_openat2",
                    "openat2_with_path_field",
                    "openat2_nonempty_path",
                    "openat2_success",
                )
            },
            "samples_missing_openat_paths": [
                sample["sample_artifact"]
                for sample in openat_audits
                if sample["raw_openat"] != sample["openat_with_path_field"]
                or sample["raw_openat2"] != sample["openat2_with_path_field"]
            ],
            "samples_with_empty_openat_path_values": [
                sample["sample_artifact"]
                for sample in openat_audits
                if sample["openat_with_path_field"] != sample["openat_nonempty_path"]
                or sample["openat2_with_path_field"] != sample["openat2_nonempty_path"]
            ],
            "per_sample": openat_audits,
        },
    }
    output_path.with_name(output_path.stem + "_capture_audit.json").write_text(
        json.dumps(audit, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(output_path), **audit}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())