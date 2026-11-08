#!/usr/bin/env python3
"""Validate the corrected three-workload benign ELF pilot."""

import argparse
import csv
import hashlib
import json
import math
import tarfile
from pathlib import Path, PurePosixPath


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_files(sample_dir: Path, run_dir: Path) -> dict[str, dict[str, object]]:
    archive_path = sample_dir / "output.tgz"
    results: dict[str, dict[str, object]] = {}
    seen: set[str] = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            parts = [part for part in PurePosixPath(member.name).parts if part not in ("", ".")]
            if not parts and member.isdir() and member.name in (".", "./"):
                continue
            if not parts or ".." in parts or PurePosixPath(member.name).is_absolute():
                raise ValueError(f"Unsafe archive path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or parts[0] != run_dir.name:
                raise ValueError(f"Unexpected archive member: {member.name}")
            relative = PurePosixPath(*parts[1:]).as_posix()
            if relative in seen:
                raise ValueError(f"Duplicate archive member: {member.name}")
            seen.add(relative)
            host_path = run_dir / relative
            payload = archive.extractfile(member)
            if payload is None or not host_path.is_file():
                raise ValueError(f"Missing archived or extracted file: {member.name}")
            archive_bytes = payload.read()
            host_bytes = host_path.read_bytes()
            archive_hash = hashlib.sha256(archive_bytes).hexdigest()
            host_hash = hashlib.sha256(host_bytes).hexdigest()
            if archive_hash != host_hash:
                raise ValueError(f"Archive/extraction hash mismatch: {member.name}")
            results[relative] = {"size_bytes": len(archive_bytes), "sha256": archive_hash}
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = json.loads((root / "retry_manifest.json").read_text())
    repo_root = root.parents[2]
    assert sha256(repo_root / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256(repo_root / "scripts/vbox_malware_batch.sh") == manifest["runner"]["batch_script_sha256"]
    assert sha256(repo_root / "scripts/stage_versioned_runner_snapshot.sh") == manifest["runner"]["staging_script_sha256"]
    assert sha256(root / manifest["runner"]["schema_output"]) == manifest["runner"]["schema_output_sha256"]

    collection = manifest["collection"]
    sample_list = root / collection["sample_manifest"]
    assert sha256(sample_list) == collection["sample_manifest_sha256"]
    names = sample_list.read_text().splitlines()
    assert names == [sample["sample_archive"] for sample in manifest["samples"]]
    output_root = root / collection["output_root"]
    assert {path.name for path in output_root.iterdir() if path.is_dir()} == set(names)

    report_samples = []
    for sample in manifest["samples"]:
        sample_name = sample["sample_archive"]
        assert sha256(root / sample_name) == sample["sample_archive_sha256"]
        arguments_path = root / collection["arguments_directory"] / f"{sample_name}.json"
        assert sha256(arguments_path) == sample["arguments_sha256"]
        expected_arguments = json.loads(arguments_path.read_text())

        sample_dir = output_root / sample_name
        run_files = list(sample_dir.glob("output/run_*/run.json"))
        assert len(run_files) == 1
        run_dir = run_files[0].parent
        metadata = json.loads(run_files[0].read_text())
        assert metadata["status"] == "completed"
        assert metadata["return_code"] == 0
        assert metadata["sample_arguments"] == expected_arguments
        assert metadata["telemetry_schema_version"] == manifest["runner"]["schema_version"]
        assert metadata["malware_runner_sha256"] == manifest["runner"]["sha256"]
        assert metadata["observation_mode"] == collection["observation_mode"]
        assert metadata["timeout_seconds"] == collection["timeout_seconds"]
        assert metadata["window_seconds"] == collection["window_seconds"]
        assert metadata["interface"] == collection["interface"]
        assert metadata["common_launch_wrapper"] is True
        assert metadata["ebpf_enabled"] is True
        assert metadata["ebpf_status"] == "active"
        assert metadata["packet_capture_status"] == "active"
        assert metadata["collection_quality_status"] == "accepted"
        assert metadata["collection_quality_reasons"] == []
        assert metadata["packet_capture_buffer_kb_requested"] == collection["packet_capture_buffer_kb"]
        assert metadata["packet_capture_drain_ms"] == collection["packet_capture_drain_ms"]
        assert metadata["bpftrace_perf_rb_pages"] == collection["bpftrace_perf_rb_pages_per_cpu"]
        assert metadata["packet_capture_counter_discrepancy"] == 0
        assert metadata["packet_capture_dropped_by_kernel"] == 0
        assert metadata["ebpf_lost_event_count"] == 0
        assert metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"]
        assert metadata["packet_capture_interface_counters_after_capture"]["rx_dropped"] == 0
        assert metadata["packet_capture_interface_counters_after_capture"]["tx_dropped"] == 0

        statistics = metadata["packet_capture_statistics"]
        assert statistics["packets_received_by_filter"] - statistics["packets_captured"] - statistics["dropped_by_kernel"] == 0
        diagnostics = json.loads((run_dir / "packet_capture_diagnostics.json").read_text())
        assert diagnostics["process_return_code"] == 0
        assert diagnostics["pcap_file"]["record_count"] == statistics["packets_captured"]
        assert diagnostics["pcap_file"]["record_count_minus_tcpdump_captured"] == 0

        telemetry_path = run_dir / "telemetry.csv"
        with telemetry_path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            columns = reader.fieldnames or []
        feature_groups = metadata["telemetry_feature_groups"]
        feature_names = {field for fields in feature_groups.values() for field in fields}
        assert len(feature_names) == manifest["runner"]["feature_count"]
        assert len(rows) == 40
        assert len(columns) == 178
        assert set(columns) == set(metadata["telemetry_fields"])
        for row in rows:
            for field in feature_names:
                assert math.isfinite(float(row[field]))

        for csv_name, count_key in (("syscall_events.csv", "raw_syscall_event_count"), ("ebpf_events.csv", "ebpf_event_count")):
            with (run_dir / csv_name).open(newline="") as handle:
                row_count = sum(1 for _ in csv.DictReader(handle))
            assert row_count == metadata[count_key]

        archived_files = archive_files(sample_dir, run_dir)
        if sample_name.startswith("sqlite3-"):
            output_name = "sqlite-workload.db"
            expected_signature = b"SQLite format 3\x00"
            assert (run_dir / "sample.stdout.log").read_text().strip() == "500|41791750"
        elif sample_name.startswith("ffmpeg-"):
            output_name = "ffmpeg-output.mp4"
            expected_signature = None
        else:
            output_name = "zstd-output.zst"
            expected_signature = b"\x28\xb5\x2f\xfd"
        output_files = [name for name in archived_files if name.endswith(f"workspace/{output_name}")]
        assert len(output_files) == 1
        output_record = archived_files[output_files[0]]
        assert output_record["size_bytes"] > 0
        output_path = run_dir / output_files[0]
        output_bytes = output_path.read_bytes()
        if expected_signature is not None:
            assert output_bytes.startswith(expected_signature)
        if sample_name.startswith("ffmpeg-"):
            assert len(output_bytes) > 12 and output_bytes[4:8] == b"ftyp"

        report_samples.append({
            "sample": sample_name,
            "run_id": metadata["run_id"],
            "return_code": metadata["return_code"],
            "collection_quality_status": metadata["collection_quality_status"],
            "windows": len(rows),
            "feature_count": len(feature_names),
            "packet_count": statistics["packets_captured"],
            "raw_syscall_rows": metadata["raw_syscall_event_count"],
            "ebpf_event_rows": metadata["ebpf_event_count"],
            "archive_regular_files": len(archived_files),
            "output_file": output_files[0],
            "output_size_bytes": output_record["size_bytes"],
            "output_sha256": output_record["sha256"],
        })

    report = {
        "status": "accepted",
        "attempt": manifest["attempt"],
        "schema_version": manifest["runner"]["schema_version"],
        "runner_sha256": manifest["runner"]["sha256"],
        "snapshot": manifest["snapshot_lineage"]["prepared_snapshot_planned"],
        "sample_count": len(report_samples),
        "samples": report_samples,
        "limitations": [
            "Three purposively selected benign workloads are a pilot, not representative detector-performance evidence.",
            "The initial attempt is preserved separately and excluded because outputs were outside archives and SQLite exited nonzero.",
        ],
    }
    report_path = root / "pilot_retry_validation.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()