import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_archive(sample_root):
    errors = []
    matched = 0
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                errors.append(f"unsafe archive path: {member.name}")
                continue
            if member.isdir():
                continue
            if not member.isfile():
                errors.append(f"special archive member: {member.name}")
                continue
            relative_path = Path(*[part for part in relative.parts if part not in ("", ".")])
            host_path = sample_root / "output" / relative_path
            if not host_path.is_file() or not host_path.resolve().is_relative_to(sample_root.resolve()):
                errors.append(f"missing or escaping host member: {member.name}")
                continue
            archived_hash = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            if archived_hash != sha256(host_path):
                errors.append(f"SHA-256 mismatch: {member.name}")
                continue
            matched += 1
    return matched, errors


def main():
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    assert manifest["runner"]["schema_version"] == "2026-10-19.8"
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == manifest["scripts"]["batch_sha256"]
    assert sha256(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == manifest["scripts"]["staging_sha256"]
    assert (ROOT / manifest["sample"]["manifest"]).read_text().strip() == manifest["sample"]["artifact"]

    sample_root = ROOT / manifest["output_directory"] / manifest["sample"]["artifact"]
    host_status = (sample_root / "host_run.txt").read_text()
    assert "status=completed" in host_status
    assert "collection_quality_status=accepted" in host_status
    run_path, = (sample_root / "output").glob("run_*/run.json")
    run_dir = run_path.parent
    metadata = json.loads(run_path.read_text())

    with (run_dir / "syscall_events.csv").open(newline="") as source:
        raw_rows = list(csv.DictReader(source))
    with (run_dir / "ebpf_events.csv").open(newline="") as source:
        ebpf_rows = list(csv.DictReader(source))
    with (run_dir / "telemetry.csv").open(newline="") as source:
        telemetry_reader = csv.DictReader(source)
        telemetry_rows = list(telemetry_reader)
        telemetry_columns = list(telemetry_reader.fieldnames or [])

    ebpf_log = (run_dir / "ebpf_collector.log").read_text()
    lost_counts = [int(value) for value in
                   re.findall(r"\bLost\s+(\d+)\s+events\b", ebpf_log, re.IGNORECASE)]
    packet_log = (run_dir / "packet_capture.log").read_text()
    packet_stats = metadata["packet_capture_statistics"]
    feature_groups = metadata["telemetry_feature_groups"]
    feature_fields = [field for group in feature_groups.values() for field in group]

    assert metadata["telemetry_schema_version"] == manifest["runner"]["schema_version"]
    assert metadata["malware_runner_sha256"] == manifest["runner"]["sha256"]
    assert metadata["bpftrace_perf_rb_pages"] == manifest["settings"]["bpftrace_perf_rb_pages_per_cpu"]
    assert metadata["packet_capture_buffer_kb_requested"] == manifest["settings"]["packet_capture_buffer_kb"]
    assert metadata["status"] == "timeout" and metadata["return_code"] == -9
    assert metadata["ebpf_status"] == metadata["packet_capture_status"] == "active"
    assert metadata["ebpf_lost_event_count"] == 0 and not lost_counts
    assert metadata["collection_quality_status"] == "accepted"
    assert metadata["collection_quality_reasons"] == []
    assert len(raw_rows) == metadata["raw_syscall_event_count"] == 2_565_063
    assert len(ebpf_rows) == metadata["ebpf_event_count"]
    assert len(feature_fields) == 169 and set(feature_fields) <= set(telemetry_columns)
    assert len(telemetry_rows) == 16 and len(telemetry_columns) == 178
    for row in telemetry_rows:
        assert row["collection_quality_status"] == "accepted"
        for field in feature_fields:
            assert row[field] != "" and math.isfinite(float(row[field]))
    assert packet_stats["dropped_by_kernel"] == metadata["packet_capture_dropped_by_kernel"] == 0
    captured_match = re.search(r"^\s*(\d+)\s+packets captured\b", packet_log, re.MULTILINE)
    received_match = re.search(r"^\s*(\d+)\s+packets received by filter\b", packet_log, re.MULTILINE)
    dropped_match = re.search(r"^\s*(\d+)\s+packets dropped by kernel\b", packet_log, re.MULTILINE)
    assert captured_match and received_match and dropped_match
    assert int(captured_match.group(1)) == packet_stats["packets_captured"]
    assert int(received_match.group(1)) == packet_stats["packets_received_by_filter"]
    assert int(dropped_match.group(1)) == packet_stats["dropped_by_kernel"]

    archive_members, archive_errors = validate_archive(sample_root)
    assert archive_members == 13 and not archive_errors
    artifact_names = ("run.json", "telemetry.csv", "syscall_events.csv",
                      "ebpf_events.csv", "packet_capture.pcap")
    report = {
        "run_id": manifest["run_id"],
        "sample": manifest["sample"]["artifact"],
        "schema": metadata["telemetry_schema_version"],
        "runner_sha256": metadata["malware_runner_sha256"],
        "process_status": metadata["status"],
        "return_code": metadata["return_code"],
        "quality": metadata["collection_quality_status"],
        "bpftrace_perf_pages_per_cpu": metadata["bpftrace_perf_rb_pages"],
        "raw_syscall_rows": len(raw_rows),
        "ebpf_named_event_rows": len(ebpf_rows),
        "ebpf_lost_events": metadata["ebpf_lost_event_count"],
        "packet_capture_statistics": packet_stats,
        "telemetry_windows": len(telemetry_rows),
        "telemetry_columns": len(telemetry_columns),
        "feature_fields": len(feature_fields),
        "archive_regular_files_sha256_matched": archive_members,
        "archive_errors": archive_errors,
        "artifact_sha256": {name: sha256(run_dir / name) for name in artifact_names},
        "limits": ["One sample/run does not guarantee zero loss for other workloads or durations.",
                   "The process timed out at the configured 8-second limit; accepted quality is not successful malware exit.",
                   "Offline PCAP reconstruction is not live P4 performance evidence."],
    }
    (ROOT / "lockbit_v8_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("sample", "process_status", "return_code", "quality",
                       "bpftrace_perf_pages_per_cpu", "raw_syscall_rows",
                       "ebpf_lost_events", "packet_capture_statistics",
                       "telemetry_windows", "archive_regular_files_sha256_matched")}, indent=2))


if __name__ == "__main__":
    main()