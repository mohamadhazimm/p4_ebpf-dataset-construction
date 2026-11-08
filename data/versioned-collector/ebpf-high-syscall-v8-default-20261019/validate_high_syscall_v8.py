import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_parity(sample_root):
    matched = 0
    errors = []
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                errors.append(f"unsafe path: {member.name}")
                continue
            if member.isdir():
                continue
            if not member.isfile():
                errors.append(f"special member: {member.name}")
                continue
            relative_path = Path(*[part for part in relative.parts if part not in ("", ".")])
            host_path = sample_root / "output" / relative_path
            if not host_path.is_file() or not host_path.resolve().is_relative_to(sample_root.resolve()):
                errors.append(f"host member missing or escaping: {member.name}")
                continue
            archived_hash = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            if archived_hash != sha256(host_path):
                errors.append(f"SHA-256 mismatch: {member.name}")
                continue
            matched += 1
    return matched, errors


def main():
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == manifest["scripts"]["batch_sha256"]
    assert sha256(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == manifest["scripts"]["staging_sha256"]
    probe = ROOT.parent / "ebpf-high-syscall-v7-20261019/high_syscall_probe.sh"
    assert sha256(probe) == manifest["scripts"]["probe_sha256"]

    sample_root = ROOT / manifest["output_directory"] / manifest["probe"]["sample"]
    host_status = (sample_root / "host_run.txt").read_text()
    assert "status=completed" in host_status
    assert "collection_quality_status=accepted" in host_status
    run_path, = (sample_root / "output").glob("*/run.json")
    run_dir = run_path.parent
    metadata = json.loads(run_path.read_text())
    with (run_dir / "syscall_events.csv").open(newline="") as source:
        raw_rows = list(csv.DictReader(source))
    with (run_dir / "telemetry.csv").open(newline="") as source:
        telemetry_rows = list(csv.DictReader(source))

    stdout = json.loads((run_dir / "sample.stdout.log").read_text())
    ebpf_log = (run_dir / "ebpf_collector.log").read_text()
    loss_counts = [int(match) for match in re.findall(r"\bLost\s+(\d+)\s+events\b", ebpf_log, re.IGNORECASE)]
    packet_stats = metadata["packet_capture_statistics"]
    assert metadata["telemetry_schema_version"] == manifest["runner"]["schema_version"]
    assert metadata["malware_runner_sha256"] == manifest["runner"]["sha256"]
    assert metadata["status"] == "completed" and metadata["return_code"] == 0
    assert metadata["bpftrace_perf_rb_pages"] == manifest["settings"]["bpftrace_perf_rb_pages"]
    assert metadata["packet_capture_buffer_kb_requested"] == manifest["settings"]["packet_capture_buffer_kb"]
    assert metadata["ebpf_status"] == metadata["packet_capture_status"] == "active"
    assert metadata["ebpf_lost_event_count"] == 0 and not loss_counts
    assert metadata["collection_quality_status"] == "accepted"
    assert metadata["collection_quality_reasons"] == []
    assert metadata["raw_syscall_event_count"] == len(raw_rows) == 2_001_036
    assert stdout["stat_calls"] == manifest["probe"]["maximum_stat_calls"]
    assert len(telemetry_rows) == 16
    assert all(row["collection_quality_status"] == "accepted" for row in telemetry_rows)
    assert packet_stats["dropped_by_kernel"] == 0

    archive_members, archive_errors = archive_parity(sample_root)
    assert archive_members == 10 and not archive_errors
    artifact_names = ("run.json", "telemetry.csv", "syscall_events.csv",
                      "ebpf_events.csv", "packet_capture.pcap")
    report = {
        "run_id": manifest["run_id"],
        "schema": metadata["telemetry_schema_version"],
        "runner_sha256": metadata["malware_runner_sha256"],
        "probe": stdout,
        "perf_pages_per_cpu": metadata["bpftrace_perf_rb_pages"],
        "raw_syscall_rows": len(raw_rows),
        "ebpf_lost_events": metadata["ebpf_lost_event_count"],
        "quality": metadata["collection_quality_status"],
        "sensor_status": {"ebpf": metadata["ebpf_status"], "packet_capture": metadata["packet_capture_status"]},
        "packet_capture_statistics": packet_stats,
        "telemetry_windows": len(telemetry_rows),
        "archive_regular_files_sha256_matched": archive_members,
        "archive_errors": archive_errors,
        "artifact_sha256": {name: sha256(run_dir / name) for name in artifact_names},
        "limits": ["One benign synthetic workload does not certify every event mix or duration.",
                   "Earlier v6 LockBit capture remains rejected and is not retroactively repaired."],
    }
    (ROOT / "loss_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("schema", "probe", "perf_pages_per_cpu", "raw_syscall_rows",
                       "ebpf_lost_events", "quality", "archive_regular_files_sha256_matched")}, indent=2))


if __name__ == "__main__":
    main()