import ast
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
WORKSPACE = STUDY.parents[1]
sys.path.insert(0, str(WORKSPACE))
sys.path.insert(0, str(STUDY))
from merge_collector_csvs import merge_csvs
from src.build_dataset import load_telemetry


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path):
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        return reader.fieldnames, list(reader)


def validate_trial(name, runner_hash, schema, buffer_kb, perf_pages, expected_quality):
    sample_root = ROOT / "runs" / name / "loss_stress_probe.sh"
    metadata_path, = (sample_root / "output").glob("*/run.json")
    run = metadata_path.parent
    metadata = json.loads(metadata_path.read_text())
    fields, windows = read_csv(run / "telemetry.csv")
    with (run / "sample.stdout.log").open() as source:
        workload = ast.literal_eval(source.read().strip().splitlines()[-1])
    assert metadata["malware_runner_sha256"] == runner_hash
    assert metadata["telemetry_schema_version"] == schema
    assert metadata["timeout_seconds"] == 8 and metadata["window_seconds"] == 0.5
    assert metadata["status"] == "completed" and metadata["return_code"] == 0
    assert metadata["packet_capture_buffer_kb_requested"] == buffer_kb
    assert metadata["bpftrace_perf_rb_pages"] == perf_pages
    assert len(windows) == 16 and len(fields) == len(metadata["telemetry_fields"])
    assert metadata["collection_quality_status"] == expected_quality
    assert all(row["collection_quality_status"] == expected_quality for row in windows)
    assert workload["route_interface"] == "enp0s3"
    assert workload["packets_sent"] == workload["stat_calls"] == 50000
    stats = metadata["packet_capture_statistics"]
    assert metadata["packet_capture_dropped_by_kernel"] == stats["dropped_by_kernel"]
    assert metadata["ebpf_lost_event_count"] == 0

    archive_count = 0
    archive_errors = []
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                archive_errors.append(member.name)
                continue
            if member.isdir():
                continue
            if not member.isfile():
                archive_errors.append(member.name)
                continue
            candidates = {candidate.resolve() for candidate in
                          (sample_root / member.name, sample_root / "output" / member.name)
                          if candidate.is_file() and candidate.resolve().is_relative_to(sample_root.resolve())}
            if len(candidates) != 1:
                archive_errors.append(member.name)
                continue
            host_path, = candidates
            with archive.extractfile(member) as source:
                if hashlib.sha256(source.read()).hexdigest() != sha256(host_path):
                    archive_errors.append(member.name)
            archive_count += 1
    assert archive_count > 0 and not archive_errors
    return {
        "trial": name, "schema": schema, "runner_sha256": runner_hash,
        "packet_capture_buffer_kb": buffer_kb, "bpftrace_perf_rb_pages": perf_pages,
        "quality_status": metadata["collection_quality_status"],
        "quality_reasons": metadata["collection_quality_reasons"],
        "tcpdump_statistics": stats, "ebpf_lost_event_count": metadata["ebpf_lost_event_count"],
        "rmem_before": metadata.get("packet_capture_rmem_max_before"),
        "rmem_during": metadata.get("packet_capture_rmem_max_during_capture"),
        "rmem_after": metadata.get("packet_capture_rmem_max_after_capture"),
        "rmem_restore_error": metadata.get("packet_capture_buffer_restore_error"),
        "packets_sent": workload["packets_sent"], "stat_calls": workload["stat_calls"],
        "telemetry_windows": len(windows), "telemetry_fields": len(fields),
        "archive_files_sha256_matched": archive_count,
        "artifact_sha256": {filename: sha256(run / filename) for filename in
                             ("run.json", "telemetry.csv", "packet_capture.pcap", "ebpf_events.csv", "syscall_events.csv")},
    }


def validate_dataset_gate(name, expected_quality):
    input_root = ROOT / "runs" / name
    merged = ROOT / f".quality-gate-{name}.csv"
    try:
        merge_csvs(input_root, merged)
        try:
            examples, _ = load_telemetry(merged, 1, "benign stress control")
        except ValueError as error:
            if expected_quality != "rejected" or "collection quality rejected" not in str(error):
                raise
            return {"trial": name, "dataset_gate": "rejected", "reason": str(error)}
        if expected_quality != "accepted":
            raise AssertionError(f"{name} unexpectedly entered dataset builder")
        assert len(examples) == 1
        assert examples[0]["collection_quality_status"] == "accepted"
        return {"trial": name, "dataset_gate": "accepted", "examples": len(examples)}
    finally:
        merged.unlink(missing_ok=True)


if __name__ == "__main__":
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    retry = json.loads((ROOT / "metadata_retry_manifest.json").read_text())
    assert sha256(STUDY / "src/malware_runner.py") == retry["runner_sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == retry["batch_sha256"]
    assert sha256(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == retry["staging_sha256"]
    assert sha256(ROOT / "loss_stress_probe.sh") == retry["workload_sha256"]
    baseline = validate_trial("baseline", manifest["runner_sha256"], "2026-10-19.5", 64, 64, "rejected")
    tuned = validate_trial("tuned", manifest["runner_sha256"], "2026-10-19.5", 16384, 1024, "accepted")
    tuned_v6 = validate_trial("tuned-v6", retry["runner_sha256"], "2026-10-19.6", 16384, 1024, "accepted")
    dataset_gate = [validate_dataset_gate(name, quality)
                    for name, quality in (("baseline", "rejected"), ("tuned", "accepted"),
                                          ("tuned-v6", "accepted"))]
    assert baseline["tcpdump_statistics"]["dropped_by_kernel"] > 0
    assert tuned["tcpdump_statistics"]["dropped_by_kernel"] == 0
    assert tuned["ebpf_lost_event_count"] == tuned_v6["ebpf_lost_event_count"] == 0
    assert tuned_v6["rmem_before"] == tuned_v6["rmem_after"]
    assert tuned_v6["rmem_during"] >= tuned_v6["packet_capture_buffer_kb"] * 2048
    assert tuned_v6["rmem_restore_error"] is None
    report = {
        "run_id": manifest["run_id"],
        "comparison": [baseline, tuned, tuned_v6],
        "dataset_builder_gate": dataset_gate,
        "interpretation": [
            "For this identical 50,000-datagram/50,000-stat benign probe, the 64-KiB/64-page run was rejected after tcpdump reported packet drops.",
            "The tuned 16-MiB/1024-page runs reported no PCAP or bpftrace loss; v6 confirms net.core.rmem_max rose during capture and returned to its original value afterward.",
            "This single synthetic load reduces measured loss versus the small-buffer baseline but does not guarantee loss-free capture for other workloads or rates.",
            "The run.json/CSV quality gate marks reported loss rejected, and build_dataset.py refuses rejected telemetry."
        ],
        "original_snapshot_restoration_target": manifest["original_snapshot_to_restore"],
        "validator_sha256": sha256(Path(__file__)),
    }
    (ROOT / "loss_mitigation_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))