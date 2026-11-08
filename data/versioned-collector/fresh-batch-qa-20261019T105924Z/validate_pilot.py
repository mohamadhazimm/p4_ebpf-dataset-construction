import bisect
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
WORKSPACE = STUDY.parents[1]
sys.path.insert(0, str(WORKSPACE / "p4_ebpf"))
from analyze_p4_pcap_ablation import P4_FEATURES, derive_p4_features, utc_timestamp


def read_csv(path):
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        return reader.fieldnames, list(reader)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decoded_frames(capture, display_filter):
    result = subprocess.run(
        ["tshark", "-r", str(capture), "-Y", display_filter, "-T", "fields",
         "-e", "frame.number", "-e", "tcp.stream", "-e", "tls.handshake.extensions_server_name"],
        capture_output=True, text=True, check=True,
    )
    return [line.split("\t") for line in result.stdout.splitlines()]


def validate_case(case, manifest):
    sample_root = ROOT / "runs" / case["label"] / case["sample"]
    metadata_path, = (sample_root / "output").glob("*/run.json")
    run = metadata_path.parent
    metadata = json.loads(metadata_path.read_text())
    fields, windows = read_csv(run / "telemetry.csv")
    features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
    checks = {
        "batch_completed": "status=completed" in (sample_root / "host_run.txt").read_text(),
        "runner_provenance": metadata["malware_runner_sha256"] == manifest["runner_sha256"]
            and metadata["telemetry_schema_version"] == manifest["runner_schema"],
        "settings": metadata["timeout_seconds"] == 20 and metadata["window_seconds"] == 0.5
            and metadata["observation_mode"] == "fixed" and metadata["common_launch_wrapper"],
        "schema": len(windows) == 40 and len(fields) == 176 and len(features) == 169
            and fields == metadata["telemetry_fields"],
        "finite_complete_features": all(None not in row and all(row[name] not in (None, "")
            and math.isfinite(float(row[name])) for name in features) for row in windows),
        "sensors_active": metadata["ebpf_status"] == metadata["packet_capture_status"] == "active",
        "no_reported_pcap_loss": metadata["packet_capture_dropped_by_kernel"] == 0,
    }
    archive_files = 0
    archive_errors = []
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts or not (member.isfile() or member.isdir()):
                archive_errors.append(member.name)
                continue
            if member.isdir():
                continue
            candidates = {path.resolve() for path in (sample_root / member.name, sample_root / "output" / member.name)
                          if path.is_file() and path.resolve().is_relative_to(sample_root.resolve())}
            if len(candidates) != 1:
                archive_errors.append(member.name)
                continue
            host_path, = candidates
            with archive.extractfile(member) as source:
                archived_hash = hashlib.sha256(source.read()).hexdigest()
            if archived_hash != digest(host_path):
                archive_errors.append(member.name)
            archive_files += 1
    checks["archive_host_hash_parity"] = archive_files > 0 and not archive_errors
    _, rebuilt, alignment = derive_p4_features(
        run / "packet_capture.pcap", windows, metadata, byte_layer="ethernet", rate_window="nominal"
    )
    p4_mismatches = [(index, name) for index, row in enumerate(windows) for name in P4_FEATURES
                     if not math.isclose(float(row[name]), rebuilt[index][name], rel_tol=1e-9, abs_tol=1e-6)]
    checks["pcap_window_alignment"] = alignment["alignment_status"] == "unique"
    checks["all_p4_cells_match"] = not p4_mismatches
    origin = metadata["sample_started_monotonic_ns"]
    wall_origin = utc_timestamp(metadata["sample_started_at_utc"])
    starts = [utc_timestamp(row["window_start_utc"]) - wall_origin for row in windows]
    ends = [utc_timestamp(row["window_end_utc"]) - wall_origin for row in windows]
    events = {}
    for filename, count_key in [("ebpf_events.csv", "ebpf_event_count"),
                                ("syscall_events.csv", "raw_syscall_event_count")]:
        _, rows = read_csv(run / filename)
        wrong_nominal = 0
        wrong_recorded = 0
        for row in rows:
            timestamp = int(row["timestamp_ns"])
            window_id = int(row["window_id"])
            wrong_nominal += window_id != (timestamp - origin) // 500_000_000
            elapsed = (timestamp - origin) / 1_000_000_000
            recorded_id = bisect.bisect_right(starts, elapsed) - 1
            if recorded_id < 0 or elapsed >= ends[recorded_id]:
                recorded_id = None
            wrong_recorded += window_id != recorded_id
        checks[filename + "_metadata_count"] = len(rows) == metadata[count_key]
        checks[filename + "_nominal_windows"] = wrong_nominal == 0
        counts = Counter(int(row["window_id"]) for row in rows)
        feature = "ebpf_event_count" if filename == "ebpf_events.csv" else "host_total_syscalls_total"
        checks[filename + "_csv_count_parity"] = all(float(row[feature]) == counts[index]
                                                    for index, row in enumerate(windows))
        events[filename] = {"rows": len(rows), "nominal_window_disagreements": wrong_nominal,
                            "recorded_interval_disagreements": wrong_recorded,
                            "distinct_pids": len({row["pid"] for row in rows})}
    ebpf_log = (run / "ebpf_collector.log").read_text()
    loss_warnings = re.findall(r"\b(?:lost|dropped)\s+[1-9][0-9]*\b", ebpf_log, re.IGNORECASE)
    checks["no_reported_ebpf_loss"] = not loss_warnings
    client_hello = decoded_frames(run / "packet_capture.pcap", "tls.handshake.type == 1")
    server_hello = decoded_frames(run / "packet_capture.pcap", "tls.handshake.type == 2")
    encrypted_data = decoded_frames(run / "packet_capture.pcap", "tls.app_data")
    tls_streams = {row[1] for row in client_hello} & {row[1] for row in server_hello} & {row[1] for row in encrypted_data}
    return {
        "order": case["order"], "label": case["label"], "sample": case["sample"],
        "run": str(run.relative_to(ROOT)), "execution_status": metadata["status"],
        "return_code": metadata["return_code"], "artifact_type": metadata["sample_artifact_type"],
        "windows": len(windows), "features": len(features), "archive_regular_files": archive_files,
        "archive_errors": archive_errors, "checks": checks, "retrieval_and_within_sensor_checks_pass": all(checks.values()),
        "alignment": alignment, "p4_cells_compared": len(windows) * len(P4_FEATURES),
        "p4_mismatches": p4_mismatches, "events": events,
        "max_recorded_window_duration_error_seconds": max(abs(end - start - 0.5) for start, end in zip(starts, ends)),
        "cross_sensor_recorded_intervals_match": not any(item["recorded_interval_disagreements"] for item in events.values()),
        "reported_pcap_drops": metadata["packet_capture_dropped_by_kernel"], "ebpf_loss_warning_count": len(loss_warnings),
        "tls": {"client_hello_frames": len(client_hello), "server_hello_frames": len(server_hello),
                "encrypted_data_frames": len(encrypted_data), "verified_encrypted_streams": sorted(tls_streams),
                "sni": sorted({row[2] for row in client_hello if len(row) > 2 and row[2]})},
        "sha256": {name: digest(run / name) for name in ("run.json", "telemetry.csv", "packet_capture.pcap", "ebpf_events.csv", "syscall_events.csv")},
    }


if __name__ == "__main__":
    manifest = json.loads((ROOT / "pilot_manifest.json").read_text())
    results = [validate_case(case, manifest) for case in manifest["cases"]]
    report = {
        "run_id": manifest["run_id"], "selection_note": "Four named cases in fixed B/M/B/M order; no random sampling was performed.",
        "source_sha256": {"runner": digest(STUDY / "src/malware_runner.py"),
                          "batch": digest(STUDY / "scripts/vbox_malware_batch.sh"),
                          "offline_extractor": digest(WORKSPACE / "p4_ebpf/analyze_p4_pcap_ablation.py"),
                          "study_compatibility_wrapper": digest(STUDY / "scripts/rebuild_versioned_p4_csvs.py"),
                          "validator": digest(Path(__file__))},
        "cases": results,
        "limitations": ["Four selected cases are not classifier or family-generalization evidence.",
                        "No loss warning does not prove zero unreported kernel/eBPF loss.",
                        "Packet traffic/TLS is not attributed to the sample process by these PCAPs.",
                        "Host events use nominal windows; compare recorded_interval_disagreements before treating sensors as aligned.",
                        "Wall/monotonic conversion uses recorded origin with microsecond wall-clock precision."],
    }
    (ROOT / "qa_results.json").write_text(json.dumps(report, indent=2) + "\n")
    for result in results:
        print(json.dumps({key: result[key] for key in ("order", "sample", "execution_status", "return_code", "checks", "alignment", "events", "tls")}, indent=2))
    print("Full report:", ROOT / "qa_results.json")
    raise SystemExit(0 if all(result["retrieval_and_within_sensor_checks_pass"] for result in results) else 1)