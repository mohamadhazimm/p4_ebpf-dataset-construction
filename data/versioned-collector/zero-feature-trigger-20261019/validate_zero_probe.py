import ast
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
OUTPUT = ROOT / "runs/benign/zero_feature_probe.sh"
ENDPOINT_FEATURES = ("host_unique_ip_total", "host_unique_port_total",
                     "host_unique_remote_ips", "host_unique_remote_ports")
SYSCALL_IDS = {"accept": 43, "pwrite64": 18, "writev": 20, "unlinkat": 263,
               "renameat": 264, "renameat2": 316, "execveat": 322,
               "openat2": 437, "ptrace": 101}
EVENT_FEATURES = {"accept": "ebpf_accept_count", "pwrite64": "ebpf_pwrite64_count",
                  "writev": "ebpf_writev_count", "unlinkat": "ebpf_unlinkat_count",
                  "renameat": "ebpf_renameat_count", "renameat2": "ebpf_renameat2_count",
                  "execveat": "ebpf_execveat_count", "openat2": "ebpf_openat2_count",
                  "ptrace": "ebpf_ptrace_count"}


def read_csv(path):
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        return reader.fieldnames, list(reader)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def frame_count(capture, display_filter):
    result = subprocess.run(["tshark", "-r", str(capture), "-Y", display_filter,
                             "-T", "fields", "-e", "frame.number"],
                            capture_output=True, text=True, check=True)
    return len([line for line in result.stdout.splitlines() if line])


def archive_parity(sample_root):
    regular_files = 0
    errors = []
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                errors.append(f"unsafe archive path: {member.name}")
            elif member.isdir():
                continue
            elif not member.isfile():
                errors.append(f"special archive member: {member.name}")
            else:
                candidates = {path.resolve() for path in
                              (sample_root / member.name, sample_root / "output" / member.name)
                              if path.is_file() and path.resolve().is_relative_to(sample_root.resolve())}
                if len(candidates) != 1:
                    errors.append(f"missing/ambiguous host member: {member.name}")
                    continue
                host_path, = candidates
                with archive.extractfile(member) as source:
                    if hashlib.sha256(source.read()).hexdigest() != sha256(host_path):
                        errors.append(f"archive SHA-256 mismatch: {member.name}")
                regular_files += 1
    return regular_files, errors


if __name__ == "__main__":
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    assert sha256(ROOT / "zero_feature_probe.sh") == manifest["workload_sha256"]
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner_sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == manifest["batch_sha256"]
    metadata_path, = (OUTPUT / "output").glob("*/run.json")
    run = metadata_path.parent
    metadata = json.loads(metadata_path.read_text())
    fields, windows = read_csv(run / "telemetry.csv")
    numeric_features = [name for names in metadata["telemetry_feature_groups"].values() for name in names]
    _, ebpf_events = read_csv(run / "ebpf_events.csv")
    _, syscalls = read_csv(run / "syscall_events.csv")
    checks = {
        "retrieval_completed": "status=completed" in (OUTPUT / "host_run.txt").read_text(),
        "runner_provenance": metadata["telemetry_schema_version"] == manifest["runner_schema"]
            and metadata["malware_runner_sha256"] == manifest["runner_sha256"],
        "sensors_active": metadata["ebpf_status"] == metadata["packet_capture_status"] == "active",
        "telemetry_complete": len(windows) == 40 and len(fields) == 176 and len(numeric_features) == 169
            and fields == metadata["telemetry_fields"]
            and all(row[name] not in (None, "") and math.isfinite(float(row[name]))
                    for row in windows for name in numeric_features),
        "raw_event_counts": len(ebpf_events) == metadata["ebpf_event_count"]
            and len(syscalls) == metadata["raw_syscall_event_count"],
        "no_reported_pcap_drop": metadata["packet_capture_dropped_by_kernel"] == 0,
    }
    archive_files, archive_errors = archive_parity(OUTPUT)
    checks["archive_parity"] = archive_files > 0 and not archive_errors

    with (run / "sample.stdout.log").open() as source:
        stdout = source.read().strip()
    probe_output = ast.literal_eval(stdout.splitlines()[-1])
    probe_results = probe_output["results"]
    feature_sums = {name: sum(float(row[name]) for row in windows)
                    for name in manifest["target_zero_features"]}
    changed = sorted(name for name, value in feature_sums.items() if value > 0)
    still_zero = sorted(name for name, value in feature_sums.items() if value == 0)
    raw_ids = Counter()
    for row in syscalls:
        try:
            number = int(row["detail"].partition("id=")[2])
        except ValueError:
            continue
        raw_ids[number] += 1
    named_events = Counter(row["event"] for row in ebpf_events)
    syscall_comparison = {
        name: {"syscall_number": number, "raw_syscall_rows": raw_ids[number],
               "named_event_rows": named_events[name],
               "entry_feature": EVENT_FEATURES[name],
               "entry_feature_sum": feature_sums.get(EVENT_FEATURES[name])}
        for name, number in SYSCALL_IDS.items()
    }
    syscall_entry_gaps = sorted(name for name, number in SYSCALL_IDS.items()
                                if raw_ids[number] and named_events[name] == 0)

    packet_counts = {
        "icmp": frame_count(run / "packet_capture.pcap", "icmp"),
        "ipv6": frame_count(run / "packet_capture.pcap", "ipv6"),
        "igmp": frame_count(run / "packet_capture.pcap", "ip.proto == 2"),
        "other_ip_protocol_253": frame_count(run / "packet_capture.pcap", "ip.proto == 253"),
        "large_frames_ge_1200": frame_count(run / "packet_capture.pcap", "frame.len >= 1200"),
        "tcp_urgent": frame_count(run / "packet_capture.pcap", "tcp.flags.urg == 1"),
    }
    ebpf_log = (run / "ebpf_collector.log").read_text()
    report = {
        "run_id": manifest["run_id"],
        "sample": manifest["sample"],
        "run_metadata": {key: metadata.get(key) for key in
            ("status", "return_code", "timeout_seconds", "window_seconds", "observation_mode",
             "ebpf_status", "packet_capture_status", "packet_capture_dropped_by_kernel",
             "ebpf_event_count", "raw_syscall_event_count", "telemetry_schema_version", "malware_runner_sha256")},
        "checks": checks,
        "archive_regular_files_sha256_matched": archive_files,
        "archive_errors": archive_errors,
        "windows": len(windows),
        "features": len(numeric_features),
        "ebpf_event_rows": len(ebpf_events),
        "raw_syscall_rows": len(syscalls),
        "script_reported_operations": probe_results,
        "target_feature_sums": feature_sums,
        "features_changed": changed,
        "features_still_zero": still_zero,
        "raw_vs_named_syscalls": syscall_comparison,
        "raw_syscall_seen_but_named_event_missing": syscall_entry_gaps,
        "pcap_dissector_frame_counts": packet_counts,
        "ebpf_collector_log": ebpf_log,
        "interpretation": [
            "Script-reported operation success is paired with raw syscall and output evidence; it does not guarantee an entry probe emits its named event.",
            "IPv6 send may be unavailable because the guest has no IPv6 route on the isolated interface.",
            "Experimental raw IP protocol 253 may be blocked for an unprivileged payload; IGMP can still produce an other-IP frame.",
            "Probe mismatches are evidence of missing named event output in this run; root cause is not inferred from this single run."
        ],
        "artifacts_sha256": {name: sha256(run / name) for name in
            ("run.json", "telemetry.csv", "ebpf_events.csv", "syscall_events.csv", "packet_capture.pcap", "sample.stdout.log")},
        "validator_sha256": sha256(Path(__file__)),
    }
    checks["workload_operation_log"] = bool(probe_results)
    report["checks"] = checks
    (ROOT / "probe_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"features_changed": changed, "features_still_zero": still_zero,
                      "raw_syscall_seen_but_named_event_missing": syscall_entry_gaps,
                      "pcap_dissector_frame_counts": packet_counts,
                      "checks": checks}, indent=2))
    raise SystemExit(0 if all(checks.values()) else 1)