import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
EXPECTED_SCHEMA = "2026-10-19.8"
EXPECTED_RUNNER_SHA256 = "1f08c55ec6c2304cc4598971e9ba8e03fcbe0f31cb0d2ca39cf7bc21a18fbaa0"
EXPECTED_BUFFER_PAGES = 16384
EXPECTED_PCAP_BUFFER_KB = 16384


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(source):
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        return list(reader), list(reader.fieldnames or [])


def parse_host_run(path):
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            result[key] = value
    return result


def parse_bpftrace_lost(log_path):
    text = log_path.read_text(encoding="utf-8", errors="replace")
    return sum(int(value) for value in re.findall(r"\bLost\s+(\d+)\s+events\b", text, re.IGNORECASE))


def parse_tcpdump_stats(log_path):
    text = log_path.read_text(encoding="utf-8", errors="replace")
    patterns = {
        "packets_captured": r"^\s*(\d+)\s+packets captured\b",
        "packets_received_by_filter": r"^\s*(\d+)\s+packets received by filter\b",
        "dropped_by_kernel": r"^\s*(\d+)\s+packets dropped by kernel\b",
    }
    values = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
        values[key] = int(matches[-1]) if matches else None
    return values


def check_archive_parity(sample_root):
    errors = []
    regular_files = 0
    archive_path = sample_root / "output.tgz"
    if not archive_path.is_file():
        return regular_files, ["output.tgz missing"]
    with tarfile.open(archive_path, "r:gz") as archive:
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
                errors.append(f"missing or escaping extracted member: {member.name}")
                continue
            archived = archive.extractfile(member)
            if archived is None or sha256_stream(archived) != sha256_file(host_path):
                errors.append(f"SHA-256 mismatch: {member.name}")
                continue
            regular_files += 1
    return regular_files, errors


def audit_run(sample_root, expected_sample, family=None):
    issues = []
    host_status = parse_host_run(sample_root / "host_run.txt") if (sample_root / "host_run.txt").is_file() else {}
    run_json_paths = list((sample_root / "output").glob("run_*/run.json"))
    if len(run_json_paths) != 1:
        return {
            "sample": expected_sample,
            "family": family,
            "retrieval_status": host_status.get("status", "missing"),
            "quality": host_status.get("collection_quality_status", "missing"),
            "issues": [f"expected one run.json; found {len(run_json_paths)}"],
        }

    run_json = run_json_paths[0]
    run_dir = run_json.parent
    metadata = read_json(run_json)
    host_retrieval = host_status.get("status", "missing")
    if host_retrieval != "completed":
        issues.append(f"retrieval_status:{host_retrieval}")
    if host_status.get("sample") != expected_sample:
        issues.append("host sample name does not match selected artifact")
    if metadata.get("telemetry_schema_version") != EXPECTED_SCHEMA:
        issues.append(f"schema:{metadata.get('telemetry_schema_version')}")
    if metadata.get("malware_runner_sha256") != EXPECTED_RUNNER_SHA256:
        issues.append("runner SHA mismatch")
    if metadata.get("bpftrace_perf_rb_pages") != EXPECTED_BUFFER_PAGES:
        issues.append(f"effective perf pages:{metadata.get('bpftrace_perf_rb_pages')}")
    if metadata.get("packet_capture_buffer_kb_requested") != EXPECTED_PCAP_BUFFER_KB:
        issues.append(f"requested PCAP buffer:{metadata.get('packet_capture_buffer_kb_requested')}")

    raw_rows, _ = read_csv(run_dir / "syscall_events.csv")
    named_rows, _ = read_csv(run_dir / "ebpf_events.csv")
    telemetry_rows, telemetry_columns = read_csv(run_dir / "telemetry.csv")
    feature_groups = metadata.get("telemetry_feature_groups", {})
    feature_fields = [field for group in feature_groups.values() for field in group]
    if len(feature_fields) != 169 or len(set(feature_fields)) != 169:
        issues.append(f"declared feature count/uniqueness:{len(feature_fields)}")
    if len(telemetry_rows) != 16 or len(telemetry_columns) != 178:
        issues.append(f"telemetry shape:{len(telemetry_rows)}x{len(telemetry_columns)}")
    for row_index, row in enumerate(telemetry_rows):
        if row.get("collection_quality_status") != metadata.get("collection_quality_status"):
            issues.append(f"quality label mismatch in telemetry row {row_index}")
            break
        for field in feature_fields:
            try:
                value = float(row[field])
            except (KeyError, TypeError, ValueError):
                issues.append(f"missing/non-numeric feature {field} in row {row_index}")
                break
            if not math.isfinite(value):
                issues.append(f"non-finite feature {field} in row {row_index}")
                break

    raw_count = metadata.get("raw_syscall_event_count")
    named_count = metadata.get("ebpf_event_count")
    if len(raw_rows) != raw_count:
        issues.append(f"raw syscall rows {len(raw_rows)} != metadata {raw_count}")
    if len(named_rows) != named_count:
        issues.append(f"named eBPF rows {len(named_rows)} != metadata {named_count}")
    log_loss = parse_bpftrace_lost(run_dir / "ebpf_collector.log")
    metadata_loss = metadata.get("ebpf_lost_event_count")
    if log_loss != metadata_loss:
        issues.append(f"bpftrace log loss {log_loss} != metadata {metadata_loss}")

    packet_log = parse_tcpdump_stats(run_dir / "packet_capture.log")
    packet_metadata = metadata.get("packet_capture_statistics") or {}
    for key in packet_log:
        if packet_log[key] is None:
            issues.append(f"tcpdump {key} unavailable in log")
        elif packet_log[key] != packet_metadata.get(key):
            issues.append(f"tcpdump {key} log/metadata mismatch")
    kernel_drops = packet_metadata.get("dropped_by_kernel")
    if kernel_drops != metadata.get("packet_capture_dropped_by_kernel"):
        issues.append("PCAP kernel-drop metadata mismatch")
    received = packet_metadata.get("packets_received_by_filter")
    captured = packet_metadata.get("packets_captured")
    counter_gap = received - captured if received is not None and captured is not None else None
    if counter_gap is None:
        issues.append("received/captured packet counters unavailable")

    quality = metadata.get("collection_quality_status")
    if metadata.get("ebpf_status") != "active" or metadata.get("packet_capture_status") != "active":
        issues.append("requested sensor inactive")
    if quality != "accepted":
        issues.append(f"collection_quality_status:{quality}")
    if metadata.get("packet_capture_buffer_restore_error"):
        issues.append(f"PCAP buffer restore error:{metadata['packet_capture_buffer_restore_error']}")
    rmem_before = metadata.get("packet_capture_rmem_max_before")
    rmem_after = metadata.get("packet_capture_rmem_max_after_capture")
    if rmem_before is not None and rmem_after != rmem_before:
        issues.append(f"rmem_max not restored:{rmem_before}->{rmem_after}")

    archive_members, archive_errors = check_archive_parity(sample_root)
    issues.extend(archive_errors)
    return {
        "sample": expected_sample,
        "family": family,
        "run_id": metadata.get("run_id"),
        "retrieval_status": host_retrieval,
        "process_status": metadata.get("status"),
        "process_return_code": metadata.get("return_code"),
        "quality": quality,
        "schema": metadata.get("telemetry_schema_version"),
        "runner_sha256": metadata.get("malware_runner_sha256"),
        "bpftrace_perf_rb_pages": metadata.get("bpftrace_perf_rb_pages"),
        "raw_syscall_rows": len(raw_rows),
        "named_ebpf_rows": len(named_rows),
        "ebpf_lost_events_log": log_loss,
        "ebpf_lost_events_metadata": metadata_loss,
        "pcap": packet_metadata,
        "received_minus_captured": counter_gap,
        "packet_capture_rmem_max_before": rmem_before,
        "packet_capture_rmem_max_during": metadata.get("packet_capture_rmem_max_during_capture"),
        "packet_capture_rmem_max_after": rmem_after,
        "telemetry_rows": len(telemetry_rows),
        "telemetry_columns": len(telemetry_columns),
        "feature_count": len(feature_fields),
        "archive_regular_files_sha256_matched": archive_members,
        "issues": issues,
        "artifact_sha256": {
            name: sha256_file(run_dir / name)
            for name in ("run.json", "telemetry.csv", "syscall_events.csv", "ebpf_events.csv", "packet_capture.pcap")
            if (run_dir / name).is_file()
        },
    }


def audit_reused_lockbit():
    result_path = STUDY / "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/lockbit_v8_results.json"
    result = read_json(result_path)
    manifest_path = STUDY / "data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/experiment_manifest.json"
    manifest = read_json(manifest_path)
    issues = []
    if result.get("schema") != EXPECTED_SCHEMA or result.get("runner_sha256") != EXPECTED_RUNNER_SHA256:
        issues.append("reused LockBit schema/hash mismatch")
    if result.get("ebpf_lost_events") != 0:
        issues.append(f"reused LockBit eBPF loss:{result.get('ebpf_lost_events')}")
    if result.get("packet_capture_statistics", {}).get("dropped_by_kernel") != 0:
        issues.append("reused LockBit PCAP kernel drops nonzero")
    return {
        "sample": manifest["sample"]["artifact"],
        "family": "LockBit",
        "execution": "reused prior validated v8 capture; not re-executed",
        "run_id": result.get("run_id"),
        "retrieval_status": "completed",
        "process_status": result.get("process_status"),
        "process_return_code": result.get("return_code"),
        "quality": result.get("quality"),
        "schema": result.get("schema"),
        "runner_sha256": result.get("runner_sha256"),
        "bpftrace_perf_rb_pages": result.get("bpftrace_perf_pages_per_cpu"),
        "raw_syscall_rows": result.get("raw_syscall_rows"),
        "named_ebpf_rows": None,
        "ebpf_lost_events_log": result.get("ebpf_lost_events"),
        "ebpf_lost_events_metadata": result.get("ebpf_lost_events"),
        "pcap": result.get("packet_capture_statistics"),
        "received_minus_captured": result.get("packet_capture_statistics", {}).get("packets_received_by_filter", 0)
                                   - result.get("packet_capture_statistics", {}).get("packets_captured", 0),
        "issues": issues,
    }


def main():
    manifest = read_json(ROOT / "experiment_manifest.json")
    selection = read_json(ROOT / "family_selection.json")
    assert sha256_file(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256_file(STUDY / "scripts/vbox_malware_batch.sh") == manifest["scripts"]["batch_sha256"]
    assert sha256_file(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == manifest["scripts"]["staging_sha256"]

    results = []
    malware_root = ROOT / "runs/malware-v8"
    for selected in selection["samples"]:
        if selected["execution"] == "reuse_existing_validated_run":
            results.append(audit_reused_lockbit())
        else:
            results.append(audit_run(malware_root / selected["artifact"], selected["artifact"], selected["family"]))

    benign_specs = (
        ("benign-curl-v8/curl-pair-01", "curl-pair-01", "benign"),
        ("benign-curl-v8/curl-pair-02", "curl-pair-02", "benign"),
        ("benign-high-syscall-v8/high_syscall_probe.sh", "high_syscall_probe.sh", "benign"),
        ("benign-packet-stress-v8/loss_stress_probe.sh", "loss_stress_probe.sh", "benign"),
    )
    for relative, sample, family in benign_specs:
        results.append(audit_run(ROOT / "runs" / relative, sample, family))

    families = {}
    for family in selection["named_families"]:
        entries = [item for item in results if item.get("family") == family]
        families[family] = {
            "sample_count": len(entries),
            "quality_accepted": sum(item.get("quality") == "accepted" for item in entries),
            "ebpf_lost_runs": sum(bool(item.get("ebpf_lost_events_metadata")) for item in entries),
            "ebpf_lost_events": sum(item.get("ebpf_lost_events_metadata") or 0 for item in entries),
            "kernel_drop_runs": sum(bool((item.get("pcap") or {}).get("dropped_by_kernel")) for item in entries),
            "kernel_drops": sum((item.get("pcap") or {}).get("dropped_by_kernel") or 0 for item in entries),
            "received_capture_gap_runs": sum(bool(item.get("received_minus_captured")) for item in entries),
        }

    pcap_gaps = [item for item in results if item.get("received_minus_captured")]
    issue_runs = [item for item in results if item.get("issues")]
    summary = {
        "expected_unique_malware_artifacts": 49,
        "expected_new_malware_captures": 48,
        "reused_validated_lockbit_captures": 1,
        "benign_controls": 4,
        "runs_audited": len(results),
        "retrieval_completed": sum(item.get("retrieval_status") == "completed" for item in results),
        "quality_accepted": sum(item.get("quality") == "accepted" for item in results),
        "quality_rejected_or_missing": sum(item.get("quality") != "accepted" for item in results),
        "ebpf_loss_runs": sum(bool(item.get("ebpf_lost_events_metadata")) for item in results),
        "ebpf_lost_events_total": sum(item.get("ebpf_lost_events_metadata") or 0 for item in results),
        "pcap_kernel_drop_runs": sum(bool((item.get("pcap") or {}).get("dropped_by_kernel")) for item in results),
        "pcap_kernel_drops_total": sum((item.get("pcap") or {}).get("dropped_by_kernel") or 0 for item in results),
        "received_capture_gap_runs": len(pcap_gaps),
        "received_capture_gap_total": sum(item.get("received_minus_captured") or 0 for item in pcap_gaps),
        "received_capture_gap_details": [
            {"sample": item["sample"], "family": item.get("family"),
             "gap": item.get("received_minus_captured"), "run_id": item.get("run_id")}
            for item in pcap_gaps
        ],
        "runs_with_validation_issues": len(issue_runs),
        "validation_issues": [
            {"sample": item.get("sample"), "family": item.get("family"), "issues": item.get("issues")}
            for item in issue_runs
        ],
        "families": families,
        "benign_packet_stress_alignment_note": manifest["interim_benign_results"]["packet_stress"]["offline_per_window_alignment"],
        "limitations": [
            "Zero reported kernel drops and zero bpftrace lost-event counters apply only to these finite runs.",
            "Received-by-filter minus packets-captured gaps remain unresolved and are not counted by the current quality gate.",
            "Accepted collection quality does not imply successful malware execution; process timeouts/signals remain separate.",
            "Offline PCAP window alignment is a separate check from kernel packet drops and total in-window feature packets.",
            "One artifact is available for seven named families, per the approved scope; the unassigned bucket is excluded.",
        ],
    }
    report = {
        "run_id": manifest["run_id"],
        "schema": EXPECTED_SCHEMA,
        "runner_sha256": EXPECTED_RUNNER_SHA256,
        "summary": summary,
        "results": results,
        "validator_sha256": sha256_file(Path(__file__)),
    }
    (ROOT / "loss_monitor_results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if summary["runs_audited"] != 53 or summary["retrieval_completed"] != 53:
        raise SystemExit("Audit incomplete: expected 53 total runs including reused LockBit and four benign controls")
    if summary["quality_rejected_or_missing"] or summary["ebpf_loss_runs"] or summary["pcap_kernel_drop_runs"]:
        raise SystemExit("Audit found rejected quality, eBPF loss, or PCAP kernel drops; inspect loss_monitor_results.json")
    if issue_runs:
        raise SystemExit("Audit found validation issues; inspect loss_monitor_results.json")


if __name__ == "__main__":
    main()