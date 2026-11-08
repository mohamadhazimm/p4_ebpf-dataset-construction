from collections import Counter, defaultdict
import csv
import hashlib
import ipaddress
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
from analyze_p4_pcap_ablation import P4_FEATURES, derive_p4_features

ENDPOINT_FEATURES = ("host_unique_ip_total", "host_unique_port_total",
                     "host_unique_remote_ips", "host_unique_remote_ports")


def read_csv(path):
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        return reader.fieldnames, list(reader)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive_hash_check(sample_root):
    regular_files = 0
    errors = []
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive.getmembers():
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                errors.append({"member": member.name, "error": "unsafe archive path"})
                continue
            if member.isdir():
                continue
            if not member.isfile():
                errors.append({"member": member.name, "error": "special archive member"})
                continue
            candidates = {path.resolve() for path in (sample_root / member.name,
                          sample_root / "output" / member.name)
                          if path.is_file() and path.resolve().is_relative_to(sample_root.resolve())}
            if len(candidates) != 1:
                errors.append({"member": member.name, "error": "host copy missing/ambiguous"})
                continue
            host_path, = candidates
            with archive.extractfile(member) as source:
                if hashlib.sha256(source.read()).hexdigest() != sha256(host_path):
                    errors.append({"member": member.name, "error": "SHA-256 mismatch"})
            regular_files += 1
    return regular_files, errors


def decoded_tls(capture):
    result = {}
    for name, display_filter in (("client", "tls.handshake.type == 1"),
                                 ("server", "tls.handshake.type == 2"),
                                 ("encrypted", "tls.app_data")):
        process = subprocess.run(
            ["tshark", "-r", str(capture), "-Y", display_filter, "-T", "fields",
             "-e", "tcp.stream", "-e", "tls.handshake.extensions_server_name"],
            capture_output=True, text=True, check=True,
        )
        rows = [line.split("\t") for line in process.stdout.splitlines()]
        result[name] = {row[0] for row in rows if row and row[0]}
        result[name + "_frames"] = len(rows)
        if name == "client":
            result["sni"] = sorted({row[1] for row in rows if len(row) > 1 and row[1]})
    result["verified_encrypted_streams"] = sorted(result["client"] & result["server"] & result["encrypted"])
    return {key: value for key, value in result.items() if not isinstance(value, set)}


def validate_case(sample, label, family, sample_root, manifest):
    metadata_path, = (sample_root / "output").glob("*/run.json")
    run = metadata_path.parent
    metadata = json.loads(metadata_path.read_text())
    fields, windows = read_csv(run / "telemetry.csv")
    feature_names = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
    checks = {
        "batch_retrieval_completed": "status=completed" in (sample_root / "host_run.txt").read_text(),
        "runner_provenance": metadata["telemetry_schema_version"] == manifest["runner_schema"]
            and metadata["malware_runner_sha256"] == manifest["runner_sha256"],
        "collection_settings": metadata["timeout_seconds"] == 8 and metadata["window_seconds"] == 0.5
            and metadata["observation_mode"] == "fixed" and metadata["common_launch_wrapper"],
        "telemetry_schema": len(windows) == 16 and len(fields) == 176 and len(feature_names) == 169
            and fields == metadata["telemetry_fields"],
        "finite_complete_features": all(row[name] not in (None, "") and math.isfinite(float(row[name]))
                                         for row in windows for name in feature_names),
        "sensors_active": metadata["ebpf_status"] == metadata["packet_capture_status"] == "active",
        "no_reported_pcap_loss": metadata["packet_capture_dropped_by_kernel"] == 0,
    }
    archive_files, archive_errors = archive_hash_check(sample_root)
    checks["archive_sha256_parity"] = archive_files > 0 and not archive_errors

    _, rebuilt, alignment = derive_p4_features(
        run / "packet_capture.pcap", windows, metadata,
        byte_layer="ethernet", rate_window="nominal",
    )
    p4_reconstruction_available = len(rebuilt) == len(windows)
    p4_mismatches = (
        [(index, name) for index, row in enumerate(windows) for name in P4_FEATURES
         if not math.isclose(float(row[name]), rebuilt[index][name], rel_tol=1e-9, abs_tol=1e-6)]
        if p4_reconstruction_available else []
    )
    checks["pcap_alignment_unique"] = alignment["alignment_status"] == "unique"
    checks["p4_reconstruction_available"] = p4_reconstruction_available
    checks["p4_cells_match"] = p4_reconstruction_available and not p4_mismatches

    _, ebpf_rows = read_csv(run / "ebpf_events.csv")
    _, raw_rows = read_csv(run / "syscall_events.csv")
    checks["event_metadata_counts"] = len(ebpf_rows) == metadata["ebpf_event_count"] \
        and len(raw_rows) == metadata["raw_syscall_event_count"]
    ebpf_by_window = Counter(int(row["window_id"]) for row in ebpf_rows)
    raw_by_window = Counter(int(row["window_id"]) for row in raw_rows)
    checks["event_feature_window_counts"] = all(
        float(row["ebpf_event_count"]) == ebpf_by_window[index]
        and float(row["host_total_syscalls_total"]) == raw_by_window[index]
        for index, row in enumerate(windows)
    )
    origin = metadata["sample_started_monotonic_ns"]
    checks["events_in_nominal_windows"] = all(
        int(row["window_id"]) == (int(row["timestamp_ns"]) - origin) // 500_000_000
        for row in ebpf_rows + raw_rows
    )

    valid_ipv4 = set()
    invalid_ipv4 = 0
    ipv4_by_window = defaultdict(list)
    connects = [row for row in ebpf_rows if row["event"] == "connect"]
    socket_families = Counter()
    for event in connects:
        details = dict(part.split("=", 1) for part in event["detail"].split() if "=" in part)
        try:
            family_number = int(details.get("family", 0))
        except ValueError:
            family_number = -1
        socket_families[str(family_number)] += 1
        if family_number != 2:
            continue
        try:
            address, port = int(details["addr"]), int(details["port"])
            if address == 0 or not 1 <= port <= 65535:
                invalid_ipv4 += 1
                continue
        except (KeyError, ValueError):
            invalid_ipv4 += 1
            continue
        valid_ipv4.add((str(ipaddress.IPv4Address(address)), port))
        ipv4_by_window[int(event["window_id"])].append((int(event["pid"]), address, port))

    endpoint_mismatches = []
    for window_id, row in enumerate(windows):
        event_rows = ipv4_by_window[window_id]
        ips_by_pid, ports_by_pid = defaultdict(set), defaultdict(set)
        for pid, address, port in event_rows:
            ips_by_pid[pid].add(address)
            ports_by_pid[pid].add(port)
        expected = (sum(map(len, ips_by_pid.values())), sum(map(len, ports_by_pid.values())),
                    len({address for _, address, _ in event_rows}),
                    len({port for _, _, port in event_rows}))
        endpoint_mismatches.extend((window_id, name, float(row[name]), value)
                                   for name, value in zip(ENDPOINT_FEATURES, expected)
                                   if float(row[name]) != value)
    checks["ipv4_endpoint_details_valid"] = invalid_ipv4 == 0
    checks["endpoint_features_reconcile"] = not endpoint_mismatches
    ebpf_log = (run / "ebpf_collector.log").read_text()
    loss_warnings = re.findall(r"\b(?:lost|dropped)\s+[1-9][0-9]*\b", ebpf_log, re.IGNORECASE)
    checks["no_reported_ebpf_loss"] = not loss_warnings

    return {
        "label": label, "family": family, "sample": sample,
        "run_directory": str(run.relative_to(ROOT)),
        "execution_status": metadata["status"], "return_code": metadata["return_code"],
        "checks": checks, "all_checks_pass": all(checks.values()),
        "windows": len(windows), "features": len(feature_names),
        "named_ebpf_rows": len(ebpf_rows), "raw_syscall_rows": len(raw_rows),
        "connect_events": len(connects), "socket_families": dict(socket_families),
        "ipv4_endpoints": sorted(valid_ipv4), "invalid_ipv4_event_count": invalid_ipv4,
        "endpoint_cells_reconciled": len(windows) * len(ENDPOINT_FEATURES) - len(endpoint_mismatches),
        "endpoint_mismatches": endpoint_mismatches,
        "archive_files_sha256_matched": archive_files, "archive_errors": archive_errors,
        "alignment": alignment,
        "p4_cells_compared": len(windows) * len(P4_FEATURES) if p4_reconstruction_available else 0,
        "p4_reconstruction_available": p4_reconstruction_available,
        "p4_mismatches": p4_mismatches, "pcap_drops": metadata["packet_capture_dropped_by_kernel"],
        "ebpf_loss_warning_count": len(loss_warnings), "tls": decoded_tls(run / "packet_capture.pcap"),
        "target_feature_zero_counts": {name: sum(float(row[name]) == 0 for row in windows)
                                        for name in manifest.get("target_zero_features", [])},
        "artifact_sha256": {name: sha256(run / name) for name in
                             ("run.json", "telemetry.csv", "ebpf_events.csv", "syscall_events.csv", "packet_capture.pcap")},
    }


if __name__ == "__main__":
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner_sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == manifest["batch_sha256"]
    assert sha256(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == manifest["staging_sha256"]
    assert sha256(STUDY / manifest["selection_source"]) == manifest["selection_source_sha256"]
    cases = []
    for item in manifest["malware"]["samples"]:
        cases.append(validate_case(item["artifact"], "malware", item["family"],
                                   ROOT / "runs/malware" / item["artifact"], manifest))
    for sample in manifest["benign"]["samples"]:
        cases.append(validate_case(sample, "benign", "benign control",
                                   ROOT / "runs/benign" / sample, manifest))
    group_zero = Counter()
    for case in cases:
        group_zero.update(name for name, count in case["target_feature_zero_counts"].items()
                          if count == case["windows"])
    report = {
        "run_id": manifest["run_id"], "case_count": len(cases),
        "malware_families_collected": len({case["family"] for case in cases if case["label"] == "malware"}),
        "checks_pass": all(case["all_checks_pass"] for case in cases),
        "cases": cases,
        "aggregate": {
            "execution_statuses": dict(Counter(case["execution_status"] for case in cases)),
            "return_codes": dict(Counter(str(case["return_code"]) for case in cases)),
            "archive_members_hash_matched": sum(case["archive_files_sha256_matched"] for case in cases),
            "p4_cells_compared": sum(case["p4_cells_compared"] for case in cases),
            "p4_mismatches": sum(len(case["p4_mismatches"]) for case in cases),
            "endpoint_cells_reconciled": sum(case["endpoint_cells_reconciled"] for case in cases),
            "endpoint_mismatches": sum(len(case["endpoint_mismatches"]) for case in cases),
            "named_ebpf_rows": sum(case["named_ebpf_rows"] for case in cases),
            "raw_syscall_rows": sum(case["raw_syscall_rows"] for case in cases),
            "connect_events": sum(case["connect_events"] for case in cases),
            "pcap_drops": dict(Counter(str(case["pcap_drops"]) for case in cases)),
            "ebpf_loss_warnings": sum(case["ebpf_loss_warning_count"] for case in cases),
        },
        "limitations": ["One purposively selected artifact per family; not classifier or prevalence evidence.",
                        "Eight-second capture is a sensor/retrieval smoke only.",
                        "Connect events are attempts, not success counts; IP traffic is not necessarily sample-attributed.",
                        "A process timeout at the observation cap is distinct from collection/retrieval failure.",
                        "Zero warnings/drops do not prove no unreported eBPF loss.",
                        "Old v1/v3 outputs and paused collection remain separate from schema v4."],
    }
    (ROOT / "family_smoke_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"case_count": report["case_count"],
                      "malware_families": report["malware_families_collected"],
                      "checks_pass": report["checks_pass"],
                      "aggregate": report["aggregate"],
                      "case_outcomes": [{"label": c["label"], "family": c["family"],
                                         "status": c["execution_status"], "return_code": c["return_code"],
                                         "ipv4_endpoints": c["ipv4_endpoints"],
                                         "checks_pass": c["all_checks_pass"]} for c in cases]}, indent=2))
    raise SystemExit(0 if report["checks_pass"] else 1)