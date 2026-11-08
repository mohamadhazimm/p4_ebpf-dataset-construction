import argparse
import csv
from collections import Counter
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY_ROOT = ROOT.parents[2]
CAPTURE_STATS = {
    "packets_captured": r"^\s*(\d+)\s+packets captured\b",
    "packets_received_by_filter": r"^\s*(\d+)\s+packets received by filter\b",
    "dropped_by_kernel": r"^\s*(\d+)\s+packets dropped by kernel\b",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition, message, errors):
    if not condition:
        errors.append(message)


def parse_capture_stats(path, errors):
    text = path.read_text(errors="replace")
    result = {}
    for name, pattern in CAPTURE_STATS.items():
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match is None:
            errors.append(f"missing tcpdump statistic {name}: {path}")
        else:
            result[name] = int(match.group(1))
    return result


def validate_archive(sample_root, errors):
    archive_path = sample_root / "output.tgz"
    matched = 0
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive.getmembers():
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    errors.append(f"unsafe archive path: {member.name}")
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    errors.append(f"special archive member: {member.name}")
                    continue
                relative = Path(*[part for part in member_path.parts if part not in ("", ".")])
                extracted = sample_root / "output" / relative
                if not extracted.is_file() or not extracted.resolve().is_relative_to(sample_root.resolve()):
                    errors.append(f"missing or escaping extracted member: {member.name}")
                    continue
                archived = archive.extractfile(member)
                if archived is None or hashlib.sha256(archived.read()).hexdigest() != sha256(extracted):
                    errors.append(f"archive hash mismatch: {member.name}")
                    continue
                matched += 1
    except (OSError, tarfile.TarError) as error:
        errors.append(f"cannot inspect archive {archive_path}: {error}")
    check(matched > 0, f"no regular archive members verified: {archive_path}", errors)
    return matched


def validate_sample(root, manifest, name):
    errors = []
    sample_root = root / manifest["planned_runs"]["output_directory"] / name
    host_log = sample_root / "host_run.txt"
    if not host_log.is_file():
        return {"sample": name, "errors": ["host_run.txt is missing"]}
    host_text = host_log.read_text(errors="replace")
    check("status=completed" in host_text, "batch retrieval was not completed", errors)

    run_json_files = sorted((sample_root / "output").glob("run_*/run.json"))
    check(len(run_json_files) == 1, f"expected one run.json, found {len(run_json_files)}", errors)
    if len(run_json_files) != 1:
        return {"sample": name, "errors": errors}

    run_dir = run_json_files[0].parent
    try:
        metadata = json.loads(run_json_files[0].read_text())
        diagnostics = json.loads((run_dir / "packet_capture_diagnostics.json").read_text())
    except (OSError, json.JSONDecodeError) as error:
        return {"sample": name, "errors": [f"cannot read run metadata: {error}"]}

    settings = manifest["settings"]
    expected_runner = manifest["runner"]
    check(metadata.get("status") == "completed", "sample runner status is not completed", errors)
    check(metadata.get("telemetry_schema_version") == expected_runner["schema_version"], "schema mismatch", errors)
    check(metadata.get("malware_runner_sha256") == expected_runner["sha256"], "runner hash mismatch", errors)
    check(metadata.get("packet_capture_buffer_kb_requested") == settings["packet_capture_buffer_kb"], "buffer size mismatch", errors)
    check(metadata.get("packet_capture_immediate_mode") is True, "immediate mode not recorded", errors)
    check(metadata.get("packet_capture_drain_ms") == settings["packet_capture_drain_ms"], "drain setting mismatch", errors)
    check(metadata.get("collection_quality_status") == "accepted", f"collection quality={metadata.get('collection_quality_status')}", errors)
    check(metadata.get("packet_capture_status") == "active", "PCAP sensor was not active", errors)
    check(metadata.get("ebpf_status") == "active", "eBPF sensor was not active", errors)

    statistics = metadata.get("packet_capture_statistics") or {}
    received = statistics.get("packets_received_by_filter")
    captured = statistics.get("packets_captured")
    kernel_drops = statistics.get("dropped_by_kernel")
    discrepancy = None
    if all(isinstance(value, int) for value in (received, captured, kernel_drops)):
        discrepancy = received - captured - kernel_drops
    check(discrepancy == 0, f"packet counter discrepancy={discrepancy}", errors)
    check(metadata.get("packet_capture_counter_discrepancy") == discrepancy, "recorded counter discrepancy mismatch", errors)
    check(metadata.get("packet_capture_dropped_by_kernel") == kernel_drops == 0, f"kernel drops={kernel_drops}", errors)
    logged_statistics = parse_capture_stats(run_dir / "packet_capture.log", errors)
    check(logged_statistics == statistics, "tcpdump log and run.json counters differ", errors)

    pcap_info = diagnostics.get("pcap_file") or {}
    pcap_records = pcap_info.get("record_count")
    check(pcap_records == captured, f"PCAP record count {pcap_records} != captured {captured}", errors)
    check(metadata.get("ebpf_lost_event_count") == 0, f"eBPF lost event count={metadata.get('ebpf_lost_event_count')}", errors)
    ebpf_log = run_dir / "ebpf_collector.log"
    lost_count = sum(int(value) for value in re.findall(r"\bLost\s+(\d+)\s+events\b", ebpf_log.read_text(errors="replace"), re.IGNORECASE))
    check(lost_count == 0, f"eBPF log reports {lost_count} lost events", errors)

    rmem_before = metadata.get("packet_capture_rmem_max_before")
    rmem_during = metadata.get("packet_capture_rmem_max_during_capture")
    rmem_after = metadata.get("packet_capture_rmem_max_after_capture")
    check(isinstance(rmem_during, int) and rmem_during >= settings["packet_capture_buffer_kb"] * 2048, "rmem_max below 2x buffer", errors)
    check(rmem_after == rmem_before, f"rmem_max not restored ({rmem_before} -> {rmem_after})", errors)
    interface_drops = metadata.get("packet_capture_interface_counter_deltas") or {}
    check(interface_drops.get("rx_dropped") == 0 and interface_drops.get("tx_dropped") == 0, "interface reports drops", errors)

    groups = metadata.get("telemetry_feature_groups") or {}
    feature_names = [field for fields in groups.values() for field in fields] if isinstance(groups, dict) else []
    check(len(feature_names) == expected_runner["feature_count"], f"declared feature count={len(feature_names)}", errors)
    telemetry_path = run_dir / "telemetry.csv"
    rows = []
    try:
        with telemetry_path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            rows = list(reader)
            columns = set(reader.fieldnames or [])
        window_count = metadata.get("windows")
        check(len(rows) == window_count == 40, f"telemetry rows/windows={len(rows)}/{window_count}", errors)
        check(set(feature_names) <= columns, "telemetry is missing declared features", errors)
        for row_index, row in enumerate(rows):
            for field in feature_names:
                try:
                    value = float(row[field])
                except (KeyError, TypeError, ValueError):
                    errors.append(f"non-numeric telemetry value at row {row_index + 1}, field {field}")
                    continue
                if not math.isfinite(value):
                    errors.append(f"non-finite telemetry value at row {row_index + 1}, field {field}")
    except OSError as error:
        errors.append(f"cannot read telemetry.csv: {error}")

    archive_members = validate_archive(sample_root, errors)
    return {
        "sample": name,
        "run_id": metadata.get("run_id"),
        "retrieval_status": "completed" if "status=completed" in host_text else "failed",
        "process_status": metadata.get("status"),
        "process_return_code": metadata.get("return_code"),
        "quality": metadata.get("collection_quality_status"),
        "received": received,
        "captured": captured,
        "kernel_drops": kernel_drops,
        "counter_discrepancy": discrepancy,
        "pcap_records": pcap_records,
        "ebpf_lost_events": metadata.get("ebpf_lost_event_count"),
        "telemetry_rows": len(rows),
        "feature_count": len(feature_names),
        "rmem_max_before": rmem_before,
        "rmem_max_during": rmem_during,
        "rmem_max_after": rmem_after,
        "archive_regular_files_hash_matched": archive_members,
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = json.loads((root / "experiment_manifest.json").read_text())
    errors = []
    runner = manifest["runner"]
    for relative, expected in (
        ("src/malware_runner.py", runner["sha256"]),
        (manifest["scripts"]["batch_path"], manifest["scripts"]["batch_sha256"]),
        (manifest["scripts"]["staging_path"], manifest["scripts"]["staging_sha256"]),
    ):
        check(sha256(STUDY_ROOT / relative) == expected, f"frozen source hash mismatch: {relative}", errors)
    sample_manifest = root / manifest["sample_manifest"]["path"]
    check(sha256(sample_manifest) == manifest["sample_manifest"]["sha256"], "sample manifest hash mismatch", errors)
    parent_manifest = STUDY_ROOT / manifest["parent_experiment"]["cohort_manifest"]
    check(sha256(parent_manifest) == manifest["parent_experiment"]["cohort_manifest_sha256"], "parent cohort manifest hash mismatch", errors)
    source_root = STUDY_ROOT / manifest["sample_manifest"]["source_directory"]
    for item in manifest["sample_manifest"]["source_files"]:
        check(sha256(source_root / item["name"]) == item["sha256"], f"source sample hash mismatch: {item['name']}", errors)

    names = [line for line in sample_manifest.read_text().splitlines() if line]
    check(names == [item["name"] for item in manifest["sample_manifest"]["source_files"]], "sample list differs from frozen source list", errors)
    results = [validate_sample(root, manifest, name) for name in names]
    errors.extend(f"{result['sample']}: {error}" for result in results for error in result["errors"])
    outcomes = Counter(str(result["process_return_code"]) for result in results)
    report = {
        "run_id": manifest["run_id"],
        "schema_version": runner["schema_version"],
        "runner_sha256": runner["sha256"],
        "sample_count": len(results),
        "process_return_code_counts": dict(outcomes),
        "samples": results,
        "errors": errors,
        "accepted": not errors and len(results) == manifest["planned_runs"]["expected_sample_count"],
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.write_report:
        (root / "pilot23_results.json").write_text(rendered)
    print(rendered, end="")
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
