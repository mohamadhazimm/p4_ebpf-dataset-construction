import argparse
import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import tarfile


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path):
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        return reader.fieldnames, list(reader)


def archive_parity(sample_root):
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
            candidates = {
                path.resolve()
                for path in (sample_root / member.name, sample_root / "output" / member.name)
                if path.is_file() and path.resolve().is_relative_to(sample_root.resolve())
            }
            if len(candidates) != 1:
                errors.append(f"missing or ambiguous archive member: {member.name}")
                continue
            host_path, = candidates
            archived = archive.extractfile(member)
            if archived is None or hashlib.sha256(archived.read()).hexdigest() != sha256(host_path):
                errors.append(f"archive SHA-256 mismatch: {member.name}")
                continue
            matched += 1
    return matched, errors


def inspect_case(sample_root, expected_sample, manifest):
    result = {
        "sample": expected_sample,
        "retrieval_completed": False,
        "process_status": None,
        "return_code": None,
        "quality": None,
        "quality_reasons": [],
        "errors": [],
    }
    host_run = sample_root / "host_run.txt"
    if not host_run.is_file():
        result["errors"].append("host_run.txt missing")
        return result
    result["retrieval_completed"] = "status=completed" in host_run.read_text(errors="replace")
    run_json_paths = sorted((sample_root / "output").glob("run_*/run.json"))
    if len(run_json_paths) != 1:
        result["errors"].append(f"expected exactly one run.json, found {len(run_json_paths)}")
        return result

    run_json = run_json_paths[0]
    run_dir = run_json.parent
    metadata = json.loads(run_json.read_text())
    diag_path = run_dir / "packet_capture_diagnostics.json"
    if not diag_path.is_file():
        result["errors"].append("packet_capture_diagnostics.json missing")
        return result
    diagnostics = json.loads(diag_path.read_text())
    result.update({
        "run_id": metadata.get("run_id"),
        "process_status": metadata.get("status"),
        "return_code": metadata.get("return_code"),
        "quality": metadata.get("collection_quality_status"),
        "quality_reasons": metadata.get("collection_quality_reasons", []),
        "run_directory": str(run_dir.relative_to(ROOT)),
    })

    if not result["retrieval_completed"]:
        result["errors"].append("retrieval incomplete")
    if metadata.get("telemetry_schema_version") != manifest["runner"]["schema_version"]:
        result["errors"].append("telemetry schema mismatch")
    if metadata.get("malware_runner_sha256") != manifest["runner"]["sha256"]:
        result["errors"].append("runner SHA-256 mismatch")
    if metadata.get("timeout_seconds") != manifest["settings"]["timeout_seconds"]:
        result["errors"].append("timeout mismatch")
    if metadata.get("window_seconds") != manifest["settings"]["window_seconds"]:
        result["errors"].append("window size mismatch")
    if metadata.get("observation_mode") != "fixed" or not metadata.get("common_launch_wrapper"):
        result["errors"].append("observation or launch mode mismatch")

    fields, windows = read_csv(run_dir / "telemetry.csv")
    feature_groups = metadata.get("telemetry_feature_groups", {})
    features = [name for group in feature_groups.values() for name in group]
    if len(windows) != 40 or len(fields) != 178 or fields != metadata.get("telemetry_fields"):
        result["errors"].append("telemetry shape/schema mismatch")
    if len(features) != manifest["runner"]["feature_count"]:
        result["errors"].append("declared feature count mismatch")
    try:
        finite = all(row.get(name) not in (None, "") and math.isfinite(float(row[name]))
                     for row in windows for name in features)
    except (TypeError, ValueError):
        finite = False
    if not finite:
        result["errors"].append("missing or non-finite feature value")

    stats = metadata.get("packet_capture_statistics", {})
    received = stats.get("packets_received_by_filter")
    captured = stats.get("packets_captured")
    dropped = stats.get("dropped_by_kernel")
    discrepancy = received - captured - dropped if all(
        isinstance(value, int) for value in (received, captured, dropped)
    ) else None
    pcap_file = diagnostics.get("pcap_file", {})
    pcap_records = pcap_file.get("record_count")
    result.update({
        "packets_received_by_filter": received,
        "packets_captured": captured,
        "dropped_by_kernel": dropped,
        "counter_discrepancy": discrepancy,
        "pcap_records": pcap_records,
        "pcap_records_minus_captured": pcap_file.get("record_count_minus_tcpdump_captured"),
        "ebpf_lost_events": metadata.get("ebpf_lost_event_count"),
        "telemetry_windows": len(windows),
        "features": len(features),
    })
    if discrepancy is None or metadata.get("packet_capture_counter_discrepancy") != discrepancy:
        result["errors"].append("packet discrepancy unavailable or metadata mismatch")
    if discrepancy is None or discrepancy != 0:
        result["errors"].append("nonzero packet counter discrepancy")
    if dropped != 0:
        result["errors"].append("reported kernel packet drops")
    if pcap_file.get("error") is not None or pcap_records != captured:
        result["errors"].append("PCAP record count mismatch/unavailable")
    if result["quality"] != "accepted" or result["quality_reasons"]:
        result["errors"].append("collection quality not accepted")
    if metadata.get("ebpf_lost_event_count") != 0:
        result["errors"].append("eBPF loss reported/unavailable")
    if manifest["settings"]["bpf_filter"] is None:
        spawn_event = next((event for event in diagnostics.get("lifecycle_events", [])
                            if event.get("event") == "tcpdump_spawn_requested"), None)
        if spawn_event is None or spawn_event.get("bpf_filter") is not None:
            result["errors"].append("unexpected packet capture filter")

    archive_count, archive_errors = archive_parity(sample_root)
    result["archive_regular_files_sha256_matched"] = archive_count
    result["archive_errors"] = archive_errors
    if archive_count == 0 or archive_errors:
        result["errors"].append("archive member hash parity failed")
    result["artifact_sha256"] = {
        name: sha256(run_dir / name)
        for name in ("run.json", "telemetry.csv", "ebpf_events.csv", "syscall_events.csv",
                     "packet_capture.pcap", "packet_capture_diagnostics.json")
    }
    result["gate_pass"] = not result["errors"]
    return result


def wave_cases(manifest, selection, wave_number):
    wave_settings = manifest["waves"][wave_number - 1]
    wave_selection = selection["waves"][wave_number - 1]
    cases = []
    for round_number in range(1, 6):
        chunk = wave_selection["samples"][(round_number - 1) * 10:round_number * 10]
        for sample in chunk:
            sample_root = (ROOT / wave_settings["output_directory"] / "malware"
                           / f"round-{round_number:02d}" / sample["artifact"])
            cases.append(("malware", sample["artifact"], sample_root))
    for profile in wave_settings["benign_profiles"]:
        for tool in manifest["benign_tools"]:
            sample_root = ROOT / wave_settings["output_directory"] / "benign" / profile / tool
            cases.append(("benign", f"{tool}@{profile}", sample_root))
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wave", type=int, choices=(1, 2), required=True)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    selection = json.loads((ROOT / "selection.json").read_text())
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == manifest["scripts"]["batch_sha256"]
    assert sha256(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == manifest["scripts"]["staging_sha256"]
    expected_wave = selection["waves"][args.wave - 1]
    results = []
    for label, sample, sample_root in wave_cases(manifest, selection, args.wave):
        results.append({"label": label, **inspect_case(sample_root, sample, manifest)})
    report = {
        "run_id": manifest["run_id"],
        "wave": args.wave,
        "expected_counts": {"malware": 50, "benign_runs": 50},
        "malware_family_count": len(expected_wave["families"]),
        "retrieval_completed": sum(item.get("retrieval_completed", False) for item in results),
        "quality_accepted": sum(item.get("quality") == "accepted" for item in results),
        "quality_rejected": sum(item.get("quality") == "rejected" for item in results),
        "discrepancy_runs": sum(item.get("counter_discrepancy") not in (None, 0) for item in results),
        "discrepancy_total": sum(item.get("counter_discrepancy") or 0 for item in results),
        "kernel_drop_runs": sum((item.get("dropped_by_kernel") or 0) > 0 for item in results),
        "ebpf_loss_runs": sum((item.get("ebpf_lost_events") or 0) > 0 for item in results),
        "gate_pass": len(results) == 100 and all(item.get("gate_pass", False) for item in results),
        "results": results,
    }
    report_path = ROOT / f"wave-{args.wave}-qa.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))
    return 0 if report["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())