from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import tarfile

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_sequences(capture_path, marker, sent):
    counts = Counter()
    frame_count = 0
    with RawPcapReader(str(capture_path)) as reader:
        for raw, _ in reader:
            frame_count += 1
            packet = Ether(raw)
            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                continue
            if packet[IP].dst != "239.255.42.198" or packet[UDP].dport != 65003:
                continue
            payload = bytes(packet[UDP].payload)
            if payload.startswith(marker) and len(payload) >= len(marker) + 8:
                sequence = struct.unpack("!Q", payload[len(marker):len(marker) + 8])[0]
                counts[sequence] += 1
    expected = set(range(sent))
    found = set(counts)
    return {
        "frame_count": frame_count,
        "sequence_ids_found": len(found),
        "missing_sequence_ids": len(expected - found),
        "duplicate_sequence_ids": sum(count - 1 for count in counts.values()),
        "unexpected_sequence_ids": len(found - expected),
    }


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


def validate_run(sample, manifest):
    sample_root = ROOT / manifest["output_directory"] / sample["name"]
    run_json, = (sample_root / "output").glob("run_*/run.json")
    run_dir = run_json.parent
    metadata = json.loads(run_json.read_text())
    diagnostics = json.loads((run_dir / "packet_capture_diagnostics.json").read_text())
    stdout = json.loads((run_dir / "sample.stdout.log").read_text())
    stats = metadata["packet_capture_statistics"]
    discrepancy = stats["packets_received_by_filter"] - stats["packets_captured"] - stats["dropped_by_kernel"]
    sequence = inspect_sequences(
        run_dir / "packet_capture.pcap",
        bytes.fromhex(stdout["sequence_marker_hex"]),
        stdout["packets_sent"],
    )
    spawn_event = next(
        event for event in diagnostics["lifecycle_events"]
        if event["event"] == "tcpdump_spawn_requested"
    )
    lifecycle = [event["event"] for event in diagnostics["lifecycle_events"]]
    pcap_file = diagnostics["pcap_file"]
    archive_count, archive_errors = archive_parity(sample_root)
    errors = []

    if metadata.get("malware_runner_sha256") != manifest["runner"]["sha256"]:
        errors.append("runner SHA-256 mismatch")
    if metadata.get("telemetry_schema_version") != manifest["runner"]["schema_version"]:
        errors.append("schema mismatch")
    if spawn_event.get("bpf_filter") != manifest["bpf_filter"]:
        errors.append("BPF filter mismatch")
    if metadata.get("timeout_seconds") != manifest["settings"]["timeout_seconds"]:
        errors.append("timeout mismatch")
    if discrepancy != metadata.get("packet_capture_counter_discrepancy"):
        errors.append("counter discrepancy metadata mismatch")
    if pcap_file.get("record_count") != stats["packets_captured"]:
        errors.append("PCAP record count differs from tcpdump captured count")
    if sequence["sequence_ids_found"] != stdout["packets_sent"]:
        errors.append("sequence coverage differs from sent packet count")
    if sequence["missing_sequence_ids"] or sequence["duplicate_sequence_ids"] or sequence["unexpected_sequence_ids"]:
        errors.append("sequence IDs missing, duplicated, or unexpected")
    if metadata.get("return_code") != 0:
        errors.append("probe process did not exit zero")
    if metadata.get("collection_quality_status") != "accepted" or discrepancy != 0:
        errors.append("filtered capture was not accepted with zero discrepancy")
    if stats["dropped_by_kernel"] != 0 or metadata.get("ebpf_lost_event_count") != 0:
        errors.append("reported sensor loss")
    if pcap_file.get("error") is not None:
        errors.append(f"PCAP parser error: {pcap_file['error']}")
    required_events = {"tcpdump_ready", "drain_completed", "sigint_sent", "tcpdump_process_exited"}
    if not required_events.issubset(set(lifecycle)):
        errors.append("required lifecycle events missing")
    if archive_count == 0 or archive_errors:
        errors.append("archive-to-host parity failed")

    return {
        "position": sample["position"],
        "name": sample["name"],
        "run_id": metadata.get("run_id"),
        "return_code": metadata.get("return_code"),
        "quality": metadata.get("collection_quality_status"),
        "quality_reasons": metadata.get("collection_quality_reasons", []),
        "packets_sent": stdout["packets_sent"],
        **sequence,
        "tcpdump_statistics": stats,
        "counter_discrepancy": discrepancy,
        "pcap_record_count_minus_captured": pcap_file.get("record_count_minus_tcpdump_captured"),
        "ebpf_lost_event_count": metadata.get("ebpf_lost_event_count"),
        "archive_regular_files_sha256_matched": archive_count,
        "archive_errors": archive_errors,
        "invariant_errors": errors,
    }


def main():
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    probe = (ROOT / manifest["sample"]["source"]).resolve()
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == manifest["scripts"]["batch_sha256"]
    assert sha256(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == manifest["scripts"]["staging_sha256"]
    assert sha256(probe) == manifest["sample"]["source_sha256"]
    assert sha256(ROOT / manifest["scripts"]["guest_setup"]) == manifest["scripts"]["guest_setup_sha256"]
    assert sha256(ROOT / manifest["sample"]["sample_list"]) == manifest["sample"]["sample_list_sha256"]

    results = [validate_run(sample, manifest) for sample in manifest["sample"]["ordered_copies"]]
    gaps = [result for result in results if result["counter_discrepancy"] != 0]
    report = {
        "run_id": manifest["run_id"],
        "schema_version": manifest["runner"]["schema_version"],
        "runner_sha256": manifest["runner"]["sha256"],
        "bpf_filter": manifest["bpf_filter"],
        "sample_count": len(results),
        "accepted_count": sum(result["quality"] == "accepted" for result in results),
        "discrepancy_run_count": len(gaps),
        "discrepancy_positions": [result["position"] for result in gaps],
        "discrepancy_total": sum(result["counter_discrepancy"] for result in results),
        "all_sequence_ids_present_once": all(
            result["sequence_ids_found"] == result["packets_sent"]
            and result["missing_sequence_ids"] == 0
            and result["duplicate_sequence_ids"] == 0
            and result["unexpected_sequence_ids"] == 0
            for result in results
        ),
        "invariant_failure_count": sum(bool(result["invariant_errors"]) for result in results),
        "interpretation_limit": "Twelve filtered repeats estimate recurrence for this synthetic workload; they do not identify the source of any counter gap or establish general packet capture completeness.",
        "results": results,
    }
    (ROOT / "filtered_repeat_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))
    print(json.dumps([{
        "position": result["position"],
        "run_id": result["run_id"],
        "received": result["tcpdump_statistics"]["packets_received_by_filter"],
        "captured": result["tcpdump_statistics"]["packets_captured"],
        "pcap_records": result["frame_count"],
        "quality": result["quality"],
        "invariant_errors": result["invariant_errors"],
    } for result in results], indent=2))
    return 0 if report["invariant_failure_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())