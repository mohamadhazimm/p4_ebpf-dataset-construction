import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile
from collections import Counter

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
MAGIC = bytes.fromhex("48415a494d534551")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_archive(sample_root):
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
            path = Path(*[part for part in relative.parts if part not in ("", ".")])
            host = sample_root / "output" / path
            if not host.is_file() or not host.resolve().is_relative_to(sample_root.resolve()):
                errors.append(f"missing or escaping extracted file: {member.name}")
                continue
            archived = archive.extractfile(member)
            if archived is None or hashlib.sha256(archived.read()).hexdigest() != sha256(host):
                errors.append(f"archive hash mismatch: {member.name}")
                continue
            matched += 1
    return matched, errors


def main():
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256(STUDY / "scripts/vbox_malware_batch.sh") == manifest["scripts"]["batch_sha256"]
    assert sha256(STUDY / "scripts/stage_versioned_runner_snapshot.sh") == manifest["scripts"]["staging_sha256"]
    probe = ROOT / "sequence_packet_probe.sh"
    assert sha256(probe) == manifest["scripts"]["probe_sha256"]

    sample_root = ROOT / manifest["output_directory"] / manifest["sample"]["name"]
    host_lines = (sample_root / "host_run.txt").read_text().splitlines()
    run_json, = (sample_root / "output").glob("run_*/run.json")
    run_dir = run_json.parent
    metadata = json.loads(run_json.read_text())
    stdout = json.loads((run_dir / "sample.stdout.log").read_text())
    packet_stats = metadata["packet_capture_statistics"]
    expected = set(range(stdout["packets_sent"]))
    sequence_counts = Counter()
    pcap_frames = 0
    udp_to_target_without_marker = 0

    with RawPcapReader(str(run_dir / "packet_capture.pcap")) as reader:
        for raw, _ in reader:
            pcap_frames += 1
            packet = Ether(raw)
            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                continue
            if packet[IP].dst != "239.255.42.198" or packet[UDP].dport != 65003:
                continue
            payload = bytes(packet[UDP].payload)
            if payload.startswith(MAGIC) and len(payload) >= len(MAGIC) + 8:
                sequence = struct.unpack("!Q", payload[len(MAGIC):len(MAGIC) + 8])[0]
                sequence_counts[sequence] += 1
            else:
                udp_to_target_without_marker += 1

    found = set(sequence_counts)
    missing = sorted(expected - found)
    unexpected = sorted(found - expected)
    duplicate_count = sum(count - 1 for count in sequence_counts.values() if count > 1)
    counter_discrepancy = (
        packet_stats["packets_received_by_filter"]
        - packet_stats["packets_captured"]
        - packet_stats["dropped_by_kernel"]
    )
    log_text = (run_dir / "ebpf_collector.log").read_text(errors="replace")
    log_lost = sum(int(value) for value in re.findall(r"\bLost\s+(\d+)\s+events\b", log_text, re.I))

    assert "status=completed" in host_lines
    assert metadata["telemetry_schema_version"] == manifest["runner"]["schema_version"]
    assert metadata["malware_runner_sha256"] == manifest["runner"]["sha256"]
    assert metadata["packet_capture_drain_ms"] == 1000
    assert metadata["status"] == "completed" and metadata["return_code"] == 0
    assert stdout["packets_sent"] == 50000 and stdout["stat_calls"] == 50000
    assert len(found) == stdout["packets_sent"] and not missing and not unexpected and duplicate_count == 0
    assert pcap_frames == packet_stats["packets_captured"]
    assert metadata["packet_capture_counter_discrepancy"] == counter_discrepancy == 38
    assert metadata["packet_capture_dropped_by_kernel"] == packet_stats["dropped_by_kernel"] == 0
    assert metadata["ebpf_lost_event_count"] == log_lost == 0
    assert metadata["collection_quality_status"] == "rejected"
    assert "packet_capture_counter_discrepancy:38" in metadata["collection_quality_reasons"]

    with (run_dir / "telemetry.csv").open(newline="") as source:
        telemetry = list(csv.DictReader(source))
    assert len(telemetry) == 16
    archive_members, archive_errors = check_archive(sample_root)
    assert archive_members > 0 and not archive_errors
    result = {
        "run_id": manifest["run_id"],
        "sample_run_id": metadata["run_id"],
        "schema": metadata["telemetry_schema_version"],
        "runner_sha256": metadata["malware_runner_sha256"],
        "drain_ms": metadata["packet_capture_drain_ms"],
        "probe": stdout,
        "sequence_ids_expected": len(expected),
        "sequence_ids_captured": len(found),
        "missing_sequence_ids": missing,
        "unexpected_sequence_ids": unexpected,
        "duplicate_sequence_count": duplicate_count,
        "udp_to_target_without_marker": udp_to_target_without_marker,
        "pcap_frames": pcap_frames,
        "packet_capture_statistics": packet_stats,
        "packet_capture_counter_discrepancy": counter_discrepancy,
        "ebpf_lost_events": metadata["ebpf_lost_event_count"],
        "quality": metadata["collection_quality_status"],
        "telemetry_windows": len(telemetry),
        "archive_regular_files_sha256_matched": archive_members,
        "archive_errors": archive_errors,
        "artifact_sha256": {
            name: sha256(run_dir / name)
            for name in ("run.json", "telemetry.csv", "syscall_events.csv", "ebpf_events.csv", "packet_capture.pcap")
        },
        "interpretation": "All 50,000 sequence-marked workload datagrams are in the PCAP; the separate tcpdump counter gap remains unresolved and the run is correctly rejected.",
    }
    (ROOT / "sequence_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in (
        "sample_run_id", "drain_ms", "sequence_ids_expected", "sequence_ids_captured",
        "missing_sequence_ids", "duplicate_sequence_count", "pcap_frames",
        "packet_capture_counter_discrepancy", "ebpf_lost_events", "quality",
        "archive_regular_files_sha256_matched",
    )}, indent=2))


if __name__ == "__main__":
    main()