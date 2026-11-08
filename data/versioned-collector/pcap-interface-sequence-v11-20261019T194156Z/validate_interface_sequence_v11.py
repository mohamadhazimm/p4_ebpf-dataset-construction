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
PROBE = ROOT.parent / "pcap-interface-sequence-v10-20261019T193900Z/interface_sequence_probe.sh"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
            relative_path = Path(*[part for part in relative.parts if part not in ("", ".")])
            host_path = sample_root / "output" / relative_path
            if not host_path.is_file() or not host_path.resolve().is_relative_to(sample_root.resolve()):
                errors.append(f"missing or escaping extracted file: {member.name}")
                continue
            archived = archive.extractfile(member)
            if archived is None or hashlib.sha256(archived.read()).hexdigest() != sha256(host_path):
                errors.append(f"archive hash mismatch: {member.name}")
                continue
            matched += 1
    return matched, errors


def main():
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    assert sha256(PROBE) == manifest["scripts"]["probe_sha256"]
    sample_root = ROOT / manifest["output_directory"] / manifest["sample"]["name"]
    run_json, = (sample_root / "output").glob("run_*/run.json")
    run_dir = run_json.parent
    metadata = json.loads(run_json.read_text())
    stdout = json.loads((run_dir / "sample.stdout.log").read_text())
    packet_stats = metadata["packet_capture_statistics"]

    with (run_dir / "syscall_events.csv").open(newline="") as source:
        syscall_rows = list(csv.DictReader(source))
    with (run_dir / "telemetry.csv").open(newline="") as source:
        telemetry = list(csv.DictReader(source))

    marker = bytes.fromhex(stdout["sequence_marker_hex"])
    sequence_counts = Counter()
    frame_count = 0
    with RawPcapReader(str(run_dir / "packet_capture.pcap")) as reader:
        for raw, _ in reader:
            frame_count += 1
            packet = Ether(raw)
            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                continue
            if packet[IP].dst != "239.255.42.198" or packet[UDP].dport != 65003:
                continue
            payload = bytes(packet[UDP].payload)
            if payload.startswith(marker) and len(payload) >= len(marker) + 8:
                number = struct.unpack("!Q", payload[len(marker):len(marker) + 8])[0]
                sequence_counts[number] += 1

    expected = set(range(stdout["packets_sent"]))
    found = set(sequence_counts)
    discrepancy = (packet_stats["packets_received_by_filter"]
                   - packet_stats["packets_captured"] - packet_stats["dropped_by_kernel"])
    log = (run_dir / "packet_capture.log").read_text(errors="replace")
    stats_patterns = {
        "packets_captured": r"^\s*(\d+)\s+packets captured\b",
        "packets_received_by_filter": r"^\s*(\d+)\s+packets received by filter\b",
        "dropped_by_kernel": r"^\s*(\d+)\s+packets dropped by kernel\b",
    }
    log_stats = {}
    for key, pattern in stats_patterns.items():
        match = re.search(pattern, log, re.MULTILINE | re.IGNORECASE)
        assert match
        log_stats[key] = int(match.group(1))

    lost_log = (run_dir / "ebpf_collector.log").read_text(errors="replace")
    lost_events = sum(int(value) for value in re.findall(r"\bLost\s+(\d+)\s+events\b", lost_log, re.I))
    interface_delta = metadata["packet_capture_interface_counter_deltas"]
    assert "status=completed" in (sample_root / "host_run.txt").read_text()
    assert metadata["telemetry_schema_version"] == manifest["runner"]["schema_version"]
    assert metadata["malware_runner_sha256"] == manifest["runner"]["sha256"]
    assert metadata["packet_capture_drain_ms"] == 1000
    assert metadata["status"] == "completed" and metadata["return_code"] == 0
    assert stdout["packets_sent"] == stdout["stat_calls"] == 50000
    assert found == expected and sum(n - 1 for n in sequence_counts.values()) == 0
    assert frame_count == packet_stats["packets_captured"]
    assert log_stats == packet_stats
    assert metadata["packet_capture_counter_discrepancy"] == discrepancy == 0
    assert metadata["packet_capture_dropped_by_kernel"] == packet_stats["dropped_by_kernel"] == 0
    assert metadata["ebpf_lost_event_count"] == lost_events == 0
    assert metadata["collection_quality_status"] == "accepted"
    assert interface_delta == {
        "rx_packets": 27, "rx_bytes": 3215, "rx_dropped": 0,
        "tx_packets": 50035, "tx_bytes": 4502991, "tx_dropped": 0,
    }
    assert len(telemetry) == 16 and len(syscall_rows) == metadata["raw_syscall_event_count"]

    archive_members, archive_errors = archive_parity(sample_root)
    assert archive_members == 10 and not archive_errors
    result = {
        "run_id": manifest["run_id"],
        "sample_run_id": metadata["run_id"],
        "schema": metadata["telemetry_schema_version"],
        "runner_sha256": metadata["malware_runner_sha256"],
        "drain_ms": metadata["packet_capture_drain_ms"],
        "probe_packets_sent": stdout["packets_sent"],
        "sequence_ids_captured": len(found),
        "missing_sequence_ids": 0,
        "duplicate_sequence_ids": 0,
        "pcap_frames": frame_count,
        "tcpdump_statistics": packet_stats,
        "counter_discrepancy": discrepancy,
        "ebpf_lost_events": metadata["ebpf_lost_event_count"],
        "quality": metadata["collection_quality_status"],
        "interface_counter_deltas": interface_delta,
        "pcap_minus_interface_rx_tx_packets": frame_count - interface_delta["rx_packets"] - interface_delta["tx_packets"],
        "telemetry_windows": len(telemetry),
        "raw_syscall_rows": len(syscall_rows),
        "archive_regular_files_sha256_matched": archive_members,
        "archive_errors": archive_errors,
        "artifact_sha256": {
            name: sha256(run_dir / name) for name in
            ("run.json", "telemetry.csv", "syscall_events.csv", "ebpf_events.csv", "packet_capture.pcap")
        },
        "limits": ["One clean run does not resolve nonmonotonic gaps in prior repeats.",
                   "Guest lacks dumpcap/tshark; interface counters are not an independent capture backend."],
    }
    (ROOT / "interface_sequence_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in (
        "sample_run_id", "drain_ms", "probe_packets_sent", "sequence_ids_captured",
        "missing_sequence_ids", "duplicate_sequence_ids", "pcap_frames",
        "counter_discrepancy", "ebpf_lost_events", "quality", "interface_counter_deltas",
        "pcap_minus_interface_rx_tx_packets",
        "archive_regular_files_sha256_matched")}, indent=2))


if __name__ == "__main__":
    main()