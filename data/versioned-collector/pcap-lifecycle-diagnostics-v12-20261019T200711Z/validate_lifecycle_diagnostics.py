import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
import tarfile
from collections import Counter

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]


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


def inspect_sequences(pcap_path, marker, destination, port, packets_sent):
    sequence_counts = Counter()
    frame_count = 0
    with RawPcapReader(str(pcap_path)) as reader:
        for raw, _ in reader:
            frame_count += 1
            packet = Ether(raw)
            if not packet.haslayer(IP) or not packet.haslayer(UDP):
                continue
            if packet[IP].dst != destination or packet[UDP].dport != port:
                continue
            payload = bytes(packet[UDP].payload)
            if payload.startswith(marker) and len(payload) >= len(marker) + 8:
                number = struct.unpack("!Q", payload[len(marker):len(marker) + 8])[0]
                sequence_counts[number] += 1
    expected = set(range(packets_sent))
    found = set(sequence_counts)
    return {
        "frame_count": frame_count,
        "sequence_ids_found": len(found),
        "missing_sequence_ids": len(expected - found),
        "duplicate_sequence_ids": sum(count - 1 for count in sequence_counts.values()),
        "unexpected_sequence_ids": len(found - expected),
    }


def main():
    manifest = json.loads((ROOT / "experiment_manifest.json").read_text())
    assert sha256(STUDY / "src/malware_runner.py") == manifest["runner"]["sha256"]
    probe = (ROOT / manifest["sample"]["source"]).resolve()
    assert sha256(probe) == manifest["scripts"]["probe_sha256"]

    results = []
    for repetition in manifest["repetitions"]:
        sample_root = ROOT / repetition["output_directory"] / manifest["sample"]["name"]
        run_json, = (sample_root / "output").glob("run_*/run.json")
        run_dir = run_json.parent
        metadata = json.loads(run_json.read_text())
        diagnostics = json.loads((run_dir / "packet_capture_diagnostics.json").read_text())
        stdout = json.loads((run_dir / "sample.stdout.log").read_text())
        stats = metadata["packet_capture_statistics"]
        pcap = run_dir / "packet_capture.pcap"
        marker = bytes.fromhex(stdout["sequence_marker_hex"])
        sequence = inspect_sequences(
            pcap,
            marker,
            "239.255.42.198",
            65003,
            stdout["packets_sent"],
        )
        discrepancy = stats["packets_received_by_filter"] - stats["packets_captured"] - stats["dropped_by_kernel"]
        lifecycle = diagnostics["lifecycle_events"]
        event_names = [event["event"] for event in lifecycle]
        monotonic_times = [event["monotonic_ns"] for event in lifecycle]
        captured_event = next(
            event["monotonic_ns"] for event in diagnostics["stderr_events"]
            if "packets captured" in event["line"].lower()
        )
        received_event = next(
            event["monotonic_ns"] for event in diagnostics["stderr_events"]
            if "packets received by filter" in event["line"].lower()
        )
        archive_members, archive_errors = archive_parity(sample_root)

        assert metadata["telemetry_schema_version"] == manifest["runner"]["schema_version"]
        assert metadata["malware_runner_sha256"] == manifest["runner"]["sha256"]
        assert metadata["return_code"] == 0
        assert sequence["missing_sequence_ids"] == 0
        assert sequence["duplicate_sequence_ids"] == 0
        assert sequence["unexpected_sequence_ids"] == 0
        assert sequence["frame_count"] == stats["packets_captured"]
        assert diagnostics["pcap_file"]["record_count"] == sequence["frame_count"]
        assert diagnostics["pcap_file"]["record_count_minus_tcpdump_captured"] == 0
        assert metadata["packet_capture_counter_discrepancy"] == discrepancy
        assert stats["dropped_by_kernel"] == 0
        assert metadata["ebpf_lost_event_count"] == 0
        assert event_names == [
            "tcpdump_spawn_requested", "tcpdump_process_started", "tcpdump_ready",
            "stop_requested", "drain_completed", "sigint_sent",
            "tcpdump_process_exited", "tcpdump_stderr_reader_joined",
            "interface_counters_after_capture",
        ]
        assert monotonic_times == sorted(monotonic_times)
        assert event_names.index("sigint_sent") < event_names.index("tcpdump_process_exited")
        assert event_names.index("drain_completed") < event_names.index("sigint_sent")
        assert archive_members > 0 and not archive_errors

        results.append({
            "repetition": repetition["id"],
            "sample_run_id": metadata["run_id"],
            "quality": metadata["collection_quality_status"],
            "quality_reasons": metadata.get("collection_quality_reasons", []),
            "packets_sent": stdout["packets_sent"],
            **sequence,
            "tcpdump_statistics": stats,
            "received_minus_captured_timestamp_us": (received_event - captured_event) / 1000,
            "pcap_records_minus_tcpdump_captured": diagnostics["pcap_file"]["record_count_minus_tcpdump_captured"],
            "interface_counter_delta_after_drain": diagnostics["interface_counter_delta_after_drain"],
            "interface_counter_delta_after_capture": diagnostics["interface_counter_delta_after_capture"],
            "lifecycle_events": event_names,
            "ebpf_lost_event_count": metadata["ebpf_lost_event_count"],
            "archive_regular_files_sha256_matched": archive_members,
            "archive_errors": archive_errors,
        })

    result = {
        "run_id": manifest["run_id"],
        "schema_version": manifest["runner"]["schema_version"],
        "runner_sha256": manifest["runner"]["sha256"],
        "results": results,
        "interpretation_limit": "These three benign runs characterize only this workload and VM. Exact PCAP-to-captured-count agreement does not identify why tcpdump's received-by-filter count differs on a rejected run.",
    }
    (ROOT / "lifecycle_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()