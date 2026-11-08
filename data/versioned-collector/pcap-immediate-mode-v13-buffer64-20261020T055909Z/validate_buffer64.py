import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader


SCRIPT_ROOT = Path(__file__).resolve().parent
STUDY_ROOT = SCRIPT_ROOT.parents[2]
STATS_PATTERNS = {
    "packets_captured": r"^\s*(\d+)\s+packets captured\b",
    "packets_received_by_filter": r"^\s*(\d+)\s+packets received by filter\b",
    "dropped_by_kernel": r"^\s*(\d+)\s+packets dropped by kernel\b",
}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def check(condition, message, errors):
    if not condition:
        errors.append(message)


def read_capture_stats(path, errors):
    text = path.read_text(errors="replace")
    stats = {}
    for key, pattern in STATS_PATTERNS.items():
        match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        if match is None:
            errors.append(f"missing tcpdump statistic in {path.name}: {key}")
        else:
            stats[key] = int(match.group(1))
    return stats


def check_archive(sample_root, errors):
    archive_path = sample_root / "output.tgz"
    matched = 0
    try:
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
                    errors.append(f"missing or escaping extracted file: {member.name}")
                    continue
                archived = archive.extractfile(member)
                if archived is None or sha256_bytes(archived.read()) != sha256_file(host_path):
                    errors.append(f"archive hash mismatch: {member.name}")
                    continue
                matched += 1
    except (OSError, tarfile.TarError) as error:
        errors.append(f"cannot inspect archive {archive_path}: {error}")
    if matched == 0:
        errors.append(f"no regular archive members matched: {archive_path}")
    return matched


def validate_repeat(root, manifest, repeat):
    errors = []
    sample_name = manifest["sample"]["name"]
    sample_root = root / repeat["output_directory"] / sample_name
    run_files = sorted((sample_root / "output").glob("run_*/run.json"))
    check(len(run_files) == 1, f"{repeat['repeat']}: expected one run.json, found {len(run_files)}", errors)
    if len(run_files) != 1:
        return {"repeat": repeat["repeat"], "errors": errors}

    run_dir = run_files[0].parent
    try:
        metadata = json.loads(run_files[0].read_text())
        diagnostics = json.loads((run_dir / "packet_capture_diagnostics.json").read_text())
        stdout = json.loads((run_dir / "sample.stdout.log").read_text())
    except (OSError, json.JSONDecodeError) as error:
        return {"repeat": repeat["repeat"], "errors": [f"cannot read run artifacts: {error}"]}

    expected_schema = manifest["runner"]["schema_version"]
    expected_runner_hash = manifest["runner"]["sha256"]
    expected_buffer = manifest["settings"]["packet_capture_buffer_kb"]
    packet_stats = metadata.get("packet_capture_statistics") or {}
    check("status=completed" in (sample_root / "host_run.txt").read_text(errors="replace"),
          f"{repeat['repeat']}: batch retrieval is not completed", errors)
    check(metadata.get("status") == "completed" and metadata.get("return_code") == 0,
          f"{repeat['repeat']}: sample execution did not complete with exit 0", errors)
    check(metadata.get("telemetry_schema_version") == expected_schema,
          f"{repeat['repeat']}: schema mismatch", errors)
    check(metadata.get("malware_runner_sha256") == expected_runner_hash,
          f"{repeat['repeat']}: runner hash mismatch", errors)
    check(metadata.get("packet_capture_buffer_kb_requested") == expected_buffer,
          f"{repeat['repeat']}: requested buffer mismatch", errors)
    check(metadata.get("packet_capture_immediate_mode") is True,
          f"{repeat['repeat']}: immediate mode is not recorded as enabled", errors)
    check(metadata.get("packet_capture_drain_ms") == manifest["settings"]["packet_capture_drain_ms"],
          f"{repeat['repeat']}: drain setting mismatch", errors)
    check(stdout.get("packets_sent") == manifest["sample"]["maximum_packets"],
          f"{repeat['repeat']}: probe did not send the expected packet count", errors)

    marker = bytes.fromhex(stdout.get("sequence_marker_hex", ""))
    check(marker.hex() == manifest["sample"]["sequence_marker_hex"],
          f"{repeat['repeat']}: probe marker mismatch", errors)
    target = manifest["sample"].get("target", "")
    target_ip = manifest["sample"].get("target_ip", target.rpartition(":")[0])
    target_port = manifest["sample"].get("target_port")
    if target_port is None:
        target_port = int(target.rpartition(":")[2])
    sequence_counts = Counter()
    frame_count = 0
    try:
        with RawPcapReader(str(run_dir / "packet_capture.pcap")) as reader:
            for raw, _ in reader:
                frame_count += 1
                packet = Ether(raw)
                if not packet.haslayer(IP) or not packet.haslayer(UDP):
                    continue
                if packet[IP].dst != target_ip or packet[UDP].dport != int(target_port):
                    continue
                payload = bytes(packet[UDP].payload)
                if payload.startswith(marker) and len(payload) >= len(marker) + 8:
                    number = struct.unpack("!Q", payload[len(marker):len(marker) + 8])[0]
                    sequence_counts[number] += 1
    except (OSError, ValueError) as error:
        errors.append(f"{repeat['repeat']}: cannot decode PCAP: {error}")

    expected_ids = set(range(manifest["sample"]["maximum_packets"]))
    found_ids = set(sequence_counts)
    missing_ids = len(expected_ids - found_ids)
    unexpected_ids = len(found_ids - expected_ids)
    duplicate_records = sum(count - 1 for count in sequence_counts.values())
    check(found_ids == expected_ids, f"{repeat['repeat']}: sequence IDs missing={missing_ids}, unexpected={unexpected_ids}", errors)
    check(duplicate_records == 0, f"{repeat['repeat']}: duplicate sequence records={duplicate_records}", errors)

    log_stats = read_capture_stats(run_dir / "packet_capture.log", errors)
    check(log_stats == packet_stats, f"{repeat['repeat']}: tcpdump log and run.json counters differ", errors)
    received = packet_stats.get("packets_received_by_filter")
    captured = packet_stats.get("packets_captured")
    kernel_drops = packet_stats.get("dropped_by_kernel")
    discrepancy = None
    if all(isinstance(value, int) for value in (received, captured, kernel_drops)):
        discrepancy = received - captured - kernel_drops
    else:
        errors.append(f"{repeat['repeat']}: packet counters are unavailable")
    check(discrepancy == 0, f"{repeat['repeat']}: counter discrepancy={discrepancy}", errors)
    check(metadata.get("packet_capture_counter_discrepancy") == discrepancy,
          f"{repeat['repeat']}: recorded counter discrepancy mismatch", errors)
    pcap_info = diagnostics.get("pcap_file") or {}
    check(pcap_info.get("record_count") == frame_count == captured,
          f"{repeat['repeat']}: independent PCAP record count differs from captured count", errors)
    check(metadata.get("packet_capture_dropped_by_kernel") == kernel_drops == 0,
          f"{repeat['repeat']}: kernel-reported drops={kernel_drops}", errors)
    check(metadata.get("ebpf_lost_event_count") == 0,
          f"{repeat['repeat']}: eBPF lost events={metadata.get('ebpf_lost_event_count')}", errors)
    lost_log = (run_dir / "ebpf_collector.log").read_text(errors="replace")
    lost_events = sum(int(value) for value in re.findall(r"\bLost\s+(\d+)\s+events\b", lost_log, re.IGNORECASE))
    check(lost_events == 0, f"{repeat['repeat']}: eBPF log reports lost events={lost_events}", errors)
    check(metadata.get("collection_quality_status") == "accepted",
          f"{repeat['repeat']}: collection quality={metadata.get('collection_quality_status')}", errors)

    rmem_before = metadata.get("packet_capture_rmem_max_before")
    rmem_during = metadata.get("packet_capture_rmem_max_during_capture")
    rmem_after = metadata.get("packet_capture_rmem_max_after_capture")
    required_rmem = expected_buffer * 1024 * 2
    check(isinstance(rmem_during, int) and rmem_during >= required_rmem,
          f"{repeat['repeat']}: effective rmem_max below requested-buffer requirement", errors)
    check(rmem_after == rmem_before,
          f"{repeat['repeat']}: rmem_max was not restored ({rmem_before} -> {rmem_after})", errors)
    interface_delta = metadata.get("packet_capture_interface_counter_deltas") or {}
    check(interface_delta.get("rx_dropped") == 0 and interface_delta.get("tx_dropped") == 0,
          f"{repeat['repeat']}: interface reports packet drops", errors)

    archive_members = check_archive(sample_root, errors)
    return {
        "repeat": repeat["repeat"],
        "run_id": metadata.get("run_id"),
        "status": metadata.get("status"),
        "quality": metadata.get("collection_quality_status"),
        "received": received,
        "captured": captured,
        "kernel_drops": kernel_drops,
        "counter_discrepancy": discrepancy,
        "pcap_records": pcap_info.get("record_count"),
        "sequence_ids": len(found_ids),
        "missing_sequence_ids": missing_ids,
        "duplicate_sequence_records": duplicate_records,
        "ebpf_lost_events": metadata.get("ebpf_lost_event_count"),
        "rmem_max_before": rmem_before,
        "rmem_max_during": rmem_during,
        "rmem_max_after": rmem_after,
        "archive_regular_files_hash_matched": archive_members,
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=SCRIPT_ROOT)
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = json.loads((root / "experiment_manifest.json").read_text())
    errors = []
    check(sha256_file(STUDY_ROOT / "src/malware_runner.py") == manifest["runner"]["sha256"],
          "host runner hash differs from frozen manifest", errors)
    probe = STUDY_ROOT / manifest["sample"]["source_script"]
    check(sha256_file(probe) == manifest["sample"]["sha256"],
          "probe source hash differs from frozen manifest", errors)
    sample_manifest = root / manifest["sample"]["manifest"]
    check(sha256_file(sample_manifest) == manifest["sample"]["manifest_sha256"],
          "sample manifest hash differs from frozen manifest", errors)
    validator_hash = manifest.get("scripts", {}).get("validator_sha256")
    if validator_hash:
        check(sha256_file(Path(__file__)) == validator_hash,
              "validator hash differs from frozen manifest", errors)

    repeats = [validate_repeat(root, manifest, repeat) for repeat in manifest["planned_runs"]]
    all_errors = errors + [error for repeat in repeats for error in repeat["errors"]]
    report = {
        "run_id": manifest["run_id"],
        "runner_schema": manifest["runner"]["schema_version"],
        "runner_sha256": manifest["runner"]["sha256"],
        "buffer_kb": manifest["settings"]["packet_capture_buffer_kb"],
        "repeats": repeats,
        "errors": all_errors,
        "accepted": not all_errors,
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.write_report:
        (root / "buffer64_results.json").write_text(rendered)
    print(rendered, end="")
    return 0 if not all_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
