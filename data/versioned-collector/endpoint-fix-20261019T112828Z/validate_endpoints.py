from collections import defaultdict
import csv
import hashlib
import ipaddress
import json
import math
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parent
ENDPOINT_FEATURES = ("host_unique_ip_total", "host_unique_port_total",
                     "host_unique_remote_ips", "host_unique_remote_ports")


def csv_rows(path):
    with path.open(newline="") as source:
        reader = csv.DictReader(source)
        return reader.fieldnames, list(reader)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(sample, manifest):
    sample_root = ROOT / manifest["output_directory"] / sample
    metadata_path, = (sample_root / "output").glob("*/run.json")
    run = metadata_path.parent
    metadata = json.loads(metadata_path.read_text())
    fields, windows = csv_rows(run / "telemetry.csv")
    _, events = csv_rows(run / "ebpf_events.csv")
    features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
    assert metadata["telemetry_schema_version"] == manifest["runner_schema"]
    assert metadata["malware_runner_sha256"] == manifest["runner_sha256"]
    assert metadata["status"] == "completed" and metadata["return_code"] == 0
    assert len(windows) == 40 and len(fields) == 176 and len(features) == 169
    assert fields == metadata["telemetry_fields"]
    assert all(None not in row and all(math.isfinite(float(row[name])) for name in features) for row in windows)
    assert metadata["ebpf_status"] == metadata["packet_capture_status"] == "active"
    assert metadata["packet_capture_dropped_by_kernel"] == 0
    assert len(events) == metadata["ebpf_event_count"]
    per_window = defaultdict(list)
    endpoints = set()
    families = defaultdict(int)
    for event in events:
        if event["event"] != "connect":
            continue
        detail = dict(item.split("=", 1) for item in event["detail"].split())
        family = int(detail["family"])
        families[family] += 1
        if family == 2:
            address = int(detail["addr"])
            port = int(detail["port"])
            assert address != 0 and 0 < port <= 65535
            endpoints.add((str(ipaddress.IPv4Address(address)), port))
            per_window[int(event["window_id"])].append((int(event["pid"]), address, port))
    for window_id, row in enumerate(windows):
        addresses_by_pid = defaultdict(set)
        ports_by_pid = defaultdict(set)
        for pid, address, port in per_window[window_id]:
            addresses_by_pid[pid].add(address)
            ports_by_pid[pid].add(port)
        expected = (
            sum(len(values) for values in addresses_by_pid.values()),
            sum(len(values) for values in ports_by_pid.values()),
            len({address for _, address, _ in per_window[window_id]}),
            len({port for _, _, port in per_window[window_id]}),
        )
        for feature, value in zip(ENDPOINT_FEATURES, expected):
            assert float(row[feature]) == value, (sample, window_id, feature, value, row[feature])
    maxima = {feature: max(float(row[feature]) for row in windows) for feature in ENDPOINT_FEATURES}
    assert all(value > 0 for value in maxima.values())
    decoded = subprocess.run(
        ["tshark", "-r", str(run / "packet_capture.pcap"), "-Y", "tls.handshake.type == 1",
         "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "tls.handshake.extensions_server_name"],
        capture_output=True, text=True, check=True,
    )
    tls_peers = [line.split("\t") for line in decoded.stdout.splitlines()]
    assert tls_peers and all((row[0], int(row[1])) in endpoints for row in tls_peers)
    archive_count = 0
    with tarfile.open(sample_root / "output.tgz", "r:gz") as archive:
        for member in archive.getmembers():
            member_path = PurePosixPath(member.name)
            assert not member_path.is_absolute() and ".." not in member_path.parts
            assert member.isfile() or member.isdir()
            if not member.isfile():
                continue
            candidates = {path.resolve() for path in (sample_root / member.name, sample_root / "output" / member.name)
                          if path.is_file() and path.resolve().is_relative_to(sample_root.resolve())}
            assert len(candidates) == 1
            host_path, = candidates
            with archive.extractfile(member) as source:
                assert hashlib.sha256(source.read()).hexdigest() == sha256(host_path)
            archive_count += 1
    assert archive_count > 0
    return {"sample": sample, "run": str(run.relative_to(ROOT)), "passed": True,
            "runner_sha256": metadata["malware_runner_sha256"], "schema": metadata["telemetry_schema_version"],
            "windows": len(windows), "features": len(features), "archive_files_hash_matched": archive_count,
            "connect_events_by_family": dict(families), "decoded_ipv4_endpoints": sorted(endpoints),
            "pcap_tls_peers": tls_peers, "endpoint_feature_maxima": maxima,
            "endpoint_feature_cells_reconciled": len(windows) * len(ENDPOINT_FEATURES),
            "reported_pcap_drops": metadata["packet_capture_dropped_by_kernel"],
            "artifact_sha256": {name: sha256(run / name) for name in ("run.json", "telemetry.csv", "ebpf_events.csv", "packet_capture.pcap")}}


if __name__ == "__main__":
    manifest = {**json.loads((ROOT / "experiment_manifest.json").read_text()),
                **json.loads((ROOT / "retry_manifest.json").read_text())}
    results = [validate(sample, manifest) for sample in manifest["samples"]]
    report = {"accepted_attempt": "retry-byte-offsets", "results": results,
              "limitations": ["IPv4 connect attempts, not connection-success counts.",
                              "UNIX and other socket families are identified; IPv6 endpoint addresses are not decoded.",
                              "No change to filesystem watch scope or repair of historical zero endpoint values.",
                              "Only the benign r2 snapshot contains this runner; old malware snapshots remain unchanged.",
                              "No reported PCAP loss does not certify absence of unreported eBPF loss."],
              "validator_sha256": sha256(Path(__file__))}
    (ROOT / "endpoint_validation.json").write_text(json.dumps(report, indent=2) + "\n")
    for result in results:
        print(json.dumps({name: result[name] for name in ("sample", "passed", "decoded_ipv4_endpoints", "endpoint_feature_maxima", "archive_files_hash_matched", "endpoint_feature_cells_reconciled")}, indent=2))