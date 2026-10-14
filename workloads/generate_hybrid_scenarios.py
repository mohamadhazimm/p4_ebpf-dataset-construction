#!/usr/bin/env python3
"""Generate matched, safe host/network complementarity scenarios."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


TARGET_IP = "10.0.0.255"
CONDITIONS = (
    ("attack_simulation", 1),
    ("benign_file_only", 0),
    ("benign_network_only", 0),
)
SCENARIOS = (
    ("udp_beacon", 53001, 1, 96, False),
    ("udp_burst", 53010, 4, 256, False),
    ("udp_bulk", 53020, 8, 1024, False),
    ("udp_fanout", 53030, 4, 192, True),
    ("udp_large_fanout", 53040, 6, 768, True),
)
P4_ADDITIONAL_SCENARIOS = (
    ("udp_dns_query", "udp", "dns", "10.0.0.1", 53, 1, 48, False, 0.0),
    ("udp_payload_mix", "udp", "mixed", "10.0.0.1", 53120, 3, 1024, False, 0.0),
    ("udp_timed_burst", "udp", "timed", "10.0.0.1", 53130, 8, 128, False, 0.05),
    ("tcp_connect", "tcp", "connect", "10.0.0.1", 65000, 1, 0, False, 0.0),
    ("tcp_connect_fanout", "tcp", "connect", "10.0.0.1", 65100, 4, 0, True, 0.0),
)
REPLICATES = 4


SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
"""Controlled {condition} case for scenario {scenario_id}; not malware."""

import socket
import struct
import tempfile
import time
from pathlib import Path

TARGET_IP = "{target_ip}"
PROTOCOL = "{protocol}"
NETWORK_MODE = "{network_mode}"
TARGET_PORT = {port}
PACKET_COUNT = {packet_count}
PAYLOAD_SIZE = {payload_size}
FILE_PAYLOAD_SIZE = {file_payload_size}
PAYLOAD_SEED = {seed}
FAN_OUT = {fan_out}
INTER_PACKET_DELAY = {inter_packet_delay}
CONDITION = "{condition}"


def make_payload(size):
    return bytes((index * 37 + PAYLOAD_SEED) % 256 for index in range(size))


def dns_query():
    name = f"sim-{{PAYLOAD_SEED}}.invalid"
    labels = b"".join(bytes((len(label),)) + label for label in name.encode().split(b"."))
    question = labels + b"\\x00" + struct.pack("!HH", 1, 1)
    header = struct.pack("!HHHHHH", PAYLOAD_SEED, 0x0100, 1, 0, 0, 0)
    return header + question


def run_file_activity(payload):
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="hybrid-sim-", suffix=".dat", dir="/tmp", delete=False
        ) as staged_file:
            temporary_path = Path(staged_file.name)
            staged_file.write(payload)
        return temporary_path.read_bytes()
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def send_udp(destination, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(0.25)
        if destination == "10.0.0.255":
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if NETWORK_MODE == "dns":
            connection.sendto(dns_query(), (destination, TARGET_PORT))
            try:
                connection.recvfrom(4096)
            except TimeoutError:
                pass
            return

        if NETWORK_MODE == "mixed":
            payload_sizes = (128, 512, PAYLOAD_SIZE)
        else:
            payload_sizes = (PAYLOAD_SIZE,) * PACKET_COUNT
        for index, size in enumerate(payload_sizes):
            port = TARGET_PORT + index if FAN_OUT else TARGET_PORT
            connection.sendto(payload[:size], (destination, port))
            if INTER_PACKET_DELAY:
                time.sleep(INTER_PACKET_DELAY)


def connect_tcp(destination):
    for index in range(PACKET_COUNT):
        port = TARGET_PORT + index if FAN_OUT else TARGET_PORT
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.25)
            connection.connect_ex((destination, port))


def perform_network_action(destination, payload):
    if PROTOCOL == "udp":
        send_udp(destination, payload)
    elif PROTOCOL == "tcp":
        connect_tcp(destination)
    else:
        raise ValueError("unknown protocol")


def main():
    time.sleep(0.25)
    file_payload = make_payload(FILE_PAYLOAD_SIZE)
    payload = make_payload(max(PAYLOAD_SIZE, 1024))
    if CONDITION in {{"attack_simulation", "benign_file_only"}}:
        staged_payload = run_file_activity(file_payload)
        destination = TARGET_IP if CONDITION == "attack_simulation" else "127.0.0.1"
    elif CONDITION == "benign_network_only":
        staged_payload = payload
        destination = TARGET_IP
    else:
        raise ValueError("unknown scenario condition")
    perform_network_action(destination, staged_payload)
    time.sleep(0.25)


if __name__ == "__main__":
    main()
'''


def build_cohort(
    output_dir: Path,
    manifest_path: Path,
    replicates: int = REPLICATES,
    scenario_pack: str = "legacy",
) -> list[dict[str, str]]:
    if replicates < 2:
        raise ValueError("at least two paired replicates are required")
    if scenario_pack not in {"legacy", "p4-additions", "all"}:
        raise ValueError(f"unknown scenario pack: {scenario_pack}")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    legacy_scenarios = [
        (scenario_id, "udp", "datagram", TARGET_IP, port, packet_count, payload_size, fan_out, 0.0)
        for scenario_id, port, packet_count, payload_size, fan_out in SCENARIOS
    ]
    scenarios = {
        "legacy": legacy_scenarios,
        "p4-additions": list(P4_ADDITIONAL_SCENARIOS),
        "all": legacy_scenarios + list(P4_ADDITIONAL_SCENARIOS),
    }[scenario_pack]
    for (
        scenario_id,
        protocol,
        network_mode,
        target_ip,
        port,
        packet_count,
        payload_size,
        fan_out,
        inter_packet_delay,
    ) in scenarios:
        for variant in range(1, replicates + 1):
            pair_id = f"{scenario_id}__v{variant:02d}"
            for condition, label in CONDITIONS:
                artifact = f"sim_{scenario_id}_{condition}_v{variant:02d}.py"
                script = SCRIPT_TEMPLATE.format(
                    condition=condition,
                    scenario_id=scenario_id,
                    target_ip=target_ip,
                    protocol=protocol,
                    network_mode=network_mode,
                    port=port,
                    packet_count=packet_count,
                    payload_size=payload_size,
                    file_payload_size=(
                        payload_size if network_mode == "datagram" else max(payload_size, 128)
                    ),
                    seed=variant * 53,
                    fan_out=fan_out,
                    inter_packet_delay=inter_packet_delay,
                )
                script_path = output_dir / artifact
                script_path.write_text(script, encoding="utf-8")
                script_path.chmod(0o755)
                rows.append(
                    {
                        "sample_artifact": artifact,
                        "label": str(label),
                        "class_name": "attack_simulation" if label else "benign_control",
                        "package": "controlled_network_scenario",
                        "workload_family": scenario_id,
                        "group_id": f"scenario::{scenario_id}",
                        "scenario_id": scenario_id,
                        "condition": condition,
                        "pair_id": pair_id,
                        "variant": str(variant),
                        "target_ip": target_ip,
                        "control_destination": "127.0.0.1" if condition == "benign_file_only" else target_ip,
                        "protocol": protocol,
                        "network_mode": network_mode,
                        "target_port": str(port),
                        "packet_count": str(packet_count),
                        "fan_out": str(fan_out).lower(),
                        "payload_bytes": str(payload_size),
                        "file_bytes": str(
                            payload_size if network_mode == "datagram" else max(payload_size, 128)
                        ),
                    }
                )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path("data/hybrid_scenarios/workloads"),
    )
    parser.add_argument(
        "--manifest", type=Path,
        default=Path("data/hybrid_scenarios/scenario_manifest.csv"),
    )
    parser.add_argument("--replicates", type=int, default=REPLICATES)
    parser.add_argument(
        "--scenario-pack",
        choices=("legacy", "p4-additions", "all"),
        default="legacy",
    )
    args = parser.parse_args()
    try:
        rows = build_cohort(
            args.output_dir,
            args.manifest,
            args.replicates,
            args.scenario_pack,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    target_ips = {TARGET_IP} if args.scenario_pack in {"legacy", "all"} else set()
    if args.scenario_pack in {"p4-additions", "all"}:
        target_ips.update(scenario[3] for scenario in P4_ADDITIONAL_SCENARIOS)
    print(
        json.dumps(
            {
                "scenario_pack": args.scenario_pack,
                "scenarios": len(
                    SCENARIOS
                    if args.scenario_pack == "legacy"
                    else P4_ADDITIONAL_SCENARIOS
                    if args.scenario_pack == "p4-additions"
                    else SCENARIOS + P4_ADDITIONAL_SCENARIOS
                ),
                "replicates_per_condition": args.replicates,
                "samples": len(rows),
                "attack_simulations": sum(row["label"] == "1" for row in rows),
                "benign_controls": sum(row["label"] == "0" for row in rows),
                "target_ips": sorted(target_ips),
                "output_dir": str(args.output_dir),
                "manifest": str(args.manifest),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
