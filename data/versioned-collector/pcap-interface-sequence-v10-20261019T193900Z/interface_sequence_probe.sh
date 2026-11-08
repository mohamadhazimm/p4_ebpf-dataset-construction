#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "/home/csci/.corrected-pilot-setup.sh" ]]; then
    probe_dir="/home/csci/Downloads/pcap-interface-sequence-probe"
    install -d "$probe_dir"
    install -m 755 "$0" "$probe_dir/interface_sequence_probe.sh"
    exit 0
fi

exec /usr/bin/python3 - <<'PY'
import json
import os
import socket
import struct
import subprocess
import time
from pathlib import Path


interface = "enp0s3"
target = ("239.255.42.198", 65003)
route = subprocess.run(
    ["/usr/sbin/ip", "-4", "route", "get", target[0]],
    capture_output=True, text=True, check=True,
)
route_fields = route.stdout.split()
route_interface = route_fields[route_fields.index("dev") + 1]
source_address = route_fields[route_fields.index("src") + 1]
if route_interface != interface:
    raise RuntimeError(f"unexpected route interface for isolated multicast: {route_interface}")


def read_interface_counters():
    counters = {}
    base = Path("/sys/class/net") / interface / "statistics"
    for name in ("rx_packets", "rx_bytes", "rx_dropped", "tx_packets", "tx_bytes", "tx_dropped"):
        counters[name] = int((base / name).read_text().strip())
    return counters


before = read_interface_counters()
ip_before = subprocess.run(
    ["/usr/sbin/ip", "-s", "link", "show", "dev", interface],
    capture_output=True, text=True, check=True,
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_address))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
magic = b"HAZIMSEQ"
padding = b"interface-counter-sequence-probe"
deadline = time.monotonic() + 5.0
packet_limit = 50000
packet_number = 0
stat_calls = 0
started = time.monotonic()
while packet_number < packet_limit and time.monotonic() < deadline:
    os.stat("/etc/passwd")
    stat_calls += 1
    sock.sendto(magic + struct.pack("!Q", packet_number) + padding, target)
    packet_number += 1
sock.close()
duration = time.monotonic() - started

after = read_interface_counters()
ip_after = subprocess.run(
    ["/usr/sbin/ip", "-s", "link", "show", "dev", interface],
    capture_output=True, text=True, check=True,
)
delta = {name: after[name] - before[name] for name in before}
print(json.dumps({
    "operation": "sequence-marked internal multicast plus read-only stat",
    "route_interface": route_interface,
    "source_address": source_address,
    "destination": target,
    "sequence_marker_hex": magic.hex(),
    "packets_sent": packet_number,
    "stat_calls": stat_calls,
    "duration_seconds": duration,
    "interface_counters_before": before,
    "interface_counters_after": after,
    "interface_counter_delta": delta,
    "ip_link_before": ip_before.stdout.strip(),
    "ip_link_after": ip_after.stdout.strip(),
}))
PY