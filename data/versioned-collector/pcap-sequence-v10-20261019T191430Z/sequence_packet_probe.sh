#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "/home/csci/.corrected-pilot-setup.sh" ]]; then
    probe_dir="/home/csci/Downloads/loss-sequence-probe"
    install -d "$probe_dir"
    install -m 755 "$0" "$probe_dir/sequence_packet_probe.sh"
    exit 0
fi

exec /usr/bin/python3 - <<'PY'
import json
import os
import socket
import struct
import subprocess
import time


target = ("239.255.42.198", 65003)
route = subprocess.run(
    ["/usr/sbin/ip", "-4", "route", "get", target[0]],
    capture_output=True, text=True, check=True,
)
route_fields = route.stdout.split()
interface = route_fields[route_fields.index("dev") + 1]
source_address = route_fields[route_fields.index("src") + 1]
if interface != "enp0s3":
    raise RuntimeError(f"unexpected route interface for isolated multicast: {interface}")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_address))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
magic = b"HAZIMSEQ"
padding = b"packet-counter-sequence-probe"
deadline = time.monotonic() + 5.0
packet_limit = 50000
packet_number = 0
stat_calls = 0
started = time.monotonic()
while packet_number < packet_limit and time.monotonic() < deadline:
    os.stat("/etc/passwd")
    stat_calls += 1
    payload = magic + struct.pack("!Q", packet_number) + padding
    sock.sendto(payload, target)
    packet_number += 1
sock.close()
elapsed = time.monotonic() - started
print(json.dumps({
    "operation": "sequence-marked internal multicast plus read-only stat",
    "route_interface": interface,
    "source_address": source_address,
    "destination": target,
    "magic_hex": magic.hex(),
    "packet_limit": packet_limit,
    "packets_sent": packet_number,
    "stat_calls": stat_calls,
    "duration_seconds": elapsed,
    "packets_per_second": packet_number / elapsed if elapsed else 0,
}))
PY