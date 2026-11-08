#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "/home/csci/.corrected-pilot-setup.sh" ]]; then
    probe_dir="/home/csci/Downloads/loss-stress-probe"
    mkdir -p "$probe_dir"
    install -m 755 "$0" "$probe_dir/loss_stress_probe.sh"
    exit 0
fi

exec /usr/bin/python3 - <<'PY'
import os
import socket
import subprocess
import time
from pathlib import Path


route = subprocess.run(
    ["/usr/sbin/ip", "-4", "route", "get", "239.255.42.198"],
    capture_output=True, text=True, check=True,
)
route_fields = route.stdout.split()
source_index = route_fields.index("src")
source_address = route_fields[source_index + 1]
interface_index = route_fields.index("dev")
interface = route_fields[interface_index + 1]
if interface != "enp0s3":
    raise RuntimeError(f"unexpected route interface for isolated multicast: {interface}")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_address))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
target = ("239.255.42.198", 65003)
payload = b"bounded internal capture-loss stress probe"
probe_path = Path.cwd() / "loss-stress-stat-target"
deadline = time.monotonic() + 5.0
packet_limit = 50000
packets_sent = 0
stat_calls = 0
while packets_sent < packet_limit and time.monotonic() < deadline:
    os.stat(probe_path.parent)
    stat_calls += 1
    sock.sendto(payload, target)
    packets_sent += 1
sock.close()
print({"route_interface": interface, "source_address": source_address,
       "destination": target, "packets_sent": packets_sent,
       "stat_calls": stat_calls, "duration_seconds": 5.0})
PY