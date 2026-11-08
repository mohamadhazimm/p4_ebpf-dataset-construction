#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "/home/csci/.corrected-pilot-setup.sh" ]]; then
    probe_dir="/home/csci/Downloads/pcap-backend-inventory"
    install -d "$probe_dir"
    install -m 755 "$0" "$probe_dir/inspect_capture_tools.sh"
    exec /usr/bin/python3 - "$probe_dir" <<'PY'
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


probe_dir = Path(sys.argv[1])
tools = {}
for name in ("dumpcap", "tshark", "tcpdump", "ip", "ethtool", "getcap"):
    path = shutil.which(name)
    details = {"path": path}
    if path:
        details["executable"] = os.access(path, os.X_OK)
        if name == "dumpcap":
            result = subprocess.run([path, "-D"], capture_output=True, text=True, timeout=5)
            details["list_interfaces_returncode"] = result.returncode
            details["list_interfaces_stdout"] = result.stdout.strip()
            details["list_interfaces_stderr"] = result.stderr.strip()
        if name == "getcap":
            dumpcap = shutil.which("dumpcap")
            if dumpcap:
                result = subprocess.run([path, dumpcap], capture_output=True, text=True, timeout=5)
                details["dumpcap_capabilities_returncode"] = result.returncode
                details["dumpcap_capabilities"] = result.stdout.strip()
    tools[name] = details

stats = {}
for name in ("rx_packets", "rx_bytes", "rx_dropped", "tx_packets", "tx_bytes", "tx_dropped"):
    counter = Path("/sys/class/net/enp0s3/statistics") / name
    try:
        stats[name] = int(counter.read_text().strip())
    except (OSError, ValueError) as error:
        stats[name] = f"unavailable:{type(error).__name__}:{error}"

ip = shutil.which("ip")
link_stats = None
if ip:
    result = subprocess.run([ip, "-s", "link", "show", "dev", "enp0s3"],
                            capture_output=True, text=True, timeout=5)
    link_stats = {"returncode": result.returncode,
                  "stdout": result.stdout.strip(),
                  "stderr": result.stderr.strip()}

report = {
    "guest_user": os.environ.get("USER"),
    "interface": "enp0s3",
    "tools": tools,
    "sysfs_interface_counters": stats,
    "ip_link_stats": link_stats,
}
output = probe_dir / "capture_tool_inventory.json"
output.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
print(f"inventory_json={output}")
PY
fi