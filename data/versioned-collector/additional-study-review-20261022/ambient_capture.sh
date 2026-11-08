#!/bin/bash
# Run as the guest user. Captures boot-phase enp0s3 traffic with tcpdump (via sudo -S from the protected
# credential file) and makes ONE bounded positive-control HTTP GET to the internal Sink part-way through.
# Usage: ambient_capture.sh <guest_root> <capture_seconds> <control_after_seconds> <control_path>
set -euo pipefail
root="$1"; seconds="$2"; control_after="$3"; control_path="$4"
auth="$root/.auth"
trap 'rm -f "$auth"' EXIT
cd "$root"

cut -d' ' -f1 /proc/uptime > uptime-start.txt
sudo -S -p '' timeout --signal=INT "$seconds" tcpdump -i enp0s3 -n -U --immediate-mode -s 0 \
    -w "$root/ambient.pcap" < "$auth" 2> tcpdump.log &
capture=$!
sleep "$control_after"
python3 - "$control_path" > control.json <<'PY'
import json, sys, time, urllib.request
record = {"url": "http://10.0.0.1" + sys.argv[1], "started_wall_ns": time.time_ns()}
try:
    with urllib.request.urlopen(record["url"], timeout=2) as response:
        record.update(status=response.status, body_bytes=len(response.read()))
except Exception as error:
    record["error"] = type(error).__name__ + ": " + str(error)
record["ended_wall_ns"] = time.time_ns()
print(json.dumps(record, sort_keys=True))
PY
wait "$capture" || true
cut -d' ' -f1 /proc/uptime > uptime-end.txt
sudo -S -p '' chmod 0644 "$root/ambient.pcap" < "$auth"
