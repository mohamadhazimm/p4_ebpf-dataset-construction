#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "/home/csci/.corrected-pilot-setup.sh" ]]; then
    probe_dir="/home/csci/Downloads/ebpf-high-syscall-probe"
    install -d "$probe_dir"
    install -m 755 "$0" "$probe_dir/high_syscall_probe.sh"
    exit 0
fi

exec /usr/bin/python3 - <<'PY'
import json
import os
import time

call_limit = 2_000_000
duration_limit = 6.25
target = "/etc/passwd"
started = time.monotonic()
deadline = started + duration_limit
stat_calls = 0
while stat_calls < call_limit and time.monotonic() < deadline:
    os.stat(target)
    stat_calls += 1
elapsed = time.monotonic() - started
print(json.dumps({
    "operation": "read-only os.stat",
    "target": target,
    "stat_calls": stat_calls,
    "duration_seconds": elapsed,
    "calls_per_second": stat_calls / elapsed if elapsed else 0,
}))
PY