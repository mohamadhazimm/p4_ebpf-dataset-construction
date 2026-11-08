#!/usr/bin/env bash
set -Eeuo pipefail
/usr/bin/python3 - <<'PY'
import hashlib
import json
import os
import shutil
import signal
import subprocess
from pathlib import Path

root = Path.home() / "Downloads/paired-elf-watchpath-pilot-20261018"
benign_dir = root / "benign"
arguments_dir = root / "arguments"
fixtures_dir = root / "fixtures"
watch_dir = root / "watch"
for directory in (benign_dir, arguments_dir, fixtures_dir, watch_dir):
    directory.mkdir(parents=True, exist_ok=True)
(fixtures_dir / "records.txt").write_text(
    "".join(f"record,{index:06d},value-{index % 97}\n" for index in range(20000)),
    encoding="utf-8",
)
(fixtures_dir / "payload.bin").write_bytes(bytes(range(256)) * 32768)

jobs = [
    ("ping", ["-i", "0.5", "-w", "6", "10.0.0.1"]),
    ("openssl", ["speed", "-seconds", "6", "sha256"]),
    ("vmstat", ["1", "7"]),
    ("tail", ["-f", "/dev/null"]),
    ("md5sum", ["/dev/zero"]),
    ("dd", [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=64K", "status=none"]),
    ("find", ["/usr/share", "-xdev", "-type", "f", "-fprint", str(watch_dir / "find-results.txt")]),
    ("tar", ["-cf", str(watch_dir / "fixtures.tar"), "-C", str(fixtures_dir), "."]),
    ("curl", ["--noproxy", "*", "-fsS", "--max-time", "6", "http://example.com/benign/pilot", "-o", "/dev/null"]),
    ("wget", ["--no-proxy", "-q", "-T", "6", "-O", "/dev/null", "http://example.com/benign/pilot"]),
]
manifest = []
for name, args in jobs:
    source = Path("/usr/bin") / name
    with source.open("rb") as handle:
        if handle.read(4) != b"\x7fELF":
            raise RuntimeError(f"Benign payload is not ELF: {source}")
    destination = benign_dir / name
    shutil.copy2(source, destination)
    destination.chmod(0o755)
    (arguments_dir / f"{name}.json").write_text(json.dumps(args) + "\n", encoding="utf-8")

    process = subprocess.Popen(
        [str(destination), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        return_code = process.wait(timeout=1.5)
        if return_code != 0:
            raise RuntimeError(f"Benign workload preflight failed: {name}, rc={return_code}")
        preflight = "completed"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        preflight = "alive_after_1.5s_stopped"
    manifest.append({
        "artifact": name,
        "command": name,
        "arguments": args,
        "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
        "artifact_type": "elf",
        "preflight": preflight,
    })

(root / "control_manifest.json").write_text(json.dumps({
    "controls": manifest,
    "watch_path": str(watch_dir),
    "observation_note": "Eight-second fixed observation; persistent workloads may time out by design.",
}, indent=2) + "\n", encoding="utf-8")
print(f"Prepared and preflighted {len(manifest)} native ELF controls at {benign_dir}")
print(f"External filesystem watch target: {watch_dir}")
PY
