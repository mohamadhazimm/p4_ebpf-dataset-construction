#!/usr/bin/env bash
set -Eeuo pipefail
/usr/bin/python3 - <<'PY'
import hashlib
import json
import shutil
import socket
import subprocess
import urllib.request
from pathlib import Path

root = Path.home() / "Downloads/corrected-host-pilot-20261018"
fixtures = root / "fixtures"
fixtures.mkdir(parents=True, exist_ok=True)
(root / "benign").mkdir(exist_ok=True)
(root / "arguments").mkdir(exist_ok=True)
(fixtures / "records.txt").write_text("".join(f"alpha,{index:04d},value\n" for index in range(1000)))
(fixtures / "data.bin").write_bytes(bytes(range(256)) * 4096)
records = str(fixtures / "records.txt")
data = str(fixtures / "data.bin")
jobs = [
    ("sha256sum", [data]), ("sort", [records]),
    ("find", [str(fixtures), "-type", "f"]), ("gzip", ["-c", data]),
    ("tar", ["-cf", "/dev/null", "-C", str(fixtures), "."]),
    ("grep", ["-c", "alpha", records]), ("head", ["-n", "50", records]),
    ("ls", ["-lR", str(fixtures)]),
    ("curl", ["--noproxy", "*", "-fsS", "--max-time", "2", "http://example.com/benign/train", "-o", "/dev/null"]),
    ("cmp", [records, records]),
    ("sha512sum", [data]), ("uniq", ["-c", records]), ("wc", [records]),
    ("bzip2", ["-c", data]), ("du", ["-a", str(fixtures)]),
    ("cut", ["-d,", "-f1", records]), ("tail", ["-n", "50", records]),
    ("stat", [data]),
    ("od", ["-N", "64", data]),
    ("wget", ["--no-proxy", "-q", "-T", "2", "-O", "/dev/null", "http://example.com/benign/validation"]),
]
manifest = []
for index, (command, arguments) in enumerate(jobs, start=1):
    source = Path("/usr/bin") / command
    with source.open("rb") as handle:
        if handle.read(4) != b"\x7fELF":
            raise RuntimeError(f"Benign payload is not ELF: {source}")
    artifact = command
    destination = root / "benign" / artifact
    shutil.copy2(source, destination)
    destination.chmod(0o755)
    result = subprocess.run([str(destination), *arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            text=True, timeout=10)
    if result.returncode:
        raise RuntimeError(f"Benign workload preflight failed: {command}: {result.stderr[:300]}")
    (root / "arguments" / f"{artifact}.json").write_text(json.dumps(arguments) + "\n")
    manifest.append({"artifact": artifact, "command": command, "arguments": arguments,
                     "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
address = socket.gethostbyname("example.com")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open("http://example.com/benign/preflight", timeout=5) as response:
    if response.status != 200:
        raise RuntimeError("Controlled HTTP sink did not return status 200")
(root / "fixture_manifest.json").write_text(json.dumps({"jobs": manifest, "sink_address": address}, indent=2) + "\n")
print(f"Prepared {len(manifest)} native benign workloads; controlled DNS/HTTP preflight passed at {address}")
PY