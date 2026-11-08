#!/usr/bin/env bash
set -Eeuo pipefail
/usr/bin/python3 - <<'PY'
import json
import shutil
from pathlib import Path

root = Path.home() / "Downloads/tls-smoke-20261019"
benign = root / "benign"
arguments = root / "arguments"
benign.mkdir(parents=True, exist_ok=True)
arguments.mkdir(parents=True, exist_ok=True)
source = Path("/usr/bin/curl")
destination = benign / "curl"
shutil.copy2(source, destination)
destination.chmod(0o755)
args = [
    "--noproxy", "*", "--insecure", "--fail", "--silent", "--show-error",
    "--max-time", "6", "https://example.com/benign/tls-smoke",
    "--output", "/dev/null",
]
(arguments / "curl.json").write_text(json.dumps(args) + "\n", encoding="utf-8")
print(f"Prepared isolated TLS smoke client: {destination}")
PY
