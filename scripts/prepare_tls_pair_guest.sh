#!/usr/bin/env bash
set -Eeuo pipefail
/usr/bin/python3 - <<'PY'
import json
import shutil
from pathlib import Path

root = Path.home() / "Downloads/tls-paired-20261019"
benign = root / "benign"
arguments = root / "arguments"
benign.mkdir(parents=True, exist_ok=True)
arguments.mkdir(parents=True, exist_ok=True)
source = Path("/usr/bin/curl")
for index in (1, 2):
    name = f"curl-pair-{index:02d}"
    destination = benign / name
    shutil.copy2(source, destination)
    destination.chmod(0o755)
    args = [
        "--noproxy", "*", "--insecure", "--fail", "--silent", "--show-error",
        "--max-time", "6", f"https://cdn.fwupd.org/benign/tls-pair-{index:02d}",
        "--output", "/dev/null",
    ]
    (arguments / f"{name}.json").write_text(json.dumps(args) + "\n", encoding="utf-8")
print(f"Prepared {len((1, 2))} benign HTTPS controls for cdn.fwupd.org")
PY
