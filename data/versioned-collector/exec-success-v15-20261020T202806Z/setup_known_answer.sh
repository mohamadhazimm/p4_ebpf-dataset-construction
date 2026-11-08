#!/usr/bin/env bash
# Guest-side setup for the schema .15 exec-success known-answer validation.
# Benign only: creates four local workloads and their argument files.
set -Eeuo pipefail

if [[ "${BASH_SOURCE[0]}" != "/home/csci/.corrected-pilot-setup.sh" ]]; then
    exit 0
fi

exec /usr/bin/python3 - <<'PY'
import json
import os
import shutil
import struct
from pathlib import Path

source_dir = Path("/home/csci/Downloads/paired-elf-watchpath-pilot-20261018")
payload = source_dir / "fixtures" / "payload.bin"
dynamic_source = source_dir / "benign" / "md5sum"
root = Path("/home/csci/Downloads/exec-known-answer-v15")
samples = root / "samples"
arguments = root / "arguments"
samples.mkdir(parents=True, exist_ok=True)
arguments.mkdir(parents=True, exist_ok=True)


def has_interp(path):
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"expected little-endian ELF64: {path}")
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    return any(struct.unpack_from("<I", data, phoff + i * phentsize)[0] == 3 for i in range(phnum))


def is_static_elf(path):
    try:
        return path.is_file() and not has_interp(path)
    except (OSError, ValueError, struct.error):
        return False


static_candidates = [Path(p) for p in ("/usr/sbin/ldconfig.real", "/sbin/ldconfig.real",
                                       "/usr/sbin/ldconfig", "/sbin/ldconfig")]
static_source = next((p for p in static_candidates if is_static_elf(p)), None)
if static_source is None:
    raise FileNotFoundError(f"no static ldconfig ELF among {static_candidates}")
print(f"static_source={static_source.resolve()}")


for required in (payload, dynamic_source):
    if not required.is_file():
        raise FileNotFoundError(required)
if not has_interp(dynamic_source):
    raise ValueError("dynamic control unexpectedly has no PT_INTERP")

# 1. Dynamic ELF: keep the original basename (multicall-safe).
shutil.copy2(dynamic_source, samples / "md5sum")
# 2. Static ELF: read-only cache listing.
shutil.copy2(static_source, samples / "ka_static_ldconfig")
# 3. Shell script: target exec is the script; descendants exec /usr/bin tools.
(samples / "ka_script.sh").write_text(
    "#!/bin/sh\n"
    "echo known-answer-script\n"
    f"/usr/bin/md5sum {payload}\n"
    "/bin/ls /etc >/dev/null\n",
    encoding="utf-8",
)
# 4. Truncated ELF: header only; kernel exec must fail (ENOEXEC or EIO).
(samples / "ka_truncated_elf").write_bytes(dynamic_source.read_bytes()[:64])

for path in samples.iterdir():
    os.chmod(path, 0o755)
argument_lists = {
    "md5sum": [str(payload)],
    "ka_static_ldconfig": ["-p"],
    "ka_script.sh": [],
    "ka_truncated_elf": [],
}
for name, values in argument_lists.items():
    (arguments / f"{name}.json").write_text(json.dumps(values) + "\n", encoding="utf-8")
print(json.dumps({p.name: p.stat().st_size for p in sorted(samples.iterdir())}))
PY
