#!/usr/bin/env python3
"""Package the benign pilot payloads as AES zips (same launch path as malware archives),
write per-sample argument files, the interleaved sample lists, and the guest setup script."""
import base64
import hashlib
import io
import json
import random
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
SEED = 20261020
GUEST_ROOT = "/home/csci/Downloads/exec-mode-pilot-v16"
SINK_URL = "http://10.0.0.1/"
FILE_LOOP = ("i=0; while [ $i -lt 300 ]; do echo $i > bb_file_workload.txt; "
             "read v < bb_file_workload.txt; i=$((i+1)); done")
# Revision 1 (before any Phase B data): busybox 1.35 wget segfaulted in every mode
# (net-applet-check-v6.log); nc completed an HTTP exchange with the Sink in every mode.
NET_SCRIPT = ('printf "GET / HTTP/1.0\\r\\nHost: 10.0.0.1\\r\\n\\r\\n" | '
              "nc -w 3 10.0.0.1 80 > bb_net_workload.html")
WORKLOAD_ARGS = {
    "null": ["true"],
    "file": ["sh", "-c", FILE_LOOP],
    "net": ["sh", "-c", NET_SCRIPT],
}
RUNNABLE_MODES = ["amd64-dynamic", "amd64-static", "i386-static",
                  "armel-static", "mipsel-static", "arm64-static"]
REPEATS = {"null": 3, "file": 2, "net": 2}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def make_truncated_elf():
    data = (ART / "busybox-amd64-static").read_bytes()[:64]
    path = ART / "truncated-elf"
    path.write_bytes(data)
    return path


def build_cases():
    cases = []
    for mode in RUNNABLE_MODES:
        for workload, count in REPEATS.items():
            for repeat in range(1, count + 1):
                cases.append({"mode": mode, "workload": workload, "repeat": repeat,
                              "member": "busybox", "source": f"busybox-{mode}",
                              "args": WORKLOAD_ARGS[workload]})
    for repeat in (1, 2):
        cases.append({"mode": "armel-dynamic", "workload": "file", "repeat": repeat, "member": "busybox",
                      "source": "busybox-armel-dynamic", "args": WORKLOAD_ARGS["file"]})
        cases.append({"mode": "amd64-static-threads", "workload": "thread-exec", "repeat": repeat,
                      "member": "thread-exec-ka", "source": "thread-exec-ka", "args": ["exec"]})
        cases.append({"mode": "amd64-static-threads", "workload": "leader-exit", "repeat": repeat,
                      "member": "thread-exec-ka", "source": "thread-exec-ka", "args": ["leader-exit"]})
    cases.append({"mode": "amd64-truncated", "workload": "invalid-elf", "repeat": 1,
                  "member": "truncated-elf", "source": "truncated-elf", "args": []})
    for case in cases:
        case["sample"] = f"{case['mode']}_{case['workload']}_r{case['repeat']}.zip"
    return cases


def main():
    make_truncated_elf()
    cases = build_cases()
    order = list(range(len(cases)))
    random.Random(SEED).shuffle(order)
    ordered = [cases[i] for i in order]
    sources = sorted({case["source"] for case in ordered})
    for case in ordered:
        case["member_sha256"] = sha256((ART / case["source"]).read_bytes())
    plan = "".join(f"{c['sample']}\t{c['member']}\t{c['source']}\t{c['member_sha256']}\n" for c in ordered)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as tar:
        for name in sources:
            data = (ART / name).read_bytes()
            info = tarfile.TarInfo(f"bin/{name}")
            info.size, info.mode, info.mtime = len(data), 0o755, 0
            tar.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo("zip_plan.tsv")
        info.size, info.mode, info.mtime = len(plan.encode()), 0o644, 0
        tar.addfile(info, io.BytesIO(plan.encode()))
        for case in ordered:
            body = json.dumps(case["args"]).encode()
            info = tarfile.TarInfo(f"arguments/{case['sample']}.json")
            info.size, info.mode, info.mtime = len(body), 0o644, 0
            tar.addfile(info, io.BytesIO(body))
    payload_bytes = payload.getvalue()
    payload_sha = sha256(payload_bytes)

    manifests = ROOT / "manifests"
    manifests.mkdir(exist_ok=True)
    (manifests / "pilot-v16.txt").write_text("".join(c["sample"] + "\n" for c in ordered))
    phase_a = [c["sample"] for c in ordered if (c["workload"], c["repeat"]) in
               {("thread-exec", 1), ("leader-exit", 1)} or
               (c["mode"], c["workload"], c["repeat"]) in
               {("armel-static", "null", 1), ("armel-dynamic", "file", 1)}]
    (manifests / "phase-a-v15.txt").write_text("".join(s + "\n" for s in phase_a))
    (ROOT / "cases.json").write_text(json.dumps(
        {"seed": SEED, "order": "random.Random(seed).shuffle over build order", "guest_root": GUEST_ROOT,
         "payload_sha256": payload_sha, "cases": ordered}, indent=2) + "\n")

    encoded = base64.encodebytes(payload_bytes).decode()
    setup = f"""#!/usr/bin/env bash
# Guest-side setup: unpack benign pilot zips/arguments and record qemu/binfmt state.
set -Eeuo pipefail
if [[ "${{BASH_SOURCE[0]}}" != "/home/csci/.corrected-pilot-setup.sh" ]]; then
    exit 0
fi
root="{GUEST_ROOT}"
mkdir -p "$root"
base64 -d > "$root/payload.tgz" <<'PAYLOAD'
{encoded}PAYLOAD
echo "{payload_sha}  $root/payload.tgz" | sha256sum -c -
tar -xzf "$root/payload.tgz" -C "$root"
rm -f "$root/payload.tgz"
mkdir -p "$root/samples"
while IFS=$'\\t' read -r sample member source digest; do
    echo "$digest  $root/bin/$source" | sha256sum -c --quiet -
    work="$(mktemp -d)"
    install -m 755 "$root/bin/$source" "$work/$member"
    (cd "$work" && 7z a -tzip -pinfected -mem=AES256 "$root/samples/$sample" "$member" >/dev/null)
    rm -rf "$work"
done < "$root/zip_plan.tsv"
rm -rf "$root/bin"
(cd "$root/samples" && sha256sum *.zip)
echo "samples=$(ls "$root/samples" | wc -l) arguments=$(ls "$root/arguments" | wc -l)"
for handler in /proc/sys/fs/binfmt_misc/qemu-arm /proc/sys/fs/binfmt_misc/qemu-mipsel /proc/sys/fs/binfmt_misc/qemu-aarch64; do
    [[ -f "$handler" ]] || {{ echo "missing $handler" >&2; exit 1; }}
    echo "== $handler"; cat "$handler"
done
for path in /lib/ld-linux.so.3 /usr/arm-linux-gnueabi /usr/gnemul/qemu-arm; do
    if [[ -e "$path" ]]; then echo "present $path"; else echo "absent $path"; fi
done
"""
    (ROOT / "setup_pilot.sh").write_text(setup)
    print(json.dumps({"cases": len(ordered), "phase_a": phase_a, "payload_sha256": payload_sha,
                      "setup_bytes": len(setup)}, indent=1))


if __name__ == "__main__":
    main()
