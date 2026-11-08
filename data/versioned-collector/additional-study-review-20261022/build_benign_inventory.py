"""Unified benign-program inventory for the matched cohort (offline; reads ELF headers only, executes nothing).

Unions every authenticated benign build already in the study tree, verifies each binary's real native mode from its
ELF header with strict linkage (amd64_static / amd64_dynamic / i386_static), dedups by SHA-256, and records
project/program so the matched cohort can keep training and validation on disjoint projects.
Sources: redesign amd64 build inventory; i386 held-out release payload; additional-benign 12-project builds;
amd64 + i386 static musl network clients.
"""

import io, json, sys, tarfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent                    # .../additional-study-review-20261022
VC = ROOT.parent                                          # .../versioned-collector
STUDY = VC.parents[1]
sys.path.insert(0, str(VC / "cohort-100x100-v18-20261021"))
import prepare_selection as ps

REDESIGN = VC / "cohort-100x100-v18-20261021/redesign-native-x64"
RELEASE = (VC / "cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z"
           / "collection-readiness/20261021T203401085156Z")
ADDL = sorted((ROOT / "additional-benign-builds").glob("*/result.json"))
NET = {"amd64": ROOT / "amd64-network-builds/20261024T172720Z/bin",
       "i386": ROOT / "i386-network-builds/20261024T163419Z/bin"}
NET_PROJECT = {"curl": "curl", "wget": "wget", "openssl": "openssl", "ftp": "inetutils", "logger": "inetutils",
               "ping": "inetutils", "telnet": "inetutils", "tftp": "inetutils", "traceroute": "inetutils",
               "whois": "inetutils"}
ADDL_PROJECTS = ("bison", "bmake", "brotli", "byacc", "diffstat", "dos2unix", "expat", "flex", "indent",
                 "lz4", "ncompress", "xxhash")
MODES = {"native_x86_64_static": "amd64_static", "native_x86_64_dynamic": "amd64_dynamic",
         "native_i386_static": "i386_static"}
OUT = STUDY / "data/benign/revision5-matched/benign_inventory.json"


def mode_of(data: bytes):
    try:
        return MODES.get(ps.inspect_elf(data[:4096], strict_linkage=True)[0])
    except Exception:
        return None


def main():
    import hashlib
    inv = {}

    def add(data, project, program, source, locator):
        if not data or data[:4] != b"\x7fELF":
            return
        sha = hashlib.sha256(data).hexdigest()
        if sha in inv:
            return
        mode = mode_of(data)
        if mode is None:
            return
        inv[sha] = {"sha256": sha, "project": project, "program": program, "mode": mode,
                    "source": source, "locator": locator}

    # 1) redesign amd64 build inventory
    audit = json.loads((REDESIGN / "preparation-audit.json").read_text())
    for rec in audit["verified_build_candidates"]:
        p = REDESIGN / rec["path"]
        if p.is_file():
            add(p.read_bytes(), rec["project"], p.name, "redesign", str(p.relative_to(STUDY)))
    # 2) i386 held-out release payload (benign cases)
    manifest = json.loads((RELEASE / "manifest.json").read_text())
    with tarfile.open(RELEASE / "payload.tgz") as tar:
        for c in manifest["cases"]:
            if c.get("label") != "benign" or not c.get("payload_path"):
                continue
            try:
                data = tar.extractfile(c["payload_path"]).read()
            except Exception:
                continue
            add(data, c["project"], c["program"], "i386-release", f"payload.tgz:{c['payload_path']}")
    # 3) additional-benign 12-project builds
    for res in ADDL:
        for e in json.loads(res.read_text()).get("executables") or []:
            p = Path(e.get("path", ""))
            if not p.is_file():
                continue
            proj = e.get("project") or next((x for x in ADDL_PROJECTS if f"/{x}" in str(p) or p.name.startswith(x)), "unknown")
            add(p.read_bytes(), proj, p.name, "additional-benign", str(p.relative_to(STUDY)))
    # 4) static musl network clients
    for arch, d in NET.items():
        for p in sorted(d.glob("*")):
            if p.is_file():
                add(p.read_bytes(), NET_PROJECT.get(p.name, p.name), p.name, f"musl-net-{arch}",
                    str(p.relative_to(STUDY)))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(sorted(inv.values(), key=lambda r: (r["mode"], r["project"], r["program"])),
                              indent=1))
    table = defaultdict(lambda: defaultdict(set))
    for r in inv.values():
        table[r["mode"]][r["project"]].add(r["program"])
    print(f"benign binaries: {len(inv)}")
    for mode in ("amd64_static", "amd64_dynamic", "i386_static"):
        projs = table[mode]
        n = sum(len(v) for v in projs.values())
        print(f"\n[{mode}] programs={n} projects={len(projs)}")
        for proj in sorted(projs, key=lambda k: -len(projs[k])):
            progs = sorted(projs[proj])
            print(f"  {proj:12s} {len(progs):3d}  {', '.join(progs[:10])}{' ...' if len(progs) > 10 else ''}")
    print("\nWROTE", OUT)


if __name__ == "__main__":
    main()
