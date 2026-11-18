"""Write benign-build/manifest.json: toolchains (provenance + verification), every built binary (sha256, toolchain,
versions, project, program, mode, ELF facts, the committee's static fingerprint class, host-check result, first 50
start-up calls, start-up comparison) and the proposed case list.

    /usr/bin/python3 -I scripts/make_manifest.py <benign-build dir>
"""
import hashlib
import json
import struct
import sys
import types
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
TCDIR = BB.parent
sys.modules["common"] = types.ModuleType("common")  # static_fingerprint only needs it in main()
sys.path.insert(0, str(TCDIR))
import static_fingerprint as SF  # noqa: E402  the committee's own static fingerprint rules
sys.argv = [sys.argv[0], str(BB)]
sys.path.insert(0, str(BB / "scripts"))
import host_check as hc  # noqa: E402

TOOLCHAINS = {
    "uclibc0.9.30.1-gcc4.1.2-x86_64": {"compiler": "GCC 4.1.2 + binutils 2.17 (FWL/impactlinux cross-compiler, 2009)",
                                       "libc": "uClibc 0.9.30.1 (linuxthreads.old)",
                                       "download": "downloads/uclibc-0.9.30.1-cross/verification.json"},
    "uclibc0.9.30.1-gcc4.1.2-i686": {"compiler": "GCC 4.1.2 + binutils 2.17 (FWL/impactlinux cross-compiler, 2009)",
                                     "libc": "uClibc 0.9.30.1 (linuxthreads.old)",
                                     "download": "downloads/uclibc-0.9.30.1-cross/verification.json"},
    "glibc2.17-centos7-x86_64": {"compiler": "host GCC 11.4.0 (Ubuntu 22.04) + binutils 2.38, --sysroot",
                                 "libc": "glibc 2.17-317.el7 static (CentOS 7.9.2009 glibc-static/-devel/-headers, "
                                         "kernel-headers 3.10.0-1160)", "download": "downloads/centos7-x86_64/verification.json"},
    "glibc2.27-bionic-x86_64": {"compiler": "host GCC 11.4.0 (Ubuntu 22.04) + binutils 2.38, --sysroot",
                                "libc": "glibc 2.27-3ubuntu1 static (Ubuntu 18.04 libc6-dev, linux-libc-dev 4.15.0-20.21)",
                                "download": "downloads/ubuntu-bionic-amd64/verification.json"},
    "glibc2.31-focal-x86_64": {"compiler": "host GCC 11.4.0 (Ubuntu 22.04) + binutils 2.38, --sysroot",
                               "libc": "glibc 2.31-0ubuntu9 static (Ubuntu 20.04 libc6-dev, linux-libc-dev 5.4.0-26.30)",
                               "download": "downloads/ubuntu-focal-amd64/verification.json"},
    "glibc2.12-centos6-i686": {"compiler": "host GCC 11.4.0 -m32 + binutils 2.38, --sysroot, 32-bit libgcc from "
                                           "Ubuntu lib32gcc-11-dev 11.4.0-1ubuntu1~22.04.3",
                               "libc": "glibc 2.12-1.212.el6 static (CentOS 6.10 i686), kernel-headers 2.6.32-754",
                               "download": "downloads/centos6-i686/verification.json"},
    "glibc2.5-centos5-i386": {"compiler": "host GCC 11.4.0 -m32 -fgnu89-inline + binutils 2.38, --sysroot, 32-bit "
                                          "libgcc from Ubuntu lib32gcc-11-dev 11.4.0-1ubuntu1~22.04.3",
                              "libc": "glibc 2.5-123 static (CentOS 5.11 i386 glibc-devel), kernel-headers 2.6.18-398",
                              "download": "downloads/centos5-i386/verification.json"},
}
UPXV = {"upx3.94": ("UPX 3.94 (Ubuntu 18.04 upx-ucl 3.94-4)", "downloads/upx-ucl-bionic/verification.json"),
        "upx4.2.2": ("UPX 4.2.2 (Ubuntu 24.04 upx-ucl 4.2.2-3, run with its own noble loader/libraries)",
                     "downloads/upx-ucl-noble/verification.json"),
        "upx3.96": ("UPX 3.96 (Ubuntu 22.04 upx-ucl 3.96-3)", "downloads/upx-ucl-jammy/verification.json"),
        "upx5.0.2": ("UPX 5.0.2 (GitHub release, sha256 = GitHub asset digest)", "downloads/upx-5.0.2-github")}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def elf(path):
    b = path.read_bytes()
    cls = b[4]
    e_type, e_machine = struct.unpack_from("<HH", b, 16)
    if cls == 2:
        phoff, = struct.unpack_from("<Q", b, 32); phentsize, phnum = struct.unpack_from("<HH", b, 54)
    else:
        phoff, = struct.unpack_from("<I", b, 28); phentsize, phnum = struct.unpack_from("<HH", b, 42)
    types_ = [struct.unpack_from("<I", b, phoff + i * phentsize)[0] for i in range(phnum)]
    f = SF.fingerprint(b)
    return {"elf_class": 64 if cls == 2 else 32, "e_type": e_type, "e_machine": e_machine, "pt_interp": 3 in types_,
            "pt_dynamic": 2 in types_, "static_et_exec": e_type == 2 and 3 not in types_ and 2 not in types_,
            "size": len(b), "gcc_comment": f.get("comment"), "go_version_string": f.get("go_version"),
            "committee_static_class": SF.classify(f)}


def load_json(p):
    p = BB / p
    if p.is_dir():
        return {"dir": str(p.relative_to(BB)), "files": {q.name: sha(q) for q in sorted(p.iterdir())}}
    return json.loads(p.read_text()) if p.exists() else None


def toolchain_info(tc):
    if tc in TOOLCHAINS:
        return TOOLCHAINS[tc]
    if tc.startswith("go1."):
        v = tc.rsplit("-", 1)[0]
        return {"compiler": "official Go %s linux-amd64 (CGO_ENABLED=0, GOARCH=%s)" % (
            v, "386" if tc.endswith("386") else "amd64"), "libc": "none (Go runtime)",
            "download": "downloads/go/verification.json"}
    if tc.startswith("upx"):
        tag, inner = tc.split("-", 1)
        return {"packer": UPXV[tag][0], "inner_toolchain": inner, "download": UPXV[tag][1]}
    if tc.startswith("dataset-"):
        return {"note": "copy of the dataset's own benign build (unchanged), used as a UPX input / reference"}
    return {}


def main():
    checks = {}
    for f in sorted((BB / "checks").glob("host_check-light*.json")):
        for r in json.loads(f.read_text())["results"]:
            checks[(r["toolchain"], r["program"])] = r
    sc = {(r["toolchain"], r["program"]): r for r in json.loads((BB / "checks/startup_compare.json").read_text())["benign"]}
    bins = []
    for t in hc.targets():
        key = (t["toolchain"], t["program"])
        p = BB / t["bin"]
        r = checks.get(key, {})
        light = r.get("runs", {}).get("light", {})
        rec = {**{k: t[k] for k in ("toolchain", "toolchain_class", "mode", "project", "program", "bin", "kind")},
               "sha256": sha(p), "versions": toolchain_info(t["toolchain"]), "elf": elf(p),
               "module": t.get("module"), "upx": t.get("upx"), "inner_sha256": t.get("inner_sha256"),
               "host_check_light": {k: light.get(k) for k in ("task", "argv", "rc", "timeout", "seconds", "output_ok",
                                                              "check")},
               "startup_first50": r.get("startup50"),
               "startup_compare": {k: sc.get(key, {}).get(k) for k in ("flags", "startup_prefix", "best_malware_match",
                                                                       "flag_vector_seen_in_malware_of_class")}}
        assert rec["sha256"] == t["sha256"], key
        bins.append(rec)
    downloads = {}
    for d in sorted((BB / "downloads").iterdir()):
        v = d / "verification.json"
        downloads[d.name] = json.loads(v.read_text()) if v.exists() else {
            "files": {q.name: sha(q) for q in sorted(d.iterdir()) if q.is_file()}}
    upx5 = BB / "downloads/upx-5.0.2-github/upx-5.0.2-amd64_linux.tar.xz"
    downloads["upx-5.0.2-github"] = {"url": "https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-amd64_linux.tar.xz",
                                     "sha256": sha(upx5), "size": upx5.stat().st_size,
                                     "github_asset_digest": "sha256:ddc2654063fe4dc80d95b420788494e4db078ebb01a650692d623b5a9906e61e",
                                     "verified": sha(upx5) == "ddc2654063fe4dc80d95b420788494e4db078ebb01a650692d623b5a9906e61e"}
    l32 = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/cohort-expansion-"
               "100x100-v18-20261021/i386-toolchain-probe/20261021T153000Z/debs/lib32gcc-11-dev_11.4.0-1ubuntu1~22.04.3_amd64.deb")
    downloads["lib32gcc-11 (reused)"] = {
        "deb": str(l32), "sha256": sha(l32),
        "verification": "deb sha256 listed in the jammy-updates (and jammy-security) main/binary-amd64 Packages whose "
                        "hash is in the InRelease signed by the Ubuntu Archive 2018 key (gpgv good signature); the "
                        "25 regular files in toolchains/lib32gcc-11 are byte-identical to the package's 11/32 directory"}
    sources = json.loads((BB / "sources/sources.json").read_text())
    amalg = (BB / "sources/sqlite3-amalgamation/SHA256SUMS").read_text()
    cases = json.loads((BB / "proposed_cases.json").read_text())
    builds = {}
    for res in sorted((BB / "builds").glob("*/results.json")):
        for project, rec in json.loads(res.read_text()).items():
            builds["%s/%s" % (res.parent.name, project)] = {k: rec.get(k) for k in ("returncode", "seconds", "log",
                                                                                    "script", "CC", "CFLAGS", "LDFLAGS")} | {
                "programs": {p: v.get("status") for p, v in rec["programs"].items()}}
    gobuilds = {f.name: json.loads(f.read_text()) for f in sorted((BB / "gobuild").glob("results-*.json"))}
    for g in gobuilds.values():
        for m in g["modules"]:
            m.pop("go.mod", None)
    manifest = {"schema": "benign-build manifest v1 (2026-11-13)",
                "purpose": "benign programs rebuilt with the toolchains the dataset's static malware were built with; "
                           "host-side only, nothing collected",
                "downloads": downloads, "toolchains": {tc: toolchain_info(tc) for tc in sorted({b["toolchain"] for b in bins})},
                "sources": sources, "sqlite3_amalgamation_sha256": amalg, "c_builds": builds, "go_builds": gobuilds,
                "upx_packing": json.loads((BB / "builds/upx-results.json").read_text()),
                "binaries": bins, "proposed_cases": cases,
                "counts": {"binaries": len(bins), "cases": len(cases)}}
    (BB / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print("binaries", len(bins), "cases", len(cases), "->", BB / "manifest.json")
    bad = [(b["toolchain"], b["program"]) for b in bins if not b["elf"]["static_et_exec"]]
    print("non-static outputs:", bad)
    mism = [(b["toolchain"], b["program"], b["elf"]["committee_static_class"]) for b in bins
            if not b["toolchain"].startswith("dataset")]
    import collections
    print(collections.Counter((b["toolchain_class"], b["elf"]["committee_static_class"]) for b in bins))


if __name__ == "__main__":
    main()
