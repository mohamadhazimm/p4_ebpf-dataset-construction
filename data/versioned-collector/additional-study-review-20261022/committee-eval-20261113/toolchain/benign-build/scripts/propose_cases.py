"""Proposed toolchain-matched benign case list (NOT collected; offline proposal only).

    /usr/bin/python3 -I scripts/propose_cases.py <benign-build dir>

Allocation: the static malware's toolchain mix per mode (toolchain_classes.json), scaled to 59 x86-64 and 28 i386
benign cases by largest remainder, then split inside a class by the malware's start-up sub-patterns (old-glibc
generation, UPX stub generation, Go release). Within old glibc only programs that link the pthread start-up are used
(sort, sqlite3, xz, zstd), because every old-glibc malware start-up contains it (set_tid_address/set_robust_list...);
within uClibc the threaded/non-threaded ratio follows the malware (linuxthreads start-up in 1 of 10 / 1 of 8).
musl and glibc>=2.35 slots reuse the dataset's own benign cases (already guest-validated). Each case uses the
program's dataset task (benign_workloads.py) at an activity bin; Go tools use the same task kind with their own flags.
Splits keep whole projects together: existing projects inherit the dataset's benign split, new Go projects are
assigned so the class counts are not one-sided.
"""
import hashlib
import json
import sys
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
L, M, H = "light", "medium", "heavy"

# (mode, class, toolchain dir, program, bin)
X64 = [
    # old glibc 21: CentOS 7 2.17 (Qilin start-up generation) 11, focal 2.31 (Akira CET+uname) 7, bionic 2.27 (Kaiten) 3
    *[("glibc-static<2.35", "glibc2.17-centos7-x86_64", p, b) for p, b in
      [("sort", L), ("sort", M), ("sort", H), ("sqlite3", L), ("sqlite3", M), ("sqlite3", H), ("xz", L), ("xz", M),
       ("xz", H), ("zstd", L), ("zstd", M)]],
    *[("glibc-static<2.35", "glibc2.31-focal-x86_64", p, b) for p, b in
      [("sort", M), ("sort", H), ("sqlite3", M), ("sqlite3", H), ("xz", L), ("xz", H), ("zstd", M)]],
    *[("glibc-static<2.35", "glibc2.27-bionic-x86_64", p, b) for p, b in [("sort", L), ("sqlite3", H), ("zstd", H)]],
    # Go 16 by release: 1.13x2 1.16x2 1.18x4 1.20x2 1.21x1 1.24x5
    *[("go", "go1.13.15-amd64", p, b) for p, b in [("gojq", L), ("tar", M)]],
    *[("go", "go1.16.15-amd64", p, b) for p, b in [("gxz", M), ("sort", L)]],
    *[("go", "go1.18.10-amd64", p, b) for p, b in [("md5sum", L), ("xxhsum-go", M), ("gzip", H), ("cmp", L)]],
    *[("go", "go1.20.14-amd64", p, b) for p, b in [("hexdump", M), ("uniq", L)]],
    *[("go", "go1.21.13-amd64", p, b) for p, b in [("shasum", H)]],
    *[("go", "go1.24.13-amd64", p, b) for p, b in [("gojq", M), ("gxz", L), ("wc", M), ("hexdump", L), ("cat", H)]],
    # uClibc 11 (GCC 4.1.2 + uClibc 0.9.30.1): 10 without threads, 1 linuxthreads
    *[("uclibc", "uclibc0.9.30.1-gcc4.1.2-x86_64", p, b) for p, b in
      [("bzip2", L), ("bzip2", M), ("compress", L), ("compress", H), ("lz4", M), ("lz4", H), ("xxhsum", L),
       ("xxhsum", M), ("brotli", L), ("xmlwf", M), ("zstd", L)]],
    # UPX 7: 3.94 stub over uClibc (Mirai/Tsunami pattern) 3; 4.2.2 stub over glibc 2.31 threaded 2, glibc 2.35 1, musl 1
    # (zstd: linuxthreads inner start-up, like the UPX-packed Mirai)
    *[("upx", "upx3.94-uclibc0.9.30.1-gcc4.1.2-x86_64", p, b) for p, b in [("bzip2", M), ("lz4", L), ("zstd", H)]],
    *[("upx", "upx4.2.2-glibc2.31-focal-x86_64", p, b) for p, b in [("sort", L), ("xz", M)]],
    ("upx", "upx4.2.2-dataset-glibc2.35-x86_64", "sha256sum", M),
    ("upx", "upx4.2.2-dataset-musl-x86_64", "curl", None),
]
I386 = [
    *[("glibc-static<2.35", "glibc2.12-centos6-i686", p, b) for p, b in
      [("sort", L), ("sort", M), ("sqlite3", L), ("xz", M), ("zstd", H)]],
    *[("glibc-static<2.35", "glibc2.5-centos5-i386", p, b) for p, b in [("sort", H), ("sqlite3", M), ("xz", L)]],
    *[("uclibc", "uclibc0.9.30.1-gcc4.1.2-i686", p, b) for p, b in
      [("bzip2", L), ("bzip2", M), ("compress", M), ("lz4", H), ("xxhsum", L), ("brotli", M), ("xmlwf", L),
       ("zstd", M)]],
    *[("go", "go1.20.14-386", p, b) for p, b in [("gojq", L), ("md5sum", M), ("gxz", L), ("sort", M),
                                                ("xxhsum-go", H)]],
    ("go", "go1.22.12-386", "cmp", L),
    *[("upx", "upx3.94-uclibc0.9.30.1-gcc4.1.2-i686", p, b) for p, b in
      [("compress", L), ("lz4", M), ("xxhsum", M), ("xmlwf", H)]],
]
DATASET_CASES = {"amd64_static": {"glibc-static>=2.35": ["b2sum", "md5sum"], "musl": ["wget", "openssl"]},
                 "i386_static": {"musl": ["curl", "wget"]}}
PROJECT = {"sort": "coreutils", "sqlite3": "sqlite3", "xz": "xz-utils", "zstd": "libzstd", "bzip2": "bzip2",
           "compress": "ncompress", "lz4": "lz4", "xxhsum": "xxhash", "brotli": "brotli", "xmlwf": "expat",
           "sha256sum": "coreutils", "curl": "curl", "wget": "wget", "openssl": "openssl", "b2sum": "coreutils",
           "md5sum": "coreutils"}
GO_PROJECT = {"gojq": "github.com/itchyny/gojq", "xxhsum-go": "github.com/cespare/xxhash/v2",
              "gxz": "github.com/ulikunitz/xz"}  # every other Go tool is github.com/u-root/u-root
# builds not used (host check): u-root base64 v0.10.0-v0.14.0 (go1.18-go1.22 builds) drops the last base64 quantum
# (encoder not flushed) whenever the input length is not a multiple of 3; u-root tar v0.10.0-v0.16.0 refuses an
# absolute directory argument ("Rel: can't make ... relative"), which the dataset task requires.
BAD = {("go1.18.10", "base64"), ("go1.20.14", "base64"), ("go1.21.13", "base64"), ("go1.22.12", "base64"),
       ("go1.18.10", "tar"), ("go1.20.14", "tar"), ("go1.21.13", "tar"), ("go1.22.12", "tar"), ("go1.24.13", "tar")}
NEW_SPLIT = {"github.com/u-root/u-root": "train", "github.com/itchyny/gojq": "test",
             "github.com/cespare/xxhash/v2": "train", "github.com/ulikunitz/xz": "test"}


def main():
    sel = json.loads((STUDY / "data/benign/revision5-matched/benign_selection.json").read_text())
    rows_split = {}
    for c in sel:
        if "project" in c:
            rows_split[c["project"]] = "train" if c["split"] == "training" else "test"
    sys.argv = [sys.argv[0], str(BB)]
    sys.path.insert(0, str(BB / "scripts"))
    import host_check as hc  # noqa: E402  (target table, task specs, references)
    tg = {(t["toolchain"], t["program"]): t for t in hc.targets()}
    sc = {(r["toolchain"], r["program"]): r for r in json.loads((BB / "checks/startup_compare.json").read_text())["benign"]}
    cases = []
    for mode, table in (("amd64_static", X64), ("i386_static", I386)):
        for cls, tc, prog, b in table:
            t = tg[(tc, prog)]
            project = GO_PROJECT.get(prog, "github.com/u-root/u-root") if t["kind"] == "go" else PROJECT[prog]
            split = NEW_SPLIT.get(project) or rows_split[project]
            spec = hc.spec_for(t, b or "light")
            cases.append({"mode": mode, "toolchain_class": cls, "toolchain": tc, "project": project, "program": prog,
                          "kind": "new build" if not tc.startswith("upx4.2.2-dataset") else "UPX-packed dataset build",
                          "task": spec["task"], "activity_bin": b, "fixtures": spec["fixtures"],
                          "argv": spec["argv"], "expected_exit_codes": spec["rc_ok"],
                          "network_task": prog in hc.NETWORK, "binary": t["bin"], "binary_sha256": t["sha256"],
                          "inner_binary_sha256": t.get("inner_sha256"), "upx": t.get("upx"),
                          "split_suggestion": split,
                          "startup_prefix": sc.get((tc, prog), {}).get("startup_prefix"),
                          "startup_flags": sc.get((tc, prog), {}).get("flags"),
                          "startup_best_malware_match": sc.get((tc, prog), {}).get("best_malware_match")})
        for cls, progs in DATASET_CASES.get(mode, {}).items():
            for prog in progs:
                c = next(c for c in sel if c.get("mode") == mode and c.get("program") == prog)
                cases.append({"mode": mode, "toolchain_class": cls, "toolchain": "dataset (unchanged)",
                              "project": c["project"], "program": prog, "kind": "existing dataset case",
                              "task": c["task_kind"], "activity_bin": c["activity_bin"], "fixture_size": c["fixture_size"],
                              "task_variant": c["task_variant"], "network_task": c["network"],
                              "expected_exit_codes": "network case: accepted when it reaches the Sink (dataset rule)"
                              if c["network"] else [0],
                              "binary_sha256": c["sha256"], "split_suggestion": rows_split[c["project"]],
                              "dataset_split": c["split"]})
    for i, c in enumerate(cases):
        c["case_id"] = "tcm-%s-%03d" % ("x64" if c["mode"] == "amd64_static" else "i386", i)
        if c.get("expected_exit_codes") is None:
            c["expected_exit_codes"] = "network case: accepted when it reaches the Sink (dataset rule)"
    (BB / "proposed_cases.json").write_text(json.dumps(cases, indent=1))
    import collections
    cnt = collections.Counter((c["mode"], c["toolchain_class"]) for c in cases)
    for k in sorted(cnt):
        print(k, cnt[k])
    print("total", collections.Counter(c["mode"] for c in cases))
    print("split", collections.Counter((c["mode"], c["toolchain_class"], c["split_suggestion"]) for c in cases))


if __name__ == "__main__":
    main()
