"""Host-side checks of the rebuilt BENIGN programs (unprivileged, no VM).

For every built program: run the dataset's task for that program (benign_workloads.py arguments and fixtures; for the
Go programs the same task kind with that tool's own flags) in a private directory with stdin=/dev/null and a 20-s
timeout, verify the output (against the dataset's glibc-2.35 build of the same program run with the same arguments,
or an independent Python computation), record the exit code, then record the start-up: the first 50 system calls of
the main process after execve under `strace -f`.

    /usr/bin/python3 -I scripts/host_check.py <benign-build dir> [--bins light[,medium,heavy]] [--only SUBSTR]
"""
import base64
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
ARGS = sys.argv[2:]
BINS = ARGS[ARGS.index("--bins") + 1].split(",") if "--bins" in ARGS else ["light"]
ONLY = ARGS[ARGS.index("--only") + 1] if "--only" in ARGS else None
ASR = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/"
           "additional-study-review-20261022")
STUDY = ASR.parents[2]
sys.path.insert(0, str(ASR))
import benign_workloads as bw  # noqa: E402  the dataset's own workload registry (not downloaded code)

TIMEOUT = 20
INV = {r["sha256"]: r["locator"] for r in json.loads((STUDY / "data/benign/revision5-matched/benign_inventory.json").read_text())}
I386_HOLD = STUDY / "data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z/project-builds"
PAYLOAD_ON_DISK = {  # payload.tgz members of the i386 release, resolved to the identical on-disk build outputs
    "0596d96adc7e": I386_HOLD / "sqlite3/20261021T202033838580Z/source/sqlite3",
    "e9febbc9e290": I386_HOLD / "cpio/20261021T201632686445Z/source/src/cpio",
    "11f76c321381": I386_HOLD / "m4/20261021T201608995369Z/source/src/m4",
}


def reference_bins():
    """program -> (path, provenance) of the dataset's glibc-2.35 build (static amd64 preferred), else the host tool."""
    sel = json.loads((STUDY / "data/benign/revision5-matched/benign_selection.json").read_text())
    pref = {"amd64_static": 0, "amd64_dynamic": 1, "i386_static": 2}
    best = {}
    for c in sel:
        if "program" not in c:
            continue
        loc = INV[c["sha256"]]
        if loc.startswith("payload.tgz:"):
            path = PAYLOAD_ON_DISK.get(c["sha256"][:12])
        else:
            path = STUDY / loc
        if path is None or not path.exists():
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != c["sha256"]:
            continue
        k = c["program"]
        if k not in best or pref[c["mode"]] < best[k][2]:
            best[k] = (str(path), "dataset %s %s sha256=%s" % (c["mode"], k, c["sha256"]), pref[c["mode"]])
    out = {k: (v[0], v[1]) for k, v in best.items()}
    for host in ("sha1sum", "sha512sum", "uniq"):
        out.setdefault(host, ("/usr/bin/" + host, "host Ubuntu 22.04 coreutils 8.32 (glibc 2.35)"))
    return out


REF = reference_bins()
GO_SPECS = {  # Go tool -> (dataset task kind, fixtures, argv tokens, checker)
    "md5sum": ("hasher", [("in", "stream")], [{"fix": "in"}], "md5"),
    "shasum": ("hasher", [("in", "stream")], ["-a", "256", {"fix": "in"}], "sha256"),
    "base64": ("encoder", [("in", "stream")], [{"fix": "in"}], "base64"),
    "gzip": ("compressor", [("in", "stream")], ["-c", {"fix": "in"}], "gunzip"),
    "sort": ("sort", [("in", "stream")], [{"fix": "in"}], "ref:sort"),
    "uniq": ("uniq", [("in", "stream")], [{"fix": "in"}], "ref:uniq"),
    "wc": ("wc", [("in", "stream")], [{"fix": "in"}], "wcnum"),
    "hexdump": ("od", [("in", "stream")], [{"fix": "in"}], "godump"),
    "cmp": ("cmp", [("a", "stream"), ("b", "stream_copy")], [{"fix": "a"}, {"fix": "b"}], "cmp"),
    "cat": ("cat", [("in", "stream")], [{"fix": "in"}], "cat"),
    "tar": ("tar", [("tree", "tree")], ["-c", "-f", {"out": "o.tar"}, {"fix": "tree"}], "tar"),
    "gojq": ("jq", [("in", "json")], ["-c", ".", {"fix": "in"}], "json"),
    "xxhsum-go": ("xxhsum", [("in", "stream")], [{"fix": "in"}], "ref:xxhsum:first"),
    "gxz": ("compressor", [("in", "stream")], ["-c", {"fix": "in"}], "unxz"),
}
C_CHECK = {"md5sum": "md5", "sha1sum": "sha1", "sha256sum": "sha256", "sha512sum": "sha512", "b2sum": "blake2b",
           "cksum": "ref:cksum", "sum": "ref:sum", "xxhsum": "ref:xxhsum", "base64": "base64", "base32": "base32",
           "basenc": "base64", "gzip": "gunzip", "bzip2": "bunzip2", "xz": "unxz", "brotli": "unbrotli",
           "compress": "uncompress", "lz4": "unlz4", "zstd": "unzstd", "sort": "ref:sort", "uniq": "ref:uniq",
           "wc": "ref:wc", "od": "ref:od", "cmp": "cmp", "m4": "ref:m4", "xmlwf": "xmlwf", "cpio": "cpio",
           "sqlite3": "ref:sqlite3"}
TOOLCLASS = [("dataset-glibc", "glibc-static>=2.35"), ("dataset-musl", "musl"), ("uclibc", "uclibc"),
             ("glibc", "glibc-static<2.35"), ("go1", "go"), ("upx", "upx")]
NETWORK = {"curl": ["--version"], "wget": ["--version"], "openssl": ["version"]}  # Sink tasks: not host-runnable


def targets():
    out = []
    for res in sorted((BB / "builds").glob("*/results.json")):
        tc = res.parent.name
        for project, rec in json.loads(res.read_text()).items():
            for prog, p in rec["programs"].items():
                if p.get("status") == "ok":
                    out.append({"toolchain": tc, "mode": rec["mode"], "project": project, "program": prog,
                                "bin": p["bin"], "sha256": p["sha256"], "kind": "c"})
    for res in sorted((BB / "gobuild").glob("results-*.json")):
        r = json.loads(res.read_text())
        for p in r["programs"]:
            if p.get("status") == "ok":
                out.append({"toolchain": "go%s-%s" % (r["go"][2:], p["arch"]), "go": r["go"],
                            "mode": "amd64_static" if p["arch"] == "amd64" else "i386_static",
                            "project": p["module"].split("@")[0], "module": p["module"], "program": p["program"],
                            "bin": p["bin"], "sha256": p["sha256"], "kind": "go"})
    upx = BB / "builds/upx-results.json"
    if upx.exists():
        base = {(t["toolchain"], t["program"]): t for t in out}
        for key, rec in json.loads(upx.read_text()).items():
            if rec.get("status") != "ok":
                continue
            tcdir, prog = key.split("/")
            src_tc = tcdir.split("-", 1)[1]
            b = base[(src_tc, prog)]
            out.append({**b, "toolchain": tcdir, "bin": rec["bin"], "sha256": rec["sha256"], "kind": b["kind"],
                        "upx": rec["upx"], "inner_toolchain": src_tc, "inner_sha256": rec["source_sha256"]})
    for t in out:
        t["toolchain_class"] = next(c for p, c in TOOLCLASS if t["toolchain"].startswith(p))
    return out


FIXCACHE = {}


def spec_for(t, activity):
    if t["kind"] == "go":
        task, fx, argv, chk = GO_SPECS[t["program"]]
        sizes = {"stream": bw.MB[activity], "stream_copy": bw.MB[activity], "json": bw.MB[activity],
                 "tree": bw.FILES[activity]}
        return {"task": task, "fixtures": [(r, k, sizes[k]) for r, k in fx], "argv": argv, "rc_ok": [0],
                "check": chk}
    if t["program"] in NETWORK:
        return {"task": t["program"] + " (network task, Sink only: host smoke test)", "fixtures": [],
                "argv": NETWORK[t["program"]], "rc_ok": [0], "check": "version"}
    s = bw.workload(t["program"], activity)
    return {"task": t["program"], **s, "check": C_CHECK[t["program"]]}


def resolve(spec, cwd):
    paths = {role: bw.materialize(kind, size, BB / "checks/fixtures", FIXCACHE) for role, kind, size in spec["fixtures"]}
    return paths, bw.resolve_argv(spec, paths, ".")


def run(binpath, argv, cwd, strace_out=None):
    cwd.mkdir(parents=True, exist_ok=True)
    cmd = [str(binpath)] + argv
    if strace_out:
        cmd = ["strace", "-f", "-o", str(strace_out), "--"] + cmd
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT,
                           env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(cwd)})
        return {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "seconds": round(time.time() - t0, 2),
                "timeout": False}
    except subprocess.TimeoutExpired:
        return {"rc": None, "stdout": b"", "stderr": b"", "seconds": TIMEOUT, "timeout": True}


def first_calls(trace, n=50):
    main, seen, names = None, False, []
    for line in open(trace, errors="replace"):
        m = re.match(r"^(\d+)\s+([a-z_0-9]+)\(", line)
        if not m:
            continue
        pid, name = m.groups()
        main = main or pid
        if pid != main:
            continue
        if not seen:
            seen = name == "execve" and "= 0" in line
            continue
        names.append(name)
        if len(names) >= n:
            break
    return names


REFCACHE = {}


def ref_out(prog, argv, key):
    if key not in REFCACHE:
        path, prov = REF[prog]
        cwd = BB / "checks/refrun" / re.sub(r"[^A-Za-z0-9_.-]", "_", key)
        shutil.rmtree(cwd, ignore_errors=True)
        r = run(path, argv, cwd)
        REFCACHE[key] = (r, prov)
    return REFCACHE[key]


def go_dump(data):
    """encoding/hex.Dump format (what u-root hexdump prints)."""
    out = io.StringIO()
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = ""
        for i in range(16):
            hx += ("%02x " % chunk[i]) if i < len(chunk) else "   "
            if i == 7:
                hx += " "
        asc = "".join(chr(c) if 32 <= c <= 126 else "." for c in chunk)
        out.write("%08x  %s |%s|\n" % (off, hx, asc))
    return out.getvalue().encode()


def decompress_with(prog, data):
    path, _ = REF[prog] if prog in REF else ("/usr/bin/" + prog, "host")
    r = subprocess.run([path, "-d", "-c"], input=data, capture_output=True, timeout=60)
    return r.stdout if r.returncode == 0 else None


def verify(t, spec, paths, res, cwd, argv, activity):
    chk = spec["check"]
    out = res["stdout"]
    src = paths.get("in") or paths.get("a")
    data = Path(src).read_bytes() if src and Path(src).is_file() else None
    if res["timeout"]:
        return False, "timeout"
    if res["rc"] not in spec["rc_ok"]:
        return False, "exit %s" % res["rc"]
    if chk in ("md5", "sha1", "sha256", "sha512", "blake2b"):
        want = getattr(hashlib, chk)(data).hexdigest()
        return out.split()[:1] == [want.encode()], "digest"
    if chk in ("base64", "base32"):
        want = (base64.b64encode if chk == "base64" else base64.b32encode)(data)
        return out.replace(b"\n", b"") == want, chk
    if chk in ("gunzip", "bunzip2", "unxz"):
        dec = {"gunzip": gzip.decompress, "bunzip2": bz2.decompress, "unxz": lzma.decompress}[chk]
        try:
            return dec(out) == data, chk + " round trip"
        except Exception as e:
            return False, "%s failed: %s" % (chk, e)
    if chk in ("unbrotli", "uncompress", "unlz4", "unzstd"):
        prog = {"unbrotli": "brotli", "uncompress": "compress", "unlz4": "lz4", "unzstd": "zstd"}[chk]
        blob = out
        if chk == "unlz4":
            blob = (cwd / "o.lz4").read_bytes() if (cwd / "o.lz4").exists() else b""
        if chk == "unzstd":
            blob = (cwd / "o.zst").read_bytes() if (cwd / "o.zst").exists() else b""
        return decompress_with(prog, blob) == data, chk + " round trip via " + prog
    if chk == "cmp":
        return out == b"", "rc 0, no output"
    if chk == "version":
        return len(out) > 0, "version smoke test (network task needs the Sink)"
    if chk == "cat":
        return out == data, "bytes equal"
    if chk == "godump":
        return out == go_dump(data), "hex.Dump format"
    if chk == "xmlwf":
        return out == b"", "well-formed, no output"
    if chk == "json":
        try:
            return json.loads(out) == json.loads(Path(src).read_text()), "JSON equal"
        except Exception as e:
            return False, "json: %s" % e
    if chk == "tar":
        tree = paths["tree"]
        try:
            with tarfile.open(cwd / "o.tar") as tf:
                files = {Path(m.name).name: tf.extractfile(m).read() for m in tf.getmembers() if m.isfile()}
        except Exception as e:
            return False, "tar: %s" % e
        want = {p.name: p.read_bytes() for p in Path(tree).iterdir()}
        return files == want, "%d files equal" % len(want)
    if chk == "cpio":
        tree = bw.materialize("tree", bw.FILES[activity], BB / "checks/fixtures", FIXCACHE)
        want = {p.name: p.read_bytes() for p in Path(tree).iterdir()}
        got = {p.name: p.read_bytes() for p in cwd.iterdir() if p.is_file()}
        return got == want, "%d files equal" % len(want)
    if chk == "wcnum":  # u-root wc defines a word differently on binary data: compare lines and bytes
        r, prov = ref_out("wc", argv, "wc|" + activity)
        a, b = out.split(), r["stdout"].split()
        same = a[:1] == b[:1] and a[2:3] == b[2:3]
        return same, "lines+bytes equal to %s (words %s vs %s)" % (prov, a[1:2], b[1:2])
    if chk.startswith("ref:"):
        parts = chk.split(":")
        prog = parts[1]
        r, prov = ref_out(prog, argv, prog + "|" + activity + "|" + " ".join(argv))
        if r["rc"] != 0:
            return False, "reference failed rc=%s" % r["rc"]
        if len(parts) > 2:
            return out.split()[:1] == r["stdout"].split()[:1], "first field equal to " + prov
        return out == r["stdout"], "stdout equal to " + prov
    return False, "no checker " + chk


def main():
    tl = [t for t in targets() if not ONLY or ONLY in t["toolchain"] + "/" + t["program"]]
    results = []
    for t in tl:
        rec = {k: v for k, v in t.items()}
        rec["runs"] = {}
        for activity in BINS:
            spec = spec_for(t, activity)
            cwd = BB / "checks/run" / t["toolchain"] / t["program"] / activity
            shutil.rmtree(cwd, ignore_errors=True)
            paths, argv = resolve(spec, cwd)
            res = run(BB / t["bin"], argv, cwd)
            ok, how = verify(t, spec, paths, res, cwd, argv, activity)
            rec["runs"][activity] = {"task": spec["task"], "argv": argv, "rc": res["rc"], "timeout": res["timeout"],
                                     "seconds": res["seconds"], "output_ok": ok, "check": how,
                                     "stderr_tail": res["stderr"][-200:].decode("latin1")}
            shutil.rmtree(cwd, ignore_errors=True)
        spec = spec_for(t, "light")
        cwd = BB / "checks/run" / t["toolchain"] / t["program"] / "strace"
        shutil.rmtree(cwd, ignore_errors=True)
        paths, argv = resolve(spec, cwd)
        trace = BB / "checks/run" / t["toolchain"] / t["program"] / "strace.txt"
        run(BB / t["bin"], argv, cwd, strace_out=trace)
        rec["startup50"] = first_calls(trace)
        shutil.rmtree(cwd, ignore_errors=True)
        trace.unlink(missing_ok=True)
        results.append(rec)
        print("%-40s %-10s %s %s" % (t["toolchain"], t["program"],
                                     " ".join("%s:%s" % (a, "OK" if r["output_ok"] else "FAIL(%s)" % r["check"])
                                              for a, r in rec["runs"].items()),
                                     " ".join(rec["startup50"][:8])), flush=True)
    name = "host_check-%s%s.json" % ("-".join(BINS), ("-" + re.sub(r"\W", "_", ONLY)) if ONLY else "")
    (BB / "checks" / name).write_text(json.dumps({"bins": BINS, "timeout_s": TIMEOUT,
                                                  "references": {k: v[1] for k, v in REF.items()},
                                                  "results": results}, indent=1))
    print("WROTE", BB / "checks" / name)


if __name__ == "__main__":
    main()
