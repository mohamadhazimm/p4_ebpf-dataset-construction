"""Pack already-built static benign programs with UPX (signed Ubuntu upx-ucl builds or the digest-verified UPX
release) into bin/<upx>-<source toolchain>/<program>.

    /usr/bin/python3 -I scripts/pack_upx.py <benign-build dir> <upx tag> <source toolchain> [<program> ...]
    upx tag: upx3.91 (xenial) | upx3.94 (bionic) | upx3.95 (focal) | upx3.96 (jammy) | upx4.2.2 (noble) |
             upx5.0.2 (GitHub release, digest-verified)
"""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
TAG, SRC = sys.argv[2], sys.argv[3]
UPX = {"upx3.91": "upx-ucl-xenial", "upx3.94": "upx-ucl-bionic", "upx3.95": "upx-ucl-focal",
       "upx3.96": "upx-ucl-jammy"}


def upx_cmd():
    if TAG == "upx5.0.2":
        return [str(BB / "toolchains/upx-5.0.2/upx-5.0.2-amd64_linux/upx")], {}
    if TAG == "upx4.2.2":  # Ubuntu noble build, run with noble's own loader and libraries
        s = BB / "toolchains/upx-ucl-noble/sysroot/usr/lib/x86_64-linux-gnu"
        return [str(s / "ld-linux-x86-64.so.2"), "--library-path", str(s),
                str(BB / "toolchains/upx-ucl-noble/sysroot/usr/bin/upx-ucl")], {}
    s = BB / "toolchains" / UPX[TAG] / "sysroot"
    return [str(s / "usr/bin/upx-ucl")], {"LD_LIBRARY_PATH": "%s:%s" % (s / "usr/lib/x86_64-linux-gnu",
                                                                         s / "lib/x86_64-linux-gnu")}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    cmd, extra = upx_cmd()
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", **extra}
    version = subprocess.run(cmd + ["--version"], env=env, capture_output=True, text=True).stdout.splitlines()[0]
    src = BB / "bin" / SRC
    out = BB / "bin" / ("%s-%s" % (TAG, SRC))
    out.mkdir(parents=True, exist_ok=True)
    progs = sys.argv[4:] or sorted(p.name for p in src.iterdir() if p.is_file())
    resfile = BB / "builds" / "upx-results.json"
    res = json.loads(resfile.read_text()) if resfile.exists() else {}
    for prog in progs:
        dst = out / prog
        shutil.copy2(src / prog, dst)
        r = subprocess.run(cmd + ["-9", "-q", str(dst)], env=env, capture_output=True, text=True)
        ok = r.returncode == 0
        rec = {"upx": TAG, "upx_version": version, "source": str((src / prog).relative_to(BB)),
               "source_sha256": sha(src / prog), "rc": r.returncode, "output": (r.stdout + r.stderr)[-400:],
               "status": "ok" if ok else "pack_failed"}
        if ok:
            rec.update(bin=str(dst.relative_to(BB)), sha256=sha(dst), size=dst.stat().st_size)
        else:
            dst.unlink()
        res["%s-%s/%s" % (TAG, SRC, prog)] = rec
        print(TAG, SRC, prog, rec["status"], flush=True)
    resfile.write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
