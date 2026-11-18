"""Build benign Go programs (static, CGO_ENABLED=0) with one official Go release for amd64 and 386.

    /usr/bin/python3 -I scripts/build_go.py <benign-build dir> <goversion> <spec> [<spec> ...]
    spec = <module>@<version>:<package>=<program>[,<package>=<program>...]

Module sources come only from proxy.golang.org; the go command verifies every module zip against the signed
checksum database sum.golang.org (GOSUMDB default, GONOSUMDB/GOFLAGS=-insecure not set) and records the hashes in
go.sum; `go mod verify` re-checks the module cache afterwards. GOPATH, GOMODCACHE, GOCACHE, HOME and
XDG_CONFIG_HOME all point inside benign-build/gopath, so nothing outside the build folder is written or read
(GOENV=off ignores the user's go env file; GOTOOLCHAIN=local prevents toolchain switching).
"""
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
GOV = sys.argv[2]
SPECS = sys.argv[3:]
GOROOT = BB / "toolchains/go" / GOV / "go"


def env_for(arch):
    gp = BB / "gopath"
    home = gp / "home"
    home.mkdir(parents=True, exist_ok=True)
    return {"PATH": "%s/bin:/usr/bin:/bin" % GOROOT, "GOROOT": str(GOROOT), "GOPATH": str(gp),
            "GOMODCACHE": str(gp / "pkg/mod"), "GOCACHE": str(gp / "cache" / GOV), "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"),
            "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org", "GO111MODULE": "on",
            "GOFLAGS": "" if GOV.startswith("go1.13") else "-mod=mod", "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": arch, "GOTOOLCHAIN": "local",
            "GOENV": "off", "GOTELEMETRY": "off", "LC_ALL": "C"}


def elf_facts(path):
    b = path.read_bytes()
    cls = b[4]
    e_type, e_machine = struct.unpack_from("<HH", b, 16)
    if cls == 2:
        phoff, = struct.unpack_from("<Q", b, 32); phentsize, phnum = struct.unpack_from("<HH", b, 54)
    else:
        phoff, = struct.unpack_from("<I", b, 28); phentsize, phnum = struct.unpack_from("<HH", b, 42)
    types = [struct.unpack_from("<I", b, phoff + i * phentsize)[0] for i in range(phnum)]
    return {"elf": True, "class": 64 if cls == 2 else 32, "e_type": e_type, "e_machine": e_machine,
            "pt_interp": 3 in types, "pt_dynamic": 2 in types, "size": len(b), "sha256": hashlib.sha256(b).hexdigest()}


def run(cmd, cwd, env, log):
    with open(log, "a") as lf:
        lf.write("$ %s\n" % " ".join(cmd)); lf.flush()
        return subprocess.run(cmd, cwd=cwd, env=env, stdout=lf, stderr=subprocess.STDOUT).returncode


def main():
    root = BB / "gobuild" / GOV
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    log = BB / "logs" / ("build-go-%s.log" % GOV)
    log.write_text("")
    env = env_for("amd64")
    run(["go", "version"], root, env, log)
    results = {"go": GOV, "goroot": str(GOROOT.relative_to(BB)), "specs": SPECS, "modules": [], "programs": []}
    for n, spec in enumerate(SPECS):
        mod, rest = spec.split(":", 1)
        work = root / str(n)
        work.mkdir()
        run(["go", "mod", "init", "benignbuild"], work, env, log)
        rc = run(["go", "get", "-d", mod], work, env, log)
        if rc != 0:
            rc = run(["go", "get", mod], work, env, log)
        modrec = {"module": mod, "get_rc": rc, "workdir": str(work.relative_to(BB))}
        for pair in rest.split(","):
            pkg, prog = pair.split("=")
            for arch, machine in (("amd64", 62), ("386", 3)):
                out = BB / "bin" / ("go%s-%s" % (GOV[2:], arch)) / prog
                out.parent.mkdir(parents=True, exist_ok=True)
                t0 = time.time()
                rc = run(["go", "build", "-o", str(out), pkg], work, env_for(arch), log)
                rec = {"module": mod, "package": pkg, "program": prog, "arch": arch, "rc": rc,
                       "seconds": round(time.time() - t0, 1)}
                if rc == 0 and out.exists():
                    f = elf_facts(out)
                    ok = f["e_type"] == 2 and not f["pt_interp"] and not f["pt_dynamic"] and f["e_machine"] == machine
                    rec.update(f, status="ok" if ok else "bad_elf", bin=str(out.relative_to(BB)))
                    if not ok:
                        out.unlink()
                else:
                    rec["status"] = "build_failed"
                results["programs"].append(rec)
                print("%-10s %-6s %-36s %-10s %s" % (GOV, arch, mod, prog, rec["status"]), flush=True)
        modrec["mod_verify_rc"] = run(["go", "mod", "verify"], work, env, log)
        for f in ("go.mod", "go.sum"):
            if (work / f).exists():
                modrec[f] = (work / f).read_text()
        results["modules"].append(modrec)
    (BB / "gobuild" / ("results-%s.json" % GOV)).write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
