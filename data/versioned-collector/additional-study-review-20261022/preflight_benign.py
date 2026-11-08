"""Host preflight of the matched-cohort benign COMPUTE workloads (no VM; benign tools on benign data only).

For each non-network benign case: resolve the built binary (sha256 -> inventory locator), materialize the workload's
fixtures from the SHARED guest-safe registry (benign_workloads), run `strace -f -c -- <bin> <argv>` with stdin=DEVNULL
(exactly the production runner's constraint), and record total syscalls (summing all personality tables so ia32
counts), exit code and whether the exit code was acceptable. The argv and fixtures are identical to what the guest
payload will run, so this host measurement is a faithful activity proxy -- host strace total includes dynamic-linker
setup, so it slightly overcounts vs the guest post-exec-boundary count; it is a sizing proxy, confirmed at collect.
Network cases (Sink clients) are not host-reachable and are validated in the guest. Run with -I.
"""

import json, os, re, shutil, subprocess, sys, tarfile
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benign_workloads as bw  # noqa: E402  shared guest-safe workload registry

STUDY = ROOT.parents[2]
SEL = STUDY / "data/benign/revision5-matched/benign_selection.json"
INV = STUDY / "data/benign/revision5-matched/benign_inventory.json"
RELEASE = (STUDY / "data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-heldout-amendment"
           / "20261021T201119747468Z/collection-readiness/20261021T203401085156Z")
WS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/benign-preflight")
OUT = STUDY / "data/benign/revision5-matched/preflight_benign.json"
# selection keeps `source` (category) but not the path; recover the on-disk locator from the inventory by sha256
INVMAP = {r["sha256"]: r["locator"] for r in json.loads(INV.read_text())}
_bincache, _fixcache = {}, {}


def resolve(case):
    sha = case["sha256"]
    if sha in _bincache:
        return _bincache[sha]
    loc = INVMAP[sha]
    dst = WS / "bins" / (sha[:16] + "-" + Path(loc.split(":", 1)[-1]).name)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if loc.startswith("payload.tgz:"):
        with tarfile.open(RELEASE / "payload.tgz") as tar:
            dst.write_bytes(tar.extractfile(loc.split(":", 1)[1]).read())
    else:
        shutil.copy2(STUDY / loc, dst)
    os.chmod(dst, 0o755)
    _bincache[sha] = dst
    return dst


def run_case(case):
    cwd = WS / "run" / f"{case['mode']}-{case['split']}-{case['program']}-{case['activity_bin']}-{case['task_variant']}"
    shutil.rmtree(cwd, ignore_errors=True); cwd.mkdir(parents=True)
    try:
        binp = resolve(case)
    except Exception as e:
        return {"status": "bin_resolve_error", "error": str(e)[:80]}
    try:
        spec = bw.workload(case["program"], case["activity_bin"])
    except KeyError as e:
        return {"status": "no_workload", "error": str(e)[:80]}
    paths = OrderedDict((role, bw.materialize(kind, size, WS / "fix", _fixcache))
                        for role, kind, size in spec["fixtures"])
    argv = [str(binp)] + bw.resolve_argv(spec, paths, str(cwd))
    strace_out = cwd / ".strace"
    try:
        r = subprocess.run(["strace", "-f", "-c", "-o", str(strace_out), "--", *argv], cwd=cwd,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    except OSError as e:
        return {"status": "exec_error", "error": str(e)[:80]}
    txt = strace_out.read_text() if strace_out.exists() else ""
    total = 0  # sum every personality table's 'total' row; calls is col index 3 (%,sec,usecs,calls[,err])
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1] == "total" and parts[3].isdigit():
            total += int(parts[3])
    ok = r.returncode in spec["rc_ok"]
    return {"status": "ok" if ok else "fail", "exit": r.returncode, "syscalls": total, "rc_ok": spec["rc_ok"]}


def main():
    shutil.rmtree(WS, ignore_errors=True); WS.mkdir(parents=True)
    sel = [c for c in json.loads(SEL.read_text()) if "program" in c]
    results = []
    for c in sel:
        if c["network"]:
            results.append({**c, "preflight": {"status": "guest_validated_later"}})
            continue
        res = run_case(c)
        results.append({**c, "preflight": res})
        print(f"{c['mode'][:12]:12s} {c['split'][:5]:5s} {c['program']:10s} {c['activity_bin']:7s} "
              f"-> {res.get('status'):18s} syscalls={res.get('syscalls')}", flush=True)
    OUT.write_text(json.dumps(results, indent=1))
    comp = [r for r in results if not r["network"]]
    bad = [r for r in comp if r["preflight"]["status"] != "ok"]
    print(f"\ncompute cases: {len(comp)} | ok: {len(comp)-len(bad)} | problems: {len(bad)}")
    for r in bad:
        print("  PROBLEM", r["mode"], r["program"], r["activity_bin"], r["preflight"])
    import statistics
    for mode in ("amd64_static", "amd64_dynamic", "i386_static"):
        v = sorted(r["preflight"]["syscalls"] for r in comp if r["mode"] == mode and r["preflight"]["status"] == "ok")
        if v:
            print(f"  benign {mode:14s} n={len(v)} min={v[0]} med={int(statistics.median(v))} max={v[-1]}")
    print("WROTE", OUT)


if __name__ == "__main__":
    main()
