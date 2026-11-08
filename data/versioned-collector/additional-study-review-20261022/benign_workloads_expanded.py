"""Expanded host- and network-active benign workloads for the 5-minute observation-length cohort.

WHY: the collected 5-min benign is only 3 program groups (rsync/wget/ping); a held-out 70/30 then collapses (a held-out
benign program is one the model never trained on). A teammate session (hazim-92) flagged three gaps, folded in here:
  (1) the host generator is ONE self-written program -> its 5 modes are ONE group (held-out "write" vs trained "read"
      is not a held-out program), not 5. Same caveat as lowrate_gen.
  (2) the new host workloads are network-silent, so network-active benign stays only wget+ping -> the network detector
      can learn "traffic => malware". Fixed by adding lowrate_gen + i386 wget/curl (Sink-only, answered traffic).
  (3) no i386 / amd64-static balance: ~1/4 of the 5-min malware is i386-static and most is amd64-static, while benign
      was amd64-dynamic-heavy (rsync). Fixed by adding amd64-static procps/find/sort and i386-static wget/curl.

This module does NOT edit the frozen benign_workloads_long.py (hash-pinned by scale/topup/finish) -- it imports it.

DENSITY: ~5 variants per group (size/rate knob), so no group dominates the held-out split (the ~50-case benign-only
run; rsync is trimmed to ~10 at analysis). hostgen/lowrate get their 5 modes as variants; the real tools are fanned out
by delay (procps), file count (find), file size (sort), or GET-list length (wget/curl).

GROUPS (real distinct binaries unless noted; each stays host- or network-active for the full 5 min with a MODEST
fixture, single argv, no shell loop, no stdin):
  top / vmstat / free  -- amd64-static procps; repeatedly read /proc; duration by iteration count (-n/-c/-s). Silent.
  find                 -- amd64-static findutils; `TREE -type f -exec md5sum {} ;` fork/exec+read per file (spawn-bound).
  sort                 -- amd64-static coreutils; `-S 2M BIGFILE -o out` tiny buffer -> external-merge I/O.
  wget (i386 cases)    -- i386-static; long GET list to the Sink (same paced pattern as the amd64 wget workload).
  curl                 -- i386-static; many small GETs from a -K url list to the Sink (distinct program from wget).
  hostgen  [1 GROUP]   -- benign_host_gen (amd64-static); 5 modes walk/read/write/stat/mixed are VARIANTS of one group.
  lowrate  [1 GROUP]   -- lowrate_gen (amd64-static); modes poll/keepalive/dns/tlspoll/tlskeep are VARIANTS; Sink-only.

Combined with the already-collected rsync/wget/ping that is 11 held-out groups (was 3), with network-active (wget/ping/
curl/lowrate) and i386 (ping/wget-i386/curl) coverage. group_of() returns the held-out group key; mode is the native
mode for matching the malware mode mix. workload() -> {fixtures, argv, rc_ok, network, binary, mode, group}.

Binaries are referenced by path under the study root (STUDY). find/sort durations are sized on-host with --verify
(DEFERRED: run AFTER the malware collection; scratch and the VM share one disk). procps/hostgen/lowrate/wget/curl
durations are fixed by their args; their only risk is the .22 4 M event cap, which --verify / the benign-only preflight
confirm. NOT ntp / device a / device c for lowrate (the Sink does not answer NTP; those runs were excluded earlier).
Run with /usr/bin/python3.
"""

import os
import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
sys.path.insert(0, str(ROOT))
import benign_workloads_long as bl  # noqa: E402  reuse SINK, resolve_argv, _fill_text, _WORDS (frozen, not edited)

SINK = bl.SINK
PROCPS_TARGET = 320                      # seconds each procps variant should run (> 300 s cutoff)
GEN_DURATION = 320                       # host generator fixed wall seconds
GEN_OPS_PER_TICK = 20                    # ~6 k syscalls/s -> ~1.9 M over 320 s (< 4 M cap)
GEN_MODES = ["walk", "read", "write", "stat", "mixed"]
GEN_TREE_FILES = 2000
GEN_TREE_DIRS = 20
LOWRATE_DURATION_MS = 320_000
LOWRATE_PERIOD_MS = 500                  # 2 ops/s -> active every 0.5 s window; ~640 ops over 320 s, far under the cap
LOWRATE_MODES = ["poll", "keepalive", "dns", "tlspoll", "tlskeep"]

# per-group density grids (~5 each). procps vary sampling RATE (distinct syscall volume, same ~320 s duration).
TOP_DELAYS = [0.25, 0.5, 1, 2, 3]
VMSTAT_DELAYS = [1, 2, 3, 4, 5]
FREE_DELAYS = [1, 2, 3, 4, 5]
# find spawn-bound (~1-3 ms/file) and sort spill-bound: these five sizes are CANDIDATES; --verify picks the ones that
# land ~320 s on the host and the frozen payload uses those. wget/curl pace by GET-list length (all comfortably long).
FIND_COUNTS = [80_000, 100_000, 120_000, 140_000, 160_000]
SORT_MBS = [200, 250, 300, 350, 400]
SORT_BUFFER = "2M"
WGET_URLS = [200_000, 300_000, 400_000, 500_000, 600_000]
CURL_URLS = [200_000, 300_000, 400_000, 500_000, 600_000]
# standalone defaults for a bare workload(program) call (independent of the grids, which --verify/self-test may shrink)
FIND_DEFAULT, SORT_DEFAULT_MB, WGET_DEFAULT_URLS, CURL_DEFAULT_URLS = 120_000, 300, 400_000, 400_000

# program -> (native mode, path under STUDY). Confirmed present on host 2026-11-06.
_RB = "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/builds"
_I386 = "data/versioned-collector/additional-study-review-20261022/i386-network-builds/20261024T163419Z/bin"
BIN = {
    "hostgen": ("native_amd64_static", "data/versioned-collector/additional-study-review-20261022/benign_host_gen"),
    "lowrate": ("native_amd64_static", "data/versioned-collector/additional-study-review-20261022/lowrate_gen"),
    "top":     ("native_amd64_static", _RB + "/procps-2160554b394a-static/top/top"),
    "vmstat":  ("native_amd64_static", _RB + "/procps-2160554b394a-static/vmstat"),
    "free":    ("native_amd64_static", _RB + "/procps-2160554b394a-static/free"),
    "find":    ("native_amd64_static", _RB + "/findutils-27d931171eca-static/find/find"),
    "sort":    ("native_amd64_static", _RB + "/coreutils-f5b60eee078d-static/src/sort"),
    "wget":    ("native_i386_static",  _I386 + "/wget"),   # i386 cases of the wget group
    "curl":    ("native_i386_static",  _I386 + "/curl"),
}


# ------------------------------------------------------------------------------------- fixture builders

def _make_subtree(path, nfiles, ndirs):
    path = Path(path)
    for d in range(ndirs):
        (path / ("d%03d" % d)).mkdir(parents=True, exist_ok=True)
    rng = random.Random(7)
    body = ((" ".join(rng.choice(bl._WORDS) for _ in range(200)) + "\n") * 11)[:2048]
    for i in range(nfiles):
        (path / ("d%03d" % (i % ndirs)) / ("f%06d.txt" % i)).write_text(body)


def _make_manyfiles(path, count):
    path = Path(path)
    for i in range(count):
        d = path / ("g%05d" % (i // 100))
        if i % 100 == 0:
            d.mkdir(parents=True, exist_ok=True)
        (d / ("f%06d" % i)).write_text("x%d\n" % i)


def _make_urllist(path, count):
    with open(path, "w") as h:
        for _ in range(count):
            h.write("http://%s/pilot\n" % SINK)


def _make_curllist(path, count):
    with open(path, "w") as h:
        for _ in range(count):
            h.write('url = "http://%s/pilot"\n' % SINK)


def materialize(kind, size, dest_dir, cache):
    key = (kind, size)
    if key in cache:
        return cache[key]
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if kind == "subtree":
        p = dest_dir / ("subtree%d" % size); _make_subtree(p, size, GEN_TREE_DIRS)
    elif kind == "manyfiles":
        p = dest_dir / ("manyfiles%d" % size); _make_manyfiles(p, size)
    elif kind == "bigfile":
        p = dest_dir / ("sortin%d.txt" % size); bl._fill_text(p, size)
    elif kind == "urllist":
        p = dest_dir / ("urls%d.txt" % size); _make_urllist(p, size)
    elif kind == "curllist":
        p = dest_dir / ("curls%d.txt" % size); _make_curllist(p, size)
    else:
        raise ValueError("unknown expanded-fixture kind: " + kind)
    cache[key] = p
    return p


# ------------------------------------------------------------------------------------- per-variant workloads

def group_of(program):
    """Held-out group key. hostgen/lowrate modes collapse to one group each (one self-written binary); i386 wget is the
    wget group; every other program is its own group."""
    if program.startswith("hostgen_"):
        return "hostgen"
    if program.startswith("lowrate_"):
        return "lowrate"
    return program


def _procps_n(delay):
    return int(round(PROCPS_TARGET / delay)) + 2   # +2 margin so a faster guest still exceeds 300 s


def workload(program, params=None):
    """program = concrete base: hostgen_<mode>, lowrate_<mode>, top, vmstat, free, find, sort, wget, curl.
    params size/rate the variant (see the grids above)."""
    params = params or {}
    f = lambda role, **kw: {"fix": role, **kw}
    o = lambda name: {"out": name}
    base = program.split("_")[0] if program.startswith(("hostgen_", "lowrate_")) else program
    mode, _ = BIN[base]
    g = group_of(program)

    if program.startswith("hostgen_"):            # host-active, network-silent, fixed duration
        m = program[len("hostgen_"):]
        return {"fixtures": [("tree", "subtree", GEN_TREE_FILES)],
                "argv": [m, str(GEN_DURATION), str(GEN_OPS_PER_TICK), f("tree")],
                "rc_ok": [0], "network": False, "binary": "hostgen", "mode": mode, "group": g}

    if program.startswith("lowrate_"):            # network-active, Sink-only, fixed duration
        m = program[len("lowrate_"):]
        return {"fixtures": [], "argv": [m, str(LOWRATE_PERIOD_MS), str(LOWRATE_DURATION_MS), SINK],
                "rc_ok": [0], "network": True, "binary": "lowrate", "mode": mode, "group": g}

    if program == "top":
        d = params.get("d", 1)
        return {"fixtures": [], "argv": ["-b", "-n", str(_procps_n(d)), "-d", ("%g" % d)],
                "rc_ok": [0], "network": False, "binary": "top", "mode": mode, "group": g}
    if program == "vmstat":                       # DELAY COUNT
        d = params.get("d", 1)
        return {"fixtures": [], "argv": [str(d), str(_procps_n(d))],
                "rc_ok": [0], "network": False, "binary": "vmstat", "mode": mode, "group": g}
    if program == "free":                         # -s DELAY -c COUNT
        d = params.get("d", 1)
        return {"fixtures": [], "argv": ["-s", str(d), "-c", str(_procps_n(d))],
                "rc_ok": [0], "network": False, "binary": "free", "mode": mode, "group": g}

    if program == "find":                         # fork/exec + read per file; `;` is a literal argv token (no shell)
        count = params.get("count", FIND_DEFAULT)
        return {"fixtures": [("tree", "manyfiles", count)],
                "argv": [f("tree"), "-type", "f", "-exec", "md5sum", "{}", ";"],
                "rc_ok": [0], "network": False, "binary": "find", "mode": mode, "group": g}
    if program == "sort":                         # tiny -S buffer -> external merge
        mb = params.get("mb", SORT_DEFAULT_MB)
        return {"fixtures": [("in", "bigfile", mb)],
                "argv": ["-S", SORT_BUFFER, "-o", o("sorted.txt"), f("in")],
                "rc_ok": [0], "network": False, "binary": "sort", "mode": mode, "group": g}

    if program == "wget":                         # i386 wget, long paced GET list to the Sink
        urls = params.get("urls", WGET_DEFAULT_URLS)
        return {"fixtures": [("list", "urllist", urls)],
                "argv": ["-q", "--limit-rate", "100k", "-O", o("wget.out"), "-i", f("list")],
                "rc_ok": [0], "network": True, "binary": "wget", "mode": mode, "group": g}
    if program == "curl":                         # i386 curl, many small GETs from a -K url list to the Sink
        urls = params.get("urls", CURL_DEFAULT_URLS)
        return {"fixtures": [("list", "curllist", urls)],
                "argv": ["-s", "--limit-rate", "100k", "-o", o("curl.out"), "-K", f("list")],
                "rc_ok": [0], "network": True, "binary": "curl", "mode": mode, "group": g}

    raise KeyError("no expanded benign workload for program: " + program)


def expanded_variants():
    """~5 variants per group -> the ~35-case benign-only run. Returns [(name, program, params), ...].
    find/sort are DROPPED: host calibration (2026-11-06) showed that to run 5 min on this fast host `find -exec md5sum`
    needs ~653k files and `sort -S 2M` needs ~143 GB (sort did 100 MB in 0.24 s) -- impractical fixtures. Only
    DURATION-CONTROLLED workloads (procps -n/-d, wget/curl GET-list count, hostgen/lowrate fixed duration) qualify.
    The find/sort workload()/BIN entries are left defined but unused. 7 collection groups x 5 = 35 new benign."""
    out = []
    out += [("hostgen-" + m, "hostgen_" + m, {}) for m in GEN_MODES]
    out += [("lowrate-" + m, "lowrate_" + m, {}) for m in LOWRATE_MODES]
    out += [("top-d%g" % d, "top", {"d": d}) for d in TOP_DELAYS]
    out += [("vmstat-d%d" % d, "vmstat", {"d": d}) for d in VMSTAT_DELAYS]
    out += [("free-s%d" % d, "free", {"d": d}) for d in FREE_DELAYS]
    out += [("wget-i386-%dk" % (u // 1000), "wget", {"urls": u}) for u in WGET_URLS]
    out += [("curl-i386-%dk" % (u // 1000), "curl", {"urls": u}) for u in CURL_URLS]
    return out


def groups():
    """Distinct held-out benign groups this module contributes (NOT the already-collected rsync/wget-amd64/ping)."""
    return sorted({workload(p)["group"] for _, p, _ in expanded_variants()})


# ------------------------------------------------------------------------------------- verification (DEFERRED run)

def _verify():
    """Host-time each variant at full size; find/sort must reach >= 300 s (pick the sizes that do); the fixed-duration
    ones (procps, hostgen) just run clean. DEFER until after the malware collection (heavy disk I/O contends with live
    snapshot restores). Network variants (lowrate/wget/curl) talk to the Sink and are confirmed in the benign-only
    guest preflight, not on the host."""
    scratch = Path(os.environ.get("EXP_SCRATCH", "/tmp/benign_expanded_verify"))
    scratch.mkdir(parents=True, exist_ok=True)
    cache = {}
    print(f"{'variant':16}{'group':9}{'mode':20}{'seconds':>9}  note")
    ok = True
    for name, program, params in expanded_variants():
        spec = workload(program, params)
        binpath = STUDY / BIN[spec["binary"]][1]
        if spec["network"]:
            print(f"{name:16}{spec['group']:9}{spec['mode']:20}{'--':>9}  network: confirm in benign-only preflight (Sink)")
            continue
        if not binpath.exists():
            print(f"{name:16}{spec['group']:9}{spec['mode']:20}{'--':>9}  MISSING {binpath}"); ok = False; continue
        paths = {role: materialize(kind, size, scratch / "fix", cache) for role, kind, size in spec["fixtures"]}
        outdir = scratch / "out" / name; outdir.mkdir(parents=True, exist_ok=True)
        argv = bl.resolve_argv(spec, paths, str(outdir))
        t = time.time()
        p = subprocess.run([str(binpath)] + argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL)
        dt = time.time() - t
        fixed = program.startswith("hostgen_") or program in ("top", "vmstat", "free")
        good = (dt >= 300 or fixed) and p.returncode in spec["rc_ok"]
        ok = ok and good
        print(f"{name:16}{spec['group']:9}{spec['mode']:20}{dt:>9.1f}  {'OK' if good else 'CHECK'} rc={p.returncode}")
    print("ALL ok:", ok)
    return ok


def _selfcheck():
    import tempfile
    from collections import Counter
    variants = expanded_variants()
    names = [n for n, _, _ in variants]
    assert len(set(names)) == len(names), "duplicate variant names"
    per_group = Counter(workload(p, pr)["group"] for _, p, pr in variants)
    with tempfile.TemporaryDirectory() as d:
        tiny = Path(d) / "tiny"; _make_subtree(tiny, 15, 3)
        for name, program, params in variants:
            spec = workload(program, params)
            assert spec["binary"] in BIN, program
            assert spec["network"] == (spec["binary"] in ("lowrate", "wget", "curl")), program
            paths = {role: (tiny if kind == "subtree" else Path(d) / ("%s%s" % (kind, size)))
                     for role, kind, size in spec["fixtures"]}
            argv = bl.resolve_argv(spec, paths, ".")
            assert all(isinstance(a, str) for a in argv), (name, argv)
        assert group_of("hostgen_walk") == group_of("hostgen_stat") == "hostgen"
        assert group_of("lowrate_poll") == group_of("lowrate_dns") == "lowrate"
        gen = STUDY / BIN["hostgen"][1]
        if gen.exists():
            cwd = Path(d) / "cwd"; cwd.mkdir()
            for m in GEN_MODES:
                r = subprocess.run([str(gen), m, "1", "20", str(tiny)], cwd=cwd,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
                assert r.returncode == 0, "hostgen mode failed: " + m
    print("PASS benign_workloads_expanded: %d variants over %d groups %s"
          % (len(variants), len(per_group), dict(per_group)))


if __name__ == "__main__":
    if "--verify" in sys.argv:
        sys.exit(0 if _verify() else 1)
    _selfcheck()
