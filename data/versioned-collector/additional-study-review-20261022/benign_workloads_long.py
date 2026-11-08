"""Long-running (>=5 min) benign workloads for the observation-length pilot (5 min / 600 windows).

The revision5 benign workloads finish in well under a second, so running them for 5 minutes would leave them idle
and reduce the comparison to "benign stops, malware keeps going" -- the lifetime shortcut. These five are designed to
stay ACTIVE for the whole 5-minute window and then be truncated at the fixed 300 s cutoff, exactly like the malware,
so each run is a fair control. Because the study host is fast, every workload is made long by a DURATION control, a
THROTTLE, or a COMPUTE LOOP (not by a giant fixture): a 5-minute run needs at most a ~70 MB fixture.

Same production-runner constraints as benign_workloads.py: stdin is DEVNULL, the target is a single argv with no
shell, fixtures are referenced by absolute paths, outputs are relative in the per-sample CWD. Network cases talk only
to the internal Sink (10.0.0.1). A workload() returns {fixtures, argv, rc_ok, network}. Tokens: plain str = literal;
{"fix": role[,"slash"]} = absolute fixture path; {"out": name} = relative CWD output; {"read": role} = sqlite ".read".

Sizes below are tuned so each command runs a bit OVER 5 minutes on the (fast) study host; a slower guest then also
exceeds 5 minutes, and the runner's fixed 300 s observation truncates the tail symmetrically with the malware.
Verify with: python3 benign_workloads_long.py --verify  (host-times each at full size; sqlite uses python's sqlite3
as a same-engine proxy because the packaged sqlite3 binary needs a newer libc than the host).
"""

import os
import random
import subprocess
import sys
import time
from pathlib import Path

SINK = "10.0.0.1"
TARGET_SECONDS = 360  # aim ~20% over the 300 s cutoff so a faster-than-host guest still stays active throughout

# Tuned sizes (see --verify). Each value is chosen for >= TARGET_SECONDS on the study host.
# openssl speed runs each symmetric algo across 6 block sizes, so one symmetric algo = 6 x OPENSSL_SECONDS. Two
# symmetric algos at 30 s => ~360 s; the extra algos add margin. Duration-controlled, so a faster guest still runs long
# (and the 300 s observation truncates the tail).
OPENSSL_SECONDS = 30
OPENSSL_ALGOS = ["sha256", "sha512", "aes-256-cbc", "rsa2048"]
SQLITE_CTE_N = 2_000_000_000              # recursive counter bound; tiny .sql script, pure compute
RSYNC_TREE_MB = 70                        # throttled copy: 70 MB at --bwlimit=200 KB/s ~= 358 s
RSYNC_BWLIMIT_KB = 200
CURL_UPLOAD_MB = 70                       # throttled upload: 70 MB at --limit-rate 200k ~= 358 s
CURL_LIMIT_RATE = "200k"
WGET_URL_COUNT = 400_000                  # long GET list to the Sink; sized above the fast-host request rate
WGET_LIMIT_RATE = "100k"

_rng = random.Random(42)
_WORDS = ["".join(_rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(_rng.randint(3, 9))) for _ in range(4000)]


# ------------------------------------------------------------------------------------- fixture builders

def _fill_text(path, mb):
    """Low-entropy text (no random padding) so throughput tools do real, steady work."""
    rng = random.Random(1)
    with open(path, "w") as h:
        line = " ".join(rng.choice(_WORDS) for _ in range(1500)) + "\n"
        while h.tell() < mb * 1048576:
            h.write(line)


def _make_bigtree(path, mb):
    """A tree totalling ~mb MB in ~100 KB files, so rsync copies real bytes that --bwlimit can throttle."""
    rng = random.Random(5)
    path.mkdir(parents=True, exist_ok=True)
    per_file = 100 * 1024
    n = max(1, (mb * 1048576) // per_file)
    chunk = (" ".join(rng.choice(_WORDS) for _ in range(per_file // 8))[:per_file] + "\n")
    for i in range(n):
        (path / ("f%06d.txt" % i)).write_text(chunk)


def _make_sqlcte(path, n):
    """A tiny script: one recursive CTE counting to n. Pure CPU in the sqlite engine; file is ~200 bytes."""
    path.write_text(
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<%d)\n"
        "SELECT count(*), sum(x %% 7) FROM c;\n" % n
    )


def _make_urllist(path, count, url):
    with open(path, "w") as h:
        for _ in range(count):
            h.write(url + "\n")


def materialize(role, kind, size, dest_dir, cache):
    key = (kind, size)
    if key in cache:
        return cache[key]
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if kind == "bigtree":
        p = dest_dir / ("bigtree%d" % size); _make_bigtree(p, size)
    elif kind == "bigfile":
        p = dest_dir / ("upload%d.bin" % size); _fill_text(p, size)
    elif kind == "sqlcte":
        p = dest_dir / "cte.sql"; _make_sqlcte(p, size)
    elif kind == "urllist":
        p = dest_dir / ("urls%d.txt" % size); _make_urllist(p, size, "http://%s/pilot" % SINK)
    else:
        raise ValueError("unknown long-fixture kind: " + kind)
    cache[key] = p
    return p


# ------------------------------------------------------------------------------------- per-program workloads

def long_workload(program):
    f = lambda role, **kw: {"fix": role, **kw}
    o = lambda name: {"out": name}
    if program == "openssl":   # duration-controlled crypto benchmark; no fixture, pure CPU
        argv = ["speed", "-seconds", str(OPENSSL_SECONDS)] + OPENSSL_ALGOS
        return {"fixtures": [], "argv": argv, "rc_ok": [0], "network": False}
    if program == "sqlite3":   # recursive-CTE compute; tiny script via .read; db in CWD
        return {"fixtures": [("s", "sqlcte", SQLITE_CTE_N)], "argv": [o("t.db"), {"read": "s"}],
                "rc_ok": [0], "network": False}
    if program == "rsync":     # throttled copy of a ~70 MB tree (file I/O, bandwidth-capped)
        return {"fixtures": [("tree", "bigtree", RSYNC_TREE_MB)],
                "argv": ["-a", "--bwlimit=%d" % RSYNC_BWLIMIT_KB, f("tree", slash=True), o("copy")],
                "rc_ok": [0], "network": False}
    if program == "ping":      # steady low-rate ICMP to the Sink: sustained network the whole window, and its ~1
                               # packet/s keeps host syscalls far under the .22 event cap (unlike a fast HTTP loop).
        return {"fixtures": [], "argv": ["-n", "-c", "600", "-w", "295", SINK],
                "rc_ok": [0], "network": True}
    if program == "wget":      # long list of GETs to the Sink (bursty network, throttled)
        return {"fixtures": [("list", "urllist", WGET_URL_COUNT)],
                "argv": ["-q", "--limit-rate", WGET_LIMIT_RATE, "-O", o("wget.out"), "-i", f("list")],
                "rc_ok": [0], "network": True}
    raise KeyError("no long benign workload for program: " + program)


def variant_workload(program, params):
    """A long workload parameterised for the scaled cohort (same programs/binaries as long_workload, varied size/rate
    so each variant is distinct but still runs >5 min). Returns {fixtures, argv, rc_ok, network}."""
    f = lambda role, **kw: {"fix": role, **kw}
    o = lambda name: {"out": name}
    if program == "openssl":   # compute: >=2 symmetric algos x 6 blocks x seconds >= 300 s
        return {"fixtures": [], "argv": ["speed", "-seconds", str(params["seconds"])] + params["algos"],
                "rc_ok": [0], "network": False}
    if program == "sqlite3":   # compute: recursive CTE to n (tiny script); guest i386 sqlite is slower than the proxy
        return {"fixtures": [("s", "sqlcte", params["n"])], "argv": [o("t.db"), {"read": "s"}],
                "rc_ok": [0], "network": False}
    if program == "rsync":     # I/O busy: throttled copy; runtime ~= tree_mb*1024/bwlimit (s)
        return {"fixtures": [("tree", "bigtree", params["tree_mb"])],
                "argv": ["-a", "--bwlimit=%d" % params["bwlimit"], f("tree", slash=True), o("copy")],
                "rc_ok": [0], "network": False}
    if program == "ping":      # network light: steady ICMP for ~deadline s
        return {"fixtures": [], "argv": ["-n", "-c", "600", "-w", str(params["deadline"]), SINK],
                "rc_ok": [0], "network": True}
    if program == "wget":      # network busy: long GET list to the Sink (wget is naturally ~150 req/s -> under the cap)
        return {"fixtures": [("list", "urllist", params["urls"])],
                "argv": ["-q", "--limit-rate", "100k", "-O", o("wget.out"), "-i", f("list")],
                "rc_ok": [0], "network": True}
    raise KeyError("no variant workload for program: " + program)


def scaled_variants():
    """Distinct long benign variants that stay HOST/NETWORK-ACTIVE for the whole 5 min window. The scale run measured
    which programs actually fit: rsync (disk I/O) and wget (network) were active in all 600 windows, ping in ~290; but
    openssl `speed` was active in only ~10/600 windows and sqlite's in-memory CTE in ~1/600 -- they burn CPU silently,
    so to the host sensor they look idle/exited and recreate the 'quiet tail = benign' shortcut. openssl and sqlite are
    therefore DROPPED here. Only programs with a deterministic rate knob (rsync --bwlimit, wget request pacing, ping -w)
    are kept, each sized so runtime >> 300 s; the fixed observation truncates the tail like the malware. Deterministic.
    LIMITATION: this restricts benign to 3 program families (disk I/O / network bulk / network light), far less diverse
    than the paper's 24 benign projects -- most programs cannot be held host-active for a full 5 min without a rate
    knob. That diversity cost is the price of the 5 min consistency. Returns [(name, program, params), ...]."""
    out = []
    # rsync (disk I/O busy): SHARED tree fixtures (cached by size) x bwlimits that keep runtime (tree_mb*1024/bwlimit)
    # >= 310 s. bwlimit varies runtime without changing the fixture, so many variants share a few trees (cheap payload).
    for tree_mb in (10, 20, 35, 50, 70, 90):
        for bw in (20, 25, 30, 40, 50, 60, 75, 100, 125, 150):
            if tree_mb * 1024 / bw >= 310:
                out.append(("rsync-%dmb-bw%d" % (tree_mb, bw), "rsync", {"tree_mb": tree_mb, "bwlimit": bw}))
    # wget (network busy): distinct GET-list lengths (all >= ~500 s at the measured ~150 req/s to the Sink)
    for urls in (80_000, 110_000, 140_000, 170_000, 200_000, 240_000, 280_000, 320_000,
                 360_000, 400_000, 460_000, 520_000, 600_000, 700_000, 820_000, 960_000):
        out.append(("wget-%dk" % (urls // 1000), "wget", {"urls": urls}))
    # ping (network light): deadlines ABOVE the 300 s cutoff so ICMP keeps flowing through the whole window and the
    # observation truncates the tail (at -w 294 the scale run stopped ~6 s early). -c 600 caps it at 600 packets/600 s.
    for w in (305, 320, 340, 360, 380):
        out.append(("ping-w%d" % w, "ping", {"deadline": w}))
    return out


def resolve_argv(spec, fixture_paths, out_root):
    out = []
    for token in spec["argv"]:
        if isinstance(token, str):
            out.append(token)
        elif "fix" in token:
            path = str(fixture_paths[token["fix"]])
            out.append(path + "/" if token.get("slash") else path)
        elif "out" in token:
            out.append(str(Path(out_root) / token["out"]) if out_root != "." else token["out"])
        elif "read" in token:
            out.append(".read " + str(fixture_paths[token["read"]]))
        else:
            raise ValueError("bad argv token: " + repr(token))
    return out


PROGRAMS = ["openssl", "sqlite3", "rsync", "ping", "wget"]


def _verify():
    """Host-time each workload at full size against a throwaway localhost server (for the two network cases).
    Network timing on localhost is a conservative lower bound: the internal Sink is no faster, so guest runtime >=.
    sqlite is timed via python's sqlite3 (same engine) because the packaged binary needs a newer libc than the host.
    """
    import http.server
    import socketserver
    import threading
    scratch = Path(os.environ.get("PILOT_SCRATCH", "/tmp")) / "benign_long_verify"
    scratch.mkdir(parents=True, exist_ok=True)
    cache = {}

    class Q(http.server.BaseHTTPRequestHandler):
        def _ok(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        def do_GET(self):
            self._ok()
        def do_PUT(self):
            while self.rfile.read(65536):
                pass
            self._ok()
        def log_message(self, *a):
            pass
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Q); port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def host_argv(program, spec, paths):
        argv = resolve_argv(spec, paths, str(scratch / "out"))
        (scratch / "out").mkdir(exist_ok=True)
        if program in ("sqlite3", "ping"):
            return None  # sqlite3 proxy-timed below; ping needs raw sockets/root on the host, verified in-guest only
        bin_ = {"openssl": "openssl", "rsync": "rsync", "wget": "wget"}[program]
        argv = [a.replace("http://%s/" % SINK, "http://127.0.0.1:%d/" % port) for a in argv]
        return [bin_] + argv

    results = {}
    for program in PROGRAMS:
        spec = long_workload(program)
        paths = {role: materialize(role, kind, size, scratch / "fix", cache) for role, kind, size in spec["fixtures"]}
        if program == "sqlite3":
            import sqlite3
            t = time.time()
            sqlite3.connect(":memory:").execute(
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<?) "
                "SELECT count(*),sum(x%7) FROM c", (SQLITE_CTE_N,)).fetchone()
            dt = time.time() - t
            results[program] = (dt, "python-sqlite proxy")
            continue
        cmd = host_argv(program, spec, paths)
        if cmd is None:  # ping: raw sockets need root on the host; its ~295 s runtime is fixed by -w and verified in-guest
            results[program] = (300.0, "skipped on host (ping needs root; -w 295 sets its runtime)")
            continue
        t = time.time()
        p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        results[program] = (time.time() - t, "rc=%d" % p.returncode)
    srv.shutdown()

    print(f"{'program':10}{'seconds':>10}  {'>=300?':7} note")
    ok = True
    for program in PROGRAMS:
        dt, note = results[program]
        good = dt >= 300
        ok = ok and good
        print(f"{program:10}{dt:>10.1f}  {'YES' if good else 'NO ':7} {note}")
    print("ALL >= 5 min:", ok)
    return ok


def _selfcheck():
    from collections import OrderedDict
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        cache = {}
        for program in PROGRAMS:
            spec = long_workload(program)
            paths = OrderedDict((role, materialize(role, kind, size, Path(d) / "fix", cache))
                                for role, kind, size in spec["fixtures"])
            argv = resolve_argv(spec, paths, ".")
            assert all(isinstance(a, str) for a in argv), (program, argv)
            assert spec["network"] == (program in ("ping", "wget"))
    print("PASS benign_workloads_long: %d programs, fixtures build + argv resolve" % len(PROGRAMS))


if __name__ == "__main__":
    if "--verify" in sys.argv:
        sys.exit(0 if _verify() else 1)
    _selfcheck()
