#!/usr/bin/env python3
"""Local test of the guest scripts (session.sh, bg.sh) without the VM, without root and without BPF.

Runs session.sh in a delegated user cgroup (systemd-run --user --scope -p Delegate=yes) with stand-ins:
  sysstatd   same start protocol as hostmon_agg; in the middle of every 0.5-s window it records which PIDs are in its
             cgroup, so the test can check that the background was in app-a from t0 on and the injected program in
             app-b only from its injection time on;
  netcfgd    same READY/HEALTH protocol as sockowner;
  webfetch / netpoll   log their arguments and cgroup (the check-in loops until killed);
and a password-protected test archive whose one member logs its start time, cgroup, working folder, user and stdin.
Time is scaled down (a 12-s session, injection at 5 s). The clock probes go to a UDP listener on 127.0.0.1.

Three runs: an archive injection, a session with nothing injected, and a failure (a monitor that never gets ready:
the session must stop before releasing anything and still hand back its outputs with status 1).

  /usr/bin/python3 tests/test_session_local.py <scratch dir>
"""
import json
import os
import shlex
import socket
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUEST = HERE.parent / "guest"

STUB_SYSSTATD = r'''#!/usr/bin/env python3
import os, signal, sys, time
win, cg = float(sys.argv[1]), sys.argv[2]
if os.environ.get("HZ_BROKEN_MONITOR") or os.path.exists(os.path.join(os.path.dirname(sys.argv[0]), "BROKEN")):
    sys.exit(1)
print("HOSTMON_READY,%d" % os.stat(cg).st_ino, flush=True)
t0 = float(sys.stdin.readline())
stop = []
signal.signal(signal.SIGINT, lambda *a: stop.append(1))
signal.signal(signal.SIGTERM, lambda *a: stop.append(1))
w = 0
while not stop:
    d = t0 + (w + 0.5) * win - time.monotonic()
    if d > 0:
        time.sleep(min(d, 0.05))
        continue
    try:
        pids = open(os.path.join(cg, "cgroup.procs")).read().split()
    except OSError:
        pids = ["gone"]
    print("==== HOST WINDOW %d START=%.3f END=%.3f" % (w, w * win, (w + 1) * win))
    print("PIDS," + " ".join(pids), flush=True)
    w += 1
print("HOSTMON_HEALTH,0,0,0,0", flush=True)
'''

STUB_NETCFGD = r'''#!/usr/bin/env python3
import os, signal, sys, time
print("SOCKOWNER_READY,%d" % os.stat(sys.argv[1]).st_ino, flush=True)
stop = []
signal.signal(signal.SIGINT, lambda *a: stop.append(1))
while not stop:
    time.sleep(0.05)
print("SOCKOWNER_HEALTH,0,0,0", flush=True)
'''

STUB_TOOL = r'''#!/bin/bash
echo "$EPOCHREALTIME tool $(basename "$0") $* pid=$$ cg=$(grep ^0:: /proc/self/cgroup | cut -d: -f3)" >> "$HZTEST_LOG"
if [ "${1:-}" = beacon ]; then while :; do sleep 0.3; done; fi
sleep 0.2
'''

PROBE_PROGRAM = r'''#!/bin/bash
{ echo "$EPOCHREALTIME injected start pid=$$ args=$*"
  echo "injected cgroup $(grep ^0:: /proc/self/cgroup | cut -d: -f3)"
  echo "injected cwd $PWD user=$(id -un) home=$HOME stdin=$(readlink /proc/self/fd/0)"; } >> "$HZTEST_LOG"
sleep 100
'''


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def write(path, text, mode=0o755):
    path.write_text(text)
    path.chmod(mode)
    return path


class ProbeListener(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.got, self.stop = [], False

    def run(self):
        while not self.stop:
            try:
                data, _ = self.sock.recvfrom(2048)
                self.got.append((time.time_ns(), data.decode()))
            except socket.timeout:
                pass


def run_case(base, name, kind, inj, broken=False):
    case = base / name
    tools, work = case / "tools", case / "w"
    (tools / "bin").mkdir(parents=True)
    work.mkdir()
    write(tools / "sysstatd", STUB_SYSSTATD)
    write(tools / "netcfgd", STUB_NETCFGD)
    write(tools / "bin" / "webfetch", STUB_TOOL)
    write(tools / "bin" / "netpoll", STUB_TOOL)
    (tools / "bg.sh").write_text((GUEST / "bg.sh").read_text())
    (tools / "session.sh").write_text((GUEST / "session.sh").read_text())
    if broken:
        (tools / "BROKEN").write_text("")
    log = case / "events.log"
    log.write_text("")
    sha = ""
    if inj == "archive":
        member = case / "probe-src" / "probe.sh"
        member.parent.mkdir()
        write(member, PROBE_PROGRAM)
        subprocess.run(["7z", "a", "-pinfected", "-tzip", str(work / "sample.zip"), str(member)], check=True,
                       capture_output=True)
        sha = subprocess.run(["sha256sum", str(member)], capture_output=True, text=True, check=True).stdout.split()[0]
    listener = ProbeListener()
    listener.start()
    user = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
    group = subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()
    out = case / "out.tgz"
    plan = {
        "SID": "t-" + name, "MARKER": "hztest", "KIND": kind, "DUR_US": "12000000", "T_INJECT_US": "5000000",
        "BG_SEED": "4242", "BG_DUR_S": "200", "SCALE_PM": "60", "GUSER": user, "GGROUP": group,
        "GUID": str(os.getuid()), "W": str(work), "T": str(tools), "WORK": str(case / "inj"),
        "BGWORK": str(case / "bgwork"), "PROBE_DST": "127.0.0.1", "PROBE_PORT": str(listener.port),
        "OUT": str(out), "INJ_SOURCE": inj, "INJ_SHA256": sha, "INJ_TOOL": "", "INJ_EXE": "", "PY": "/usr/bin/python3"}
    lines = ["%s=%s" % (k, shlex.quote(v)) for k, v in plan.items()]
    lines.append("INJ_ARGS=(%s)" % " ".join(shlex.quote(a) for a in ["alpha", "two words"]))
    lines.append("DROP=()")
    env = ["HOME=" + os.environ["HOME"], "USER=" + user, "LOGNAME=" + user, "SHELL=/bin/bash",
           "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "HZTEST_LOG=" + str(log)]
    lines.append("UENV=(%s)" % " ".join(shlex.quote(e) for e in env))
    (work / "plan.env").write_text("\n".join(lines) + "\n")
    inner = ('cg=/sys/fs/cgroup$(grep "^0::" /proc/self/cgroup | cut -d: -f3); mkdir "$cg/leaf" && '
             'echo $$ > "$cg/leaf/cgroup.procs" && echo "CGROOT=$cg" >> "$1" && exec /bin/bash "$2" "$1"')
    started = time.time_ns()
    proc = subprocess.run(["systemd-run", "--user", "--scope", "-q", "-p", "Delegate=yes", "/bin/bash", "-c", inner,
                           "hzinner", str(work / "plan.env"), str(tools / "session.sh")],
                          capture_output=True, text=True, timeout=180)
    listener.stop = True
    listener.join()
    require(out.is_file(), "%s: no output archive (rc %s, %s)" % (name, proc.returncode, proc.stderr[-400:]))
    got = case / "got"
    with tarfile.open(out) as tar:
        tar.extractall(got)
    return {"case": case, "got": got, "proc": proc, "log": log.read_text(), "probes": listener.got,
            "started_ns": started, "plan": plan}


def windows(path):
    """{window: [pids]} from a stub monitor log."""
    out, w = {}, None
    for line in Path(path).read_text().splitlines():
        if line.startswith("==== HOST WINDOW"):
            w = int(line.split()[3])
        elif line.startswith("PIDS,") and w is not None:
            out[w] = line[5:].split()
    return out


def check_archive_case(r):
    got, text = r["got"], r["log"]
    require((got / "status.txt").read_text().strip() == "0", "status not 0: %s" % (got / "session.log").read_text())
    require(not (got / "failed.txt").exists(), "failed.txt present")
    session_log = (got / "session.log").read_text()
    for step in ("monitors ready", "blocked bg", "blocked inj", "t0 ", "background released", "inject release end",
                 "end of session", "cgroups killed", "monitors stopped", "finish status 0"):
        require(step in session_log, "session log lacks %r" % step)
    t0_real_us = int(session_log.split(" r0_us ")[1].split()[0])
    # the injected program: started once, at t0 + 5 s (+ a little), in app-b, in its work folder, stdin /dev/null
    starts = [l for l in text.splitlines() if " injected start " in l]
    require(len(starts) == 1, "injected start lines: %s" % starts)
    t_start_us = int(starts[0].split()[0].replace(".", ""))
    delay = (t_start_us - t0_real_us) / 1e6
    require(5.0 <= delay < 5.5, "injected program started %.3f s after t0" % delay)
    require("args=alpha two words" in starts[0], "arguments lost: %s" % starts[0])
    require(any(l.startswith("injected cgroup ") and l.endswith("/app-b") for l in text.splitlines()),
            "injected program not in app-b")
    require("stdin=/dev/null" in text and r["plan"]["WORK"] + "/w" in text, "cwd/stdin of the injected program")
    # monitors: the blocked programs are in their cgroups from before t0 (a blocked process makes no system calls,
    # and the real monitor drops everything before t0); the injected program keeps the blocked PID (no fork between
    # the move and its start), so all it does is in app-b
    wa, wb = windows(got / "host-a.log"), windows(got / "host-b.log")
    require(len(wa) >= 24 and len(wb) >= 24, "windows recorded: a %d b %d" % (len(wa), len(wb)))
    inj_pid = starts[0].split("pid=")[1].split()[0]
    blocked = dict(l.split()[2:5:2] for l in session_log.splitlines() if " blocked " in l)
    require(blocked.get("inj") == inj_pid, "injected pid %s, blocked %s" % (inj_pid, blocked))
    require(all(inj_pid in wb[w] for w in range(24)), "injected pid missing from app-b windows")
    require(all(blocked["bg"] in wa[w] for w in range(24)), "background pid missing from app-a windows")
    first_b = 0
    # background: check-in from t0, other jobs from the scaled schedule; all tools ran in app-a
    tools = [l for l in text.splitlines() if " tool " in l]
    require(any(" beacon 1000 10.0.0.1 80 600 " in l for l in tools), "no check-in: %s" % tools[:3])
    require(all(l.endswith("/app-a") for l in tools), "a background tool ran outside app-a")
    kinds = {l.split(" tool ")[1].split()[1] for l in tools}
    require({"beacon", "session", "bulk", "dns"} <= kinds, "background job kinds %s" % kinds)
    bg = (got / "bg.log").read_text()
    require("start checkin" in bg and any(k in bg for k in ("start hash", "start compress", "start archive",
                                                             "start search", "start listing", "start grep")),
            "bg.log lacks command jobs")
    # clock probes: three before t0, three after the end, with the guest's clocks
    start = json.loads((got / "clock-start.json").read_text())
    end = json.loads((got / "clock-end.json").read_text())
    phases = [p.split()[2] for _, p in r["probes"]]
    require(phases == ["start"] * 3 + ["end"] * 3, "probes received: %s" % phases)
    require(max(p["mono_ns"] for p in start["probes"]) < start["t0_mono_ns"], "start probes not before t0")
    require(min(p["mono_ns"] for p in end["probes"]) > start["t0_mono_ns"] + 12e9, "end probes not after the end")
    # cleanup
    require(not (r["case"] / "inj").exists() and not (r["case"] / "bgwork").exists(), "work folders left")
    require("sample.zip" not in [p.name for p in got.iterdir()], "archive packed")
    require((got / "injected.sha256").read_text().split()[0] == r["plan"]["INJ_SHA256"], "injected hash")
    return {"injected_delay_s": round(delay, 3), "app_b_first_window": first_b, "windows": len(wb),
            "background_tools": len(tools), "probes": len(phases)}


def check_none_case(r):
    got, text = r["got"], r["log"]
    require((got / "status.txt").read_text().strip() == "0", "status not 0")
    require(" injected start " not in text, "something was injected")
    require("pseudo injection" in (got / "session.log").read_text(), "no pseudo injection time")
    wb = windows(got / "host-b.log")
    require(wb and not any(wb.values()), "app-b not empty")
    return {"windows": len(wb)}


def check_broken_case(r):
    got, text = r["got"], r["log"]
    require((got / "status.txt").read_text().strip() == "1", "status not 1")
    require("not ready" in (got / "failed.txt").read_text(), "failure reason: %s" % (got / "failed.txt").read_text())
    require(" injected start " not in text and " tool " not in text, "something ran after a failed start")
    require(not (r["case"] / "inj").exists(), "work folder left")
    return {"failed": (got / "failed.txt").read_text().strip()}


def main():
    base = Path(sys.argv[1]).resolve() / ("session-local-%d" % time.time_ns())
    base.mkdir(parents=True)
    results = {"archive": check_archive_case(run_case(base, "archive", "malware", "archive")),
               "none": check_none_case(run_case(base, "none", "none", "none")),
               "broken": check_broken_case(run_case(base, "broken", "none", "none", broken=True))}
    print(json.dumps(results, indent=1))
    print("PASS local session test (%s)" % base)


if __name__ == "__main__":
    main()
