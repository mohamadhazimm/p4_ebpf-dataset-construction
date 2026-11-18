"""Operator auto-tasker for the Sliver C2 testbed.

Runs on the host, drives the Sink's sliver-client (localhost operator) via the sinkhole driver's credential-safe
sink_run. Every poll it lists sessions and beacons, finds the live ones, and issues a FIXED benign task list to
each (by server-assigned ID, so it is immune to reused names and dead entries). Each live implant is tasked once
per TASK_EVERY seconds, a few times across its window, to generate a command phase. Logs every task to a JSONL
file. The task list is hard-coded and benign (system info + small lab-file ops); it cannot issue anything else.

Runs until a stop file appears or a duration elapses. Intended to run as a background daemon for the whole
collection, decoupled from the collect timing.

Run: /usr/bin/python3 autotask.py --duration 9000 --log <path> [--stop <file>] [--once]
"""
import argparse
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import collect_sinkhole_c2 as c2  # noqa: E402

LAB = "/home/remnux/hazim-sliver"
LABDIR = "/home/csci/hazim-lab"          # staged in the guest by the collect payload
TASK_EVERY = 25                          # re-task a live implant at most this often
LIVE_BEACON_S = 20                       # a beacon counts as live if it checked in this recently

# Fixed benign task list, run after `use <id>`. System info + reading existing system files + one write to /tmp.
# No guest pre-staging needed. Nothing else; the operator cannot issue anything but these.
TASKS = ["whoami", "getuid", "getgid", "getpid", "info", "pwd", "ls",
         "execute -o uname -a", "execute -o id", "execute -o cat /etc/os-release",
         "download /etc/hostname", "upload %s/lab-upload.txt /tmp/uploaded.txt" % LAB, "cat /etc/hostname"]
ID = re.compile(r"^\s*([0-9a-f]{8})\s+(\S+)\s")
AGO = re.compile(r"\((?:(\d+)m)?(\d+)s ago\)")


def strip(text):
    return "\n".join(re.sub(r"\x1b\[[0-9;]*m", "", l).rstrip() for l in text.splitlines())


def client(module, lines, timeout_ms=90000):
    body = "\n".join(lines + ["exit"])
    script = ("cat > %s/at.rc <<'RC'\n%s\nRC\ncd %s && timeout %d ./sliver-client_linux-amd64 --config op.cfg "
              "--rc at.rc 2>&1") % (LAB, body, LAB, timeout_ms // 1000 - 10)
    r = c2.sink_run(module, ["/bin/bash", "-lc", script], timeout_ms=timeout_ms)
    return strip((r.stdout or "") + (r.stderr or ""))


def live_implants(module):
    """Return [(id, name, kind)] for ALIVE sessions and recently-checked-in beacons."""
    out = []
    text = client(module, ["sessions"])
    alive = "[ALIVE]" in text
    for line in text.splitlines():
        m = ID.match(line)
        if m and "[ALIVE]" in line:
            out.append((m.group(1), m.group(2), "session"))
    text = client(module, ["beacons"])
    for line in text.splitlines():
        m = ID.match(line)
        if not m:
            continue
        a = AGO.search(line)
        secs = (int(a.group(1) or 0) * 60 + int(a.group(2))) if a else 9999
        if secs <= LIVE_BEACON_S:
            out.append((m.group(1), m.group(2), "beacon"))
    return out


def task_one(module, iid):
    return client(module, ["use " + iid] + TASKS)


def run(module, duration, log, stop, once):
    logf = open(log, "a")
    last = {}
    end = time.time() + duration
    rounds = 0
    while time.time() < end:
        if stop and Path(stop).exists():
            break
        rounds += 1
        try:
            live = live_implants(module)
        except Exception as e:                       # noqa: BLE001  keep the daemon alive
            json.dump({"t": time.time(), "error": str(e)[:200]}, logf); logf.write("\n"); logf.flush()
            time.sleep(8)
            continue
        for iid, name, kind in live:
            if time.time() - last.get(iid, 0) >= TASK_EVERY:
                out = task_one(module, iid)
                ok = "csci" in out or "uid=" in out
                last[iid] = time.time()
                json.dump({"t": round(time.time(), 1), "id": iid, "name": name, "kind": kind,
                           "tasked": True, "result_ok": ok, "tail": out[-200:]}, logf)
                logf.write("\n"); logf.flush()
                print("tasked %s %-20s %s" % (iid, name, "ok" if ok else "queued/async"))
        if once:
            break
        time.sleep(8)
    logf.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=600)
    ap.add_argument("--log", default=str(HERE / "autotask.log.jsonl"))
    ap.add_argument("--stop", default="")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    module = c2.cp.frozen.helper()
    assert module.isolated("Sink")["VMState"] == '"running"', "Sink not running"
    run(module, a.duration, a.log, a.stop or None, a.once)


if __name__ == "__main__":
    main()
