#!/usr/bin/env python3
"""Session lab: attacks injected into normal activity, network recorded outside the guest (see DESIGN.md).

One session = one boot of the quiet headless guest (restored from its baseline each time), DUR seconds long:
background activity from the start (guest/bg.sh), one program injected at a seeded random time (or nothing), the host
recorded in the kernel by two hostmon_agg (named sysstatd; one per cgroup) and sockowner (netcfgd), started and
stopped by guest/session.sh as root. The guest's traffic is recorded by tcpdump on the Sink (the guest's gateway).
The Sink answers everything: INetSim, dnsmasq answering every name with 203.0.113.200, the passive sinkhole on.

Phases (each needs the user's verbatim approval, recorded in the attempt):
  preflight      read-only: VM states and isolation, snapshot UUIDs, the Sink's services and tools;
  sink-prepare   sinkhole on, dnsmasq switched to the redirect configuration (answer checked), log sizes recorded;
  sessions       the sessions in order (or --only): restore baseline, Sink capture on, boot, stage, run, fetch,
                 capture off, power off; per-session technical checks; stop at the first failed check;
                 finally the original clean snapshot is restored;
  sink-logs      the catch-all, INetSim and dnsmasq log lines written since sink-prepare;
  sink-restore   original dnsmasq (answers 10.0.0.1) and sinkhole off, both checked.
--run-all does them in that order (the Sink is restored whatever happens once it was prepared).

  /usr/bin/python3 run_session_lab.py --self-test
  /usr/bin/python3 run_session_lab.py --freeze-only [--plan pilot|main]
  /usr/bin/python3 run_session_lab.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<user's words>"
                                      [--only s01,s02] [--deadline-utc 2026-11-16T11:30]
"""
import argparse
import fcntl
import hashlib
import json
import os
import random
import re
import secrets
import shlex
import struct
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
sys.path.insert(0, str(ASR / "sockowner-check"))
import run_sockowner_check as base      # noqa: E402  tested VM helpers (restore, boot wait, power off, UUIDs)
import run_sockowner_malware as rsm     # noqa: E402  archive check (one member, its SHA-256), streamed, nothing written

FORMAT = "session-lab-v1"
require, stamp, sha256 = base.require, base.stamp, base.sha256
GUEST = HERE / "guest"
GUEST_FILES = ["enter.sh", "session.sh", "bg.sh"]
P4 = HERE.parents[5] / "p4_ebpf"
TOOLS = {"sysstatd": (P4 / "ebpf_perf/build/hostmon_agg",
                      "afbcbe2f547689407667833c28cfce31fe3a9ce87002e6cfa85540613d6c9f62"),
         "netcfgd": (base.SOCKOWNER, "89a106b3d38ebbccee74d8f51cfcc07186e2bd4ffd50130773287f4c196ce856"),
         "webfetch": (ASR / "flood_gen", "1bc8630d60d7330b7089879cb2a684d2bbc59b8f47e980c1b7ff92155fefdd6d"),
         "netpoll": (ASR / "lowrate_gen", "37f8c12f5adec83bbe42d9e8e93166fabec52da0bb264de2b3b66a0e66e0d435")}
REV5 = ASR / "revision5-collection/20261025T100025568989Z/payload/samples"
RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
DUR_S = 180
INJECT_RANGE = (40.0, 100.0)
GUEST_USER, GUEST_HOME = "csci", "/home/csci"
SINK_VM, SINK_USER, SINK_IP, GUEST_IP = "Sink", "remnux", "10.0.0.1", "10.0.0.10"
SINK_CAP = "/var/tmp/hz-sesslab"
DNS_REDIRECT, DNS_ORIGINAL = "203.0.113.200", "10.0.0.1"
ORIGINAL_DNSMASQ_CONF = "/etc/dnsmasq.d/malnet.conf"
REDIRECT_DNSMASQ_CONF = "/usr/local/lib/hazim-sinkhole/dnsmasq-redirect.conf"
REDIRECT_CONF_TEXT = """# hazim sinkhole C2 experiment: same as /etc/dnsmasq.d/malnet.conf except the answer address.
# Every name resolves to an outside address, so connections by name also go through the sinkhole.
interface=enp0s3
listen-address=10.0.0.1
bind-interfaces
no-resolv
no-hosts
no-poll
address=/#/%s
log-queries
log-facility=/var/log/inetsim/dnsmasq.log
""" % DNS_REDIRECT
REDIRECT_CONF_SHA256 = hashlib.sha256(REDIRECT_CONF_TEXT.encode()).hexdigest()
SINK_LOGS = {"catchall.jsonl": "/var/log/hazim-sinkhole/catchall.jsonl",
             "inetsim-service.log": "/var/log/inetsim/service.log",
             "dnsmasq.log": "/var/log/inetsim/dnsmasq.log"}
DNS_PROBE = ("import socket,struct,random\n"
             "q=random.randint(0,65535)\n"
             "name='check.session-lab.example'\n"
             "pkt=struct.pack('>HHHHHH',q,0x0100,1,0,0,0)+b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))"
             "+b'\\x00'+struct.pack('>HH',1,1)\n"
             "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(pkt,('10.0.0.1',53))\n"
             "r=s.recv(512)\n"
             "print('ancount=%d a=%s'%(struct.unpack('>H',r[6:8])[0],'.'.join(map(str,r[-4:]))))\n")
UENV = ["HOME=" + GUEST_HOME, "USER=" + GUEST_USER, "LOGNAME=" + GUEST_USER, "SHELL=/bin/bash",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"]

TSUNAMI = [("0d762c8cbba56cd827c0dc710688d7410840940b9994020b8e365b63d3ff316c", "native_amd64_static"),
           ("3e16c3bc39182471cac0c89b9883bd102d23d4bb938eb648c7d88b8649e857a9", "native_i386_static"),
           ("7d22fabcc98916294775e10101526492c105b583ccc9cf3e2edad9187dab4f14", "native_i386_static"),
           ("86947b00a3d61b82b6f752876404953ff3c39952f2b261988baf63fbbbd6d6ae", "native_i386_static"),
           ("9e28f942262805b5fb59f46568fed53fd4b7dbf6faf666bedaf6ff22dd416572", "native_amd64_static")]
NETWORKED = [("0714651541a17ca4cd54ccc018d23b02aaf248d9d7ea5e6dab507ecef3c8e699", "Mirai", "native_amd64_static"),
             ("47b6ecba4e77e4fce84fe768b11d8bde2936938c2ae07a35aa9aa8f7fe6fe192", "Kaiji", "native_i386_static"),
             ("d328a8df797e9a5c3c2f282b014f7cf538e141143a3054cdb542ca360d43b624", "Ngioweb", "native_amd64_static"),
             ("8124f4ac27a1afb25d2479da9bf5f06c52e3e9cf25d4d514ec386f05e264dd14", "CoinMiner", "native_amd64_static")]
BENIGN = [
    {"name": "download-burst", "source": "tool", "tool": "webfetch", "args": ["bulk", "20", "10.0.0.1", "80"]},
    {"name": "browse-public", "source": "tool", "tool": "webfetch", "args": ["session", "60", "198.51.100.23", "80"]},
    {"name": "checkin-public", "source": "tool", "tool": "webfetch",
     "args": ["beacon", "15", "203.0.113.77", "80", "2000"]},
    {"name": "dns-poll", "source": "tool", "tool": "netpoll", "args": ["dns", "2000", "50000", "10.0.0.1"]},
    {"name": "archive-docs", "source": "system", "exe": "/usr/bin/tar", "args": ["czf", "docs.tgz", "/usr/share/doc"]},
    {"name": "file-search", "source": "system", "exe": "/usr/bin/find",
     "args": ["/usr/share", "-type", "f", "-name", "*.gz"]}]
ATTACKS = [{"name": "syn-sink-40k", "source": "tool", "tool": "webfetch", "args": ["synsink", "40000", "80", "10.0.0.1"]}]
NULLS = [{"name": "null-true", "source": "archive", "archive": "null-native_amd64_static-start.zip", "args": ["true"]}]


# ------------------------------------------------------------------------------------------------------- utilities

def save(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def load(path):
    return json.loads(Path(path).read_text())


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def helper_module():
    return base.real_deps().helper


# ----------------------------------------------------------------------------------------------------------- plans

def spec_malware(sha, family, mode):
    return {"kind": "malware", "name": family + "-" + sha[:8], "family": family, "mode": mode, "source": "archive",
            "archive": sha + ".zip", "sha256": sha, "args": []}


def session_specs(plan):
    if plan == "pilot":
        specs = [{"kind": "none", "name": "background-only"} for _ in range(3)]
        specs += [spec_malware(sha, "Tsunami", mode) for sha, mode in TSUNAMI]
        specs += [spec_malware(sha, fam, mode) for sha, fam, mode in NETWORKED]
        specs += [dict(a, kind="attack") for a in ATTACKS] + [dict(b, kind="benign") for b in BENIGN]
        specs += [dict(n, kind="null") for n in NULLS]
        return specs
    raise ValueError("unknown plan " + plan)


def order_sessions(specs, seed):
    """The first session is background-only (the smoke test); the rest in a seeded random order. Each session gets
    a seeded injection time in INJECT_RANGE (also the background-only ones: a pseudo time) and background seed."""
    rng = random.Random(seed)
    first = next(i for i, s in enumerate(specs) if s["kind"] == "none")
    rest = specs[:first] + specs[first + 1:]
    rng.shuffle(rest)
    out = []
    for i, spec in enumerate([specs[first]] + rest, 1):
        out.append(dict(spec, sid="s%02d" % i, t_inject_s=round(rng.uniform(*INJECT_RANGE), 3),
                        bg_seed=rng.randrange(1, 32768), marker="hz" + secrets.token_hex(6),
                        work="/tmp/" + secrets.token_hex(4)))
    return out


def plan_env(s):
    source = s.get("source", "none")
    values = {"SID": s["sid"], "MARKER": s["marker"], "KIND": s["kind"], "DUR_US": str(DUR_S * 10**6),
              "T_INJECT_US": str(int(round(s["t_inject_s"] * 1e6))), "BG_SEED": str(s["bg_seed"]),
              "BG_DUR_S": str(DUR_S), "SCALE_PM": "1000", "GUSER": GUEST_USER, "GGROUP": "", "GUID": "",
              "W": "/var/lib/work", "T": "/opt/work", "CGROOT": "/sys/fs/cgroup", "WORK": s["work"],
              "BGWORK": GUEST_HOME + "/work", "PROBE_DST": SINK_IP, "PROBE_PORT": "9",
              "OUT": "%s/out-%s.tgz" % (GUEST_HOME, s["marker"]), "INJ_SOURCE": source,
              "INJ_SHA256": s.get("sha256", ""), "INJ_TOOL": s.get("tool", ""), "INJ_EXE": s.get("exe", ""),
              "PY": "/usr/bin/python3", "DROP_AUTO": "1"}
    lines = ["# session lab plan %s (%s %s)" % (s["sid"], s["kind"], s["name"])]
    lines += ["%s=%s" % (k, shlex.quote(v)) for k, v in values.items()]
    lines.append("INJ_ARGS=(%s)" % " ".join(shlex.quote(a) for a in s.get("args", [])))
    lines.append("DROP=()")
    lines.append("UENV=(%s)" % " ".join(shlex.quote(e) for e in UENV))
    return "\n".join(lines) + "\n"


def null_member_sha256(path, sha):
    """For the benign null program (busybox): stream the single member and return its SHA-256."""
    import subprocess
    listing = subprocess.run(["7z", "l", "-slt", "-pinfected", str(path)], capture_output=True, text=True, check=True)
    names = [l.split("=", 1)[1].strip() for l in listing.stdout.splitlines() if l.startswith("Path = ")][1:]
    require(len(names) == 1, "null archive members %s" % names)
    blob = subprocess.run(["7z", "x", "-so", "-pinfected", str(path)], capture_output=True, check=True).stdout
    return hashlib.sha256(blob).hexdigest()


def freeze(plan="pilot", out_root=None, verify=None):
    out_root = Path(out_root or HERE / "runs")
    sessions = order_sessions(session_specs(plan), 42)
    for s in sessions:
        if s["kind"] == "null":
            s["sha256"] = null_member_sha256(REV5 / s["archive"], None)

    def verifier(path, sha):
        return (verify or rsm.verify_archive)(path, sha)
    for name, (path, want) in TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed: %s" % (name, path))
    for s in sessions:
        if s.get("source") == "archive":
            verifier(REV5 / s["archive"], s["sha256"])
            s["archive_sha256"] = sha256(REV5 / s["archive"])
    run_id = stamp()
    attempt = out_root / run_id
    (attempt / "plans").mkdir(parents=True)
    for s in sessions:
        (attempt / "plans" / (s["sid"] + ".env")).write_text(plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
    counts = {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    protocol = {
        "format": FORMAT, "plan": plan, "run_id": run_id, "frozen_utc": now_utc(), "duration_s": DUR_S,
        "inject_range_s": list(INJECT_RANGE), "window_s": 0.5, "sessions": sessions, "counts": counts,
        "guest": {"vm": "Ubuntu-Clean-24.04", "baseline": base.BASELINE, "baseline_uuid": base.BASELINE_UUID,
                  "original": base.ORIGINAL, "original_uuid": base.ORIGINAL_UUID, "user": GUEST_USER},
        "sink": {"vm": SINK_VM, "capture": "tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root (full frames)",
                 "capture_dir": SINK_CAP, "sinkhole": "on during the sessions", "dns_answer": DNS_REDIRECT,
                 "redirect_conf": REDIRECT_DNSMASQ_CONF, "redirect_conf_sha256": REDIRECT_CONF_SHA256,
                 "after": "sinkhole off, original dnsmasq (answers %s)" % DNS_ORIGINAL},
        "files": {name: sha256(GUEST / name) for name in GUEST_FILES},
        "tools": {name: {"source": str(path), "sha256": want} for name, (path, want) in TOOLS.items()},
        "driver_sha256": sha256(__file__), "approval": None, "retries": False, "merge_with_any_dataset": False,
        "model_fitting": False,
        "pilot_checks": ["capture: tcpdump received = captured, no drops; clock probes at start and end, stable offset",
                         "host monitors: windows for the whole session, health zero",
                         "hidden monitor: the Tsunami bots connect",
                         "controls: background-only and null sessions carry only the background's traffic; flows "
                         "attributed to the right cgroup",
                         "every session on the restored baseline; Sink restored at the end"],
        "limitations": ["generated background, not real users", "the Sink fakes services, no C2 protocol",
                        "VirtualBox helpers stay visible in the guest", "capture at the Sink, not the hardware switch",
                        "separate dataset; never merged with the paper's or any other collection"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"),
                      "counts": counts, "order": [(s["sid"], s["kind"], s["name"], s["t_inject_s"]) for s in sessions]},
                     indent=1))
    return attempt


def verify_plan(attempt, expected):
    attempt = Path(attempt)
    require(sha256(attempt / "protocol.json") == expected, "protocol hash differs")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == FORMAT, "format differs")
    for name, want in protocol["files"].items():
        require(sha256(GUEST / name) == want, "guest file changed since freeze: " + name)
    for name, info in protocol["tools"].items():
        require(sha256(info["source"]) == info["sha256"], "tool changed since freeze: " + name)
    for s in protocol["sessions"]:
        require(sha256(attempt / "plans" / (s["sid"] + ".env")) == s["plan_sha256"], "plan changed: " + s["sid"])
        if s.get("source") == "archive":
            require(sha256(REV5 / s["archive"]) == s["archive_sha256"], "archive changed: " + s["archive"])
    return protocol


# ------------------------------------------------------------------------------------------- the Sink (copies of the
# tested helpers of collect_transport21 / collect_sinkhole_c2; importing those would load collect_pilot's settings)

def _with_password(module, fn):
    fd, name = tempfile.mkstemp(prefix="hz-sinkpw-")
    secret = b""
    try:
        os.fchmod(fd, 0o600)
        secret = module.credentials().encode()
        os.write(fd, secret)
        os.close(fd)
        return fn(name)
    finally:
        try:
            with open(name, "r+b") as stream:
                stream.write(b"\0" * max(len(secret), 64))
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            pass
        os.unlink(name)


def sink_run(module, argv, timeout_ms=120000, sudo=False):
    info = module.isolated(SINK_VM)
    require(info["VMState"] == '"running"', "Sink is not running")
    exe, rest = ("/usr/bin/sudo", ["-n", *argv]) if sudo else (argv[0], list(argv[1:]))
    return _with_password(module, lambda pw: module.vbox(
        "guestcontrol", SINK_VM, "run", "--username", SINK_USER, "--passwordfile", pw, "--exe", exe,
        "--wait-stdout", "--wait-stderr", "--timeout", str(timeout_ms), "--", *rest, check=False))


def sink_root(module, script, timeout_ms=120000):
    return sink_run(module, ["/bin/bash", "-c", script], timeout_ms=timeout_ms, sudo=True)


def sink_copyto(module, local, remote):
    return _with_password(module, lambda pw: module.vbox(
        "guestcontrol", SINK_VM, "copyto", "--username", SINK_USER, "--passwordfile", pw, str(local), remote,
        check=False))


def sink_copyfrom(module, remote, local):
    return _with_password(module, lambda pw: module.vbox(
        "guestcontrol", SINK_VM, "copyfrom", "--username", SINK_USER, "--passwordfile", pw, remote, str(local),
        check=False))


def sink_status(module):
    proc = sink_run(module, ["/usr/local/sbin/hazim-sinkhole", "status"], sudo=True)
    text = proc.stdout or ""
    state = "on" if "state:              on" in text else "off" if "state:              off" in text else "unknown"
    return {"rc": proc.returncode, "state": state, "ok": "overall:            OK" in text, "text": text}


def dns_answer(module):
    proc = sink_run(module, ["/usr/bin/python3", "-I", "-c", DNS_PROBE])
    out = (proc.stdout or "").strip()
    return out.split("a=")[-1] if proc.returncode == 0 and "ancount=1" in out else "error: %s %s" % (
        out, (proc.stderr or "").strip()[:200])


def dnsmasq_processes(module):
    proc = sink_run(module, ["/usr/bin/pgrep", "-a", "-x", "dnsmasq"], sudo=True)
    return [line for line in (proc.stdout or "").splitlines() if line.strip()]


def switch_dnsmasq(module, conf, sleep=time.sleep):
    for _ in range(2):
        sink_run(module, ["/usr/bin/pkill", "-x", "dnsmasq"], sudo=True)
        for _ in range(20):
            if not dnsmasq_processes(module):
                break
            sleep(0.5)
    require(not dnsmasq_processes(module), "dnsmasq did not stop")
    started = sink_run(module, ["/usr/sbin/dnsmasq", "--conf-file=" + conf], sudo=True)
    require(started.returncode == 0, "dnsmasq did not start with %s: %s" % (conf, (started.stderr or "")[:300]))
    sleep(1.0)
    running = dnsmasq_processes(module)
    require(len(running) == 1 and ("--conf-file=" + conf) in running[0], "unexpected dnsmasq processes: %s" % running)
    return running


def log_sizes(module):
    sizes = {}
    for name, path in SINK_LOGS.items():
        proc = sink_run(module, ["/usr/bin/wc", "-l", path], sudo=True)
        sizes[name] = int(proc.stdout.split()[0]) if proc.returncode == 0 and (proc.stdout or "").split() else None
    return sizes


SINK_STATE = ("ss -Hltnu 2>/dev/null; echo '=== tools'; command -v tcpdump; tcpdump --version 2>&1 | head -2;"
              " echo '=== disk'; df -Pk /var/tmp | tail -1; echo '=== dnsmasq'; pgrep -a -x dnsmasq;"
              " echo '=== sinkhole'; /usr/local/sbin/hazim-sinkhole status 2>&1 | head -20")


def sink_state(module):
    proc = sink_root(module, SINK_STATE)
    text = proc.stdout or ""
    listen = text.split("=== tools", 1)[0]
    tools = text.split("=== tools", 1)[1].split("=== disk", 1)[0] if "=== tools" in text else ""
    disk = text.split("=== disk", 1)[1].split("=== dnsmasq", 1)[0] if "=== disk" in text else ""
    dns = text.split("=== dnsmasq", 1)[1].split("=== sinkhole", 1)[0] if "=== dnsmasq" in text else ""
    free_kb = int(disk.split()[3]) if len(disk.split()) > 3 and disk.split()[3].isdigit() else 0
    checks = {"inetsim_http": bool(re.search(r"tcp\s+LISTEN\s+\S+\s+\S+\s+(10\.0\.0\.1|0\.0\.0\.0|\*):80\s", listen)),
              "inetsim_https": bool(re.search(r"tcp\s+LISTEN\s+\S+\s+\S+\s+(10\.0\.0\.1|0\.0\.0\.0|\*):443\s", listen)),
              "dns_udp": bool(re.search(r"udp\s+UNCONN\s+\S+\s+\S+\s+(10\.0\.0\.1|0\.0\.0\.0|\*):53\s", listen)),
              "tcpdump": "/tcpdump" in tools, "disk_free_gb>=5": free_kb >= 5 * 1024 * 1024,
              "dnsmasq_one": len([l for l in dns.splitlines() if l.strip()]) == 1,
              "sinkhole_installed": "state:" in text}
    return checks, text


# ------------------------------------------------------------------------------------------------- Sink capture

COUNTER_RE = {"captured": r"(\d+) packets? captured", "received": r"(\d+) packets? received by filter",
              "dropped": r"(\d+) packets? dropped by kernel"}


def capture_start(module, run_id, sid):
    d = "%s/%s" % (SINK_CAP, run_id)
    script = ("install -d -m 0755 {d} && cd {d} && rm -f {s}.pcap {s}.err {s}.pid && "
              "(setsid tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root -w {s}.pcap "
              "</dev/null >/dev/null 2>{s}.err & echo $! > {s}.pid) && sleep 1.5 && p=$(cat {s}.pid) && "
              "[ \"$(cat /proc/$p/comm 2>/dev/null)\" = tcpdump ] && echo running $p && cat {s}.err").format(d=d, s=sid)
    proc = sink_root(module, script)
    out = proc.stdout or ""
    require(proc.returncode == 0 and "running" in out, "Sink capture did not start: %s %s" % (
        out[-300:], (proc.stderr or "")[-300:]))
    return {"dir": d, "pid": out.split("running", 1)[1].split()[0], "started_utc": now_utc(), "start_text": out}


def capture_stop(module, cap, sid, local):
    d = cap["dir"]
    script = ("cd {d} && p=$(cat {s}.pid) && if [ \"$(cat /proc/$p/comm 2>/dev/null)\" = tcpdump ]; then kill -INT $p; fi;"
              " for i in $(seq 1 75); do kill -0 $p 2>/dev/null || break; sleep 0.2; done;"
              " kill -0 $p 2>/dev/null && kill -KILL $p && echo killed; chmod 0644 {s}.pcap; echo '=== err';"
              " cat {s}.err; echo '=== sha'; sha256sum {s}.pcap; stat -c %s {s}.pcap").format(d=d, s=sid)
    proc = sink_root(module, script)
    out = proc.stdout or ""
    err = out.split("=== err", 1)[1].split("=== sha", 1)[0] if "=== err" in out else ""
    counters = {k: int(m.group(1)) for k, rx in COUNTER_RE.items() for m in [re.search(rx, err)] if m}
    sha = out.split("=== sha", 1)[1].split()[0] if "=== sha" in out and out.split("=== sha", 1)[1].split() else ""
    record = {"counters": counters, "killed": "killed" in out.split("=== err", 1)[0], "sink_sha256": sha,
              "stopped_utc": now_utc()}
    back = sink_copyfrom(module, "%s/%s.pcap" % (d, sid), local)
    record["fetched"] = back.returncode == 0 and Path(local).is_file()
    if record["fetched"]:
        record["sha256"] = sha256(local)
        record["bytes"] = Path(local).stat().st_size
        if record["sha256"] == sha:
            sink_root(module, "rm -f {d}/{s}.pcap".format(d=d, s=sid))
            record["removed_on_sink"] = True
    return record


# -------------------------------------------------------------------------------------------------- guest outputs

def safe_extract(archive, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    names = []
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            name = member.name[2:] if member.name.startswith("./") else member.name
            if member.isdir() and name in ("", "."):
                continue
            require(member.isfile() and name and "/" not in name and not name.startswith("."),
                    "unexpected member %r" % member.name)
            data = tar.extractfile(member).read()
            (dest / name).write_bytes(data)
            names.append(name)
    return sorted(names)


def read_pcap(path):
    """(time_us, frame) of a classic pcap (micro- or nanosecond); enough for the probe check."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    magic = data[:4]
    order = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    out, i = [], 24
    while i + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(order + "IIII", data[i:i + 16])
        i += 16
        out.append((sec * 10**6 + (frac // 1000 if nano else frac), data[i:i + incl]))
        i += incl
    return out


def sync_probes(pcap):
    """The guest's clock probes in a capture: [(capture_us, sid, phase, n, guest_mono_ns, guest_real_ns)]."""
    found = []
    for t, frame in read_pcap(pcap):
        if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[23] != 17:
            continue
        ihl = (frame[14] & 0x0F) * 4
        dport = struct.unpack(">H", frame[14 + ihl + 2:14 + ihl + 4])[0]
        payload = frame[14 + ihl + 8:]
        if dport == 9 and payload.startswith(b"HZSYNC "):
            parts = payload.decode(errors="replace").split()
            if len(parts) == 6:
                found.append((t, parts[1], parts[2], int(parts[3]), int(parts[4]), int(parts[5])))
    return found


def technical_checks(sdir, protocol, s, capture):
    """The per-session checks the run stops on (sample behaviour is never a failure)."""
    g = Path(sdir) / "guest"
    reasons = []
    status = (g / "status.txt").read_text().strip() if (g / "status.txt").is_file() else "missing"
    if status != "0":
        reasons.append("session status %s: %s" % (status, (g / "failed.txt").read_text().strip()
                                                  if (g / "failed.txt").is_file() else ""))
    windows = 2 * protocol["duration_s"]
    for name in ("host-a.log", "host-b.log"):
        text = (g / name).read_text() if (g / name).is_file() else ""
        blocks = text.count("==== HOST WINDOW")
        health = [l for l in text.splitlines() if l.startswith("HOSTMON_HEALTH,")]
        if blocks < windows:
            reasons.append("%s: %d windows (< %d)" % (name, blocks, windows))
        if health != ["HOSTMON_HEALTH,0,0,0,0"]:
            reasons.append("%s: health %s" % (name, health))
    sock = (g / "sock.log").read_text() if (g / "sock.log").is_file() else ""
    if [l for l in sock.splitlines() if l.startswith("SOCKOWNER_HEALTH,")] != ["SOCKOWNER_HEALTH,0,0,0"]:
        reasons.append("sock.log health %s" % [l for l in sock.splitlines() if l.startswith("SOCKOWNER_")][-1:])
    c = capture.get("counters", {})
    if not capture.get("fetched") or c.get("received") is None or c.get("received") != c.get("captured") \
            or c.get("dropped", 1) != 0 or capture.get("sha256") != capture.get("sink_sha256"):
        reasons.append("capture %s" % {k: capture.get(k) for k in ("counters", "fetched", "killed")})
    probes = sync_probes(Path(sdir) / "sink.pcap") if capture.get("fetched") else []
    mine = [p for p in probes if p[1] == s["sid"]]
    phases = sorted(p[2] for p in mine)
    if phases != ["end"] * 3 + ["start"] * 3:
        reasons.append("clock probes %s" % phases)
    # the offset (capture clock - guest monotonic clock) of each probe: within each set of three the jitter must be
    # small; between the start and the end set the two VMs' clocks drift (s01: 92 ms in 183 s), which the analysis
    # maps linearly, so the drift is only bounded
    spreads, medians = [], {}
    for phase in ("start", "end"):
        offsets = sorted(p[0] * 1000 - p[4] for p in mine if p[2] == phase)
        if offsets:
            spreads.append((offsets[-1] - offsets[0]) / 1e6)
            medians[phase] = offsets[len(offsets) // 2]
    spread_ms = max(spreads) if len(spreads) == 2 else None
    drift_ms = (medians["end"] - medians["start"]) / 1e6 if len(medians) == 2 else None
    if spread_ms is None or spread_ms > 20:
        reasons.append("clock probe jitter %s ms" % spread_ms)
    if drift_ms is None or abs(drift_ms) > 2000:
        reasons.append("clock drift %s ms" % drift_ms)
    if s.get("source") == "archive":
        got = (g / "injected.sha256").read_text().split()[0] if (g / "injected.sha256").is_file() else ""
        if got != s["sha256"]:
            reasons.append("injected SHA-256 %s" % got[:16])
    return {"accepted": not reasons, "reasons": reasons, "probes": len(mine), "probe_jitter_ms": spread_ms,
            "clock_drift_ms": drift_ms}


# ---------------------------------------------------------------------------------------------------------- phases

def phase_dir(attempt, name, approval, expected):
    d = Path(attempt) / "phases" / name
    d.mkdir(parents=True, exist_ok=True)
    n = len(list(d.glob("authorization*.json")))
    save(d / ("authorization-%d.json" % n), {"phase": name, "approval": approval, "protocol_sha256": expected,
                                             "authorized_utc": now_utc()})
    return d


def preflight(module, deps, attempt, expected, approval):
    d = phase_dir(attempt, "preflight", approval, expected)
    result = {"phase": "preflight", "status": "failed", "started_utc": now_utc()}
    try:
        deps.check_competitors()
        states = base.vm_states(module)
        result["vm"] = states
        require(states["guest"]["VMState"] == '"poweroff"'
                and states["guest"]["CurrentSnapshotName"] == '"%s"' % base.ORIGINAL
                and states["sink"]["VMState"] == '"running"',
                "need the guest powered off on %s and the Sink running" % base.ORIGINAL)
        for vm in ("guest", "sink"):
            info = states[vm]
            require(info.get("nic1") == '"intnet"' and info.get("intnet1") == '"malnet"'
                    and all(info.get("nic%d" % i) == '"none"' for i in range(2, 9)),
                    "%s is not on the isolated internal network only" % vm)
        uuids = base.snapshot_uuids(module)
        require(uuids.get(base.ORIGINAL) == [base.ORIGINAL_UUID], "original snapshot missing or its UUID differs")
        require(uuids.get(base.BASELINE) == [base.BASELINE_UUID], "quiet baseline missing or its UUID differs")
        checks, text = sink_state(module)
        (d / "sink_state.txt").write_text(text)
        result["sink_checks"] = checks
        require(all(checks.values()), "Sink not ready: %s" % checks)
        result["status"] = "passed"
    finally:
        result["finished_utc"] = now_utc()
        save(d / "result.json", result)
    return result


def sink_prepare(module, attempt, expected, approval):
    d = phase_dir(attempt, "sink-prepare", approval, expected)
    record = {"phase": "sink-prepare", "status": "failed", "started_utc": now_utc()}
    try:
        status = sink_status(module)
        record["sinkhole_before"] = {k: status[k] for k in ("state", "ok")}
        if status["state"] != "on":
            on = sink_run(module, ["/usr/local/sbin/hazim-sinkhole", "on"], sudo=True)
            record["sinkhole_on"] = {"rc": on.returncode, "out": (on.stdout or "")[-1500:],
                                     "err": (on.stderr or "")[-500:]}
            status = sink_status(module)
        record["sinkhole_after"] = {k: status[k] for k in ("state", "ok")}
        (d / "sinkhole_status.txt").write_text(status["text"])
        require(status["state"] == "on" and status["ok"], "sinkhole not on and OK")
        before = dnsmasq_processes(module)
        record["dnsmasq_before"] = before
        require(len(before) == 1 and ORIGINAL_DNSMASQ_CONF in before[0], "expected the original dnsmasq only")
        check = sink_run(module, ["/usr/bin/sha256sum", REDIRECT_DNSMASQ_CONF], sudo=True)
        if (check.stdout or "").split()[:1] != [REDIRECT_CONF_SHA256]:
            local = d / "dnsmasq-redirect.conf"
            local.write_text(REDIRECT_CONF_TEXT)
            require(sink_copyto(module, local, "/tmp/hz-dnsmasq-redirect.conf").returncode == 0, "copy failed")
            require(sink_run(module, ["/usr/bin/install", "-m", "0644", "-o", "root", "-g", "root",
                                      "/tmp/hz-dnsmasq-redirect.conf", REDIRECT_DNSMASQ_CONF], sudo=True).returncode == 0,
                    "install of the redirect conf failed")
            check = sink_run(module, ["/usr/bin/sha256sum", REDIRECT_DNSMASQ_CONF], sudo=True)
        require((check.stdout or "").split()[:1] == [REDIRECT_CONF_SHA256], "redirect conf hash differs on the Sink")
        try:
            record["dnsmasq_after"] = switch_dnsmasq(module, REDIRECT_DNSMASQ_CONF)
            record["dns_answer"] = dns_answer(module)
            require(record["dns_answer"] == DNS_REDIRECT, "DNS answer is %s" % record["dns_answer"])
        except BaseException:
            record["rollback"] = switch_dnsmasq(module, ORIGINAL_DNSMASQ_CONF)
            raise
        record["log_lines_before"] = log_sizes(module)
        record["status"] = "passed"
    finally:
        record["finished_utc"] = now_utc()
        save(d / ("result-%s.json" % stamp()), record)
    return record


def sink_logs(module, attempt, expected, approval):
    d = phase_dir(attempt, "sink-logs", approval, expected)
    prepared = sorted((Path(attempt) / "phases/sink-prepare").glob("result-*.json"))
    prepared = [p for p in prepared if load(p).get("status") == "passed"]
    require(prepared, "no passed sink-prepare record")
    before = load(prepared[-1])["log_lines_before"]
    record = {"phase": "sink-logs", "logs": {}, "started_utc": now_utc()}
    for name, path in SINK_LOGS.items():
        start = (before.get(name) or 0) + 1
        proc = sink_run(module, ["/usr/bin/tail", "-n", "+%d" % start, path], timeout_ms=600000, sudo=True)
        (d / name).write_text(proc.stdout or "")
        record["logs"][name] = {"rc": proc.returncode, "from_line": start, "sha256": sha256(d / name)}
    record["status"] = "passed"
    save(d / ("result-%s.json" % stamp()), record)
    return record


def sink_restore(module, attempt, expected, approval):
    d = phase_dir(attempt, "sink-restore", approval, expected)
    record = {"phase": "sink-restore", "status": "failed", "started_utc": now_utc()}
    try:
        sink_root(module, "pkill -INT -x tcpdump; true")
        record["dnsmasq"] = switch_dnsmasq(module, ORIGINAL_DNSMASQ_CONF)
        record["dns_answer"] = dns_answer(module)
        require(record["dns_answer"] == DNS_ORIGINAL, "DNS answer after restore is %s" % record["dns_answer"])
        off = sink_run(module, ["/usr/local/sbin/hazim-sinkhole", "off"], sudo=True)
        record["sinkhole_off_rc"] = off.returncode
        status = sink_status(module)
        record["sinkhole_after"] = {k: status[k] for k in ("state", "ok")}
        require(status["state"] == "off", "sinkhole did not switch off")
        record["status"] = "passed"
    finally:
        record["finished_utc"] = now_utc()
        save(d / ("result-%s.json" % stamp()), record)
    return record


def run_session(module, deps, attempt, protocol, s, auth, password_file):
    sdir = Path(attempt) / "sessions" / s["sid"]
    sdir.mkdir(parents=True, exist_ok=False)
    rec = {"sid": s["sid"], "kind": s["kind"], "name": s["name"], "started_utc": now_utc(), "status": "failed"}
    capture = {}
    timings = {}

    def grun(*command, timeout=120):
        return module.vbox("guestcontrol", module.VM, "run", *auth, "--exe", command[0], "--wait-stdout",
                           "--wait-stderr", "--timeout", str(timeout * 1000), "--", *command[1:], check=False)

    def copyto(src, dst):
        done = module.vbox("guestcontrol", module.VM, "copyto", *auth, str(src), dst, check=False)
        require(done.returncode == 0, "copyto %s failed rc=%s %s" % (Path(src).name, done.returncode,
                                                                      (done.stderr or "")[:200]))
    try:
        base.power_off(module, deps)
        module.vbox("snapshot", module.VM, "restore", base.BASELINE)
        require(module.isolated(module.VM)["CurrentSnapshotName"] == '"%s"' % base.BASELINE, "baseline not restored")
        capture = capture_start(module, protocol["run_id"], s["sid"])
        timings["boot_start"] = time.monotonic()
        deps.wait_guest(module, auth, sdir / "boot.log")
        timings["booted"] = time.monotonic()
        stage = "%s/s-%s" % (GUEST_HOME, s["marker"])
        require(grun("/bin/mkdir", "-m", "700", stage).returncode == 0, "staging folder not created")
        copyto(password_file, stage + "/.auth")
        require(grun("/bin/chmod", "600", stage + "/.auth").returncode == 0, "credential chmod failed")
        for name in GUEST_FILES:
            copyto(GUEST / name, "%s/%s" % (stage, name))
        copyto(Path(attempt) / "plans" / (s["sid"] + ".env"), stage + "/plan.env")
        for name, info in protocol["tools"].items():
            copyto(info["source"], "%s/%s" % (stage, name))
        if s.get("source") == "archive":
            copyto(REV5 / s["archive"], stage + "/sample.zip")
        timings["enter"] = time.monotonic()
        proc = grun("/bin/bash", stage + "/enter.sh", stage, timeout=120)
        rec["enter"] = {"rc": proc.returncode, "stdout": (proc.stdout or "")[-500:], "stderr": (proc.stderr or "")[-500:]}
        require(proc.returncode == 0 and "started" in (proc.stdout or ""), "enter failed: %s" % rec["enter"])
        out = "%s/out-%s.tgz" % (GUEST_HOME, s["marker"])
        deps.sleep(max(0.0, timings["enter"] + 20 + protocol["duration_s"] + 15 - time.monotonic()))
        polls = 0
        while True:
            polls += 1
            if grun("/usr/bin/test", "-e", out, timeout=30).returncode == 0:
                break
            require(time.monotonic() < timings["enter"] + protocol["duration_s"] + 300, "no session output in time")
            deps.sleep(5)
        timings["output"] = time.monotonic()
        rec["polls"] = polls
        back = module.vbox("guestcontrol", module.VM, "copyfrom", *auth, out, str(sdir / "out.tgz"), check=False)
        require(back.returncode == 0 and (sdir / "out.tgz").is_file(), "output not fetched")
        rec["out_sha256"] = sha256(sdir / "out.tgz")
        rec["files"] = safe_extract(sdir / "out.tgz", sdir / "guest")
        rec["staging_removed"] = grun("/usr/bin/test", "-e", stage, timeout=30).returncode != 0
        require(rec["staging_removed"], "staging folder (with the credential) still present")
        rec["status"] = "ran"
    finally:
        if capture:
            try:
                capture.update(capture_stop(module, capture, s["sid"], sdir / "sink.pcap"))
            except BaseException as error:  # the guest still gets powered off
                capture["stop_error"] = "%s: %s" % (type(error).__name__, error)
        rec["capture"] = capture
        try:
            base.power_off(module, deps)
        finally:
            rec["timings_s"] = {k: round(v - timings.get("boot_start", v), 2) for k, v in timings.items()}
            rec["finished_utc"] = now_utc()
            save(sdir / "result.json", rec)
    rec["checks"] = technical_checks(sdir, protocol, s, capture)
    rec["status"] = "accepted" if rec["checks"]["accepted"] else "rejected"
    save(sdir / "result.json", rec)
    return rec


def sessions_phase(module, deps, attempt, protocol, expected, approval, only=None, deadline=None):
    d = phase_dir(attempt, "sessions", approval, expected)
    todo = [s for s in protocol["sessions"] if (not only or s["sid"] in only)
            and not (Path(attempt) / "sessions" / s["sid"] / "result.json").exists()]
    summary = {"phase": "sessions", "started_utc": now_utc(), "done": [], "status": "failed"}
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deps.check_competitors()
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hz-sesslab-") as password:
                os.chmod(password.name, 0o600)
                password.write(module.credentials())
                password.flush()
                auth = ["--username", module.GUEST_USER, "--passwordfile", password.name]
                for s in todo:
                    if deadline and datetime.now(timezone.utc) >= deadline:
                        summary["stopped_at_deadline"] = s["sid"]
                        break
                    rec = run_session(module, deps, attempt, protocol, s, auth, password.name)
                    summary["done"].append({"sid": s["sid"], "status": rec["status"], "reasons": rec["checks"]["reasons"]})
                    print("%s %s %-16s %s %s" % (now_utc()[11:19], s["sid"], s["name"][:16], rec["status"],
                                                 "; ".join(rec["checks"]["reasons"])[:300]), flush=True)
                    require(rec["status"] == "accepted", "session %s rejected: %s" % (s["sid"], rec["checks"]["reasons"]))
            summary["status"] = "passed"
        finally:
            try:
                base.power_off(module, deps)
            finally:
                module.vbox("snapshot", module.VM, "restore", base.ORIGINAL)
                final = base.vm_states(module)
                summary["final_vm_state"] = final
                summary["finished_utc"] = now_utc()
                save(d / ("result-%s.json" % stamp()), summary)
                require(final["guest"]["VMState"] == '"poweroff"'
                        and final["guest"]["CurrentSnapshotName"] == '"%s"' % base.ORIGINAL,
                        "cleanup incomplete: guest not powered off on " + base.ORIGINAL)
    return summary


def run_all(attempt, expected, approval, deps=None, only=None, deadline=None):
    require(approval and approval.strip(), "a verbatim user approval is required")
    protocol = verify_plan(attempt, expected)
    deps = deps or base.real_deps()
    module = deps.helper
    require(module.ORIGINAL == base.ORIGINAL, "helper's original snapshot differs")
    preflight(module, deps, attempt, expected, approval)
    prepared = False
    try:
        sink_prepare(module, attempt, expected, approval)
        prepared = True
        sessions_phase(module, deps, attempt, protocol, expected, approval, only=only, deadline=deadline)
    finally:
        if prepared:
            try:
                sink_logs(module, attempt, expected, approval)
            finally:
                sink_restore(module, attempt, expected, approval)
        else:
            try:
                sink_restore(module, attempt, expected, approval)
            except BaseException as error:
                print("sink restore after a failed prepare: %s" % error, flush=True)


# -------------------------------------------------------------------------------------------------------- self-test

class FakeHelper(base.FakeHelper):
    """The attribution check's fake VirtualBox, plus the Sink and this driver's guest files."""

    def __init__(self, folder, fail=None, uuids=None):
        super().__init__(folder, fail, uuids)
        self.folder = folder
        self.sinkhole, self.dns, self.tcpdump = "off", DNS_ORIGINAL, {}
        self.guest_files = {}

    def vbox(self, *args, check=True):
        if args[0] != "guestcontrol":
            return super().vbox(*args, check=check)
        self.calls.append(args)
        out = SimpleNamespace(returncode=0, stdout="", stderr="")
        vm, verb = args[1], args[2]
        if vm == SINK_VM:
            if verb == "run":
                rest = list(args[args.index("--") + 1:])
                if rest[:1] == ["-n"]:
                    rest = rest[1:]
                text = " ".join(rest)
                if "ss -Hltnu" in text:
                    out.stdout = ("tcp LISTEN 0 5 10.0.0.1:80 0.0.0.0:*\ntcp LISTEN 0 5 10.0.0.1:443 0.0.0.0:*\n"
                                  "udp UNCONN 0 0 10.0.0.1:53 0.0.0.0:*\n=== tools\n/usr/bin/tcpdump\n=== disk\n"
                                  "/dev/sda1 100 50 99999999 1% /\n=== dnsmasq\n777 /usr/sbin/dnsmasq\n=== sinkhole\n"
                                  "state:              off\n")
                elif "setsid tcpdump" in text:
                    sid = text.split("-w ")[1].split(".pcap")[0]
                    self.tcpdump[sid] = "running"
                    out.stdout = "running 4242\n"
                elif "kill -INT" in text and ".pid" in text:
                    sid = text.split("cat ")[1].split(".pid")[0]
                    self.tcpdump[sid] = "stopped"
                    pcap = self.folder / ("fake-%s.pcap" % sid)
                    fake_capture(pcap, sid)
                    out.stdout = ("=== err\n100 packets captured\n100 packets received by filter\n0 packets dropped "
                                  "by kernel\n=== sha\n%s  %s.pcap\n%d\n" % (sha256(pcap), sid, pcap.stat().st_size))
                elif rest[:1] == ["/usr/bin/sha256sum"]:
                    out.stdout = REDIRECT_CONF_SHA256 + "  " + REDIRECT_DNSMASQ_CONF + "\n"
                elif rest[:1] == ["/usr/local/sbin/hazim-sinkhole"] and rest[-1] == "status":
                    out.stdout = "state:              %s (backend nft)\noverall:            %s\n" % (
                        self.sinkhole, "OK" if self.sinkhole == "on" else "off")
                elif rest[:1] == ["/usr/local/sbin/hazim-sinkhole"] and rest[-1] in ("on", "off"):
                    self.sinkhole = rest[-1]
                elif rest[:1] == ["/usr/bin/pgrep"]:
                    conf = REDIRECT_DNSMASQ_CONF if self.dns == DNS_REDIRECT else ORIGINAL_DNSMASQ_CONF
                    out.stdout = "" if self.dns == "stopped" else "777 /usr/sbin/dnsmasq --conf-file=%s\n" % conf
                elif rest[:1] == ["/usr/bin/pkill"]:
                    self.dns = "stopped"
                elif rest[:1] == ["/usr/sbin/dnsmasq"]:
                    self.dns = DNS_REDIRECT if REDIRECT_DNSMASQ_CONF in rest[1] else DNS_ORIGINAL
                elif rest[:2] == ["-I", "-c"]:
                    out.stdout = "ancount=1 a=%s\n" % self.dns
                elif rest[:1] == ["/usr/bin/wc"]:
                    out.stdout = "10 file\n"
                elif rest[:1] == ["/usr/bin/tail"]:
                    out.stdout = "line\n"
            elif verb == "copyfrom":
                sid = Path(args[-2]).stem
                Path(args[-1]).write_bytes((self.folder / ("fake-%s.pcap" % sid)).read_bytes())
            return out
        # the guest
        if verb == "copyto":
            if self.fail == "copyto":
                out.returncode = 1
            self.guest_files[args[-1]] = args[-2]
            if args[-1].endswith("/.auth"):
                self.auth_present = True
        elif verb == "run":
            exe = args[args.index("--exe") + 1]
            rest = list(args[args.index("--") + 1:])
            if exe == "/bin/bash" and rest[0].endswith("/enter.sh"):
                self.auth_present = self.fail == "keep-auth"
                self.staging_gone = self.fail != "keep-auth"
                out.stdout = "started 999\n"
                self.entered = rest[1]
            elif exe == "/usr/bin/test":
                if rest[-1].endswith(".tgz"):
                    out.returncode = 0 if self.fail != "no-output" else 1
                else:
                    out.returncode = 1 if getattr(self, "staging_gone", True) else 0
        elif verb == "copyfrom":
            plan = [v for k, v in self.guest_files.items() if k.endswith("/plan.env")][-1]
            found = re.search(r"^INJ_SHA256=(\S*)$", Path(plan).read_text(), re.M)
            fake_outputs(Path(args[-1]), (found.group(1) if found else "").strip("'"),
                         broken=self.fail == "bad-health")
        return out


def fake_capture(pcap, sid):
    frames = []
    base_us = 1_700_000_000_000_000
    for phase, offset in (("start", 0), ("end", 190_000_000)):
        for n in range(3):
            mono = 5_000_000_000 + offset * 1000 + n * 100_000_000
            payload = ("HZSYNC %s %s %d %d %d" % (sid, phase, n, mono, 0)).encode()
            udp = struct.pack(">HHHH", 40000, 9, 8 + len(payload), 0) + payload
            ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes([10, 0, 0, 10]),
                             bytes([10, 0, 0, 1])) + udp
            frames.append((base_us + offset + n * 100_000, b"\x00" * 12 + b"\x08\x00" + ip))
    data = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
    for t, f in frames:
        data += struct.pack("<IIII", t // 10**6, t % 10**6, len(f), len(f)) + f
    pcap.write_bytes(data)


def fake_outputs(path, injected_sha256, broken=False):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        blocks = "".join("==== HOST WINDOW %d START=%.3f END=%.3f DUR=0.5\n" % (w, w / 2, w / 2 + 0.5)
                         for w in range(2 * DUR_S + 1))
        health = "HOSTMON_HEALTH,0,0,0,%d\n" % (1 if broken else 0)
        (tmp / "host-a.log").write_text("HOSTMON_READY,1\n" + blocks + health)
        (tmp / "host-b.log").write_text("HOSTMON_READY,2\n" + blocks + "HOSTMON_HEALTH,0,0,0,0\n")
        (tmp / "sock.log").write_text("SOCKOWNER_READY,1\nSOCKOWNER_HEALTH,0,0,0\n")
        (tmp / "status.txt").write_text("0\n")
        (tmp / "session.log").write_text("fake\n")
        if injected_sha256:
            (tmp / "injected.sha256").write_text(injected_sha256 + "\n")
        with tarfile.open(path, "w:gz") as tar:
            for name in sorted(os.listdir(tmp)):
                tar.add(tmp / name, arcname="./" + name)


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        # 1. plans: pilot composition, order, injection times, quoting of arguments with spaces and globs
        sessions = order_sessions(session_specs("pilot"), 42)
        kinds = [s["kind"] for s in sessions]
        require(len(sessions) == 20 and kinds[0] == "none" and kinds.count("malware") == 9 and kinds.count("none") == 3
                and kinds.count("benign") == 6 and kinds.count("attack") == 1 and kinds.count("null") == 1,
                "pilot composition %s" % kinds)
        require(all(INJECT_RANGE[0] <= s["t_inject_s"] <= INJECT_RANGE[1] for s in sessions), "injection times")
        again = order_sessions(session_specs("pilot"), 42)
        require([s["name"] for s in again] == [s["name"] for s in sessions], "order not reproducible")
        search = next(s for s in sessions if s["name"] == "file-search")
        env = plan_env(search)
        import subprocess
        shown = subprocess.run(["bash", "-c", 'set -u; . "$1"; printf "%s|" "${INJ_ARGS[@]}"; echo; '
                                'printf "%s|" "${UENV[@]}"; echo "$KIND $INJ_EXE $DROP_AUTO ${#DROP[@]}"', "_",
                                "/dev/stdin"], input=env, capture_output=True, text=True, check=True).stdout
        require("/usr/share|-type|f|-name|*.gz|" in shown and "benign /usr/bin/find 1 0" in shown
                and "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|" in shown,
                "plan.env round trip: %s" % shown)
        for name in GUEST_FILES:
            subprocess.run(["bash", "-n", str(GUEST / name)], check=True)
        # 2. a fake attempt (no archive checks: fake verifier), then the whole chain against the fake VirtualBox
        verified = []
        attempt = freeze("pilot", folder / "runs", verify=lambda p, sha: verified.append(p.name) or sha)
        expected = sha256(attempt / "protocol.json")
        require(len(verified) == 10, "archives verified at freeze: %d" % len(verified))

        def deps(fail=None):
            helper = FakeHelper(folder, fail)

            def wait_guest(h, auth, log):
                require(Path(auth[3]).read_text() == "not-a-real-secret", "password file not handed over")
                h.vbox("startvm", h.VM, "--type", "headless")
            return SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None,
                                   sleep=lambda s: None)
        d = deps()
        run_all(attempt, expected, "self-test approval", deps=d, only={"s01", "s02", "s03"})
        restores = [c[3] for c in d.helper.calls if c[:1] == ("snapshot",) and c[2] == "restore"]
        require(restores == [base.BASELINE] * 3 + [base.ORIGINAL], "restore order %s" % restores)
        require(d.helper.sinkhole == "off" and d.helper.dns == DNS_ORIGINAL, "Sink not restored")
        require(all(v == "stopped" for v in d.helper.tcpdump.values()) and len(d.helper.tcpdump) == 3, "captures")
        for sid in ("s01", "s02", "s03"):
            rec = load(attempt / "sessions" / sid / "result.json")
            require(rec["status"] == "accepted", "%s: %s" % (sid, rec.get("checks")))
        staged = [c[-1].rsplit("/", 1)[-1] for c in d.helper.calls if c[:3] == ("guestcontrol", base.FakeHelper.VM,
                                                                                    "copyto")]
        require(staged[:1] == [".auth"] and "plan.env" in staged and "sysstatd" in staged, "staged %s" % staged[:12])
        for path in attempt.rglob("*"):
            if path.is_file():
                require(b"not-a-real-secret" not in path.read_bytes(), "secret written to " + str(path))
        # 3. a rejected session stops the run; the guest and the Sink are still restored
        d = deps("bad-health")
        try:
            run_all(attempt, expected, "self-test approval", deps=d, only={"s04", "s05"})
            raise AssertionError("bad health accepted")
        except ValueError as error:
            require("s04 rejected" in str(error), "error %s" % error)
        require(not (attempt / "sessions/s05").exists(), "continued after a rejected session")
        require(d.helper.state == "poweroff" and d.helper.current == base.ORIGINAL and d.helper.sinkhole == "off",
                "not restored after a rejected session")
        # 4. no approval / changed guest file: refused before any VirtualBox call
        d = deps()
        for approval in ("", "  "):
            try:
                run_all(attempt, expected, approval, deps=d)
                raise AssertionError("ran without approval")
            except ValueError:
                pass
        require(not d.helper.calls, "VirtualBox called without approval")
        # 5. capture parsing and output extraction guards
        fake_capture(folder / "p.pcap", "s09")
        probes = sync_probes(folder / "p.pcap")
        require([p[2] for p in probes] == ["start"] * 3 + ["end"] * 3 and all(p[1] == "s09" for p in probes), "probes")
        bad = folder / "bad.tgz"
        with tarfile.open(bad, "w:gz") as tar:
            info = tarfile.TarInfo("../escape")
            info.size = 1
            import io
            tar.addfile(info, io.BytesIO(b"x"))
        try:
            safe_extract(bad, folder / "x")
            raise AssertionError("escaping member accepted")
        except ValueError:
            pass
    print("PASS run_session_lab self-test (pilot plan, plan.env quoting, fake VirtualBox chain with Sink prepare/"
          "restore and captures, stop on a rejected session, refusals, probe parsing, extraction guard)")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--plan", default="pilot")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    p.add_argument("--only")
    p.add_argument("--deadline-utc")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze(a.plan)
    elif a.run_all:
        deadline = datetime.fromisoformat(a.deadline_utc).replace(tzinfo=timezone.utc) if a.deadline_utc else None
        only = set(a.only.split(",")) if a.only else None
        run_all(Path(a.attempt).resolve(), a.protocol_sha256, a.approval, only=only, deadline=deadline)
    else:
        p.error("choose --self-test, --freeze-only or --run-all")


if __name__ == "__main__":
    main()
