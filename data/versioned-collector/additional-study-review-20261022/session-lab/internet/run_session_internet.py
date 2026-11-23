#!/usr/bin/env python3
"""Session lab with real internet, for benign programs (user request 2026-11-19).

No Sink, no INetSim, no sinkhole, no fake DNS, no isolation check. Each session restores the real-internet snapshot
made by make_internet_snapshot.py (NIC 1 on VirtualBox NAT, DHCP), boots it, and runs one program from the plan as
the guest user inside the session lab's monitors: the in-kernel host monitor (two cgroups, 0.5-s windows) and the
socket tracer, exactly as in the isolated lab (guest/enter.sh and guest/session.sh are byte-identical copies). What
differs:
  network capture  VirtualBox's NIC trace of NIC 1, written on the host per session (sessions/<sid>/trace.pcap),
                   so the capture is outside the guest as before; it has no drop counter;
  background       none: guest/bg.sh only waits, so the lab adds no traffic of its own;
  clock probes     to the NAT gateway 10.0.2.2, UDP port 9 (they stay at VirtualBox's NAT engine);
  programs         benign only: the plan may hold benign, null and background-only sessions; an archive whose
                   program is a known sample (any SHA-256 the host side knows) is refused at freeze.
A rejected or failed session is recorded and the run goes on; three in a row stop it. At the end the VM goes back to
its original snapshot (clean-tls-paired-2026-10-19) and is powered off.

Plan file (JSON): {"duration_s": 180, "sessions": [{"name": ..., "kind": "benign"|"null"|"none",
  "source": "system"|"archive"|"tool"|"none", "exe": "/usr/bin/..." (system), "path": "<host zip>" (archive),
  "tool": "webfetch"|"netpoll" (tool), "args": [...], "t_inject_s": 60.0 (optional)}, ...]}

  /usr/bin/python3 run_session_internet.py --self-test
  /usr/bin/python3 run_session_internet.py --freeze-only [--plan example_plan.json]
  /usr/bin/python3 run_session_internet.py --run-all --attempt runs/<ID> --protocol-sha256 <SHA>
"""
import argparse
import fcntl
import json
import os
import random
import re
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
sys.path.insert(0, str(LAB))
sys.path.insert(0, str(HERE))
import run_session_lab as lab   # noqa: E402
import run_session_main as M    # noqa: E402

base = lab.base
require, sha256, save, load, now_utc, stamp = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc, lab.stamp
GUEST_DIR = HERE / "guest"
lab.GUEST = GUEST_DIR
FORMAT = "session-lab-internet-v1"
NAT_GATEWAY = "10.0.2.2"
RECORD = HERE / "snapshot.json"
KINDS = ("benign", "null", "none")
SAFE_NAME = re.compile(r"^[A-Za-z0-9._+-]{1,60}$")
SEED = 4271


def plan_env(s, duration):
    keep = lab.DUR_S
    lab.DUR_S = duration
    try:
        text = lab.plan_env(s)
    finally:
        lab.DUR_S = keep
    old = "PROBE_DST=%s\n" % lab.SINK_IP
    require(old in text, "plan.env layout differs")
    return text.replace(old, "PROBE_DST=%s\n" % NAT_GATEWAY)


def check_entry(e, i, known):
    kind = e.get("kind", "benign")
    require(kind in KINDS, "session %d (%s): this driver runs benign programs only, not kind %r"
            % (i, e.get("name"), kind))
    name = e.get("name") or ""
    require(SAFE_NAME.match(name), "session %d: name %r (letters, digits, . _ + - only)" % (i, name))
    source = e.get("source", "none" if kind == "none" else "system")
    args = e.get("args", [])
    require(isinstance(args, list) and all(isinstance(a, str) for a in args), "%s: args must be a list of strings" % name)
    s = {"kind": kind, "name": name, "source": source, "args": args}
    if kind == "none":
        require(source == "none", "%s: a background-only session injects nothing" % name)
    elif source == "system":
        exe = e.get("exe") or ""
        require(exe.startswith("/") and " " not in exe, "%s: exe must be an absolute guest path" % name)
        s["exe"] = exe
    elif source == "tool":
        require(e.get("tool") in ("webfetch", "netpoll"), "%s: tool must be webfetch or netpoll" % name)
        s["tool"] = e["tool"]
    elif source == "archive":
        path = Path(e.get("path") or "")
        require(path.is_file(), "%s: archive %s not found" % (name, path))
        s["host_archive"] = str(path.resolve())
        s["sha256"] = M.member_sha256(path)
        require(s["sha256"] not in known, "%s: the archive's program is a known sample; benign programs only" % name)
    else:
        raise ValueError("%s: unknown source %r" % (name, source))
    if "t_inject_s" in e:
        s["t_inject_s"] = float(e["t_inject_s"])
    return s


def freeze(plan_path=None, out_root=None, record=None, known=None):
    plan_path = Path(plan_path or HERE / "example_plan.json")
    out_root = Path(out_root or HERE / "runs")
    record = load(Path(record or RECORD)) if Path(record or RECORD).is_file() else None
    require(record, "no real-internet snapshot yet: run make_internet_snapshot.py --run first")
    plan = load(plan_path)
    entries = plan["sessions"] if isinstance(plan, dict) else plan
    duration = int(plan.get("duration_s", lab.DUR_S)) if isinstance(plan, dict) else lab.DUR_S
    require(30 <= duration <= 3600, "duration_s %s out of range" % duration)
    if known is None:
        import make_internet_snapshot as mk
        known = mk.known_hashes()[0]
    specs = [check_entry(e, i, known) for i, e in enumerate(entries, 1)]
    require(specs, "the plan has no sessions")
    for name, (path, want) in lab.TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed" % name)
    rng = random.Random(SEED)
    attempt = out_root / stamp()
    (attempt / "plans").mkdir(parents=True)
    (attempt / "samples").mkdir()
    sessions = []
    lo, hi = min(lab.INJECT_RANGE[0], duration * 0.2), min(lab.INJECT_RANGE[1], duration * 0.6)
    for i, spec in enumerate(specs, 1):
        s = dict(spec, sid="i%03d" % i, marker="hz" + secrets.token_hex(6), work="/tmp/" + secrets.token_hex(4),
                 bg_seed=rng.randrange(1, 32768))
        s.setdefault("t_inject_s", round(rng.uniform(lo, hi), 3))
        require(0 < s["t_inject_s"] < duration - 5, "%s: t_inject_s must be inside the session" % s["name"])
        if s["source"] == "archive":
            src = Path(s.pop("host_archive"))
            s["archive"] = "%s-%s" % (s["sid"], src.name if src.name.endswith(".zip") else src.name + ".zip")
            shutil.copy2(src, attempt / "samples" / s["archive"])
            s["archive_sha256"] = sha256(attempt / "samples" / s["archive"])
        (attempt / "plans" / (s["sid"] + ".env")).write_text(plan_env(s, duration))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts = {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    protocol = {
        "format": FORMAT, "plan": "internet-benign", "run_id": attempt.name, "frozen_utc": now_utc(),
        "plan_file": str(plan_path), "plan_file_sha256": sha256(plan_path), "duration_s": duration,
        "window_s": 0.5, "sessions": sessions, "counts": counts, "snapshot": record,
        "network": {"attachment": "VirtualBox NAT on NIC 1 (real internet)", "sink": "not used",
                    "capture": "VirtualBox NIC trace of NIC 1, one file per session (no drop counter)",
                    "probe_dst": NAT_GATEWAY},
        "background": "none (guest/bg.sh only waits)",
        "files": {n: sha256(GUEST_DIR / n) for n in lab.GUEST_FILES},
        "tools": {n: {"source": str(p), "sha256": w} for n, (p, w) in lab.TOOLS.items()},
        "known_sample_hashes_checked": len(known),
        "driver_sha256": sha256(__file__), "lab_driver_sha256": sha256(lab.__file__), "retries": False,
        "keep_going": "a rejected/failed session is recorded; %d in a row stop the run" % M.MAX_IN_A_ROW,
        "merge_with_any_dataset": False, "model_fitting": False,
        "limitations": ["benign programs only", "real internet: what remote servers send varies between runs",
                        "NIC trace has no drop counter", "no generated background",
                        "guest IP 10.0.2.15 behind VirtualBox NAT (the isolated lab used 10.0.0.10)",
                        "separate dataset; never merged with the isolated session runs"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"),
                      "counts": counts, "snapshot": record["name"],
                      "sessions": [(s["sid"], s["kind"], s["name"]) for s in sessions]}, indent=1))
    return attempt


def verify(attempt, expected):
    attempt = Path(attempt)
    require(sha256(attempt / "protocol.json") == expected, "protocol hash differs")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == FORMAT, "format differs")
    for n, want in protocol["files"].items():
        require(sha256(GUEST_DIR / n) == want, "guest file changed since freeze: " + n)
    for n, info in protocol["tools"].items():
        require(sha256(info["source"]) == info["sha256"], "tool changed since freeze: " + n)
    for s in protocol["sessions"]:
        require(sha256(attempt / "plans" / (s["sid"] + ".env")) == s["plan_sha256"], "plan changed: " + s["sid"])
        if s["source"] == "archive":
            require(sha256(attempt / "samples" / s["archive"]) == s["archive_sha256"], "archive changed: " + s["sid"])
    return protocol


def checks(sdir, protocol, s, trace):
    g = Path(sdir) / "guest"
    reasons = []
    status = (g / "status.txt").read_text().strip() if (g / "status.txt").is_file() else "missing"
    if status != "0":
        reasons.append("session status %s: %s" % (status, (g / "failed.txt").read_text().strip()
                                                  if (g / "failed.txt").is_file() else ""))
    windows = 2 * protocol["duration_s"]
    for name in ("host-a.log", "host-b.log"):
        text = (g / name).read_text() if (g / name).is_file() else ""
        health = [l for l in text.splitlines() if l.startswith("HOSTMON_HEALTH,")]
        if text.count("==== HOST WINDOW") < windows:
            reasons.append("%s: %d windows (< %d)" % (name, text.count("==== HOST WINDOW"), windows))
        if health != ["HOSTMON_HEALTH,0,0,0,0"]:
            reasons.append("%s: health %s" % (name, health))
    sock = (g / "sock.log").read_text() if (g / "sock.log").is_file() else ""
    if [l for l in sock.splitlines() if l.startswith("SOCKOWNER_HEALTH,")] != ["SOCKOWNER_HEALTH,0,0,0"]:
        reasons.append("sock.log health %s" % [l for l in sock.splitlines() if l.startswith("SOCKOWNER_")][-1:])
    if not trace.get("present"):
        reasons.append("no NIC trace")
    mine = [p for p in lab.sync_probes(Path(sdir) / "trace.pcap") if p[1] == s["sid"]] if trace.get("present") else []
    if sorted(p[2] for p in mine) != ["end"] * 3 + ["start"] * 3:
        reasons.append("clock probes %s" % sorted(p[2] for p in mine))
    spreads, medians = [], {}
    for phase in ("start", "end"):
        offsets = sorted(p[0] * 1000 - p[4] for p in mine if p[2] == phase)
        if offsets:
            spreads.append((offsets[-1] - offsets[0]) / 1e6)
            medians[phase] = offsets[len(offsets) // 2]
    spread = max(spreads) if len(spreads) == 2 else None
    drift = (medians["end"] - medians["start"]) / 1e6 if len(medians) == 2 else None
    if spread is None or spread > 20:
        reasons.append("clock probe jitter %s ms" % spread)
    if drift is None or abs(drift) > 2000:
        reasons.append("clock drift %s ms" % drift)
    if s["source"] == "archive":
        got = (g / "injected.sha256").read_text().split()[0] if (g / "injected.sha256").is_file() else ""
        if got != s["sha256"]:
            reasons.append("injected SHA-256 %s" % got[:16])
    return {"accepted": not reasons, "reasons": reasons, "probes": len(mine), "probe_jitter_ms": spread,
            "clock_drift_ms": drift}


def run_session(module, deps, attempt, protocol, s, auth, password_file):
    sdir = Path(attempt) / "sessions" / s["sid"]
    sdir.mkdir(parents=True, exist_ok=False)
    trace_path = sdir / "trace.pcap"
    rec = {"sid": s["sid"], "kind": s["kind"], "name": s["name"], "started_utc": now_utc(), "status": "failed"}
    timings, trace = {}, {}
    snap = protocol["snapshot"]["name"]

    def grun(*command, timeout=120):
        return module.vbox("guestcontrol", module.VM, "run", *auth, "--exe", command[0], "--wait-stdout",
                           "--wait-stderr", "--timeout", str(timeout * 1000), "--", *command[1:], check=False)

    def copyto(src, dst):
        done = module.vbox("guestcontrol", module.VM, "copyto", *auth, str(src), dst, check=False)
        require(done.returncode == 0, "copyto %s failed rc=%s %s" % (Path(src).name, done.returncode,
                                                                      (done.stderr or "")[:200]))
    try:
        base.power_off(module, deps)
        module.vbox("snapshot", module.VM, "restore", snap)
        info = module.vm_info(module.VM)
        require(info["CurrentSnapshotName"] == '"%s"' % snap, "internet snapshot not restored")
        rec["nic1"] = info.get("nic1")
        module.vbox("modifyvm", module.VM, "--nictrace1", "on", "--nictracefile1", str(trace_path))
        timings["boot_start"] = time.monotonic()
        deps.wait_guest(module, auth, sdir / "boot.log")
        timings["booted"] = time.monotonic()
        stage = "%s/s-%s" % (lab.GUEST_HOME, s["marker"])
        require(grun("/bin/mkdir", "-m", "700", stage).returncode == 0, "staging folder not created")
        copyto(password_file, stage + "/.auth")
        require(grun("/bin/chmod", "600", stage + "/.auth").returncode == 0, "credential chmod failed")
        for name in lab.GUEST_FILES:
            copyto(GUEST_DIR / name, "%s/%s" % (stage, name))
        copyto(Path(attempt) / "plans" / (s["sid"] + ".env"), stage + "/plan.env")
        for name, info in protocol["tools"].items():
            copyto(info["source"], "%s/%s" % (stage, name))
        if s["source"] == "archive":
            copyto(Path(attempt) / "samples" / s["archive"], stage + "/sample.zip")
        timings["enter"] = time.monotonic()
        proc = grun("/bin/bash", stage + "/enter.sh", stage, timeout=120)
        rec["enter"] = {"rc": proc.returncode, "stdout": (proc.stdout or "")[-500:], "stderr": (proc.stderr or "")[-500:]}
        require(proc.returncode == 0 and "started" in (proc.stdout or ""), "enter failed: %s" % rec["enter"])
        out = "%s/out-%s.tgz" % (lab.GUEST_HOME, s["marker"])
        deps.sleep(max(0.0, timings["enter"] + 20 + protocol["duration_s"] + 15 - time.monotonic()))
        polls = 0
        while True:
            polls += 1
            if grun("/usr/bin/test", "-e", out, timeout=30).returncode == 0:
                break
            require(time.monotonic() < timings["enter"] + protocol["duration_s"] + 300, "no session output in time")
            deps.sleep(5)
        rec["polls"] = polls
        back = module.vbox("guestcontrol", module.VM, "copyfrom", *auth, out, str(sdir / "out.tgz"), check=False)
        require(back.returncode == 0 and (sdir / "out.tgz").is_file(), "output not fetched")
        rec["out_sha256"] = sha256(sdir / "out.tgz")
        rec["files"] = lab.safe_extract(sdir / "out.tgz", sdir / "guest")
        rec["staging_removed"] = grun("/usr/bin/test", "-e", stage, timeout=30).returncode != 0
        require(rec["staging_removed"], "staging folder (with the credential) still present")
        rec["status"] = "ran"
    finally:
        try:
            base.power_off(module, deps)
        finally:
            module.vbox("modifyvm", module.VM, "--nictrace1", "off", check=False)
            trace = {"present": trace_path.is_file()}
            if trace["present"]:
                trace.update(bytes=trace_path.stat().st_size, sha256=sha256(trace_path))
            rec["trace"] = trace
            rec["timings_s"] = {k: round(v - timings.get("boot_start", v), 2) for k, v in timings.items()}
            rec["finished_utc"] = now_utc()
            save(sdir / "result.json", rec)
    rec["checks"] = checks(sdir, protocol, s, trace)
    rec["status"] = "accepted" if rec["checks"]["accepted"] else "rejected"
    (sdir / "result.json").unlink()
    save(sdir / "result.json", rec)
    return rec


def run_all(attempt, expected, approval=None, deps=None, only=None):
    attempt = Path(attempt).resolve()
    protocol = verify(attempt, expected)
    deps = deps or base.real_deps()
    module = deps.helper
    d = attempt / "phases" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    save(d / ("authorization-%s.json" % stamp()), {"approval": approval or "run by the user", "protocol_sha256": expected,
                                                    "authorized_utc": now_utc()})
    todo = [s for s in protocol["sessions"] if (not only or s["sid"] in only)
            and not (attempt / "sessions" / s["sid"] / "result.json").exists()]
    summary = {"phase": "sessions", "started_utc": now_utc(), "done": [], "status": "failed"}
    in_a_row = 0
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deps.check_competitors()
        try:
            require(module.vm_info(module.VM)["VMState"] == '"poweroff"', "the guest is running; stop it first")
            uuids = base.snapshot_uuids(module)
            snap = protocol["snapshot"]
            require(uuids.get(snap["name"]) == [snap["uuid"]], "internet snapshot %s missing or changed" % snap["name"])
            with tempfile.NamedTemporaryFile(mode="w", prefix="hz-sesslab-") as password:
                os.chmod(password.name, 0o600)
                password.write(module.credentials())
                password.flush()
                auth = ["--username", module.GUEST_USER, "--passwordfile", password.name]
                for s in todo:
                    try:
                        rec = run_session(module, deps, attempt, protocol, s, auth, password.name)
                        status, reasons = rec["status"], rec["checks"]["reasons"]
                    except Exception as error:     # recorded; the guest was powered off in run_session's finally
                        status, reasons = "failed", ["%s: %s" % (type(error).__name__, error)]
                        sdir = attempt / "sessions" / s["sid"]
                        if sdir.is_dir():
                            save(sdir / ("failure-%s.json" % stamp()), {"error": reasons[0], "failed_utc": now_utc()})
                    summary["done"].append({"sid": s["sid"], "status": status, "reasons": reasons})
                    print("%s %s %-8s %-24s %s %s" % (now_utc()[11:19], s["sid"], s["kind"], s["name"][:24], status,
                                                      "; ".join(reasons)[:300]), flush=True)
                    in_a_row = 0 if status == "accepted" else in_a_row + 1
                    require(in_a_row < M.MAX_IN_A_ROW, "%d sessions in a row not accepted; stopping" % in_a_row)
            summary["status"] = "passed"
        finally:
            try:
                base.power_off(module, deps)
            finally:
                module.vbox("snapshot", module.VM, "restore", base.ORIGINAL)
                final = module.vm_info(module.VM)
                summary["final_vm"] = {k: final.get(k) for k in ("VMState", "CurrentSnapshotName", "nic1", "intnet1")}
                summary["finished_utc"] = now_utc()
                save(d / ("result-%s.json" % stamp()), summary)
    print(json.dumps({"status": summary["status"], "sessions": len(summary["done"]),
                      "accepted": sum(1 for x in summary["done"] if x["status"] == "accepted"),
                      "final_vm": summary["final_vm"]}, indent=1))
    return summary


# ------------------------------------------------------------------------------------------------------ self-test

class FakeHelper(lab.FakeHelper):
    INTERNET = "clean-internet-benign-TEST"

    def __init__(self, folder, fail=None):
        super().__init__(folder, fail)
        self.uuids = dict(self.uuids, **{self.INTERNET: "11111111-2222-3333-4444-555555555555"})
        self.trace = None

    def vm_info(self, name):
        info = super().vm_info(name)
        if name == self.VM and self.current == self.INTERNET:
            info["nic1"] = '"nat"'
            info.pop("intnet1", None)
        return info

    def vbox(self, *args, check=True):
        if args[0] == "modifyvm":
            self.calls.append(args)
            require(self.state == "poweroff", "modifyvm while running")
            if "--nictracefile1" in args:
                self.trace = args[args.index("--nictracefile1") + 1]
            elif "--nictrace1" in args and args[args.index("--nictrace1") + 1] == "off":
                self.trace = None
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[0] == "controlvm" and self.state == "running" and self.trace:
            plan = [v for k, v in self.guest_files.items() if k.endswith("/plan.env")][-1]
            sid = re.search(r"^SID=(\S+)$", Path(plan).read_text(), re.M).group(1).strip("'")
            lab.fake_capture(Path(self.trace), sid)
        return super().vbox(*args, check=check)


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        record = folder / "snapshot.json"
        record.write_text(json.dumps({"name": FakeHelper.INTERNET, "uuid": "11111111-2222-3333-4444-555555555555"}))
        zpath = folder / "benign-tool.zip"
        import zipfile
        with zipfile.ZipFile(zpath, "w") as z:
            z.writestr("tool.elf", b"\x7fELF benign test bytes")
        plan = folder / "plan.json"
        plan.write_text(json.dumps({"sessions": [
            {"name": "background-only", "kind": "none"},
            {"name": "fetch", "exe": "/usr/bin/python3", "args": ["-c", "print(1)"]},
            {"name": "packed", "source": "archive", "path": str(zpath), "args": []},
            {"name": "null-true", "kind": "null", "exe": "/usr/bin/true"}]}))
        attempt = freeze(plan, folder / "runs", record, known=set())
        expected = sha256(attempt / "protocol.json")
        protocol = load(attempt / "protocol.json")
        env = (attempt / "plans" / "i002.env").read_text()
        require("PROBE_DST=10.0.2.2" in env and "PROBE_DST=10.0.0.1" not in env, "probe destination")
        helper = FakeHelper(folder)

        def wait_guest(h, auth, log):
            require(h.current == FakeHelper.INTERNET and h.vm_info(h.VM)["nic1"] == '"nat"', "not the internet snapshot")
            require(h.trace, "trace not on before boot")
            h.vbox("startvm", h.VM, "--type", "headless")
            Path(log).write_text("booted\n")
        deps = SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None, sleep=lambda x: None)
        summary = run_all(attempt, expected, deps=deps)
        done = {x["sid"]: x["status"] for x in summary["done"]}
        require(len(done) == 4 and all(v == "accepted" for v in done.values()), "fake run: %s" % done)
        require(all((attempt / "sessions" / sid / "trace.pcap").is_file() for sid in done), "traces missing")
        require(not any(a[:2] == ("guestcontrol", lab.SINK_VM) for a in helper.calls), "the Sink was used")
        require(helper.current == base.ORIGINAL and helper.state == "poweroff", "not restored")
        # refusals
        for bad in ({"name": "x", "kind": "malware", "exe": "/bin/true"}, {"name": "x", "kind": "attack"}):
            plan.write_text(json.dumps({"sessions": [bad]}))
            try:
                freeze(plan, folder / "runs2", record, known=set())
                raise AssertionError("malware/attack kind accepted")
            except ValueError as error:
                require("benign programs only" in str(error), str(error))
        plan.write_text(json.dumps({"sessions": [{"name": "y", "source": "archive", "path": str(zpath)}]}))
        try:
            freeze(plan, folder / "runs3", record, known={M.member_sha256(zpath)})
            raise AssertionError("known sample accepted")
        except ValueError as error:
            require("known sample" in str(error), str(error))
    print(json.dumps({"self_test": "ok", "fake_sessions": done}, indent=1))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--plan")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze(a.plan)
    elif a.run_all:
        run_all(a.attempt, a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only or --run-all")


if __name__ == "__main__":
    main()
