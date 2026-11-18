"""Sensor-visibility test: do the malware that stayed silent in our lab connect when nothing of ours runs in the guest?

Seven dataset malware (5 Tsunami, 2 DeskRAT, all held-out test rows) used the network within seconds on Triage's
internet-connected sandbox but sent nothing in our lab (sample-intel-20261113/triage_network-20261115.csv). Several
of them first list the running processes; in our lab the collector (Python runner, bpftrace, tcpdump) and its paths
(/tmp/malware-lab) are visible there, while Triage watches from outside the VM. Each sample is run twice, 60 s each,
in the same sealed lab (quiet headless guest from the same staged snapshot, the Sink with INetSim and dnsmasq, no
internet), plus a null program and a benign positive control:

  A (collect):   as in the dataset: the production batch and the .22 collector inside the guest, 60 s.
  B (collect-b): nothing of ours in the guest. The guest only unpacks and starts the sample (start.sh, bash exec,
                 stdin /dev/null, own session, neutral /tmp path); VirtualBox records the guest's virtual network card
                 from outside; after the 60 s, one process listing shows whether the sample is still running.

Reading: connects in B but not in A -> our in-guest tools or paths make them quit. Silent in both -> something
else (VirtualBox itself, whose helper processes are present in both; or a real internet connection). The positive
control (the lab's benign low-rate poller, every 5 s for 58 s) must appear in the B recording for the whole minute,
and the null must stay silent; otherwise B is not readable.

Every VM phase needs a verbatim approval; one attempt per phase, no retries; original TLS snapshot and NIC-trace state
restored on every exit. Phases: preflight -> sink-check -> stage -> dry-run -> collect (A) -> collect-b (B), then
--validate (A captures) and --analyze (A vs B, offline).

    python3 collect_visibility.py --self-test | --freeze-only
    python3 collect_visibility.py --phase PHASE --attempt DIR --protocol-sha256 SHA --approval TEXT
    python3 collect_visibility.py --analyze --attempt DIR --protocol-sha256 SHA
"""
import argparse
import fcntl
import importlib.util
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
sys.path.insert(0, str(ASR))
sys.path.insert(0, str(HERE))
import collect_pilot as cp                    # noqa: E402  .22 pins and the batch phase machinery (A runs)
import build_visibility_payload as builder    # noqa: E402

VIS_SETTINGS = ["--timeout", "60", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
                "--fixed-observation", "--common-launch-wrapper"]
cp.v21.SETTINGS = VIS_SETTINGS                # the batch command reads these
cp.SETTINGS = VIS_SETTINGS                    # the pilot's plan check compares against these
cp.FORMAT = FORMAT = "sensor-visibility-v1"
cp.EXPECTED_WINDOWS = 120
require, digest, save, load, stamp = cp.require, cp.digest, cp.save, cp.load, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA

B_SECONDS = 60
READINESS_SECONDS, PROBE_PERIOD_SECONDS = 75, 5      # as quiet_ambient_v32 (headless boots answer in ~20 s)
GUEST_IP = "10.0.0.10"
SINK_VM, SINK_USER = "Sink", "remnux"
RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")


def _module_from(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ------------------------------------------------------------------------------------------------------- freeze

def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed")
    run_id = stamp()
    attempt = HERE / "runs" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/d-" + run_id
    manifest, order = builder.build(attempt / "payload")
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    protocol = {
        "format": FORMAT, "schema": cp.SCHEMA, "production_hashes": cp.PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": cp.BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-vis-" + run_id, "benign_snapshot": "clean-vis-unused-" + run_id,
        "guest_root": guest_root, "settings": VIS_SETTINGS,
        "settings_required": {"telemetry_schema_version": cp.SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "members": manifest["members"], "expected_windows": 120, "b_seconds": B_SECONDS,
        "readiness_seconds": READINESS_SECONDS,
        "sink_required": {"inetsim_http": "10.0.0.1:80", "dns": "10.0.0.1:53", "dnsmasq_answers": "10.0.0.1",
                          "sinkhole": "off"},
        "payload_sha256": digest(attempt / "payload.tgz"), "start_sh_sha256": digest(HERE / "start.sh"),
        "builder_sha256": digest(Path(builder.__file__)), "driver_sha256": digest(Path(__file__)),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "model_fitting": False, "merge_with_any_dataset": False, "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt")},
        "source": "sample-intel-20261113/triage_network-20261115.csv (active on Triage, silent in the lab)",
        "limitations": ["7 samples of 2 families; one run per sample and variant.",
                        "B removes our tools AND our telling paths (/tmp/malware-lab, the runner's directories) at once;",
                        "a difference between A and B points at both together, not at one of them.",
                        "VirtualBox's own guest helpers (VBoxService) are visible in A and B alike.",
                        "B has no system-call data; only packets (recorded outside the guest) and one process listing.",
                        ".22 captures of 60 s; never merged with the dataset or any other collection."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "new_snapshot": protocol["new_snapshot"],
                      "payload_kb": round((attempt / "payload.tgz").stat().st_size / 1024),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    protocol = cp.verify_plan(attempt, expected_hash)
    require(protocol["settings"] == VIS_SETTINGS and protocol["b_seconds"] == B_SECONDS, "Frozen settings differ")
    require(digest(HERE / "start.sh") == protocol["start_sh_sha256"], "start.sh changed since freeze")
    return protocol


# ------------------------------------------------------------------------------------------------- the Sink

def _with_password(module, fn):
    fd, name = tempfile.mkstemp(prefix="hz-vis-")
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


def sink_bash(module, script, timeout_ms=60000):
    info = module.isolated(SINK_VM)
    require(info["VMState"] == '"running"', "Sink is not running")
    return _with_password(module, lambda pw: module.vbox(
        "guestcontrol", SINK_VM, "run", "--username", SINK_USER, "--passwordfile", pw, "--exe", "/bin/bash",
        "--wait-stdout", "--wait-stderr", "--timeout", str(timeout_ms), "--", "-c", script, check=False))


SINK_SCRIPT = ("ss -Hltnu 2>/dev/null; echo '=== nft'; sudo -n nft list tables 2>&1; echo '=== dnsmasq';"
               " ps -eo args | grep '[d]nsmasq'; grep -h '^address' /etc/dnsmasq.d/*.conf 2>/dev/null")


def sink_verdict(text):
    listen, nft, dns = (text + "\n=== nft\n=== dnsmasq\n").split("=== nft", 1)[0], "", ""
    if "=== nft" in text:
        nft = text.split("=== nft", 1)[1].split("=== dnsmasq", 1)[0]
        dns = text.split("=== dnsmasq", 1)[1] if "=== dnsmasq" in text else ""
    checks = {"inetsim_http": bool(re.search(r"tcp\s+LISTEN\s+\S+\s+\S+\s+(10\.0\.0\.1|0\.0\.0\.0|\*):80\s", listen)),
              "dns_udp": bool(re.search(r"udp\s+UNCONN\s+\S+\s+\S+\s+(10\.0\.0\.1|0\.0\.0\.0|\*):53\s", listen)),
              "sinkhole_off": "hazim" not in nft.lower(),
              "dnsmasq_answers_sink": "address=/#/10.0.0.1" in dns and "203.0.113" not in dns}
    return checks


def sink_check(attempt, expected_hash, approval):
    require(approval and approval.strip(), "A verbatim user approval is required")
    protocol = verify_plan(attempt, expected_hash)
    prior = load(attempt / "phases/preflight/result.json")
    require(prior["status"] == "passed" and prior["protocol_sha256"] == expected_hash, "Preflight not accepted")
    destination = attempt / "phases/sink-check"
    destination.mkdir(parents=True, exist_ok=False)
    save(destination / "authorization.json", {"approval": approval, "phase": "sink-check", "read_only": True,
         "protocol_sha256": expected_hash, "authorized_utc": datetime.now(timezone.utc).isoformat()})
    result = {"phase": "sink-check", "protocol_sha256": expected_hash, "status": "failed_preserved"}
    try:
        module = cp.frozen.helper()
        r = sink_bash(module, SINK_SCRIPT)
        (destination / "sink_state.txt").write_text((r.stdout or "") + (r.stderr or ""))
        result["checks"] = sink_verdict(r.stdout or "")
        require(all(result["checks"].values()), "Sink not set up as in the dataset: %s" % result["checks"])
        result["status"] = "passed"
    finally:
        save(destination / "result.json", result)
    print(json.dumps(result, indent=2))


# ------------------------------------------------------------------------------------------------------ B runs

def guest_run(module, auth, *command, timeout=120):
    return module.vbox("guestcontrol", module.VM, "run", *auth, "--exe", command[0], "--wait-stdout",
                       "--wait-stderr", "--timeout", str(timeout * 1000), "--", *command[1:], check=False)


def wait_boot_guest(module, auth, directory, deadline_ns):
    """Power on, then probe Guest Control with /bin/true every 5 s until it answers (quiet_ambient_v32's routine)."""
    receipt = {"events": [], "deadline_ns": deadline_ns, "status": "rejected"}
    try:
        response = module.vbox("startvm", module.VM, "--type", "headless", check=False, timeout=5)
        receipt["events"].append({"operation": "startvm", "returncode": response.returncode})
        require(response.returncode == 0, "Boot power-on failed")
        while True:
            started = time.monotonic_ns()
            remaining = (deadline_ns - started) / 1e9
            require(remaining > 0, "Guest Control did not answer within %d s of power-on" % READINESS_SECONDS)
            try:
                code = module.vbox("guestcontrol", module.VM, "run", *auth, "--exe", "/bin/true", "--wait-stdout",
                                   "--wait-stderr", "--timeout", "5000", "--", check=False,
                                   timeout=min(PROBE_PERIOD_SECONDS, remaining)).returncode
            except subprocess.TimeoutExpired:
                code = None
            receipt["events"].append({"operation": "guestcontrol", "returncode": code, "ended_ns": time.monotonic_ns()})
            if code == 0:
                receipt["status"] = "accepted"
                return
            pause = PROBE_PERIOD_SECONDS - (time.monotonic_ns() - started) / 1e9
            if pause > 0:
                time.sleep(min(pause, max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)))
    finally:
        save(directory / "startup-readiness.json", receipt)


def run_b_case(module, trace_state, protocol, destination, case, auth):
    d = destination / case["sample"][:-4]
    d.mkdir()
    rec = {"sample": case["sample"], "label": case["label"], "family": case.get("family")}
    module.vbox("snapshot", module.VM, "restore", protocol["new_snapshot"])
    module.isolated(module.VM)
    trace = d / "nic.pcap"
    module.vbox("modifyvm", module.VM, "--nictracefile1", str(trace), "--nictrace1", "on")
    require(trace_state(module.vm_info(module.VM)) == {"nictrace1": "on", "nictracefile1": str(trace)},
            "NIC trace not confirmed before power-on")
    rec["power_requested_ns"] = time.monotonic_ns()
    wait_boot_guest(module, auth, d, rec["power_requested_ns"] + READINESS_SECONDS * 1_000_000_000)
    rec["ready_ns"] = time.monotonic_ns()
    work = "/tmp/" + secrets.token_hex(4)
    rec["work_dir"] = work
    args = case.get("arguments") or []
    r = guest_run(module, auth, "/bin/bash", protocol["guest_root"] + "/start.sh",
                  protocol["guest_root"] + "/samples/" + case["sample"], work, *args, timeout=60)
    rec["launch_returncode"] = r.returncode
    rec["launched_ns"] = time.monotonic_ns()
    (d / "launch.log").write_text((r.stdout or "") + (r.stderr or ""))
    require(r.returncode == 0, "start.sh failed (%s)" % r.returncode)
    time.sleep(max(0.0, B_SECONDS - (time.monotonic_ns() - rec["launched_ns"]) / 1e9))
    rec["observation_end_ns"] = time.monotonic_ns()
    stop = module.vbox("controlvm", module.VM, "nictrace1", "off", check=False)
    rec["trace_stop_returncode"] = stop.returncode
    after = guest_run(module, auth, "/bin/sh", "-c",
                      "cat %s/.pid %s/.started 2>&1; echo '=== ps'; ps -e -o pid,ppid,etimes,stat,comm,args" % (work, work),
                      timeout=30)
    (d / "after.txt").write_text((after.stdout or "") + (after.stderr or ""))
    module.vbox("controlvm", module.VM, "poweroff")
    module.vbox("modifyvm", module.VM, "--nictrace1", "off")
    rec["trace_bytes"] = trace.stat().st_size if trace.exists() else 0
    save(d / "run.json", rec)
    return rec


def collect_b(attempt, expected_hash, approval):
    require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    protocol = verify_plan(attempt, expected_hash)
    for phase in ("sink-check", "collect"):
        prior = load(attempt / "phases" / phase / "result.json")
        require(prior["status"] == "passed" and prior["protocol_sha256"] == expected_hash, phase + " not accepted")
    import quiet_ambient_v21 as qa21           # trace-aware VM helper and cleanup (imported only here)
    module = qa21.runtime_helper()
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        destination = attempt / "phases/collect-b"
        destination.mkdir(parents=True, exist_ok=False)
        save(destination / "authorization.json", {"approval": approval, "phase": "collect-b", "protocol_sha256":
             expected_hash, "authorized_utc": datetime.now(timezone.utc).isoformat(), "one_attempt_only": True})
        result = {"phase": "collect-b", "protocol_sha256": expected_hash, "status": "failed_preserved", "runs": []}

        def interrupted(_signal, _frame):
            raise KeyboardInterrupt("Stop, restore original TLS/off and NIC trace state, preserve the failure")
        previous = signal.signal(signal.SIGTERM, interrupted)
        touched = False
        try:
            before = cp.v21.preflight(module, protocol)
            before["trace"] = qa21.base.trace_state(module.vm_info(module.VM))
            require(before["trace"] == qa21.ORIGINAL_TRACE, "Existing NIC trace; do not disturb another capture")
            save(destination / "initial_vm_state.json", before)
            staged = load(attempt / "phases/stage/result.json")
            require(cp.frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"],
                    "Staged child differs")
            touched = True
            with tempfile.NamedTemporaryFile(mode="w", prefix="hz-vis-auth-") as password:
                Path(password.name).chmod(0o600)
                password.write(module.credentials())
                password.flush()
                auth = ["--username", module.GUEST_USER, "--passwordfile", password.name]
                for case in protocol["cases"]:
                    result["runs"].append(run_b_case(module, qa21.base.trace_state, protocol, destination, case, auth))
            verify_plan(attempt, expected_hash)
            result["status"] = "passed"
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            try:
                if touched:
                    qa21.cleanup(module, destination, qa21.ORIGINAL_TRACE)
            except BaseException as error:
                result.update(status="cleanup_failed_requires_user", cleanup_error=type(error).__name__ + ": " + str(error))
                raise
            finally:
                save(destination / "result.json", result)
                signal.signal(signal.SIGTERM, previous)
    print(json.dumps({k: v for k, v in result.items() if k != "runs"}, indent=2))


# ------------------------------------------------------------------------------------------------------ analysis

def flows_of(pcap, start_offset_s=None, end_offset_s=None, start_us=None):
    """Guest TCP/UDP flows of a capture. With start_us: absolute window [start_us, start_us + 60 s) (A, in-guest
    capture). Otherwise offsets from the first record (B, VirtualBox trace, whose clock starts at the recording)."""
    sm = _module_from("switch_model", RELEASE / "features" / "switch_model.py")
    flows, first, before = {}, None, 0
    for time_us, _ts, frame in sm.read_pcap(str(pcap)):
        first = time_us if first is None else first
        if start_us is not None:
            off = (time_us - start_us) / 1e6
            if off < 0 or off >= B_SECONDS:
                continue
        else:
            off = (time_us - first) / 1e6
        p = sm.parse_flow_packet(frame)
        if p is None:
            continue
        src, dst, proto, ports, _flags = p
        if start_us is None and start_offset_s is not None and off < start_offset_s:
            before += 1
            continue
        if start_us is None and end_offset_s is not None and off > end_offset_s:
            continue
        a, b = (src, ports[0]), (dst, ports[1])
        key = (proto,) + ((a, b) if a <= b else (b, a))
        f = flows.setdefault(key, {"first": a, "peer": b, "fwd": 0, "rev": 0, "t0": off, "t1": off, "proto": proto})
        f["fwd" if a == f["first"] else "rev"] += 1
        f["t1"] = off
    guest = [f for f in flows.values() if f["first"][0] == GUEST_IP]
    return {"flows": len(guest), "answered": sum(1 for f in guest if f["rev"] > 0),
            "destinations": sorted({"%s:%s/%s" % (f["peer"][0], f["peer"][1], f["proto"]) for f in guest})[:12],
            "first_s": min((f["t0"] for f in guest), default=None), "last_s": max((f["t1"] for f in guest), default=None),
            "frames_before_start": before}


def process_listing(text):
    pid = text.split("\n", 1)[0].strip() if text else ""
    rows = [r for r in text.split("=== ps", 1)[1].splitlines() if r.strip()][1:] if "=== ps" in text else []
    alive = [r for r in rows if r.split()[:1] == [pid]] if pid.isdigit() else []
    young = [r.strip() for r in rows if len(r.split()) > 2 and r.split()[2].isdigit() and int(r.split()[2]) <= B_SECONDS + 15
             and not re.search(r"\b(ps|sh)\b", " ".join(r.split()[4:5]))]
    return {"launched_pid": pid, "launched_alive_at_end": bool(alive), "processes_younger_than_window": young[:12]}


def a_summary(attempt, case):
    runs = list((attempt / "runs" / case["sample"] / "output").glob("run_*/run.json"))
    if len(runs) != 1:
        return {"status": "missing"}
    m = load(runs[0])
    pcap = runs[0].parent / "packet_capture.pcap"
    out = {"return_code": m.get("return_code"), "exec": (m.get("target_exec") or {}).get("status"),
           "post_target_syscalls": (m.get("target_exec") or {}).get("post_target_lineage_raw_syscalls"),
           "quality": m.get("collection_quality_status")}
    if pcap.exists():
        out.update(flows_of(pcap, start_us=int(m["sample_started_wall_us"])))
    ev = runs[0].parent / "ebpf_events.csv"
    if ev.exists():
        text = ev.read_text(errors="replace")
        out["process_list_reads"] = len(re.findall(r"path=(/proc/)?\d+/(cmdline|stat|status)\b", text))
        out["pgrep_pidof_ps_execs"] = len(re.findall(r"execve.*path=\S*/(pgrep|pidof|ps)\b", text))
    return out


def analyze(attempt, expected_hash):
    protocol = verify_plan(attempt, expected_hash)
    rows = []
    for case in protocol["cases"]:
        b = {}
        d = attempt / "phases/collect-b" / case["sample"][:-4]
        if (d / "run.json").exists():
            rec = load(d / "run.json")
            start = (rec["launched_ns"] - rec["power_requested_ns"]) / 1e9 - 1.0   # trace starts near power-on
            end = (rec["observation_end_ns"] - rec["power_requested_ns"]) / 1e9 + 1.0
            b = flows_of(d / "nic.pcap", start_offset_s=start, end_offset_s=end)
            b.update(process_listing((d / "after.txt").read_text(errors="replace")))
        rows.append({"sample": case["sample"], "label": case["label"], "family": case.get("family", case.get("program")),
                     "A": a_summary(attempt, case), "B": b})
    out = {"protocol_sha256": expected_hash, "rows": rows,
           "readable": {"null_silent_in_B": next((r["B"].get("flows") == 0 for r in rows if r["label"] == "null"), None),
                        "control_seen_in_B_whole_minute": next(
                            (r["B"].get("flows", 0) >= 8 and (r["B"].get("last_s") or 0) - (r["B"].get("first_s") or 0) >= 45
                             for r in rows if r["label"] == "benign"), None)}}
    save(attempt / "analysis.json", out)
    print("%-10s %-8s | A: rc %-4s flows %-4s ans %-4s proc-reads %-5s | B: flows %-4s ans %-4s alive %s" % (
        "sample", "family", "", "", "", "", "", "", ""))
    for r in rows:
        a, b = r["A"], r["B"]
        print("%-10s %-8s | A: rc %-4s flows %-4s ans %-4s proc-reads %-5s | B: flows %-4s ans %-4s alive %s %s" % (
            r["sample"][:10], (r["family"] or "")[:8], a.get("return_code"), a.get("flows"), a.get("answered"),
            a.get("process_list_reads"), b.get("flows"), b.get("answered"), b.get("launched_alive_at_end"),
            b.get("destinations", [])[:3]))
    print("readable:", out["readable"])


# ------------------------------------------------------------------------------------------------------ self-test

def _pcap(path, records, linktype=1):
    import struct
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for t_us, frame in records:
            f.write(struct.pack("<IIII", t_us // 1_000_000, t_us % 1_000_000, len(frame), len(frame)))
            f.write(frame)


def _tcp(src, dst, sport, dport, flags=0x02):
    import socket
    import struct
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 1024, 0, 0)
    return b"\x00" * 6 + bytes.fromhex("001b210aee09") + b"\x08\x00" + ip + tcp


def self_test():
    import shutil
    from types import SimpleNamespace
    from unittest import mock
    with tempfile.TemporaryDirectory(prefix="hz-vis-test-") as tmp:
        tmp = Path(tmp)
        manifest, order = builder.build(tmp / "payload")
        require(manifest["counts"] == {"null": 1, "benign": 1, "malware": 7}, "payload counts")
        require(order[0]["label"] == "null" and order[1].get("control") == "positive", "order")
        # the batch command carries the 60-s settings
        fake = SimpleNamespace(VM="Ubuntu-Clean-24.04", GUEST_USER="csci")
        cmd = cp.v21.batch_command(fake, tmp, {"guest_root": "/g"}, "snap", tmp / "o", tmp / "c.txt")
        require(cmd[cmd.index("--timeout") + 1] == "60" and "--fixed-observation" in cmd, "batch settings")
        # pcap reading: VirtualBox's 4-byte start record, a guest SYN answered by a RST, one unanswered SYN
        p = tmp / "t.pcap"
        _pcap(p, [(0, b"\x00" * 4), (500_000, _tcp("10.0.0.10", "10.0.0.1", 40000, 80)),
                  (600_000, _tcp("10.0.0.1", "10.0.0.10", 80, 40000, 0x14)),
                  (9_000_000, _tcp("10.0.0.10", "1.2.3.4", 40001, 8080)),
                  (20_000_000, _tcp("10.0.0.10", "5.6.7.8", 40002, 23))])
        f = flows_of(p, start_offset_s=5.0, end_offset_s=15.0)
        require(f["flows"] == 1 and f["answered"] == 0 and f["frames_before_start"] == 2, "flows window %s" % f)
        f = flows_of(p, start_offset_s=0.0, end_offset_s=30.0)
        require(f["flows"] == 3 and f["answered"] == 1, "flows all %s" % f)
        # process listing
        listing = "1234\n1763.5\n=== ps\n  PID  PPID ELAPSED STAT COMMAND COMMAND\n 1234     1      58 Sl   x a\n 99 1 3000 S systemd x\n"
        pl = process_listing(listing)
        require(pl["launched_alive_at_end"] and len(pl["processes_younger_than_window"]) == 1, "process listing %s" % pl)
        # Sink checks
        good = ("udp UNCONN 0 0 10.0.0.1:53 0.0.0.0:*\ntcp LISTEN 0 5 10.0.0.1:80 0.0.0.0:*\n=== nft\n=== dnsmasq\n"
                "dnsmasq --conf-file=/etc/dnsmasq.d/malnet.conf\naddress=/#/10.0.0.1\n")
        require(all(sink_verdict(good).values()), "sink good %s" % sink_verdict(good))
        bad = good.replace("=== nft\n", "=== nft\ntable inet hazim_sinkhole\n")
        require(not sink_verdict(bad)["sinkhole_off"], "sink bad")
        # B case: the call sequence on a fake VirtualBox (no VM)
        calls = []

        class FakeModule:
            VM, GUEST_USER, __file__ = "Ubuntu-Clean-24.04", "csci", str(tmp / "fake.py")

            def __init__(self):
                self.trace = {"nictrace1": "off", "nictracefile1": "none"}

            def vbox(self, *a, check=True, timeout=None):
                calls.append(a)
                if a[:1] == ("modifyvm",) and "--nictracefile1" in a:
                    self.trace = {"nictrace1": "on", "nictracefile1": a[a.index("--nictracefile1") + 1]}
                    Path(self.trace["nictracefile1"]).write_bytes(b"")
                out = "1234\n0\n=== ps\n" if "-c" in a else ""
                return SimpleNamespace(returncode=0, stdout=out, stderr="")

            def isolated(self, name):
                return {"VMState": '"poweroff"'}

            def vm_info(self, name):
                return dict(self.trace)
        module = FakeModule()
        dest = tmp / "b"
        dest.mkdir()
        case = dict(order[1])
        with mock.patch("time.sleep"):
            rec = run_b_case(module, lambda info: {k: info[k] for k in ("nictrace1", "nictracefile1")},
                             {"new_snapshot": "snap", "guest_root": "/g"}, dest, case, ["--username", "csci"])
        ops = [c[0] if c[0] != "guestcontrol" else "gc:" + c[c.index("--exe") + 1] for c in calls]
        want = ["snapshot", "modifyvm", "startvm", "gc:/bin/true", "gc:/bin/bash", "controlvm", "gc:/bin/sh",
                "controlvm", "modifyvm"]
        require(ops == want, "B call order %s" % ops)
        launch = next(c for c in calls if "gc:/bin/bash" == ("gc:" + c[c.index("--exe") + 1] if "--exe" in c else ""))
        require(launch[-5:] == tuple(case["arguments"]) and "/g/start.sh" in launch, "launch arguments %s" % (launch,))
        require(rec["launch_returncode"] == 0 and calls[-1] == ("modifyvm", module.VM, "--nictrace1", "off"), "B end")
        shutil.rmtree(dest)
    print("PASS collect_visibility self-test (payload 7+1+1, 60-s batch settings, pcap/flows incl. the VirtualBox start "
          "record, process listing, Sink checks, B call order on a fake VirtualBox)")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--phase", choices=["preflight", "sink-check", "stage", "dry-run", "collect", "collect-b"])
    p.add_argument("--validate", action="store_true")
    p.add_argument("--analyze", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.analyze:
        analyze(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.validate:
        verify_plan(Path(a.attempt).resolve(), a.protocol_sha256)
        cp.validate(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.phase == "sink-check":
        sink_check(Path(a.attempt).resolve(), a.protocol_sha256, a.approval)
    elif a.phase == "collect-b":
        collect_b(Path(a.attempt).resolve(), a.protocol_sha256, a.approval)
    elif a.phase:
        attempt = Path(a.attempt).resolve()
        verify_plan(attempt, a.protocol_sha256)
        if a.phase == "collect":
            prior = load(attempt / "phases/sink-check/result.json")
            require(prior["status"] == "passed", "sink-check not accepted")
        cp.perform_phase(attempt, a.phase, a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only, --phase, --validate or --analyze")


if __name__ == "__main__":
    main()
