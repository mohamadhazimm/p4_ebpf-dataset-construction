"""Driver for the sinkhole C2 experiment (300 s / 600 windows): 28 C2/backdoor samples + 28 benign clients + 3 null.

Reuses collect_pilot's phase machinery unchanged (preflight / stage / dry-run / collect / validate, .22 runner, quiet
baseline, restore original TLS/off on every mutating exit, no retries). Adds the Sink-side steps that make the network
the experiment needs and put it back afterwards:

  sink prepare  the sinkhole must already be on and OK; dnsmasq is switched to answer every name with the outside
                address 203.0.113.200 (instead of the Sink's own 10.0.0.1) so that domain-based C2, like IP-based C2,
                goes through the sinkhole; the answer is checked; counters and log sizes are recorded.
  sink logs     after collect: the catch-all log, INetSim's service log, the dnsmasq log and the nft counters.
  sink restore  original dnsmasq (answers 10.0.0.1) back and checked, sinkhole switched off.

  /usr/bin/python3 collect_sinkhole_c2.py --self-test | --freeze-only
  /usr/bin/python3 collect_sinkhole_c2.py --run-all --attempt A --protocol-sha256 H --approval "<user's words>"
  (or single steps: --phase preflight|stage|dry-run|collect, --sink prepare|logs|restore, --validate, --behavior)

Sink commands run as `remnux` through Guest Control with `sudo -n`; the password comes from the drivers' helper and
lives only in a 0600 temporary file. Nothing here sends anything to a sample.
"""

import csv
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_pilot as cp                       # noqa: E402  phase machinery + .22 pins + 300 s settings
import build_sinkhole_c2_payload as bsc         # noqa: E402

cp.FORMAT = "sinkhole-c2-5min-v1"
FORMAT = cp.FORMAT
require, digest, save, load, stamp = cp.require, cp.digest, cp.save, cp.load, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE

KIT = ROOT / "sink-sinkhole"
SINK_VM, SINK_USER = "Sink", "remnux"
DNS_REDIRECT = "203.0.113.200"
DNS_ORIGINAL = "10.0.0.1"
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
SINK_LOGS = {"catchall.jsonl": "/var/log/hazim-sinkhole/catchall.jsonl",
             "inetsim-service.log": "/var/log/inetsim/service.log",
             "dnsmasq.log": "/var/log/inetsim/dnsmasq.log"}
DNS_PROBE = ("import socket,struct,random\n"
             "q=random.randint(0,65535)\n"
             "name='check.sinkhole-c2.example'\n"
             "pkt=struct.pack('>HHHHHH',q,0x0100,1,0,0,0)+b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))"
             "+b'\\x00'+struct.pack('>HH',1,1)\n"
             "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(pkt,('10.0.0.1',53))\n"
             "r=s.recv(512)\n"
             "print('ancount=%d a=%s'%(struct.unpack('>H',r[6:8])[0],'.'.join(map(str,r[-4:]))))\n")


# ------------------------------------------------------------------------------------------------ freeze / verify

def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed")
    run_id = stamp()
    attempt = ROOT / "sinkhole-c2-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/sinkholec2-" + run_id
    manifest, order = bsc.build(attempt / "payload", guest_root)
    require(manifest["counts"] == {"malware": 28, "benign": 28, "null": 3}, "payload counts differ")
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in order if c["label"] != "malware"))
    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-sinkholec2-" + run_id, "benign_snapshot": "clean-sinkholec2-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "by_group": manifest["by_group"], "benign_binaries": manifest["benign_binaries"],
        "expected_windows": cp.EXPECTED_WINDOWS, "payload_sha256": digest(attempt / "payload.tgz"),
        "sink": {"vm": SINK_VM, "sinkhole_required": "on", "dns_answer_during_collect": DNS_REDIRECT,
                 "dns_answer_restored": DNS_ORIGINAL, "redirect_conf": REDIRECT_DNSMASQ_CONF,
                 "redirect_conf_sha256": hashlib.sha256(REDIRECT_CONF_TEXT.encode()).hexdigest(),
                 "kit": {name: digest(KIT / name) for name in ("sinkhole.sh", "sinkhole_catchall.py")},
                 "after": "sinkhole off, original dnsmasq"},
        "malware_sources": ["c2-viability/20261025T142642347649Z (all 18)",
                            "evasive-viability/20261025T151638248361Z (Rekoobe, cap 10; BPFDoor left out: passive)"],
        "builder_sha256": digest(Path(bsc.__file__)), "driver_sha256": digest(__file__),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "model_fitting": False, "merge_with_any_dataset": False, "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Experiment 1 of the C2 work: with the passive sinkhole on, do real C2/backdoor samples' check-ins",
                    "reach the wire, and can host/network/hybrid features tell them from benign clients that also",
                    "contact outside addresses (polling, retries against silent servers, holds, one-shots)?"],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec;",
                     "600x169 finite telemetry; safe archive hashes; nulls quiet; Sink in sinkhole mode with the",
                     "DNS redirect for the whole collect phase (checked right before it starts)."],
        "limitations": ["Separate dataset variant (sinkhole on); never merged with any other capture.",
                        "The sinkhole never replies on non-HTTP/DNS ports and INetSim is not a C2 server, so only the",
                        "start of a C2 session is visible (hello, retries, waits), never commands.",
                        "Benign side: 7 programs (wget, curl, openssl, lowrate_gen, git, rsync, whois); lowrate_gen is",
                        "self-built; Rekoobe builds are near-duplicates (about 3-4 distinct builds)."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_mode_label": protocol["by_mode_label"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576, 1),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    protocol = cp.verify_plan(attempt, expected_hash)
    for name, expected in protocol["sink"]["kit"].items():
        require(digest(KIT / name) == expected, "sinkhole kit changed since freeze: " + name)
    return protocol


# ----------------------------------------------------------------------------------------------------- Sink side

def sink_run(module, argv, timeout_ms=120000, sudo=True):
    """Run argv on the Sink as remnux (with sudo -n unless sudo=False). Returns the CompletedProcess."""
    info = module.isolated(SINK_VM)
    require(info["VMState"] == '"running"', "Sink is not running")
    fd, name = tempfile.mkstemp(prefix="hz-sinkpw-")
    secret = b""
    try:
        os.fchmod(fd, 0o600)
        secret = module.credentials().encode()
        os.write(fd, secret)
        os.close(fd)
        exe, rest = ("/usr/bin/sudo", ["-n", *argv]) if sudo else (argv[0], list(argv[1:]))
        return module.vbox("guestcontrol", SINK_VM, "run", "--username", SINK_USER, "--passwordfile", name,
                           "--exe", exe, "--wait-stdout", "--wait-stderr", "--timeout", str(timeout_ms),
                           "--", *rest, check=False)
    finally:
        try:
            with open(name, "r+b") as stream:
                stream.write(b"\0" * max(len(secret), 64))
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            pass
        os.unlink(name)


def sink_copyto(module, local, remote):
    fd, name = tempfile.mkstemp(prefix="hz-sinkpw-")
    secret = b""
    try:
        os.fchmod(fd, 0o600)
        secret = module.credentials().encode()
        os.write(fd, secret)
        os.close(fd)
        return module.vbox("guestcontrol", SINK_VM, "copyto", "--username", SINK_USER, "--passwordfile", name,
                           str(local), remote, check=False)
    finally:
        try:
            with open(name, "r+b") as stream:
                stream.write(b"\0" * max(len(secret), 64))
        except OSError:
            pass
        os.unlink(name)


def sink_status(module):
    proc = sink_run(module, ["/usr/local/sbin/hazim-sinkhole", "status"])
    text = proc.stdout or ""
    state = "on" if "state:              on" in text else "off" if "state:              off" in text else "unknown"
    return {"rc": proc.returncode, "state": state, "ok": "overall:            OK" in text, "text": text}


def dns_answer(module):
    proc = sink_run(module, ["/usr/bin/python3", "-I", "-c", DNS_PROBE], sudo=False)
    out = (proc.stdout or "").strip()
    return out.split("a=")[-1] if proc.returncode == 0 and "ancount=1" in out else "error: %s %s" % (
        out, (proc.stderr or "").strip()[:200])


def dnsmasq_processes(module):
    proc = sink_run(module, ["/usr/bin/pgrep", "-a", "-x", "dnsmasq"])
    return [line for line in (proc.stdout or "").splitlines() if line.strip()]


def switch_dnsmasq(module, conf):
    for _ in range(2):
        sink_run(module, ["/usr/bin/pkill", "-x", "dnsmasq"])
        for _ in range(20):
            if not dnsmasq_processes(module):
                break
            time.sleep(0.5)
    require(not dnsmasq_processes(module), "dnsmasq did not stop")
    started = sink_run(module, ["/usr/sbin/dnsmasq", "--conf-file=" + conf])
    require(started.returncode == 0, "dnsmasq did not start with %s: %s" % (conf, (started.stderr or "")[:300]))
    time.sleep(1.0)
    running = dnsmasq_processes(module)
    require(len(running) == 1 and ("--conf-file=" + conf) in running[0], "unexpected dnsmasq processes: %s" % running)
    return running


def log_sizes(module):
    sizes = {}
    for name, path in SINK_LOGS.items():
        proc = sink_run(module, ["/usr/bin/wc", "-l", path])
        sizes[name] = int(proc.stdout.split()[0]) if proc.returncode == 0 and proc.stdout.split() else None
    return sizes


def sink_step(attempt, expected_hash, step, approval):
    require(approval and approval.strip(), "a verbatim user approval is required for Sink steps")
    protocol = verify_plan(attempt, expected_hash)
    module = cp.frozen.helper()
    out_dir = attempt / "sink"
    out_dir.mkdir(exist_ok=True)
    record = {"step": step, "approval": approval, "protocol_sha256": expected_hash,
              "started_utc": datetime.now(timezone.utc).isoformat(), "status": "failed"}
    try:
        if step == "prepare":
            status = sink_status(module)
            record["sinkhole_before"] = {k: status[k] for k in ("state", "ok")}
            require(status["state"] == "on" and status["ok"], "sinkhole must be on and OK before collect")
            before = dnsmasq_processes(module)
            record["dnsmasq_before"] = before
            require(len(before) == 1 and ORIGINAL_DNSMASQ_CONF in before[0], "expected the original dnsmasq only")
            local = attempt / "sink" / "dnsmasq-redirect.conf"
            local.write_text(REDIRECT_CONF_TEXT)
            copied = sink_copyto(module, local, "/tmp/hz-dnsmasq-redirect.conf")
            require(copied.returncode == 0, "copy of the redirect conf failed")
            installed = sink_run(module, ["/usr/bin/install", "-m", "0644", "-o", "root", "-g", "root",
                                          "/tmp/hz-dnsmasq-redirect.conf", REDIRECT_DNSMASQ_CONF])
            require(installed.returncode == 0, "install of the redirect conf failed")
            check = sink_run(module, ["/usr/bin/sha256sum", REDIRECT_DNSMASQ_CONF])
            require((check.stdout or "").split()[:1] == [protocol["sink"]["redirect_conf_sha256"]],
                    "redirect conf hash differs on the Sink")
            try:
                record["dnsmasq_after"] = switch_dnsmasq(module, REDIRECT_DNSMASQ_CONF)
                record["dns_answer"] = dns_answer(module)
                require(record["dns_answer"] == DNS_REDIRECT, "DNS answer is %s" % record["dns_answer"])
            except BaseException:
                record["rollback"] = switch_dnsmasq(module, ORIGINAL_DNSMASQ_CONF)
                raise
            record["log_lines_before"] = log_sizes(module)
            record["nft_before"] = sink_status(module)["text"]
        elif step == "logs":
            prepared = sorted(p for p in out_dir.glob("prepare-*.json") if load(p).get("status") == "passed")
            require(prepared, "no passed prepare record: log offsets unknown")
            before = load(prepared[-1])["log_lines_before"]
            record["nft_after"] = sink_status(module)["text"]
            record["log_lines_after"] = log_sizes(module)
            record["logs"] = {}
            for name, path in SINK_LOGS.items():   # only the lines written since prepare
                start = (before.get(name) or 0) + 1
                proc = sink_run(module, ["/usr/bin/tail", "-n", "+%d" % start, path], timeout_ms=600000)
                (out_dir / name).write_text(proc.stdout or "")
                record["logs"][name] = {"rc": proc.returncode, "from_line": start,
                                        "bytes": len((proc.stdout or "").encode()), "sha256": digest(out_dir / name)}
        elif step == "restore":
            record["dnsmasq"] = switch_dnsmasq(module, ORIGINAL_DNSMASQ_CONF)
            record["dns_answer"] = dns_answer(module)
            require(record["dns_answer"] == DNS_ORIGINAL, "DNS answer after restore is %s" % record["dns_answer"])
            off = sink_run(module, ["/usr/local/sbin/hazim-sinkhole", "off"])
            record["sinkhole_off_rc"] = off.returncode
            status = sink_status(module)
            record["sinkhole_after"] = {k: status[k] for k in ("state", "ok")}
            require(status["state"] == "off", "sinkhole did not switch off")
        else:
            raise ValueError("unknown sink step " + step)
        record["status"] = "passed"
    except BaseException as error:
        record["error"] = "%s: %s" % (type(error).__name__, error)
        raise
    finally:
        record["finished_utc"] = datetime.now(timezone.utc).isoformat()
        path = out_dir / ("%s-%s.json" % (step, stamp()))
        save(path, record)
        print(json.dumps({k: v for k, v in record.items() if k not in ("nft_before", "nft_after")}, indent=2)[:3000])
    return record


def require_sink_ready(module):
    status = sink_status(module)
    require(status["state"] == "on" and status["ok"], "sinkhole not on/OK right before collect")
    answer = dns_answer(module)
    require(answer == DNS_REDIRECT, "DNS redirect not active right before collect (%s)" % answer)


# ------------------------------------------------------------------------------------------------ behaviour check

def behavior_check(attempt, expected_hash):
    protocol = verify_plan(attempt, expected_hash)
    rows, bad = [], []
    for case in protocol["cases"]:
        runs = sorted((attempt / "runs" / case["sample"] / "output").glob("run_*/run.json"))
        if len(runs) != 1:
            rows.append({"sample": case["sample"], "label": case["label"], "status": "missing"})
            bad.append(case["sample"])
            continue
        m = load(runs[0])
        tel = list(csv.DictReader(open(runs[0].with_name("telemetry.csv"))))
        host = [float(t["host_total_syscalls_total"]) for t in tel]
        p4 = [float(t["net_pkts_total_delta"]) for t in tel]
        iface = [float(t["net_packets_sent"]) + float(t["net_packets_recv"]) for t in tel]
        active = [i for i, v in enumerate(host) if v]
        row = {"sample": case["sample"], "label": case["label"], "mode": case["mode"],
               "group": case.get("family") or case.get("program") or "null", "variant": case.get("variant"),
               "rc": m.get("return_code"), "quality": m.get("collection_quality_status"),
               "host_active_windows": len(active), "last_active_window": max(active) if active else -1,
               "p4_active_windows": sum(1 for v in p4 if v), "p4_packets": int(sum(p4)),
               "iface_packets": int(sum(iface)),
               "post_target_syscalls": (m.get("target_exec") or {}).get("post_target_lineage_raw_syscalls")}
        why = []
        e = case.get("expectation")
        if case["label"] == "benign" and e:
            if row["rc"] not in e["rc"]:
                why.append("rc %s not in %s" % (row["rc"], e["rc"]))
            if row["host_active_windows"] < e.get("min_active", 0):
                why.append("active %d < %d" % (row["host_active_windows"], e["min_active"]))
            if row["last_active_window"] < e.get("min_last_active", -1):
                why.append("last active %d < %d" % (row["last_active_window"], e["min_last_active"]))
            if row["last_active_window"] > e.get("max_last_active", 10 ** 9):
                why.append("last active %d > %d" % (row["last_active_window"], e["max_last_active"]))
            if row["iface_packets"] == 0:
                why.append("no packets in the windows")
            row["behavior"] = "as_designed" if not why else "mismatch: " + "; ".join(why)
            if why:
                bad.append(case["sample"])
        rows.append(row)
    report = {"protocol_sha256": expected_hash, "rows": rows, "benign_mismatches": bad,
              "counts": {"benign_as_designed": sum(1 for r in rows if r.get("behavior") == "as_designed"),
                         "benign_mismatch": len(bad)}, "checker_sha256": digest(__file__)}
    out = attempt / ("behavior-" + stamp() + ".json")
    save(out, report)
    for r in rows:
        print("  %-7s %-14s %-24s rc=%-4s active=%3s last=%3s p4win=%3s p4pkts=%-7s %s" % (
            r["label"], r.get("group", "")[:14], (r.get("variant") or r["sample"][:10])[:24], r.get("rc"),
            r.get("host_active_windows"), r.get("last_active_window"), r.get("p4_active_windows"),
            r.get("p4_packets"), r.get("behavior", r.get("status", ""))))
    print(json.dumps({"report": str(out), **report["counts"]}, indent=2))
    return report


# --------------------------------------------------------------------------------------------------- orchestration

def run_all(attempt, expected_hash, approval):
    """preflight -> stage -> dry-run -> sink prepare -> collect -> sink logs -> sink restore -> validate -> behavior.
    Stops at the first failure; once the Sink was prepared, logs and restore always run."""
    require(approval and approval.strip(), "approval required")

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt("stopped: restore the Sink and the guest, preserve the attempt")
    signal.signal(signal.SIGTERM, interrupted)
    for phase in ("preflight", "stage", "dry-run"):
        cp.perform_phase(attempt, phase, expected_hash, approval)
    prepared = False
    try:
        sink_step(attempt, expected_hash, "prepare", approval)
        prepared = True
        require_sink_ready(cp.frozen.helper())
        cp.perform_phase(attempt, "collect", expected_hash, approval)
    finally:
        if prepared:
            try:
                sink_step(attempt, expected_hash, "logs", approval)
            finally:
                sink_step(attempt, expected_hash, "restore", approval)
    cp.validate(attempt, expected_hash)
    behavior_check(attempt, expected_hash)


def self_test():
    cp.settings_tests()
    bsc.self_test()
    cp.phase_mock_tests()
    answers = [line for line in REDIRECT_CONF_TEXT.splitlines() if line.startswith("address=")]
    require(answers == ["address=/#/%s" % DNS_REDIRECT] and "listen-address=10.0.0.1" in REDIRECT_CONF_TEXT,
            "redirect conf wrong")
    compile(DNS_PROBE, "dns_probe", "exec")
    for name in ("sinkhole.sh", "sinkhole_catchall.py"):
        require((KIT / name).exists(), "kit file missing: " + name)
    print("PASS collect_sinkhole_c2 self-test (payload 28/28/3, phase mocks, redirect conf, DNS probe compiles)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Sinkhole C2 experiment (300 s / 600 windows)")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--phase", choices=["preflight", "stage", "dry-run", "collect"])
    p.add_argument("--sink", choices=["prepare", "logs", "restore"])
    p.add_argument("--validate", action="store_true")
    p.add_argument("--behavior", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    else:
        attempt = Path(a.attempt).resolve()
        if a.run_all:
            run_all(attempt, a.protocol_sha256, a.approval)
        elif a.phase:
            if a.phase == "collect":
                require_sink_ready(cp.frozen.helper())
            cp.perform_phase(attempt, a.phase, a.protocol_sha256, a.approval)
        elif a.sink:
            sink_step(attempt, a.protocol_sha256, a.sink, a.approval)
        elif a.validate:
            cp.validate(attempt, a.protocol_sha256)
        elif a.behavior:
            behavior_check(attempt, a.protocol_sha256)
        else:
            p.error("choose a step")


if __name__ == "__main__":
    main()
