"""Phase 2 of the bot-flooding experiment: COMPLETE the Gafgyt/Kaiten IRC handshake with a contained lab controller
and (bonus, still NO attack) probe the ENABLE gate -- no flood is ever commanded.

Phase 1 proved the bot dials a HARDCODED C2 (45.61.164.81:6667) that nothing on the sealed malnet answers, so it
never handshook. The Sink is a separate appliance we have no credentials for, so instead of standing the controller
up on the Sink we run it INSIDE the Ubuntu guest (which we fully control) and bind 45.61.164.81 as a /32 alias on `lo`
so the bot's connect() is delivered locally to our controller. The controller speaks just enough IRC to register the
bot, echo its JOIN, answer PING, and then PRIVMSG a short list of candidate `ENABLE <pass>` guesses to discover the
command-gate password. It has a hard guardrail that REFUSES to transmit any attack keyword (UDP/TCP/STD/HTTP/HOLD/
JUNK/PAN/PHATWONK/BLACKNURSE/UNKNOWN/GET/SCANNER/KILLALL), so Phase 2 cannot cause a flood even by mistake.

Mechanism is bespoke (not the collector) because it needs a background controller alongside the sample; VM safety is
the SAME vetted pattern as export_original_sources.export(): verify isolation + only-Sink, restore the quiet baseline,
wait for Guest Control, run one orchestrated guest session, then power off and restore the ORIGINAL snapshot. Guest is
intnet-only (no route off malnet). The bot runs as csci in the isolated guest and is wiped by the snapshot restore.
No telemetry/model/merge; Phase 3 (flood) requires a new explicit approval.
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
import collect_v21 as v21               # noqa: E402  BASELINE (quiet child) + verify_production/PINNED
import collect_v19 as frozen            # noqa: E402  digest/save/load/stamp

STUDY = frozen.STUDY
digest, save, load, stamp = frozen.digest, frozen.save, frozen.load, frozen.stamp
COHORT = "data/malware/full-cohort-323/samples"
KAITEN_SHA = "478053ea93052dd3f1477cf497443c0cb1b0e75361ba3927b929b707c18f35e2"
C2_IP = "45.61.164.81"       # the bot's hardcoded C2 (Phase 1); bound as a local lo alias so connect() stays in-guest
C2_PORT = 6667
RUNSECS = 100
# edgy/version-ish tokens pulled from the binary's own strings as candidate ENABLE passwords (auth probe only)
ENABLE_CANDIDATES = ["y0u1sg3y", "klv14", "klv1", "Desudesudesu", "Customgrow420", "unhappygh0st",
                     "Milenko", "Ziggy", "ziggy", "gaybot", "SendTheSTD", "BurnTheJews", "bigNullz",
                     "Keemstar", "Leafy", "Leonidus", "admin", "root"]

# ---- the contained lab IRC controller (runs in the guest). Attack keywords are REFUSED on send. ----
CONTROLLER_SRC = r'''
import socket, sys, time, json, threading
port = int(sys.argv[1]); logpath = sys.argv[2]; candidates = json.load(open(sys.argv[3]))
logf = open(logpath, "a", buffering=1)
state = {"winner": None, "found": False, "channel": None, "last_guess": None, "sent_attack": False}
lock = threading.Lock()
ATTACK = {"UDP","TCP","STD","HTTP","HOLD","JUNK","PAN","PHATWONK","BLACKNURSE","UNKNOWN","GET","SCANNER","KILLALL","KILLATTK","DNS"}
def rec(direction, raw):
    logf.write(json.dumps({"t": time.time(), "dir": direction, "raw": raw}) + "\n")
def send(conn, s):
    body = s.split(" :", 1)[1] if " :" in s else ""
    tok = body.split()[0].upper() if body else ""
    if tok in ATTACK:                      # hard guardrail: Phase 2 can never issue an attack command
        state["sent_attack"] = True; rec("BLOCKED", s); return
    conn.sendall((s + "\r\n").encode("latin-1", "replace")); rec("S->C", s)
def enable_probes(conn, channel):
    time.sleep(5)
    for g in candidates:
        with lock:
            if state["found"]: break
            state["last_guess"] = g
        send(conn, ":op!op@lab PRIVMSG %s :ENABLE %s" % (channel, g))
        time.sleep(2.5)
    rec("INFO", "enable probes done found=%s winner=%s" % (state["found"], state["winner"]))
def handle(conn):
    conn.settimeout(150); nick=None; registered=False; joined=False; buf=b""
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
                with lock: state["found"]=True; state["winner"]=state["last_guess"]
                rec("INFO", "ENABLE accepted winner=%s" % state["winner"])
            parts = text.split(); cmd = parts[0].upper() if parts else ""
            if cmd=="NICK" and len(parts)>1: nick = parts[1].lstrip(":")
            elif cmd=="USER" and not registered:
                n = nick or "bot"
                for num,msg in (("001","Welcome"),("002","your host is lab"),("003","created"),
                                ("004","lab lab 1.0 o o"),("375","- MOTD -"),("372","- lab -"),("376","End of MOTD")):
                    send(conn, ":lab %s %s :%s" % (num, n, msg))
                registered = True
            elif cmd=="CAP": send(conn, ":lab CAP * LS :")
            elif cmd=="PING":
                arg = text.split(" ",1)[1] if " " in text else ":lab"
                send(conn, "PONG %s" % arg)
            elif cmd=="JOIN" and len(parts)>1:
                ch = parts[1].lstrip(":").split(",")[0]; state["channel"]=ch
                send(conn, ":%s!%s@lab JOIN :%s" % (nick, nick, ch))
                send(conn, ":lab 353 %s = %s :%s @op" % (nick, ch, nick))
                send(conn, ":lab 366 %s %s :End of names" % (nick, ch))
                if not joined:
                    joined = True
                    threading.Thread(target=enable_probes, args=(conn, ch), daemon=True).start()
    rec("INFO", "client disconnected")
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(5); s.settimeout(130)
    rec("INFO", "listening on %d" % port)
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

# ---- the in-guest orchestrator: extract bot, add lo alias, start controller, run bot, collect log, clean up ----
ORCH_SRC = r'''
import json, os, signal, socket, subprocess, sys, time, glob, hashlib
sample_zip, controller_py, pwfile, cand_json, c2ip, port, runsecs, outdir = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6]), int(sys.argv[7]), sys.argv[8])
os.makedirs(outdir, exist_ok=True)
result = {"steps": {}, "errors": []}
extract_dir = os.path.join(outdir, "bot"); os.makedirs(extract_dir, exist_ok=True)
ex = subprocess.run(["/usr/bin/7z","x","-pinfected","-o"+extract_dir,"-y",sample_zip],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
result["steps"]["extract_rc"] = ex.returncode
files = [f for f in glob.glob(extract_dir+"/*") if os.path.isfile(f)]
if not files:
    result["errors"].append("no extracted file"); print(json.dumps(result)); sys.exit(1)
bot = files[0]
result["bot_sha256"] = hashlib.sha256(open(bot,"rb").read()).hexdigest()
os.chmod(bot, 0o755); result["steps"]["bot_path"] = bot
pw = open(pwfile).read().strip()
def sudo(args):
    p = subprocess.run(["sudo","-S","-p",""]+args, input=pw+"\n", text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout
rc, out = sudo(["/usr/sbin/ip","addr","add",c2ip+"/32","dev","lo"])
result["steps"]["alias_add_rc"] = rc
chk = subprocess.run(["/usr/sbin/ip","addr","show","dev","lo"], stdout=subprocess.PIPE, text=True).stdout
result["alias_present"] = c2ip in chk
if not result["alias_present"]: result["errors"].append("alias missing: " + out[:200])
clog = os.path.join(outdir, "c2.jsonl")
ctrl = subprocess.Popen(["/usr/bin/python3", controller_py, str(port), clog, cand_json],
                        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
time.sleep(1.5)
try:
    t = socket.create_connection((c2ip, port), timeout=3); t.close(); result["listener_ok"] = True
except OSError as e:
    result["listener_ok"] = False; result["errors"].append("listener: " + str(e))
botout = open(os.path.join(outdir,"bot.out"), "wb")
proc = subprocess.Popen([bot], cwd=extract_dir, stdin=subprocess.DEVNULL,
                        stdout=botout, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
try: pgid = os.getpgid(proc.pid)
except Exception: pgid = None
t0 = time.time(); result["bot_exit"] = None
while time.time() - t0 < runsecs:
    r = proc.poll()
    if r is not None: result["bot_exit"] = r; break
    time.sleep(1)
base = os.path.basename(bot)
if pgid:
    try: os.killpg(pgid, signal.SIGKILL)
    except Exception: pass
subprocess.run(["pkill","-9","-f",base], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
try: ctrl.send_signal(signal.SIGINT)
except Exception: pass
time.sleep(1)
try: ctrl.kill()
except Exception: pass
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


def freeze():
    v21.verify_production()
    helper = exp.helper_module()
    run_id = stamp()
    attempt = ROOT / "gafgyt-phase2" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    sample = STUDY / COHORT / (KAITEN_SHA + ".zip")
    frozen.require(sample.is_file(), "missing Kaiten sample")
    (attempt / "labctl.py").write_text(CONTROLLER_SRC)
    (attempt / "orchestrate.py").write_text(ORCH_SRC)
    save(attempt / "candidates.json", ENABLE_CANDIDATES)
    subprocess.run(["python3", "-c", "import ast,sys; ast.parse(open(sys.argv[1]).read()); ast.parse(open(sys.argv[2]).read())",
                    str(attempt / "labctl.py"), str(attempt / "orchestrate.py")], check=True)
    protocol = {
        "format": "gafgyt-phase2-handshake-v1", "purpose": "complete the Kaiten IRC handshake with a contained "
        "in-guest controller and probe the ENABLE gate; NO flood/attack is ever commanded (send-side guardrail)",
        "sample_sha256": KAITEN_SHA, "sample_family": "Gafgyt/Kaiten-Ziggy-Qbot-Redo",
        "c2_endpoint": {"ip": C2_IP, "port": C2_PORT, "bound_as": "lo alias (connect stays in-guest)"},
        "enable_candidates": ENABLE_CANDIDATES, "run_seconds": RUNSECS,
        "baseline_snapshot": v21.BASELINE, "baseline_uuid": v21.BASELINE_UUID, "original_snapshot": helper.ORIGINAL,
        "production_hashes": v21.PINNED, "guest_user": helper.GUEST_USER,
        "controller_sha256": digest(attempt / "labctl.py"), "orchestrator_sha256": digest(attempt / "orchestrate.py"),
        "candidates_sha256": digest(attempt / "candidates.json"), "driver_sha256": digest(Path(__file__)),
        "no_attack_commanded": True, "sink_untouched": True, "approval": None,
        "limitations": [
            "Phase 2 completes the C2 handshake and probes the auth gate only; it commands no attack.",
            "ENABLE candidates come from the binary's own strings; a miss here is handled in Phase 3 (disasm/brute).",
            "Guest is intnet-only; the bot cannot reach anything off the sealed malnet; snapshot restore wipes it.",
            "Controller runs in the guest (Sink has separate creds we don't hold and is left untouched)."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "sample": KAITEN_SHA[:12], "c2": "%s:%d" % (C2_IP, C2_PORT),
                      "enable_candidates": len(ENABLE_CANDIDATES)}, indent=2))
    return attempt


def run(attempt, approval):
    frozen.require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    attempt = Path(attempt)
    if not attempt.is_absolute():            # VBoxManage copyto needs absolute host source paths
        attempt = (ROOT / attempt).resolve()
    protocol = load(attempt / "protocol.json")
    helper = exp.helper_module()
    v21.verify_production()   # .21-pinned production integrity (helper's run_readiness pins the stale .18)
    destination = attempt / "run"
    destination.mkdir(parents=True, exist_ok=False)
    save(destination / "authorization.json", {"approval": approval, "phase": "handshake",
         "authorized_utc": datetime.now(timezone.utc).isoformat(), "no_attack_commanded": True})
    import fcntl
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        exp.check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        frozen.require(before["guest"]["VMState"] == '"poweroff"' and before["sink"]["VMState"] == '"running"'
                       and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"',
                       "Expected original clean powered-off guest and running isolated Sink")
        save(destination / "initial_vm_state.json", before)
        base = "/tmp/labp2-" + attempt.name + "-"   # flat guest paths; no guest mkdir (the orchestrator makes its outdir)
        result = {"status": "failed_preserved"}
        touched = False
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-p2-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials()); password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                touched = True
                helper.vbox("snapshot", helper.VM, "restore", protocol["baseline_snapshot"])
                state = helper.isolated(helper.VM)
                frozen.require(state["CurrentSnapshotName"] == '"' + protocol["baseline_snapshot"] + '"',
                               "Restored baseline differs")
                exp.wait_guest(helper, auth, destination / "guest-login.log")
                with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-p2pw-") as gpw:
                    os.chmod(gpw.name, 0o600); gpw.write(helper.credentials()); gpw.flush()
                    copies = [(str(attempt / "labctl.py"), base + "labctl.py"),
                              (str(attempt / "orchestrate.py"), base + "orchestrate.py"),
                              (str(attempt / "candidates.json"), base + "cand.json"),
                              (str(STUDY / COHORT / (KAITEN_SHA + ".zip")), base + "sample.zip"),
                              (gpw.name, base + "pbot")]
                    for src, dst in copies:
                        cp = helper.vbox("guestcontrol", helper.VM, "copyto", *auth, src, dst, check=False)
                        frozen.require(cp.returncode == 0,
                                       "copyto %s failed rc=%s: %s" % (dst, cp.returncode, (cp.stderr or "")[:300]))
                # VBoxManage `run --exe X -- ARGS` makes ARGS argv[1:] (argv[0] is auto-filled with X), so the
                # first token after `--` is the script path, NOT a repeated "python3".
                orch = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                    "--wait-stdout", "--wait-stderr", "--timeout", str((RUNSECS + 160) * 1000), "--",
                    base + "orchestrate.py", base + "sample.zip", base + "labctl.py",
                    base + "pbot", base + "cand.json", C2_IP, str(C2_PORT), str(RUNSECS), base + "out",
                    check=False)
                (destination / "orchestrator.stdout").write_text(orch.stdout)
                (destination / "orchestrator.stderr").write_text(orch.stderr)
                frozen.require(orch.returncode == 0,
                               "orchestrator rc=%s stderr=%s" % (orch.returncode, (orch.stderr or "")[-400:]))
                data = json.loads(orch.stdout.strip().splitlines()[-1])
                save(destination / "handshake_result.json", data)
                result = {"status": "passed", **summarize(data)}
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
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
                               "Phase-2 cleanup incomplete")
            save(destination / "result.json", result)
    v21.verify_production()   # .21-pinned production integrity (helper's run_readiness pins the stale .18)
    print(json.dumps(result, indent=2))
    return result


def summarize(data):
    events = data.get("c2_events", [])
    c2s = [e for e in events if e.get("dir") == "C->S"]
    verbs = []
    for e in c2s:
        v = e["raw"].split()[0].upper() if e["raw"].split() else ""
        if v and v not in verbs:
            verbs.append(v)
    summary = data.get("c2_summary", {})
    return {"bot_sha256_ok": data.get("bot_sha256") == KAITEN_SHA, "alias_present": data.get("alias_present"),
            "listener_ok": data.get("listener_ok"), "bot_exit": data.get("bot_exit"),
            "client_verbs": verbs, "channel": summary.get("channel"),
            "enable_found": summary.get("found"), "enable_winner": summary.get("winner"),
            "controller_sent_attack": summary.get("sent_attack"), "c2_event_count": len(events),
            "errors": data.get("errors", [])}


def self_test():
    """Local-only: drive the controller with a simulated Kaiten bot; confirm handshake + enable probe + guardrail."""
    import threading
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "labctl.py").write_text(CONTROLLER_SRC)
        correct = "klv14"
        cands = ["aaa", "bbb", correct, "ccc"]
        save(td / "cand.json", cands)
        sock = socket.socket(); sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]; sock.close()
        log = td / "c2.jsonl"
        ctrl = subprocess.Popen(["python3", str(td / "labctl.py"), str(port), str(log), str(td / "cand.json")])
        try:
            time.sleep(1.0)
            bot = socket.create_connection(("127.0.0.1", port), timeout=5)
            bot.settimeout(30)
            bot.sendall(b"NICK [US|0]abcd\r\nUSER x localhost localhost :real\r\n")
            buf = b""; joined = False; got_probe = 0; result_seen = False; attack_seen = False
            deadline = time.time() + 40
            while time.time() < deadline:
                try:
                    data = bot.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("latin-1").rstrip("\r")
                    up = text.upper()
                    if any(a in up for a in ("UDP ", "TCP ", "STD ", "SCANNER", "KILLALL")):
                        attack_seen = True
                    if " 376 " in text and not joined:
                        bot.sendall(b"JOIN #aA\r\n"); joined = True
                    if text.startswith("PING"):
                        bot.sendall(("PONG %s\r\n" % text.split(" ", 1)[1]).encode())
                    if "PRIVMSG" in text and "ENABLE" in up:
                        got_probe += 1
                        guess = text.split("ENABLE", 1)[1].strip()
                        if guess == correct:
                            bot.sendall(b":b!b@h NOTICE op :Password correct.\r\n"
                                        b":b!b@h NOTICE op :Enabled and awaiting orders\r\n")
                            result_seen = True
                        else:
                            bot.sendall(b":b!b@h NOTICE op :Wrong password\r\n")
                if result_seen and got_probe >= 3:
                    break
            bot.close()
        finally:
            time.sleep(1); ctrl.send_signal(2); time.sleep(0.5); ctrl.kill(); ctrl.wait()
        events = [json.loads(x) for x in (log).read_text().splitlines() if x.strip()]
        summ = json.loads((Path(str(log) + ".summary")).read_text())
        cverbs = {e["raw"].split()[0].upper() for e in events if e["dir"] == "C->S" and e["raw"].split()}
        sent = [e for e in events if e["dir"] == "S->C"]
        probes = [e for e in events if e["dir"] == "S->C" and "ENABLE" in e["raw"]]
        assert {"NICK", "USER", "JOIN"} <= cverbs, cverbs
        assert len(probes) >= 1 and got_probe >= 1, (len(probes), got_probe)
        assert summ["found"] and summ["winner"] == correct, summ
        assert not summ["sent_attack"] and not attack_seen, "attack keyword escaped the guardrail"
        assert not any(e["dir"] == "S->C" and e["raw"].split(" :", 1)[-1].split()[:1] and
                       e["raw"].split(" :", 1)[-1].split()[0].upper() in
                       {"UDP", "TCP", "STD", "HTTP", "HOLD", "JUNK", "SCANNER", "KILLALL"} for e in sent)
    print("self-test OK: registration + JOIN + ENABLE probe discovered '%s'; attack guardrail held" % correct)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--run", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.run:
        run(a.attempt, a.approval)
    else:
        p.error("one of --self-test / --freeze-only / --run required")


if __name__ == "__main__":
    main()
