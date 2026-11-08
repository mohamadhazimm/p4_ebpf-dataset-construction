"""Phase 4 of the bot-flooding route: the PRECISION experiment.

Captures, under ONE identical bespoke harness, both classes needed to test the precision contribution:
  * MALICIOUS FLOOD  -- real botnet auto-scanners (Kaiten Gafgyt + Mirai/Gafgyt amd64-static), which on launch
                        emit a SYN-scan/flood with no completed handshakes.
  * BENIGN BULK / HIGH-RATE NETWORK -- legitimate host-loud network workloads to the isolated Sink (large curl
                        uploads/downloads, openssl bulk, many short HTTP connections, python streams).

For EVERY sample it records, over a fixed window, three paired measurements:
  (1) host activity  -- an IN-KERNEL bpftrace syscall counter (count() maps, NOT a perf ring buffer, so it cannot
                        overflow the way the .21 collector does on a flood): a total and a per-syscall-id histogram,
                        EXCLUDING the tcpdump/bpftrace instruments themselves.
  (2) network volume -- true enp0s3 NIC rx/tx packet+byte deltas from /sys (kernel counters, no capture drops).
  (3) network shape  -- a tcpdump capture (snaplen 96, first 300k frames) for offline flow-shape features.

The honest claim under test (PRECISION, not host-evasion -- a userland flood is host-LOUD too): a host activity/
volume signal cannot separate a malicious flood from benign high-throughput traffic without false alarms (both are
high-activity), whereas network flow-SHAPE features separate them cleanly -- so adding network/P4 features reduces
false positives on benign bulk. This is the matched-cohort precision argument, measured directly.

SAFETY (hard, unchanged): the guest is intnet-only on the sealed malnet (no route off); benign workloads target ONLY
the Sink 10.0.0.1; malware auto-scans random public IPs whose packets die at the gateway inside the sealed net (same
containment as every prior malware run). The VM is restored to the clean BASELINE between samples and to the ORIGINAL
snapshot + powered off at the end. Reuses the Phase-3 VM choreography (export_original_sources.helper + collect_v21 .21 pins).
No model is fitted and no dataset is merged here; this only CAPTURES. Offline analysis is a separate no-VM step.
"""
import argparse
import json
import os
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


def write_json(path, obj):      # overwriting writer for the incrementally-updated campaign file (save() is exclusive-create)
    Path(path).write_text(json.dumps(obj, indent=2))
COHORT = "data/malware/full-cohort-323/samples"
SINK = "10.0.0.1"            # the ONLY benign target; also the sealed-net gateway the malware scan dies at
WINDOW = 20                  # seconds the workload runs under the instruments
C2_IP = "45.61.164.81"       # the Kaiten bot's hardcoded C2, aliased to lo so its control channel stays in-guest
C2_PORT = 6667

# ---- malicious network flood via an in-guest reg-only C2 controller (triggers the Kaiten autonomous SYN scanner) ----
# The Kaiten does NOT scan until it completes IRC registration against its C2 (confirmed: without C2 it only retries,
# ~900k host syscalls / ~17 packets). With the reg-only controller on a lo alias it registers and its telnet SYN
# scanner floods (Phase 3: ~5.5M SYN). The controller sends NO attack command; the flood is the bot's own scanner.
MALWARE_C2 = [
    ("gafgyt_kaiten_flood", "478053ea93052dd3f1477cf497443c0cb1b0e75361ba3927b929b707c18f35e2", "Gafgyt/Kaiten"),
]

# ---- other malware run without C2 (host-loud but, as measured, network-silent: a useful host-activity data point) ----
MALWARE = [
    ("mirai_heavy",   "0882f75e8c13922e2e6dcdf767b01aecd928881a166c68f677265908b2125a99", "Mirai"),
    ("mirai_a",       "04387a4111fd4e8564a8e28baeec413ac4fe2bee2f665e3d7de9310993fd93ee", "Mirai"),
    ("gafgyt_a",      "0018c8962adb4e9f85982b374574befe0bac5db5cd0862b372fb4d872a1d338e", "Gafgyt"),
]

# ---- in-guest reg-only IRC controller: completes registration + keepalive so the bot's scanner runs; NO commands ----
REG_CONTROLLER_SRC = r'''
import socket, sys, threading, time, json
port = int(sys.argv[1]); logpath = sys.argv[2]
logf = open(logpath, "a", buffering=1)
def rec(d, s):
    try: logf.write(json.dumps({"t": time.time(), "dir": d, "msg": s}) + "\n")
    except Exception: pass
def send(conn, s):
    conn.sendall((s + "\r\n").encode("latin-1", "replace")); rec("S->C", s)
def keepalive(conn):
    while True:
        time.sleep(1.5)
        try: conn.sendall(b"PING :lab\r\n")
        except Exception: return
def handle(conn):
    conn.settimeout(300); nick=None; ka=[False]; chan=[None]; buf=b""
    while True:
        try: data = conn.recv(4096)
        except socket.timeout: break
        if not data: break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            text = line.decode("latin-1").rstrip("\r")
            if not text: continue
            rec("C->S", text); parts = text.split(); cmd = parts[0].upper() if parts else ""
            if cmd == "NICK" and len(parts) > 1: nick = parts[1].lstrip(":")
            elif cmd == "USER":
                n = nick or "bot"
                for num, msg in (("001","Welcome"),("002","your host is lab"),("003","created"),
                                 ("004","lab lab 1.0 o o"),("375","- MOTD -"),("372","- lab -"),("376","End of MOTD")):
                    send(conn, ":lab %s %s :%s" % (num, n, msg))
                if not ka[0]:
                    ka[0] = True; threading.Thread(target=keepalive, args=(conn,), daemon=True).start()
            elif cmd == "CAP": send(conn, ":lab CAP * LS :")
            elif cmd == "PING":
                arg = text.split(" ", 1)[1] if " " in text else ":lab"
                send(conn, "PONG %s" % arg)
            elif cmd == "JOIN" and len(parts) > 1:
                ch = parts[1].lstrip(":").split(",")[0]; chan[0] = ch
                send(conn, ":%s!%s@lab JOIN :%s" % (nick, nick, ch))
                send(conn, ":lab 353 %s = %s :%s @op" % (nick, ch, nick))
                send(conn, ":lab 366 %s %s :End of names" % (nick, ch))
            elif cmd == "WHO" and len(parts) > 1:
                who = parts[1]; ch = chan[0] or "#bots"
                send(conn, ":lab 352 %s %s %s 10.0.0.10 lab %s H :0 %s" % (nick, ch, who, nick, who))
                send(conn, ":lab 315 %s %s :End of /WHO list." % (nick, who))
    rec("INFO", "client disconnected")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(5); s.settimeout(300)
rec("INFO", "reg-only controller on %d (NO attack commands)" % port)
try:
    while True:
        try: conn, addr = s.accept()
        except socket.timeout: break
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
except KeyboardInterrupt:
    pass
'''

# ---- benign host-loud network workloads to the Sink ONLY (single-line bash, no embedded quotes) ----
BENIGN = {
    "bulk_post":   "while :; do curl -s -o /dev/null --data-binary @/tmp/p4big http://%s/u; done" % SINK,
    "bulk_get":    "while :; do curl -s -o /dev/null http://%s/; done" % SINK,
    "highrate":    "while :; do curl -s -o /dev/null --max-time 2 http://%s/; done" % SINK,
    "tls_bulk":    "while :; do head -c 5000000 /dev/zero | openssl s_client -quiet -connect %s:443 2>/dev/null; done" % SINK,
    "wget_loop":   "while :; do wget -q -O /dev/null http://%s/; done" % SINK,
    "py_stream":   "@PYFILE@",   # a copied python script (guaranteed, no external-tool dependency); see PY_STREAM
}
# python stream: many large benign sends to the Sink for the window (run as a copied file, no nested quoting)
PY_STREAM = (
    "import socket, time\n"
    "end = time.time() + %d\n"
    "buf = bytes(65536)\n"
    "while time.time() < end:\n"
    "    try:\n"
    "        s = socket.create_connection((\"%s\", 80), 2)\n"
    "        s.sendall(b\"POST /u HTTP/1.0\\r\\nContent-Length: 999999999\\r\\n\\r\\n\")\n"
    "        for _ in range(400):\n"
    "            s.sendall(buf)\n"
    "        s.close()\n"
    "    except OSError:\n"
    "        time.sleep(0.05)\n"
) % (WINDOW, SINK)

# ---- in-guest orchestrator: one sample, paired host(bpftrace)+network(tcpdump+NIC) measurement ----
ORCH_SRC = r'''
import os, sys, json, time, glob, hashlib, subprocess, signal
mode, pwfile, window, outdir, pcap, payload = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
extra = sys.argv[7:]
os.makedirs(outdir, exist_ok=True)
pw = open(pwfile).read().strip()
def sudo(args, bg=False, out=None):
    cmd = ["sudo","-S","-p",""]+args
    if bg:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=(out or subprocess.DEVNULL),
                             stderr=subprocess.STDOUT, text=True)
        p.stdin.write(pw+"\n"); p.stdin.close(); return p
    p = subprocess.run(cmd, input=pw+"\n", text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout
def nic():
    d = {}
    for k in ("rx_packets","tx_packets","rx_bytes","tx_bytes"):
        try: d[k] = int(open("/sys/class/net/enp0s3/statistics/"+k).read().strip())
        except Exception: d[k] = None
    return d
result = {"mode": mode, "payload": (payload if mode != "malware" else os.path.basename(payload)),
          "steps": {}, "errors": []}
try:
    os.remove(pwfile)
except Exception:
    pass
bpf_out = os.path.join(outdir, "bpf.out")
# in-kernel syscall counter: total + per-id histogram, excluding the measurement tools themselves
PROG = ('tracepoint:raw_syscalls:sys_enter /comm != "tcpdump" && comm != "bpftrace" && comm != "sudo"/ '
        '{ @total = count(); @by[args->id] = count(); }')
btf = open(bpf_out, "w")
bt = sudo(["/usr/bin/bpftrace","-e",PROG], bg=True, out=btf)
td = sudo(["/usr/bin/tcpdump","-i","enp0s3","-n","-s","96","-c","300000","-w",pcap], bg=True)
time.sleep(4)                      # let bpftrace compile/attach and tcpdump open the link
nic0 = nic()
t0 = time.time()
if mode == "malware":
    ed = os.path.join(outdir, "bot"); os.makedirs(ed, exist_ok=True)
    subprocess.run(["/usr/bin/7z","x","-pinfected","-o"+ed,"-y",payload],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    files = [f for f in glob.glob(ed+"/*") if os.path.isfile(f)]
    if not files:
        result["errors"].append("no extracted bot")
    else:
        bot = files[0]; result["bot_sha256"] = hashlib.sha256(open(bot,"rb").read()).hexdigest(); os.chmod(bot, 0o755)
        bo = open(os.path.join(outdir,"bot.out"),"wb")
        proc = subprocess.Popen([bot], cwd=ed, stdin=subprocess.DEVNULL, stdout=bo, stderr=subprocess.STDOUT,
                                preexec_fn=os.setsid)
        time.sleep(2); result["launcher_exit"] = proc.poll()
        time.sleep(window)
        subprocess.run(["pkill","-9","-f",os.path.basename(bot)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
elif mode == "malware_c2":
    controller_py, c2ip, c2port = extra[0], extra[1], int(extra[2])
    sudo(["/usr/sbin/ip","addr","add",c2ip+"/32","dev","lo"])
    show = subprocess.run(["/usr/sbin/ip","addr","show","dev","lo"], stdout=subprocess.PIPE, text=True).stdout
    result["steps"]["alias_present"] = c2ip in show
    ctrl = subprocess.Popen(["/usr/bin/python3", controller_py, str(c2port), os.path.join(outdir,"c2.log")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    ed = os.path.join(outdir, "bot"); os.makedirs(ed, exist_ok=True)
    subprocess.run(["/usr/bin/7z","x","-pinfected","-o"+ed,"-y",payload],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    files = [f for f in glob.glob(ed+"/*") if os.path.isfile(f)]
    if not files:
        result["errors"].append("no extracted bot")
    else:
        bot = files[0]; result["bot_sha256"] = hashlib.sha256(open(bot,"rb").read()).hexdigest(); os.chmod(bot, 0o755)
        bo = open(os.path.join(outdir,"bot.out"),"wb")
        proc = subprocess.Popen([bot], cwd=ed, stdin=subprocess.DEVNULL, stdout=bo, stderr=subprocess.STDOUT,
                                preexec_fn=os.setsid)
        time.sleep(2); result["launcher_exit"] = proc.poll()
        time.sleep(window)
        subprocess.run(["pkill","-9","-f",os.path.basename(bot)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try: ctrl.terminate()
    except Exception: pass
    sudo(["/usr/sbin/ip","addr","del",c2ip+"/32","dev","lo"])
elif mode == "benign":
    if "/tmp/p4big" in payload:
        subprocess.run(["dd","if=/dev/zero","of=/tmp/p4big","bs=1M","count=50"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = ["timeout", str(window), "bash", "-c", payload]
    w = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try: w.wait(timeout=window+30)
    except subprocess.TimeoutExpired:
        w.kill()
    result["workload_exit"] = w.poll()
else:   # null baseline
    time.sleep(window)
t1 = time.time(); result["active_seconds"] = round(t1 - t0, 2)
nic1 = nic()
# tear down the instruments
sudo(["pkill","-INT","-x","tcpdump"]); time.sleep(2)
sudo(["pkill","-INT","-x","bpftrace"]); time.sleep(4)   # bpftrace prints its maps on SIGINT
btf.flush(); btf.close()
result["nic_delta"] = {k: ((nic1.get(k) or 0) - (nic0.get(k) or 0)) if nic0.get(k) is not None else None
                       for k in ("rx_packets","tx_packets","rx_bytes","tx_bytes")}
# parse bpftrace maps
total = 0; by = {}
if os.path.exists(bpf_out):
    for ln in open(bpf_out):
        ln = ln.strip()
        if ln.startswith("@total:"):
            try: total = int(ln.split(":")[1])
            except Exception: pass
        elif ln.startswith("@by["):
            try:
                sid = int(ln[ln.index("[")+1:ln.index("]")]); cnt = int(ln.rsplit(":",1)[1])
                by[sid] = cnt
            except Exception: pass
result["syscalls_total"] = total
result["syscalls_by_id"] = by
# pcap retrievable + record count
sudo(["/bin/chown", os.environ.get("USER","csci"), pcap]); sudo(["/bin/chmod","0644",pcap])
result["pcap_bytes"] = os.path.getsize(pcap) if os.path.exists(pcap) else 0
print(json.dumps(result))
'''


def freeze():
    v21.verify_production()
    helper = exp.helper_module()
    attempt = ROOT / "precision-phase4" / stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    for name, sha, fam in MALWARE + MALWARE_C2:
        frozen.require((STUDY / COHORT / (sha + ".zip")).is_file(), "missing malware " + name)
    (attempt / "orchestrate.py").write_text(ORCH_SRC)
    (attempt / "stream.py").write_text(PY_STREAM)
    (attempt / "controller.py").write_text(REG_CONTROLLER_SRC)
    subprocess.run(["python3", "-c",
                    "import ast,sys; [ast.parse(open(p).read()) for p in sys.argv[1:]]",
                    str(attempt / "orchestrate.py"), str(attempt / "stream.py"), str(attempt / "controller.py")],
                   check=True)
    samples = ([{"name": n, "kind": "malware_c2", "sha256": s, "family": f} for n, s, f in MALWARE_C2]
               + [{"name": n, "kind": "malware", "sha256": s, "family": f} for n, s, f in MALWARE]
               + [{"name": "benign_" + n, "kind": "benign", "cmd": c} for n, c in BENIGN.items()]
               + [{"name": "null", "kind": "null", "cmd": ""}])
    protocol = {
        "format": "precision-phase4-capture-v1",
        "purpose": "paired host(in-kernel syscall count)+network(NIC+pcap) capture of malicious floods vs benign "
                   "bulk/high-rate network, to test the PRECISION claim (network flow-shape separates what host "
                   "activity confuses). Capture only; no model, no merge.",
        "window_seconds": WINDOW, "sink": SINK, "samples": samples,
        "baseline_snapshot": v21.BASELINE, "baseline_uuid": v21.BASELINE_UUID, "original_snapshot": helper.ORIGINAL,
        "production_hashes": v21.PINNED, "guest_user": helper.GUEST_USER,
        "orchestrator_sha256": digest(attempt / "orchestrate.py"), "driver_sha256": digest(Path(__file__)),
        "approval": None,
        "safety": ["guest intnet-only on sealed malnet; benign targets ONLY the Sink 10.0.0.1; malware auto-scan "
                   "packets die at the sealed-net gateway (same containment as all prior malware runs); clean "
                   "BASELINE restore between samples; ORIGINAL restore + poweroff at end; in-kernel count maps "
                   "(no perf ring) so the flood cannot overflow the counter."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "samples": len(samples), "malware": len(MALWARE), "benign": len(BENIGN)}, indent=2))
    return attempt


def _poweroff(helper):
    if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
        helper.vbox("controlvm", helper.VM, "poweroff", check=False)
        time.sleep(3)


def _capture_one(helper, auth, attempt, destination, sample, base):
    """Restore baseline, boot, run the orchestrator on one sample, copy results back. Returns the per-sample dict."""
    _poweroff(helper)                                   # a prior sample may have left the guest running
    helper.vbox("snapshot", helper.VM, "restore", v21.BASELINE)
    state = helper.isolated(helper.VM)
    frozen.require(state["CurrentSnapshotName"] == '"' + v21.BASELINE + '"', "restored baseline differs")
    exp.wait_guest(helper, auth, destination / (sample["name"] + ".login.log"))
    gpcap = base + sample["name"] + ".pcap"
    with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-p4pw-") as gpw:
        os.chmod(gpw.name, 0o600); gpw.write(helper.credentials()); gpw.flush()
        copies = [(str(attempt / "orchestrate.py"), base + "orch.py"), (gpw.name, base + "pw")]
        if sample["kind"] in ("malware", "malware_c2"):
            copies.append((str(STUDY / COHORT / (sample["sha256"] + ".zip")), base + "sample.zip"))
        if sample["kind"] == "malware_c2":
            copies.append((str(attempt / "controller.py"), base + "ctl.py"))
        if sample.get("cmd") == "@PYFILE@":
            copies.append((str(attempt / "stream.py"), base + "stream.py"))
        for src, dst in copies:
            cp = helper.vbox("guestcontrol", helper.VM, "copyto", *auth, src, dst, check=False)
            frozen.require(cp.returncode == 0, "copyto %s rc=%s %s" % (dst, cp.returncode, (cp.stderr or "")[:200]))
        extra = []
        if sample["kind"] in ("malware", "malware_c2"):
            payload = base + "sample.zip"
            if sample["kind"] == "malware_c2":
                extra = [base + "ctl.py", C2_IP, str(C2_PORT)]
        elif sample.get("cmd") == "@PYFILE@":
            payload = "/usr/bin/python3 " + base + "stream.py"
        else:
            payload = sample.get("cmd", "")
        runargs = ["guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                   "--wait-stdout", "--wait-stderr", "--timeout", str((WINDOW + 180) * 1000),
                   "--", base + "orch.py", sample["kind"], base + "pw", str(WINDOW), base + "out", gpcap, payload] + extra
        orch = helper.vbox(*runargs, check=False)
    (destination / (sample["name"] + ".stdout")).write_text(orch.stdout or "")
    (destination / (sample["name"] + ".stderr")).write_text(orch.stderr or "")
    rec = {"sample": sample, "orch_rc": orch.returncode}
    if orch.returncode == 0 and (orch.stdout or "").strip():
        try:
            data = json.loads(orch.stdout.strip().splitlines()[-1]); rec["result"] = data
            cf = helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, gpcap,
                             str(destination / (sample["name"] + ".pcap")), check=False)
            rec["pcap_copied"] = cf.returncode == 0
        except Exception as e:
            rec["parse_error"] = str(e)
    else:
        rec["error"] = "orchestrator rc=%s stderr=%s" % (orch.returncode, (orch.stderr or "")[-300:])
    save(destination / (sample["name"] + ".result.json"), rec)
    _poweroff(helper)                                   # leave the guest off so the next restore succeeds
    return rec


def run_campaign(attempt, approval):
    frozen.require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    attempt = Path(attempt)
    if not attempt.is_absolute():
        attempt = (ROOT / attempt).resolve()
    protocol = load(attempt / "protocol.json")
    helper = exp.helper_module()
    v21.verify_production()
    destination = attempt / "run"
    destination.mkdir(parents=True, exist_ok=False)
    save(destination / "authorization.json", {"approval": approval, "phase": "precision-capture",
         "authorized_utc": datetime.now(timezone.utc).isoformat()})
    import fcntl
    records = []
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        exp.check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        frozen.require(before["guest"]["VMState"] == '"poweroff"' and before["sink"]["VMState"] == '"running"'
                       and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"',
                       "Expected original clean powered-off guest and running isolated Sink")
        save(destination / "initial_vm_state.json", before)
        touched = False
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-p4-") as password:
                os.chmod(password.name, 0o600); password.write(helper.credentials()); password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                touched = True
                for sample in protocol["samples"]:
                    base = "/tmp/p4-" + attempt.name + "-" + sample["name"] + "-"
                    try:
                        rec = _capture_one(helper, auth, attempt, destination, sample, base)
                    except BaseException as e:
                        rec = {"sample": sample, "error": type(e).__name__ + ": " + str(e)}
                        save(destination / (sample["name"] + ".result.json"), rec)
                    records.append(rec)
                    write_json(destination / "campaign.json", {"records": records})
        finally:
            if touched:
                if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                    helper.vbox("controlvm", helper.VM, "poweroff")
                helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
                final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
                save(destination / "final_vm_state.json", final)
                frozen.require(final["guest"]["VMState"] == '"poweroff"'
                               and final["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"',
                               "Phase-4 cleanup incomplete")
    v21.verify_production()
    summary = {"samples": len(records),
               "ok": sum(1 for r in records if r.get("result")),
               "malware_flooded": sum(1 for r in records if r.get("sample", {}).get("kind") in ("malware", "malware_c2")
                                      and (r.get("result", {}).get("nic_delta", {}) or {}).get("tx_packets", 0) and
                                      r["result"]["nic_delta"]["tx_packets"] > 50000),
               "benign_active": sum(1 for r in records if r.get("sample", {}).get("kind") == "benign"
                                    and (r.get("result", {}).get("nic_delta", {}) or {}).get("tx_packets", 0) and
                                    r["result"]["nic_delta"]["tx_packets"] > 100)}
    write_json(destination / "campaign.json", {"records": records, "summary": summary})
    print(json.dumps(summary, indent=2))
    return records


def self_test():
    # safety: every benign command targets ONLY the Sink; no other IP literal appears
    import re
    ipre = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
    for name, cmd in BENIGN.items():
        for m in ipre.finditer(cmd):
            assert m.group(0) == SINK, "benign %s references non-Sink IP %s" % (name, m.group(0))
    for m in ipre.finditer(PY_STREAM):
        assert m.group(0) == SINK, "py_stream references non-Sink IP"
    # orchestrator + controller + driver parse
    import ast
    ast.parse(ORCH_SRC); ast.parse(PY_STREAM); ast.parse(REG_CONTROLLER_SRC); ast.parse(Path(__file__).read_text())
    # the reg-only controller must never send an attack command (no ENABLE / PRIVMSG / attack verb)
    for banned in ("PRIVMSG", "ENABLE", "UDP ", "TCP ", "STD ", "HTTP ", "JUNK", "HOLD"):
        assert banned not in REG_CONTROLLER_SRC, "controller contains %r" % banned
    # malware set well-formed (C2 + non-C2 distinct hashes)
    allm = MALWARE + MALWARE_C2
    assert len({s for _, s, _ in allm}) == len(allm)
    # bpftrace program excludes the instruments
    assert 'comm != "tcpdump"' in ORCH_SRC and 'comm != "bpftrace"' in ORCH_SRC
    assert "raw_syscalls:sys_enter" in ORCH_SRC and "@by[args->id]" in ORCH_SRC
    print("self-test OK: reg-only controller attack-free, benign Sink-only, in-kernel counter excludes instruments,",
          len(MALWARE_C2), "c2-flood +", len(MALWARE), "host-storm +", len(BENIGN), "benign + 1 null")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--freeze-only", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--attempt")
    ap.add_argument("--approval")
    a = ap.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.run:
        frozen.require(a.attempt, "--attempt required")
        run_campaign(a.attempt, a.approval)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
