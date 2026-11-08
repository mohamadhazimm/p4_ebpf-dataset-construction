"""Stage 2: flood-trigger VIABILITY probe for the network-strong candidates (sealed VM; floods die at the gateway).

For each quarantined candidate it runs one restored-baseline boot and measures, paired and overflow-robust:
host syscalls (in-kernel bpftrace count), true enp0s3 NIC rx/tx deltas, and a tcpdump flow capture (snaplen 96,
first 300k frames). IRC families (Tsunami/Gafgyt) are run with their OWN candidate C2 IP(s) aliased to lo and a
reg-only IRC controller bound across the common IRC/DDoS ports (registration + keepalive ONLY -- NO attack command;
the bot's autonomous scanner is the flood). Mirai is run autonomously (its C2 is opaque/non-IRC). Tiers each sample
flood (tx_packets > FLOOD_TX) vs no-flood. SAFETY: guest intnet-only on sealed malnet (scan SYNs die at the gateway,
never leave the host); C2 only on an in-guest lo alias; VM restored to the original snapshot + powered off after each
sample. Reuses collect_v21 .21-pinned verify_production + the Phase-3/4 VM choreography. No model, no merge.
"""
import argparse, json, os, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import export_original_sources as exp   # noqa: E402
import collect_v21 as v21               # noqa: E402
import collect_v19 as frozen            # noqa: E402

STUDY = frozen.STUDY
digest, save, load, stamp = frozen.digest, frozen.save, frozen.load, frozen.stamp
QUAR = STUDY / "data/malware/revision5-diverse/net-strong-incoming"
MANIFEST = QUAR / "net_strong_candidates.json"
TRIAGE_QUAR = STUDY / "data/malware/revision5-diverse/triage-netstrong"
TRIAGE_MANIFEST = TRIAGE_QUAR / "triage_netstrong_candidates.json"
WINDOW = 20
FLOOD_TX = 50000          # tx_packets over the window above which a sample counts as "flooded" (null noise << 1k)
# common IRC / DDoS-bot C2 ports to bind the reg-only controller on (the bot's exact port is unknown per sample)
C2_PORTS = [6667, 6668, 6669, 6697, 23, 443, 80, 8080, 1024, 2000, 666, 1337, 5555, 48101, 420, 7, 53]
RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "114.114.114.114", "4.2.2.2", "208.67.222.222"}

# ---- in-guest reg-only IRC controller, MULTI-PORT (registration + keepalive only; NO attack command) ----
REG_CONTROLLER_SRC = r'''
import socket, sys, threading, time, json
ports = [int(p) for p in sys.argv[1].split(",")]; logpath = sys.argv[2]
logf = open(logpath, "a", buffering=1)
def rec(d, s):
    try: logf.write(json.dumps({"t": time.time(), "dir": d, "msg": s}) + "\n")
    except Exception: pass
def send(conn, s):
    conn.sendall((s + "\r\n").encode("latin-1", "replace"))
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
            parts = text.split(); cmd = parts[0].upper() if parts else ""
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
def serve(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port)); s.listen(8); s.settimeout(300)
    except Exception as e:
        rec("INFO", "bind %d failed: %s" % (port, e)); return
    while True:
        try: conn, addr = s.accept()
        except socket.timeout: return
        except Exception: return
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
for p in ports:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
rec("INFO", "reg-only multi-port controller up on %s (NO attack commands)" % ports)
time.sleep(100000)
'''

ORCH_SRC = r'''
import os, sys, json, time, glob, hashlib, subprocess
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
result = {"mode": mode, "steps": {}, "errors": []}
try: os.remove(pwfile)
except Exception: pass
bpf_out = os.path.join(outdir, "bpf.out")
PROG = ('tracepoint:raw_syscalls:sys_enter /comm != "tcpdump" && comm != "bpftrace" && comm != "sudo"/ '
        '{ @total = count(); @by[args->id] = count(); }')
btf = open(bpf_out, "w")
bt = sudo(["/usr/bin/bpftrace","-e",PROG], bg=True, out=btf)
td = sudo(["/usr/bin/tcpdump","-i","enp0s3","-n","-s","96","-c","300000","-w",pcap], bg=True)
time.sleep(4)
ctrl = None; aliased = []
if mode == "malware_c2":
    controller_py, ips_csv, ports_csv = extra[0], extra[1], extra[2]
    for ip in [x for x in ips_csv.split(",") if x]:
        rc,_ = sudo(["/usr/sbin/ip","addr","add",ip+"/32","dev","lo"])
        if rc == 0: aliased.append(ip)
    result["steps"]["aliased"] = aliased
    ctrl = subprocess.Popen(["/usr/bin/python3", controller_py, ports_csv, os.path.join(outdir,"c2.log")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    time.sleep(1.5)
nic0 = nic(); t0 = time.time()
if mode in ("malware", "malware_c2"):
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
elif mode == "benign":
    if "/tmp/p4big" in payload:
        subprocess.run(["dd","if=/dev/zero","of=/tmp/p4big","bs=1M","count=50"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    w = subprocess.Popen(["timeout", str(window), "bash", "-c", payload],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try: w.wait(timeout=window+30)
    except subprocess.TimeoutExpired: w.kill()
    result["workload_exit"] = w.poll()
else:
    time.sleep(window)
t1 = time.time(); result["active_seconds"] = round(t1 - t0, 2)
nic1 = nic()
sudo(["pkill","-INT","-x","tcpdump"]); time.sleep(2)
sudo(["pkill","-INT","-x","bpftrace"]); time.sleep(4)
btf.flush(); btf.close()
if ctrl is not None:
    try: ctrl.terminate()
    except Exception: pass
    for ip in aliased:
        sudo(["/usr/sbin/ip","addr","del",ip+"/32","dev","lo"])
result["nic_delta"] = {k: ((nic1.get(k) or 0) - (nic0.get(k) or 0)) if nic0.get(k) is not None else None
                       for k in ("rx_packets","tx_packets","rx_bytes","tx_bytes")}
total = 0; by = {}
for ln in open(bpf_out):
    ln = ln.strip()
    if ln.startswith("@total:"):
        try: total = int(ln.split(":")[1])
        except Exception: pass
    elif ln.startswith("@by["):
        try:
            sid = int(ln[ln.index("[")+1:ln.index("]")]); by[sid] = int(ln.rsplit(":",1)[1])
        except Exception: pass
result["syscalls_total"] = total; result["syscalls_by_id"] = by
sudo(["/bin/chown", os.environ.get("USER","csci"), pcap]); sudo(["/bin/chmod","0644",pcap])
result["pcap_bytes"] = os.path.getsize(pcap) if os.path.exists(pcap) else 0
print(json.dumps(result))
'''


def valid_public(ip):
    try:
        o = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if len(o) != 4 or any(x < 0 or x > 255 for x in o):
        return False
    if ip in RESOLVERS:
        return False
    if o[0] in (0, 10, 127) or (o[0] == 192 and o[1] == 168) or (o[0] == 172 and 16 <= o[1] <= 31) \
       or o[0] >= 224 or o[3] == 0:
        return False
    return True


def select(per_family):
    m = json.load(open(MANIFEST))
    out = []
    for fam in ("Tsunami", "Gafgyt", "Mirai"):
        rows = [r for r in m["kept"] if r["family"] == fam]
        if fam == "Mirai":
            pick = rows[:per_family]                       # Mirai: autonomous (C2 opaque)
            for r in pick:
                out.append({"name": "mirai_%s" % r["sha256"][:10], "kind": "malware",
                            "sha256": r["sha256"], "family": fam, "mode": r["mode"]})
        else:
            real = [r for r in rows if any(valid_public(ip) for ip in r["c2"]["candidate_ips"])]
            pick = (real + [r for r in rows if r not in real])[:per_family]
            for r in pick:
                ips = [ip for ip in r["c2"]["candidate_ips"] if valid_public(ip)][:6]
                out.append({"name": "%s_%s" % (fam.lower(), r["sha256"][:10]), "kind": "malware_c2",
                            "sha256": r["sha256"], "family": fam, "mode": r["mode"], "c2_ips": ips})
    return out


def select_triage(n):
    """Triage-sourced Gafgyt with EXACT C2 ip:port; bot run with that IP aliased + controller on that exact port."""
    import zipfile
    m = json.load(open(TRIAGE_MANIFEST))
    out = []
    for r in m["kept"][:n]:
        ips, ports = [], []
        for c in r["c2"]:
            if ":" in c:
                ip, _, pt = c.rpartition(":")
                if valid_public(ip):
                    ips.append(ip)
                if pt.isdigit():
                    ports.append(pt)
            elif valid_public(c):
                ips.append(c)
        out.append({"name": "%s_%s" % (r["family"], r["sha256"][:10]), "kind": "malware_c2",
                    "sha256": r["sha256"], "family": r["family"], "mode": r["mode"],
                    "c2_ips": ips[:6], "c2_ports": (ports[:6] or [str(p) for p in C2_PORTS]),
                    "raw_elf": r["elf_path"]})
    return out


def freeze(per_family, tag, source="mb", n=12):
    import zipfile
    v21.verify_production()
    helper = exp.helper_module()
    attempt = ROOT / "net-strong-viability" / (tag + "-" + stamp())
    attempt.mkdir(parents=True, exist_ok=False)
    (attempt / "orchestrate.py").write_text(ORCH_SRC)
    (attempt / "controller.py").write_text(REG_CONTROLLER_SRC)
    subprocess.run(["python3", "-c", "import ast,sys; [ast.parse(open(p).read()) for p in sys.argv[1:]]",
                    str(attempt / "orchestrate.py"), str(attempt / "controller.py")], check=True)
    if source == "triage":
        samples = select_triage(n)
        sdir = attempt / "samples"; sdir.mkdir()
        for s in samples:                                   # wrap each raw Triage ELF into a plain zip for the orchestrator
            z = sdir / (s["sha256"] + ".zip")
            with zipfile.ZipFile(z, "w") as zf:
                zf.write(s["raw_elf"], arcname=s["sha256"])
            s["zip"] = "samples/" + s["sha256"] + ".zip"
    else:
        samples = select(per_family)
        for s in samples:
            frozen.require((QUAR / (s["sha256"] + ".zip")).is_file(), "missing quarantined zip " + s["sha256"][:12])
    protocol = {"format": "net-strong-viability-v1", "source": source, "window_seconds": WINDOW,
                "flood_tx_threshold": FLOOD_TX, "c2_ports": C2_PORTS, "samples": samples,
                "baseline_snapshot": v21.BASELINE, "original_snapshot": helper.ORIGINAL,
                "orchestrator_sha256": digest(attempt / "orchestrate.py"),
                "controller_sha256": digest(attempt / "controller.py"), "driver_sha256": digest(Path(__file__)),
                "approval": None,
                "safety": ["guest intnet-only on sealed malnet; scan SYNs die at the gateway (never leave host); "
                           "bot C2 only on in-guest lo alias; reg-only controller sends NO attack command; "
                           "BASELINE restore + poweroff after each sample; ORIGINAL restore at end."]}
    save(attempt / "protocol.json", protocol)
    fams = sorted({s["family"] for s in samples})
    print(json.dumps({"attempt": str(attempt), "source": source, "samples": len(samples),
                      "by_family": {f: sum(1 for s in samples if s["family"] == f) for f in fams}}, indent=2))
    return attempt


def _poweroff(helper):
    if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
        helper.vbox("controlvm", helper.VM, "poweroff", check=False); time.sleep(3)


def _one(helper, auth, attempt, dest, s, base):
    _poweroff(helper)
    helper.vbox("snapshot", helper.VM, "restore", v21.BASELINE)
    frozen.require(helper.isolated(helper.VM)["CurrentSnapshotName"] == '"' + v21.BASELINE + '"', "baseline restore differs")
    exp.wait_guest(helper, auth, dest / (s["name"] + ".login.log"))
    gpcap = base + s["name"] + ".pcap"
    with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-nspw-") as gpw:
        os.chmod(gpw.name, 0o600); gpw.write(helper.credentials()); gpw.flush()
        zip_src = str((attempt / s["zip"]).resolve()) if s.get("zip") else str(QUAR / (s["sha256"] + ".zip"))
        copies = [(str(attempt / "orchestrate.py"), base + "orch.py"), (gpw.name, base + "pw"),
                  (zip_src, base + "sample.zip")]
        if s["kind"] == "malware_c2":
            copies.append((str(attempt / "controller.py"), base + "ctl.py"))
        for src, dst in copies:
            cp = helper.vbox("guestcontrol", helper.VM, "copyto", *auth, src, dst, check=False)
            frozen.require(cp.returncode == 0, "copyto %s rc=%s" % (dst, cp.returncode))
        extra = []
        if s["kind"] == "malware_c2":
            ports = s.get("c2_ports") or [str(p) for p in C2_PORTS]
            extra = [base + "ctl.py", ",".join(s.get("c2_ips", [])), ",".join(str(p) for p in ports)]
        runargs = ["guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                   "--wait-stdout", "--wait-stderr", "--timeout", str((WINDOW + 180) * 1000),
                   "--", base + "orch.py", s["kind"], base + "pw", str(WINDOW), base + "out", gpcap,
                   base + "sample.zip"] + extra
        orch = helper.vbox(*runargs, check=False)
    (dest / (s["name"] + ".stdout")).write_text(orch.stdout or "")
    (dest / (s["name"] + ".stderr")).write_text(orch.stderr or "")
    rec = {"sample": s, "orch_rc": orch.returncode}
    if orch.returncode == 0 and (orch.stdout or "").strip():
        try:
            data = json.loads(orch.stdout.strip().splitlines()[-1]); rec["result"] = data
            cf = helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, gpcap, str(dest / (s["name"] + ".pcap")), check=False)
            rec["pcap_copied"] = cf.returncode == 0
            tx = (data.get("nic_delta", {}) or {}).get("tx_packets") or 0
            rec["flooded"] = tx > FLOOD_TX
        except Exception as e:
            rec["parse_error"] = str(e)
    else:
        rec["error"] = "orch rc=%s %s" % (orch.returncode, (orch.stderr or "")[-200:])
    frozen.save(dest / (s["name"] + ".result.json"), rec)
    _poweroff(helper)
    return rec


def run_campaign(attempt, approval):
    frozen.require(approval and approval.strip(), "verbatim approval required")
    attempt = Path(attempt)
    if not attempt.is_absolute():
        attempt = (ROOT / attempt).resolve()
    protocol = load(attempt / "protocol.json")
    helper = exp.helper_module(); v21.verify_production()
    dest = attempt / "run"; dest.mkdir(parents=True, exist_ok=False)
    save(dest / "authorization.json", {"approval": approval, "authorized_utc": datetime.now(timezone.utc).isoformat()})
    import fcntl
    records = []
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        exp.check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        frozen.require(before["guest"]["VMState"] == '"poweroff"' and before["sink"]["VMState"] == '"running"'
                       and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"',
                       "expected original powered-off guest + running Sink")
        save(dest / "initial_vm_state.json", before)
        touched = False
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-ns-") as pwf:
                os.chmod(pwf.name, 0o600); pwf.write(helper.credentials()); pwf.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", pwf.name]; touched = True
                for s in protocol["samples"]:
                    base = "/tmp/ns-" + attempt.name + "-" + s["name"] + "-"
                    try:
                        rec = _one(helper, auth, attempt, dest, s, base)
                    except BaseException as e:
                        rec = {"sample": s, "error": type(e).__name__ + ": " + str(e)}
                        frozen.save(dest / (s["name"] + ".result.json"), rec)
                    records.append(rec)
                    (dest / "campaign.json").write_text(json.dumps({"records": records}, indent=2))
        finally:
            if touched:
                if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                    helper.vbox("controlvm", helper.VM, "poweroff")
                helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
                final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
                save(dest / "final_vm_state.json", final)
                frozen.require(final["guest"]["VMState"] == '"poweroff"'
                               and final["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"', "cleanup incomplete")
    v21.verify_production()
    flood = [r for r in records if r.get("flooded")]
    fams = sorted({r["sample"]["family"] for r in records if r.get("sample")})
    summ = {"n": len(records), "ok": sum(1 for r in records if r.get("result")), "flooded": len(flood),
            "flooded_by_family": {f: sum(1 for r in flood if r["sample"]["family"] == f) for f in fams}}
    (dest / "campaign.json").write_text(json.dumps({"records": records, "summary": summ}, indent=2))
    print(json.dumps(summ, indent=2))
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--freeze-only", action="store_true")
    ap.add_argument("--per-family", type=int, default=3)
    ap.add_argument("--tag", default="batch")
    ap.add_argument("--source", default="mb", choices=["mb", "triage"])
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--attempt")
    ap.add_argument("--approval")
    a = ap.parse_args()
    if a.freeze_only:
        freeze(a.per_family, a.tag, source=a.source, n=a.n)
    elif a.run:
        frozen.require(a.attempt, "--attempt required")
        run_campaign(a.attempt, a.approval)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
