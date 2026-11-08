
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
