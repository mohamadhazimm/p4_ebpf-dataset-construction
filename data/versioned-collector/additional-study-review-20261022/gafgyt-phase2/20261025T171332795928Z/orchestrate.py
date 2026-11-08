
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
