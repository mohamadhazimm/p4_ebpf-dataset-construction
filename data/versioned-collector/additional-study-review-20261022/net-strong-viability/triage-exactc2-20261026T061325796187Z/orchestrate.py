
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
