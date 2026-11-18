import csv, glob, json, re, sys
from collections import Counter
sys.path.insert(0, "/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/switch-exact-1s")
import build_rows as br
def table(path):
    t = {}
    for line in open(path):
        m = re.match(r"#define __NR_(\w+)\s+(\d+)", line)
        if m: t[int(m.group(2))] = m.group(1)
    return t
N64 = table("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")
N32 = table("/usr/include/x86_64-linux-gnu/asm/unistd_32.h")
rows = list(csv.DictReader(open(br.REL / "dataset/features.csv")))
pool = json.load(open(br.POOL))
out = []
for i, row in enumerate(rows[:204]):
    if row["category"] != "benign": continue
    run = glob.glob(str(br.run_dir(i, row, pool) / "output" / "run_*"))[0]
    meta = json.load(open(run + "/run.json"))
    root = meta["sample_root_pid"]
    succ = [int(e["timestamp_ns"]) for e in csv.DictReader(open(run + "/exec_events.csv")) if e["event"] == "exec_success" and int(e["pid"]) == root]
    cut = succ[1]
    names = N32 if row["mode"] == "i386_static" else N64
    seq = []
    for r in csv.DictReader(open(run + "/syscall_events.csv")):
        if r["event"] != "syscall" or int(r["pid"]) != root or int(r["timestamp_ns"]) < cut: continue
        if int(r["window_id"]) != 0: break
        sid = int(r["detail"].split("id=")[1].split()[0])
        seq.append(names.get(sid, str(sid)))
        if len(seq) == 50: break
    out.append({"execution_id": row["execution_id"], "mode": row["mode"], "program": row["program"],
                "first50": seq, "distinct": len(set(seq)), "feature": float(row["host_first50_unique_mean__max"])})
json.dump(out, open("dataset_first50.json", "w"), indent=1)
for o in out:
    if o["mode"] == "amd64_dynamic":
        print(o["execution_id"], o["distinct"], " ".join(o["first50"]))
