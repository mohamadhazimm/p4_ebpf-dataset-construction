import csv, glob, json, os, sys
REL="/home/ali/Desktop/Hazim/p4-ebpf-malware-detection"
STUDY="/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022"
REV5=STUDY+"/revision5-collection/20261025T100025568989Z"
OUT="/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/launcher-ablation"
sys.path.insert(0, REL+"/features"); import host_model as hm
BASE18=hm.FEATURES
SUF=["mean","max","sum","std","active_windows"]

cases={c["position"]: c for c in json.load(open(REV5+"/payload/cases.json"))}

def find_run(d):
    g=sorted(glob.glob(d+"/output/run_*"))
    return g[0] if g else None

def resolve(row):
    cat=row["category"]; eid=row["execution_id"]; pos=row["collection_position"].strip()
    if pos:  # revision5 case
        s=cases[int(pos)]["sample"]
        r=find_run(REV5+"/runs/"+s)
        return [r] if r else []
    # background batch: search by <eid>.zip
    cands=[]
    for d in glob.glob(STUDY+"/*/*/runs/"+eid+".zip")+glob.glob(STUDY+"/*/runs/"+eid+".zip"):
        r=find_run(d)
        if r: cands.append(r)
    return cands

def parse(run):
    meta=json.load(open(run+"/run.json"))
    root=meta["sample_root_pid"]
    # cut = 2nd root exec_success ts (bash->target boundary)
    succ=[int(e["timestamp_ns"]) for e in csv.DictReader(open(run+"/exec_events.csv"))
          if e["event"]=="exec_success" and int(e["pid"])==root]
    cut=succ[1] if len(succ)>=2 else None
    ev=[]; mask=[]
    for r in csv.DictReader(open(run+"/syscall_events.csv")):
        if r["event"]!="syscall": continue
        try: sid=int(r["detail"].split("id=")[1].split()[0])
        except: continue
        ev.append((int(r["window_id"]), int(r["pid"]), sid))
        mask.append(cut is not None and int(r["pid"])==root and int(r["timestamp_ns"])<cut)
    return ev, mask

def agg90(wl):
    out={}
    for b in BASE18:
        v=[float(w[b]) for w in wl]; n=len(v); m=sum(v)/n
        out[b+"__mean"]=m; out[b+"__max"]=max(v); out[b+"__sum"]=sum(v)
        out[b+"__std"]=(sum((x-m)**2 for x in v)/n)**0.5
        out[b+"__active_windows"]=float(sum(1 for x in v if x!=0))
    return out

def feats(ev, mask, drop):
    e=[x for x,mm in zip(ev,mask) if not mm] if drop else ev
    return agg90(hm.window_features(e, windows=40))

rows=list(csv.DictReader(open(REL+"/dataset/features.csv")))
hostcols=[c for c in rows[0] if c.startswith("host_")]
assert len(hostcols)==90
freecols={}  # idx -> dict of launcher-free host cols
report={"match":0,"mismatch":[],"unresolved":[],"launch":{}}
for i,row in enumerate(rows):
    cands=resolve(row)
    chosen=None; full=None
    for run in cands:
        ev,mask=parse(run)
        total=len(ev)
        # cheap gate: lineage total == host_total__sum
        if abs(total-float(row["host_total_syscalls_total__sum"]))>0.5:
            continue
        full=feats(ev,mask,False)
        err=max(abs(full[c]-float(row[c])) for c in hostcols)
        if err<=1e-6*max(1,max(abs(float(row[c])) for c in hostcols)):
            chosen=(run,ev,mask); break
    if chosen is None:
        # fall back: take first candidate even if cheap-gate failed, record error
        if cands:
            ev,mask=parse(cands[0]); full=feats(ev,mask,False)
            err=max(abs(full[c]-float(row[c])) for c in hostcols)
            report["mismatch"].append((row["execution_id"],row["category"],round(err,6),len(ev)))
            chosen=(cands[0],ev,mask)
        else:
            report["unresolved"].append((row["execution_id"],row["category"])); continue
    else:
        report["match"]+=1
    run,ev,mask=chosen
    nl=sum(mask); report["launch"][nl]=report["launch"].get(nl,0)+1
    freecols[i]=feats(ev,mask,True)

print("resolved+matched: %d / %d" % (report["match"], len(rows)))
print("launcher-count distribution:", dict(sorted(report["launch"].items())))
print("unresolved:", report["unresolved"][:10], "count", len(report["unresolved"]))
print("mismatches (eid,cat,maxerr,ncalls):")
for m in report["mismatch"][:20]: print("   ",m)
print("   total mismatches:", len(report["mismatch"]))

# write launcher-free csv (host cols replaced where available)
if not report["unresolved"]:
    fn=OUT+"/features_launcherfree.csv"
    with open(fn,"w",newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader()
        for i,row in enumerate(rows):
            r=dict(row)
            for c in hostcols: r[c]=repr(freecols[i][c])
            w.writerow(r)
    print("WROTE", fn)
    # control copy (original) for the harness
    import shutil; shutil.copy(REL+"/dataset/features.csv", OUT+"/features_original.csv")
    print("WROTE", OUT+"/features_original.csv")
else:
    print("NOT writing csv: unresolved rows remain")
