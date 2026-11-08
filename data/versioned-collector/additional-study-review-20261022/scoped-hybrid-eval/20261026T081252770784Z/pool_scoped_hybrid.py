"""Pooled host-vs-network-vs-hybrid evaluation over ALL paired sandbox captures (offline, no VM).

Sources (each sample = one real program run with BOTH a host syscall trace and a PCAP):
  - precision-phase4  : flood, host-storm malware, benign network bulk, null   (host hist = syscalls_by_id)
  - c2-viability      : Meterpreter reverse shells (host-evasive), Sliver/CobaltStrike/Winnti/Merlin beacons, nulls
  - evasive-viability : Rekoobe reverse/backdoor (host-visible), BPFDoor (dormant), nulls
  - gafgyt-phase3     : scanner SYN-floods (PCAP only -> network-only corroboration, excluded from fitted model)

Network features are flow-SHAPE, parsed uniformly from every PCAP with the same code.
Host features are a syscall-id histogram per sample (phase4: stored; viability: syscall_events.csv).
Caveat recorded: host scope differs by probe (phase4 coarse whole-run vs viability lineage-scoped); the
network parser is identical for all. Models: leave-one-GROUP-out (group=family/scenario, so near-duplicate
Meterpreter/Rekoobe cannot leak) logistic regression AND random forest, host-only / network-only / hybrid.
"""
import json, glob, os, csv, math, statistics, sys
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

BASE = os.path.abspath(".")
SEND_FAMILY = {44, 46, 20, 1, 40}      # sendto/sendmsg/writev/write/sendfile (coarse)
RECV_FAMILY = {45, 47, 19, 0}          # recvfrom/recvmsg/readv/read
CONN_FAMILY = {41, 42, 3}              # socket/connect/close
SINK, GUEST = "10.0.0.1", "10.0.0.10"

def host_from_hist(by, secs=20.0):
    by = {int(k): int(v) for k, v in by.items()}
    total = sum(by.values())
    send = sum(by.get(i,0) for i in SEND_FAMILY); recv = sum(by.get(i,0) for i in RECV_FAMILY)
    conn = sum(by.get(i,0) for i in CONN_FAMILY); top = max(by.values()) if by else 0
    ent = 0.0
    if total>0:
        for v in by.values():
            p=v/total
            if p>0: ent -= p*math.log2(p)
    return {"syscalls_total": total, "distinct_syscalls": len(by),
            "top_syscall_frac": top/total if total else 0.0,
            "send_frac": send/total if total else 0.0, "recv_frac": recv/total if total else 0.0,
            "conn_frac": conn/total if total else 0.0, "syscall_entropy": ent}

def net_shape(pcap, maxpkts=400000):
    from scapy.all import PcapReader, IP, TCP, UDP
    n=syn=synack=ackonly=rst=fin=udp=tiny=frm_sink=0; lens=[]; dip=set(); dpt=set()
    try:
        with PcapReader(str(pcap)) as pr:
            for p in pr:
                if n>=maxpkts: break
                n+=1; L=len(p); lens.append(L)
                if L<=74: tiny+=1
                if IP not in p: continue
                ip=p[IP]
                if ip.src==SINK: frm_sink+=1
                if ip.dst not in (GUEST,): dip.add(ip.dst)
                if TCP in p:
                    fl=int(p[TCP].flags); s=bool(fl&0x02); a=bool(fl&0x10)
                    if s and not a: syn+=1
                    elif s and a: synack+=1
                    elif a and not s: ackonly+=1
                    if fl&0x04: rst+=1
                    if fl&0x01: fin+=1
                    dpt.add(int(p[TCP].dport))
                elif UDP in p:
                    udp+=1; dpt.add(int(p[UDP].dport))
    except Exception as e:
        return {"pcap_error": str(e), "pkts":0}
    return {"pkts": n, "frac_syn_only": syn/n if n else 0.0, "frac_tiny": tiny/n if n else 0.0,
            "handshake": 1 if (synack>0 and ackonly>0) else 0, "bidir": 1 if frm_sink>0 else 0,
            "distinct_dst_ip": len(dip), "distinct_dst_port": len(dpt),
            "pkts_per_dst": (n/len(dip)) if dip else float(n),
            "mean_len": statistics.mean(lens) if lens else 0.0,
            "std_len": statistics.pstdev(lens) if len(lens)>1 else 0.0}

def hist_from_syscall_csv(path):
    by={}
    with open(path) as f:
        r=csv.DictReader(f)
        for row in r:
            if row.get("event")=="syscall":
                d=row.get("detail","")
                if d.startswith("id="):
                    try: k=int(d[3:].split()[0])
                    except: continue
                    by[k]=by.get(k,0)+1
    return by

rows=[]  # each: dict with keys label, scenario, group, probe, sample, host..., net...

# ---- precision-phase4 ----
p4="precision-phase4/20261025T210212016343Z/run"
P4MAP={"gafgyt_kaiten_flood":("flood","kaiten_flood",1),
       "gafgyt_a":("host_storm","gafgyt_a",1),"mirai_a":("host_storm","mirai_a",1),
       "mirai_heavy":("host_storm","mirai_heavy",1),
       "benign_bulk_get":("benign_bulk","benign_bulk",0),"benign_bulk_post":("benign_bulk","benign_bulk",0),
       "benign_tls_bulk":("benign_bulk","benign_bulk",0),"benign_py_stream":("benign_bulk","benign_bulk",0),
       "benign_wget_loop":("benign_bulk","benign_bulk",0),"benign_highrate":("benign_bulk","benign_bulk",0),
       "null":("benign_quiet","benign_quiet",0)}
for rj in sorted(glob.glob(p4+"/*.result.json")):
    name=os.path.basename(rj).replace(".result.json","")
    if name not in P4MAP: continue
    d=json.load(open(rj)).get("result",{})
    by=d.get("syscalls_by_id") or {}
    pcap=os.path.join(p4,name+".pcap")
    if not by or not os.path.exists(pcap): continue
    sc,grp,lab=P4MAP[name]
    h=host_from_hist(by); nt=net_shape(pcap)
    if nt.get("pcap_error"): continue
    rows.append({"probe":"phase4","sample":name,"label":lab,"scenario":sc,"group":grp,**{"h_"+k:v for k,v in h.items()},**{"n_"+k:v for k,v in nt.items()}})

# ---- c2-viability + evasive-viability (through .21 collector) ----
def fam_scn(label, fam):
    if label!="malware": return ("benign_quiet","benign_quiet",0)
    f=(fam or "").lower()
    if f=="meterpreter": return ("reverse_shell_evasive","meterpreter",1)
    if f=="rekoobe":     return ("reverse_shell_hostvisible","rekoobe",1)
    if f=="bpfdoor":     return ("backdoor_dormant","bpfdoor",1)
    return ("beacon_hostloud", f or "beacon", 1)   # sliver/cobaltstrike/winnti/merlin
for base in ["c2-viability/20261025T142642347649Z","evasive-viability/20261025T151638248361Z"]:
    m=json.load(open(glob.glob(base+"/measurement/*.json")[0]))
    for c in m["cases"]:
        s=c["sample"]
        pcs=glob.glob(os.path.join(base,"runs",s,"output","run_*","packet_capture.pcap"))
        scs=glob.glob(os.path.join(base,"runs",s,"output","run_*","syscall_events.csv"))
        if not pcs or not scs: continue
        by=hist_from_syscall_csv(scs[0]); nt=net_shape(pcs[0])
        if nt.get("pcap_error"): continue
        h=host_from_hist(by)
        sc,grp,lab=fam_scn(c["label"], c.get("family"))
        rows.append({"probe":os.path.basename(base.split('/')[0]),"sample":s[:40],"label":lab,"scenario":sc,"group":grp,
                     "exec_observed":c.get("exec_observed"),"return_code":c.get("return_code"),
                     **{"h_"+k:v for k,v in h.items()},**{"n_"+k:v for k,v in nt.items()}})

# ---- gafgyt-phase3 flood pcaps (network-only corroboration) ----
p3rows=[]
for pc in sorted(glob.glob("gafgyt-phase3/*/run/flood.pcap")):
    nt=net_shape(pc)
    if nt.get("pcap_error"): continue
    p3rows.append({"probe":"phase3","sample":pc.split('/')[1],"label":1,"scenario":"flood","group":"kaiten_flood_p3",**{"n_"+k:v for k,v in nt.items()}})

print("pooled samples with host+net:", len(rows))
from collections import Counter
print("by scenario:", dict(Counter(r["scenario"] for r in rows)))
print("by label:", dict(Counter(r["label"] for r in rows)))
print("phase3 flood pcaps (net-only):", len(p3rows))

# write tidy CSV
allkeys=sorted({k for r in rows for k in r})
with open("scoped-hybrid-eval/20261026T081252770784Z/pooled_samples.csv","w",newline="") as f:
    w=csv.DictWriter(f,fieldnames=allkeys); w.writeheader()
    for r in rows: w.writerow(r)

HOST=["h_syscalls_total","h_distinct_syscalls","h_top_syscall_frac","h_send_frac","h_recv_frac","h_conn_frac","h_syscall_entropy"]
NET =["n_frac_syn_only","n_frac_tiny","n_handshake","n_bidir","n_distinct_dst_ip","n_pkts_per_dst","n_mean_len","n_std_len","n_pkts"]
def vec(r,cols):
    out=[]
    for c in cols:
        v=float(r.get(c,0.0) or 0.0)
        if c in ("h_syscalls_total","n_distinct_dst_ip","n_pkts_per_dst","n_pkts"): v=math.log1p(max(v,0))
        out.append(v)
    return out

y=np.array([r["label"] for r in rows]); groups=[r["group"] for r in rows]; names=[r["sample"] for r in rows]
scen=[r["scenario"] for r in rows]

def logo(cols, model):
    X=np.array([vec(r,cols) for r in rows],float)
    preds=np.full(len(y),-1)
    ug=sorted(set(groups))
    for g in ug:
        te=[i for i in range(len(y)) if groups[i]==g]
        tr=[i for i in range(len(y)) if groups[i]!=g]
        if len(set(y[tr].tolist()))<2: continue
        if model=="lr":
            sc=StandardScaler().fit(X[tr]); clf=LogisticRegression(max_iter=3000,class_weight="balanced").fit(sc.transform(X[tr]),y[tr])
            preds[te]=clf.predict(sc.transform(X[te]))
        else:
            clf=RandomForestClassifier(n_estimators=400,class_weight="balanced",random_state=42,n_jobs=1).fit(X[tr],y[tr])
            preds[te]=clf.predict(X[te])
    mask=preds>=0
    tp=int(np.sum((preds==1)&(y==1)&mask)); tn=int(np.sum((preds==0)&(y==0)&mask))
    fp=int(np.sum((preds==1)&(y==0)&mask)); fn=int(np.sum((preds==0)&(y==1)&mask))
    rec=tp/(tp+fn) if tp+fn else 0.0; spec=tn/(tn+fp) if tn+fp else 0.0
    prec=tp/(tp+fp) if tp+fp else 0.0; f1=2*prec*rec/(prec+rec) if prec+rec else 0.0
    return {"BA":round((rec+spec)/2,3),"precision":round(prec,3),"recall":round(rec,3),"F1":round(f1,3),
            "tp":tp,"tn":tn,"fp":fp,"fn":fn,"n_scored":int(mask.sum()),
            "preds":preds.tolist()}

res={}
for mdl in ("lr","rf"):
    res[mdl]={"host":logo(HOST,mdl),"network":logo(NET,mdl),"hybrid":logo(HOST+NET,mdl)}

print("\n==== leave-one-group-out, malicious-vs-benign (n=%d; %d malicious / %d benign) ===="%(len(y),int(y.sum()),int((y==0).sum())))
for mdl in ("lr","rf"):
    print("model=%s"%("logistic" if mdl=="lr" else "random-forest"))
    for fs in ("host","network","hybrid"):
        r=res[mdl][fs]
        print("  %-8s BA=%.3f  prec=%.3f  rec=%.3f  F1=%.3f   cm[tp=%d tn=%d fp=%d fn=%d]"%(fs,r["BA"],r["precision"],r["recall"],r["F1"],r["tp"],r["tn"],r["fp"],r["fn"]))

# per-scenario correctness under RF-hybrid vs RF-host vs RF-network
print("\n==== per-scenario detection (RF, leave-one-group-out) ====")
rf=res["rf"]
scns=["flood","host_storm","reverse_shell_evasive","beacon_hostloud","reverse_shell_hostvisible","backdoor_dormant","benign_bulk","benign_quiet"]
print("%-27s %4s | %-18s %-18s %-18s"%("scenario","n","host correct","net correct","hybrid correct"))
per={}
for s in scns:
    idx=[i for i in range(len(y)) if scen[i]==s]
    if not idx: continue
    def corr(fs):
        p=rf[fs]["preds"]; return sum(1 for i in idx if p[i]==y[i] and p[i]>=0)
    per[s]={"n":len(idx),"host":corr("host"),"net":corr("network"),"hybrid":corr("hybrid")}
    print("%-27s %4d | %-18s %-18s %-18s"%(s,len(idx),f"{corr('host')}/{len(idx)}",f"{corr('network')}/{len(idx)}",f"{corr('hybrid')}/{len(idx)}"))

# network-only flood corroboration from phase3
print("\n==== phase3 scanner-flood PCAPs (network-only flood signature) ====")
for r in p3rows:
    print("  %-22s syn_only=%.3f handshake=%d bidir=%d distinct_dst=%d pkts_per_dst=%.1f"%(r["sample"],r["n_frac_syn_only"],r["n_handshake"],r["n_bidir"],r["n_distinct_dst_ip"],r["n_pkts_per_dst"]))

json.dump({"n":len(rows),"by_scenario":dict(Counter(scen)),"models":{m:{f:{k:v for k,v in res[m][f].items() if k!="preds"} for f in res[m]} for m in res},
           "per_scenario_rf":per,"phase3_flood":p3rows},
          open("scoped-hybrid-eval/20261026T081252770784Z/pooled_results.json","w"),indent=1)
print("\nwrote CSV + JSON")
