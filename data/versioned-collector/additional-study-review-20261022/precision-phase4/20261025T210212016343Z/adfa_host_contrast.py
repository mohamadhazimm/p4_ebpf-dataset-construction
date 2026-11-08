"""Apply the LOCKED ADFA host contract to this Phase-4 precision attempt, OFFLINE (no VM).

The Phase-4 host side was captured as a coarse system-wide syscall counter; this recomputes the
DISTRIBUTIONAL ADFA descriptors the saved per-syscall-id histogram supports (entropy, unique/total
syscalls, top-syscall-freq, rare-ratio) and tests whether host SEQUENCE-SHAPE separates the malicious
flood from benign bulk. Order-dependent ADFA descriptors (run-length/transition/first-N) need the raw
ordered stream, which a flood overflows, so they are out of scope here. Descriptors are whole-run,
system-wide proxies for the contract's per-window lineage-scoped mean/max features. Writes
adfa_host_contrast.json beside this script. Run: python3 adfa_host_contrast.py
"""
import json, math, glob, os
RUN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run")
LIMIT = 1024  # HOSTMON_SYSCALL_LIMIT

def adfa(hist, total):
    ent = mx = singles = uniq = 0; ent = 0.0
    for k, c in hist.items():
        if 0 <= int(k) < LIMIT and total:
            uniq += 1; p = c / total; ent -= p * math.log2(p)
            mx = max(mx, c); singles += (c == 1)
    return {"total_syscalls": total, "unique_syscalls": uniq, "entropy": round(ent, 4),
            "top_syscall_freq": round(mx / total, 5) if total else 0.0,
            "rare_syscall_ratio": singles / total if total else 0.0}

rows = []
for rj in sorted(glob.glob(os.path.join(RUN, "*.result.json"))):
    d = json.load(open(rj)); r = d.get("result", {})
    hist = r.get("syscalls_by_id") or {}; total = r.get("syscalls_total") or sum(hist.values())
    rows.append({"name": d["sample"]["name"], "kind": d["sample"].get("kind", r.get("mode", "?")),
                 "tx_pkts": r.get("nic_delta", {}).get("tx_packets", 0), **adfa(hist, total)})

flood = [x for x in rows if x["kind"] == "malware_c2"]
benign = [x for x in rows if x["kind"] == "benign"]
sep = {}
if flood and benign:
    f = flood[0]
    for feat in ("total_syscalls", "unique_syscalls", "entropy", "top_syscall_freq", "rare_syscall_ratio"):
        lo = min(b[feat] for b in benign); hi = max(b[feat] for b in benign)
        sep[feat] = {"flood": f[feat], "benign_min": lo, "benign_max": hi,
                     "separates": bool(f[feat] < lo or f[feat] > hi)}

out = {"contract": "host=ADFA distributional descriptors (whole-run, system-wide proxy); network=P4 flow",
       "note": "order-dependent ADFA descriptors omitted (flood overflows ordered stream); "
               "per-window lineage-scoped contract features on the flood remain unmeasured",
       "samples": rows, "flood_vs_benign_separation": sep}
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "adfa_host_contrast.json"), "w").write(json.dumps(out, indent=1))
print(json.dumps(sep, indent=1))
print("wrote adfa_host_contrast.json")
