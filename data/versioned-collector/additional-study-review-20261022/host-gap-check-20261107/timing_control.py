"""How much of the 5-min detector score survives when the timing information is removed?

Same 5-min cohort, protocol and seeds as compare_host.py (102 malware / 102 benign, StratifiedGroupKFold(5) over
families/programs, RF300 balanced, threshold 0.5, fold seeds 42 + 0-8). Host = the 18 ADFA signals, network = the
29 P4 signals, hybrid = both. Three representations of each run:

  full      mean, max, sum, std, active_windows per signal (the paper's 5 statistics) -- as reported before
  no_active the same without the active_windows columns
  shape     per signal, its mean over the windows in which that sensor saw anything (host: windows with any
            system calls; network: windows with any packets). No count of windows, no sum, no spread, no peak:
            "what the program looks like while it is running", with no information on when or for how long.
Plus the one-feature lifetime baseline (number of windows with any system calls) for reference.
Offline; no VM, no merge, no promotion. Run: nice -n 19 /usr/bin/python3 timing_control.py
"""
import csv
import glob
import json
import sys
from collections import defaultdict
from multiprocessing import Pool

import numpy as np

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import compare_host as ch  # noqa: E402  same cohort definition, summ(), job_cv(), SEEDS

OUT = ch.PROJ + "/host-gap-check-20261107/timing_control.json"


def signals():
    rows = list(csv.DictReader(open(ch.REL + "/dataset/features.csv")))
    host = list(dict.fromkeys(c.rsplit("__", 1)[0] for c in rows[0] if c.startswith("host_")))
    net = list(dict.fromkeys(c.rsplit("__", 1)[0] for c in rows[0] if c.startswith("net_")))
    assert len(host) == 18 and len(net) == 29
    return host, net


def load(host, net):
    out, seen = [], set()
    for tag, rel, keep in ch.ATT:
        att = ch.PROJ + "/" + rel
        meta = {c["sample"]: c for c in json.load(open(att + "/protocol.json"))["cases"]}
        for rj in sorted(glob.glob(att + "/runs/*/output/run_*/run.json")):
            sample = rj.split("/runs/")[1].split("/")[0]
            c = meta.get(sample)
            if not c or c["label"] not in keep or sample in seen:
                continue
            d = json.load(open(rj))
            if d.get("collection_quality_status") != "accepted":
                continue
            tel = list(csv.DictReader(open(rj.replace("run.json", "telemetry.csv"))))
            if len(tel) != 600:
                continue
            assert d["telemetry_feature_groups"]["p4_network"] == net
            seen.add(sample)
            prog = c.get("program") or c.get("variant")
            out.append({"y": int(c["label"] == "malware"),
                        "group": ("fam:" + c["family"]) if c["label"] == "malware" else ("prog:" + prog),
                        "H": np.array([[float(t[s]) for s in host] for t in tel]),
                        "N": np.array([[float(t[s]) for s in net] for t in tel])})
    return out


def shape(M, k, gate_col):
    """Mean of each column over the windows (of the first k) in which column gate_col is non-zero."""
    m = M[:k]
    on = m[:, gate_col] != 0
    return m[on].mean(0) if on.any() else np.zeros(m.shape[1])


def drop_active(v):
    keep = [i for i in range(len(v)) if i % 5 != 4]       # signal-major: index 4 of each block = active_windows
    return v[keep]


def main():
    host, net = signals()
    cases = load(host, net)
    y = np.array([c["y"] for c in cases]); g = np.array([c["group"] for c in cases])
    h_gate = host.index("host_total_syscalls_total"); n_gate = net.index("net_pkts_total_delta")
    print("cohort: %d malware / %d benign, %d groups" % (y.sum(), (y == 0).sum(), len(set(g))))
    sets = {}
    for k, lab in ((40, "20s"), (600, "5min")):
        Hf = np.array([ch.summ(c["H"], k) for c in cases]); Nf = np.array([ch.summ(c["N"], k) for c in cases])
        Hn = np.array([drop_active(v) for v in Hf]); Nn = np.array([drop_active(v) for v in Nf])
        Hs = np.array([shape(c["H"], k, h_gate) for c in cases]); Ns = np.array([shape(c["N"], k, n_gate) for c in cases])
        for rep, (Hx, Nx) in (("full", (Hf, Nf)), ("no_active", (Hn, Nn)), ("shape", (Hs, Ns))):
            sets["%s|%s|host" % (lab, rep)] = Hx
            sets["%s|%s|network" % (lab, rep)] = Nx
            sets["%s|%s|hybrid" % (lab, rep)] = np.hstack([Hx, Nx])
        sets["%s|lifetime|host" % lab] = Hf[:, [host.index("host_total_syscalls_total") * 5 + 4]]
    jobs = [(name, X, y, g, s, 300) for name, X in sets.items() for s in ch.SEEDS]
    with Pool(12) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for name, seed, sc, _ in out:
        per[name].append(sc)
    res = {"cohort": {"malware": int(y.sum()), "benign": int((y == 0).sum()), "groups": len(set(g))}, "scores": {}}
    print("\n%-6s %-10s %-8s %-16s %-16s  seed-42 (tn,fp,fn,tp)" % ("len", "features", "detector", "BA mean+/-sd",
                                                                   "AUC mean+/-sd"))
    for name in sets:
        lab, rep, det = name.split("|")
        ba = ch.summary([s["ba"] for s in per[name]]); auc = ch.summary([s["auc"] for s in per[name]])
        s42 = [s for s in per[name]][0]
        res["scores"][name] = {"ba": ba, "auc": auc, "seed42": s42, "n_features": int(sets[name].shape[1])}
        print("%-6s %-10s %-8s %.3f +/- %.3f    %.3f +/- %.3f    %d,%d,%d,%d   (%d features)"
              % (lab, rep, det, ba["mean"], ba["sd"], auc["mean"], auc["sd"],
                 s42["tn"], s42["fp"], s42["fn"], s42["tp"], sets[name].shape[1]))
    json.dump(res, open(OUT, "w"), indent=2, default=float)
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
