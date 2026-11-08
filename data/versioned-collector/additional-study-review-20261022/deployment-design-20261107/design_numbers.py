"""Numbers for the deployment design: how early a verdict is available, and how many flows per window the switch
reader must handle for one monitored host.

A. Time to decision. The 204 general-malware runs of the paper dataset (raw 40 x 0.5-s windows), cut at prefixes of
   1, 2, 5, 10, 15 and 20 s; host / network / hybrid with the paper's five statistics; grouped CV over whole families
   and projects, StratifiedGroupKFold(5), 10 fold seeds, RF300 balanced, threshold 0.5. Also the same with the
   launch prologue removed from window 0 is NOT done here (it needs the raw events); the prologue is identical in
   every run and is noted in AGENTS.md section 4.14.
B. Flow budget. Per-window active flows (net_flow_count_seen) in every run of the released dataset (features.csv:
   the window maximum per run), by category, and per window in the raw paper telemetry; and the switch reader's
   capacity at 1.14 ms (sync + shadow read, persistent session) and 1.40 ms (per-cell) per flow.
Offline; no VM. Run: nice -n 19 /usr/bin/python3 design_numbers.py
"""
import csv
import json
import sys
from collections import defaultdict
from multiprocessing import Pool

import numpy as np

HERE = __file__.rsplit("/", 1)[0]
GAP = HERE.rsplit("/", 1)[0] + "/host-gap-check-20261107"
sys.path.insert(0, GAP)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch   # noqa: E402
import timing_control as tc  # noqa: E402
import paper_vs_5min as pv   # noqa: E402

PREFIX_S = [1, 2, 5, 10, 15, 20]
OUT = HERE + "/design_numbers.json"


def main():
    host, net = tc.signals()
    paper = pv.load_paper(host, net)
    y = np.array([c["y"] for c in paper]); g = np.array([c["group"] for c in paper])
    ng = net.index("net_flow_count_seen")
    sets = {}
    for s in PREFIX_S:
        k = s * 2
        Hf = np.array([ch.summ(c["H"], k) for c in paper]); Nf = np.array([ch.summ(c["N"], k) for c in paper])
        sets[(s, "host")] = (Hf, y, g); sets[(s, "network")] = (Nf, y, g); sets[(s, "hybrid")] = (np.hstack([Hf, Nf]), y, g)
    keys = list(sets)
    jobs = [(i, sets[kk][0], sets[kk][1], sets[kk][2], seed, 300) for i, kk in enumerate(keys) for seed in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for i, seed, sc, _ in out:
        per[keys[i]].append(sc)
    res = {"A_time_to_decision_paper204": {}, "B_flow_budget": {}}
    print("A. Time to decision, paper cohort (99 malware / 105 benign), BA mean +/- sd (AUC mean), 10 fold seeds")
    print("%-10s %-22s %-22s %-22s" % ("prefix", "host", "network", "hybrid"))
    for s in PREFIX_S:
        row = {}
        for det in ("host", "network", "hybrid"):
            ba = [x["ba"] for x in per[(s, det)]]; auc = [x["auc"] for x in per[(s, det)]]
            row[det] = {"ba": ch.summary(ba), "auc": ch.summary(auc)}
        res["A_time_to_decision_paper204"]["%ds" % s] = row
        print("%-10s %-22s %-22s %-22s" % ("%d s" % s, *["%.3f +/- %.3f (%.3f)" % (row[d]["ba"]["mean"], row[d]["ba"]["sd"], row[d]["auc"]["mean"])
                                                   for d in ("host", "network", "hybrid")]))

    # B. flows per window
    rows = list(csv.DictReader(open(ch.REL + "/dataset/features.csv")))
    bycat = defaultdict(list)
    for r in rows:
        bycat[r["category"]].append(float(r["net_flow_count_seen__max"]))
    print("\nB. Active flows in the busiest 0.5-s window of each run (features.csv net_flow_count_seen__max)")
    for cat, v in bycat.items():
        v = np.array(v); q = np.percentile(v, [50, 90, 100])
        res["B_flow_budget"][cat] = {"n": len(v), "median": float(q[0]), "p90": float(q[1]), "max": float(q[2])}
        print("   %-16s n=%3d  median %6.0f  p90 %6.0f  max %6.0f" % (cat, len(v), *q))
    per_window = np.concatenate([c["N"][:, ng] for c in paper])
    netben = [c for c in paper if c["y"] == 0 and c["N"][:, ng].any()]
    res["B_flow_budget"]["paper_all_windows"] = {"windows": int(len(per_window)), "p99": float(np.percentile(per_window, 99)),
                                                 "max": float(per_window.max()),
                                                 "network_active_benign_runs": len(netben)}
    print("   paper cohort, all %d windows: p99 %.0f, max %.0f active flows per 0.5-s window" % (len(per_window), np.percentile(per_window, 99), per_window.max()))
    print("\n   Switch reader capacity per window at 80%% duty: flows = 0.8 * window / cost")
    cap = {}
    for w in (0.5, 1, 2, 4, 10):
        cap["%gs" % w] = {"at_1.14ms": int(0.8 * w / 0.00114), "at_1.40ms": int(0.8 * w / 0.0014)}
        print("   window %4g s: %6d flows (1.14 ms sync+shadow)  %6d flows (1.40 ms per-cell)" % (w, cap["%gs" % w]["at_1.14ms"], cap["%gs" % w]["at_1.40ms"]))
    res["B_flow_budget"]["reader_capacity_80pct_duty"] = cap
    res["B_flow_budget"]["timestamp_wrap_s"] = 4.294967296
    json.dump(res, open(OUT, "w"), indent=2, default=float)
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
