"""How much does the Sink outage move the final 5-min cohort's scores? A swap at 20 s.

The lab's emulated internet server stopped answering between 2026-11-06 15:27Z and 16:02Z (sink_status.py): in
the final cohort (V3 of rescore_with_bursty.py) 36 benign and 4 malware runs used the network while it was down
(final_cohort_server_state.json), against 5 benign and 20 malware that used it while it worked. The paper's
collection (2026-10-25, server up) holds a twin of most of these runs: the same task (benign) or the same sample
(malware), with the same transport, arguments and fixtures. At 20 s (the first 40 windows of the 5-min runs, the
paper's 40 windows of its runs) the affected runs that have a twin are replaced by it, and both versions are
scored with the same protocol (StratifiedGroupKFold(5) over malware families / benign projects, RF300 balanced,
0.5, 10 fold seeds): host / network / hybrid, full and shape views. Runs without a twin stay as they are.
Offline; no VM; no merge.   Run: nice -n 19 /usr/bin/python3 server_outage_swap.py
"""
import json
import sys
from collections import defaultdict
from multiprocessing import Pool

import numpy as np

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch          # noqa: E402
import paper_vs_5min as pv         # noqa: E402
import rescore_with_bursty as rb   # noqa: E402
import timing_control as tc        # noqa: E402

OUT = HERE + "/server_outage_swap.json"


def main():
    host, net = tc.signals()
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")   # as length_sweep.py
    cases, *_ = rb.load_all(host, net)
    v3 = rb.cohorts(cases)["V3"]
    state = {x["sample"]: x for x in json.load(open(HERE + "/final_cohort_server_state.json"))}
    paper = {c["sample"]: c for c in pv.load_paper(host, net)}
    affected = [c for c in v3 if state[c["sample"]]["server"] == "rst" and state[c["sample"]]["network_active"]]
    twins = [c for c in affected if c["sample"] in paper and paper[c["sample"]]["y"] == c["y"]]
    y = np.array([c["y"] for c in v3]); g = np.array([c["group_proj"] for c in v3])
    sets = {}
    for version in ("as_collected", "affected_swapped"):
        H, N = [], []
        for c in v3:
            src = paper[c["sample"]] if (version == "affected_swapped" and c in twins) else c
            H.append(src["H"][:40]); N.append(src["N"][:40])
        Hf = np.array([ch.summ(h, 40) for h in H]); Nf = np.array([ch.summ(n, 40) for n in N])
        Hs = np.array([tc.shape(h, 40, hg) for h in H]); Ns = np.array([tc.shape(n, 40, ng) for n in N])
        for view, (Hx, Nx) in (("full", (Hf, Nf)), ("shape", (Hs, Ns))):
            sets["%s|%s|host" % (version, view)] = (Hx, y, g)
            sets["%s|%s|network" % (version, view)] = (Nx, y, g)
            sets["%s|%s|hybrid" % (version, view)] = (np.hstack([Hx, Nx]), y, g)
    jobs = [(n, X, yy, gg, s, 300) for n, (X, yy, gg) in sets.items() for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for n, _seed, sc, _ in out:
        per[n].append(sc)
    res = {"cohort": "V3: %d malware / %d benign" % (int(y.sum()), int((y == 0).sum())),
           "affected": {"benign": sum(1 for c in affected if c["y"] == 0), "malware": sum(1 for c in affected if c["y"] == 1)},
           "swapped_for_their_paper_twin": {"benign": sum(1 for c in twins if c["y"] == 0),
                                            "malware": sum(1 for c in twins if c["y"] == 1)},
           "not_swapped_no_twin": sorted(c["sample"] for c in affected if c not in twins),
           "scores_20s": {n: {"ba": ch.summary([s["ba"] for s in per[n]]), "auc": ch.summary([s["auc"] for s in per[n]])}
                          for n in sets}}
    json.dump(res, open(OUT, "w"), indent=1)
    print(res["cohort"], "| affected", res["affected"], "| swapped for their paper twin", res["swapped_for_their_paper_twin"],
          "| no twin:", len(res["not_swapped_no_twin"]))
    print("20 s, BA mean +/- sd (AUC)      as collected             affected runs swapped")
    for view in ("full", "shape"):
        for det in ("host", "network", "hybrid"):
            a, b = res["scores_20s"]["as_collected|%s|%s" % (view, det)], res["scores_20s"]["affected_swapped|%s|%s" % (view, det)]
            print("  %-5s %-8s   %.3f +/- %.3f (%.3f)    %.3f +/- %.3f (%.3f)" % (view, det, a["ba"]["mean"], a["ba"]["sd"],
                  a["auc"]["mean"], b["ba"]["mean"], b["ba"]["sd"], b["auc"]["mean"]))
    print("saved", OUT)


if __name__ == "__main__":
    main()
