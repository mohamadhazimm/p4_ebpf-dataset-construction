"""The Sink outage, second check: drop the affected runs instead of swapping them.

server_outage_swap.py replaces, at 20 s, the 29 outage-affected runs of the final cohort that have a twin in the
paper's collection. It cannot cover the other 11 (5 busy wget runs, 3 sparse wget jobs and 3 sparse lowrate_gen
jobs, which have no twin) nor the 5-min prefix (no 5-min twin exists). Five of those 11 changed most: the busy
wget runs cycle through a URL list, and against the down server every request was refused at its first packet, so
each opened 200,000-500,000 connections in 5 min where the same program opened about 33,600 answered ones with the
server up (final_cohort_server_state.json). This scores the final cohort (V3 of rescore_with_bursty.py, as
server_outage_swap.py) in three versions:
  as_collected            the cohort as collected; must reproduce length_sweep_real.json (checked)
  affected_removed        without the 40 runs that used the network while the server was down (36 benign, 4 malware),
                          at every length of the length sweep (20 s, 40 s, 1, 3 and 5 min)
  swapped_rest_removed    20 s only: the 29 with a twin replaced by it, the 11 without one removed
with the same protocol (StratifiedGroupKFold(5) over malware families / benign projects, RF300 balanced, threshold
0.5, the 10 fold seeds of compare_host.py): host / network / hybrid, five-statistics and shape views, and the
lifetime baseline. It also records, as collected, which runs the two hybrids flag. Removal changes the cohort (whole
benign projects can disappear), so it bounds the effect from the other side; it is not a corrected result.
Offline; no VM; no merge.   Run: nice -n 19 /usr/bin/python3 server_outage_drop.py
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

OUT = HERE + "/server_outage_drop.json"
SWEEP = HERE + "/length_sweep_real.json"
LABEL = {40: "20 s", 80: "40 s", 120: "1 min", 360: "3 min", 600: "5 min"}
DETS = ("host", "network", "hybrid", "host (shape view)", "network (shape view)",
        "hybrid (shape view, pre-registered)", "baseline: windows with any activity")   # names as length_sweep.py


def feature_sets(cs, k, hg, ng, source=None):
    """The seven detector inputs of length_sweep.py on the first k windows; source maps a sample to a replacement."""
    runs = [(source or {}).get(c["sample"], c) for c in cs]
    Hf = np.array([ch.summ(r["H"], k) for r in runs]); Nf = np.array([ch.summ(r["N"], k) for r in runs])
    Hs = np.array([tc.shape(r["H"], k, hg) for r in runs]); Ns = np.array([tc.shape(r["N"], k, ng) for r in runs])
    return dict(zip(DETS, (Hf, Nf, np.hstack([Hf, Nf]), Hs, Ns, np.hstack([Hs, Ns]), Hf[:, [hg * 5 + 4]])))


def main():
    host, net = tc.signals()
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")   # as length_sweep.py
    cases, *_ = rb.load_all(host, net)
    v3 = rb.cohorts(cases)["V3"]
    state = {x["sample"]: x for x in json.load(open(HERE + "/final_cohort_server_state.json"))}
    paper = {c["sample"]: c for c in pv.load_paper(host, net)}
    label_of = {c["sample"]: c["y"] for c in v3}
    affected = {c["sample"] for c in v3 if state[c["sample"]]["server"] == "rst" and state[c["sample"]]["network_active"]}
    twin = {s: paper[s] for s in affected if s in paper and paper[s]["y"] == label_of[s]}
    kept = [c for c in v3 if c["sample"] not in affected]
    swap_keep = [c for c in v3 if c["sample"] not in affected or c["sample"] in twin]
    versions = [("as_collected", v3, None, (40, 600)), ("affected_removed", kept, None, tuple(LABEL)),
                ("swapped_rest_removed", swap_keep, twin, (40,))]
    sets, cohorts = {}, {}
    for name, cs, source, lengths in versions:
        y = np.array([c["y"] for c in cs]); g = np.array([c["group_proj"] for c in cs])
        cohorts[name] = {"malware": int(y.sum()), "benign": int((y == 0).sum()),
                         "malware_families": len({x for x, yy in zip(g, y) if yy == 1}),
                         "benign_projects": len({x for x, yy in zip(g, y) if yy == 0})}
        for k in lengths:
            for det, X in feature_sets(cs, k, hg, ng, source).items():
                sets["%s|%s|%s" % (name, LABEL[k], det)] = (X, y, g)
    jobs = [(n, X, yy, gg, s, 300) for n, (X, yy, gg) in sets.items() for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per, probs = defaultdict(list), defaultdict(list)
    for n, _seed, sc, p in out:
        per[n].append(sc)
        probs[n].append(np.asarray(p))
    scores = {n: {"ba": ch.summary([s["ba"] for s in per[n]]), "auc": ch.summary([s["auc"] for s in per[n]])} for n in sets}
    # consistency check: the as-collected scores must equal the final length sweep's (same cohort, seeds and models)
    sweep = json.load(open(SWEEP))["scores"]
    check = {n: all(abs(scores[n][m][s] - sweep["final|" + n.split("|", 1)[1]][m][s]) < 1e-12
                    for m in ("ba", "auc") for s in ("mean", "sd"))
             for n in scores if n.startswith("as_collected|")}

    # which runs the two hybrids flag, as collected: share of the 10 assignments that flag each run, mean per group
    def category(c):
        if c["y"] == 1:
            return "malware, server down" if c["sample"] in affected else "malware, other"
        if c["sample"] in affected:
            return {"new-sparse": "sparse job, server down", "new-short": "short task, server down"}.get(
                c["src"], "busy wget, server down")
        if c["src"].startswith("old-") and c["program"] == "wget":
            return "busy wget, server up"
        return "benign, other"
    cats = [category(c) for c in v3]
    flags = {}
    for k in (40, 600):
        for det in ("hybrid", "hybrid (shape view, pre-registered)"):
            n = "as_collected|%s|%s" % (LABEL[k], det)
            rate = (np.array(probs[n]) >= 0.5).mean(0)
            flags[n] = {cat: {"runs": cats.count(cat), "share_flagged": float(np.mean([r for r, cc in zip(rate, cats)
                                                                                        if cc == cat]))}
                        for cat in sorted(set(cats))}
    res = {"note": __doc__.split("\n")[0], "affected": sorted(affected),
           "affected_with_paper_twin": sorted(twin), "affected_without_twin": sorted(affected - set(twin)),
           "cohorts": cohorts, "scores": scores, "as_collected_reproduces_length_sweep_real": check,
           "as_collected_share_flagged_by_group": flags}
    json.dump(res, open(OUT, "w"), indent=1)
    print("cohorts:", json.dumps(cohorts))
    print("affected %d (with a paper twin %d, without %d)" % (len(affected), len(twin), len(affected - set(twin))))
    print("\nBA mean +/- sd (AUC)                         as collected           affected removed       swapped + rest removed")
    for k in (40, 600):
        for det in DETS:
            row = []
            for name in ("as_collected", "affected_removed", "swapped_rest_removed"):
                key = "%s|%s|%s" % (name, LABEL[k], det)
                row.append("%.3f +/- %.3f (%.3f)" % (scores[key]["ba"]["mean"], scores[key]["ba"]["sd"],
                                                    scores[key]["auc"]["mean"]) if key in scores else "-")
            print("  %-5s %-38s %-22s %-22s %s" % (LABEL[k], det, *row))
    print("\naffected removed, every length: BA mean +/- sd (AUC)")
    print("%-38s" % "" + "".join("%20s" % LABEL[k] for k in LABEL))
    for det in DETS:
        print("%-38s" % det + "".join("%20s" % ("%.3f±%.3f (%.3f)" % (
            scores["affected_removed|%s|%s" % (LABEL[k], det)]["ba"]["mean"],
            scores["affected_removed|%s|%s" % (LABEL[k], det)]["ba"]["sd"],
            scores["affected_removed|%s|%s" % (LABEL[k], det)]["auc"]["mean"])) for k in LABEL))
    print("\nas collected, share of the 10 assignments that flag a run (mean per group):")
    for n, f in flags.items():
        print("  %-48s %s" % (n, "; ".join("%s (%d) %.2f" % (cat, v["runs"], v["share_flagged"]) for cat, v in f.items())))
    print("\nas-collected reproduces length_sweep_real.json:", all(check.values()), "(%d checks)" % len(check))
    print("saved", OUT)


if __name__ == "__main__":
    main()
