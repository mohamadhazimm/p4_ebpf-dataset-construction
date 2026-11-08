"""Is the collection batch visible in the features? The same programs measured in different batches.

The final 5-min cohort was collected in several batches, and most of its benign runs come from benign-only
batches (the batch alone separates the classes: final_baselines.py). If the batch changed what the sensors
record, the detectors could learn the batch instead of the behaviour. Two checks:

 A  the paper's 105 benign tasks, measured twice: in the paper's collection (2026-10-25, 20 s, interleaved with
    malware, revision5) and in the benign-only 5-min batches (2026-11-07, benign-bursty / benign-rest: the same
    transports, arguments and fixtures). The first 20 s of the 5-min run against the paper run, per task: host
    system calls, network packets, the 235 summary features (ADFA 18 x 5 + P4 29 x 5, as compare_host.py),
    and the exit code.
 B  the null controls of every batch (the same no-op program): their features across batches.
Together with the same-malware-twice check of paper_vs_5min.py (S4), A shows whether a program's features depend
on the batch. Offline; no VM; no merge.   Run: nice -n 19 /usr/bin/python3 same_benign_twice.py
"""
import csv
import glob
import json
import sys
from collections import Counter, defaultdict

import numpy as np
from scipy.stats import spearmanr

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch          # noqa: E402
import paper_vs_5min as pv         # noqa: E402
import rescore_with_bursty as rb   # noqa: E402
import timing_control as tc        # noqa: E402

OUT = HERE + "/same_benign_twice.json"


def null_runs(host, net):
    """Every accepted null run of the 5-min batches and of the paper collection: (batch, H, N)."""
    out = []
    atts = [(tag, ch.PROJ + "/" + rel) for tag, rel, _ in ch.ATT] + \
           [(a.rstrip("/").rsplit("/", 2)[-2], a) for a in rb.NEW_ATTEMPTS] + [("paper", pv.R5)]
    for tag, att in atts:
        meta = {c["sample"]: c for c in json.load(open(att + "/protocol.json"))["cases"]} \
            if glob.glob(att + "/protocol.json") else {c["sample"]: c for c in json.load(open(att + "/payload/cases.json"))}
        for rj in sorted(glob.glob(att + "/runs/*/output/run_*/run.json")):
            sample = rj.split("/runs/")[1].split("/")[0]
            c = meta.get(sample, {})
            if c.get("label") != "null" and not sample.startswith("null"):
                continue
            d = json.load(open(rj))
            if d.get("collection_quality_status") != "accepted":
                continue
            tel = list(csv.DictReader(open(rj.rsplit("/", 1)[0] + "/telemetry.csv")))
            out.append((tag, sample, np.array([[float(t[s]) for s in host] for t in tel]),
                        np.array([[float(t[s]) for s in net] for t in tel])))
    return out


def main():
    host, net = tc.signals()
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta") \
        if "net_pkts_total_delta" in net else 0
    paper = {c["sample"]: c for c in pv.load_paper(host, net) if c["y"] == 0}
    cases, _, _, _ = rb.load_all(host, net)
    new = {c["sample"]: c for c in cases if c["src"] == "new-short"}
    shared = sorted(set(paper) & set(new))
    res = {"A_tasks_measured_twice": {"n": len(shared), "paper_benign": len(paper), "new_short": len(new)}}
    P = np.array([np.r_[ch.summ(paper[s]["H"], 40), ch.summ(paper[s]["N"], 40)] for s in shared])
    F = np.array([np.r_[ch.summ(new[s]["H"], 40), ch.summ(new[s]["N"], 40)] for s in shared])
    rho = []
    for j in range(P.shape[1]):
        if np.ptp(P[:, j]) > 0 and np.ptp(F[:, j]) > 0:
            rho.append((j, float(spearmanr(P[:, j], F[:, j])[0])))
    hr = np.array([r for j, r in rho if j < 90]); nr = np.array([r for j, r in rho if j >= 90])
    tp = np.array([paper[s]["H"][:, hg].sum() for s in shared])
    tf = np.array([new[s]["H"][:40, hg].sum() for s in shared])
    netp = np.array([bool((paper[s]["N"] != 0).any()) for s in shared])
    netf = np.array([bool((new[s]["N"][:40] != 0).any()) for s in shared])
    rc_same = sum(1 for s in shared if str(paper[s].get("rc")) == str(new[s].get("rc")))
    identical = sum(1 for k, s in enumerate(shared) if np.array_equal(P[k], F[k]))
    after20 = sum(1 for s in shared if (new[s]["H"][40:, hg] != 0).any() or (new[s]["N"][40:] != 0).any())
    ratio = tf / np.maximum(tp, 1)
    res["A_tasks_measured_twice"].update({
        "features_compared": len(rho),
        "spearman_host": {"median": float(np.median(hr)), "min": float(hr.min()), "share_ge_0.8": float((hr >= .8).mean())},
        "spearman_network": {"median": float(np.median(nr)) if len(nr) else None,
                             "min": float(nr.min()) if len(nr) else None,
                             "share_ge_0.8": float((nr >= .8).mean()) if len(nr) else None},
        "total_syscalls": {"spearman": float(spearmanr(tp, tf)[0]), "within_2x": float(((ratio >= .5) & (ratio <= 2)).mean()),
                           "exactly_equal": int((tp == tf).sum()), "median_ratio": float(np.median(ratio))},
        "network_presence_agreement": float((netp == netf).mean()), "network_active_paper": int(netp.sum()),
        "exit_code_equal": rc_same, "feature_vectors_identical": identical,
        "active_after_20s_in_the_5min_run": after20})
    nulls = null_runs(host, net)
    by = defaultdict(list)
    for tag, _s, H, N in nulls:
        by[tag].append((int(H[:, hg].sum()), int((H[:, hg] != 0).sum()), int((N != 0).any())))
    res["B_nulls_by_batch"] = {tag: {"runs": len(v), "post_launch_syscalls": sorted(Counter(x[0] for x in v).items()),
                                     "active_windows": sorted(Counter(x[1] for x in v).items()),
                                     "with_network": sum(x[2] for x in v)} for tag, v in sorted(by.items())}
    json.dump(res, open(OUT, "w"), indent=1)
    a = res["A_tasks_measured_twice"]
    print("A. the paper's benign tasks measured twice: %d tasks (paper 2026-10-25, mixed batch, 20 s; again "
          "2026-11-07, benign-only batch, first 20 s of 5 min)" % a["n"])
    print("   per-feature Spearman: host median %.3f (min %.3f, %.0f%% >= 0.8) | network median %s (%s >= 0.8) over %d features"
          % (a["spearman_host"]["median"], a["spearman_host"]["min"], 100 * a["spearman_host"]["share_ge_0.8"],
             "%.3f" % a["spearman_network"]["median"] if a["spearman_network"]["median"] is not None else "-",
             "%.0f%%" % (100 * a["spearman_network"]["share_ge_0.8"]) if a["spearman_network"]["share_ge_0.8"] is not None else "-",
             a["features_compared"]))
    print("   total system calls in the first 20 s: Spearman %.3f, %d of %d exactly equal, %.0f%% within 2x, median ratio %.3f"
          % (a["total_syscalls"]["spearman"], a["total_syscalls"]["exactly_equal"], a["n"],
             100 * a["total_syscalls"]["within_2x"], a["total_syscalls"]["median_ratio"]))
    print("   network presence agrees in %.0f%% (%d network-active in the paper); exit code equal in %d of %d; "
          "feature vectors identical in %d; active after 20 s in the 5-min run: %d"
          % (100 * a["network_presence_agreement"], a["network_active_paper"], a["exit_code_equal"], a["n"],
             a["feature_vectors_identical"], a["active_after_20s_in_the_5min_run"]))
    print("B. null controls by batch (post-launch system calls over the run, active windows, runs with network):")
    for tag, v in res["B_nulls_by_batch"].items():
        print("   %-28s %d runs  calls %s  windows %s  network %d" % (tag, v["runs"], v["post_launch_syscalls"],
                                                                   v["active_windows"], v["with_network"]))
    print("saved", OUT)


if __name__ == "__main__":
    main()
