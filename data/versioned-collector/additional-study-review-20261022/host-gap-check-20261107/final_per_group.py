"""Where the final 5-min detectors err: false alarms per benign project and kind, recall per malware family.

Final cohort exactly as length_sweep.py --real builds it (102 malware / 160 benign, 27 benign projects); the
pre-registered design (shape view, concatenated, 0.5) and the thesis's design (five statistics, concatenated,
0.5); 20 s and 5 min; the same protocol (StratifiedGroupKFold(5) over malware families / benign projects, RF300
balanced, the 10 fold seeds of compare_host.py). Each run's out-of-fold decision in each of the 10 assignments is
counted: rates below are over runs x assignments. Benign kinds: "short" = the thesis's own tasks, "sparse" = the
periodic jobs, "busy" = the always-busy 5-min programs (rsync, wget, ping, free, vmstat, hostgen).
Offline; no VM; no merge.   Run: nice -n 19 /usr/bin/python3 final_per_group.py
"""
import json
import sys
from collections import defaultdict
from multiprocessing import Pool

import numpy as np

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch                  # noqa: E402
import estimate_with_paper_short as est    # noqa: E402
import rescore_with_bursty as rb           # noqa: E402
import timing_control as tc                # noqa: E402

OUT = HERE + "/final_per_group.json"


def kind(c):
    if c["src"] == "new-short":
        return "short"
    if c["src"] == "new-sparse":
        return "sparse"
    return "busy" if c["y"] == 0 else "malware"


def main():
    host, net = tc.signals()
    cases, new_ok, new_bad, _ = rb.load_all(host, net)
    v1 = [c for c in cases if not c["src"].startswith("new-") and not c["broken"]]
    cs = est.cap_dense(v1 + [c for c in cases if c["src"].startswith("new-")])
    y = np.array([c["y"] for c in cs]); g = np.array([c["group_proj"] for c in cs])
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    sets = {}
    for k, lab in ((40, "20 s"), (600, "5 min")):
        Hf = np.array([ch.summ(c["H"], k) for c in cs]); Nf = np.array([ch.summ(c["N"], k) for c in cs])
        Hs = np.array([tc.shape(c["H"], k, hg) for c in cs]); Ns = np.array([tc.shape(c["N"], k, ng) for c in cs])
        sets[(lab, "pre-registered (shape, concatenated)")] = np.hstack([Hs, Ns])
        sets[(lab, "thesis design (five statistics, concatenated)")] = np.hstack([Hf, Nf])
    keys = list(sets)
    jobs = [(i, sets[kk], y, g, s, 300) for i, kk in enumerate(keys) for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    flags = defaultdict(list)          # design -> list over seeds of the 0/1 decision vector
    scores = defaultdict(list)
    for i, _seed, sc, p in out:
        flags[keys[i]].append((np.asarray(p) >= 0.5).astype(int))
        scores[keys[i]].append(sc)
    res = {"cohort": {"malware": int(y.sum()), "benign": int((y == 0).sum()),
                      "benign_projects": len({c["group_proj"] for c in cs if c["y"] == 0}),
                      "benign_by_kind": {kd: sum(1 for c in cs if c["y"] == 0 and kind(c) == kd)
                                         for kd in ("short", "sparse", "busy")}},
           "designs": {}}
    for kk in keys:
        F = np.array(flags[kk])                       # seeds x runs
        rate = F.mean(0)                              # per run: share of the 10 assignments that flag it
        by_proj, by_kind, by_fam, by_prog = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
        for r, c in zip(rate, cs):
            if c["y"] == 0:
                by_proj[c["group_proj"][5:]].append(r); by_kind[kind(c)].append(r)
                by_prog[c["program"]].append(r)
            else:
                by_fam[c["group_proj"][4:]].append(r)
        sc = scores[kk]
        res["designs"]["%s | %s" % kk] = {
            "ba": ch.summary([s["ba"] for s in sc]), "auc": ch.summary([s["auc"] for s in sc]),
            "confusion_summed_over_10": {k: int(sum(s[k] for s in sc)) for k in ("tn", "fp", "fn", "tp")},
            "false_alarm_rate_by_kind": {k: {"runs": len(v), "rate": float(np.mean(v))} for k, v in sorted(by_kind.items())},
            "false_alarm_rate_by_project": {k: {"runs": len(v), "rate": float(np.mean(v))}
                                            for k, v in sorted(by_proj.items(), key=lambda kv: -np.mean(kv[1]))},
            "false_alarm_rate_by_program": {k: {"runs": len(v), "rate": float(np.mean(v))}
                                            for k, v in sorted(by_prog.items(), key=lambda kv: -np.mean(kv[1]))},
            "recall_by_family": {k: {"runs": len(v), "recall": float(np.mean(v))}
                                 for k, v in sorted(by_fam.items(), key=lambda kv: np.mean(kv[1]))}}
    json.dump(res, open(OUT, "w"), indent=1)
    print("cohort", res["cohort"])
    for name, d in res["designs"].items():
        cf = d["confusion_summed_over_10"]
        print("\n== %s: BA %.3f +/- %.3f (AUC %.3f); summed over 10: TN %d FP %d FN %d TP %d"
              % (name, d["ba"]["mean"], d["ba"]["sd"], d["auc"]["mean"], cf["tn"], cf["fp"], cf["fn"], cf["tp"]))
        print("   false alarms by kind:", {k: "%.0f%% of %d" % (100 * v["rate"], v["runs"]) for k, v in d["false_alarm_rate_by_kind"].items()})
        top = [(k, v) for k, v in d["false_alarm_rate_by_project"].items() if v["rate"] > 0][:10]
        print("   projects flagged (rate, runs):", ", ".join("%s %.0f%% (%d)" % (k, 100 * v["rate"], v["runs"]) for k, v in top))
        low = [(k, v) for k, v in d["recall_by_family"].items() if v["recall"] < 1][:10]
        print("   families missed (recall, runs):", ", ".join("%s %.0f%% (%d)" % (k, 100 * v["recall"], v["runs"]) for k, v in low))
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
