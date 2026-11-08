"""Where did the 5-min hybrid's 0.88 go? Per-fold-assignment balanced accuracy, one line per seed.

  A  the exact setup that produced the 0.88 (analyze_prefix loader: stored 26-column host group + P4 29, per-PROGRAM
     groups, cohort = scale malware + topup + finish + benign-expanded benign + paced wget = 102 / 102), at 1 and 5 min
  B  the same cohort with the paper's ADFA-18 host signals
  C  the one-feature lifetime baseline on the same cohort (number of windows with any system calls)
  D  the fixed-benign estimate (S43cap: broken runs removed, 43 simulated short tasks, rsync/wget capped; per-PROJECT
     groups), hybrid, at 5 min
Fold seeds 42, 0-8 (only the fold assignment changes; the forest seed stays 42). RF300 balanced, threshold 0.5.
Offline; no VM; no merge.   Run: nice -n 19 /usr/bin/python3 hybrid_seed_spread.py
"""
import sys
from multiprocessing import Pool

import numpy as np

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import analyze_prefix as ap                # noqa: E402
import compare_host as ch                  # noqa: E402
import timing_control as tc                # noqa: E402
import rescore_with_bursty as rb           # noqa: E402
import estimate_with_paper_short as est    # noqa: E402
import build_benign_bursty_payload as bbp  # noqa: E402

ATT = [("scale", "scale-5min/20261105T224558731619Z", {"malware"}),
       ("topup", "topup-5min/20261106T073625330426Z", {"malware", "benign"}),
       ("finish", "topup-5min-finish/20261106T155820346732Z", {"malware", "benign"}),
       ("benx", "benign-expanded-5min/20261106T204303086228Z", {"benign"}),
       ("wgetp", "wgetp-5min/20261107T015242522524Z", {"benign"})]


def setup_a():
    cases, seen = [], set()
    for _, rel, keep in ATT:
        cs, _, _ = ap.load_cases(ch.PROJ + "/" + rel)
        for c in cs:
            if c["label"] in keep and c["sample"] not in seen:
                seen.add(c["sample"]); cases.append(c)
    return cases


def main():
    seeds = ch.SEEDS
    a = setup_a()
    ya, ga = np.array([c["y"] for c in a]), np.array([c["group"] for c in a])
    host, net = tc.signals()
    b, _, _, _ = rb.load_all(host, net)
    b = [c for c in b if not c["src"].startswith("new-")]
    yb, gb = np.array([c["y"] for c in b]), np.array([c["group_prog"] for c in b])
    v1 = [c for c in b if not c["broken"]]
    sim, _ = est.load_paper_benign(host, net)
    planned = {c["sample"] for c in bbp.select_short()}
    d = est.cap_dense(v1 + [c for c in sim if c["sample"] in planned])
    yd, gd = np.array([c["y"] for c in d]), np.array([c["group_proj"] for c in d])
    hg = host.index("host_total_syscalls_total")
    sets = {}
    for k, lab in ((120, "1min"), (600, "5min")):
        sets["A stored-26 hybrid %s" % lab] = (np.array([np.r_[ap.agg(c["H"], k), ap.agg(c["N"], k)] for c in a]), ya, ga)
        sets["B ADFA-18 hybrid %s" % lab] = (np.array([np.r_[ch.summ(c["H"], k), ch.summ(c["N"], k)] for c in b]), yb, gb)
        sets["C lifetime only %s" % lab] = (np.array([[float((c["H"][:k, hg] != 0).sum())] for c in b]), yb, gb)
    sets["D fixed-benign hybrid 5min (estimate)"] = (np.array([np.r_[ch.summ(c["H"], 600), ch.summ(c["N"], 600)] for c in d]), yd, gd)
    jobs = [(n, X, y, g, s, 300) for n, (X, y, g) in sets.items() for s in seeds]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    print("cohort A: %d malware / %d benign | B: %d / %d | D: %d / %d" % (ya.sum(), (ya == 0).sum(), yb.sum(),
                                                                       (yb == 0).sum(), yd.sum(), (yd == 0).sum()))
    print("%-40s" % "balanced accuracy by fold seed ->" + "".join("%6d" % s for s in seeds) + "   mean   sd")
    for n in sets:
        ba = [sc["ba"] for nm, s, sc, _ in out if nm == n]
        print("%-40s" % n + "".join("%6.2f" % v for v in ba) + "   %.2f  %.2f" % (np.mean(ba), np.std(ba, ddof=1)))
    print("\nAUC (ranking) for the same runs:")
    for n in sets:
        auc = [sc["auc"] for nm, s, sc, _ in out if nm == n]
        print("%-40s" % n + "".join("%6.2f" % v for v in auc) + "   %.2f  %.2f" % (np.mean(auc), np.std(auc, ddof=1)))


if __name__ == "__main__":
    main()
