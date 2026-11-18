"""Add the 10-s point to the final observation-length sweep (length_sweep.py --real), same cohort and protocol.

Scores the FINAL cohort (102 malware / 160 benign, 27 benign projects; V3 of rescore_with_bursty.py) cut at
10 s (20 windows) and, as a reproduction check, at 20 s (40 windows), which must equal length_sweep_real.json.
Whole malware families / benign projects held out, StratifiedGroupKFold(5), RF300 balanced, threshold 0.5,
fold seeds 42 + 0-8. Host = ADFA 18 x 5, network = P4 29 x 5, hybrid = both. Offline; no VM; no merge.
length_sweep.py and its outputs are left unchanged.
Run: nice -n 19 /usr/bin/python3 length_sweep_10s.py
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
import timing_control as tc                # noqa: E402
import rescore_with_bursty as rb           # noqa: E402
import estimate_with_paper_short as est    # noqa: E402

LENGTHS = [(20, "10 s"), (40, "20 s")]
DETS = ("host", "network", "hybrid", "host (shape view)", "network (shape view)",
        "hybrid (shape view, pre-registered)", "baseline: windows with any activity")


def main():
    host, net = tc.signals()
    cases, new_ok, new_bad, have_report = rb.load_all(host, net)
    if not have_report:
        raise SystemExit("behaviour-check report missing")
    v1 = [c for c in cases if not c["src"].startswith("new-") and not c["broken"]]
    cs = est.cap_dense(v1 + [c for c in cases if c["src"].startswith("new-")])
    hg = host.index("host_total_syscalls_total")
    ng = net.index("net_pkts_total_delta")
    y = np.array([c["y"] for c in cs]); g = np.array([c["group_proj"] for c in cs])
    sets = {}
    for k, lab in LENGTHS:
        Hf = np.array([ch.summ(c["H"], k) for c in cs]); Nf = np.array([ch.summ(c["N"], k) for c in cs])
        Hs = np.array([tc.shape(c["H"], k, hg) for c in cs]); Ns = np.array([tc.shape(c["N"], k, ng) for c in cs])
        sets[(lab, "host")] = Hf
        sets[(lab, "network")] = Nf
        sets[(lab, "hybrid")] = np.hstack([Hf, Nf])
        sets[(lab, "host (shape view)")] = Hs
        sets[(lab, "network (shape view)")] = Ns
        sets[(lab, "hybrid (shape view, pre-registered)")] = np.hstack([Hs, Ns])
        sets[(lab, "baseline: windows with any activity")] = Hf[:, [hg * 5 + 4]]
    keys = list(sets)
    jobs = [(i, sets[kk], y, g, s, 300) for i, kk in enumerate(keys) for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for i, seed, sc, _ in out:
        per[keys[i]].append(sc)
    res = {"label": "FINAL cohort, 10-s point (+ 20-s reproduction check)",
           "cohort": {"malware": int(y.sum()), "benign": int((y == 0).sum()),
                      "benign_projects": len({c["group_proj"] for c in cs if c["y"] == 0}),
                      "new_benign_used": new_ok, "new_benign_excluded": len(new_bad)},
           "lengths": [lab for _, lab in LENGTHS], "scores": {}}
    ref = json.load(open(HERE + "/length_sweep_real.json"))["scores"]
    worst = 0.0
    print(res["label"], res["cohort"])
    print("%-38s" % "" + "".join("%17s" % lab for _, lab in LENGTHS))
    for det in DETS:
        cells = []
        for _, lab in LENGTHS:
            sc = per[(lab, det)]
            ba = [s["ba"] for s in sc]; auc = [s["auc"] for s in sc]
            res["scores"]["final|%s|%s" % (lab, det)] = {"ba": ch.summary(ba), "auc": ch.summary(auc)}
            if lab == "20 s":
                r = ref["final|20 s|%s" % det]
                worst = max(worst, abs(r["ba"]["mean"] - float(np.mean(ba))), abs(r["auc"]["mean"] - float(np.mean(auc))))
            cells.append("%17s" % ("%.3f±%.3f (%.3f)" % (np.mean(ba), np.std(ba, ddof=1), np.mean(auc))))
        print("%-38s" % det + "".join(cells))
    res["check_20s_max_abs_diff_vs_length_sweep_real"] = worst
    print("20-s reproduction: max |diff| vs length_sweep_real.json = %.2e" % worst)
    out_path = HERE + "/length_sweep_real_10s.json"
    json.dump(res, open(out_path, "w"), indent=2, default=float)
    print("saved", out_path)


if __name__ == "__main__":
    main()
