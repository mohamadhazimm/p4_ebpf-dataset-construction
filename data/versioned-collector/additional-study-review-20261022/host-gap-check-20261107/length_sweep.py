"""Average score of the 5-min dataset at 20 s / 40 s / 1 min / 3 min / 5 min (the same runs, cut at each length).

  default  ESTIMATE: 5-min malware (102) + the working old benign + the 43 planned short tasks SIMULATED from their
           20 s captures (+ zeros), always-busy programs (rsync, wget) capped at 10 old runs  (= S43cap)
  --real   FINAL: the same but with the REAL bursty/short runs (only those the behaviour check marks as_designed),
           sparse periodic jobs included (= V3 of rescore_with_bursty.py)
Also the old cohort (working benign only, no short tasks) for reference. Whole malware families / benign projects
held out, StratifiedGroupKFold(5), RF300 balanced, threshold 0.5, fold seeds 42 + 0-8. Host = ADFA 18 x 5,
network = P4 29 x 5, hybrid = both. Offline; no VM; no merge.
Run: nice -n 19 /usr/bin/python3 length_sweep.py [--real]
"""
import argparse
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
import build_benign_bursty_payload as bbp  # noqa: E402

LENGTHS = [(40, "20 s"), (80, "40 s"), (120, "1 min"), (360, "3 min"), (600, "5 min")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true")
    a = ap.parse_args()
    host, net = tc.signals()
    cases, new_ok, new_bad, have_report = rb.load_all(host, net)
    v1 = [c for c in cases if not c["src"].startswith("new-") and not c["broken"]]
    if a.real:
        if not have_report:
            raise SystemExit("run collect_benign_bursty.py --behavior-check first")
        final = est.cap_dense(v1 + [c for c in cases if c["src"].startswith("new-")])
        label = "FINAL (real runs: %d new benign used, %d excluded)" % (new_ok, len(new_bad))
    else:
        sim, _ = est.load_paper_benign(host, net)
        planned = {c["sample"] for c in bbp.select_short()}
        final = est.cap_dense(v1 + [c for c in sim if c["sample"] in planned])
        label = "ESTIMATE (43 short tasks simulated; 15 sparse jobs not yet included)"
    hg = host.index("host_total_syscalls_total")
    cohorts = {"final": final, "old": v1}
    sets = {}
    for cname, cs in cohorts.items():
        y = np.array([c["y"] for c in cs]); g = np.array([c["group_proj"] for c in cs])
        ng = net.index("net_pkts_total_delta")
        for k, lab in LENGTHS:
            Hf = np.array([ch.summ(c["H"], k) for c in cs]); Nf = np.array([ch.summ(c["N"], k) for c in cs])
            Hs = np.array([tc.shape(c["H"], k, hg) for c in cs]); Ns = np.array([tc.shape(c["N"], k, ng) for c in cs])
            sets[(cname, lab, "host")] = (Hf, y, g)
            sets[(cname, lab, "network")] = (Nf, y, g)
            sets[(cname, lab, "hybrid")] = (np.hstack([Hf, Nf]), y, g)
            sets[(cname, lab, "host (shape view)")] = (Hs, y, g)
            sets[(cname, lab, "network (shape view)")] = (Ns, y, g)
            sets[(cname, lab, "hybrid (shape view, pre-registered)")] = (np.hstack([Hs, Ns]), y, g)
            sets[(cname, lab, "baseline: windows with any activity")] = (Hf[:, [hg * 5 + 4]], y, g)
    keys = list(sets)
    jobs = [(i, sets[kk][0], sets[kk][1], sets[kk][2], s, 300) for i, kk in enumerate(keys) for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for i, seed, sc, _ in out:
        per[keys[i]].append(sc)
    res = {"label": label, "lengths": [lab for _, lab in LENGTHS], "cohorts": {}, "scores": {}}
    for cname, cs in cohorts.items():
        y = np.array([c["y"] for c in cs])
        res["cohorts"][cname] = {"malware": int(y.sum()), "benign": int((y == 0).sum()),
                                 "benign_projects": len({c["group_proj"] for c in cs if c["y"] == 0})}
    print(label)
    for cname in cohorts:
        m = res["cohorts"][cname]
        print("\n[%s cohort: %d malware / %d benign, %d benign projects]  balanced accuracy mean +/- sd (AUC mean)"
              % (cname, m["malware"], m["benign"], m["benign_projects"]))
        print("%-38s" % "" + "".join("%17s" % lab for _, lab in LENGTHS))
        for det in ("host", "network", "hybrid", "host (shape view)", "network (shape view)",
                    "hybrid (shape view, pre-registered)", "baseline: windows with any activity"):
            cells = []
            for _, lab in LENGTHS:
                sc = per[(cname, lab, det)]
                ba = [s["ba"] for s in sc]; auc = [s["auc"] for s in sc]
                res["scores"]["%s|%s|%s" % (cname, lab, det)] = {"ba": ch.summary(ba), "auc": ch.summary(auc)}
                cells.append("%17s" % ("%.2f±%.2f (%.2f)" % (np.mean(ba), np.std(ba, ddof=1), np.mean(auc))))
            print("%-38s" % det + "".join(cells))
    out_path = ch.PROJ + "/host-gap-check-20261107/length_sweep%s.json" % ("_real" if a.real else "_estimate")
    json.dump(res, open(out_path, "w"), indent=2, default=float)
    print("\nsaved", out_path)


if __name__ == "__main__":
    main()
