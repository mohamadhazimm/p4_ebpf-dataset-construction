"""Shortcut baselines of the FINAL real 5-min cohort (V3 of rescore_with_bursty.py: 102 malware / 160 benign,
27 benign projects; all 105 paper benign tasks as real 5-min runs, the sparse periodic jobs, the always-busy
programs capped at 10 runs each).

Same protocol as paper_vs_5min.py section S2 (StratifiedGroupKFold(5) over whole malware families and benign
projects, RF300 balanced, threshold 0.5, the 10 fold seeds of compare_host.py), at 20 s and 5 min:
  lifetime   windows with any host system call (the shortcut of the old 5-min cohort)
  activity   total host system calls (the paper's activity baseline)
  exit_code  the target's return code, one-hot (the paper's metadata baseline uses it)
  mode       execution mode (amd64 dynamic / amd64 static / i386 static), one-hot
  batch      the collection batch the run came from, one-hot. The 5-min cohort was collected in several
             batches, and most of its benign runs come from benign-only batches: this measures how well the
             batch alone separates the classes. The detectors never see it.
Offline; no VM; no merge; no promotion.   Run: nice -n 19 /usr/bin/python3 final_baselines.py
"""
import json
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

import numpy as np

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch          # noqa: E402
import rescore_with_bursty as rb   # noqa: E402
import timing_control as tc        # noqa: E402

OUT = HERE + "/final_baselines.json"


def onehot(values):
    keys = sorted({str(v) for v in values})
    return np.array([[float(str(v) == k) for k in keys] for v in values])


def modes():
    out = {}
    for _, rel, _ in ch.ATT:
        for c in json.load(open(ch.PROJ + "/" + rel + "/protocol.json"))["cases"]:
            out[c["sample"]] = c.get("mode")
    for att in rb.NEW_ATTEMPTS:
        for c in json.load(open(att + "/protocol.json"))["cases"]:
            out[c["sample"]] = c.get("mode")
    return out


def main():
    host, net = tc.signals()
    cases, new_ok, new_bad, reports = rb.load_all(host, net)
    v3 = rb.cohorts(cases)["V3"]
    md = modes()
    for c in v3:
        c["mode"] = md.get(c["sample"])
    missing = [c["sample"] for c in v3 if c["mode"] is None]
    if missing:
        raise SystemExit("no execution mode for %d runs: %s" % (len(missing), missing[:5]))
    y = np.array([c["y"] for c in v3]); g = np.array([c["group_proj"] for c in v3])
    hg = host.index("host_total_syscalls_total")
    life, tot = hg * 5 + 4, hg * 5 + 2
    comp = {lab: {"n": int((y == yv).sum()),
                  "batches": dict(Counter(c["src"] for c in v3 if c["y"] == yv)),
                  "modes": dict(Counter(c["mode"] for c in v3 if c["y"] == yv)),
                  "exit_codes_top5": Counter(str(c["rc"]) for c in v3 if c["y"] == yv).most_common(5)}
            for lab, yv in (("malware", 1), ("benign", 0))}
    sets = {}
    for k in (40, 600):
        lab = "20s" if k == 40 else "5min"
        Hf = np.array([ch.summ(c["H"], k) for c in v3])
        sets[lab + "|lifetime"] = (Hf[:, [life]], y, g)
        sets[lab + "|activity"] = (Hf[:, [tot]], y, g)
    sets["any|exit_code"] = (onehot([c["rc"] for c in v3]), y, g)
    sets["any|mode"] = (onehot([c["mode"] for c in v3]), y, g)
    sets["any|batch"] = (onehot([c["src"] for c in v3]), y, g)
    jobs = [(n, X, yy, gg, s, 300) for n, (X, yy, gg) in sets.items() for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for n, _seed, sc, _ in out:
        per[n].append(sc)
    res = {"cohort": "V3 (final): %d malware / %d benign, %d benign projects" %
                     (int(y.sum()), int((y == 0).sum()), len({c["group_proj"] for c in v3 if c["y"] == 0})),
           "new_benign_used": new_ok, "new_benign_excluded": len(new_bad), "behaviour_reports": reports,
           "composition": comp,
           "baselines": {n: {"ba": ch.summary([s["ba"] for s in per[n]]), "auc": ch.summary([s["auc"] for s in per[n]])}
                         for n in sets}}
    json.dump(res, open(OUT, "w"), indent=1, default=str)
    print(res["cohort"], "| new benign used", new_ok, "excluded", len(new_bad))
    for lab in ("malware", "benign"):
        print("  %-7s batches %s" % (lab, comp[lab]["batches"]))
        print("  %-7s modes %s | exit codes %s" % (lab, comp[lab]["modes"], comp[lab]["exit_codes_top5"]))
    print("baseline           BA mean +/- sd     AUC mean +/- sd")
    for n in sets:
        b, a = res["baselines"][n]["ba"], res["baselines"][n]["auc"]
        print("  %-16s %.3f +/- %.3f    %.3f +/- %.3f" % (n, b["mean"], b["sd"], a["mean"], a["sd"]))
    print("saved", OUT)


if __name__ == "__main__":
    main()
