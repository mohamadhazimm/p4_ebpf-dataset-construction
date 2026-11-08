"""Re-score after adding the bursty/short benign: does the lifetime shortcut go away, and what do the detectors score?

Cohorts (all .22, 5 min, 600 windows; whole groups held out: malware FAMILY / benign PROJECT):
  V0  the previous 5-min cohort (102 malware / 102 benign, incl. the 10 broken top/lowrate runs) -- reference
  V1  V0 without the 10 broken runs (top segfaulted, lowrate exited on a usage error)
  V2  V1 + the new short and sparse benign that ran as designed (collect_benign_bursty.py --behavior-check)
  V3  V2 with the always-busy programs capped at 10 old runs each (rsync, wget): benign activity mix closest to malware
Per cohort: the lifetime baseline (number of windows with any system calls), the pre-registered activity baseline
(total system calls), and host / network / hybrid on three feature views (full; no_active; shape = per-signal mean over
the windows in which that sensor saw anything), at 20 s (first 40 windows) and 5 min (600), over 10 fold seeds.
Same models and protocol as compare_host.py / timing_control.py (StratifiedGroupKFold(5), RF300 balanced, 0.5).
Benign groups are projects (procps = top/vmstat/free; inetutils = ping), stricter than the per-program groups used
earlier; every cohort is also scored with per-program groups to tie back to the earlier numbers. (V0/V1 have only
5-6 benign projects, so their project-held-out scores are degenerate -- that is a property of the old cohort.)
Offline; no VM; no merge; no promotion.   Run: nice -n 19 /usr/bin/python3 rescore_with_bursty.py [--seeds N]
"""
import argparse
import csv
import glob
import json
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

import numpy as np

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
import compare_host as ch      # noqa: E402  ATT, PROJ, summ(), job_cv(), SEEDS, summary()
import timing_control as tc    # noqa: E402  signals(), shape(), drop_active()

NEW = ch.PROJ + "/benign-bursty-5min/20261107T071120390917Z"
NEW_ATTEMPTS = [NEW, ch.PROJ + "/benign-rest-5min/20261107T080517413667Z"]   # real benign-only 5-min runs
OUT = ch.PROJ + "/host-gap-check-20261107/rescore_with_bursty.json"
PROG2PROJ = {"rsync": "rsync", "wget": "wget", "ping": "inetutils", "free": "procps", "vmstat": "procps",
             "top": "procps", "hostgen": "hostgen", "lowrate": "lowrate"}
DENSE_CAP = {"rsync": 10, "wget": 10}


def read_run(rj, host, net):
    d = json.load(open(rj))
    if d.get("collection_quality_status") != "accepted":
        return None
    tel = list(csv.DictReader(open(rj.rsplit("/", 1)[0] + "/telemetry.csv")))
    if len(tel) != 600:
        return None
    return d, np.array([[float(t[s]) for s in host] for t in tel]), np.array([[float(t[s]) for s in net] for t in tel])


def load_all(host, net):
    cases, seen = [], set()
    for tag, rel, keep in ch.ATT:                                      # the previous 5-min cohort, exactly as before
        att = ch.PROJ + "/" + rel
        meta = {c["sample"]: c for c in json.load(open(att + "/protocol.json"))["cases"]}
        for rj in sorted(glob.glob(att + "/runs/*/output/run_*/run.json")):
            sample = rj.split("/runs/")[1].split("/")[0]
            c = meta.get(sample)
            if not c or c["label"] not in keep or sample in seen:
                continue
            r = read_run(rj, host, net)
            if r is None:
                continue
            seen.add(sample)
            d, H, N = r
            prog = c.get("program") or c.get("variant")
            mal = c["label"] == "malware"
            cases.append({"sample": sample, "y": int(mal), "src": "old-" + tag, "program": prog,
                          "group_proj": ("fam:" + c["family"]) if mal else ("proj:" + PROG2PROJ[prog]),
                          "group_prog": ("fam:" + c["family"]) if mal else ("prog:" + prog),
                          "broken": (not mal) and tag == "benx" and prog in ("top", "lowrate"),
                          "rc": d.get("return_code"), "H": H, "N": N})
    new_ok, new_bad, reports_ok = 0, [], []
    for att in NEW_ATTEMPTS:                                           # each real benign-only run needs its own report
        runs = sorted(glob.glob(att + "/runs/*/output/run_*/run.json"))
        if not runs or not glob.glob(att + "/protocol.json"):
            continue
        reports = sorted(glob.glob(att + "/behavior-*.json"))
        verdict = {}
        if reports:
            for row in json.load(open(reports[-1]))["rows"]:
                verdict[row["sample"]] = row.get("behavior", row.get("status"))
        reports_ok.append(bool(reports))
        meta = {c["sample"]: c for c in json.load(open(att + "/protocol.json"))["cases"]}
        for rj in runs:
            sample = rj.split("/runs/")[1].split("/")[0]
            c = meta.get(sample)
            if not c or c["label"] != "benign":
                continue
            if not reports:
                new_bad.append((sample, "no behaviour report yet for " + att.rsplit("/", 2)[-2]))
                continue
            if verdict.get(sample) != "as_designed":
                new_bad.append((sample, verdict.get(sample)))
                continue
            r = read_run(rj, host, net)
            if r is None:
                new_bad.append((sample, "quality/windows"))
                continue
            d, H, N = r
            cases.append({"sample": sample, "y": 0, "src": "new-" + c["kind"], "program": c["program"],
                          "group_proj": "proj:" + c["project"], "group_prog": "prog:" + c["program"],
                          "broken": False, "rc": d.get("return_code"), "H": H, "N": N})
            new_ok += 1
    return cases, new_ok, new_bad, bool(reports_ok) and all(reports_ok)


def cohorts(cases):
    v0 = [c for c in cases if not c["src"].startswith("new-")]
    v1 = [c for c in v0 if not c["broken"]]
    v2 = v1 + [c for c in cases if c["src"].startswith("new-")]
    rng = np.random.default_rng(42)
    capped = []
    for prog, cap in DENSE_CAP.items():
        idx = [i for i, c in enumerate(v2) if c["y"] == 0 and c["src"].startswith("old-") and c["program"] == prog]
        keep = set(rng.choice(idx, size=min(cap, len(idx)), replace=False).tolist()) if idx else set()
        capped += [i for i in idx if i not in keep]
    v3 = [c for i, c in enumerate(v2) if i not in set(capped)]
    return {"V0": v0, "V1": v1, "V2": v2, "V3": v3}


def shape_mix(cs, gate):
    out = {}
    for lab, yv in (("malware", 1), ("benign", 0)):
        act = np.array([int((c["H"][:, gate] != 0).sum()) for c in cs if c["y"] == yv])
        first20 = np.array([int((c["H"][:40, gate] != 0).sum()) for c in cs if c["y"] == yv])
        out[lab] = {"n": int(len(act)), "only_first_second": float((act <= 2).mean()),
                    "sparse_2_to_60_windows": float(((act > 2) & (act <= 60)).mean()),
                    "busy_over_60_windows": float((act > 60).mean()),
                    "median_active_windows": float(np.median(act)), "median_active_first20s": float(np.median(first20))}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--jobs", type=int, default=8)
    a = ap.parse_args()
    seeds = ch.SEEDS[:a.seeds]
    host, net = tc.signals()
    cases, new_ok, new_bad, have_report = load_all(host, net)
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    life, tot = hg * 5 + 4, hg * 5 + 2                       # columns of the 90-col signal-major summary
    sets, meta = {}, {}
    for vname, cs in cohorts(cases).items():
        y = np.array([c["y"] for c in cs])
        groupings = [("proj", np.array([c["group_proj"] for c in cs])), ("prog", np.array([c["group_prog"] for c in cs]))]
        meta[vname] = {"malware": int(y.sum()), "benign": int((y == 0).sum()),
                       "benign_groups_project": len({c["group_proj"] for c in cs if c["y"] == 0}),
                       "benign_by_source": dict(Counter(c["src"] for c in cs if c["y"] == 0)),
                       "activity_mix_5min": shape_mix(cs, hg)}
        for k, lab in ((40, "20s"), (600, "5min")):
            Hf = np.array([ch.summ(c["H"], k) for c in cs]); Nf = np.array([ch.summ(c["N"], k) for c in cs])
            views = {"full": (Hf, Nf),
                     "no_active": (np.array([tc.drop_active(v) for v in Hf]), np.array([tc.drop_active(v) for v in Nf])),
                     "shape": (np.array([tc.shape(c["H"], k, hg) for c in cs]), np.array([tc.shape(c["N"], k, ng) for c in cs]))}
            for gname, g in groupings:
                pre = "%s|%s|%s" % (vname, gname, lab)
                sets[pre + "|baseline|lifetime"] = (Hf[:, [life]], y, g)
                sets[pre + "|baseline|activity"] = (Hf[:, [tot]], y, g)
                for view, (Hx, Nx) in views.items():
                    sets[pre + "|%s|host" % view] = (Hx, y, g)
                    sets[pre + "|%s|network" % view] = (Nx, y, g)
                    sets[pre + "|%s|hybrid" % view] = (np.hstack([Hx, Nx]), y, g)
    jobs = [(name, X, y, g, s, 300) for name, (X, y, g) in sets.items() for s in seeds]
    with Pool(a.jobs) as pool:
        out = pool.map(ch.job_cv, jobs)
    per, oof42 = defaultdict(list), {}
    for name, seed, sc, p in out:
        per[name].append(sc)
        if seed == seeds[0]:
            oof42[name] = p
    res = {"new_benign_used": new_ok, "new_benign_excluded": new_bad, "behavior_report_found": have_report,
           "seeds": seeds, "cohorts": meta, "scores": {}}
    print("new benign used: %d | excluded: %d | behaviour report found: %s" % (new_ok, len(new_bad), have_report))
    for v, m in meta.items():
        mix = m["activity_mix_5min"]
        print("%s: %d malware / %d benign (%d benign projects) | benign sources %s" % (
            v, m["malware"], m["benign"], m["benign_groups_project"], m["benign_by_source"]))
        print("     activity over 5 min  only-first-second / sparse / busy:  malware %.0f%% / %.0f%% / %.0f%%   benign %.0f%% / %.0f%% / %.0f%%"
              % tuple(100 * mix[l][f] for l in ("malware", "benign")
                      for f in ("only_first_second", "sparse_2_to_60_windows", "busy_over_60_windows")))
    print("\n%-4s %-4s %-5s %-9s %-8s %-15s %-15s" % ("coh", "grp", "len", "view", "detector", "BA mean+/-sd", "AUC mean+/-sd"))
    for name in sets:
        v, gname, lab, view, det = name.split("|")
        ba = ch.summary([s["ba"] for s in per[name]]); auc = ch.summary([s["auc"] for s in per[name]])
        res["scores"][name] = {"ba": ba, "auc": auc, "seed_first": per[name][0]}
        print("%-4s %-4s %-5s %-9s %-8s %.3f +/- %.3f  %.3f +/- %.3f" % (v, gname, lab, view, det, ba["mean"], ba["sd"],
                                                                     auc["mean"], auc["sd"]))
    # which benign are still flagged by the 5-min full hybrid (first seed), per source and project
    res["hybrid_5min_flagged_benign"] = {}
    for v, cs in cohorts(cases).items():
        name = "%s|proj|5min|full|hybrid" % v
        p = oof42[name]
        d = defaultdict(lambda: [0, 0])
        for c, pi in zip(cs, p):
            if c["y"] == 0:
                key = "%s:%s" % (c["src"], c["group_proj"].split(":", 1)[1])
                d[key][1] += 1
                d[key][0] += int(pi >= 0.5)
        res["hybrid_5min_flagged_benign"][v] = {k: d[k] for k in sorted(d)}
    json.dump(res, open(OUT, "w"), indent=2, default=float)
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
