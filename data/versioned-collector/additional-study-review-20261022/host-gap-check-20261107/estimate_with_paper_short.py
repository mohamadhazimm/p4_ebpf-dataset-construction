"""ESTIMATE (simulation) of the bursty/short benign run before it finishes, from captures we already have.

The new run's 43 short tasks are the paper's own revision5 benign tasks, already captured at 20 s (40 windows) on the
same headless quiet baseline. A task that has finished inside its 20 s capture does nothing afterwards, and in the
quiet guest every later window is exactly zero on both sensors: all 9 earlier 5-min nulls show host activity only in
window 0 and no P4 activity at all. So a finished task's 5-min run is estimated as its 20 s capture + 560 zero windows.
Only tasks that finished (exit code recorded, not killed at the cutoff, last host- and P4-active window <= 36) are
simulated; the rest are excluded and counted. The 15 sparse periodic jobs are NOT simulated (no captures exist), so
this estimates the effect of the short tasks alone. .21 (20 s) vs .22 (5 min): .22 only adds an event-count overflow
guard, features unchanged; the 2x2 swap in compare_host.py showed the same malware score identically across the two
campaigns. Real runs replace this estimate when the collection finishes (rescore_with_bursty.py).

Cohorts (5-min malware 102 throughout; benign groups = projects, also per program):
  V1       the old 5-min benign without the 10 broken runs (92)              -- reference
  S43      V1 + the 43 selected short tasks, simulated                      -- the planned run, short part only
  S43cap   S43 with the always-busy old programs capped at 10 runs (rsync, wget)
  Sall     V1 + every finished paper benign task, simulated                 -- more benign diversity
  Sallcap  Sall with the same cap
Scores: lifetime + activity baselines, host / network / hybrid on 'full' and 'shape' views, 20 s and 5 min, 10 seeds.
Offline; no VM; no merge; no promotion.   Run: nice -n 19 /usr/bin/python3 estimate_with_paper_short.py
"""
import csv
import glob
import json
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

import numpy as np

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch                  # noqa: E402
import timing_control as tc                # noqa: E402
import rescore_with_bursty as rb           # noqa: E402  load_all (old cohort), DENSE_CAP, shape_mix
import build_benign_bursty_payload as bbp  # noqa: E402  select_short (the 43 in the planned run)

REV5 = ch.PROJ + "/revision5-collection/20261025T100025568989Z"
OUT = ch.PROJ + "/host-gap-check-20261107/estimate_with_paper_short.json"


def load_paper_benign(host, net):
    meta = {c["sample"]: c for c in json.load(open(REV5 + "/payload/cases.json"))}
    out, skipped = [], Counter()
    for rj in sorted(glob.glob(REV5 + "/runs/*/output/run_*/run.json")):
        sample = rj.split("/runs/")[1].split("/")[0]
        c = meta.get(sample)
        if not c or c["label"] != "benign":
            continue
        d = json.load(open(rj))
        if d.get("collection_quality_status") != "accepted":
            skipped["quality"] += 1
            continue
        tel = list(csv.DictReader(open(rj.rsplit("/", 1)[0] + "/telemetry.csv")))
        if len(tel) != 40:
            skipped["windows"] += 1
            continue
        H = np.array([[float(t[s]) for s in host] for t in tel]); N = np.array([[float(t[s]) for s in net] for t in tel])
        hl = int(np.max(np.nonzero(H[:, host.index("host_total_syscalls_total")])[0])) if H[:, 0].any() else -1
        nz = np.nonzero(N[:, net.index("net_pkts_total_delta")])[0]
        nl = int(nz.max()) if len(nz) else -1
        rc = d.get("return_code")
        finished = rc is not None and rc not in (-15, -9) and hl <= 36 and nl <= 36
        if not finished:
            skipped["not_finished_in_20s"] += 1
            continue
        pad = lambda M: np.vstack([M, np.zeros((560, M.shape[1]))])
        out.append({"sample": sample, "y": 0, "src": "sim-short", "program": c["program"],
                    "group_proj": "proj:" + c["project"], "group_prog": "prog:" + c["program"], "broken": False,
                    "rc": rc, "H": pad(H), "N": pad(N), "last_host": hl, "last_p4": nl})
    return out, skipped


def cap_dense(cs):
    rng = np.random.default_rng(42)
    drop = set()
    for prog, cap in rb.DENSE_CAP.items():
        idx = [i for i, c in enumerate(cs) if c["y"] == 0 and c["src"].startswith("old-") and c["program"] == prog]
        keep = set(rng.choice(idx, size=min(cap, len(idx)), replace=False).tolist()) if idx else set()
        drop |= {i for i in idx if i not in keep}
    return [c for i, c in enumerate(cs) if i not in drop]


def main():
    host, net = tc.signals()
    old, _, _, _ = rb.load_all(host, net)
    old = [c for c in old if not c["src"].startswith("new-")]          # the old 5-min cohort only
    v1 = [c for c in old if not c["broken"]]
    sim, skipped = load_paper_benign(host, net)
    planned = {c["sample"] for c in bbp.select_short()}
    sim43 = [c for c in sim if c["sample"] in planned]
    cohorts = {"V1": v1, "S43": v1 + sim43, "S43cap": cap_dense(v1 + sim43),
               "Sall": v1 + sim, "Sallcap": cap_dense(v1 + sim)}
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    life, tot = hg * 5 + 4, hg * 5 + 2
    sets, meta = {}, {}
    for vname, cs in cohorts.items():
        y = np.array([c["y"] for c in cs])
        meta[vname] = {"malware": int(y.sum()), "benign": int((y == 0).sum()),
                       "benign_projects": len({c["group_proj"] for c in cs if c["y"] == 0}),
                       "benign_by_source": dict(Counter(c["src"] for c in cs if c["y"] == 0)),
                       "activity_mix_5min": rb.shape_mix(cs, hg)}
        for k, lab in ((40, "20s"), (600, "5min")):
            Hf = np.array([ch.summ(c["H"], k) for c in cs]); Nf = np.array([ch.summ(c["N"], k) for c in cs])
            Hs = np.array([tc.shape(c["H"], k, hg) for c in cs]); Ns = np.array([tc.shape(c["N"], k, ng) for c in cs])
            for gname in ("proj", "prog"):
                g = np.array([c["group_" + gname] for c in cs])
                pre = "%s|%s|%s" % (vname, gname, lab)
                sets[pre + "|baseline|lifetime"] = (Hf[:, [life]], y, g)
                sets[pre + "|baseline|activity"] = (Hf[:, [tot]], y, g)
                for view, (Hx, Nx) in (("full", (Hf, Nf)), ("shape", (Hs, Ns))):
                    sets[pre + "|%s|host" % view] = (Hx, y, g)
                    sets[pre + "|%s|network" % view] = (Nx, y, g)
                    sets[pre + "|%s|hybrid" % view] = (np.hstack([Hx, Nx]), y, g)
    jobs = [(name, X, y, g, s, 300) for name, (X, y, g) in sets.items() for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for name, seed, sc, _ in out:
        per[name].append(sc)
    res = {"simulated_paper_benign": len(sim), "simulated_planned_short": len(sim43), "skipped": dict(skipped),
           "last_active_windows_of_simulated": {"host_max": max(c["last_host"] for c in sim),
                                                "p4_max": max(c["last_p4"] for c in sim)},
           "cohorts": meta, "scores": {}}
    print("paper benign simulated: %d (of which planned short tasks: %d/43) | skipped: %s | latest activity among "
          "simulated: host window %d, P4 window %d (of 40)" % (len(sim), len(sim43), dict(skipped),
                                                            res["last_active_windows_of_simulated"]["host_max"],
                                                            res["last_active_windows_of_simulated"]["p4_max"]))
    for v, m in meta.items():
        mix = m["activity_mix_5min"]
        print("%-8s %d malware / %d benign, %d benign projects | 5-min activity  first-second-only/sparse/busy: "
              "malware %.0f/%.0f/%.0f%%  benign %.0f/%.0f/%.0f%%" % ((v, m["malware"], m["benign"], m["benign_projects"])
              + tuple(100 * mix[l][f] for l in ("malware", "benign")
                      for f in ("only_first_second", "sparse_2_to_60_windows", "busy_over_60_windows"))))
    print("\n%-8s %-4s %-5s %-8s %-8s %-15s %-15s" % ("cohort", "grp", "len", "view", "detector", "BA mean+/-sd", "AUC mean+/-sd"))
    for name in sets:
        v, gname, lab, view, det = name.split("|")
        ba = ch.summary([s["ba"] for s in per[name]]); auc = ch.summary([s["auc"] for s in per[name]])
        res["scores"][name] = {"ba": ba, "auc": auc}
        print("%-8s %-4s %-5s %-8s %-8s %.3f +/- %.3f  %.3f +/- %.3f" % (v, gname, lab, view, det, ba["mean"], ba["sd"],
                                                                      auc["mean"], auc["sd"]))
    json.dump(res, open(OUT, "w"), indent=2, default=float)
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
