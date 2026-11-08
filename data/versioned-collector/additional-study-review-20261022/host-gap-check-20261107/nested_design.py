"""Nested design selection: the highest score that is still honest.

The FEATURES stay fixed (host = the 18 ADFA sequence descriptors validated on LID-DS, network = the 29 P4 flow
features). What is optimised is how they are turned into a detector, and every choice is made INSIDE the training
folds, never on the data being scored:
  view      full  = the 5 statistics (mean,max,sum,std,active windows) per signal, as in the paper
            shape = per-signal mean over the windows in which that sensor saw anything (no timing information)
            both  = full + shape
  fusion    concat  = one random forest on host+network columns (Table IV design)
            stacked = a forest per sensor, their out-of-fold probabilities combined by a balanced logistic model
                      (Table V design)
  threshold fixed 0.5, or tuned on the training folds' out-of-fold probabilities to maximise balanced accuracy
Outer: StratifiedGroupKFold(5) over whole malware families / benign projects, fold seeds 42,0-8. Inner: grouped
5-fold on each outer training set scores all 12 designs; the best inner design is refit on the outer training set
and scored once on the outer test fold. The outer score therefore includes the cost of choosing. Every fixed design
is also scored on the same outer folds for comparison. RF300, class-balanced, forest seed 42.
Cohorts: paper (the 204 general-malware runs of the paper dataset, raw revision5 windows, 20 s), five_est (the
5-min cohort with the fixed-benign ESTIMATE, at 5 min and at 20 s); --real swaps the estimate for the real runs.
Offline; no VM; no merge.   Run: nice -n 19 /usr/bin/python3 nested_design.py [--real] [--seeds N]
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch                  # noqa: E402
import timing_control as tc                # noqa: E402
import rescore_with_bursty as rb           # noqa: E402
import estimate_with_paper_short as est    # noqa: E402
import build_benign_bursty_payload as bbp  # noqa: E402
import paper_vs_5min as pv                 # noqa: E402

VIEWS, FUSIONS, THRESH = ("full", "shape", "both"), ("concat", "stacked"), ("fixed", "tuned")
DESIGNS = [(v, f, t) for v in VIEWS for f in FUSIONS for t in THRESH]
RANK = {d: i for i, d in enumerate(DESIGNS)}            # tie-break: simpler design first
DATA = {}                                               # filled before the fork; read by the workers


def rf(seed=42):
    return RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=1)


def grouped(y, g, seed):
    splits = min(5, len(set(g)), int(min(np.bincount(y))))
    return list(StratifiedGroupKFold(n_splits=splits, shuffle=True, random_state=seed).split(np.zeros((len(y), 1)), y, g))


def predict(fusion, Htr, Ntr, ytr, gtr, Hte, Nte, seed=42):
    if fusion == "concat":
        return rf(seed).fit(np.hstack([Htr, Ntr]), ytr).predict_proba(np.hstack([Hte, Nte]))[:, 1]
    oof = np.zeros((len(ytr), 2))
    for tr, te in grouped(ytr, gtr, seed):
        oof[te, 0] = rf(seed).fit(Htr[tr], ytr[tr]).predict_proba(Htr[te])[:, 1]
        oof[te, 1] = rf(seed).fit(Ntr[tr], ytr[tr]).predict_proba(Ntr[te])[:, 1]
    lr = LogisticRegression(class_weight="balanced", max_iter=2000).fit(oof, ytr)
    ph = rf(seed).fit(Htr, ytr).predict_proba(Hte)[:, 1]
    pn = rf(seed).fit(Ntr, ytr).predict_proba(Nte)[:, 1]
    return lr.predict_proba(np.column_stack([ph, pn]))[:, 1]


def best_threshold(p, y):
    cand = np.unique(np.r_[0.5, (np.sort(p)[1:] + np.sort(p)[:-1]) / 2])
    scores = [(balanced_accuracy_score(y, (p >= t).astype(int)), -abs(t - 0.5), t) for t in cand]
    return max(scores)[2]


def views(tag):
    d = DATA[tag]
    return {"full": (d["Hf"], d["Nf"]), "shape": (d["Hs"], d["Ns"]),
            "both": (np.hstack([d["Hf"], d["Hs"]]), np.hstack([d["Nf"], d["Ns"]]))}


def outer_job(args):
    tag, seed, k, tr, te = args
    y, g = DATA[tag]["y"], DATA[tag]["g"]
    V = views(tag)
    ytr, gtr = y[tr], g[tr]
    inner = defaultdict(lambda: np.zeros(len(tr)))
    for itr, ite in grouped(ytr, gtr, seed + 1000):
        for v in VIEWS:
            H, N = V[v]
            for f in FUSIONS:
                inner[(v, f)][ite] = predict(f, H[tr][itr], N[tr][itr], ytr[itr], gtr[itr], H[tr][ite], N[tr][ite])
    inner_score, thr = {}, {}
    for (v, f), p in inner.items():
        for t in THRESH:
            thr[(v, f, t)] = 0.5 if t == "fixed" else best_threshold(p, ytr)
            inner_score[(v, f, t)] = balanced_accuracy_score(ytr, (p >= thr[(v, f, t)]).astype(int))
    chosen = max(DESIGNS, key=lambda d: (inner_score[d], -RANK[d]))
    outer = {}
    for v in VIEWS:
        H, N = V[v]
        for f in FUSIONS:
            p = predict(f, H[tr], N[tr], ytr, gtr, H[te], N[te])
            for t in THRESH:
                outer[(v, f, t)] = (p, thr[(v, f, t)])
    return tag, seed, k, te, chosen, inner_score[chosen], outer


def load_cohorts(real):
    host, net = tc.signals()
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    paper = pv.load_paper(host, net)
    cases, new_ok, new_bad, have_report = rb.load_all(host, net)
    v1 = [c for c in cases if not c["src"].startswith("new-") and not c["broken"]]
    if real:
        if not have_report:
            raise SystemExit("run collect_benign_bursty.py --behavior-check first")
        five = est.cap_dense(v1 + [c for c in cases if c["src"].startswith("new-")])
        note = "five = REAL bursty runs (%d used, %d excluded), capped" % (new_ok, len(new_bad))
    else:
        sim, _ = est.load_paper_benign(host, net)
        planned = {c["sample"] for c in bbp.select_short()}
        five = est.cap_dense(v1 + [c for c in sim if c["sample"] in planned])
        note = "five = ESTIMATE (43 short tasks simulated), capped"
    for c in five:
        c["group"] = c["group_proj"]
    out = {}
    for tag, cs, k in (("paper@20s", paper, 40), ("five@5min", five, 600), ("five@20s", five, 40)):
        out[tag] = {"y": np.array([c["y"] for c in cs]), "g": np.array([c["group"] for c in cs]), "k": k,
                    "Hf": np.array([ch.summ(c["H"], k) for c in cs]), "Nf": np.array([ch.summ(c["N"], k) for c in cs]),
                    "Hs": np.array([tc.shape(c["H"], k, hg) for c in cs]), "Ns": np.array([tc.shape(c["N"], k, ng) for c in cs])}
    return out, note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--jobs", type=int, default=8)
    a = ap.parse_args()
    seeds = ch.SEEDS[:a.seeds]
    cohorts, note = load_cohorts(a.real)
    DATA.update(cohorts)
    jobs = []
    for tag, d in cohorts.items():
        for seed in seeds:
            for tr, te in grouped(d["y"], d["g"], seed):
                jobs.append((tag, seed, d["k"], tr, te))
    print("%s | %d outer-fold jobs" % (note, len(jobs)), flush=True)
    with Pool(a.jobs) as pool:
        out = pool.map(outer_job, jobs, chunksize=1)
    res = {"note": note, "seeds": seeds, "designs": ["|".join(d) for d in DESIGNS], "cohorts": {}}
    for tag, d in cohorts.items():
        y = d["y"]; n = len(y)
        chosen_p = {s: np.zeros(n) for s in seeds}; chosen_dec = {s: np.zeros(n, int) for s in seeds}
        fixed_p = {(s, dd): np.zeros(n) for s in seeds for dd in DESIGNS}
        fixed_dec = {(s, dd): np.zeros(n, int) for s in seeds for dd in DESIGNS}
        picks, inner_scores = Counter(), []
        for t_, seed, k, te, chosen, isc, outer in out:
            if t_ != tag:
                continue
            picks[chosen] += 1; inner_scores.append(isc)
            p, th = outer[chosen]
            chosen_p[seed][te] = p; chosen_dec[seed][te] = (p >= th).astype(int)
            for dd, (p, th) in outer.items():
                fixed_p[(seed, dd)][te] = p; fixed_dec[(seed, dd)][te] = (p >= th).astype(int)
        nested = {"ba": ch.summary([balanced_accuracy_score(y, chosen_dec[s]) for s in seeds]),
                  "auc": ch.summary([roc_auc_score(y, chosen_p[s]) for s in seeds]),
                  "picks": {"|".join(k_): v for k_, v in picks.most_common()},
                  "mean_inner_ba_of_chosen": float(np.mean(inner_scores))}
        fixed = {"|".join(dd): {"ba": ch.summary([balanced_accuracy_score(y, fixed_dec[(s, dd)]) for s in seeds]),
                                "auc": ch.summary([roc_auc_score(y, fixed_p[(s, dd)]) for s in seeds])} for dd in DESIGNS}
        res["cohorts"][tag] = {"n": int(n), "malware": int(y.sum()), "benign": int((y == 0).sum()),
                               "groups": len(set(d["g"])), "nested": nested, "fixed": fixed}
        print("\n=== %s: %d malware / %d benign, %d groups ===" % (tag, y.sum(), (y == 0).sum(), len(set(d["g"]))))
        print("NESTED (design chosen inside each training fold): BA %.3f +/- %.3f  AUC %.3f +/- %.3f"
              % (nested["ba"]["mean"], nested["ba"]["sd"], nested["auc"]["mean"], nested["auc"]["sd"]))
        print("   designs picked:", ", ".join("%s x%d" % (k_, v) for k_, v in nested["picks"].items()))
        print("   %-24s %-16s %-16s" % ("fixed design", "BA mean+/-sd", "AUC mean+/-sd"))
        for dd in DESIGNS:
            f = fixed["|".join(dd)]
            print("   %-24s %.3f +/- %.3f    %.3f +/- %.3f" % ("|".join(dd), f["ba"]["mean"], f["ba"]["sd"], f["auc"]["mean"], f["auc"]["sd"]))
    path = ch.PROJ + "/host-gap-check-20261107/nested_design%s.json" % ("_real" if a.real else "_estimate")
    json.dump(res, open(path, "w"), indent=2, default=float)
    print("\nsaved", path)


if __name__ == "__main__":
    main()
