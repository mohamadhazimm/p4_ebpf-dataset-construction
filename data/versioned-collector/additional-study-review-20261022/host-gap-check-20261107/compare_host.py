"""Why is the 5-min host lower than the paper's host? Side-by-side on the same footing.

Host = the paper's ADFA contract: 18 per-window signals x (mean,max,sum,std,active_windows) = 90 columns,
signal-major, exactly the column order of the release dataset/features.csv. Both cohorts go through ONE pipeline.

  E0  Paper numbers reproduced from features.csv (Table IV fixed held-out split; training-only grouped CV).
  E1  Paper cohort (99 mal / 105 ben, 20 s) under the 5-min protocol: grouped CV over ALL rows, 10 fold seeds.
  E2  5-min cohort (102 / 102) at 20 s (first 40 windows) and 5 min (600 windows), same protocol.
  E3  2x2 swap at 20 s: {paper, 5-min} malware x {paper, 5-min} benign.
  E4  Transfer: the exact Table IV host model applied to the 5-min runs' first 20 s.
  E5  Lifetime shortcut: one feature only (number of windows with any syscalls).
  E6  Group structure: 5-min benign capped at 5 runs per program.
  E7  Single-split luck: distribution of held-out BA over 200 random group-held-out splits (paper-like size).
Offline; no VM, no merge, no promotion. Run: nice -n 19 /usr/bin/python3 compare_host.py
"""
import csv
import glob
import json
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

REL = "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection"
PROJ = ("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/"
        "additional-study-review-20261022")
OUT = PROJ + "/host-gap-check-20261107/compare_host.json"
sys.path.insert(0, REL + "/evaluation")
import common   # noqa: E402  release-repo loader + RF500 + metrics (unchanged)
import heldout  # noqa: E402  release-repo grouped CV (unchanged)

STATS = ("mean", "max", "sum", "std", "active_windows")
SEEDS = [42] + list(range(9))          # 10 fold assignments (Table V style); seed 42 == analyze_prefix exactly
ATT = [("scale", "scale-5min/20261105T224558731619Z", {"malware"}),
       ("topup", "topup-5min/20261106T073625330426Z", {"malware", "benign"}),
       ("finish", "topup-5min-finish/20261106T155820346732Z", {"malware", "benign"}),
       ("benx", "benign-expanded-5min/20261106T204303086228Z", {"benign"}),
       ("wgetp", "wgetp-5min/20261107T015242522524Z", {"benign"})]


# ----------------------------------------------------------------------------------------------- data
def summ(W, k):
    """== features/summary.py: per signal mean,max,sum,std(ddof0),active over the first k windows, signal-major."""
    m = W[:k]
    out = []
    for j in range(m.shape[1]):
        v = m[:, j]
        out += [v.mean(), v.max(), v.sum(), v.std(), float((v != 0).sum())]
    return np.array(out)


def load_paper():
    rows, host, _ = common.load()
    rows = [r for r in rows if r["category"] in ("malware", "benign")]
    sig = list(dict.fromkeys(c.rsplit("__", 1)[0] for c in host))
    assert len(sig) == 18 and ["%s__%s" % (s, t) for s in sig for t in STATS] == host
    return rows, host, sig


def load_five(sig):
    out, seen = [], set()
    for tag, rel, keep in ATT:
        att = PROJ + "/" + rel
        meta = {c["sample"]: c for c in json.load(open(att + "/protocol.json"))["cases"]}
        for rj in sorted(glob.glob(att + "/runs/*/output/run_*/run.json")):
            sample = rj.split("/runs/")[1].split("/")[0]
            c = meta.get(sample)
            if not c or c["label"] not in keep or sample in seen:
                continue
            d = json.load(open(rj))
            if d.get("collection_quality_status") != "accepted":
                continue
            tel = list(csv.DictReader(open(rj.replace("run.json", "telemetry.csv"))))
            if len(tel) != 600:
                continue
            seen.add(sample)
            W = np.array([[float(t[s]) for s in sig] for t in tel])
            prog = c.get("program") or c.get("variant")
            out.append({"sample": sample, "tag": tag, "y": int(c["label"] == "malware"),
                        "group": ("fam:" + c["family"]) if c["label"] == "malware" else ("prog:" + prog),
                        "family": c.get("family"), "program": prog, "W": W})
    return out


# ----------------------------------------------------------------------------------------------- models
def rf(n=300, seed=42):
    return RandomForestClassifier(n_estimators=n, class_weight="balanced", random_state=seed, n_jobs=1)


def cv_oof(X, y, g, fold_seed, n_trees=300):
    splits = min(5, len(set(g)), int(min(np.bincount(y))))
    oof = np.zeros(len(y))
    for tr, te in StratifiedGroupKFold(n_splits=splits, shuffle=True, random_state=fold_seed).split(X, y, g):
        oof[te] = rf(n_trees).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    return oof


def score(y, p):
    pred = (p >= 0.5).astype(int)
    best = max(balanced_accuracy_score(y, (p >= t).astype(int)) for t in np.unique(p))
    return {"ba": balanced_accuracy_score(y, pred), "auc": roc_auc_score(y, p), "oracle_ba": best,
            "tn": int(((pred == 0) & (y == 0)).sum()), "fp": int(((pred == 1) & (y == 0)).sum()),
            "fn": int(((pred == 0) & (y == 1)).sum()), "tp": int(((pred == 1) & (y == 1)).sum())}


def job_cv(args):
    name, X, y, g, seed, ntrees = args
    p = cv_oof(X, y, g, seed, ntrees)
    return name, seed, score(y, p), p


def draw_split(y, g, rng, frac=0.265):
    test = set()
    for lab in (1, 0):
        gl = sorted({gg for gg, yy in zip(g, y) if yy == lab})
        rng.shuffle(gl)
        n, held = int((y == lab).sum()), 0
        for gg in gl[:-1]:                     # always keep >= 1 group of each class in training
            if held >= frac * n:
                break
            test.add(gg)
            held += int((g == gg).sum())
    te = np.array([i for i in range(len(g)) if g[i] in test])
    tr = np.array([i for i in range(len(g)) if g[i] not in test])
    return tr, te


def job_split(args):
    name, X, y, g, k = args
    tr, te = draw_split(y, g, np.random.default_rng(1000 + k))
    p = rf(500).fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    return name, k, balanced_accuracy_score(y[te], (p >= 0.5).astype(int)), roc_auc_score(y[te], p)


def summary(vals):
    a = np.array(vals)
    return {"mean": float(a.mean()), "sd": float(a.std(ddof=1)) if len(a) > 1 else 0.0,
            "min": float(a.min()), "max": float(a.max())}


# ----------------------------------------------------------------------------------------------- main
def main():
    res = {}
    prow, host, sig = load_paper()
    PX = common.matrix(prow, host); Py = common.labels(prow)
    Pg = np.array([r["cv_group"] for r in prow]); Psplit = np.array([r["split"] for r in prow])
    five = load_five(sig)
    Fy = np.array([c["y"] for c in five]); Fg = np.array([c["group"] for c in five])
    F40 = np.array([summ(c["W"], 40) for c in five]); F600 = np.array([summ(c["W"], 600) for c in five])
    Fprog = np.array([c["program"] or "" for c in five])

    psha = {r["sha256"] for r in prow if r["label"] == "1"}
    fsha = {c["sample"].split(".")[0] for c in five if c["y"] == 1}
    res["cohorts"] = {
        "paper": {"malware": int(Py.sum()), "benign": int((Py == 0).sum()),
                  "malware_groups": len(set(Pg[Py == 1])), "benign_groups": len(set(Pg[Py == 0]))},
        "five": {"malware": int(Fy.sum()), "benign": int((Fy == 0).sum()),
                 "malware_groups": len(set(Fg[Fy == 1])), "benign_groups": len(set(Fg[Fy == 0])),
                 "benign_by_program": dict(Counter(Fprog[Fy == 0]))},
        "malware_sha_overlap": len(psha & fsha)}
    print("cohorts:", json.dumps(res["cohorts"]))

    # E0 -- paper numbers, exactly as the release repo computes them
    tr, te = Psplit == "train", Psplit == "test"
    t4 = common.metrics(Py[te], common.random_forest().fit(PX[tr], Py[tr]).predict_proba(PX[te])[:, 1])
    oof_train = heldout.grouped_cv_ba(PX[tr], Py[tr], Pg[tr])
    res["E0"] = {"tableIV_heldout": t4, "training_grouped_cv_ba": oof_train}
    print("E0 Table IV host held-out: BA %.3f AUC %.3f (tn,fp,fn,tp)=%d,%d,%d,%d | training grouped CV BA %.3f"
          % (t4["balanced_accuracy"], t4["auc"], t4["tn"], t4["fp"], t4["fn"], t4["tp"], oof_train))

    # cross-validation jobs
    life = host.index("host_total_syscalls_total__active_windows")
    cap = []
    rng = np.random.default_rng(42)
    for prog in sorted(set(Fprog[Fy == 0])):
        idx = np.where((Fy == 0) & (Fprog == prog))[0]
        cap += list(rng.choice(idx, size=min(5, len(idx)), replace=False))
    capidx = np.array(sorted(list(np.where(Fy == 1)[0]) + cap))
    mal_p, ben_p, mal_f, ben_f = Py == 1, Py == 0, Fy == 1, Fy == 0
    sets = {
        "paper_20s":         (PX, Py, Pg),
        "five_20s":          (F40, Fy, Fg),
        "five_5min":         (F600, Fy, Fg),
        "paperMal_fiveBen":  (np.vstack([PX[mal_p], F40[ben_f]]), np.r_[Py[mal_p], Fy[ben_f]], np.r_[Pg[mal_p], Fg[ben_f]]),
        "fiveMal_paperBen":  (np.vstack([F40[mal_f], PX[ben_p]]), np.r_[Fy[mal_f], Py[ben_p]], np.r_[Fg[mal_f], Pg[ben_p]]),
        "five_20s_cap5":     (F40[capidx], Fy[capidx], Fg[capidx]),
        "five_5min_cap5":    (F600[capidx], Fy[capidx], Fg[capidx]),
        "life_paper_20s":    (PX[:, [life]], Py, Pg),
        "life_five_20s":     (F40[:, [life]], Fy, Fg),
        "life_five_5min":    (F600[:, [life]], Fy, Fg),
    }
    jobs = [(n, X, y, g, s, 300) for n, (X, y, g) in sets.items() for s in SEEDS]
    jobs += [("paper_20s_rf500", PX, Py, Pg, s, 500) for s in SEEDS]
    with Pool(12) as pool:
        out = pool.map(job_cv, jobs)
    per = defaultdict(list); oof42 = {}
    for name, seed, sc, p in out:
        per[name].append(sc)
        if seed == 42:
            oof42[name] = (sc, p)
    res["cv"] = {}
    print("\n=== grouped CV, 10 fold seeds (mean +/- sd); BA at 0.5 / AUC / oracle-threshold BA (diagnostic) ===")
    for name in list(sets) + ["paper_20s_rf500"]:
        ba = summary([s["ba"] for s in per[name]]); auc = summary([s["auc"] for s in per[name]])
        orc = summary([s["oracle_ba"] for s in per[name]])
        s42 = oof42[name][0]
        res["cv"][name] = {"ba": ba, "auc": auc, "oracle_ba": orc, "seed42": s42}
        print("  %-18s BA %.3f +/- %.3f  AUC %.3f +/- %.3f  oracleBA %.3f | seed42 (tn,fp,fn,tp)=%d,%d,%d,%d"
              % (name, ba["mean"], ba["sd"], auc["mean"], auc["sd"], orc["mean"],
                 s42["tn"], s42["fp"], s42["fn"], s42["tp"]))

    # per-benign-program false alarms (seed 42) in the 5-min cohort
    res["fp_by_program"] = {}
    for name, X in (("five_20s", F40), ("five_5min", F600)):
        p = oof42[name][1]
        d = {}
        for prog in sorted(set(Fprog[Fy == 0])):
            m = (Fy == 0) & (Fprog == prog)
            d[prog] = {"n": int(m.sum()), "flagged": int((p[m] >= 0.5).sum())}
        res["fp_by_program"][name] = d
        print("\n%s false alarms by held-out benign program (seed 42):" % name,
              ", ".join("%s %d/%d" % (k, v["flagged"], v["n"]) for k, v in d.items()))
    p = oof42["paperMal_fiveBen"][1]; yy = sets["paperMal_fiveBen"][1]
    d = {}
    for prog in sorted(set(Fprog[Fy == 0])):
        m = np.r_[np.zeros(int(mal_p.sum()), bool), (Fprog[ben_f] == prog)]
        d[prog] = {"n": int(m.sum()), "flagged": int((p[m] >= 0.5).sum())}
    res["fp_by_program"]["paperMal_fiveBen"] = d
    print("paperMal_fiveBen false alarms by program (seed 42):",
          ", ".join("%s %d/%d" % (k, v["flagged"], v["n"]) for k, v in d.items()))
    pb = oof42["paper_20s"][1]
    res["fp_paper_benign_20s"] = {"n": int(ben_p.sum()), "flagged": int((pb[ben_p] >= 0.5).sum())}

    # E4 -- the exact Table IV host model on the 5-min runs' first 20 s
    m4 = common.random_forest().fit(PX[tr], Py[tr])
    pf = m4.predict_proba(F40)[:, 1]
    mall = common.random_forest().fit(PX, Py)
    pf_all = mall.predict_proba(F40)[:, 1]
    e4 = {}
    for nm, pr in (("tableIV_model", pf), ("all204_model", pf_all)):
        dd = {"malware_flagged": [int((pr[Fy == 1] >= 0.5).sum()), int(Fy.sum())], "auc": roc_auc_score(Fy, pr),
              "benign_flagged_by_program": {}}
        for prog in sorted(set(Fprog[Fy == 0])):
            m = (Fy == 0) & (Fprog == prog)
            dd["benign_flagged_by_program"][prog] = [int((pr[m] >= 0.5).sum()), int(m.sum())]
        dd["benign_flagged_total"] = [int((pr[Fy == 0] >= 0.5).sum()), int((Fy == 0).sum())]
        e4[nm] = dd
        print("\nE4 %s on 5-min first 20 s: malware flagged %d/%d, benign flagged %d/%d, AUC %.3f | by program: %s"
              % (nm, dd["malware_flagged"][0], dd["malware_flagged"][1], dd["benign_flagged_total"][0],
                 dd["benign_flagged_total"][1], dd["auc"],
                 ", ".join("%s %d/%d" % (k, v[0], v[1]) for k, v in dd["benign_flagged_by_program"].items())))
    res["E4"] = e4

    # E5 descriptive -- how long is each class host-active in the first 20 s?
    def act(X, y, lab):
        v = X[y == lab, life]
        return {"median": float(np.median(v)), "frac_1window": float((v <= 1).mean()), "frac_all40": float((v >= 40).mean())}
    res["E5_active_windows_first20s"] = {
        "paper_malware": act(PX, Py, 1), "paper_benign": act(PX, Py, 0),
        "five_malware": act(F40, Fy, 1), "five_benign": act(F40, Fy, 0)}
    print("\nE5 windows with any syscalls in the first 20 s (of 40):", json.dumps(res["E5_active_windows_first20s"]))

    # E7 -- single-split luck (paper-sized group-held-out splits)
    sjobs = [(n, X, y, g, k) for n, (X, y, g) in (("paper_20s", (PX, Py, Pg)), ("five_20s", (F40, Fy, Fg)),
                                                  ("five_5min", (F600, Fy, Fg))) for k in range(200)]
    with Pool(12) as pool:
        sout = pool.map(job_split, sjobs)
    res["E7"] = {}
    print("\n=== E7 single random group-held-out splits (200 draws, ~26% of each class held out, RF500) ===")
    for name in ("paper_20s", "five_20s", "five_5min"):
        bas = np.array([b for n, k, b, a in sout if n == name]); aucs = np.array([a for n, k, b, a in sout if n == name])
        q = np.percentile(bas, [10, 25, 50, 75, 90])
        rec = {"ba_percentiles_10_25_50_75_90": [float(x) for x in q], "ba_mean": float(bas.mean()),
               "auc_median": float(np.median(aucs)), "frac_ba_ge_0929": float((bas >= 0.929).mean())}
        res["E7"][name] = rec
        print("  %-10s BA p10/p25/median/p75/p90 = %s | AUC median %.3f | share of splits with BA >= 0.929: %.1f%%"
              % (name, "/".join("%.3f" % x for x in q), rec["auc_median"], 100 * rec["frac_ba_ge_0929"]))

    json.dump(res, open(OUT, "w"), indent=2, default=float)
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
