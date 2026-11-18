#!/usr/bin/env python3
"""Both hybrids under the protocols of the thesis's robustness table (tab:robustness), first collection.

The thesis's table reports only the concatenated hybrid, the release's held-out design. This adds the stacked
hybrid of Table V (the release's evaluation/combined.py rule, through common.fit_predict: a forest per view, their
inner grouped out-of-fold probabilities combined by a class-balanced logistic model, inner fold seed 7) under the
same protocols, and first reproduces every figure that the table already prints:

  - the held-out split (train -> test), forest seed 42 and forest seeds 0-9 and 42
  - grouped five-fold cross-validation over the 150 training executions, fold seed 42 (as the release's
    evaluation/heldout.py) and ten fold assignments (fold seeds 42, 0-8)
  - each with the published host columns and with the launch prologue removed
    (launcher-ablation-05s/run-20261111/features_05s_prologuefree.csv)

Offline, post hoc (the other figures had been examined), nothing tuned. Needs scikit-learn 1.7 (the version of the
published tables).
  /usr/bin/python3 both_hybrids.py
"""
import csv
import hashlib
import json
import sys
from multiprocessing import Pool

import numpy as np
import sklearn

import common as C

PROLOGUE_FREE = C.STUDY / "launcher-ablation-05s" / "run-20261111" / "features_05s_prologuefree.csv"
OUT = C.HERE / "results" / "both_hybrids.json"
FOREST_SEEDS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 42]

# Figures the thesis prints (tab:robustness, tab:heldout); the run must reproduce them to the third decimal.
PUBLISHED = {
    ("heldout_rf42", "published"): {"host": 0.929, "network": 0.750, "concat": 0.926},
    ("heldout_rf42", "prologue_free"): {"host": 0.929, "network": 0.750, "concat": 0.946},
    ("train_cv_fold_seed42", "published"): {"host": 0.632, "network": 0.747, "concat": 0.718},
    ("train_cv_fold_seed42", "prologue_free"): {"host": 0.748, "network": 0.747, "concat": 0.807},
    ("train_cv_ten_assignments", "published"): {"host": (0.701, 0.043), "network": (0.734, 0.039),
                                                "concat": (0.748, 0.036)},
    ("train_cv_ten_assignments", "prologue_free"): {"host": (0.791, 0.025), "network": (0.734, 0.039),
                                                    "concat": (0.815, 0.036)},
    # committee rigor.json (Table IV over forest seeds): stacked 0.932 +/- 0.021, host 0.927 +/- 0.005
    ("heldout_forest_seeds", "published"): {"host": (0.927, 0.005), "network": (0.750, 0.0), "concat": (0.926, 0.0),
                                            "stacked": (0.932, 0.021)},
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_versions():
    rows, host, net = C.load()
    with open(PROLOGUE_FREE, newline="") as f:
        pf = list(csv.DictReader(f))
    assert [r["execution_id"] for r in pf] == [r["execution_id"] for r in rows]
    for a, b in zip(rows, pf):
        for k in ("label", "category", "split", "cv_group"):
            assert a[k] == b[k], (a["execution_id"], k)
        assert all(a[c] == b[c] for c in net), a["execution_id"]
    keep = [i for i, r in enumerate(rows) if r["category"] in ("malware", "benign")]
    assert len(keep) == 204
    sub = [rows[i] for i in keep]
    y = C.labels(sub)
    groups = C.groups_published(sub)
    split = np.asarray([r["split"] for r in sub])
    Xn = C.matrix(sub, net)
    versions = {"published": C.matrix(sub, host), "prologue_free": C.matrix([pf[i] for i in keep], host)}
    return versions, Xn, y, groups, split


def _heldout_job(args):
    Xh, Xn, y, groups, tr, te, seed = args
    out = C.fit_predict(Xh, Xn, y, groups, tr, te, rf_seed=seed)
    return seed, {d: C.metrics(y[te], p) for d, p in out.items()}


def summary(values):
    v = np.asarray(values, dtype=float)
    return {"mean": float(v.mean()), "sd_sample": float(v.std(ddof=1)) if len(v) > 1 else 0.0,
            "sd_population": float(v.std(ddof=0)), "min": float(v.min()), "max": float(v.max()),
            "values": [float(x) for x in v]}


def check(name, got, want):
    """got: detector -> float (single figure) or summary dict; want: detector -> float or (mean, sd)."""
    bad = []
    for d, w in want.items():
        g = got[d]
        if isinstance(w, tuple):
            ok_mean = abs(round(g["mean"], 3) - w[0]) < 1e-9
            ok_sd = abs(round(g["sd_sample"], 3) - w[1]) < 1e-9 or abs(round(g["sd_population"], 3) - w[1]) < 1e-9
            if not (ok_mean and ok_sd):
                bad.append("%s %s: %.4f +/- %.4f/%.4f, published %.3f +/- %.3f"
                           % (name, d, g["mean"], g["sd_sample"], g["sd_population"], w[0], w[1]))
        elif abs(round(g, 3) - w) >= 1e-9:
            bad.append("%s %s: %.4f, published %.3f" % (name, d, g, w))
    return bad


def main():
    assert sklearn.__version__.startswith("1.7"), sklearn.__version__
    versions, Xn, y, groups, split = load_versions()
    tr, te = np.flatnonzero(split == "train"), np.flatnonzero(split == "test")
    assert len(tr) == 150 and len(te) == 54
    res = {"date": "2026-11-17", "description": __doc__.strip().splitlines()[0],
           "scikit_learn": sklearn.__version__, "forest": "RF500, balanced, n_jobs 1",
           "fold_seeds": C.FOLD_SEEDS, "forest_seeds_heldout": FOREST_SEEDS, "inner_fold_seed": C.INNER_SEED,
           "counts": {"train": int(len(tr)), "test": int(len(te)), "train_groups": int(len(set(groups[tr])))},
           "inputs": {"features.csv": sha256(C.FEATURES),
                      "features_05s_prologuefree.csv": sha256(PROLOGUE_FREE),
                      "common.py": sha256(C.HERE / "common.py"), "both_hybrids.py": sha256(__file__)},
           "versions": {}}
    mismatches = []
    for name, Xh in versions.items():
        v = {}
        with Pool(11) as pool:
            held = dict(pool.map(_heldout_job, [(Xh, Xn, y, groups, tr, te, s) for s in FOREST_SEEDS]))
        v["heldout_rf42"] = held[42]
        v["heldout_forest_seeds"] = {d: summary([held[s][d]["balanced_accuracy"] for s in FOREST_SEEDS])
                                     for d in C.DETECTORS}
        ytr, gtr = y[tr], groups[tr]
        P, _F = C.cv_all(Xh[tr], Xn[tr], ytr, gtr, seeds=C.FOLD_SEEDS, jobs=10)
        per = {d: [C.ba(ytr, (P[d][k] >= 0.5).astype(int)) for k in range(len(C.FOLD_SEEDS))] for d in C.DETECTORS}
        v["train_cv_fold_seed42"] = {d: float(per[d][C.FOLD_SEEDS.index(42)]) for d in C.DETECTORS}
        v["train_cv_ten_assignments"] = {d: summary(per[d]) for d in C.DETECTORS}
        v["train_cv_stacked_minus_concat"] = summary(np.asarray(per["stacked"]) - np.asarray(per["concat"]))
        v["train_cv_stacked_minus_host"] = summary(np.asarray(per["stacked"]) - np.asarray(per["host"]))
        v["train_cv_concat_minus_host"] = summary(np.asarray(per["concat"]) - np.asarray(per["host"]))
        res["versions"][name] = v
        for (proto, ver), want in PUBLISHED.items():
            if ver != name:
                continue
            got = v[proto]
            if proto == "heldout_rf42":
                got = {d: got[d]["balanced_accuracy"] for d in got}
            mismatches += check("%s/%s" % (proto, ver), got, want)
    res["published_figures_reproduced"] = not mismatches
    res["mismatches"] = mismatches
    C.write_json(OUT, res)
    for name, v in res["versions"].items():
        print("== %s" % name)
        h = v["heldout_rf42"]
        print("  held-out, forest seed 42: " + "  ".join("%s %.3f (%d/%d/%d/%d)" % (
            d, h[d]["balanced_accuracy"], h[d]["tn"], h[d]["fp"], h[d]["fn"], h[d]["tp"]) for d in C.DETECTORS))
        fs = v["heldout_forest_seeds"]
        print("  held-out, 11 forest seeds: " + "  ".join("%s %.3f +/- %.3f" % (d, fs[d]["mean"], fs[d]["sd_sample"])
                                                         for d in C.DETECTORS))
        print("  training CV, fold seed 42: " + "  ".join("%s %.3f" % (d, v["train_cv_fold_seed42"][d])
                                                         for d in C.DETECTORS))
        t = v["train_cv_ten_assignments"]
        print("  training CV, ten assignments: " + "  ".join(
            "%s %.3f +/- %.3f (pop %.3f)" % (d, t[d]["mean"], t[d]["sd_sample"], t[d]["sd_population"])
            for d in C.DETECTORS))
        for k in ("train_cv_stacked_minus_concat", "train_cv_stacked_minus_host", "train_cv_concat_minus_host"):
            s = v[k]
            print("  %s: %+.3f (positive in %d of 10)" % (k, s["mean"], sum(x > 0 for x in s["values"])))
    print("published figures reproduced:", res["published_figures_reproduced"])
    for m in mismatches:
        print("  MISMATCH", m)
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
