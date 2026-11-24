"""Learning curves: does detection of unseen families improve with more training families, or with more samples?

Offline, exploratory, on already-examined data (2026-11-23). No VM, no sample execution.

Pools
  A  first collection, all 240 released rows (Table V protocol: malware + attacks vs benign + network benign + null)
  B  first collection, the 204 malware and benign workload rows (general malware only)
  S  session base dataset, primary view, 20 s after the injection (435 rows; lab only, not released)

Protocol (the thesis's): StratifiedGroupKFold(5, shuffle, seed) over whole families / attack runs / benign projects,
fold seeds 42 and 0-8, RF500 balanced, forest seed 42, threshold 0.5. Detectors: host (90 columns), network (145),
concatenated (235). The stacked hybrid is left out: its inner folds are unstable with few groups.

In every training fold the training data is cut down in two ways, with nested subsets (a larger fraction contains the
smaller one):
  groups  keep a fraction of the training GROUPS of each class (all their rows)   -> fewer families/projects
  rows    keep every group but a fraction of each group's rows (at least one)       -> same families, fewer samples
The test fold is never changed. Fraction 1.0 is the thesis's own protocol and must reproduce its numbers for pool A.

Usage: python3 learning_curve.py out.json
"""
import csv
import hashlib
import json
import math
import os
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
WS = ASR.parents[4]  # the workspace folder that holds the repositories
FEATURES = WS / "p4-ebpf-malware-detection" / "dataset" / "features.csv"
SESSION = ASR / "session-lab" / "base" / "20261117c" / "base_relaxed_sessions_20s.csv"
FOLD_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
FRACTIONS = [0.125, 0.25, 0.5, 0.75, 1.0]
DETECTORS = ("host", "network", "concat")


def rf():
    return RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=42, n_jobs=1)


def load(path, group_col, keep=None):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if keep:
        rows = [r for r in rows if keep(r)]
    host = [c for c in rows[0] if c.startswith("host_")]
    net = [c for c in rows[0] if c.startswith("net_")]
    assert len(host) == 90 and len(net) == 145, (len(host), len(net))
    Xh = np.asarray([[float(r[c]) for c in host] for r in rows])
    Xn = np.asarray([[float(r[c]) for c in net] for r in rows])
    y = np.asarray([int(r["label"]) for r in rows])
    g = np.asarray([r[group_col] for r in rows])
    for name in set(g):  # a group never mixes labels
        assert len(set(y[g == name])) == 1, name
    return Xh, Xn, y, g


def subsample(tr, y, g, mode, frac, rng_seed):
    """Indices of the reduced training set; nested in frac for a fixed rng_seed."""
    if frac >= 1.0:
        return tr
    rng = np.random.RandomState(rng_seed)
    keep = []
    if mode == "groups":
        for cls in (0, 1):
            names = sorted(set(g[tr][y[tr] == cls]))
            rng.shuffle(names)
            k = max(2, int(math.ceil(frac * len(names))))
            chosen = set(names[:k])
            keep.extend(i for i in tr if y[i] == cls and g[i] in chosen)
    else:
        for name in sorted(set(g[tr])):
            idx = [i for i in tr if g[i] == name]
            rng.shuffle(idx)
            keep.extend(idx[:max(1, int(math.ceil(frac * len(idx))))])
    return np.asarray(sorted(keep))


def job(args):
    Xh, Xn, y, g, seed = args
    Xc = np.hstack([Xh, Xn])
    X = {"host": Xh, "network": Xn, "concat": Xc}
    oof = {(m, f, d): np.zeros(len(y)) for m in ("groups", "rows") for f in FRACTIONS for d in DETECTORS}
    size = {(m, f): [] for m in ("groups", "rows") for f in FRACTIONS}
    folds = StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g)
    for fold, (tr, te) in enumerate(folds):
        full = None
        for mode in ("groups", "rows"):
            for frac in FRACTIONS:
                if frac >= 1.0 and full is not None:
                    for d in DETECTORS:
                        oof[(mode, frac, d)][te] = full[d]
                    size[(mode, frac)].append(size[("groups", 1.0)][-1])
                    continue
                sub = subsample(tr, y, g, mode, frac, 100000 * seed + 100 * fold + (0 if mode == "groups" else 1))
                size[(mode, frac)].append((len(sub), len(set(g[sub][y[sub] == 1])), len(set(g[sub][y[sub] == 0]))))
                pred = {d: rf().fit(X[d][sub], y[sub]).predict_proba(X[d][te])[:, 1] for d in DETECTORS}
                for d in DETECTORS:
                    oof[(mode, frac, d)][te] = pred[d]
                if frac >= 1.0:
                    full = pred
    out = {}
    for (m, f, d), p in oof.items():
        out[(m, f, d)] = (balanced_accuracy_score(y, (p >= 0.5).astype(int)), roc_auc_score(y, p),
                          float(((p >= 0.5) & (y == 1)).sum() / (y == 1).sum()),
                          float(((p < 0.5) & (y == 0)).sum() / (y == 0).sum()))
    return seed, out, {k: np.mean(np.asarray(v), axis=0).tolist() for k, v in size.items()}


def curve(name, Xh, Xn, y, g):
    with Pool(len(FOLD_SEEDS)) as p:
        res = p.map(job, [(Xh, Xn, y, g, s) for s in FOLD_SEEDS])
    out = {"rows": int(len(y)), "malicious": int(y.sum()), "benign": int((y == 0).sum()),
           "groups": len(set(g)), "malicious_groups": len(set(g[y == 1])), "benign_groups": len(set(g[y == 0])),
           "curves": {}}
    print("\n%s: %d rows (%d malicious / %d benign), %d groups (%d / %d)" % (
        name, len(y), y.sum(), (y == 0).sum(), len(set(g)), len(set(g[y == 1])), len(set(g[y == 0]))))
    for mode in ("groups", "rows"):
        print("  cut by %s" % mode)
        print("    frac  train rows  mal.groups  ben.groups   " + "   ".join("%-22s" % d for d in DETECTORS))
        for frac in FRACTIONS:
            sz = np.mean([r[2][(mode, frac)] for r in res], axis=0)
            rec = {"train_rows": sz[0], "malicious_groups": sz[1], "benign_groups": sz[2]}
            cells = []
            for d in DETECTORS:
                v = np.asarray([r[1][(mode, frac, d)] for r in res])
                rec[d] = {"ba_mean": v[:, 0].mean(), "ba_sd": v[:, 0].std(ddof=1), "auc_mean": v[:, 1].mean(),
                          "recall_mean": v[:, 2].mean(), "specificity_mean": v[:, 3].mean(),
                          "ba_per_seed": v[:, 0].tolist()}
                cells.append("%.3f+-%.3f (AUC %.3f)" % (rec[d]["ba_mean"], rec[d]["ba_sd"], rec[d]["auc_mean"]))
            out["curves"]["%s@%g" % (mode, frac)] = rec
            print("    %-5g %9.1f  %9.1f  %9.1f    %s" % (frac, sz[0], sz[1], sz[2], "   ".join(cells)))
    return out


def main():
    result = {"protocol": __doc__, "fold_seeds": FOLD_SEEDS, "fractions": FRACTIONS, "pools": {}}
    A = load(FEATURES, "cv_group")
    result["pools"]["A_first_collection_240"] = a = curve("A first collection, 240 rows", *A)
    # gate: fraction 1.0 is the published Table V protocol
    full = a["curves"]["groups@1"]
    for d, want in (("host", 0.784), ("network", 0.756), ("concat", 0.812)):
        assert abs(full[d]["ba_mean"] - want) < 0.0006, (d, full[d]["ba_mean"], want)
    print("  gate: fraction 1.0 reproduces Table V (host 0.784, network 0.756, concatenated 0.812)")
    B = load(FEATURES, "cv_group", keep=lambda r: r["category"] in ("malware", "benign"))
    result["pools"]["B_first_collection_204"] = curve("B first collection, malware and benign workloads only", *B)
    if SESSION.exists():
        S = load(SESSION, "group")
        result["pools"]["S_session_base_435_20s"] = curve("S session base dataset, 20 s", *S)
    result["sources"] = {os.path.relpath(p, WS): hashlib.sha256(Path(p).read_bytes()).hexdigest()
                         for p in (FEATURES, SESSION, Path(__file__).resolve()) if Path(p).exists()}
    with open(sys.argv[1], "w") as f:
        json.dump(result, f, indent=1)


if __name__ == "__main__":
    main()
