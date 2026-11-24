"""Does the choice of classifier matter? The thesis's Random Forest against four other standard classifiers.

Offline, exploratory, on already-examined data (2026-11-23). No VM, no sample execution. Purpose: to answer the
question "why a Random Forest?" with a sensitivity check, not to pick a model: the thesis's detector stays the
pre-specified Random Forest whatever this shows. Every classifier uses library defaults fixed before the run (listed
in MODELS); nothing is tuned.

Pools and protocol as learning_curve.py: A (first collection, 240 rows, Table V protocol) and S (session base
dataset, 435 rows, 20 s). StratifiedGroupKFold(5, shuffle, seed), fold seeds 42 and 0-8, threshold 0.5, views host
(90 columns), network (145), concatenated (235). The Random Forest row must reproduce Table V for pool A.

Usage: python3 model_family.py out.json
"""
import hashlib
import json
import os
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.svm import SVC

sys.path.insert(0, str(Path(__file__).resolve().parent))
from learning_curve import FEATURES, FOLD_SEEDS, SESSION, WS, load  # noqa: E402

VIEWS = ("host", "network", "concat")


def signed_log(X):
    return np.sign(X) * np.log1p(np.abs(X))


def scaled(clf):
    # heavy-tailed counts: signed log, then standardize (fitted on the training fold only)
    return make_pipeline(FunctionTransformer(signed_log), StandardScaler(), clf)


MODELS = {
    "random_forest (thesis)": lambda: RandomForestClassifier(n_estimators=500, class_weight="balanced",
                                                             random_state=42, n_jobs=1),
    "extra_trees": lambda: ExtraTreesClassifier(n_estimators=500, class_weight="balanced", random_state=42, n_jobs=1),
    "gradient_boosting": lambda: HistGradientBoostingClassifier(class_weight="balanced", random_state=42),
    "logistic_regression": lambda: scaled(LogisticRegression(max_iter=5000, class_weight="balanced")),
    "svm_rbf": lambda: scaled(SVC(class_weight="balanced", probability=True, random_state=42)),
}


def job(args):
    Xh, Xn, y, g, seed = args
    X = {"host": Xh, "network": Xn, "concat": np.hstack([Xh, Xn])}
    oof = {(m, v): np.zeros(len(y)) for m in MODELS for v in VIEWS}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        for m, make in MODELS.items():
            for v in VIEWS:
                oof[(m, v)][te] = make().fit(X[v][tr], y[tr]).predict_proba(X[v][te])[:, 1]
    return {k: (balanced_accuracy_score(y, (p >= 0.5).astype(int)), roc_auc_score(y, p)) for k, p in oof.items()}


def run(name, Xh, Xn, y, g):
    with Pool(len(FOLD_SEEDS)) as p:
        res = p.map(job, [(Xh, Xn, y, g, s) for s in FOLD_SEEDS])
    print("\n%s (%d rows)" % (name, len(y)))
    print("  %-24s " % "classifier" + "  ".join("%-26s" % v for v in VIEWS))
    out = {}
    for m in MODELS:
        cells, out[m] = [], {}
        for v in VIEWS:
            a = np.asarray([r[(m, v)] for r in res])
            out[m][v] = {"ba_mean": a[:, 0].mean(), "ba_sd": a[:, 0].std(ddof=1), "auc_mean": a[:, 1].mean(),
                         "ba_per_seed": a[:, 0].tolist()}
            cells.append("%.3f+-%.3f (AUC %.3f)" % (a[:, 0].mean(), a[:, 0].std(ddof=1), a[:, 1].mean()))
        print("  %-24s " % m + "  ".join("%-26s" % c for c in cells))
    return out


def main():
    result = {"protocol": __doc__, "pools": {}}
    result["pools"]["A_first_collection_240"] = a = run("A first collection, Table V protocol", *load(FEATURES, "cv_group"))
    rf = a["random_forest (thesis)"]
    for v, want in (("host", 0.784), ("network", 0.756), ("concat", 0.812)):
        assert abs(rf[v]["ba_mean"] - want) < 0.0006, (v, rf[v]["ba_mean"])
    print("  gate: the Random Forest row reproduces Table V")
    if SESSION.exists():
        result["pools"]["S_session_base_435_20s"] = run("S session base dataset, 20 s", *load(SESSION, "group"))
    result["sources"] = {os.path.relpath(p, WS): hashlib.sha256(Path(p).read_bytes()).hexdigest()
                         for p in (FEATURES, SESSION, Path(__file__).resolve()) if Path(p).exists()}
    with open(sys.argv[1], "w") as f:
        json.dump(result, f, indent=1)


if __name__ == "__main__":
    main()
