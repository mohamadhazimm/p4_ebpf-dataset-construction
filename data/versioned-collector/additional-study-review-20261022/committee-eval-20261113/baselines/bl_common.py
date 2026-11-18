"""Shared helpers for the committee baselines (offline analysis of already-collected runs).

Everything reuses the verified loader ../common.py unchanged (rows of features.csv in file order, run
directories, the published groups and fold seeds). This module only adds: the Table IV / Table V splits,
inner benign-group folds for unsupervised thresholds, evaluation summaries with per-category flag rates,
and the saved-score format used for later pairwise (McNemar) comparisons with the thesis detectors.

No sample is executed and no VM is touched; everything reads files on disk.
"""

import hashlib
import json
import math
import os
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent            # .../committee-eval-20261113/baselines
EVAL = HERE.parent                                 # .../committee-eval-20261113
sys.path.insert(0, str(EVAL))
import common as C  # noqa: E402  (verified loader, not modified)

CACHE = HERE / "cache"
SCORES = HERE / "scores"
VENDOR = HERE / "vendor"
RESULTS = HERE / "results"
CATS = ("malware", "network_attack", "benign", "network_benign", "null")
CAT_LABEL = {"malware": "general-malware recall", "network_attack": "network-attack recall",
             "benign": "CLI-benign false-alarm rate", "network_benign": "network-benign false-alarm rate",
             "null": "null false-alarm rate"}
INNER_THRESHOLD_SEED = 7     # shuffles training-benign groups into inner folds (same value as common.INNER_SEED)
INNER_THRESHOLD_FOLDS = 5
THRESHOLD_PERCENTILE = 95.0  # primary operating point of the unsupervised baselines (stated before scoring)
MAX_JOBS = min(10, int(os.environ.get("BL_JOBS", "10")))  # never more than ten processes at a time


def dataset():
    rows, hc, nc = C.load()
    y = C.labels(rows)
    g = C.groups_published(rows)
    cat = np.asarray([r["category"] for r in rows])
    split = np.asarray([r["split"] for r in rows])
    mode = np.asarray([r["mode"] for r in rows])
    return rows, y, g, cat, split, mode


def table4_split(cat, split):
    """Indices of the published held-out split: 150 training and 54 test rows (malware and CLI benign only)."""
    gen = np.isin(cat, ("malware", "benign"))
    tr = np.flatnonzero(gen & (split == "train"))
    te = np.flatnonzero(gen & (split == "test"))
    assert len(tr) == 150 and len(te) == 54
    return tr, te


def table5_folds(y, g):
    """Fold index per row for each of the ten published fold assignments.

    Same splitter call as common.cv_oof: StratifiedGroupKFold(5, shuffle=True, random_state=seed) on (y, groups).
    The splitter uses X only for its length, which check_folds() verifies.
    """
    F = np.full((len(C.FOLD_SEEDS), len(y)), -1, dtype=int)
    X = np.zeros((len(y), 1))
    for k, seed in enumerate(C.FOLD_SEEDS):
        for f, (_, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, g)):
            F[k, te] = f
    assert (F >= 0).all()
    return F


def check_folds(F, y, g, X):
    """The fold assignment does not depend on the content of X (re-split with the real host matrix)."""
    for k, seed in enumerate(C.FOLD_SEEDS):
        for f, (_, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, g)):
            assert (F[k, te] == f).all()
    return True


def inner_benign_folds(groups_of_train_benign, n_folds=INNER_THRESHOLD_FOLDS, seed=INNER_THRESHOLD_SEED):
    """Inner fold id for each training-benign row: whole groups, shuffled with a fixed seed, dealt round-robin.

    Used only to obtain held-out benign scores for setting an unsupervised threshold on the training side.
    """
    uniq = sorted(set(groups_of_train_benign))
    order = np.random.default_rng(seed).permutation(len(uniq))
    k = min(n_folds, len(uniq))
    fold_of = {uniq[j]: i % k for i, j in enumerate(order)}
    return np.asarray([fold_of[x] for x in groups_of_train_benign]), k


def threshold_from(scores, percentile=THRESHOLD_PERCENTILE):
    """Primary rule: the 95th percentile (numpy linear interpolation) of held-out training-benign run scores.

    A run is flagged when its score is strictly greater than the threshold.
    """
    return float(np.percentile(np.asarray(scores, dtype=float), percentile))


# ------------------------------------------------------------------------------------------- metrics
def binary_metrics(y, pred, score=None):
    pred = np.asarray(pred).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else float("nan")
    spec = tn / (tn + fp) if tn + fp else float("nan")
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    auc = float("nan")
    if score is not None and len(set(y.tolist())) == 2:
        auc = float(roc_auc_score(y, np.asarray(score, dtype=float)))
    return {"balanced_accuracy": (rec + spec) / 2, "auc": auc, "recall": rec, "specificity": spec,
            "precision": prec, "f1": f1, "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def flag_rates(cat, pred, idx=None):
    """Fraction of runs flagged in each category (recall for attack categories, false-alarm rate for benign)."""
    idx = np.arange(len(cat)) if idx is None else np.asarray(idx)
    out = {}
    for c in CATS:
        m = idx[cat[idx] == c]
        out[c] = {"n": int(len(m)), "flagged": int(np.asarray(pred)[m].sum()) if len(m) else 0,
                  "rate": float(np.asarray(pred)[m].mean()) if len(m) else float("nan")}
    return out


def summarize_table5(y, cat, score, pred):
    """score, pred: arrays (n_assignments, n). Returns per-assignment metrics and mean +/- sd (ddof=1)."""
    per = []
    for k in range(score.shape[0]):
        m = binary_metrics(y, pred[k], score[k])
        m["flag_rates"] = {c: v["rate"] for c, v in flag_rates(cat, pred[k]).items()}
        per.append(m)
    summ = {}
    for key in ("balanced_accuracy", "auc", "recall", "specificity", "precision", "f1"):
        v = np.asarray([p[key] for p in per], dtype=float)
        summ[key] = {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)), "min": float(v.min()),
                     "max": float(v.max())}
    summ["flag_rates"] = {}
    for c in CATS:
        v = np.asarray([p["flag_rates"][c] for p in per], dtype=float)
        summ["flag_rates"][c] = {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)),
                                 "n": int((cat == c).sum())}
    summ["per_assignment"] = per
    return summ


def summarize_table4(y, cat, te, score, pred):
    m = binary_metrics(y[te], pred, score)
    m["flag_rates"] = {c: v for c, v in flag_rates(cat[te], np.asarray(pred)).items() if v["n"]}
    return m


def save_scores(name, **arrays):
    SCORES.mkdir(parents=True, exist_ok=True)
    path = SCORES / ("%s.npz" % name)
    np.savez_compressed(path, **arrays)
    return path


def write_json(path, obj):
    C.write_json(path, obj)


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def fmt(s):
    """'0.823 +/- 0.015' from a summary entry."""
    return "%.3f +/- %.3f" % (s["mean"], s["sd"])


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)
