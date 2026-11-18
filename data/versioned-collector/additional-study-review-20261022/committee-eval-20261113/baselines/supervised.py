"""Supervised software baselines under the thesis's two protocols (same RF and stacker as the thesis).

Detectors (RandomForest(500, class_weight="balanced", random_state=42, n_jobs=1) = common.rf(); threshold 0.5):
  ngram        system-call n-gram HIDS: log1p counts of per-thread 1-3-grams, vocabulary = n-grams present in
               >= 2 training runs of the fold (refit in every training set, inner folds included)
  ngram_pf     the same on prologue-free traces (secondary)
  flow         unconstrained software network features (CICFlowMeter-like flows, 115 per run)
  sw_concat    software hybrid, one RF on n-gram + flow features
  sw_stacked   software hybrid, logistic regression (common.stacker()) on inner out-of-fold probabilities of the
               n-gram RF and the flow RF; inner StratifiedGroupKFold(min(5, groups), shuffle=True, random_state=7),
               exactly the design of common.fit_predict's stacked detector
  kitsune_rf   (--kitsune) RF on per-run mean/max/std of Kitsune's per-packet AfterImage features
  ngram_startup (--startup) diagnostic only: n-grams of the first 50 calls of the target program (its runtime /
               C-library start-up), to measure how far a start-up fingerprint alone separates the classes
  ngram_nostart (--startup) diagnostic only: the n-gram HIDS without the launcher prologue and those 50 calls
  sw_concat_nostart, sw_stacked_nostart (--startup) diagnostic only: the software hybrids built on ngram_nostart

Protocols: Table V (all 240 rows, ten published fold assignments, published groups) and Table IV (published
held-out split, 150 training / 54 test rows).

    /usr/bin/python3 supervised.py [--kitsune]
"""
import argparse
import sys
from multiprocessing import Pool

import numpy as np
from scipy import sparse
from sklearn.model_selection import StratifiedGroupKFold

import bl_common as B
import ngrams as NG

C = B.C
D = {}  # data shared with forked workers


def feats(name, idx, train_idx):
    """Feature matrix of rows idx for feature set `name`, with the vocabulary fit on train_idx only."""
    if name in ("ngram", "ngram_pf", "ngram_startup", "ngram_nostart"):
        bag = D["bags"][name]
        voc = NG.vocab(bag, train_idx)
        return NG.matrix(bag, idx, voc)
    return D["dense"][name][idx]


def rf_prob(name, tr, te, y):
    Xtr = feats(name, tr, tr)
    Xte = feats(name, te, tr)
    return C.rf().fit(Xtr, y[tr]).predict_proba(Xte)[:, 1]


def concat_prob(names, tr, te, y):
    parts_tr, parts_te = [], []
    for n in names:
        a, b = feats(n, tr, tr), feats(n, te, tr)
        parts_tr.append(sparse.csr_matrix(a)); parts_te.append(sparse.csr_matrix(b))
    Xtr, Xte = sparse.hstack(parts_tr).tocsr(), sparse.hstack(parts_te).tocsr()
    return C.rf().fit(Xtr, y[tr]).predict_proba(Xte)[:, 1]


def stacked_prob(a, b, tr, te, y, g, pa, pb):
    """Stacker trained on inner OOF probabilities of RF(a) and RF(b); applied to the outer base probabilities."""
    ia, ib = np.zeros(len(tr)), np.zeros(len(tr))
    gt = g[tr]
    inner = StratifiedGroupKFold(min(5, len(set(gt))), shuffle=True, random_state=C.INNER_SEED)
    for itr, ite in inner.split(np.zeros((len(tr), 1)), y[tr], gt):
        r, s = tr[itr], tr[ite]
        ia[ite] = rf_prob(a, r, s, y)
        ib[ite] = rf_prob(b, r, s, y)
    st = C.stacker().fit(np.column_stack([ia, ib]), y[tr])
    return st.predict_proba(np.column_stack([pa, pb]))[:, 1]


def fit_predict(tr, te):
    y, g = D["y"], D["g"]
    out = {}
    if D["kitsune"]:
        out["kitsune_rf"] = rf_prob("kitsune_agg", tr, te, y)
        return out
    if D["startup"]:
        out["ngram_startup"] = rf_prob("ngram_startup", tr, te, y)
        out["ngram_nostart"] = rf_prob("ngram_nostart", tr, te, y)
        flow = rf_prob("flow", tr, te, y)
        out["sw_concat_nostart"] = concat_prob(("ngram_nostart", "flow"), tr, te, y)
        out["sw_stacked_nostart"] = stacked_prob("ngram_nostart", "flow", tr, te, y, g, out["ngram_nostart"], flow)
        return out
    out["ngram"] = rf_prob("ngram", tr, te, y)
    out["ngram_pf"] = rf_prob("ngram_pf", tr, te, y)
    out["flow"] = rf_prob("flow", tr, te, y)
    out["sw_concat"] = concat_prob(("ngram", "flow"), tr, te, y)
    out["sw_stacked"] = stacked_prob("ngram", "flow", tr, te, y, g, out["ngram"], out["flow"])
    return out


def _assignment(k):
    F, n = D["F"], len(D["y"])
    P = {}
    for f in range(5):
        tr, te = np.flatnonzero(F[k] != f), np.flatnonzero(F[k] == f)
        for d, p in fit_predict(tr, te).items():
            P.setdefault(d, np.zeros(n))[te] = p
    B.log("assignment", C.FOLD_SEEDS[k], "done")
    return k, P


def kitsune_aggregates():
    rows = []
    for i in range(240):
        V = np.load(B.CACHE / "kitsune" / "vec" / ("%03d.npy" % i))
        if len(V):
            rows.append(np.concatenate([V.mean(0), V.max(0), V.std(0)]))
        else:
            rows.append(np.zeros(3 * V.shape[1]))
    X = np.asarray(rows)
    assert np.isfinite(X).all()
    return X


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kitsune", action="store_true")
    ap.add_argument("--startup", action="store_true",
                    help="diagnostic: n-grams of the first 50 calls of the target program only")
    a = ap.parse_args()
    rows, y, g, cat, split, mode = B.dataset()
    F = B.table5_folds(y, g)
    D.update(y=y, g=g, F=F, kitsune=a.kitsune, startup=a.startup, bags={}, dense={})
    if a.startup:
        D["bags"]["ngram_startup"] = NG.bags("startup50")
        D["bags"]["ngram_nostart"] = NG.bags("nostart50")
        D["dense"]["flow"] = np.load(B.CACHE / "flows" / "features.npz")["X"]
        dets = ("ngram_startup", "ngram_nostart", "sw_concat_nostart", "sw_stacked_nostart")
    elif a.kitsune:
        D["dense"]["kitsune_agg"] = kitsune_aggregates()
        dets = ("kitsune_rf",)
    else:
        D["bags"]["ngram"] = NG.bags("collected")
        D["bags"]["ngram_pf"] = NG.bags("prologue_free")
        D["dense"]["flow"] = np.load(B.CACHE / "flows" / "features.npz")["X"]
        dets = ("ngram", "ngram_pf", "flow", "sw_concat", "sw_stacked")
    B.log("data ready", dets)
    with Pool(min(B.MAX_JOBS, len(C.FOLD_SEEDS))) as p:
        res = p.map(_assignment, range(len(C.FOLD_SEEDS)), chunksize=1)
    res.sort(key=lambda t: t[0])
    tr, te = B.table4_split(cat, split)
    P4 = fit_predict(tr, te)
    out = {"settings": {"rf": "RandomForestClassifier(n_estimators=500, class_weight='balanced', random_state=42, "
                              "n_jobs=1)", "threshold": 0.5, "ngram_min_df": NG.MIN_DF,
                        "stacker": "LogisticRegression(max_iter=2000, class_weight='balanced'), inner "
                                   "StratifiedGroupKFold(min(5, groups), shuffle=True, random_state=7)"}}
    for d in dets:
        prob = np.stack([r[1][d] for r in res])
        pred = (prob >= 0.5).astype(int)
        s5 = B.summarize_table5(y, cat, prob, pred)
        p4 = P4[d]
        s4 = B.summarize_table4(y, cat, te, p4, (p4 >= 0.5).astype(int))
        out[d] = {"table5": s5, "table4": s4}
        B.save_scores("%s_table5" % d, score=prob, pred=pred, folds=F)
        B.save_scores("%s_table4" % d, test_index=te, score=p4, pred=(p4 >= 0.5).astype(int))
        B.log("%-11s TableV BA %s AUC %s | TableIV BA %.3f AUC %.3f (tn %d fp %d fn %d tp %d)" % (
            d, B.fmt(s5["balanced_accuracy"]), B.fmt(s5["auc"]), s4["balanced_accuracy"], s4["auc"],
            s4["tn"], s4["fp"], s4["fn"], s4["tp"]))
    B.write_json(B.RESULTS / ("supervised_kitsune.json" if a.kitsune else
                              "supervised_startup.json" if a.startup else "supervised.json"), out)


if __name__ == "__main__":
    sys.exit(main())
