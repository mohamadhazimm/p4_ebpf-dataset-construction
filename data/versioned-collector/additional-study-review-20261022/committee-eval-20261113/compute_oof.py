"""Compute and cache every prediction the rigor analyses need (committee item 2). Offline.

Caches (cache/):
  cv_<grouping>_k<k>.npz   out-of-fold probabilities, 4 detectors x 10 fold assignments x 240 rows, Table V protocol
                           groupings: published | attacktype | implementation;  k = observation windows (0.5 s each)
  heldout_k<k>.npz         Table IV test probabilities (54 rows); k=40 also for RF seeds 0..9 besides 42
  stream.npz               prefix-trained streaming model: OOF probabilities at every prefix (latency analysis)

    /usr/bin/python3 compute_oof.py [--jobs 10]
"""
import argparse
import time
from multiprocessing import Pool

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

import common as C

PREFIXES = [1, 2, 4, 10, 20, 30, 40]  # 0.5, 1, 2, 5, 10, 15, 20 s
GROUPINGS = {"published": C.groups_published, "attacktype": C.groups_by_attack_type,
             "implementation": C.groups_by_implementation}
RF_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
STREAM_PREFIXES = [1, 2, 4, 6, 10, 16, 20, 30, 40]

D = {}  # filled in main, read by worker processes (fork start method)


def cv_job(args):
    name, k, seed = args
    Xh, Xn = C.summarize(D["H"], k), C.summarize(D["N"], k)
    oof, folds = C.cv_oof(Xh, Xn, D["y"], D["groups"][name], seed)
    return name, k, seed, oof, folds


def heldout_job(args):
    k, rf_seed = args
    Xh, Xn = C.summarize(D["H"], k), C.summarize(D["N"], k)
    return k, rf_seed, C.fit_predict(Xh, Xn, D["y"], D["groups"]["published"], D["tr"], D["te"], rf_seed)


def stream_job(seed):
    """Models trained on the union of prefixes of the training rows, evaluated at every prefix of the test rows."""
    y, g = D["y"], D["groups"]["published"]
    H, N = D["H"], D["N"]
    feats = {k: (C.summarize(H, k), C.summarize(N, k)) for k in STREAM_PREFIXES}
    out = {d: np.zeros((len(STREAM_PREFIXES), len(y))) for d in C.DETECTORS}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(H[:, 0, :1], y, g):
        # augmented training set: every training row at every prefix (rows of one run share its group)
        Xh_tr = np.vstack([feats[k][0][tr] for k in STREAM_PREFIXES])
        Xn_tr = np.vstack([feats[k][1][tr] for k in STREAM_PREFIXES])
        y_tr = np.concatenate([y[tr]] * len(STREAM_PREFIXES))
        g_tr = np.concatenate([g[tr]] * len(STREAM_PREFIXES))
        n_tr = len(y_tr)
        for j, k in enumerate(STREAM_PREFIXES):
            Xh_all = np.vstack([Xh_tr, feats[k][0][te]])
            Xn_all = np.vstack([Xn_tr, feats[k][1][te]])
            y_all = np.concatenate([y_tr, y[te]])
            g_all = np.concatenate([g_tr, g[te]])
            idx_tr, idx_te = np.arange(n_tr), np.arange(n_tr, n_tr + len(te))
            if j == 0:
                models = _fit_stream_models(Xh_all, Xn_all, y_all, g_all, idx_tr)
            for d, p in _predict_stream(models, Xh_all[idx_te], Xn_all[idx_te]).items():
                out[d][j, te] = p
    return seed, out


def _fit_stream_models(Xh, Xn, y, g, tr):
    hm = C.rf().fit(Xh[tr], y[tr])
    nm = C.rf().fit(Xn[tr], y[tr])
    cm = C.rf().fit(np.hstack([Xh, Xn])[tr], y[tr])
    ih, inn = np.zeros(len(tr)), np.zeros(len(tr))
    inner = StratifiedGroupKFold(min(5, len(set(g[tr]))), shuffle=True, random_state=C.INNER_SEED)
    for itr, ite in inner.split(Xh[tr], y[tr], g[tr]):
        a, b = tr[itr], tr[ite]
        ih[ite] = C.rf().fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
        inn[ite] = C.rf().fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
    st = C.stacker().fit(np.column_stack([ih, inn]), y[tr])
    return hm, nm, cm, st


def _predict_stream(models, Xh, Xn):
    hm, nm, cm, st = models
    ph, pn = hm.predict_proba(Xh)[:, 1], nm.predict_proba(Xn)[:, 1]
    return {"host": ph, "network": pn, "concat": cm.predict_proba(np.hstack([Xh, Xn]))[:, 1],
            "stacked": st.predict_proba(np.column_stack([ph, pn]))[:, 1]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=10)
    ap.add_argument("--skip-stream", action="store_true")
    a = ap.parse_args()
    rows, hc, nc = C.load()
    H, N, _, _ = C.per_window(rows, hc, nc)
    y = C.labels(rows)
    assert np.allclose(C.summarize(H), C.matrix(rows, hc)) and np.allclose(C.summarize(N), C.matrix(rows, nc))
    gen = np.asarray([r["category"] in ("malware", "benign") for r in rows])
    split = np.asarray([r["split"] for r in rows])
    D.update(H=H, N=N, y=y, groups={n: f(rows) for n, f in GROUPINGS.items()},
             tr=np.flatnonzero(gen & (split == "train")), te=np.flatnonzero(gen & (split == "test")))
    C.CACHE.mkdir(exist_ok=True)

    t0 = time.time()
    jobs = []
    for name in GROUPINGS:
        for k in (PREFIXES if name == "published" else [40]):
            if not (C.CACHE / ("cv_%s_k%d.npz" % (name, k))).exists():
                jobs += [(name, k, s) for s in C.FOLD_SEEDS]
    hjobs = [(k, 42) for k in PREFIXES] + [(40, s) for s in RF_SEEDS if s != 42]
    hjobs = [j for j in hjobs if not (C.CACHE / "heldout_k40.npz").exists() or j[0] != 40]
    with Pool(a.jobs) as pool:
        res = pool.map(cv_job, jobs, chunksize=1)
        hres = pool.map(heldout_job, hjobs, chunksize=1) if hjobs else []
    by = {}
    for name, k, seed, oof, folds in res:
        by.setdefault((name, k), {})[seed] = (oof, folds)
    for (name, k), d in by.items():
        P = {det: np.stack([d[s][0][det] for s in C.FOLD_SEEDS]) for det in C.DETECTORS}
        F = np.stack([d[s][1] for s in C.FOLD_SEEDS])
        np.savez_compressed(C.CACHE / ("cv_%s_k%d.npz" % (name, k)), folds=F, seeds=np.asarray(C.FOLD_SEEDS), **P)
    hb = {}
    for k, rs, p in hres:
        hb.setdefault(k, {})[rs] = p
    for k, d in hb.items():
        arrays = {"%s__rf%d" % (det, rs): p[det] for rs, p in d.items() for det in C.DETECTORS}
        np.savez_compressed(C.CACHE / ("heldout_k%d.npz" % k), te=D["te"], **arrays)
    print("cv+heldout done in %.0f s (%d cv jobs, %d heldout jobs)" % (time.time() - t0, len(jobs), len(hjobs)))

    if not a.skip_stream and not (C.CACHE / "stream.npz").exists():
        t0 = time.time()
        with Pool(a.jobs) as pool:
            sres = dict(pool.map(stream_job, C.FOLD_SEEDS, chunksize=1))
        arrays = {det: np.stack([sres[s][det] for s in C.FOLD_SEEDS]) for det in C.DETECTORS}
        np.savez_compressed(C.CACHE / "stream.npz", prefixes=np.asarray(STREAM_PREFIXES),
                            seeds=np.asarray(C.FOLD_SEEDS), **arrays)
        print("stream done in %.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
