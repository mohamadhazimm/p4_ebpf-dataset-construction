"""Pure NIDS baseline: Kitsune / KitNET (Mirsky et al., NDSS 2018), unsupervised, official KitNET code.

Input: per-packet AfterImage vectors from kitsune_extract.py (official FE/netStat/AfterImage, first 20,000
in-window packets of each run).

Training (per fold, benign training rows only):
  * from every benign training run, at most RUN_CAP = 4,000 of its packet vectors (random subset, generator
    seeded with the row number, so a run contributes the same packets whenever it is in a training set);
  * the pooled packets are shuffled (fixed seed) and fed one by one to the official KitNET.process(), with the
    paper's settings: max autoencoder size 10, learning rate 0.1, hidden ratio 0.75, and the official example's
    grace periods FM = 5,000 and AD = 50,000 (stream of FM + AD + 1 packets); when fewer packets are available
    the two grace periods keep the same 1:10 ratio.
Scoring: KitNET's execute() (RMSE of the output autoencoder) for every packet of a run, computed in batch with the
trained weights (same arithmetic; checked against the official per-packet execute() on sampled packets).
Run score = maximum RMSE over the run's packets (also reported: 99th percentile and mean); a run without packets
gets the lowest score (0). Threshold, from the training side only: 95th percentile of held-out training-benign run
scores (5 inner group folds, each with its own KitNET trained on the other 4); flag if score > threshold; second
operating point: maximum of the held-out scores.

    /usr/bin/python3 kitsune_eval.py
"""
import contextlib
import io
import sys
from multiprocessing import Pool

import numpy as np

import bl_common as B

SRC = B.VENDOR / "kitsune-py" / "src"
RUN_CAP = 4000
FM_GRACE, AD_GRACE = 5000, 50000
MAX_AE, LR, HR = 10, 0.1, 0.75
STREAM_SEED = 42
AGGS = ("max", "p99", "mean")
D = {}


def import_kitnet():
    sys.path.insert(0, str(SRC))
    np.Inf = np.inf  # alias removed in NumPy 2.0; same value (used by KitNET/dA.py)
    from KitNET.KitNET import KitNET  # noqa: E402
    return KitNET


def sigmoid(x):
    return 1.0 / (1 + np.exp(-x))


def batch_execute(K, X):
    """KitNET.execute() for every row of X (same operations as dA.execute / KitNET.execute, vectorized)."""
    S = np.zeros((len(X), len(K.ensembleLayer)))
    with np.errstate(all="ignore"):
        for a, ae in enumerate(K.ensembleLayer):
            xi = X[:, K.v[a]]
            xn = (xi - ae.norm_min) / (ae.norm_max - ae.norm_min + 0.0000000000000001)
            z = sigmoid(np.dot(sigmoid(np.dot(xn, ae.W) + ae.hbias), ae.W_prime) + ae.vbias)
            S[:, a] = np.sqrt(((xn - z) ** 2).mean(axis=1))
        o = K.outputLayer
        sn = (S - o.norm_min) / (o.norm_max - o.norm_min + 0.0000000000000001)
        z = sigmoid(np.dot(sigmoid(np.dot(sn, o.W) + o.hbias), o.W_prime) + o.vbias)
        return np.sqrt(((sn - z) ** 2).mean(axis=1))


def training_stream(rows_idx):
    parts = []
    for i in rows_idx:
        V = D["vec"][i]
        if len(V) > RUN_CAP:
            V = V[np.sort(np.random.default_rng(1000 + int(i)).choice(len(V), RUN_CAP, replace=False))]
        parts.append(V)
    X = np.concatenate(parts) if parts else np.zeros((0, 100))
    X = X[np.random.default_rng(STREAM_SEED).permutation(len(X))]
    n = min(len(X), FM_GRACE + AD_GRACE + 1)
    fm = FM_GRACE if n == FM_GRACE + AD_GRACE + 1 else max(1, int(round(n * FM_GRACE / (FM_GRACE + AD_GRACE + 1))))
    ad = n - fm - 1
    return X[:n], fm, ad


def train(rows_idx):
    KitNET = D["KitNET"]
    X, fm, ad = training_stream(rows_idx)
    with contextlib.redirect_stdout(io.StringIO()):
        K = KitNET(X.shape[1], MAX_AE, fm, ad, LR, HR)
        for x in X:
            K.process(x)
    assert K.n_trained == fm + ad + 1 and K.v is not None
    return K, {"packets": int(len(X)), "fm_grace": fm, "ad_grace": ad, "autoencoders": len(K.v)}


def run_scores(K, idx):
    out = np.zeros((len(idx), len(AGGS)))
    for j, i in enumerate(idx):
        V = D["vec"][i]
        if len(V):
            r = batch_execute(K, V)
            out[j] = [r.max(), np.percentile(r, 99), r.mean()]
    return out


def check_equivalence(K, idx, n=300, seed=0):
    """Max |batch - official execute()| on sampled packets of the given runs."""
    rng = np.random.default_rng(seed)
    pool = [(i, k) for i in idx for k in range(len(D["vec"][i]))]
    if not pool:
        return 0.0
    pick = rng.choice(len(pool), min(n, len(pool)), replace=False)
    X = np.asarray([D["vec"][pool[p][0]][pool[p][1]] for p in pick])
    with contextlib.redirect_stdout(io.StringIO()):
        off = np.asarray([K.execute(x) for x in X])
    return float(np.max(np.abs(off - batch_execute(K, X)) / np.maximum(1.0, np.abs(off))))


def fit_score(trb, te, g, check=False):
    inner, k = B.inner_benign_folds(g[trb])
    held = np.zeros((len(trb), len(AGGS)))
    for j in range(k):
        Kj, _ = train(trb[inner != j])
        held[inner == j] = run_scores(Kj, trb[inner == j])
    thr95 = np.asarray([B.threshold_from(held[:, a]) for a in range(len(AGGS))])
    thrmax = held.max(axis=0)
    K, info = train(trb)
    s = run_scores(K, te)
    if check:
        info["max_rel_diff_batch_vs_official"] = check_equivalence(K, te)
    return s, thr95, thrmax, info


def _assignment(k):
    y, g, F = D["y"], D["g"], D["F"]
    n = len(y)
    raw = np.zeros((n, len(AGGS))); t95 = np.zeros((n, len(AGGS))); tmax = np.zeros((n, len(AGGS)))
    infos = []
    for f in range(5):
        tr, te = np.flatnonzero(F[k] != f), np.flatnonzero(F[k] == f)
        trb = tr[y[tr] == 0]
        s, a, b, info = fit_score(trb, te, g, check=(f == 0))
        raw[te] = s; t95[te] = a; tmax[te] = b
        infos.append(info)
    B.log("assignment", B.C.FOLD_SEEDS[k], "done", infos[0])
    return k, raw, t95, tmax, infos


def _table4(_):
    y, g, cat, split = D["y"], D["g"], D["cat"], D["split"]
    tr, te = B.table4_split(cat, split)
    trb = tr[y[tr] == 0]
    return fit_score(trb, te, g, check=True), te


def margin(raw, thr):
    with np.errstate(divide="ignore"):
        m = np.log10(np.maximum(raw, 1e-300) / np.where(thr > 0, thr, 1e-300))
    return m


def main():
    rows, y, g, cat, split, mode = B.dataset()
    F = B.table5_folds(y, g)
    vec = [np.load(B.CACHE / "kitsune" / "vec" / ("%03d.npy" % i)) for i in range(len(rows))]
    assert all(v.shape[1] == 100 and np.isfinite(v).all() for v in vec if len(v))
    D.update(y=y, g=g, F=F, cat=cat, split=split, vec=vec, KitNET=import_kitnet())
    jobs = list(range(len(B.C.FOLD_SEEDS)))
    with Pool(min(B.MAX_JOBS, len(jobs) + 1)) as p:
        t4 = p.apply_async(_table4, (0,))
        res = p.map(_assignment, jobs, chunksize=1)
        (s4, a4, b4, info4), te = t4.get()
    res.sort(key=lambda t: t[0])
    raw = np.stack([r[1] for r in res]); t95 = np.stack([r[2] for r in res]); tmax = np.stack([r[3] for r in res])
    out = {"settings": {"run_cap_training_packets": RUN_CAP, "fm_grace": FM_GRACE, "ad_grace": AD_GRACE,
                        "max_autoencoder_size": MAX_AE, "learning_rate": LR, "hidden_ratio": HR,
                        "packets_per_run": "first 20,000 in-window packets (kitsune_extract.py)",
                        "threshold": "95th percentile of inner held-out training-benign run scores (5 group folds)"},
           "training_info_table5": [r[4] for r in res], "training_info_table4": info4, "table5": {}, "table4": {}}
    for a, agg in enumerate(AGGS):
        pred95 = (raw[:, :, a] > t95[:, :, a]).astype(int)
        predmax = (raw[:, :, a] > tmax[:, :, a]).astype(int)
        out["table5"][agg] = {"p95": B.summarize_table5(y, cat, margin(raw[:, :, a], t95[:, :, a]), pred95),
                              "max": B.summarize_table5(y, cat, margin(raw[:, :, a], tmax[:, :, a]), predmax)}
        B.save_scores("kitsune_%s_table5" % agg, score=margin(raw[:, :, a], t95[:, :, a]), pred=pred95,
                      pred_max=predmax, raw=raw[:, :, a], threshold=t95[:, :, a], threshold_max=tmax[:, :, a],
                      folds=F)
        pred4 = (s4[:, a] > a4[a]).astype(int)
        predm4 = (s4[:, a] > b4[a]).astype(int)
        out["table4"][agg] = {"threshold_p95": float(a4[a]), "threshold_max": float(b4[a]),
                              "p95": B.summarize_table4(y, cat, te, s4[:, a], pred4),
                              "max": B.summarize_table4(y, cat, te, s4[:, a], predm4)}
        B.save_scores("kitsune_%s_table4" % agg, test_index=te, score=s4[:, a], pred=pred4, pred_max=predm4,
                      threshold=a4[a], threshold_max=b4[a])
        t5 = out["table5"][agg]["p95"]; t4s = out["table4"][agg]["p95"]
        B.log("kitsune %-4s TableV BA %s AUC %s | TableIV BA %.3f AUC %.3f" % (
            agg, B.fmt(t5["balanced_accuracy"]), B.fmt(t5["auc"]), t4s["balanced_accuracy"], t4s["auc"]))
    B.write_json(B.RESULTS / "kitsune.json", out)


if __name__ == "__main__":
    sys.exit(main())
