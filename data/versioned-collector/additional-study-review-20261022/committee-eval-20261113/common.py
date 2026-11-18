"""Shared loader and models for the committee-response analyses (2026-11-13).

Everything here reproduces the published setup first (release repo features.csv, Table IV held-out split,
Table V grouped CV with ten fold assignments) and only then adds new analyses on top. Offline only.

Rows are the 240 executions of the release dataset, in file order. Each row is mapped to its run directory so
per-window telemetry (40 windows x 18 host signals and 29 switch signals), packet captures and system-call
traces can be read for time-to-detection, baselines and simulations.
"""

import csv
import glob
import json
import math
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent  # additional-study-review-20261022
RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
FEATURES = RELEASE / "dataset" / "features.csv"
POOL = STUDY / "paper-check-20261028" / "independent_pool.json"
REV5 = STUDY / "revision5-collection/20261025T100025568989Z"
RT = STUDY / "realtools-collect/20261026T165642798242Z"
DV = STUDY / "flood21-collect/20261026T154421063760Z"
X1 = STUDY / "flood21-collect/20261026T150016786262Z"
X2 = STUDY / "flood21-collect/20261026T151240756153Z"
CACHE = HERE / "cache"

FOLD_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
INNER_SEED = 7
STATS = ("mean", "max", "sum", "std", "active_windows")
DETECTORS = ("host", "network", "concat", "stacked")


# ----------------------------------------------------------------------------------------------- data
def load():
    """Rows of features.csv in file order, with the 90 host and 145 network column names."""
    with open(FEATURES, newline="") as f:
        rows = list(csv.DictReader(f))
    host = [c for c in rows[0] if c.startswith("host_")]
    net = [c for c in rows[0] if c.startswith("net_")]
    assert len(rows) == 240 and len(host) == 90 and len(net) == 145
    return rows, host, net


def signals(columns):
    """Signal names in column order (each signal has the five summary columns, signal-major)."""
    out = []
    for c in columns:
        s = c.rsplit("__", 1)[0]
        if s not in out:
            out.append(s)
    for i, s in enumerate(out):
        assert columns[5 * i:5 * i + 5] == ["%s__%s" % (s, st) for st in STATS], s
    return out


def matrix(rows, columns):
    return np.asarray([[float(r[c]) for c in columns] for r in rows])


def labels(rows):
    return np.asarray([int(r["label"]) for r in rows])


def run_dirs(rows):
    """Run directory (the .../runs/<sample> folder) for every row, via the frozen pool order."""
    pool = json.loads(POOL.read_text())
    assert len(pool) == len(rows)
    flood_root = {"general_malware": REV5, "cli_benign": REV5}
    x1 = {"bulkdl", "nullidle"}
    out = []
    for p, r in zip(pool, rows):
        s = p["sample"]
        assert int(p["label"]) == int(r["label"]), (s, r["execution_id"])
        if p["stratum"] in flood_root:
            d = REV5 / "runs" / s
            key = r["sha256"] if r["category"] == "malware" else r["program"]
            assert key and key in s, (s, r["execution_id"])
        elif p["stratum"].startswith("flood_"):
            d = RT / "runs" / (s + ".zip")
        elif s in x1:
            d = X1 / "runs" / (s + ".zip")
        elif s.startswith("bulk") and not s.startswith("bulkup"):
            d = X2 / "runs" / (s + ".zip")
        else:
            d = DV / "runs" / (s + ".zip")
        if p["stratum"] not in flood_root:
            assert r["execution_id"] == s, (s, r["execution_id"])
        assert d.is_dir(), d
        out.append(d)
    return out


def output_dir(run_dir):
    hits = glob.glob(str(Path(run_dir) / "output" / "run_*"))
    assert len(hits) == 1, run_dir
    return Path(hits[0])


def per_window(rows, host_cols, net_cols, use_cache=True):
    """Arrays H (n,40,18) and N (n,40,29) of per-window signals, in the signal order of the columns."""
    hs, ns = signals(host_cols), signals(net_cols)
    cache = CACHE / "windows.npz"
    if use_cache and cache.exists():
        z = np.load(cache, allow_pickle=False)
        if list(z["host_signals"]) == hs and list(z["net_signals"]) == ns:
            return z["H"], z["N"], hs, ns
    H = np.zeros((len(rows), 40, len(hs)))
    N = np.zeros((len(rows), 40, len(ns)))
    for i, d in enumerate(run_dirs(rows)):
        tel = output_dir(d) / "telemetry.csv"
        w = list(csv.DictReader(open(tel, newline="", encoding="utf-8-sig")))
        assert len(w) == 40, tel
        H[i] = [[float(x[s]) for s in hs] for x in w]
        N[i] = [[float(x[s]) for s in ns] for x in w]
    CACHE.mkdir(exist_ok=True)
    np.savez_compressed(cache, H=H, N=N, host_signals=np.asarray(hs), net_signals=np.asarray(ns))
    return H, N, hs, ns


def summarize(W, k=None):
    """Five summaries (mean, max, sum, std, active windows) of the first k windows, signal-major columns."""
    W = W[:, :k] if k else W
    mean, mx, sm = W.mean(1), W.max(1), W.sum(1)
    std, act = W.std(1), (W != 0).sum(1).astype(float)
    out = np.stack([mean, mx, sm, std, act], axis=2)  # n, sig, 5
    return out.reshape(W.shape[0], -1)


# --------------------------------------------------------------------------------------------- groups
def groups_published(rows):
    return np.asarray([r["cv_group"] for r in rows])


def groups_by_attack_type(rows):
    """Network-attack runs grouped by attack type (syn, udp, slowloris, goldeneye); all else as published."""
    return np.asarray(["attack::" + r["attack_type"] if r["category"] == "network_attack" else r["cv_group"]
                       for r in rows])


def groups_by_implementation(rows):
    """Network-attack runs grouped by implementation: the C generator (SYN, UDP) vs the Python tools."""
    impl = {"syn_flood": "c_generator", "udp_flood": "c_generator", "slowloris": "python", "goldeneye": "python"}
    return np.asarray(["attackimpl::" + impl[r["attack_type"]] if r["category"] == "network_attack" else r["cv_group"]
                       for r in rows])


# --------------------------------------------------------------------------------------------- models
def rf(seed=42):
    return RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=seed, n_jobs=1)


def stacker():
    return LogisticRegression(max_iter=2000, class_weight="balanced")


def fit_predict(Xh, Xn, y, groups, tr, te, rf_seed=42, detectors=DETECTORS):
    """Probabilities on te for each detector, trained on tr (the paper's definitions)."""
    out = {}
    need_base = {"host", "network", "stacked"} & set(detectors)
    if need_base:
        ph = rf(rf_seed).fit(Xh[tr], y[tr]).predict_proba(Xh[te])[:, 1]
        pn = rf(rf_seed).fit(Xn[tr], y[tr]).predict_proba(Xn[te])[:, 1]
        if "host" in detectors:
            out["host"] = ph
        if "network" in detectors:
            out["network"] = pn
    if "concat" in detectors:
        Xc = np.hstack([Xh, Xn])
        out["concat"] = rf(rf_seed).fit(Xc[tr], y[tr]).predict_proba(Xc[te])[:, 1]
    if "stacked" in detectors:
        ih, inn = np.zeros(len(tr)), np.zeros(len(tr))
        g = groups[tr]
        inner = StratifiedGroupKFold(min(5, len(set(g))), shuffle=True, random_state=INNER_SEED)
        for itr, ite in inner.split(Xh[tr], y[tr], g):
            a, b = tr[itr], tr[ite]
            ih[ite] = rf(rf_seed).fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
            inn[ite] = rf(rf_seed).fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
        st = stacker().fit(np.column_stack([ih, inn]), y[tr])
        out["stacked"] = st.predict_proba(np.column_stack([ph, pn]))[:, 1]
    return out


def cv_oof(Xh, Xn, y, groups, seed, rf_seed=42, detectors=DETECTORS):
    """Out-of-fold probabilities for one fold assignment (outer StratifiedGroupKFold(5, shuffle, seed))."""
    oof = {d: np.zeros(len(y)) for d in detectors}
    folds = np.zeros(len(y), dtype=int)
    for f, (tr, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, groups)):
        folds[te] = f
        for d, p in fit_predict(Xh, Xn, y, groups, tr, te, rf_seed, detectors).items():
            oof[d][te] = p
    return oof, folds


def _cv_job(args):
    Xh, Xn, y, groups, seed, rf_seed, detectors = args
    oof, folds = cv_oof(Xh, Xn, y, groups, seed, rf_seed, detectors)
    return seed, oof, folds


def cv_all(Xh, Xn, y, groups, seeds=FOLD_SEEDS, rf_seed=42, detectors=DETECTORS, jobs=10):
    """OOF probabilities for every fold assignment: dict detector -> (len(seeds), n), and folds (len(seeds), n)."""
    from multiprocessing import Pool
    args = [(Xh, Xn, y, groups, s, rf_seed, detectors) for s in seeds]
    if jobs > 1:
        with Pool(min(jobs, len(args))) as p:
            res = p.map(_cv_job, args)
    else:
        res = [_cv_job(a) for a in args]
    res.sort(key=lambda t: seeds.index(t[0]))
    P = {d: np.stack([r[1][d] for r in res]) for d in detectors}
    F = np.stack([r[2] for r in res])
    return P, F


# -------------------------------------------------------------------------------------------- metrics
def metrics(y, prob, threshold=0.5):
    pred = (prob >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    rec = tp / (tp + fn) if tp + fn else float("nan")
    spec = tn / (tn + fp) if tn + fp else float("nan")
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    auc = float(roc_auc_score(y, prob)) if len(set(y)) == 2 else float("nan")
    return {"balanced_accuracy": (rec + spec) / 2, "auc": auc, "recall": rec, "specificity": spec,
            "precision": prec, "f1": f1, "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def ba(y, pred):
    pos, neg = y == 1, y == 0
    return 0.5 * ((pred[pos] == 1).mean() + (pred[neg] == 0).mean())


def mcnemar_exact(y, pred_a, pred_b):
    """Exact two-sided McNemar test on the discordant pairs (A right/B wrong vs A wrong/B right)."""
    a_ok, b_ok = pred_a == y, pred_b == y
    b = int((a_ok & ~b_ok).sum())  # only A correct
    c = int((~a_ok & b_ok).sum())  # only B correct
    n = b + c
    if n == 0:
        return {"only_a_correct": b, "only_b_correct": c, "p": 1.0}
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n * 2
    return {"only_a_correct": b, "only_b_correct": c, "p": min(1.0, p)}


def cluster_bootstrap_indices(y, groups, n_boot, seed):
    """Resample whole groups with replacement, separately within each class (groups are class-pure here)."""
    rng = np.random.default_rng(seed)
    by_class = {}
    for g in np.unique(groups):
        idx = np.flatnonzero(groups == g)
        cls = int(round(y[idx].mean()))
        assert set(y[idx]) == {cls}, g
        by_class.setdefault(cls, []).append(idx)
    for _ in range(n_boot):
        parts = []
        for cls, members in by_class.items():
            pick = rng.integers(0, len(members), len(members))
            parts.extend(members[i] for i in pick)
        yield np.concatenate(parts)


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, default=lambda o: o.tolist() if hasattr(o, "tolist") else str(o))
