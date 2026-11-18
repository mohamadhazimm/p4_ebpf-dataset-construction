"""Feature importance for committee item 2: do the detectors learn behaviour or artifacts? Offline.

1. Grouped permutation importance: the five summary columns of one signal are shuffled together (among the
   held-out rows of each fold), so correlated summaries of the same signal cannot mask each other.
   Table V protocol (ten fold assignments, out-of-fold, 5 shuffles) and Table IV held-out (30 shuffles).
2. Summary-family permutation: all columns of one statistic (e.g. every `active_windows` column = how many
   windows a signal was non-zero, i.e. lifetime-like; every `sum` column = volume-like) shuffled at once.
3. Drop-and-retrain (Table V protocol): host detector without the volume signals (total system calls,
   transitions), without all `active_windows`/`sum` columns, and the shape-only variant (means/max/std of the
   normalised signals only).

    /usr/bin/python3 importance.py [--jobs 10]
"""
import argparse
from multiprocessing import Pool

import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

import common as C

REPEATS_CV, REPEATS_T4 = 5, 30
VOLUME_HOST = ["host_total_syscalls_total", "host_transition_count_total"]
D = {}


def column_groups(cols):
    sig = {}
    for i, c in enumerate(cols):
        sig.setdefault(c.rsplit("__", 1)[0], []).append(i)
    stat = {}
    for i, c in enumerate(cols):
        stat.setdefault("ALL__" + c.rsplit("__", 1)[1], []).append(i)
    return {**sig, **stat}


def permuted_predictions(model, X, groups, rng, repeats):
    """dict group -> (repeats, rows) predictions with that column group shuffled among the rows."""
    out = {}
    for name, idx in groups.items():
        preds = []
        for _ in range(repeats):
            Xp = X.copy()
            perm = rng.permutation(len(X))
            Xp[:, idx] = X[perm][:, idx]
            preds.append(model.predict_proba(Xp)[:, 1])
        out[name] = np.asarray(preds)
    return out


def cv_job(seed):
    y, g = D["y"], D["g"]
    rng = np.random.default_rng(1000 + seed)
    res = {}
    for det, X, groups in (("host", D["Xh"], D["gh"]), ("network", D["Xn"], D["gn"]), ("concat", D["Xc"], D["gc"])):
        base = np.zeros(len(y))
        perm = {name: np.zeros((REPEATS_CV, len(y))) for name in groups}
        for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, g):
            m = C.rf().fit(X[tr], y[tr])
            base[te] = m.predict_proba(X[te])[:, 1]
            for name, P in permuted_predictions(m, X[te], groups, rng, REPEATS_CV).items():
                perm[name][:, te] = P
        b_auc, b_ba = roc_auc_score(y, base), C.ba(y, (base >= .5).astype(int))
        res[det] = {name: (b_auc - np.mean([roc_auc_score(y, P[r]) for r in range(REPEATS_CV)]),
                           b_ba - np.mean([C.ba(y, (P[r] >= .5).astype(int)) for r in range(REPEATS_CV)]))
                    for name, P in perm.items()}
    return seed, res


def drop_job(args):
    seed, name, cols = args
    y, g = D["y"], D["g"]
    X = D["Xh"][:, cols]
    oof = np.zeros(len(y))
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, g):
        oof[te] = C.rf().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
    return name, seed, C.metrics(y, oof)["balanced_accuracy"], C.metrics(y, oof)["auc"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=10)
    a = ap.parse_args()
    rows, hc, nc = C.load()
    y = C.labels(rows)
    Xh, Xn = C.matrix(rows, hc), C.matrix(rows, nc)
    D.update(y=y, g=C.groups_published(rows), Xh=Xh, Xn=Xn, Xc=np.hstack([Xh, Xn]),
             gh=column_groups(hc), gn=column_groups(nc), gc=column_groups(hc + nc))
    out = {"repeats_cv": REPEATS_CV, "repeats_table_iv": REPEATS_T4}

    with Pool(a.jobs) as pool:
        cv = dict(pool.map(cv_job, C.FOLD_SEEDS, chunksize=1))
    agg = {}
    for det in ("host", "network", "concat"):
        names = list(cv[C.FOLD_SEEDS[0]][det])
        agg[det] = sorted(({"group": n,
                            "auc_drop_mean": round(float(np.mean([cv[s][det][n][0] for s in C.FOLD_SEEDS])), 4),
                            "auc_drop_sd": round(float(np.std([cv[s][det][n][0] for s in C.FOLD_SEEDS], ddof=1)), 4),
                            "ba_drop_mean": round(float(np.mean([cv[s][det][n][1] for s in C.FOLD_SEEDS])), 4)}
                           for n in names), key=lambda r: -r["auc_drop_mean"])
    out["table_v_permutation"] = agg

    # Table IV held-out
    gen = np.asarray([r["category"] in ("malware", "benign") for r in rows])
    split = np.asarray([r["split"] for r in rows])
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    rng = np.random.default_rng(7)
    t4 = {}
    for det, X, groups in (("host", Xh, D["gh"]), ("network", Xn, D["gn"]), ("concat", D["Xc"], D["gc"])):
        m = C.rf().fit(X[tr], y[tr])
        base = m.predict_proba(X[te])[:, 1]
        b_auc, b_ba = roc_auc_score(y[te], base), C.ba(y[te], (base >= .5).astype(int))
        perm = permuted_predictions(m, X[te], groups, rng, REPEATS_T4)
        t4[det] = sorted(({"group": n,
                           "auc_drop_mean": round(float(b_auc - np.mean([roc_auc_score(y[te], p) for p in P])), 4),
                           "ba_drop_mean": round(float(b_ba - np.mean([C.ba(y[te], (p >= .5).astype(int)) for p in P])), 4)}
                          for n, P in perm.items()), key=lambda r: -r["auc_drop_mean"])
    out["table_iv_permutation"] = t4

    # drop and retrain (host detector, Table V protocol)
    sigs = C.signals(hc)
    keep = lambda pred: [i for i, c in enumerate(hc) if pred(c)]
    variants = {
        "all_90": keep(lambda c: True),
        "no_volume_signals": keep(lambda c: c.rsplit("__", 1)[0] not in VOLUME_HOST),
        "no_active_windows": keep(lambda c: not c.endswith("__active_windows")),
        "no_sum": keep(lambda c: not c.endswith("__sum")),
        "no_active_windows_no_sum": keep(lambda c: not c.endswith(("__active_windows", "__sum"))),
        "shape_only": keep(lambda c: c.rsplit("__", 1)[0] not in VOLUME_HOST
                           and not c.endswith(("__active_windows", "__sum"))),
        "volume_only": keep(lambda c: c.rsplit("__", 1)[0] in VOLUME_HOST),
        "active_windows_only": keep(lambda c: c.endswith("__active_windows")),
    }
    jobs = [(s, n, cols) for n, cols in variants.items() for s in C.FOLD_SEEDS]
    with Pool(a.jobs) as pool:
        dr = pool.map(drop_job, jobs, chunksize=1)
    out["host_drop_and_retrain"] = {}
    for n, cols in variants.items():
        b = [x[2] for x in dr if x[0] == n]; u = [x[3] for x in dr if x[0] == n]
        out["host_drop_and_retrain"][n] = {"n_columns": len(cols),
                                           "ba_mean": round(float(np.mean(b)), 3), "ba_sd": round(float(np.std(b, ddof=1)), 3),
                                           "auc_mean": round(float(np.mean(u)), 3)}
    # correlation of each host/network signal summary with overall activity (Spearman), for the artifact check
    from scipy.stats import spearmanr
    act = np.asarray([float(r["syscall_count"]) for r in rows])
    out["spearman_with_activity"] = {c: round(float(spearmanr(X_col, act).statistic), 3)
                                     for c, X_col in zip(hc + nc, np.hstack([Xh, Xn]).T)
                                     if np.std(X_col) > 0}
    C.write_json(C.HERE / "results" / "importance.json", out)
    print("wrote results/importance.json")


if __name__ == "__main__":
    main()
