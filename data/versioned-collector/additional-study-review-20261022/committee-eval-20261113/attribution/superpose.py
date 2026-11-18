"""Window-level vs socket-level join with concurrent programs (committee item 4). Offline, exact simulation.

Every test execution (the target) is replayed together with k other executions on the same host (or on hosts
behind the switch that the join cannot tell apart). Host features stay the target's own: eBPF attributes system
calls to processes natively. The switch features differ by join:
  socket join   the target's own flows only (flows mapped to processes through their sockets) = dataset features
  window join   every flow of the window: the target's plus all co-runners' (the current design's assumption
                that one program runs per window)
Co-runners start 0-10 s after the target (whole windows) and come from the same test fold (never in training).

Scenarios
  A  k benign co-runners, k in 0,1,2,4,8
  B  one malicious co-runner plus k-1 benign ones (k >= 1): does a benign program get flagged for sharing the host?
Arms
  socket                    detectors trained on single-program data, target features = own flows
  window                    same detectors, target switch features from all flows
  window_trained_on_mixtures  detectors retrained on k-matched mixtures of the training fold (scenario A only)

    /usr/bin/python3 superpose.py [--jobs 8] [--mixtures 5]
"""
import argparse
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import common as C  # noqa: E402
import components as K  # noqa: E402

KS = [0, 1, 2, 4, 8]
MAX_SHIFT = 20  # windows (10 s)
D = {}


def net_summary(parts):
    feats = K.features(K.combine(parts))  # 40 x 29 in switch_model order
    return C.summarize(feats[None, :, D["order"]])[0]


def mixture_features(t, co, shifts):
    return net_summary([D["A"][t]] + [K.shifted(D["A"][b], s) for b, s in zip(co, shifts)])


def fit_models(Xh, Xn, y, g, tr):
    hm = C.rf().fit(Xh[tr], y[tr]); nm = C.rf().fit(Xn[tr], y[tr])
    cm = C.rf().fit(np.hstack([Xh, Xn])[tr], y[tr])
    ih, inn = np.zeros(len(tr)), np.zeros(len(tr))
    inner = StratifiedGroupKFold(min(5, len(set(g[tr]))), shuffle=True, random_state=C.INNER_SEED)
    for itr, ite in inner.split(Xh[tr], y[tr], g[tr]):
        a, b = tr[itr], tr[ite]
        ih[ite] = C.rf().fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
        inn[ite] = C.rf().fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
    return hm, nm, cm, C.stacker().fit(np.column_stack([ih, inn]), y[tr])


def predict(models, Xh, Xn):
    hm, nm, cm, st = models
    ph, pn = hm.predict_proba(Xh)[:, 1], nm.predict_proba(Xn)[:, 1]
    return {"host": ph, "network": pn, "concat": cm.predict_proba(np.hstack([Xh, Xn]))[:, 1],
            "stacked": st.predict_proba(np.column_stack([ph, pn]))[:, 1]}


def job(args):
    seed, M = args
    y, g, Xh, Xn = D["y"], D["g"], D["Xh"], D["Xn"]
    rng = np.random.default_rng(10_000 + seed)
    benign_all, malicious_all = np.flatnonzero(y == 0), np.flatnonzero(y == 1)
    recs = []  # (arm, scenario, k, target, mixture, detector probs...)
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        te_b, te_m = np.intersect1d(te, benign_all), np.intersect1d(te, malicious_all)
        tr_b = np.intersect1d(tr, benign_all)
        clean = fit_models(Xh, Xn, y, g, tr)
        for k in KS:
            # mixtures of the test targets
            for scen in ("A", "B"):
                if scen == "B" and k == 0:
                    continue
                rows_h, rows_n, meta = [], [], []
                for t in te:
                    for m in range(M if k else 1):
                        if scen == "A":
                            pool = te_b[te_b != t]
                            co = rng.choice(pool, size=min(k, len(pool)), replace=False) if k else np.array([], int)
                        else:
                            mal = te_m[te_m != t]
                            pool = te_b[te_b != t]
                            co = np.concatenate([rng.choice(mal, 1), rng.choice(pool, size=min(k - 1, len(pool)), replace=False)])
                        shifts = rng.integers(0, MAX_SHIFT + 1, size=len(co))
                        rows_h.append(Xh[t]); rows_n.append(mixture_features(t, co, shifts) if k else Xn[t])
                        meta.append((t, m))
                Ph = np.asarray(rows_h); Pn = np.asarray(rows_n)
                P_window = predict(clean, Ph, Pn)
                P_socket = predict(clean, Ph, Xn[[t for t, _ in meta]])
                for arm, P in (("socket", P_socket), ("window", P_window)):
                    for j, (t, m) in enumerate(meta):
                        recs.append((arm, scen, k, int(t), m, *[float(P[d][j]) for d in C.DETECTORS]))
            # detectors retrained on k-matched mixtures of the training fold (scenario A)
            if k:
                aug_h, aug_n, aug_y, aug_g = [Xh[tr]], [Xn[tr]], [y[tr]], [g[tr]]
                for rep in range(2):
                    mix = []
                    for t in tr:
                        pool = tr_b[tr_b != t]
                        co = rng.choice(pool, size=min(k, len(pool)), replace=False)
                        mix.append(mixture_features(t, co, rng.integers(0, MAX_SHIFT + 1, size=len(co))))
                    aug_h.append(Xh[tr]); aug_n.append(np.asarray(mix)); aug_y.append(y[tr]); aug_g.append(g[tr])
                AXh, AXn = np.vstack(aug_h), np.vstack(aug_n)
                Ay, Ag = np.concatenate(aug_y), np.concatenate(aug_g)
                aug_models = fit_models(AXh, AXn, Ay, Ag, np.arange(len(Ay)))
                # score fresh test mixtures drawn the same way as scenario A
                rows_h, rows_n, meta = [], [], []
                for t in te:
                    for m in range(M):
                        pool = te_b[te_b != t]
                        co = rng.choice(pool, size=min(k, len(pool)), replace=False)
                        rows_h.append(Xh[t]); rows_n.append(mixture_features(t, co, rng.integers(0, MAX_SHIFT + 1, size=len(co))))
                        meta.append((t, m))
                P = predict(aug_models, np.asarray(rows_h), np.asarray(rows_n))
                for j, (t, m) in enumerate(meta):
                    recs.append(("window_trained_on_mixtures", "A", k, int(t), m, *[float(P[d][j]) for d in C.DETECTORS]))
    return seed, recs


def summarize_records(recs_by_seed, rows, y):
    cats = np.asarray([r["category"] for r in rows])
    out = {}
    keys = sorted({(r[0], r[1], r[2]) for recs in recs_by_seed.values() for r in recs})
    for arm, scen, k in keys:
        per_seed = {d: [] for d in C.DETECTORS}
        cat_rates = {}
        for seed, recs in recs_by_seed.items():
            sel = [r for r in recs if (r[0], r[1], r[2]) == (arm, scen, k)]
            t = np.asarray([r[3] for r in sel])
            yy = y[t]
            for j, d in enumerate(C.DETECTORS):
                p = np.asarray([r[5 + j] for r in sel]) >= 0.5
                per_seed[d].append(C.ba(yy, p.astype(int)))
                for c in ("malware", "network_attack", "benign", "network_benign", "null"):
                    m = cats[t] == c
                    if m.any():
                        cat_rates.setdefault(c, {}).setdefault(d, []).append(p[m].mean())
        out["%s|%s|k=%d" % (arm, scen, k)] = {
            "ba": {d: {"mean": round(float(np.mean(v)), 3), "sd": round(float(np.std(v, ddof=1)), 3)} for d, v in per_seed.items()},
            "flag_rate": {c: {d: round(float(np.mean(v)), 3) for d, v in dd.items()} for c, dd in cat_rates.items()}}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--mixtures", type=int, default=5)
    a = ap.parse_args()
    rows, hc, nc = C.load()
    H, N, hs, ns = C.per_window(rows, hc, nc)
    A = np.load(C.CACHE / "components.npz")["A"]
    import switch_model as SM
    order = [SM.FEATURES.index(s) for s in ns]  # switch_model order -> dataset signal order
    D.update(A=A, y=C.labels(rows), g=C.groups_published(rows), Xh=C.matrix(rows, hc), Xn=C.matrix(rows, nc), order=order)
    # exactness check: a mixture of one equals the dataset features
    chk = np.asarray([net_summary([A[i]]) for i in range(len(rows))])
    assert np.allclose(chk, D["Xn"], rtol=1e-12, atol=1e-9), np.abs(chk - D["Xn"]).max()
    with Pool(a.jobs) as p:
        res = dict(p.map(job, [(s, a.mixtures) for s in C.FOLD_SEEDS], chunksize=1))
    summary = summarize_records(res, rows, D["y"])
    C.write_json(C.HERE / "results" / "attribution_superposition.json",
                 {"ks": KS, "max_shift_windows": MAX_SHIFT, "mixtures_per_target": a.mixtures, "summary": summary})
    np.savez_compressed(C.CACHE / "superpose_records.npz",
                        **{"seed%d" % s: np.asarray([r[2:] for r in recs], float) for s, recs in res.items()},
                        **{"seed%d_labels" % s: np.asarray(["%s|%s" % (r[0], r[1]) for r in recs]) for s, recs in res.items()})
    print("wrote results/attribution_superposition.json")


if __name__ == "__main__":
    main()
