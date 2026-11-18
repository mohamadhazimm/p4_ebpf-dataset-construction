"""Why E2d's interval of the stacked-minus-host edge touches zero and analyze_rigor.py's does not.

Same cached OOF predictions (Table V, ten assignments); 2 estimators x 2 resampling designs:
  estimator 'mean_ba'      : BA of each assignment's decisions, averaged (the published Table V statistic)
  estimator 'ensemble'     : BA of the decision on the probabilities averaged over assignments (E2d)
  resampling 'stratified'  : whole groups resampled within each class (class group counts fixed)
  resampling 'unstratified': whole groups resampled from all groups (E2d)
"""
import json
import numpy as np
import common as C

rows, hc, nc = C.load()
y, g = C.labels(rows), C.groups_published(rows)
z = np.load(C.CACHE / "cv_published_k40.npz")
S, H = z["stacked"], z["host"]
uniq = np.unique(g); idx_by = {u: np.flatnonzero(g == u) for u in uniq}
cls = {u: int(y[idx_by[u]][0]) for u in uniq}

def est(sel, kind):
    yy = y[sel]
    if kind == "mean_ba":
        return np.mean([C.ba(yy, (S[i][sel] >= .5).astype(int)) - C.ba(yy, (H[i][sel] >= .5).astype(int)) for i in range(len(S))])
    ms, mh = S.mean(0)[sel], H.mean(0)[sel]
    return C.ba(yy, (ms >= .5).astype(int)) - C.ba(yy, (mh >= .5).astype(int))

out = {}
for design in ("stratified", "unstratified"):
    rng = np.random.default_rng(42)
    pos = [u for u in uniq if cls[u] == 1]; neg = [u for u in uniq if cls[u] == 0]
    res = {"mean_ba": [], "ensemble": []}
    for _ in range(4000):
        if design == "stratified":
            pick = list(rng.choice(pos, len(pos))) + list(rng.choice(neg, len(neg)))
        else:
            pick = list(rng.choice(uniq, len(uniq)))
        sel = np.concatenate([idx_by[u] for u in pick])
        if y[sel].min() == y[sel].max():
            continue
        for k in res:
            res[k].append(est(sel, k))
    for k, v in res.items():
        v = np.asarray(v)
        out["%s|%s" % (k, design)] = {"point": round(float(est(np.arange(len(y)), k)), 4),
                                      "ci95": [round(float(np.percentile(v, 2.5)), 4), round(float(np.percentile(v, 97.5)), 4)],
                                      "p_gt0": round(float((v > 0).mean()), 4)}
C.write_json(C.HERE / "results" / "bootstrap_designs.json", out)
for k, v in out.items():
    print("%-26s point %+.4f  CI [%+.4f, %+.4f]  P(>0) %.3f" % (k, v["point"], *v["ci95"], v["p_gt0"]))
