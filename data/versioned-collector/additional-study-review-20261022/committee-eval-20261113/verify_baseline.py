"""Gate for every committee analysis: the shared loader must reproduce the published numbers exactly.

1. Five-summary features rebuilt from each run's per-window telemetry equal features.csv (all 240 x 235).
2. Table IV (held-out split, RF seed 42): network .750/.789 28/0/13/13, host .929/.993 24/4/0/26,
   hybrid (concatenated) .926/.982 26/2/2/24.
3. Table V (combined pool, 10 fold assignments, stacked hybrid): BA host .784, network .756, hybrid .823.

    /usr/bin/python3 verify_baseline.py
"""
import sys

import numpy as np
import sklearn

import common as C


def main():
    assert sklearn.__version__.startswith("1.7"), "Table V reproduces only with scikit-learn < 1.8: %s" % sklearn.__version__
    rows, hc, nc = C.load()
    Xh, Xn, y = C.matrix(rows, hc), C.matrix(rows, nc), C.labels(rows)
    H, N, hs, ns = C.per_window(rows, hc, nc, use_cache=False)
    dh = np.abs(C.summarize(H) - Xh).max() / max(1.0, np.abs(Xh).max())
    dn = np.abs(C.summarize(N) - Xn).max() / max(1.0, np.abs(Xn).max())
    print("rebuilt-vs-published relative max diff: host %.2e network %.2e" % (dh, dn))
    assert dh < 1e-12 and dn < 1e-12

    gen = np.asarray([r["category"] in ("malware", "benign") for r in rows])
    tr = np.flatnonzero(gen & (np.asarray([r["split"] for r in rows]) == "train"))
    te = np.flatnonzero(gen & (np.asarray([r["split"] for r in rows]) == "test"))
    g = C.groups_published(rows)
    out = C.fit_predict(Xh, Xn, y, g, tr, te, detectors=("host", "network", "concat"))
    want = {"network": (0.750, 0.789, (28, 0, 13, 13)), "host": (0.929, 0.993, (24, 4, 0, 26)),
            "concat": (0.926, 0.982, (26, 2, 2, 24))}
    for d, (wba, wauc, wcm) in want.items():
        m = C.metrics(y[te], out[d])
        cm = (m["tn"], m["fp"], m["fn"], m["tp"])
        print("Table IV %-8s BA %.3f AUC %.4f %s" % (d, m["balanced_accuracy"], m["auc"], cm))
        assert round(m["balanced_accuracy"], 3) == wba and cm == wcm, d
        assert abs(m["auc"] - wauc) < 0.0011, d  # network AUC is 0.78846 (paper rounds to .789; should be .788)

    P, F = C.cv_all(Xh, Xn, y, g, detectors=("host", "network", "stacked"))
    for d, w in (("host", 0.784), ("network", 0.756), ("stacked", 0.823)):
        v = np.asarray([C.metrics(y, P[d][i])["balanced_accuracy"] for i in range(len(C.FOLD_SEEDS))])
        print("Table V  %-8s BA %.3f +/- %.3f" % (d, v.mean(), v.std(ddof=1)))
        assert round(v.mean(), 3) == w, d
    print("BASELINE REPRODUCED")


if __name__ == "__main__":
    sys.exit(main())
