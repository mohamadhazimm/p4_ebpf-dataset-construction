"""heldout.py's training grouped CV over fold seeds 42,0-8, stock 1.7 splitter and >=1.8 shuffle.
Usage: python3 cv_seeds.py CSV"""
import sys
from collections import defaultdict
from multiprocessing import Pool
import numpy as np, warnings
import sklearn.model_selection._split as sp
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import balanced_accuracy_score
STOCK = (sp.StratifiedGroupKFold._iter_test_indices, sp.StratifiedGroupKFold._find_best_fold)
src = open(str(__import__("pathlib").Path(__file__).resolve().parent / "sklearn-1.9.1" / "_split.py")).read()
i = src.index("class StratifiedGroupKFold("); j = src.index("\nclass ", i + 1); c = src[i:j]
ns = dict(sp.__dict__); ns.update(np=np, defaultdict=defaultdict, warnings=warnings)
exec("class _X:\n" + c[c.index("    def _iter_test_indices"):], ns)
NEW = (ns["_X"]._iter_test_indices, ns["_X"]._find_best_fold)
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/evaluation")
import common
rows, host, network = common.load(sys.argv[1])
train = [r for r in rows if r["category"] in ("malware", "benign") and r["split"] == "train"]
y = common.labels(train); groups = np.asarray([r["cv_group"] for r in train])
F = {"network": common.matrix(train, network), "host": common.matrix(train, host), "hybrid": common.matrix(train, host + network)}
def job(a):
    mode, seed = a
    sp.StratifiedGroupKFold._iter_test_indices, sp.StratifiedGroupKFold._find_best_fold = (STOCK if mode == "stock" else NEW)
    out = {}
    for k, X in F.items():
        oof = np.zeros(len(y))
        for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, groups):
            oof[te] = common.random_forest().fit(X[tr], y[tr]).predict_proba(X[te])[:, 1]
        out[k] = balanced_accuracy_score(y, oof >= 0.5)
    return mode, seed, out
seeds = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
with Pool(20) as p:
    res = p.map(job, [(m, s) for m in ("stock", "patched") for s in seeds])
for m in ("stock", "patched"):
    for k in F:
        v = np.array([o[k] for mm, s, o in res if mm == m])
        print("%-8s %-8s seed42 %.3f  mean %.3f +/- %.3f  min %.3f max %.3f" % (m, k, v[0], v.mean(), v.std(ddof=1), v.min(), v.max()))
