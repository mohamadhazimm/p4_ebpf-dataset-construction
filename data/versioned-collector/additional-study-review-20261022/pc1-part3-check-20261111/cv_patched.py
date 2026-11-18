"""Training grouped CV of heldout.py (paper: network .747 / host .632 / hybrid .718) with the stock 1.7
splitter and with the >=1.8 shuffle patched in. Usage: python3 cv_patched.py CSV"""
import sys
from collections import defaultdict
import numpy as np, warnings
import sklearn.model_selection._split as sp
stock = (sp.StratifiedGroupKFold._iter_test_indices, sp.StratifiedGroupKFold._find_best_fold)
src = open(str(__import__("pathlib").Path(__file__).resolve().parent / "sklearn-1.9.1" / "_split.py")).read()
i = src.index("class StratifiedGroupKFold("); j = src.index("\nclass ", i + 1); c = src[i:j]
ns = dict(sp.__dict__); ns.update(np=np, defaultdict=defaultdict, warnings=warnings)
exec("class _X:\n" + c[c.index("    def _iter_test_indices"):], ns)
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/evaluation")
import common, heldout
rows, host, network = common.load(sys.argv[1])
train = [r for r in rows if r["category"] in ("malware", "benign") and r["split"] == "train"]
y = common.labels(train); groups = np.asarray([r["cv_group"] for r in train])
feats = {"network-only": common.matrix(train, network), "host-only": common.matrix(train, host),
         "hybrid": common.matrix(train, host + network)}
for mode in ("stock", "patched"):
    if mode == "patched":
        sp.StratifiedGroupKFold._iter_test_indices = ns["_X"]._iter_test_indices
        sp.StratifiedGroupKFold._find_best_fold = ns["_X"]._find_best_fold
    print(mode, {k: round(heldout.grouped_cv_ba(X, y, groups), 3) for k, X in feats.items()})
