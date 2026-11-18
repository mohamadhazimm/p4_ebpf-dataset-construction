"""Run the release's Table V (combined.py) with scikit-learn 1.7.0 but the >=1.8 StratifiedGroupKFold
shuffle (copied verbatim from the 1.9.1 wheel). Usage: python3 run_patched.py CSV [patched|stock]"""
import sys, re, types
from collections import defaultdict
import numpy as np, warnings
import sklearn.model_selection._split as sp
mode = sys.argv[2]
if mode == "patched":
    src = open(str(__import__("pathlib").Path(__file__).resolve().parent / "sklearn-1.9.1" / "_split.py")).read()
    i = src.index("class StratifiedGroupKFold("); j = src.index("\nclass ", i + 1); c = src[i:j]
    k = c.index("    def _iter_test_indices"); body = c[k:]
    ns = dict(sp.__dict__); ns.update(np=np, defaultdict=defaultdict, warnings=warnings)
    exec("class _X:\n" + body, ns)
    sp.StratifiedGroupKFold._iter_test_indices = ns["_X"]._iter_test_indices
    sp.StratifiedGroupKFold._find_best_fold = ns["_X"]._find_best_fold
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/evaluation")
import common, combined
path = sys.argv[1]
combined.load = lambda: common.load(path)
sys.argv = ["combined.py", "--jobs", "10"]
print("splitter:", mode, "csv:", path)
combined.main()
