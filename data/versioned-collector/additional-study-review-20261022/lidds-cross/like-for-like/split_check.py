#!/usr/bin/env python3
"""Our 240 rows scored the way LID-DS E2 was (random stratified folds, families may be in both train and
test) next to the paper's grouped folds (families and projects held out). Release evaluation code unchanged:
combined.run with each row as its own group == ordinary stratified 5-fold.
    /usr/bin/python3 split_check.py OUT.json"""
import json, sys
from multiprocessing import Pool
from pathlib import Path
REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "evaluation"))
import numpy as np
import combined, common

rows, host, net = common.load()
y = common.labels(rows)
Xh, Xn = common.matrix(rows, host), common.matrix(rows, net)
out = {}
for name, groups in (("grouped_as_paper", np.asarray([r["cv_group"] for r in rows])),
                     ("random_like_lidds_E2", np.asarray([r["execution_id"] for r in rows]))):
    with Pool(10) as pool:
        res = pool.map(combined.run, [(s, Xh, Xn, y, groups) for s in combined.FOLD_SEEDS])
    out[name] = {m: {k: [float(np.mean([r[m][k] for r in res])), float(np.std([r[m][k] for r in res], ddof=1))]
                     for k in ("balanced_accuracy", "auc", "recall", "specificity")} for m in res[0]}
    print(name, {m: "BA %.3f+-%.3f AUC %.3f" % (*out[name][m]["balanced_accuracy"], out[name][m]["auc"][0]) for m in out[name]}, flush=True)
json.dump(out, open(sys.argv[1], "w"), indent=1)
