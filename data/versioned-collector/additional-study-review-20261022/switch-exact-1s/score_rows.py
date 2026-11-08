#!/usr/bin/env python3
"""Score feature CSVs (features.csv layout) with the release's own evaluation code, unchanged:
Table V's grouped nested CV over 10 fold assignments (evaluation/combined.py: run) and Table IV's
held-out split plus the grouped 5-fold CV on its training set (evaluation/heldout.py).

    /usr/bin/python3 score_rows.py OUT.json NAME=features.csv [NAME=other.csv ...]
"""
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "evaluation"))
import common  # noqa: E402
import combined  # noqa: E402
import heldout  # noqa: E402


def score(path):
    rows, host, network = common.load(Path(path))
    y = common.labels(rows)
    groups = np.asarray([r["cv_group"] for r in rows])
    jobs = [(seed, common.matrix(rows, host), common.matrix(rows, network), y, groups) for seed in combined.FOLD_SEEDS]
    with Pool(10) as pool:
        per_seed = pool.map(combined.run, jobs)
    table5 = {}
    for name in ("host-only", "network-only", "hybrid"):
        table5[name] = {k: {"mean": float(np.mean([s[name][k] for s in per_seed])),
                            "sd": float(np.std([s[name][k] for s in per_seed], ddof=1))}
                        for k in ("balanced_accuracy", "auc", "recall", "specificity", "f1")}
        table5[name]["per_seed_ba"] = [s[name]["balanced_accuracy"] for s in per_seed]
    sub = [r for r in rows if r["category"] in ("malware", "benign")]
    train = [r for r in sub if r["split"] == "train"]
    test = [r for r in sub if r["split"] == "test"]
    yt, ys = common.labels(train), common.labels(test)
    feats = {"network-only": network, "host-only": host, "hybrid": host + network}
    table4 = {}
    for name, cols in feats.items():
        m = common.metrics(ys, common.random_forest().fit(common.matrix(train, cols), yt)
                           .predict_proba(common.matrix(test, cols))[:, 1])
        table4[name] = m
    cv = heldout._permutation_job(({n: common.matrix(train, c) for n, c in feats.items()}, yt,
                                   np.asarray([r["cv_group"] for r in train])))
    return {"table5_combined": table5, "table4_heldout": table4, "training_grouped_cv_ba": cv}


def main():
    out = {}
    for arg in sys.argv[2:]:
        name, path = arg.split("=", 1)
        out[name] = score(path)
        t5, t4, cv = out[name]["table5_combined"], out[name]["table4_heldout"], out[name]["training_grouped_cv_ba"]
        print("%-28s Table V BA host %.3f+-%.3f  net %.3f+-%.3f  hybrid %.3f+-%.3f | Table IV BA host %.3f net %.3f "
              "hybrid %.3f | train CV host %.3f net %.3f hybrid %.3f" % (
                  name, t5["host-only"]["balanced_accuracy"]["mean"], t5["host-only"]["balanced_accuracy"]["sd"],
                  t5["network-only"]["balanced_accuracy"]["mean"], t5["network-only"]["balanced_accuracy"]["sd"],
                  t5["hybrid"]["balanced_accuracy"]["mean"], t5["hybrid"]["balanced_accuracy"]["sd"],
                  t4["host-only"]["balanced_accuracy"], t4["network-only"]["balanced_accuracy"],
                  t4["hybrid"]["balanced_accuracy"], cv["host-only"], cv["network-only"], cv["hybrid"]), flush=True)
        json.dump(out, open(sys.argv[1], "w"), indent=1)


if __name__ == "__main__":
    main()
