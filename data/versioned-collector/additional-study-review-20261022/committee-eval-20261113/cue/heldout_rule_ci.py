#!/usr/bin/env python3
"""Table IV row for the unanswered-connection rule (thesis Ch6, tab:heldout): the rule "flag an execution that left at
least one TCP/UDP flow unanswered" (cue/run_flows.csv, from unanswered_cue.py) applied to the held-out test split of
features.csv, with a 95% cluster-bootstrap interval over the test groups (2,000 resamples, groups resampled within
class, common.cluster_bootstrap_indices). The same bootstrap is run on the network detector's decisions (refitted as
published, forest seed 42) as a check against the published interval [0.645, 0.875]. Nothing is trained.
  /usr/bin/python3 cue/heldout_rule_ci.py
"""
import csv
import hashlib
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as C   # noqa: E402



def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def ba(y, pred):
    tp = int(((y == 1) & (pred == 1)).sum()); fn = int(((y == 1) & (pred == 0)).sum())
    tn = int(((y == 0) & (pred == 0)).sum()); fp = int(((y == 0) & (pred == 1)).sum())
    return 0.5 * (tp / (tp + fn) + tn / (tn + fp)), (tn, fp, fn, tp)


def main():
    rows = [r for r in csv.DictReader(C.FEATURES.open()) if r["category"] in ("malware", "benign")]
    flows = {r["execution_id"]: r for r in csv.DictReader((HERE / "run_flows.csv").open())}
    test = [r for r in rows if r["split"] == "test"]
    assert len(test) == 54, len(test)
    y = np.asarray([1 if r["category"] == "malware" else 0 for r in test])
    g = np.asarray([r["cv_group"] for r in test])
    cue = np.asarray([1 if int(flows[r["execution_id"]]["unanswered_flows"]) > 0 else 0 for r in test])
    # the network detector of Table IV, refitted exactly as published (common.fit_predict, forest seed 42;
    # verify_baseline.py checks that it gives 28/0/13/13)
    allrows, hc, nc = C.load()
    Xh, Xn, yall = C.matrix(allrows, hc), C.matrix(allrows, nc), C.labels(allrows)
    gen = np.asarray([r["category"] in ("malware", "benign") for r in allrows])
    split = np.asarray([r["split"] for r in allrows])
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    assert [allrows[i]["execution_id"] for i in te] == [r["execution_id"] for r in test]
    pnet = C.fit_predict(Xh, Xn, yall, C.groups_published(allrows), tr, te, detectors=("network",))["network"]
    net = (pnet >= 0.5).astype(int)
    out = {"sources": {"features.csv": sha(C.FEATURES), "run_flows.csv": sha(HERE / "run_flows.csv"),
                       "script": sha(__file__)}}
    for name, pred in (("unanswered_rule", cue), ("network_detector", net)):
        b, conf = ba(y, pred)
        boot = [ba(y[idx], pred[idx])[0] for idx in C.cluster_bootstrap_indices(y, g, 2000, seed=1)]
        out[name] = {"balanced_accuracy": round(b, 4), "tn_fp_fn_tp": conf, "recall": round(conf[3] / (conf[2] + conf[3]), 3),
                     "ci95": [round(float(np.percentile(boot, 2.5)), 3), round(float(np.percentile(boot, 97.5)), 3)]}
    out["network_catches_with_cue"] = int(((net == 1) & (cue == 1) & (y == 1)).sum())
    out["network_catches"] = int(((net == 1) & (y == 1)).sum())
    C.write_json(HERE.parent / "results" / "heldout_rule_ci.json", out)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
