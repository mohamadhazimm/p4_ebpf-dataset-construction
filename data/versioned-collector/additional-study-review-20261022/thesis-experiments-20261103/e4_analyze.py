"""E4: does training with background traffic make the network view robust to it?

    /usr/bin/python3 e4_analyze.py <background-test-attempt> <background-train-attempt> [--jobs 10]

Builds feature vectors for the background reruns of the 90 test/attack executions (batch 1) and the 150
training executions (batch 2). Table IV setting, four train/test combinations per detector:
  quiet->quiet   (the released Table IV, reproduced)
  quiet->bg      (train on quiet, test on background: the B1 result from vm_batches)
  bg->bg         (train on background, test on background)
  bg->quiet      (train on background, test on quiet)
The question is whether bg->bg restores the network and hybrid specificity that quiet->bg destroys.
Writes e4_results.json.
"""
import argparse
import csv
import glob
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
sys.path.insert(0, str(REL / "evaluation"))
import host_model, switch_model, summary  # noqa: E402
from common import load, matrix, metrics, random_forest  # noqa: E402

HOST, NET = host_model.FEATURES, switch_model.FEATURES


def featurize_attempt(attempt):
    """execution_id -> feature dict, for the accepted runs of a background attempt."""
    protocol = json.loads((Path(attempt) / "protocol.json").read_text())
    out = {}
    for c in protocol["cases"]:
        rj = (glob.glob(str(Path(attempt) / "runs" / c["sample"] / "output" / "run_*" / "run.json"))
              + glob.glob(str(Path(attempt) / "runs-continuation" / c["sample"] / "output" / "run_*" / "run.json")))
        if not rj:
            continue
        d = Path(rj[0]).parent
        m = json.loads((d / "run.json").read_text())
        if m.get("collection_quality_status") != "accepted" or (m.get("target_exec") or {}).get("status") != "observed":
            continue
        tel = list(csv.DictReader(open(d / "telemetry.csv", newline="", encoding="utf-8-sig")))
        out[c["execution_id"]] = summary.summarize(tel, HOST) | summary.summarize(tel, NET)
    return out


def as_rows(ids, feats, meta, cols):
    rows = []
    for e in ids:
        r = dict(meta[e]); r.update({c: feats[e][c] for c in cols}); rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bg_test"); ap.add_argument("bg_train")
    ap.add_argument("--jobs", type=int, default=10)
    args = ap.parse_args()
    orig, host_cols, net_cols = load()
    meta = {r["execution_id"]: r for r in orig}

    bg_test = featurize_attempt(args.bg_test)     # 90 test/attack executions, background present
    bg_train = featurize_attempt(args.bg_train)   # 150 training executions, background present

    # Table IV uses malware+benign only. Train ids = train split; test ids = test split.
    train_ids = [r["execution_id"] for r in orig if r["category"] in ("malware", "benign") and r["split"] == "train"]
    test_ids = [r["execution_id"] for r in orig if r["category"] in ("malware", "benign") and r["split"] == "test"]
    train_ids = [e for e in train_ids if e in bg_train]
    test_ids = [e for e in test_ids if e in bg_test]

    allcols = host_cols + net_cols
    quiet_train = {r["execution_id"]: {c: float(r[c]) for c in allcols} for r in orig}
    combos = {
        "quiet->quiet": (quiet_train, train_ids, quiet_train, test_ids),
        "quiet->bg":    (quiet_train, train_ids, bg_test, test_ids),
        "bg->bg":       (bg_train, train_ids, bg_test, test_ids),
        "bg->quiet":    (bg_train, train_ids, quiet_train, test_ids),
    }
    y = lambda ids: np.array([int(meta[e]["label"]) for e in ids])
    out = {"created_utc": datetime.now(timezone.utc).isoformat(), "train_n": len(train_ids), "test_n": len(test_ids), "combos": {}}
    for name, (trf, tri, tef, tei) in combos.items():
        tr_rows, te_rows = as_rows(tri, trf, meta, allcols), as_rows(tei, tef, meta, allcols)
        ytr, yte = y(tri), y(tei)
        res = {}
        for det, cols in (("host", host_cols), ("network", net_cols), ("hybrid", host_cols + net_cols)):
            m = metrics(yte, random_forest().fit(matrix(tr_rows, cols), ytr).predict_proba(matrix(te_rows, cols))[:, 1])
            res[det] = {k: m[k] for k in ("balanced_accuracy", "specificity", "recall", "auc", "tn", "fp", "fn", "tp")}
        out["combos"][name] = res
    (Path(__file__).resolve().parent / "e4_results.json").write_text(json.dumps(out, indent=1, default=float) + "\n")
    print("Table IV setting, %d train / %d test executions\n" % (len(train_ids), len(test_ids)))
    print("%-13s %-9s %-9s %-9s" % ("combo", "host BA", "net BA", "hybrid BA") + "   (specificity in parens)")
    for name, res in out["combos"].items():
        cells = []
        for det in ("host", "network", "hybrid"):
            r = res[det]; cells.append("%.3f(%.2f)" % (r["balanced_accuracy"], r["specificity"]))
        print("%-13s %-15s %-15s %-15s" % (name, *cells))
    print("\nwritten e4_results.json")


if __name__ == "__main__":
    main()
