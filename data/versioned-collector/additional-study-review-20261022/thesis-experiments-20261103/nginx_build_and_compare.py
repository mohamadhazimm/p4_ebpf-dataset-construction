"""Build the nginx-era dataset CSV from a completed recollection, and compare it to the INetSim dataset.

    /usr/bin/python3 nginx_build_and_compare.py <nginx-attempt> [--jobs 10]

Writes <attempt>/features_nginx.csv (same columns as the released dataset, metadata from the protocol,
features from the new runs) and <attempt>/comparison.json. The comparison is paired by execution_id: per
category, the median/p90 relative change of host and network features, and per-run detector decision flips
(detectors fitted on the 240 released runs). Also reruns Table IV and Table V on the nginx dataset.
"""
import argparse
import csv
import glob
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
sys.path.insert(0, str(REL / "evaluation"))
import host_model, switch_model, summary  # noqa: E402
from common import labels, load, matrix, metrics, random_forest  # noqa: E402

HOST, NET = host_model.FEATURES, switch_model.FEATURES
FOLD_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]


def build_csv(attempt, header, meta_cols, feat_cols):
    protocol = json.loads((attempt / "protocol.json").read_text())
    rows, rejected = [], []
    for case in protocol["cases"]:
        rj = (glob.glob(str(attempt / "runs" / case["sample"] / "output" / "run_*" / "run.json"))
              + glob.glob(str(attempt / "runs-continuation" / case["sample"] / "output" / "run_*" / "run.json")))
        if not rj:
            rejected.append((case["sample"], "not retrieved")); continue
        d = Path(rj[0]).parent
        meta = json.loads((d / "run.json").read_text())
        if meta.get("collection_quality_status") != "accepted" or (meta.get("target_exec") or {}).get("status") != "observed":
            rejected.append((case["sample"], "rejected/%s" % meta.get("collection_quality_status"))); continue
        tel = list(csv.DictReader(open(d / "telemetry.csv", newline="", encoding="utf-8-sig")))
        vec = summary.summarize(tel, HOST) | summary.summarize(tel, NET)
        row = {c: case.get({"label": "label", "category": "category", "execution_id": "execution_id",
                            "split": "split", "cv_group": "cv_group", "mode": "mode"}.get(c, c), "") for c in meta_cols}
        row.update({c: vec[c] for c in feat_cols})
        rows.append(row)
    with open(attempt / "features_nginx.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header, lineterminator="\n"); w.writeheader(); w.writerows(rows)
    return rows, rejected


def fit(rows, cols):
    return random_forest().fit(matrix(rows, cols), labels(rows))


def decisions(vec_rows, orig_rows, host_cols, net_cols):
    y = labels(orig_rows)
    groups = np.array([r["cv_group"] for r in orig_rows])
    Xh, Xn = matrix(orig_rows, host_cols), matrix(orig_rows, net_cols)
    h, n = random_forest().fit(Xh, y), random_forest().fit(Xn, y)
    ih, inn = np.zeros(len(y)), np.zeros(len(y))
    for a, b in StratifiedGroupKFold(5, shuffle=True, random_state=7).split(Xh, y, groups):
        ih[b] = random_forest().fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
        inn[b] = random_forest().fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
    stack = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inn]), y)

    def dec(rowset):
        ph = h.predict_proba(matrix(rowset, host_cols))[:, 1]
        pn = n.predict_proba(matrix(rowset, net_cols))[:, 1]
        ps = stack.predict_proba(np.column_stack([ph, pn]))[:, 1]
        return ph >= 0.5, pn >= 0.5, ps >= 0.5
    return dec


def relchange(a, b, cols):
    vals = [abs(float(a[c]) - float(b[c])) / max(abs(float(a[c])), abs(float(b[c])))
            for c in cols if max(abs(float(a[c])), abs(float(b[c]))) > 0]
    return (float(np.median(vals)) if vals else 0.0, float(np.percentile(vals, 90)) if vals else 0.0)


def table4(rows, host_cols, net_cols):
    tr = [r for r in rows if r["category"] in ("malware", "benign") and r["split"] == "train"]
    te = [r for r in rows if r["category"] in ("malware", "benign") and r["split"] == "test"]
    out = {}
    for name, cols in (("network", net_cols), ("host", host_cols), ("hybrid", host_cols + net_cols)):
        m = metrics(labels(te), fit(tr, cols).predict_proba(matrix(te, cols))[:, 1])
        out[name] = {k: m[k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("attempt")
    ap.add_argument("--jobs", type=int, default=10)
    args = ap.parse_args()
    attempt = Path(args.attempt).resolve()
    orig_rows, host_cols, net_cols = load()
    header = list(csv.reader(open(REL / "dataset" / "features.csv")).__next__())
    meta_cols = [c for c in header if not c.startswith(("host_", "net_"))]
    feat_cols = host_cols + net_cols
    new_rows, rejected = build_csv(attempt, header, meta_cols, feat_cols)
    print("nginx dataset: %d accepted, %d rejected" % (len(new_rows), len(rejected)))

    orig_by = {r["execution_id"]: r for r in orig_rows}
    new_by = {r["execution_id"]: r for r in new_rows}
    common = [e for e in new_by if e in orig_by]
    dec = decisions(None, orig_rows, host_cols, net_cols)
    no = dec([orig_by[e] for e in common]); nn = dec([new_by[e] for e in common])
    by_cat = defaultdict(lambda: {"n": 0, "net_rel": [], "host_rel": [], "flips": 0, "flip_list": []})
    for i, e in enumerate(common):
        o, nw = orig_by[e], new_by[e]
        cat = o["category"]
        c = by_cat[cat]; c["n"] += 1
        c["net_rel"].append(relchange(nw, o, net_cols)[0])
        c["host_rel"].append(relchange(nw, o, host_cols)[0])
        flip = [k for k, a, b in zip(("host", "network", "stacked"), (no[0][i], no[1][i], no[2][i]), (nn[0][i], nn[1][i], nn[2][i])) if a != b]
        if flip:
            c["flips"] += 1; c["flip_list"].append({"execution_id": e, "flip": flip})
    comp = {"common": len(common), "rejected": rejected, "by_category": {}}
    for cat, c in by_cat.items():
        comp["by_category"][cat] = {"n": c["n"], "net_median_relchange": float(np.median(c["net_rel"])),
                                    "host_median_relchange": float(np.median(c["host_rel"])), "decision_flips": c["flips"],
                                    "flip_examples": c["flip_list"][:8]}
    comp["table4_nginx"] = table4(new_rows, host_cols, net_cols)
    comp["table4_inetsim"] = table4(orig_rows, host_cols, net_cols)
    (attempt / "comparison.json").write_text(json.dumps(comp, indent=1, default=float) + "\n")
    print("\n%-16s n   net medΔ  host medΔ  decision flips" % "category")
    for cat in ("malware", "benign", "network_attack", "network_benign", "null"):
        if cat in comp["by_category"]:
            c = comp["by_category"][cat]
            print("%-16s %-3d %.3f     %.3f      %d" % (cat, c["n"], c["net_median_relchange"], c["host_median_relchange"], c["decision_flips"]))
    print("\nTable IV  INetSim -> nginx:")
    for d in ("host", "network", "hybrid"):
        print("  %-8s %.3f -> %.3f" % (d, comp["table4_inetsim"][d]["balanced_accuracy"], comp["table4_nginx"][d]["balanced_accuracy"]))
    print("written", attempt / "comparison.json")


if __name__ == "__main__":
    main()
