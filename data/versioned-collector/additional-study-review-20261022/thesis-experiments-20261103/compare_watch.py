"""Watch an nginx-dataset recollection and, every N completed runs, compare each new run to the original
INetSim-era run of the same sample (the released dataset row). Prints a difference summary per block.

    /usr/bin/python3 -u compare_watch.py <nginx-attempt> [--block 10]

For each run: median and p90 relative change of the 145 network features and of the 90 host features,
versus the original, and whether the host-only / network-only / stacked decision flips (detectors fitted on
the 240 released runs). Rejected runs are reported, not compared.
"""
import argparse
import csv
import glob
import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
sys.path.insert(0, str(REL / "evaluation"))
import host_model, switch_model, summary  # noqa: E402
from common import labels, load, matrix, random_forest  # noqa: E402

HOST = host_model.FEATURES
NET = switch_model.FEATURES


def fit_detectors(rows, host_cols, net_cols):
    y = labels(rows)
    groups = np.array([r["cv_group"] for r in rows])
    Xh, Xn = matrix(rows, host_cols), matrix(rows, net_cols)
    h = random_forest().fit(Xh, y)
    n = random_forest().fit(Xn, y)
    ih, inn = np.zeros(len(y)), np.zeros(len(y))
    for a, b in StratifiedGroupKFold(5, shuffle=True, random_state=7).split(Xh, y, groups):
        ih[b] = random_forest().fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
        inn[b] = random_forest().fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
    stack = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inn]), y)
    return h, n, stack


def decide(vec, host_cols, net_cols, h, n, stack):
    xh = np.array([[vec[c] for c in host_cols]])
    xn = np.array([[vec[c] for c in net_cols]])
    ph, pn = h.predict_proba(xh)[0, 1], n.predict_proba(xn)[0, 1]
    ps = stack.predict_proba(np.column_stack([[ph], [pn]]))[0, 1]
    return {"host": ph >= 0.5, "network": pn >= 0.5, "stacked": ps >= 0.5}


def relchange(a, b, cols):
    vals = []
    for c in cols:
        x, y = a[c], b[c]
        if max(abs(x), abs(y)) > 0:
            vals.append(abs(x - y) / max(abs(x), abs(y)))
    return (float(np.median(vals)) if vals else 0.0, float(np.percentile(vals, 90)) if vals else 0.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("attempt")
    ap.add_argument("--block", type=int, default=10)
    ap.add_argument("--skip", type=int, default=0, help="mark the first N completed cases seen without reporting (for re-arming)")
    args = ap.parse_args()
    attempt = Path(args.attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())

    rows, host_cols, net_cols = load()
    orig_by_id = {r["execution_id"]: r for r in rows}
    h, n, stack = fit_detectors(rows, host_cols, net_cols)

    seen, pending, block_no = set(), [], args.skip // args.block
    if args.skip:
        skipped = 0
        for case in protocol["cases"]:
            if skipped >= args.skip:
                break
            if glob.glob(str(attempt / "runs" / case["sample"] / "output" / "run_*" / "run.json")):
                seen.add(case["sample"]); skipped += 1
    done = lambda: (attempt / "run" / "result.json").exists()
    while True:
        finished = done()
        for case in protocol["cases"]:
            s = case["sample"]
            if s in seen:
                continue
            rj = glob.glob(str(attempt / "runs" / s / "output" / "run_*" / "run.json"))
            hr = attempt / "runs" / s / "host_run.txt"
            if not rj:
                if finished and hr.exists():
                    seen.add(s); pending.append((case, None, "not retrieved"))
                continue
            try:
                meta = json.loads(Path(rj[0]).read_text())
            except json.JSONDecodeError:
                continue
            seen.add(s)
            d = Path(rj[0]).parent
            if meta.get("collection_quality_status") != "accepted" or (meta.get("target_exec") or {}).get("status") != "observed":
                pending.append((case, None, "rejected/%s" % meta.get("collection_quality_status")))
                continue
            tel = list(csv.DictReader(open(d / "telemetry.csv", newline="", encoding="utf-8-sig")))
            vec = summary.summarize(tel, HOST) | summary.summarize(tel, NET)
            orig = orig_by_id.get(case["execution_id"])
            pending.append((case, vec, orig))
            while len(pending) >= args.block:
                block_no += 1
                emit(pending[:args.block], block_no, host_cols, net_cols, h, n, stack)
                del pending[:args.block]
        if finished:
            if pending:
                block_no += 1
                emit(pending, block_no, host_cols, net_cols, h, n, stack)
            print("DONE: %d runs seen" % len(seen), flush=True)
            return
        time.sleep(15)


def emit(block, block_no, host_cols, net_cols, h, n, stack):
    net_changed = host_changed = flips = problems = compared = 0
    net_rels, host_rels, lines = [], [], []
    for case, vec, orig in block:
        if vec is None or not isinstance(orig, dict):
            problems += 1
            lines.append("    %-26s %s" % (case["sample"][:26], orig if isinstance(orig, str) else "no original"))
            continue
        compared += 1
        orig_f = {c: float(orig[c]) for c in host_cols + net_cols}
        nr = relchange(vec, orig_f, net_cols); hr = relchange(vec, orig_f, host_cols)
        net_rels.append(nr[0]); host_rels.append(hr[0])
        if nr[1] > 0.1:
            net_changed += 1
        if hr[1] > 0.1:
            host_changed += 1
        dn = decide(vec, host_cols, net_cols, h, n, stack)
        do = decide(orig_f, host_cols, net_cols, h, n, stack)
        changed = [k for k in dn if dn[k] != do[k]]
        if changed:
            flips += 1
            lines.append("    %-26s %-14s decision flip: %s" % (case["sample"][:26], case["category"], changed))
    med = lambda v: ("%.2f" % np.median(v)) if v else "-"
    print("block %d (%d runs): net features changed >10%% in %d, host in %d; decision flips %d; problems %d | median rel-change net %s host %s" % (
        block_no, len(block), net_changed, host_changed, flips, problems, med(net_rels), med(host_rels)), flush=True)
    for l in lines[:6]:
        print(l, flush=True)


if __name__ == "__main__":
    main()
