"""E5 analysis: compare the HTTP and HTTPS run of each pair, and score both with the paper's detectors.

    /usr/bin/python3 e5_analyze.py <e5-attempt>

For every pair whose HTTP and HTTPS run are both accepted (quality accepted, target observed), reports how
much each network feature changes between the two, and the decisions of the host-only, network-only and
stacked detectors (fitted on all 240 dataset executions) on each run. Writes e5_results.json.
"""
import csv
import glob
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
sys.path.insert(0, str(REL / "evaluation"))
import host_model, switch_model, summary  # noqa: E402
from common import labels, load, matrix, random_forest  # noqa: E402

HERE = Path(__file__).resolve().parent
INNER_SEED = 7


def accepted(run_json):
    m = json.loads(run_json.read_text())
    return m.get("collection_quality_status") == "accepted" and (m.get("target_exec") or {}).get("status") == "observed"


def vector(run_dir):
    tel = list(csv.DictReader(open(run_dir / "telemetry.csv", newline="", encoding="utf-8-sig")))
    return summary.summarize(tel, host_model.FEATURES) | summary.summarize(tel, switch_model.FEATURES)


def fit_all(rows, host, network):
    y = labels(rows)
    groups = np.array([r["cv_group"] for r in rows])
    Xh, Xn = matrix(rows, host), matrix(rows, network)
    h = random_forest().fit(Xh, y)
    n = random_forest().fit(Xn, y)
    # stacker on inner out-of-fold probabilities of the whole dataset
    ih, inn = np.zeros(len(y)), np.zeros(len(y))
    for a, b in StratifiedGroupKFold(5, shuffle=True, random_state=INNER_SEED).split(Xh, y, groups):
        ih[b] = random_forest().fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
        inn[b] = random_forest().fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
    stack = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inn]), y)
    return h, n, stack


def score(vec, host, network, h, n, stack):
    xh = np.array([[vec[c] for c in host]])
    xn = np.array([[vec[c] for c in network]])
    ph = float(h.predict_proba(xh)[0, 1])
    pn = float(n.predict_proba(xn)[0, 1])
    ps = float(stack.predict_proba(np.column_stack([[ph], [pn]]))[0, 1])
    return {"host": ph, "network": pn, "stacked": ps}


def main(attempt):
    attempt = Path(attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    rows, host, network = load()
    h, n, stack = fit_all(rows, host, network)

    runs = {}
    for c in protocol["cases"]:
        rj = glob.glob(str(attempt / "runs" / c["sample"] / "output" / "run_*" / "run.json"))
        if rj and accepted(Path(rj[0])):
            runs[c["sample"]] = {"dir": Path(rj[0]).parent, "base": c["base"], "scheme": c["scheme"], "label": c["label"]}

    out = {"pairs": [], "dropped_pairs": []}
    bases = sorted({v["base"] for v in runs.values()})
    for base in bases:
        http = next((v for s, v in runs.items() if v["base"] == base and v["scheme"] == "http"), None)
        https = next((v for s, v in runs.items() if v["base"] == base and v["scheme"] == "https"), None)
        if not (http and https):
            out["dropped_pairs"].append(base)
            continue
        vh, vs = vector(http["dir"]), vector(https["dir"])
        net_changes = {}
        for c in network:
            a, b = vh[c], vs[c]
            if max(abs(a), abs(b)) > 0:
                net_changes[c] = abs(a - b) / max(abs(a), abs(b))
        rel = sorted(net_changes.values())
        sh, ss = score(vh, host, network, h, n, stack), score(vs, host, network, h, n, stack)
        out["pairs"].append({
            "base": base, "label": http["label"],
            "net_feature_median_relchange": float(np.median(rel)) if rel else 0.0,
            "net_feature_p90_relchange": float(np.percentile(rel, 90)) if rel else 0.0,
            "http_scores": sh, "https_scores": ss,
            "decisions_http": {k: sh[k] >= 0.5 for k in sh},
            "decisions_https": {k: ss[k] >= 0.5 for k in ss},
            "decision_changed": {k: (sh[k] >= 0.5) != (ss[k] >= 0.5) for k in sh},
        })
    (attempt / "pair_results.json").write_text(json.dumps(out, indent=1, default=float) + "\n")
    print("pairs with both halves accepted:", len(out["pairs"]), "| dropped:", out["dropped_pairs"])
    print("\n%-16s %-7s  net feat med/p90 rel-change   host http->https   net http->https   stacked http->https   changed?" % ("pair", "label"))
    for p in out["pairs"]:
        d = [k for k, v in p["decision_changed"].items() if v]
        print("%-16s %-7s  %.2f / %.2f                 %.2f->%.2f        %.2f->%.2f       %.2f->%.2f          %s" % (
            p["base"], p["label"], p["net_feature_median_relchange"], p["net_feature_p90_relchange"],
            p["http_scores"]["host"], p["https_scores"]["host"],
            p["http_scores"]["network"], p["https_scores"]["network"],
            p["http_scores"]["stacked"], p["https_scores"]["stacked"], d or "none"))
    # summary: how often did the decision flip?
    flips = {k: sum(p["decision_changed"][k] for p in out["pairs"]) for k in ("host", "network", "stacked")}
    print("\ndecision flips across %d pairs:" % len(out["pairs"]), flips)
    print("written", attempt / "pair_results.json")


if __name__ == "__main__":
    main(sys.argv[1])
