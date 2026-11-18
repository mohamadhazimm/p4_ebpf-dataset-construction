#!/usr/bin/env python3
"""Pre-registered scoring of the silent-server benign batch (run_session_silentbenign.py; decision rule in its
protocol "expectations"). Pools the batch's benign rows with the Triage cohort and the network-active pilot
(build_base.py's rows: relaxed rule, "sessions" view, 20 s), reruns the grouped CV (same folds and seeds), and reports:

  - the C2/backdoor implants against all benign (with and without the batch): BA per detector, per-family recall,
    specificity on the batch's silent-server benign;
  - the silent-server rule (silent_server_check.py) on the same pool;
  - the pre-registered decision for the network view.

No new model type, threshold or feature; nothing is executed. --dry-run scores the pool without the batch (checks the
code path before the batch exists).

  /usr/bin/python3 score_silentbenign.py --attempt runs/<batch> --out <dir>
  /usr/bin/python3 score_silentbenign.py --dry-run --out <dir>
"""
import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np

import build_base as BB
import silent_server_check as SC

CS, C, lab = BB.CS, BB.C, BB.lab
C2_FOCUS = ("rekoobe", "sliver", "adaptixc2")


def rows_for(names):
    sessions, skipped = BB.load_runs(names)
    release = list(csv.DictReader(BB.RELEASE.open()))
    ds99 = {r["sha256"] for r in release if r["category"] == "malware"}
    rev5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
    allrows, _u, _d = BB.build_views(sessions, "relaxed", ds99, rev5)
    return allrows, skipped


def flag_rates(P, y, keep, idx_sets):
    """Mean over fold assignments of the share flagged (prob >= 0.5) in each named index set (indices into keep)."""
    out = {}
    for d, pr in P.items():
        fl = (np.asarray(pr) >= 0.5).mean(axis=0)
        out[d] = {k: (round(float(fl[v].mean()), 3) if len(v) else None) for k, v in idx_sets.items()}
    return out


def score(ps, label):
    n = BB.SPANS["20s"]
    y = np.asarray([CS.label(s) for s in ps])
    g = np.asarray([s["group"] for s in ps])
    Xh, Xn, _pi, _, _ = BB.matrices(ps, n)
    c2 = np.asarray([(s["kind"] == "malware" and s["family"].lower() in BB.C2_FAMILIES) or s["kind"] in ("benign", "null")
                     for s in ps])
    sub = [s for s, k in zip(ps, c2) if k]
    sc, P = CS.grouped_cv_P(Xh[c2], Xn[c2], y[c2], g[c2])
    res = {"pool": label, "implants": int(y[c2].sum()), "benign": int((y[c2] == 0).sum()),
           "scores": {d: {"ba": round(v["ba_mean"], 3), "ba_sd": round(v["ba_sd"], 3), "auc": round(v["auc_mean"], 3),
                          "recall": round(v["recall_mean"], 3), "specificity": round(v["specificity_mean"], 3)}
                      for d, v in sc.items() if isinstance(v, dict) and "ba_mean" in v}}
    if P is None:
        res["skipped"] = sc
        return res
    res["minus_host"] = {k: {"mean": round(v["mean"], 3), "positive": "%d/%d" % (v["positive"], v["assignments"])}
                         for k, v in CS.paired(y[c2], P).items()}
    idx = {"silent_server_benign": [i for i, s in enumerate(sub) if s["run"] == "silentbenign"],
           "other_benign": [i for i, s in enumerate(sub) if s["kind"] != "malware" and s["run"] != "silentbenign"]}
    for f in sorted({s["family"].lower() for s in sub if s["kind"] == "malware"}):
        idx["family::" + f] = [i for i, s in enumerate(sub) if s["kind"] == "malware" and s["family"].lower() == f]
    res["flag_rate"] = flag_rates(P, y[c2], c2, {k: np.asarray(v, dtype=int) for k, v in idx.items()})
    return res


def cue_rule(names, span=20.0):
    rows = []
    for run in names:
        attempt = BB.HERE / "runs" / BB.RUNS[run]
        protocol = lab.load(attempt / "protocol.json")
        for s in protocol["sessions"]:
            if s["kind"] not in ("malware", "benign", "null"):
                continue
            res = attempt / "sessions" / s["sid"] / "result.json"
            if not res.is_file() or lab.load(res).get("status") != "accepted":
                continue
            fl = SC.program_flows(attempt, protocol, s, span)
            if fl is None:
                continue
            fam = s.get("family", "") if s["kind"] == "malware" else ""
            rows.append(dict(run=run, kind=s["kind"], label=int(s["kind"] == "malware"),
                             c2=int(fam.lower() in BB.C2_FAMILIES), **SC.classify(fl)))
    y = [r["label"] for r in rows]
    flag = [int(r["tcp_silent_server"] > 0) for r in rows]
    sub = [i for i, r in enumerate(rows) if r["label"] == 0 or r["c2"]]
    sb = [r for r in rows if r["run"] == "silentbenign"]
    return {"all_programs": SC.ba(y, flag), "c2_vs_benign": SC.ba([y[i] for i in sub], [flag[i] for i in sub]),
            "silent_server_benign_with_cue": "%d/%d" % (sum(1 for r in sb if r["tcp_silent_server"] > 0), len(sb))}


def decision(res):
    sc = res["scores"].get("network", {})
    fr = res.get("flag_rate", {}).get("network", {})
    checks = {"implants_only_BA>=0.75": sc.get("ba", 0) >= 0.75,
              "silent_benign_specificity>=0.7": fr.get("silent_server_benign") is not None
                                                and 1 - fr["silent_server_benign"] >= 0.7}
    for f in C2_FOCUS:
        checks["recall_%s>=0.5" % f] = (fr.get("family::" + f) or 0) >= 0.5
    return {"checks": checks, "credited": all(checks.values())}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--attempt")
    p.add_argument("--out", required=True)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    base_names = ["tpilot", "triage"]
    result = {"protocol_decision_rule": "network view credited only if implants-only BA >= 0.75, recall >= 0.5 on each "
                                        "of Rekoobe, Sliver, AdaptixC2, and silent-server-benign specificity >= 0.7"}
    if not a.dry_run:
        att = Path(a.attempt).resolve()
        BB.RUNS["silentbenign"] = att.name
        BB.ORDER.append("silentbenign")
        result["attempt"] = att.name
        result["protocol_sha256"] = lab.sha256(att / "protocol.json")
    names = base_names + ([] if a.dry_run else ["silentbenign"])
    ps, skipped = rows_for(names)
    result["skipped"] = skipped
    result["with_batch" if not a.dry_run else "without_batch"] = score(ps, "+".join(names))
    if not a.dry_run:
        ps0 = [s for s in ps if s["run"] != "silentbenign"]
        result["without_batch"] = score(ps0, "+".join(base_names))
        result["decision"] = decision(result["with_batch"])
    result["cue_rule"] = cue_rule(names)
    (out / "silentbenign_scores.json").write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    sys.exit(main())
