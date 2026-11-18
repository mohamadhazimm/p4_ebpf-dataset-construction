#!/usr/bin/env python3
"""Table V of the paper, computed on the session lab: balanced accuracy, recall, specificity, precision and F1 (mean and
sd over the ten fold assignments of grouped 5-fold cross-validation; malware families, attack instances and benign
projects held out; threshold 0.5), plus AUC, for the host, network, concatenated and stacked detectors.

Pools (rows, groups, matrices and folds exactly as build_base.py builds them; relaxed rule, "sessions" view):
  paper  the paper's Table V composition: the dataset's own programs (main run + rest of the main plan: the dataset's
         malware that started, its 105 benign tasks, nulls) and the flood batch (attacks, its network-active benign,
         nulls) plus the main run's attacks. The 2 malware the dataset rejected are left out, as in the paper.
  paper_sb  the paper pool plus the silent-server benign batch (its network-active benign clients and nulls).
  paper_sb_nb  paper_sb plus the network-active benign batch (its benign clients and nulls; batch controls left out).
  base   every row of the base dataset (361 at 20 s in base/20261117).
For "base" the balanced accuracies equal base.json's (checked).

  /usr/bin/python3 table45_session.py --pool paper|base --out <dir> [--spans 20s,80s]
"""
import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np

import build_base as BB

CS, C, lab = BB.CS, BB.C, BB.lab
COLS = ("balanced_accuracy", "recall", "specificity", "precision", "f1", "auc")


def pool_rows(name, ps):
    if name == "base":
        return ps
    runs = ("main", "rest", "floods") + {"paper": (), "paper_sb": ("silentbenign",),
                                         "paper_sb_nb": ("silentbenign", "netbenign")}[name]
    return [s for s in ps if s["run"] in runs and s["stratum"] != "malware_dataset_extra"]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pool", choices=("paper", "paper_sb", "paper_sb_nb", "base"), required=True)
    p.add_argument("--base", default="base/20261117")
    p.add_argument("--out", required=True)
    p.add_argument("--spans", default="20s,80s")
    a = p.parse_args()
    base = BB.HERE / a.base
    saved = json.loads((base / "base.json").read_text())
    for name, att in saved["runs"].items():          # a base built with extra runs (with_runs.py)
        BB.RUNS.setdefault(name, att)
        if name not in BB.ORDER:
            BB.ORDER.append(name)
    sessions, _ = BB.load_runs(list(saved["runs"]))
    release = list(csv.DictReader(BB.RELEASE.open()))
    ds99 = {r["sha256"] for r in release if r["category"] == "malware"}
    rev5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
    allrows, _u, _d = BB.build_views(sessions, "relaxed", ds99, rev5)
    ps = pool_rows(a.pool, allrows)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    result = {"pool": a.pool, "rows": len(ps),
              "composition": {k: sum(1 for s in ps if s["stratum"] == k) for k in sorted({s["stratum"] for s in ps})},
              "by_run": {k: sum(1 for s in ps if s["run"] == k) for k in sorted({s["run"] for s in ps})},
              "script_sha256": lab.sha256(__file__), "spans": {}}
    lines = ["pool %s: %d rows %s" % (a.pool, len(ps), result["composition"])]
    for span in [x for x in a.spans.split(",") if x]:
        n = BB.SPANS[span]
        y = np.asarray([CS.label(s) for s in ps])
        g = np.asarray([s["group"] for s in ps])
        Xh, Xn, _pi, _, _ = BB.matrices(ps, n)
        sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
        if a.pool == "base":
            ref = saved["rules"]["relaxed"]["views"]["sessions"][span]["scores"]
            for d in ("host", "network", "concat", "stacked"):
                assert abs(sc[d]["ba_mean"] - ref[d]["ba_mean"]) < 1e-9, (span, d)
        entry = {"malicious": int(y.sum()), "benign": int((y == 0).sum()),
                 "malicious_groups": len(set(g[y == 1])), "label0_groups": len(set(g[y == 0])), "detectors": {}}
        lines.append("\n== %s: %d malicious / %d benign and controls" % (span, y.sum(), (y == 0).sum()))
        lines.append("  %-8s %15s %15s %15s %15s %15s %15s" % ("", *COLS))
        for d in ("host", "network", "concat", "stacked"):
            per = [C.metrics(y, P[d][k]) for k in range(P[d].shape[0])]
            st = {c: (float(np.mean([m[c] for m in per])), float(np.std([m[c] for m in per], ddof=1))) for c in COLS}
            entry["detectors"][d] = {c: {"mean": round(v[0], 4), "sd": round(v[1], 4)} for c, v in st.items()}
            lines.append("  %-8s %s" % (d, " ".join("%7.3f+/-%.3f" % st[c] for c in COLS)))
        mal = y == 1
        for d in ("host", "network", "concat", "stacked"):
            flagged = (np.asarray(P[d]) >= 0.5).mean(axis=0)
            entry["detectors"][d]["recall_by_stratum"] = {
                k: round(float(flagged[[i for i, s in enumerate(ps) if s["stratum"] == k]].mean()), 3)
                for k in sorted({s["stratum"] for s, m in zip(ps, mal) if m})}
            entry["detectors"][d]["specificity_by_stratum"] = {
                k: round(1 - float(flagged[[i for i, s in enumerate(ps) if s["stratum"] == k]].mean()), 3)
                for k in sorted({s["stratum"] for s, m in zip(ps, mal) if not m})}
        paired = CS.paired(y, P)
        entry["minus_host"] = {k: {"mean": round(v["mean"], 4), "positive": "%d/%d" % (v["positive"], v["assignments"])}
                               for k, v in paired.items()}
        lines.append("  minus host: " + ", ".join("%s %+.3f (%s)" % (k.replace("_minus_host", ""), v["mean"],
                                                                     v["positive"]) for k, v in entry["minus_host"].items()))
        result["spans"][span] = entry
    (out / ("table5_%s.json" % a.pool)).write_text(json.dumps(result, indent=1))
    (out / ("table5_%s.txt" % a.pool)).write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
