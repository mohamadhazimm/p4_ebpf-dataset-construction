#!/usr/bin/env python3
"""Post hoc: how far do the session-lab detectors' decisions follow the silent-server cue (silent_server_check.py)?

Rebuilds the base dataset's program rows exactly as build_base.py does (relaxed rule, "sessions" view, 20 s), reruns
its grouped cross-validation (same folds and seeds, so the scores equal base.json's), and splits each detector's
out-of-fold flag rate by whether the program met a silent server (a TCP connection that the server accepted and
then never sent data on) in its first 20 s. Done for all programs and for the C2/backdoor implants against the benign.
No new model or threshold; the cue flags come from silent_server_rows.csv.

  /usr/bin/python3 silent_cue_crosstab.py --runs triage,tpilot --silent <dir with silent_server_rows.csv> --out <json>
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

import build_base as BB

CS, C, lab = BB.CS, BB.C, BB.lab


def rates(P, y, ps, flag, mask):
    """Per detector: flag rate (mean over fold assignments) of the rows in each (label, cue) cell."""
    out = {}
    for d, pr in P.items():
        pr = np.asarray(pr)
        flagged = (pr >= 0.5).mean(axis=0) if pr.ndim == 2 else (pr >= 0.5).astype(float)
        cell = defaultdict(list)
        for i in range(len(y)):
            if not mask[i]:
                continue
            if ps[i]["kind"] == "attack":          # floods: their SYN-only flows are no sinkhole artifact
                key = "attack"
            else:
                key = "%s_%s" % ("malicious" if y[i] else "benign", "cue" if flag[i] else "no_cue")
            cell[key].append(flagged[i])
        out[d] = {k: {"n": len(v), "flagged": round(float(np.mean(v)), 3)} for k, v in sorted(cell.items())}
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--runs", default="triage,tpilot")
    p.add_argument("--silent", required=True)
    p.add_argument("--out", required=True)
    a = p.parse_args()
    names = [r for r in a.runs.split(",") if r]
    sessions, _ = BB.load_runs(names)
    release = list(csv.DictReader(BB.RELEASE.open()))
    ds99 = {r["sha256"] for r in release if r["category"] == "malware"}
    rev5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
    allrows, _unique, _ = BB.build_views(sessions, "relaxed", ds99, rev5)
    ps = allrows
    n = BB.SPANS["20s"]
    y = np.asarray([CS.label(s) for s in ps])
    g = np.asarray([s["group"] for s in ps])
    Xh, Xn, _pi, _, _ = BB.matrices(ps, n)
    cue = {}
    with open(Path(a.silent) / "silent_server_rows.csv") as fh:
        for r in csv.DictReader(fh):
            cue[(r["run"], r["sid"])] = int(r["tcp_silent_server_client_sent"]) > 0
    flag = np.asarray([cue.get((s["run"], s["sid"]), False) for s in ps])
    missing = sum(1 for s in ps if (s["run"], s["sid"]) not in cue)
    sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
    res = {"runs": names, "rows": int(len(y)), "malicious": int(y.sum()), "rows_without_cue_record": missing,
           "cue": "a TCP connection where the program sent data and the server, after accepting, sent none (20 s)",
           "scores_BA": {d: round(v["ba_mean"], 3) for d, v in sc.items() if isinstance(v, dict) and "ba_mean" in v},
           "all_programs": rates(P, y, ps, flag, np.ones(len(y), bool))}
    c2 = np.asarray([(s["kind"] == "malware" and s["family"].lower() in BB.C2_FAMILIES) or s["kind"] in ("benign", "null")
                     for s in ps])
    sc2, P2 = CS.grouped_cv_P(Xh[c2], Xn[c2], y[c2], g[c2])
    sub = [s for s, k in zip(ps, c2) if k]
    if P2 is None:                       # no C2/backdoor families in these runs (e.g. the main run alone)
        res["c2_vs_benign"] = sc2
        Path(a.out).write_text(json.dumps(res, indent=1))
        print(json.dumps(res, indent=1))
        return
    res["c2_scores_BA"] = {d: round(v["ba_mean"], 3) for d, v in sc2.items() if isinstance(v, dict) and "ba_mean" in v}
    res["c2_vs_benign"] = rates(P2, y[c2], sub, flag[c2], np.ones(int(c2.sum()), bool))
    fam = defaultdict(lambda: defaultdict(list))
    for d, pr in P2.items():
        fl = (np.asarray(pr) >= 0.5).mean(axis=0)
        for i, s in enumerate(sub):
            if y[c2][i]:
                fam[s["family"].lower()]["%s_%s" % (d, "cue" if flag[c2][i] else "no_cue")].append(fl[i])
    res["c2_family_flag_rate_by_cue"] = {f: {k: [len(v), round(float(np.mean(v)), 3)] for k, v in sorted(dd.items())}
                                         for f, dd in sorted(fam.items())}
    Path(a.out).write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    sys.exit(main())
