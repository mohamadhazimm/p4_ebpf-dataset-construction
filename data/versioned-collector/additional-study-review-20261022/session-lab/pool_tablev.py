#!/usr/bin/env python3
"""Session-lab combined pool (the paper's Table V structure, on today's runs): the main run's general malware +
tonight's floods as positives, benign as negatives, grouped CV (malware family-held-out, floods instance-held-out,
benign shape/project-held-out). Both attempts are the same session-lab collection (same launch path, same busy
background, same sinkhole), so they pool; this is NOT merged with the paper's 240 rows. Per-program rows, 20 s and
80 s from the injection. Reports host/network/concat/stacked BA and per-stratum recall (general malware / flood /
benign specificity), to put next to the paper's Table V.

  /usr/bin/python3 pool_tablev.py <main attempt> <flood attempt> --out <dir>
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compare_session_lab as CS   # noqa: E402
import flood_score as FS           # noqa: E402  (benign_shape)
C = CS.C
SPANS = {"20s": 40, "80s": 160}


def pool_group(s):
    if s["kind"] == "malware":
        return "family::" + s["family"]
    if s["kind"] == "attack":
        return "flood::" + s["name"]            # instance-held-out, as Table V
    if s["kind"] == "benign":
        return "project::" + s.get("project", FS.benign_shape(s["name"]))
    return "%s::%s" % (s["kind"], s["name"])


def stratum(s):
    return {"malware": "general_malware", "attack": "flood"}.get(s["kind"], "benign")


def per_stratum(ps, y, prob):
    out = {}
    for st in ("general_malware", "flood", "benign"):
        idx = [i for i, s in enumerate(ps) if stratum(s) == st]
        if not idx:
            continue
        pr = np.asarray([prob[i] for i in idx])
        yy = np.asarray([y[i] for i in idx])
        if st == "benign":
            out["benign_specificity"] = float((pr < 0.5).mean())
        else:
            out[st + "_recall"] = float((pr >= 0.5).mean()) if len(pr) else None
        out[st + "_n"] = len(idx)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("main")
    p.add_argument("flood")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    attempts = [Path(a.main).resolve(), Path(a.flood).resolve()]
    sessions, skipped = CS.load_sessions(attempts)
    inj = [int(s["t_inject_s"] // 0.5) for s in sessions]
    prog = [(s, iw) for s, iw in zip(sessions, inj)
            if s["kind"] in ("malware", "attack", "benign", "null") and s["program_ran"] is not False]
    ps, pi = [s for s, _ in prog], [iw for _, iw in prog]
    y = np.asarray([CS.label(s) for s in ps])
    g = np.asarray([pool_group(s) for s in ps])
    rows, host_cols, net_cols = C.load()
    hs, ns = C.signals(host_cols), C.signals(net_cols)

    counts = {"general_malware": int(sum(1 for s in ps if s["kind"] == "malware")),
              "flood": int(sum(1 for s in ps if s["kind"] == "attack")),
              "benign": int(sum(1 for s in ps if s["kind"] == "benign")),
              "null": int(sum(1 for s in ps if s["kind"] == "null"))}
    result = {"attempts": [x.name for x in attempts], "counts": counts,
              "groups": {"malware_families": len(set(g[[s["kind"] == "malware" for s in ps]])),
                         "flood_instances": int(sum(1 for s in ps if s["kind"] == "attack")),
                         "benign_projects": len(set(g[[s["kind"] == "benign" for s in ps]]))},
              "skipped": len(skipped)}
    lines = ["session-lab combined pool (today): %s" % counts]
    for span, n in SPANS.items():
        Xh = C.summarize(CS.window_matrix(ps, "program", "host", pi, n, hs))
        Xn = C.summarize(CS.window_matrix(ps, "program", "net", pi, n, ns))
        sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
        entry = {"n": int(len(y)), "scores": sc}
        if P is not None:
            entry["per_stratum"] = {d: per_stratum(ps, y, P[d].mean(axis=0)) for d in P}
        result[span] = entry
        lines.append("\n== %s (n=%d) ==" % (span, len(y)))
        if "skipped" in sc:
            lines.append("  " + sc["skipped"])
            continue
        for d in ("host", "network", "concat", "stacked"):
            if d in sc:
                st = entry["per_stratum"][d]
                lines.append("  %-8s BA %.3f+/-%.3f AUC %.3f | gen-malware rec %.3f  flood rec %.3f  benign spec %.3f"
                             % (d, sc[d]["ba_mean"], sc[d]["ba_sd"], sc[d]["auc_mean"],
                                st.get("general_malware_recall", float("nan")), st.get("flood_recall", float("nan")),
                                st.get("benign_specificity", float("nan"))))
    (out_dir / "pool_tablev.json").write_text(json.dumps(result, indent=1))
    (out_dir / "pool_tablev.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
