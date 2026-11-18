#!/usr/bin/env python3
"""Score the flood batch (run_session_flood.py). Run analyze_session_lab.py <flood attempt> --features first.

Three views, all on the injected program's own rows (20 s and 80 s from the injection), reusing the paper's
detectors and CV (committee-eval common.py, via compare_session_lab):
  transfer      the paper's detectors trained on the 240 dataset rows, applied to the flood sessions. The dataset
                has SYN/UDP/Slowloris/GoldenEye but no HTTP flood, so this shows the gap the main run hit (the
                network/hybrid view scoring an HTTP flood like the benign download loop it learned from);
  leave-one-type-out   grouped CV within the batch, attacks grouped by TYPE (syn/udp/http/slowloris/goldeneye),
                benign by shape -- the honest test: no other rate of the held-out attack type is in training;
  leave-one-instance-out   grouped CV with each attack its own group (other rates of the same type stay in
                training) -- the "enough examples" test, for contrast.
Plus per-attack-type recall for each detector. Post hoc; no model promoted, nothing merged.

  /usr/bin/python3 flood_score.py <flood attempt> --out <dir>
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compare_session_lab as CS   # noqa: E402  (reuses its loaders, window_matrix, score, grouped_cv_P)
C = CS.C
SPANS = {"20s": 40, "80s": 160}


def benign_shape(name):
    return name.split("-")[0]       # download/upload/browse/beacon/dns/null


def type_group(s):
    if s["kind"] == "attack":
        return "type::" + s.get("atype", s["name"])
    if s["kind"] == "benign":
        return "shape::" + benign_shape(s["name"])
    return "%s::%s" % (s["kind"], s["name"])


def per_type_recall(ps, y, prob):
    out = defaultdict(lambda: [0, 0])
    for s, yi, pi in zip(ps, y, prob):
        if yi == 1:
            key = s.get("atype", s["name"]) if s["kind"] == "attack" else s["name"]
            out[key][0] += int(pi >= 0.5)
            out[key][1] += 1
    return {k: {"caught": v[0], "n": v[1]} for k, v in sorted(out.items())}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("attempt")
    p.add_argument("--out", required=True)
    a = p.parse_args()
    att = Path(a.attempt).resolve()
    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    sessions, skipped = CS.load_sessions([att])
    inj = [int(s["t_inject_s"] // 0.5) for s in sessions]
    # eligibility as in the dataset: the injected program must have started
    prog = [(s, iw) for s, iw in zip(sessions, inj)
            if s["kind"] in ("attack", "benign", "null") and s["program_ran"] is not False]
    not_started = [[s["sid"], s["kind"], s["name"]] for s, iw in zip(sessions, inj)
                   if s["kind"] in ("attack", "benign", "null") and s["program_ran"] is False]
    ps, pi = [s for s, _ in prog], [iw for _, iw in prog]
    y = np.asarray([CS.label(s) for s in ps])
    g_type = np.asarray([type_group(s) for s in ps])
    g_inst = np.asarray([CS.group(s) for s in ps])

    rows, host_cols, net_cols = C.load()
    hs, ns = C.signals(host_cols), C.signals(net_cols)
    Xd_h, Xd_n = C.matrix(rows, host_cols), C.matrix(rows, net_cols)
    yd, gd = C.labels(rows), C.groups_published(rows)

    result = {"attempt": att.name, "sessions": len(sessions), "skipped": skipped, "not_started": not_started,
              "kinds": {k: int(sum(1 for s in ps if s["kind"] == k)) for k in sorted({s["kind"] for s in ps})},
              "attack_types": {t: int(sum(1 for s in ps if s["kind"] == "attack" and s.get("atype") == t))
                               for t in sorted({s.get("atype") for s in ps if s["kind"] == "attack"})}}

    for span, n in SPANS.items():
        Xh = C.summarize(CS.window_matrix(ps, "program", "host", pi, n, hs))
        Xn = C.summarize(CS.window_matrix(ps, "program", "net", pi, n, ns))
        entry = {"n": int(len(y)), "malicious": int(y.sum())}
        if span == "20s":
            # transfer: the paper's detectors (trained on the 240 dataset rows) applied here
            XH, XN = np.vstack([Xd_h, Xh]), np.vstack([Xd_n, Xn])
            YY, GG = np.concatenate([yd, y]), np.concatenate([gd, g_type])
            tr, te = np.arange(len(yd)), np.arange(len(yd), len(yd) + len(y))
            probs = C.fit_predict(XH, XN, YY, GG, tr, te)
            entry["transfer"] = {d: C.metrics(y, pr) for d, pr in probs.items()}
            entry["transfer_per_type_recall"] = {d: per_type_recall(ps, y, pr) for d, pr in probs.items()}
            entry["transfer_flagged_by_kind"] = {
                d: {k: float(np.mean([pr[i] >= 0.5 for i, s in enumerate(ps) if s["kind"] == k]))
                    for k in sorted({s["kind"] for s in ps})} for d, pr in probs.items()}
        # within-batch grouped CV, two groupings
        for tag, g in (("leave_one_type_out", g_type), ("leave_one_instance_out", g_inst)):
            sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
            entry[tag] = sc
            if P is not None:
                entry[tag + "_per_type_recall"] = {d: per_type_recall(ps, y, P[d].mean(axis=0)) for d in P}
        result[span] = entry

    (out_dir / "flood_scores.json").write_text(json.dumps(result, indent=1))
    # a short text summary
    lines = ["flood batch %s: %d program rows (%d attack, %d benign, %d null); attack types %s" % (
        att.name, len(y), result["kinds"].get("attack", 0), result["kinds"].get("benign", 0),
        result["kinds"].get("null", 0), result["attack_types"])]
    for span in SPANS:
        e = result[span]
        lines.append("\n== %s ==" % span)
        if "transfer" in e:
            lines.append("transfer (paper detectors on the 240 rows):")
            for d, m in e["transfer"].items():
                lines.append("  %-8s BA %.3f AUC %.3f recall %.3f spec %.3f" % (
                    d, m["balanced_accuracy"], m["auc"], m["recall"], m["specificity"]))
            lines.append("  per-type recall (network / stacked): " + ", ".join(
                "%s %d/%d|%d/%d" % (t, e["transfer_per_type_recall"]["network"][t]["caught"],
                                    e["transfer_per_type_recall"]["network"][t]["n"],
                                    e["transfer_per_type_recall"]["stacked"][t]["caught"],
                                    e["transfer_per_type_recall"]["stacked"][t]["n"])
                for t in e["transfer_per_type_recall"]["network"]))
        for tag in ("leave_one_type_out", "leave_one_instance_out"):
            sc = e[tag]
            if "skipped" in sc:
                lines.append("%s: %s" % (tag, sc["skipped"]))
                continue
            lines.append("%s:" % tag)
            for d in ("host", "network", "concat", "stacked"):
                if d in sc:
                    lines.append("  %-8s BA %.3f+/-%.3f AUC %.3f recall %.3f spec %.3f" % (
                        d, sc[d]["ba_mean"], sc[d]["ba_sd"], sc[d]["auc_mean"], sc[d]["recall_mean"],
                        sc[d]["specificity_mean"]))
    (out_dir / "flood_summary.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("\nwrote", out_dir / "flood_scores.json")


if __name__ == "__main__":
    main()
