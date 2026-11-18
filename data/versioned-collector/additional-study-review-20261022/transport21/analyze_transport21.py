"""Does encryption shift the features? Analysis of the transport21 collection (committee item 3). Offline.

    /usr/bin/python3 transport21/analyze_transport21.py transport21-collect/<attempt> [--validation VALIDATION.json]

Each accepted run (one benign client, one workload, one transport: plain HTTP, TLS 1.1/1.2/1.3 over HTTP/1.1, or
QUIC) becomes a dataset-shaped row: the 18 host and 29 network window signals of its 40 windows (telemetry.csv,
the dataset's names), summarized like dataset/features.csv (mean, max, sum, population std, active windows).

1. Shift. For each program and workload, every transport's runs against the plain-HTTP runs, in units of the
   dataset's spread: each column is divided by its standard deviation over the 240 dataset rows (columns that are
   constant there are left out), and the shift is the mean absolute difference over the host or the network
   columns. The same distance between the two repeats of one transport is the run-to-run spread to compare with.
   The columns that move most are listed.
Two views of the network side: "as captured" (the collector's telemetry, from the guest's own capture, where the
NIC's receive and segmentation offloads merge TCP segments into frames of up to 64 KB, while QUIC's UDP datagrams
stay separate) and "wire" (the same capture with every TCP frame above 1514 B split into MTU-size segments, what a
switch sees; committee-eval-20261113/offload/resegment.py). Check first: the release's switch model on the original
capture reproduces the telemetry's network columns of every run.

2. Scores. The paper's detectors (release evaluation/common.py random_forest: host-only, network-only, the
   concatenated hybrid on all 235 columns, and the stacked hybrid of evaluation/combined.py) trained on the 240
   dataset rows score every run. The clients are benign programs the dataset has never seen, so every flag is a
   false alarm; the question is whether the transport changes the scores.
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(RELEASE / "evaluation"))
import common  # noqa: E402  the release's loader and forest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "committee-eval-20261113" / "offload"))
import resegment  # noqa: E402  window_features_wire, and the release's switch_model and summary

STATS = ("mean", "max", "sum", "std", "active_windows")
TRANSPORTS = ("http", "tls11", "tls12", "tls13", "quic")


def signals(columns):
    out = []
    for c in columns:
        s = c.rsplit("__", 1)[0]
        if s not in out:
            out.append(s)
    return out


def summarize(W):
    return np.stack([W.mean(0), W.max(0), W.sum(0), W.std(0), (W != 0).sum(0).astype(float)], axis=1).reshape(-1)


def run_row(run_dir, host_sig, net_sig, net_cols):
    """Host and network summaries as captured (telemetry), and the network summary in the wire view."""
    tel = list(csv.DictReader(open(run_dir / "telemetry.csv", newline="", encoding="utf-8-sig")))
    assert len(tel) == 40, run_dir
    H = np.asarray([[float(w[s]) for s in host_sig] for w in tel])
    N = np.asarray([[float(w[s]) for s in net_sig] for w in tel])
    start = int(json.load(open(run_dir / "run.json"))["sample_started_wall_us"])
    pcap = str(run_dir / "packet_capture.pcap")
    model = resegment.summary.summarize(resegment.sm.window_features(pcap, start), resegment.sm.FEATURES)
    captured = np.asarray([model[c] for c in net_cols])
    n = summarize(N)
    rel = float(np.max(np.abs(captured - n) / np.maximum(np.abs(n), 1e-9))) if n.any() else 0.0
    wire_w, split = resegment.window_features_wire(pcap, start)
    wire = resegment.summary.summarize(wire_w, resegment.sm.FEATURES)
    return summarize(H), n, np.asarray([wire[c] for c in net_cols]), rel, split


def detectors(Xh, Xn, y, groups):
    host = common.random_forest().fit(Xh, y)
    net = common.random_forest().fit(Xn, y)
    concat = common.random_forest().fit(np.hstack([Xh, Xn]), y)
    ih, inn = np.zeros(len(y)), np.zeros(len(y))
    for a, b in StratifiedGroupKFold(5, shuffle=True, random_state=7).split(Xh, y, groups):
        ih[b] = common.random_forest().fit(Xh[a], y[a]).predict_proba(Xh[b])[:, 1]
        inn[b] = common.random_forest().fit(Xn[a], y[a]).predict_proba(Xn[b])[:, 1]
    stacker = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inn]), y)

    def score(H, N):
        ph, pn = host.predict_proba(H)[:, 1], net.predict_proba(N)[:, 1]
        return {"host": ph, "network": pn, "concat": concat.predict_proba(np.hstack([H, N]))[:, 1],
                "stacked": stacker.predict_proba(np.column_stack([ph, pn]))[:, 1]}
    return score


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attempt")
    ap.add_argument("--validation", help="the collector's validation report (default: the newest in the attempt)")
    ap.add_argument("--out", help="output folder (default: the attempt's analysis/)")
    args = ap.parse_args()
    attempt = Path(args.attempt).resolve()
    vpath = Path(args.validation) if args.validation else sorted(attempt.glob("validation-*.json"))[-1]
    val = json.load(open(vpath))
    accepted = {c["sample"] for c in val["cases"] if c["status"] == "accepted" and c["label"] == "benign"}
    protocol = json.load(open(attempt / "protocol.json"))
    rows, host_cols, net_cols = common.load()
    host_sig, net_sig = signals(host_cols), signals(net_cols)
    assert [f"{s}__{t}" for s in host_sig for t in STATS] == host_cols
    assert [f"{s}__{t}" for s in net_sig for t in STATS] == net_cols
    Xh, Xn, y = common.matrix(rows, host_cols), common.matrix(rows, net_cols), common.labels(rows)
    groups = np.asarray([r["cv_group"] for r in rows])
    sd_h, sd_n = Xh.std(0), Xn.std(0)
    keep_h, keep_n = sd_h > 0, sd_n > 0

    runs = []
    for c in protocol["cases"]:
        if c["sample"] not in accepted:
            continue
        out = sorted((attempt / "runs" / c["sample"] / "output").glob("run_*"))[-1]
        h, n, nw, rel, split = run_row(out, host_sig, net_sig, net_cols)
        runs.append(dict(c, H=h, N=n, NW=nw, model_rel_diff=rel, frames_split=split))
    worst = max(r["model_rel_diff"] for r in runs)
    print("switch model vs telemetry, largest relative difference over %d runs: %.2e" % (len(runs), worst))
    if not runs:
        sys.exit("no accepted runs")
    score = detectors(Xh, Xn, y, groups)
    P = score(np.asarray([r["H"] for r in runs]), np.asarray([r["N"] for r in runs]))
    PW = score(np.asarray([r["H"] for r in runs]), np.asarray([r["NW"] for r in runs]))
    for i, r in enumerate(runs):
        r["scores"] = {d: float(P[d][i]) for d in P}
        r["scores_wire"] = {d: float(PW[d][i]) for d in PW}

    by = defaultdict(list)
    for r in runs:
        by[(r["program"], r["workload"], r["transport"])].append(r)

    def dist(a, b, which):
        if which == "host":
            return float(np.mean(np.abs(a["H"] - b["H"])[keep_h] / sd_h[keep_h]))
        key = "NW" if which == "wire" else "N"
        return float(np.mean(np.abs(a[key] - b[key])[keep_n] / sd_n[keep_n]))

    shift = []
    for (prog, wl, tr), rs in sorted(by.items()):
        base = by.get((prog, wl, "http"), [])
        rec = {"program": prog, "workload": wl, "transport": tr, "runs": len(rs)}
        for which in ("host", "network", "wire"):
            if len(rs) >= 2:
                rec["repeat_spread_" + which] = dist(rs[0], rs[1], which)
            if tr != "http" and base:
                rec["shift_vs_http_" + which] = float(np.mean([dist(a, b, which) for a in rs for b in base]))
        # the columns that move most against plain HTTP (in dataset standard deviations)
        if tr != "http" and base:
            mh = np.mean([r["H"] for r in rs], 0) - np.mean([b["H"] for b in base], 0)
            mn = np.mean([r["N"] for r in rs], 0) - np.mean([b["N"] for b in base], 0)
            zh = np.where(keep_h, mh / np.where(keep_h, sd_h, 1), 0)
            zn = np.where(keep_n, mn / np.where(keep_n, sd_n, 1), 0)
            top = sorted([(abs(v), host_cols[j], float(v)) for j, v in enumerate(zh)] +
                         [(abs(v), net_cols[j], float(v)) for j, v in enumerate(zn)], reverse=True)[:5]
            rec["largest_moves_sd"] = [(name, round(v, 2)) for _, name, v in top]
        rec["flagged"] = {d: sum(r["scores"][d] >= 0.5 for r in rs) for d in P}
        rec["flagged_wire"] = {d: sum(r["scores_wire"][d] >= 0.5 for r in rs) for d in P}
        rec["packets_wire"] = [float(r["NW"][net_sig.index("net_pkts_total_delta") * 5 + 2]) for r in rs]
        rec["frames_split"] = [r["frames_split"] for r in rs]
        rec["mean_score"] = {d: float(np.mean([r["scores"][d] for r in rs])) for d in P}
        rec["packets"] = [float(r["N"][net_sig.index("net_pkts_total_delta") * 5 + 2]) for r in rs]
        rec["syscalls"] = [float(r["H"][host_sig.index("host_total_syscalls_total") * 5 + 2]) for r in rs]
        shift.append(rec)

    flag = {}
    for tr in TRANSPORTS:
        rs = [r for r in runs if r["transport"] == tr]
        if rs:
            flag[tr] = {"runs": len(rs), **{d: sum(r["scores"][d] >= 0.5 for r in rs) for d in P},
                        "wire": {d: sum(r["scores_wire"][d] >= 0.5 for r in rs) for d in P}}
    result = {"attempt": str(attempt), "validation": str(vpath), "accepted_runs": len(runs),
              "switch_model_vs_telemetry_max_rel_diff": worst,
              "flagged_by_transport": flag, "cells": shift,
              "runs": [{k: r[k] for k in ("sample", "program", "workload", "transport", "repeat", "scores",
                                          "scores_wire", "frames_split")} for r in runs]}
    out = Path(args.out) if args.out else attempt / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    (out / "transport_analysis.json").write_text(json.dumps(result, indent=1) + "\n")

    print("accepted runs:", len(runs))
    print("\nflagged (probability >= 0.5) by transport; every run is benign (wire view in brackets):")
    print("%-6s %4s %9s %9s %9s %9s" % ("", "runs", "host", "network", "concat", "stacked"))
    for tr, f in flag.items():
        print("%-6s %4d %9s %9s %9s %9s" % (tr, f["runs"], *["%d (%d)" % (f[d], f["wire"][d])
                                                               for d in ("host", "network", "concat", "stacked")]))
    print("\nshift against plain HTTP vs repeat spread (mean |difference| in dataset standard deviations):")
    print("%-4s %-8s %-6s %10s %10s %10s %10s %10s %10s  %s" % ("prog", "workload", "trans", "host", "host rep",
          "net", "net rep", "wire", "wire rep", "packets (wire) / syscalls"))
    for r in shift:
        f = lambda k: "%.3f" % r[k] if k in r else "-"  # noqa: E731
        print("%-4s %-8s %-6s %10s %10s %10s %10s %10s %10s  %s (%s) / %s" % (
            r["program"], r["workload"], r["transport"], f("shift_vs_http_host"), f("repeat_spread_host"),
            f("shift_vs_http_network"), f("repeat_spread_network"), f("shift_vs_http_wire"), f("repeat_spread_wire"),
            [int(x) for x in r["packets"]], [int(x) for x in r["packets_wire"]], [int(x) for x in r["syscalls"]]))
    print("\nwritten:", out / "transport_analysis.json")


if __name__ == "__main__":
    main()
