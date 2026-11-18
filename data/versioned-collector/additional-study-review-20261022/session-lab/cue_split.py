#!/usr/bin/env python3
"""How much of the session lab's results rests on the sinkhole's silent listener (a TCP server that accepts and never
sends data; met almost only by malware). Post hoc, offline; rows, groups, folds and seeds are build_base.py's
(base/20261117c: every run incl. the silent-server and network-active benign batches; relaxed rule, sessions view, 20 s).

Row groups (from silent-server/silent_server_rows.csv): met the silent listener (a connection where the program sent
data and the server, after accepting, sent none, or any silent connection) / used the network, answered servers only /
no network; floods separately.

  1. flags per group for the four detectors (out-of-fold, mean over the 10 fold assignments)
  2. the concatenated hybrid's lead over host split by group: each group's share of the balanced-accuracy difference
  3. a proxy for a sinkhole that answers: the detectors retrained with only the client-side flow signals, which do not
     depend on what the server sends (flow count, client->server packets and bytes, client packet size, flows with
     client data); the client's own retries still reflect the silence, so this is an optimistic bound

  /usr/bin/python3 cue_split.py --base base/20261117c --out base/20261117c/cue-split
"""
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import with_runs as WR   # noqa: E402

BB = WR.BB
DETS = ("host", "network", "concat", "stacked")
CLIENT = ["net_flow_count_seen", "net_pkts_ab_delta", "net_bytes_ab_delta", "net_avg_pkt_size_ab_delta",
          "net_flows_with_ab"]


def group_of(s, cue):
    c = cue.get((s["run"], s["sid"]))
    if s["kind"] == "attack":
        return "attack (floods)"
    if c is None:
        return "no cue record"
    met = int(c["tcp_silent_server_client_sent"]) > 0 or int(c.get("tcp_silent_server", 0) or 0) > 0
    net = int(c["tcp"]) + int(c["udp"]) > 0
    return "met silent listener" if met else ("network, answered only" if net else "no network")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default="base/20261117c")
    p.add_argument("--out", default="base/20261117c/cue-split")
    a = p.parse_args()
    base = HERE / a.base
    out = HERE / a.out
    out.mkdir(parents=True, exist_ok=True)
    saved = json.loads((base / "base.json").read_text())
    for name, att in saved["runs"].items():
        if name not in BB.RUNS:
            WR.register(name, att)
    WR.patch()
    import score_netbenign as S                      # same row builder as the scorer and the base
    rows, *_ = S.all_rows(list(saved["runs"]))
    cue = {(r["run"], r["sid"]): r for r in csv.DictReader((base / "silent-server" / "silent_server_rows.csv").open())}
    y = np.asarray([BB.CS.label(s) for s in rows])
    g = np.asarray([s["group"] for s in rows])
    Xh, Xn, _pi, _hc, net_cols = BB.matrices(rows, BB.SPANS["20s"])
    keep = [i for i, c in enumerate(net_cols) if any(c.startswith(sig + "__") for sig in CLIENT)]
    lab = np.asarray([("malicious" if y[i] else "benign") + " | " + group_of(s, cue) for i, s in enumerate(rows)])
    result = {"base": a.base, "runs": saved["runs"], "rows": len(rows), "malicious": int(y.sum()),
              "client_side_columns": len(keep), "client_side_signals": CLIENT, "script_sha256": BB.lab.sha256(__file__),
              "variants": {}}
    ref = saved["rules"]["relaxed"]["views"]["sessions"]["20s"]["scores"]
    for name, X in (("all_network_features", Xn), ("client_side_only", Xn[:, keep])):
        sc, P = BB.CS.grouped_cv_P(Xh, X, y, g)
        if name == "all_network_features":
            for d in DETS:
                assert abs(sc[d]["ba_mean"] - ref[d]["ba_mean"]) < 1e-9, (d, sc[d]["ba_mean"], ref[d]["ba_mean"])
        flags = {d: (np.asarray(P[d]) >= 0.5).mean(axis=0) for d in DETS}
        v = {"BA": {d: round(sc[d]["ba_mean"], 4) for d in DETS},
             "minus_host": {k: {"mean": round(x["mean"], 4), "positive": "%d/%d" % (x["positive"], x["assignments"])}
                            for k, x in BB.CS.paired(y, P).items()},
             "flags_by_group": {gn: {"n": int((lab == gn).sum()), **{d: round(float(flags[d][lab == gn].mean()), 3)
                                                                    for d in DETS}} for gn in sorted(set(lab))}}
        nm, nb = (y == 1).sum(), (y == 0).sum()
        parts = defaultdict(list)
        for k in range(P["host"].shape[0]):
            ch = (P["host"][k] >= 0.5).astype(int) == y
            cc = (P["concat"][k] >= 0.5).astype(int) == y
            for gn in sorted(set(lab)):
                idx = lab == gn
                parts[gn].append(0.5 * (cc[idx].sum() - ch[idx].sum()) / (nm if gn.startswith("malicious") else nb))
        v["concat_lead_by_group"] = {gn: round(float(np.mean(x)), 4) for gn, x in parts.items()}
        cue_part = sum(np.mean(parts[gn]) for gn in parts if gn.endswith("met silent listener"))
        v["concat_lead_cue_related"] = round(float(cue_part), 4)
        v["concat_lead_other"] = round(float(sum(np.mean(x) for x in parts.values()) - cue_part), 4)
        result["variants"][name] = v
    (out / "cue_split.json").write_text(json.dumps(result, indent=1))
    lines = []
    for name, v in result["variants"].items():
        lines.append("== %s: BA %s" % (name, " ".join("%s %.3f" % kv for kv in v["BA"].items())))
        lines.append("   concat - host %+.4f: cue-related %+.4f, other %+.4f" % (
            v["minus_host"]["concat_minus_host"]["mean"], v["concat_lead_cue_related"], v["concat_lead_other"]))
        for gn, f in v["flags_by_group"].items():
            lines.append("   %-40s n=%3d host %.2f network %.2f concat %.2f stacked %.2f  lead part %+.4f" % (
                gn, f["n"], f["host"], f["network"], f["concat"], f["stacked"], v["concat_lead_by_group"][gn]))
    (out / "cue_split.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
