#!/usr/bin/env python3
"""Detection by malware type and benign category in the session dataset (thesis Ch6 table).

The rows, matrices, groups, folds and seeds are build_base.py's (relaxed rule, "sessions" view), so the balanced
accuracies equal the base's base.json (checked to 1e-9 for every detector). For every row, the out-of-fold flag rate
of each detector (mean over the ten fold assignments, threshold 0.5) is aggregated:
  malicious rows   by malware type (types as in sample_scores.py, from public descriptions of the family names) and
                   the attacks: mean flag rate = recall;
  label-0 rows     by benign category (command-line tasks; network clients of the benign projects; the laboratory
                   request tool; the poller; the transport clients; null): 1 - mean flag rate = specificity, with the
                   silent-server clients (the batch aimed at the sinkhole's catch-all listener) also on their own.
Nothing is executed and nothing is trained beyond build_base.py's own cross-validation. Run through with_runs.py
when the base holds the benign batches:

  /usr/bin/python3 with_runs.py silentbenign=20261117T013400746805Z netbenign=20261117T113428913222Z -- \\
      type_table.py --base base/20261117c --spans 20s,80s
"""
import argparse
import collections
import csv
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_base as BB   # noqa: E402
import sample_scores as SS   # noqa: E402

CS, lab = BB.CS, BB.lab
NETP = {"curl", "wget", "openssl", "ftp", "ping", "telnet", "whois"}
SILENT = "20261117T013400746805Z"


def protocol_sessions():
    out = {}
    for name, att in BB.RUNS.items():
        p = HERE / "runs" / att / "protocol.json"
        if p.is_file():
            for s in json.loads(p.read_text())["sessions"]:
                out[(name, s["sid"])] = s
    return out


def benign_category(s, proto):
    if s["stratum"] == "null":
        return "null"
    if s["stratum"] == "benign_cli":
        return "cli"
    ps = proto[(s["run"], s["sid"])]
    prog = ps.get("program") or ps.get("tool") or ps.get("name", "").split("-")[0]
    if prog == "webfetch":
        return "request_tool"
    if prog == "netpoll":
        return "poller"
    if prog in ("labtransport", "python-client"):
        return "transport"
    if prog in NETP:
        return "project_clients"
    raise ValueError("no category for %s %s %s" % (s["run"], s["sid"], prog))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", required=True)
    p.add_argument("--spans", default="20s")
    p.add_argument("--out", help="output JSON (default <base>/type_table.json)")
    a = p.parse_args()
    base = BB.HERE / a.base
    saved = json.loads((base / "base.json").read_text())
    names = list(saved["runs"])
    sessions, _ = BB.load_runs(names)
    release = list(csv.DictReader(BB.RELEASE.open()))
    ds99 = {r["sha256"] for r in release if r["category"] == "malware"}
    rev5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
    ps, _u, _d = BB.build_views(sessions, "relaxed", ds99, rev5)
    proto = protocol_sessions()
    silent = {(n, sid) for (n, sid), s in proto.items() if BB.RUNS.get(n) == SILENT and s["kind"] == "benign"}
    result = {"base": a.base, "rows": len(ps), "script_sha256": lab.sha256(__file__), "spans": {}}
    for span in a.spans.split(","):
        n = BB.SPANS[span]
        y = np.asarray([CS.label(s) for s in ps])
        g = np.asarray([s["group"] for s in ps])
        Xh, Xn, _pi, _, _ = BB.matrices(ps, n)
        sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
        ref = saved["rules"]["relaxed"]["views"]["sessions"][span]["scores"]
        for d in ("host", "network", "concat", "stacked"):
            assert abs(sc[d]["ba_mean"] - ref[d]["ba_mean"]) < 1e-9, (span, d, sc[d]["ba_mean"], ref[d]["ba_mean"])
        flag = {d: (np.asarray(P[d]) >= 0.5).mean(axis=0) for d in ("host", "network", "concat", "stacked")}
        groups = collections.defaultdict(list)
        for i, s in enumerate(ps):
            if CS.label(s) == 1:
                key = "attack" if s["stratum"] == "attack" else "type:" + SS.TYPE[s["family"].lower()]
            else:
                key = "benign:" + benign_category(s, proto)
                if (s["run"], s["sid"]) in silent:
                    groups["benign:silent_server_clients"].append(i)
            groups[key].append(i)
        table = {}
        for key, idx in sorted(groups.items()):
            row = {"n": len(idx)}
            for d in flag:
                m = float(np.mean([flag[d][i] for i in idx]))
                row[d] = round(m if not key.startswith("benign:") else 1 - m, 3)
            row["measure"] = "specificity" if key.startswith("benign:") else "recall"
            table[key] = row
        result["spans"][span] = {"ba": {d: round(sc[d]["ba_mean"], 4) for d in flag}, "table": table}
        print(span, json.dumps(result["spans"][span], indent=1))
    (Path(a.out) if a.out else base / "type_table.json").write_text(json.dumps(result, indent=1))


if __name__ == "__main__":
    sys.exit(main())
