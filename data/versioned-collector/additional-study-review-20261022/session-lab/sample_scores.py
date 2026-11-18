#!/usr/bin/env python3
"""Per-sample table of the base dataset's malware: what the platforms said (Triage score and family, MalwareBazaar
signature and vendor verdicts) next to what the session lab's detectors said (out-of-fold flag rate of each detector,
mean over the ten fold assignments of build_base.py's grouped cross-validation, relaxed rule, "sessions" view, 20 s)
and whether the program met the sinkhole's silent listener.

The rows, matrices, groups, folds and seeds are build_base.py's, so the balanced accuracies equal base.json's (checked).
Platform data: sample-intel-20261113/intel99-paper-dataset-20261113.json (the dataset's 99) and
intel-base-extra-20261117.json (the Triage samples and the two the dataset rejected), both from intel_lookup.py
(read-only lookups). Writes <base>/sample_scores.csv and sample_scores.json. Nothing is executed.

  /usr/bin/python3 sample_scores.py --base base/20261117
"""
import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np

import build_base as BB

CS, lab = BB.CS, BB.lab
INTEL = BB.HERE.parent / "sample-intel-20261113"
TYPE = {}
for f in ("mirai gafgyt kaiji tsunami dofloo ddosagent kaiten chaos katana xorddos billgates chinaz rapperbot "
          "fritzfrog flylegitbot echobot moobot zergeca").split():
    TYPE[f] = "DDoS / IoT botnet"
for f in "akira qilin bert lockbit inc nitrogen promptlock noescape".split():
    TYPE[f] = "ransomware"
for f in "brickstorm deskrat getshell ngioweb rekoobe gobrat".split():
    TYPE[f] = "backdoor / RAT / proxy"
for f in "sliver vshell adaptixc2".split():
    TYPE[f] = "C2 framework"
for f in "coinminer prometei xmrig_linux perfctl".split():
    TYPE[f] = "cryptominer"
TYPE["ladvix"] = "file infector (trojan)"
TYPE["catstorm"] = "type not established"


def mal_votes(vendors):
    n = 0
    for k, x in (vendors or {}).items():
        if x is None:
            continue
        xs = str(x).lower()
        if xs == "malicious" or xs.startswith("malware") or (k == "ReversingLabs" and xs not in ("", "unknown")):
            n += 1
    return n


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default="base/20261117")
    a = p.parse_args()
    base = BB.HERE / a.base
    saved = json.loads((base / "base.json").read_text())
    names = list(saved["runs"])
    sessions, _ = BB.load_runs(names)
    release = list(csv.DictReader(BB.RELEASE.open()))
    ds99 = {r["sha256"] for r in release if r["category"] == "malware"}
    source = {r["sha256"]: r["source"] for r in release if r["category"] == "malware"}
    rev5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
    ps, _u, _d = BB.build_views(sessions, "relaxed", ds99, rev5)
    n = BB.SPANS["20s"]
    y = np.asarray([CS.label(s) for s in ps])
    g = np.asarray([s["group"] for s in ps])
    Xh, Xn, _pi, _, _ = BB.matrices(ps, n)
    sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
    ref = saved["rules"]["relaxed"]["views"]["sessions"]["20s"]["scores"]
    for d in ("host", "network", "concat", "stacked"):
        assert abs(sc[d]["ba_mean"] - ref[d]["ba_mean"]) < 1e-9, (d, sc[d]["ba_mean"], ref[d]["ba_mean"])
    flag = {d: (np.asarray(P[d]) >= 0.5).mean(axis=0) for d in P}
    cue = {(r["run"], r["sid"]): r for r in csv.DictReader((base / "silent-server" / "silent_server_rows.csv").open())}
    intel = json.loads((INTEL / "intel99-paper-dataset-20261113.json").read_text())
    intel.update(json.loads((INTEL / "intel-base-extra-20261117.json").read_text()))
    out = []
    for i, s in enumerate(ps):
        if s["kind"] != "malware":
            continue
        sha = s["sha256"]
        it = intel[sha]
        t, mb = it["triage"], it.get("mb") or {}
        x = cue[(s["run"], s["sid"])]
        out.append({
            "run": s["run"], "sid": s["sid"], "family": s["family"], "type": TYPE[s["family"].lower()],
            "sha8": sha[:8], "stratum": s["stratum"],
            "source": (source.get(sha, "") if s["stratum"] == "malware_dataset99" else
                       "Triage" if s["stratum"] == "malware_triage" else "revision5 pool (rejected by the dataset)"),
            "triage_score": t.get("score") if t.get("found") else "",
            "triage_family": " ".join(t.get("family") or []),
            "mb_signature": mb.get("signature") or "",
            "mb_vendors_reporting": sum(1 for v in (mb.get("vendors") or {}).values() if v is not None),
            "mb_vendors_malicious": mal_votes(mb.get("vendors")),
            "met_silent_listener": int(int(x["tcp_silent_server_client_sent"]) > 0),
            "used_network": int(int(x["tcp"]) + int(x["udp"]) > 0),
            **{"flag_" + d: round(float(flag[d][i]), 2) for d in ("host", "network", "concat", "stacked")}})
    fields = list(out[0])
    with (base / "sample_scores.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(out)
    summary = {"rows": len(out), "scores_BA_reproduced": {d: round(sc[d]["ba_mean"], 3) for d in sc
                                                          if isinstance(sc[d], dict) and "ba_mean" in sc[d]},
               "intel_sources": ["sample-intel-20261113/intel99-paper-dataset-20261113.json",
                                 "sample-intel-20261113/intel-base-extra-20261117.json"],
               "script_sha256": lab.sha256(__file__)}
    (base / "sample_scores.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    sys.exit(main())
