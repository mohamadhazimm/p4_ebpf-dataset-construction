"""Benign Python network programs next to the Python attack tools (committee item 2, exploratory). Offline.

The committee asked to neutralize the "Python interpreter" cue: Slowloris and GoldenEye run in python3, and no benign
row of the dataset does. The encrypted-traffic collection (transport21-collect/20261115T104423464636Z) gives 24 benign
Python network clients, started exactly like the Python attack tools (flood_gen pyexec -> /usr/bin/python3), and 30
benign Go clients. This adds them to the 240 rows as network-benign rows, the Python clients in one group and the Go
clients in another, and reruns the attack-tool groupings of REPORT 2.3 (published, by attack type, by
implementation; ten fold assignments, the four detectors). Questions:
1. Are the Python attack tools still caught when benign Python programs are in the training data?
2. Are the benign Python clients flagged when their group is held out?
Exploratory pools (264 and 294 rows); the published numbers stay as they are.

    /usr/bin/python3 encryption/python_benign.py
"""
import csv
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as C  # noqa: E402

ATTEMPT = HERE.parents[1] / "transport21-collect" / "20261115T104423464636Z"
OUT = HERE / "python_benign.json"


def transport_rows(hc, nc):
    """As-captured rows (90 host + 145 network columns, the dataset's order) of the accepted benign clients."""
    val = json.load(open(sorted(ATTEMPT.glob("validation-*.json"))[-1]))
    ok = {c["sample"] for c in val["cases"] if c["status"] == "accepted" and c["label"] == "benign"}
    hs, ns = C.signals(hc), C.signals(nc)
    out = []
    for c in json.load(open(ATTEMPT / "protocol.json"))["cases"]:
        if c["sample"] not in ok:
            continue
        run = sorted((ATTEMPT / "runs" / c["sample"] / "output").glob("run_*"))[-1]
        tel = list(csv.DictReader(open(run / "telemetry.csv", newline="", encoding="utf-8-sig")))
        assert len(tel) == 40
        H = np.asarray([[[float(w[s]) for s in hs] for w in tel]])
        N = np.asarray([[[float(w[s]) for s in ns] for w in tel]])
        out.append({"program": c["program"], "transport": c["transport"], "workload": c["workload"],
                    "h": C.summarize(H)[0], "n": C.summarize(N)[0]})
    return out


def main():
    rows, hc, nc = C.load()
    Xh0, Xn0, y0 = C.matrix(rows, hc), C.matrix(rows, nc), C.labels(rows)
    cat0 = np.asarray([r["category"] for r in rows])
    atk0 = np.asarray([r["attack_type"] for r in rows])
    extra = transport_rows(hc, nc)
    py = [e for e in extra if e["program"] == "py"]
    go = [e for e in extra if e["program"] == "go"]
    assert len(py) == 24 and len(go) == 30, (len(py), len(go))
    groupings = {"published": C.groups_published, "attacktype": C.groups_by_attack_type,
                 "implementation": C.groups_by_implementation}
    pools = {"published_240": [], "plus_python_clients": [("t21::python_clients", py)],
             "plus_python_and_go_clients": [("t21::python_clients", py), ("t21::go_clients", go)]}
    result = {"attempt": str(ATTEMPT), "pools": {}}
    for pname, adds in pools.items():
        Xh = np.vstack([Xh0] + [np.asarray([e["h"] for e in es]) for _, es in adds]) if adds else Xh0
        Xn = np.vstack([Xn0] + [np.asarray([e["n"] for e in es]) for _, es in adds]) if adds else Xn0
        y = np.concatenate([y0] + [np.zeros(len(es), dtype=int) for _, es in adds])
        extra_groups = [g for g, es in adds for _ in es]
        res = {}
        for gname, fn in groupings.items():
            g = np.concatenate([fn(rows), np.asarray(extra_groups, dtype=object)]) if adds else fn(rows)
            P, _ = C.cv_all(Xh, Xn, y, g)
            n0 = len(rows)
            rec = {}
            for d in C.DETECTORS:
                flag = P[d] >= 0.5                                       # (assignments, rows)
                r = {"ba_original_240": float(np.mean([C.ba(y0, flag[s, :n0].astype(int)) for s in range(len(flag))])),
                     "malware_recall": float(flag[:, :n0][:, cat0 == "malware"].mean())}
                for t in ("syn_flood", "udp_flood", "slowloris", "goldeneye"):
                    r["recall_" + t] = float(flag[:, :n0][:, atk0 == t].mean())
                off = n0
                for gname2, es in adds:
                    r["flagged_" + gname2.split("::")[1]] = float(flag[:, off:off + len(es)].mean())
                    off += len(es)
                rec[d] = r
            res[gname] = rec
            print(pname, gname, {d: {k: round(v, 2) for k, v in rec[d].items()} for d in ("host", "network", "stacked")},
                  flush=True)
        result["pools"][pname] = res
    C.write_json(OUT, result)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
