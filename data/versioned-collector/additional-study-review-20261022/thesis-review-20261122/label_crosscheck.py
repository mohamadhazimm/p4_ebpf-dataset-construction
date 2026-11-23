#!/usr/bin/env python3
"""Do the 99 malware samples' family labels agree with the other repository? Offline, from the saved 2026-11-13
lookup (sample-intel-20261113/intel99-paper-dataset-20261113.json; hashes only were sent, no sample downloaded).

A label from MalwareBazaar is checked against Triage's family tags, and a label from Triage against MalwareBazaar's
signature and tags. Known aliases and naming variants count as agreement (Katana and RapperBot under Mirai, Tsunami
under Kaiten, Chaos under Kaiji, BillGates and Dofloo under MrBlack, CoinMiner under XMRig, Bert under Sodinokibi,
inc_ransom, prometei_elf). Writes label_crosscheck.json and prints the counts.
"""
import csv
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOOKUP = HERE.parent / "sample-intel-20261113/intel99-paper-dataset-20261113.json"
FEATURES = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
ALIAS = {"katana": {"mirai"}, "rapperbot": {"mirai"}, "tsunami": {"kaiten"}, "chaos": {"kaiji"},
         "billgates": {"mrblack"}, "dofloo": {"mrblack", "aesddos"}, "coinminer": {"xmrig"},
         "bert": {"sodinokibi"}, "inc": {"inc_ransom"}, "prometei": {"prometei_elf"}}


def main():
    lookup = json.loads(LOOKUP.read_text())
    rows = [r for r in csv.DictReader(open(FEATURES)) if r["category"] == "malware"]
    out = {"MalwareBazaar": {"samples": 0, "other_names_family": 0, "agree": 0, "disagree": [],
                             "triage_score_ge5": 0, "triage_score_ge8": 0},
           "Triage": {"samples": 0, "other_names_family": 0, "agree": 0, "disagree": []}}
    for r in rows:
        e, ours = lookup[r["sha256"]], r["family"].lower()
        ok = {ours} | ALIAS.get(ours, set())
        s = out[r["source"]]
        s["samples"] += 1
        if r["source"] == "MalwareBazaar":
            t = e.get("triage") or {}
            other = {f.lower() for f in (t.get("family") or [])}
            s["triage_score_ge5"] += (t.get("score") or 0) >= 5
            s["triage_score_ge8"] += (t.get("score") or 0) >= 8
        else:
            m = e.get("mb") or {}
            other = ({m["signature"].lower()} if m.get("signature") else set())
            if other:
                other |= {x.lower() for x in (m.get("tags") or [])}
        if other:
            s["other_names_family"] += 1
            if other & ok:
                s["agree"] += 1
            else:
                s["disagree"].append({"family": r["family"], "other": sorted(other)})
    out["sources"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (LOOKUP, FEATURES)}
    (HERE / "label_crosscheck.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != "sources"}, indent=1))


if __name__ == "__main__":
    main()
