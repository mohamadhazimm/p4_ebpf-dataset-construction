#!/usr/bin/env python3
"""Add the session lab's Table V-format results (table45_session.py) and the per-sample platform scores
(sample_scores.py) to the thesis data file data/lab/session_lab.json (merge mode). Nothing is recomputed; the
SHA-256 of each source is recorded. The interim "combined_pool_tableV" block (main run + floods) is kept and
marked as superseded by "combined_pool_tableV_full".

  /usr/bin/python3 export_table5_json.py [--table45 base/20261117/table45] [--out PATH]
"""
import argparse
import csv
import os
import sys
from collections import Counter

from export_triage_json import THESIS, load, sha

HERE = os.path.dirname(os.path.abspath(__file__))


def block(f):
    r = load(f)
    return {"rows": r["rows"], "composition": r["composition"], "by_run": r["by_run"], "spans": r["spans"],
            "script_sha256": r["script_sha256"], "_sources_sha256": {os.path.relpath(f, HERE): sha(f)}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--table45", default="base/20261117/table45")
    p.add_argument("--scores", default="base/20261117/sample_scores.csv")
    p.add_argument("--out", default=os.path.join(THESIS, "data", "lab", "session_lab.json"))
    a = p.parse_args()
    t = os.path.join(HERE, a.table45)
    doc = load(a.out)
    doc["combined_pool_tableV_full"] = dict(block(os.path.join(t, "table5_paper.json")), _note=(
        "The paper's Table V pool from the session lab: the dataset's started malware and the floods against the "
        "dataset's benign tasks, the flood batch's network-active benign and nulls; grouped CV, 10 fold assignments, "
        "mean and sd. Supersedes the interim combined_pool_tableV (main run's 60 malware only)."))
    doc["base_tableV_format"] = dict(block(os.path.join(t, "table5_base.json")),
                                     _note="The whole base dataset in the paper's Table V format.")
    if "combined_pool_tableV" in doc and isinstance(doc["combined_pool_tableV"], dict):
        doc["combined_pool_tableV"]["_superseded_by"] = "combined_pool_tableV_full"
    f = os.path.join(HERE, a.scores)
    rows = list(csv.DictReader(open(f)))
    uniq = {}
    for r in rows:
        uniq.setdefault(r["sha8"] + r["family"], r)

    def band(x):
        if x == "":
            return "not_on_triage"
        x = int(x)
        return "10" if x == 10 else "8-9" if x >= 8 else "6-7" if x >= 6 else "1-5"
    by_src = {}
    for r in uniq.values():
        src = r["source"] if r["source"] in ("MalwareBazaar", "Triage") else "rejected_by_dataset"
        d = by_src.setdefault(src, {"samples": 0, "triage_score": Counter(), "mb_labelled": 0,
                                    "mb_vendor_malicious_ge1": 0})
        d["samples"] += 1
        d["triage_score"][band(r["triage_score"])] += 1
        d["mb_labelled"] += r["mb_signature"] != ""
        d["mb_vendor_malicious_ge1"] += int(r["mb_vendors_malicious"]) >= 1
    det = {}
    for b in ("10", "8-9", "6-7", "1-5"):
        vs = [r for r in rows if band(r["triage_score"]) == b]
        if vs:
            det[b] = {"rows": len(vs), **{d: round(sum(float(v["flag_" + d]) for v in vs) / len(vs), 3)
                                          for d in ("host", "network", "concat", "stacked")}}
    doc["platform_scores"] = {
        "_note": ("Triage score (0-10; 10 = a known family) and MalwareBazaar vendor verdicts of the base's malware, "
                  "from read-only lookups (sample-intel-20261113); detection = the session-lab detectors' "
                  "out-of-fold flag rate at 20 s by Triage score band."),
        "unique_samples": len(uniq), "rows": len(rows),
        "by_source": {k: dict(v, triage_score=dict(v["triage_score"])) for k, v in by_src.items()},
        "detection_by_triage_score_band": det,
        "_sources_sha256": {os.path.relpath(f, HERE): sha(f)}, "_exporter_sha256": sha(os.path.abspath(__file__))}
    import json
    tmp = a.out + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, a.out)
    print("wrote %s (combined_pool_tableV_full, base_tableV_format, platform_scores)" % a.out)


if __name__ == "__main__":
    sys.exit(main())
