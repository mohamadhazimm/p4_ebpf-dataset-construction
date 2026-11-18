#!/usr/bin/env python3
"""Add the base dataset's results (build_base.py) to the thesis data file data/lab/session_lab.json.

Every number is copied from the saved base.json of one build_base.py output folder (nothing is recomputed), and the
SHA-256 of base.json, manifest.csv and every row CSV is recorded. The primary view (relaxed acceptance rule,
"sessions" view: every accepted program session, each run balanced by design) is copied in full: composition,
grouped-CV scores, per-stratum recall/specificity, per-family recall, detector-minus-host per fold assignment,
baselines with the random-feature reference, and the C2-implant subset. The "unique" view (first session per program)
and the strict rule are copied as sensitivity checks. The other keys of session_lab.json are left unchanged.

  /usr/bin/python3 export_base_json.py base/20261117 [--key base_dataset] [--out PATH]
"""
import argparse
import csv
import hashlib
import json
import os
import sys

from export_triage_json import DET, THESIS, ba_auc, ba_sd, families, load, paired, r3, sha, view

HERE = os.path.dirname(os.path.abspath(__file__))


def short(base, rule, vname, span):
    s = base["rules"][rule]["views"][vname][span]
    c = s["c2_subset"]
    return {"n": {"malicious": s["malicious"], "benign": s["benign"]},
            "BA_sd": ba_sd(s["scores"]),
            "per_stratum": {k: dict(n=v["n"], measure=v["measure"], **{d: r3(v[d]) for d in DET})
                            for k, v in s["per_stratum"].items()},
            "minus_host": paired(s["minus_host"]),
            "baselines_BA": dict({k: r3(v["ba_mean"]) for k, v in s["baselines"].items()},
                                 noise_p95=r3(s["noise_reference"]["p95"])),
            "c2_subset_BA": {d: r3(c["scores"][d]["ba_mean"]) for d in DET},
            "c2_subset_minus_host": paired(c["minus_host"])}


def relabel(v):
    """view() (written for the Triage cohort, which had only malware) calls the malicious groups "malware_families";
    in the base they also hold the attack instances, so name them for what they are."""
    n = v["n"]
    n["malicious_groups"] = n.pop("malware_families")
    n["label0_groups"] = n.pop("benign_groups")
    return v


def main():
    p = argparse.ArgumentParser()
    p.add_argument("base_dir")
    p.add_argument("--key", default="base_dataset")
    p.add_argument("--out", default=os.path.join(THESIS, "data", "lab", "session_lab.json"))
    a = p.parse_args()
    bdir = os.path.abspath(a.base_dir)
    base = load(os.path.join(bdir, "base.json"))
    rules = base["rules"]
    spans = [k for k in rules["relaxed"]["views"]["sessions"] if k not in ("composition", "files")]
    srcs = {"base.json": sha(os.path.join(bdir, "base.json")), "manifest.csv": sha(os.path.join(bdir, "manifest.csv"))}
    for rule in rules:
        for vname, v in rules[rule]["views"].items():
            for span, f in v["files"].items():
                srcs[f["csv"]] = sha(os.path.join(bdir, f["csv"]))
                assert srcs[f["csv"]] == f["sha256"], f["csv"]        # the CSV is the one base.json was scored on
    with open(os.path.join(bdir, "manifest.csv")) as fh:
        man = list(csv.DictReader(fh))
    block = {
        "_note": ("Base dataset: every session-lab run under the main settings pooled (each run balanced by design), "
                  "one acceptance rule for all (relaxed: a capacity-only overflow of the host monitor's connect-address "
                  "set is tolerated for malware and attack sessions, as the flood and Triage protocols declared; strict as "
                  "a sensitivity check). Program rows: the injected program's own windows from its injection. Grouped CV "
                  "(malware family / attack instance / benign project or shape held out), 10 fold assignments, RF500 "
                  "balanced, threshold 0.5. Separate collection; never merged with the 240-row dataset."),
        "folder": os.path.relpath(bdir, HERE),
        "runs": base["runs"],
        "program_sessions_loaded": base["loaded_program_sessions"],
        "skipped": base["skipped"],
        "manifest_rows": len(man),
        "accepted_relaxed_only": sum(1 for r in man if r["accepted_relaxed"] == "1" and r["accepted_strict"] == "0"),
        "cap_dropped": {rule: rules[rule].get("cap_dropped") for rule in rules},
        "composition": {vname: rules["relaxed"]["views"][vname]["composition"] for vname in rules["relaxed"]["views"]},
        "primary_relaxed_sessions": {span: relabel(view(base, "relaxed", span)) for span in spans},
        "sensitivity": {"%s_%s" % (rule, vname): {span: short(base, rule, vname, span) for span in spans
                                                  if span in rules[rule]["views"][vname]}
                        for rule in rules for vname in rules[rule]["views"]
                        if (rule, vname) != ("relaxed", "sessions")},
        "_unscored": "build_base.py scores the strict/unique view at 20 s only (a sensitivity check of a sensitivity check)",
        "builder_inputs": base["inputs"],
        "_sources_sha256": srcs,
        "_exporter_sha256": sha(os.path.abspath(__file__)),
    }
    out = load(a.out)
    out[a.key] = block
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    os.replace(tmp, a.out)
    print("wrote %s (%s, %d sources)" % (a.out, a.key, len(srcs)))


if __name__ == "__main__":
    sys.exit(main())
