#!/usr/bin/env python3
"""Add the numbers that thesis Chapter 6's "Detection in the Session Collection" (sec:eval-session) and Table IV's
unanswered-connection rule cite to the thesis data file data/lab/session_lab.json, under the key "ch6_session".

Nothing is recomputed: every number is copied from a saved result file, and the SHA-256 of each source is recorded.
Sources: the final base with both benign batches (base/20261117c: base.json, table45/, silent-server/, type_table.json),
the two pre-registered scorings (silentbenign_scores.json, netbenign_scores.json), the dataset cohort's held-out split
on the session rows (analysis-dataset-cohort/heldout.json), and the committee folder's Table IV rule interval
(committee-eval-20261113/results/heldout_rule_ci.json). The silent-listener rule over the session dataset's rows is
derived from the cross-tab's per-row counts (malicious rows that met the listener are its true positives; attacks and
the other malicious rows its false negatives), as stated in the block. The other keys are left unchanged.

  /usr/bin/python3 export_ch6_json.py [--base base/20261117c] [--out PATH]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from export_triage_json import THESIS, load, sha   # noqa: E402

SILENT_BATCH = "runs/20261117T013400746805Z/analysis/silentbenign_scores.json"
NET_BATCH = "runs/20261117T113428913222Z/analysis/netbenign_scores.json"
HELDOUT = "analysis-dataset-cohort/heldout.json"
CUE_CI = "../committee-eval-20261113/results/heldout_rule_ci.json"
DET = ("host", "network", "concat", "stacked")


def r3(x):
    return None if x is None else round(float(x), 3)


def view(base, rule, vname, span):
    s = base["rules"][rule]["views"][vname].get(span)
    if s is None:
        return None
    return {"n": {"malicious": s["malicious"], "benign": s["benign"], "groups": s["groups"]},
            "ba": {d: [r3(s["scores"][d]["ba_mean"]), r3(s["scores"][d]["ba_sd"])] for d in DET},
            "minus_host": {k: {"mean": r3(v["mean"]), "positive": v["positive"]} for k, v in s["minus_host"].items()}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="base/20261117c")
    p.add_argument("--out", default=os.path.join(THESIS, "data", "lab", "session_lab.json"))
    a = p.parse_args()
    B = os.path.join(HERE, a.base)
    src = {"base.json": os.path.join(B, "base.json"),
           "table5_base.json": os.path.join(B, "table45", "table5_base.json"),
           "table5_paper_sb_nb.json": os.path.join(B, "table45", "table5_paper_sb_nb.json"),
           "type_table.json": os.path.join(B, "type_table.json"),
           "crosstab.json": os.path.join(B, "silent-server", "crosstab.json"),
           "silent_server.json": os.path.join(B, "silent-server", "silent_server.json"),
           "silentbenign_scores.json": os.path.join(HERE, SILENT_BATCH),
           "netbenign_scores.json": os.path.join(HERE, NET_BATCH),
           "heldout.json": os.path.join(HERE, HELDOUT),
           "heldout_rule_ci.json": os.path.normpath(os.path.join(HERE, CUE_CI))}
    R = {k: load(v) for k, v in src.items()}
    base = R["base.json"]
    out = {"_note": "Numbers cited by thesis Ch6 sec:eval-session (2026-11-17) and Table IV's unanswered-connection "
                    "rule. Session dataset = base/20261117c (main, tpilot, floods, triage, rest, silentbenign, netbenign;"
                    " relaxed rule, sessions view). Separate collection; never merged with the 240-row dataset.",
           "_sources_sha256": {os.path.relpath(v, HERE): sha(v) for v in src.values()},
           "_exporter_sha256": sha(os.path.abspath(__file__))}
    # Table IV row: the unanswered-connection rule on the first collection's held-out split
    ci = R["heldout_rule_ci.json"]
    out["tableIV_unanswered_rule"] = {k: ci[k] for k in ("unanswered_rule", "network_detector",
                                                       "network_catches_with_cue", "network_catches")}
    # the held-out split repeated on the session rows
    h = R["heldout.json"]
    out["heldout_split_on_session_rows"] = {sp: {"rf42": {d: h["spans"][sp]["rf42"][d] for d in DET},
                                                 "rf_seeds_ba": {d: h["spans"][sp]["rf_seed_robustness"][d]["balanced_accuracy"]
                                                                 for d in DET},
                                                 "cue_rule": h["spans"][sp]["cue_rule"],
                                                 "baselines": h["spans"][sp]["baselines_rf42_balanced_accuracy"],
                                                 "n": h["spans"][sp]["n"]}
                                            for sp in ("20s", "80s")}
    # the session dataset (Table V format) and the re-collected pool
    out["session_dataset_tableV"] = {sp: R["table5_base.json"]["spans"][sp] for sp in ("20s", "80s")}
    out["recollected_pool_tableV"] = {sp: R["table5_paper_sb_nb.json"]["spans"][sp] for sp in ("20s", "80s")}
    rel = base["rules"]["relaxed"]["views"]["sessions"]
    out["session_dataset_baselines"] = {sp: {"baselines": {k: r3(v["ba_mean"]) for k, v in rel[sp]["baselines"].items()},
                                             "noise_reference": rel[sp]["noise_reference"]} for sp in ("20s", "80s")}
    out["session_dataset_sensitivity"] = {"%s_%s_%s" % (rule, vname, sp): view(base, rule, vname, sp)
                                          for rule in ("relaxed", "strict") for vname in ("sessions", "unique")
                                          for sp in ("20s", "80s")}
    out["implants_vs_benign"] = {sp: {"n_implant": rel[sp]["c2_subset"]["n_implant"],
                                      "n_benign": rel[sp]["c2_subset"]["n_benign"],
                                      "scores": {d: {k: r3(rel[sp]["c2_subset"]["scores"][d][k])
                                                     for k in ("ba_mean", "ba_sd", "recall_mean", "specificity_mean")}
                                                 for d in DET},
                                      "per_family_recall": rel[sp]["c2_subset"]["per_family_recall"],
                                      "minus_host": rel[sp]["c2_subset"]["minus_host"]} for sp in ("20s", "80s")}
    out["type_table"] = R["type_table.json"]["spans"]
    # silent listener over the session dataset
    x = R["crosstab.json"]
    allp = x["all_programs"]
    tp = allp["network"]["malicious_cue"]["n"]
    fn = allp["network"]["malicious_no_cue"]["n"] + allp["network"]["attack"]["n"]
    fp = allp["network"]["benign_cue"]["n"]
    tn = allp["network"]["benign_no_cue"]["n"]
    rec, spec = tp / (tp + fn), tn / (tn + fp)
    out["silent_listener"] = {
        "cue": x["cue"],
        "flag_rate_by_cue": allp, "implants_vs_benign_by_cue": x["c2_vs_benign"],
        "implant_family_flag_rate_by_cue": x["c2_family_flag_rate_by_cue"],
        "rule_on_session_dataset_rows": {"tp": tp, "fn": fn, "tn": tn, "fp": fp, "recall": r3(rec),
                                         "specificity": r3(spec), "balanced_accuracy": r3((rec + spec) / 2),
                                         "_derivation": "rows with the cue flagged; attacks (no cue record) and malicious "
                                                        "rows without the cue are false negatives"},
        "rule_per_program": {k: R["silent_server.json"][k] for k in
                             ("rule_silent_server_client_sent_all_programs", "rule_silent_server_client_sent_c2_vs_benign",
                              "network_active_benign")}}
    # the two pre-registered benign batches
    sb = R["silentbenign_scores.json"]
    out["silent_server_batch"] = {"rule": sb["protocol_decision_rule"], "decision": sb["decision"],
                                  "with_batch": sb["with_batch"], "without_batch": sb["without_batch"]}
    nb = R["netbenign_scores.json"]
    out["network_client_batch"] = {"new_rows": nb["new_rows"], "Q1": nb["Q1_network_false_alarms"],
                                   "Q2": nb["Q2_hybrid_over_host"], "Q3": nb["Q3_original_rows"],
                                   "Q4_flag_rate": nb["Q4_transfer"]["flag_rate"],
                                   "Q4_by_program": nb["Q4_transfer"]["by_program"],
                                   "batch_check": nb["batch_check"]}
    data = load(a.out)
    data["ch6_session"] = out
    with open(a.out, "w") as f:
        json.dump(data, f, indent=1, sort_keys=False)
        f.write("\n")
    print("wrote ch6_session to", a.out, "rule", out["silent_listener"]["rule_on_session_dataset_rows"])


if __name__ == "__main__":
    main()
