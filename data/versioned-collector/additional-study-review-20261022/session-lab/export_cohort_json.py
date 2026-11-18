#!/usr/bin/env python3
"""Add the dataset cohort's session-lab results to the thesis data file data/lab/session_lab.json (merge mode: the
other keys are left unchanged).

The dataset cohort is the main run plus the rest of the main plan: every program of the dataset (the 99 malware, the 6
malware the dataset rejected, the 105 benign tasks) with exactly one accepted session under the main settings.

  dataset_cohort_full     compare_session_lab.py on main + rest (base/<name>/dataset-programs/comparison.json):
                          behaviour against the dataset and Triage, benign agreement, per-program detection (grouped
                          CV, seen families, baselines, transfer of the dataset-trained detectors), whole-machine
                          windows at matched positions, the unanswered-connection rule
  dataset_cohort_heldout  dataset_cohort_heldout.py: the same rows on the paper's Table IV split

Nothing is recomputed; every number is copied from a saved result file, whose SHA-256 is recorded.

  /usr/bin/python3 export_cohort_json.py --comparison base/20261117/dataset-programs/comparison.json \
        --heldout analysis-dataset-cohort/heldout.json [--out PATH]
"""
import argparse
import os
import sys

from export_triage_json import THESIS, load, r3, sha

HERE = os.path.dirname(os.path.abspath(__file__))
DET = ("host", "network", "concat", "stacked")


def cv_block(cv):
    if not isinstance(cv, dict) or "host" not in cv:
        return cv
    return {d: {"ba": r3(cv[d]["ba_mean"]), "ba_sd": r3(cv[d]["ba_sd"]), "auc": r3(cv[d]["auc_mean"]),
                "recall": r3(cv[d]["recall_mean"]), "specificity": r3(cv[d]["specificity_mean"]),
                "recall_at_5fa": r3(cv[d].get("recall_at_5fa")), "recall_at_10fa": r3(cv[d].get("recall_at_10fa"))}
            for d in DET if d in cv}


def metrics_block(m):
    return {d: {k: (r3(v) if isinstance(v, float) else v) for k, v in m[d].items()} for d in DET if d in m}


def full(comp):
    A = comp["A_behaviour"]
    out = {"attempts": comp.get("attempts"), "sessions_scored": comp.get("sessions"), "kinds": comp.get("kinds"),
           "not_started": comp.get("not_started"),
           "behaviour_dataset_to_session": A.get("dataset_lab_vs_session"),
           "behaviour_other": {k: v for k, v in A.items() if k not in ("samples", "dataset_lab_vs_session")},
           "benign_agreement": {"median_spearman": r3(comp["B_benign_agreement"]["median_spearman"]),
                                "tasks": len(comp["B_benign_agreement"]["tasks"])},
           "injection_time_by_class": comp.get("C_injection_time_by_class"),
           "per_program": {}, "lab_cue_unanswered": comp.get("E_lab_cue")}
    for span, e in (comp.get("C_per_program") or {}).items():
        out["per_program"][span] = {
            "n": e.get("n"), "malicious": e.get("malicious"),
            "grouped_cv_families_held_out": cv_block(e.get("C2_grouped_cv")),
            "families_seen": cv_block(e.get("C2_seen_families")),
            "minus_host": e.get("C2_paired"),
            "baselines": {k: (r3(v.get("ba_mean")) if isinstance(v, dict) else v)
                          for k, v in (e.get("C2_baselines") or {}).items()},
            "noise_reference": e.get("C2_baseline_noise_reference"),
            "transfer_dataset_trained": metrics_block(e["C1_transfer"]) if "C1_transfer" in e else None,
            "transfer_without_prologue_signals": (
                {"signals_dropped": e["C1_transfer_without_prologue_signals"]["signals_dropped"],
                 "metrics": metrics_block(e["C1_transfer_without_prologue_signals"]["metrics"])}
                if "C1_transfer_without_prologue_signals" in e else None),
            "transfer_flagged_by_kind": e.get("C1_flagged_by_kind")}
    for key in ("D_machine_windows_matched", "D_machine_windows_30s_matched"):
        if key in comp:
            out[key.replace("D_", "")] = comp[key]
    return out


def heldout(h):
    out = {"protocol_sha256": h["protocol_sha256"], "script_sha256": h["script_sha256"],
           "table_iv_reference_rf42": metrics_block(h["table_iv_reference"]["rf42"]),
           "table_iv_reference_rf_seeds": h["table_iv_reference"]["rf_seed_robustness"], "spans": {}}
    for span, s in h["spans"].items():
        out["spans"][span] = {k: s[k] for k in ("rows", "outside_the_99", "dataset_malware_without_a_row", "n",
                                                "rf_seed_robustness", "flag_rate_by_cue", "cue_rule",
                                                "network_true_positives_rf42_with_cue",
                                                "baselines_rf42_balanced_accuracy", "flag_rate_by_test_group")
                              if k in s}
        out["spans"][span]["rf42"] = metrics_block(s["rf42"])
        out["spans"][span]["csv_sha256"] = s["csv_sha256"]
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--comparison", required=True)
    p.add_argument("--heldout", required=True)
    p.add_argument("--out", default=os.path.join(THESIS, "data", "lab", "session_lab.json"))
    a = p.parse_args()
    comp_f, held_f = os.path.abspath(a.comparison), os.path.abspath(a.heldout)
    comp, held = load(comp_f), load(held_f)
    doc = load(a.out)
    note = ("The dataset cohort in sessions: the main run plus the rest of the main plan, where every program of the "
            "dataset has exactly one accepted session under the main settings. Separate collection; never merged "
            "with the 240-row dataset; the network view carries the silent-listener cue (section 7.3).")
    doc["dataset_cohort_full"] = dict(full(comp), _note=note,
                                      _sources_sha256={os.path.relpath(comp_f, HERE): sha(comp_f)})
    doc["dataset_cohort_heldout"] = dict(heldout(held), _note=note + " Rows scored on the paper's Table IV split.",
                                         _sources_sha256={os.path.relpath(held_f, HERE): sha(held_f)})
    doc["dataset_cohort_full"]["_exporter_sha256"] = doc["dataset_cohort_heldout"]["_exporter_sha256"] = \
        sha(os.path.abspath(__file__))
    import json
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    os.replace(tmp, a.out)
    print("wrote %s (dataset_cohort_full, dataset_cohort_heldout)" % a.out)


if __name__ == "__main__":
    sys.exit(main())
