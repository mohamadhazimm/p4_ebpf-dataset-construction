#!/usr/bin/env python3
"""Add the final Triage-cohort results to the thesis data file data/lab/session_lab.json.

Every number is copied from a saved result file of the Triage cohort's final analysis (nothing is recomputed):
  runs/20261116T153432251861Z/analysis-final/summary.json            run outcome (summarize_runs.py)
  runs/20261116T153432251861Z/analysis-final/comparison.json         behaviour, benign agreement, transfer, machine
                                                                     windows, lab cue (compare_session_lab.py)
  runs/20261116T153432251861Z/analysis-final/base-triage/base.json   per-program grouped CV, Triage sessions only
  runs/20261116T153432251861Z/analysis-final/base-triage-families/base.json
                                                                     the same with the network-active pilot's sessions
                                                                     (13 more benign network clients)
and each file's SHA-256 is recorded. Malware are named by family only. The other keys of session_lab.json are left
unchanged; the file is rewritten as indented JSON.

  /usr/bin/python3 export_triage_json.py [--out PATH]
"""
import argparse
import hashlib
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
THESIS = "/home/ali/Desktop/Hazim/a-unified-p4-ebpf-architecture-for-host-and-network-malware-detection"
RUN = "runs/20261116T153432251861Z"
AF = RUN + "/analysis-final"
C2 = ("rekoobe", "sliver", "vshell", "adaptixc2", "ladvix")      # the protocol's "host-quiet C2/backdoor implants"
DET = ("host", "network", "concat", "stacked")


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load(path):
    with open(path) as f:
        return json.load(f)


def r3(x):
    return None if x is None else round(float(x), 3)


def ba_auc(scores):
    return {d: [r3(scores[d]["ba_mean"]), r3(scores[d]["auc_mean"])] for d in DET if d in scores}


def ba_sd(scores):
    return {d: [r3(scores[d]["ba_mean"]), r3(scores[d]["ba_sd"])] for d in DET if d in scores}


def paired(m):
    return {k: {"mean": r3(v["mean"]), "positive": "%d/%d" % (v["positive"], v["assignments"])} for k, v in m.items()}


def families(per_group):
    out = {}
    for g, v in sorted(per_group.items()):
        if v.get("label") == 1 and g.startswith("family::"):
            out[g[len("family::"):]] = dict(rows=v["rows"], **{d: r3(v[d]) for d in DET})
    return out


def view(base, rule, span):
    s = base["rules"][rule]["views"]["sessions"][span]
    c = s["c2_subset"]
    return {
        "n": {"malicious": s["malicious"], "benign": s["benign"], "malware_families": s["groups"]["malicious"],
              "benign_groups": s["groups"]["benign"]},
        "BA_sd": ba_sd(s["scores"]),
        "BA_AUC": ba_auc(s["scores"]),
        "per_stratum": {k: dict(n=v["n"], measure=v["measure"], **{d: r3(v[d]) for d in DET})
                        for k, v in s["per_stratum"].items()},
        "minus_host": paired(s["minus_host"]),
        "baselines_BA": dict({k: r3(v["ba_mean"]) for k, v in s["baselines"].items()},
                             noise_p95=r3(s["noise_reference"]["p95"])),
        "per_family_recall": families(s["per_group"]),
        "c2_subset": {"implants": c["n_implant"], "benign": c["n_benign"], "families": c["families"],
                      "BA_AUC": ba_auc(c["scores"]), "minus_host": paired(c["minus_host"]),
                      "lifetime_baseline_BA": r3(c["lifetime_baseline"]["ba_mean"]),
                      "noise_p95": r3(c["noise_reference"]["p95"]),
                      "per_family_recall": families(c["per_family_recall"])},
    }


def machine(d):
    return {"BA_AUC": ba_auc(d["grouped_cv"]), "activity_BA": r3(d["activity_baseline"]["ba_mean"]),
            "position_BA": r3(d["position_baseline"]["ba_mean"]), "minus_host": paired(d["paired"])}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default=os.path.join(THESIS, "data", "lab", "session_lab.json"))
    a = p.parse_args()
    files = {"summary": AF + "/summary.json", "comparison": AF + "/comparison.json",
             "base_triage": AF + "/base-triage/base.json", "base_with_pilot": AF + "/base-triage-families/base.json",
             "protocol": RUN + "/protocol.json"}
    src = {k: os.path.join(HERE, v) for k, v in files.items()}
    S, C, BT, BP, P = (load(src[k]) for k in ("summary", "comparison", "base_triage", "base_with_pilot", "protocol"))
    run = S[0] if isinstance(S, list) else S
    A = C["A_behaviour"]
    C1 = C["C_per_program"]["20s"]
    fam_cap = P["malware_selection"]["families"]
    calls_20s = {}
    for smp in A["samples"]:
        calls_20s.setdefault(smp["family"], []).append(smp["session_host_calls_20s"])
    block = {
        "_note": ("54 malware from 13 Triage families chosen because they use the network on Triage's internet "
                  "sandbox (capped), 44 mode-matched benign, 9 controls; the main run's settings. Pre-registered "
                  "question (protocol 'expectations'): for the host-quiet C2/backdoor implants, does the network "
                  "view catch what the host view misses? Network-view recall is optimistic by selection."),
        "attempt": os.path.basename(RUN),
        "protocol_question": P["expectations"]["the_question"],
        "selection": {"families": fam_cap, "n": P["malware_selection"]["n"]},
        "outcome": {"planned": run["planned"], "by_status": run["by_status"], "by_kind_status": run["by_kind_status"],
                    "not_accepted": [{"sid": r[0], "kind": r[1], "status": r[3], "reason": r[4]} for r in run["reasons"]],
                    "phases": {k: v[-1] for k, v in run["phases"].items()},
                    "minutes_per_session_median": r3(run["minutes"]["median"]),
                    "flows_attributed_share": r3(run["flows_attributed_share"])},
        "relaxed_rule_only": {"sessions": 5, "family": "fritzfrog",
                              "reason": "capacity-only overflow of the host monitor's 64-slot connect-address set"},
        "behaviour": {"session_class": {k.split(" -> ")[-1]: v for k, v in A["triage_vs_session"].items()},
                      "session_class_first_20s": {k.split(" -> ")[-1]: v for k, v in A["dataset_lab_vs_session_20s"].items()},
                      "host_calls_20s_median_by_family": {f: statistics.median(v) for f, v in sorted(calls_20s.items())},
                      "benign_reproduce_median_spearman": r3(C["B_benign_agreement"]["median_spearman"]),
                      "benign_tasks": len(C["B_benign_agreement"]["tasks"]),
                      "injection_time_median_s": {"malicious": r3(C["C_injection_time_by_class"]["malicious_median_s"]),
                                                  "benign": r3(C["C_injection_time_by_class"]["benign_median_s"]),
                                                  "mannwhitney_p": r3(C["C_injection_time_by_class"]["mannwhitney_p"])},
                      "lab_cue_rule_BA": r3(C["E_lab_cue"]["metrics"]["balanced_accuracy"]),
                      "lab_cue_flagged_malware": r3(C["E_lab_cue"]["flagged_by_kind"]["malware"])},
        "per_program_triage_only": {"_protocol": "injected program's own rows; grouped CV (families / benign projects "
                                                 "held out), 10 fold assignments; relaxed rule (primary)",
                                    "20s": view(BT, "relaxed", "20s"), "80s": view(BT, "relaxed", "80s")},
        "per_program_with_pilot": {"_protocol": "as above, with the network-active pilot's 33 sessions (13 more malware "
                                                "of the same families, 13 benign network clients)",
                                   "20s": view(BP, "relaxed", "20s"), "80s": view(BP, "relaxed", "80s")},
        "strict_rule_sensitivity_triage_only": {"20s": view(BT, "strict", "20s")["BA_sd"],
                                                "80s": view(BT, "strict", "80s")["BA_sd"]},
        "families_seen_20s_BA": {d: r3(C1["C2_seen_families"][d]["ba_mean"]) for d in DET},
        "transfer_paper_detectors_20s": {
            "_note": "trained on the 240 dataset rows; BA / specificity",
            "all_columns": {d: [r3(C1["C1_transfer"][d]["balanced_accuracy"]), r3(C1["C1_transfer"][d]["specificity"])]
                            for d in DET},
            "without_6_startup_columns": {
                d: [r3(C1["C1_transfer_without_prologue_signals"]["metrics"][d]["balanced_accuracy"]),
                    r3(C1["C1_transfer_without_prologue_signals"]["metrics"][d]["specificity"])] for d in DET}},
        "whole_machine_windows": {"10s_as_placed": machine(C["D_machine_windows"]),
                                  "10s_position_matched": machine(C["D_machine_windows_matched"]),
                                  "30s_as_placed": machine(C["D_machine_windows_30s"]),
                                  "30s_position_matched": machine(C["D_machine_windows_30s_matched"])},
        "_sources_sha256": {v: sha(src[k]) for k, v in files.items()},
        "_exporter_sha256": sha(os.path.abspath(__file__)),
    }
    out = load(a.out)
    out.setdefault("runs", {})["triage_cohort"] = {
        "attempt": os.path.basename(RUN), "planned": run["planned"], "ran": sum(run["by_status"].values()),
        "accepted": run["by_status"]["accepted"], "status": "final",
        "note": "54 Triage malware (13 families, capped), 44 benign, 9 controls; 1 rejected (background-only, no "
                "clock probes), 2 failed (VM boot hang)"}
    out["triage_cohort"] = block
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    os.replace(tmp, a.out)
    print("wrote %s (triage_cohort, %d sources)" % (a.out, len(block["_sources_sha256"])))


if __name__ == "__main__":
    sys.exit(main())
