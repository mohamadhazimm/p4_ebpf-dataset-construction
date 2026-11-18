#!/usr/bin/env python3
"""Add the silent-server cue check (silent_server_check.py, silent_cue_crosstab.py) to the thesis data file
data/lab/session_lab.json. Numbers are copied from the saved result files, whose SHA-256 are recorded.

  /usr/bin/python3 export_silent_json.py [--out PATH]
"""
import argparse
import json
import os
import sys

from export_triage_json import THESIS, load, sha

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = {"rule_triage_pilot": "analysis-silent-server/triage-tpilot/silent_server.json",
         "rule_main_floods": "analysis-silent-server/main-floods/silent_server.json",
         "crosstab_triage_pilot": "analysis-silent-server/crosstab-triage-tpilot.json",
         "crosstab_main": "analysis-silent-server/crosstab-main.json",
         "floods_attacks": "analysis-silent-server/floods-attacks/silent_server.json"}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default=os.path.join(THESIS, "data", "lab", "session_lab.json"))
    p.add_argument("--base", help="a build_base.py folder whose silent-server/ holds the check over every run")
    a = p.parse_args()
    src = {k: os.path.join(HERE, v) for k, v in FILES.items()}
    R = {k: load(v) for k, v in src.items()}
    keep = ("rule_silent_server_all_programs", "rule_silent_server_client_sent_all_programs",
            "rule_silent_server_c2_vs_benign", "rule_silent_server_client_sent_c2_vs_benign", "network_active_benign")
    block = {
        "_note": ("Post hoc check (after the Triage results): the passive sinkhole's catch-all listener accepts every TCP "
                  "connection INetSim does not serve and never sends data. Cue = a TCP connection on which the program "
                  "sent data and the server, after accepting, sent none (first 20 s after injection; 'any silent' also "
                  "counts connections where neither side sent data). Rule = flag a program with such a connection; no "
                  "fitting. Cross-tab = each detector's out-of-fold flag rate (build_base.py's grouped CV, 10 "
                  "assignments, unchanged) split by the cue."),
        "rule_triage_and_pilot": {k: R["rule_triage_pilot"][k] for k in keep},
        "rule_main": {k: R["rule_main_floods"][k] for k in keep},
        "family_share_with_silent_flow_triage_pilot": R["rule_triage_pilot"]["share_with_silent_server_flow"],
        "family_share_with_silent_flow_main": R["rule_main_floods"]["share_with_silent_server_flow"],
        "crosstab_triage_and_pilot": {"scores_BA": R["crosstab_triage_pilot"]["scores_BA"],
                                      "all_programs": R["crosstab_triage_pilot"]["all_programs"],
                                      "c2_scores_BA": R["crosstab_triage_pilot"]["c2_scores_BA"],
                                      "c2_vs_benign": R["crosstab_triage_pilot"]["c2_vs_benign"],
                                      "c2_family_flag_rate_by_cue": R["crosstab_triage_pilot"]["c2_family_flag_rate_by_cue"]},
        "crosstab_main": {"scores_BA": R["crosstab_main"]["scores_BA"], "all_programs": R["crosstab_main"]["all_programs"],
                          "rows_without_cue_record": R["crosstab_main"]["rows_without_cue_record"]},
        "_sources_sha256": {v: sha(src[k]) for k, v in FILES.items()},
        "_scripts_sha256": {s: sha(os.path.join(HERE, s)) for s in
                            ("silent_server_check.py", "silent_cue_crosstab.py", "export_silent_json.py")},
    }
    if a.base:
        bdir = os.path.abspath(a.base)
        rule_f, cross_f = (os.path.join(bdir, "silent-server", n) for n in ("silent_server.json", "crosstab.json"))
        rule, cross = load(rule_f), load(cross_f)
        block["full_base"] = {
            "runs": rule["runs"], "programs": rule["programs"], "by_kind": rule["by_kind"],
            "rule": {k: rule[k] for k in keep},
            "family_share_with_silent_flow": rule["share_with_silent_server_flow"],
            "crosstab": {k: cross[k] for k in ("rows", "malicious", "rows_without_cue_record", "scores_BA",
                                              "all_programs", "c2_scores_BA", "c2_vs_benign",
                                              "c2_family_flag_rate_by_cue") if k in cross},
            "_sources_sha256": {os.path.relpath(rule_f, HERE): sha(rule_f), os.path.relpath(cross_f, HERE): sha(cross_f)}}
    out = load(a.out)
    out["silent_server_cue"] = block
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    os.replace(tmp, a.out)
    print("wrote %s (silent_server_cue)" % a.out)


if __name__ == "__main__":
    sys.exit(main())
