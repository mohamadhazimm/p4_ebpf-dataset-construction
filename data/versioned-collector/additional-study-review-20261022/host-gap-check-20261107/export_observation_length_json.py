"""Write the thesis data file data/lab/observation_length.json from the saved results of the observation-length
study (host-gap check, timing control, simulation estimate, nested design, length sweep, paper-vs-5-min comparison,
seed spread) and from the collection attempts' frozen protocols, validation and behaviour reports.

Nothing is recomputed: every number is copied from a saved result file, and each source file's SHA-256 is recorded.
"status" is "estimate" while the real bursty/rest runs are not yet scored and "final" once length_sweep_real.json
and nested_design_real.json exist.   Run: /usr/bin/python3 export_observation_length_json.py [--out PATH]
"""
import argparse
import glob
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
THESIS = "/home/ali/Desktop/Hazim/a-unified-p4-ebpf-architecture-for-host-and-network-malware-detection"
ATTEMPTS = {
    "pilot": "pilot-5min/20261105T212404537976Z",
    "scale": "scale-5min/20261105T224558731619Z",
    "topup": "topup-5min/20261106T073625330426Z",
    "finish": "topup-5min-finish/20261106T155820346732Z",
    "benign_expanded": "benign-expanded-5min/20261106T204303086228Z",
    "paced_wget": "wgetp-5min/20261107T015242522524Z",
    "bursty": "benign-bursty-5min/20261107T071120390917Z",
    "rest": "benign-rest-5min/20261107T080517413667Z",
}


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def load(path):
    return json.load(open(path)) if os.path.exists(path) else None


def latest(pattern):
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None


def attempt_record(name, rel):
    att = os.path.join(PROJ, rel)
    proto = load(os.path.join(att, "protocol.json"))
    if proto is None:
        return {"name": name, "path": rel, "status": "missing"}
    rec = {"name": name, "path": rel, "protocol_sha256": sha(os.path.join(att, "protocol.json")),
           "format": proto.get("format"), "counts": proto.get("counts"), "by_kind": proto.get("by_kind"),
           "network_benign": proto.get("network_benign"), "new_snapshot": proto.get("new_snapshot"),
           "runs_with_run_json": len(glob.glob(att + "/runs/*/output/run_*/run.json"))}
    val = latest(att + "/validation-*.json")
    if val:
        v = load(val)
        rec["validation"] = {"file": os.path.basename(val), "counts": v.get("counts"),
                             "accepted_by_mode_label": v.get("accepted_by_mode_label"),
                             "excluded": [{"sample": r["sample"], "reason": r.get("reason")} for r in v.get("results", [])
                                          if r.get("status") != "accepted"]}
    beh = latest(att + "/behavior-*.json")
    if beh:
        b = load(beh)
        rec["behaviour_check"] = {"file": os.path.basename(beh), "counts": b.get("counts"), "mismatches": b.get("mismatches")}
    for phase in ("preflight", "stage", "dry-run", "collect"):
        r = load(os.path.join(att, "phases", phase, "result.json"))
        if r:
            rec.setdefault("phases", {})[phase] = r.get("status")
    return rec


def parse_seed_spread(path):
    """hybrid_seed_spread.log -> {row label: {"ba": [...], "auc": [...]}} (10 seeds each)."""
    if not os.path.exists(path):
        return None
    out, section = {}, "ba"
    for line in open(path):
        if line.startswith("AUC (ranking)"):
            section = "auc"
            continue
        m = re.match(r"^([A-D] .+?)\s{2,}((?:-?\d\.\d\d\s+){10})\s*(\d\.\d\d)\s+(\d\.\d\d)\s*$", line.rstrip("\n"))
        if m:
            vals = [float(x) for x in m.group(2).split()]
            out.setdefault(m.group(1).strip(), {})[section] = {"per_seed": vals, "mean": float(m.group(3)), "sd": float(m.group(4))}
    return out or None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(THESIS, "data/lab/observation_length.json"))
    a = ap.parse_args()
    f = lambda name: os.path.join(HERE, name)
    sources = {name: f(name) for name in (
        "compare_host.json", "timing_control.json", "estimate_with_paper_short.json", "paper_vs_5min.json",
        "nested_design_estimate.json", "length_sweep_estimate.json", "design_freeze.json", "hybrid_seed_spread.log",
        "nested_design_real.json", "length_sweep_real.json", "rescore_with_bursty.json",
        "length_sweep_real_bursty_only.json", "final_baselines.json", "same_benign_twice.json", "sink_status.json",
        "final_cohort_server_state.json", "server_outage_swap.json", "server_outage_drop.json",
        "final_per_group.json")}
    present = {k: v for k, v in sources.items() if os.path.exists(v)}
    final = "length_sweep_real.json" in present and "nested_design_real.json" in present
    sink = load(present.get("sink_status.json", ""))
    state = load(present.get("final_cohort_server_state.json", "")) or []
    compare, timing, est = load(present.get("compare_host.json", "")), load(present.get("timing_control.json", "")), \
        load(present.get("estimate_with_paper_short.json", ""))
    pv = load(present.get("paper_vs_5min.json", ""))
    out = {
        "status": "final" if final else "estimate",
        "note": ("Final: all real runs scored (the bursty/short and rest benign runs included). The lab server's services "
                 "were down for the runs from 2026-11-06 16:02 UTC on (server_outage); 40 runs of the final cohort used it "
                 "while it was down. Replacing 29 of them with their working-server twins (20 s) or leaving the affected "
                 "runs out (every length) moves the pre-registered design by at most 0.007 BA and the five-statistics "
                 "hybrid by up to +0.04. The author decided on 2026-11-07 not to re-run them: this is the final "
                 "collection."
                 if final else
                 "The 43 short benign tasks are SIMULATED from their 20-s captures (+ zero windows); the 15 sparse jobs and "
                 "the 62 remaining tasks are not included. Replace when the real runs are scored."),
        "collections": [attempt_record(n, r) for n, r in ATTEMPTS.items()],
        "paper_cohort_reference": (pv or {}).get("S1", {}).get("paper"),
        "five_min_cohort_v1": (pv or {}).get("S1", {}).get("five_V1"),
        "five_min_cohort_estimate": (pv or {}).get("S1", {}).get("five_est"),
        "same_malware_measured_twice": (pv or {}).get("S4"),
        "what_20s_misses": (pv or {}).get("S5"),
        "simulation_check_first_real_short_runs": (pv or {}).get("S6"),
        "host_gap_check": None if compare is None else {
            "table_iv_reproduced": compare["E0"], "grouped_cv_10_seeds": compare["cv"],
            "false_alarms_by_program_seed42": compare["fp_by_program"],
            "active_windows_first20s": compare["E5_active_windows_first20s"],
            "random_group_heldout_splits": compare["E7"], "cohorts": compare["cohorts"]},
        "timing_control": None if timing is None else timing["scores"],
        "scores_by_cohort_paper_vs_5min": (pv or {}).get("S2_S3"),
        "estimate": {"length_sweep": load(present.get("length_sweep_estimate.json", "")),
                     "nested_design": load(present.get("nested_design_estimate.json", "")),
                     "simulated_cohorts": None if est is None else {k: v for k, v in est.items() if k != "scores"},
                     "simulated_scores": None if est is None else est["scores"]},
        "final": {"length_sweep": load(present.get("length_sweep_real.json", "")),
                  "nested_design": load(present.get("nested_design_real.json", "")),
                  "rescore": load(present.get("rescore_with_bursty.json", "")),
                  "shortcut_baselines": load(present.get("final_baselines.json", "")),
                  "benign_tasks_measured_twice_and_nulls": load(present.get("same_benign_twice.json", "")),
                  "errors_by_group": load(present.get("final_per_group.json", "")),
                  "interim_bursty_only_length_sweep": load(present.get("length_sweep_real_bursty_only.json", ""))},
        "server_outage": None if sink is None else {
            "per_batch": sink["per_batch"], "last_run_answered": sink["last_up"], "first_run_refused": sink["first_down"],
            "state_changes": sink["flips"],
            "final_cohort": {"runs": len(state),
                             "by_label_server_network": {"%s|%s|%s" % (lab, srv, net): sum(
                                 1 for x in state if x["label"] == lab and x["server"] == srv and x["network_active"] == net)
                                 for lab in ("malware", "benign") for srv in ("synack", "rst") for net in (True, False)},
                             "affected": sorted(x["sample"] for x in state if x["server"] == "rst" and x["network_active"])},
            "swap_test_20s": load(present.get("server_outage_swap.json", "")),
            "affected_runs_left_out": load(present.get("server_outage_drop.json", ""))},
        "seed_spread_of_the_earlier_0_88": parse_seed_spread(present.get("hybrid_seed_spread.log", "")),
        "design_freeze": load(present.get("design_freeze.json", "")),
        "provenance": {"analysis_dir": HERE, "source_files_sha256": {k: sha(v) for k, v in present.items()},
                       "scripts_sha256": {s: sha(f(s)) for s in ("compare_host.py", "timing_control.py",
                                                                    "estimate_with_paper_short.py", "paper_vs_5min.py",
                                                                    "nested_design.py", "length_sweep.py",
                                                                    "rescore_with_bursty.py", "hybrid_seed_spread.py",
                                                                    "final_baselines.py", "same_benign_twice.py",
                                                                    "sink_status.py", "server_outage_swap.py", "server_outage_drop.py",
                                                                    "final_per_group.py",
                                                                    "export_observation_length_json.py") if os.path.exists(f(s))},
                       "runner_v22_sha256": "b6d7abb91fd35d10514a85f354818e51786e2247a5f2354c051f7fdbbd8190f6",
                       "python": sys.version.split()[0]},
    }
    try:
        import numpy, sklearn, scipy  # noqa: F401
        out["provenance"].update(numpy=numpy.__version__, sklearn=sklearn.__version__, scipy=scipy.__version__)
    except ImportError:
        pass
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1, default=float)
    print("status", out["status"], "| wrote", a.out, "| sha256", sha(a.out))
    print("sources:", ", ".join(sorted(present)))


if __name__ == "__main__":
    main()
