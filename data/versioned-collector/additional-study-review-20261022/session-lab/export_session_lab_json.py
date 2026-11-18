#!/usr/bin/env python3
"""Write the thesis data file data/lab/session_lab.json from the saved results of the session lab: the frozen
protocols and session-phase results of both attempts, summarize_runs.py's summary and compare_session_lab.py's
comparison of one analysis folder.

Nothing is recomputed: every number is copied from a saved result file, and each source file's SHA-256 is recorded.
Malware samples are given by family and the first 8 hex digits of their SHA-256 (all are samples of the released
dataset). "status" is "final" when the main attempt's session phase has a result file, otherwise "interim".

  /usr/bin/python3 export_session_lab_json.py <analysis folder> [--out PATH]
"""
import argparse
import glob
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
THESIS = "/home/ali/Desktop/Hazim/a-unified-p4-ebpf-architecture-for-host-and-network-malware-detection"
ATTEMPTS = {"pilot": "runs/20261115T213142604626Z", "main": "runs/20261115T214153675625Z"}
SCRIPTS = ["DESIGN.md", "guest/enter.sh", "guest/session.sh", "guest/bg.sh", "run_session_lab.py",
           "run_session_main.py", "analyze_session_lab.py", "compare_session_lab.py", "summarize_runs.py",
           "tables_session_lab.py", "export_session_lab_json.py"]


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load(path):
    with open(path) as f:
        return json.load(f)


def phase_results(att):
    out = {}
    for phase in ("preflight", "sink-prepare", "sessions", "sink-logs", "sink-restore"):
        files = sorted(glob.glob(os.path.join(att, "phases", phase, "result*.json")))
        if files:
            r = load(files[-1])
            out[phase] = {"file": os.path.relpath(files[-1], HERE), "status": r.get("status"),
                          "finished_utc": r.get("finished_utc"), "stopped_at_deadline": r.get("stopped_at_deadline")}
    return out


def condensed_samples(samples):
    keep = ("family", "attempt", "sid", "dataset_split", "dataset_lab_class", "triage_class", "session_class",
            "session_class_20s", "session_flows", "session_answered", "session_flows_20s", "session_remotes",
            "session_ports", "session_first_contact_s", "session_dns_relayed", "dataset_packets_20s",
            "session_packets_20s", "dataset_host_calls_20s", "session_host_calls_20s", "spearman_235_vs_dataset",
            "program_ran")
    return [dict({"sha256_8": s["sha256"][:8]}, **{k: s.get(k) for k in keep}) for s in samples]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("analysis", help="folder with summary.json and comparison.json")
    p.add_argument("--out", default=os.path.join(THESIS, "data", "lab", "session_lab.json"))
    a = p.parse_args()
    adir = os.path.abspath(a.analysis)
    summary_f, comp_f, tables_f = (os.path.join(adir, n) for n in ("summary.json", "comparison.json", "tables.md"))
    summary, comp = load(summary_f), load(comp_f)
    sources = {os.path.relpath(f, HERE): sha(f) for f in (summary_f, comp_f, tables_f) if os.path.exists(f)}
    attempts = {}
    for name, rel in ATTEMPTS.items():
        att = os.path.join(HERE, rel)
        proto = os.path.join(att, "protocol.json")
        sources[os.path.relpath(proto, HERE)] = sha(proto)
        attempts[name] = {"path": rel, "protocol_sha256": sources[os.path.relpath(proto, HERE)],
                          "phases": phase_results(att)}
    for s in SCRIPTS:
        f = os.path.join(HERE, s)
        if os.path.exists(f):
            sources[s] = sha(f)
    status = "final" if attempts["main"]["phases"].get("sessions") else "interim"
    A = comp["A_behaviour"]
    out = {
        "what": "Session lab (LID-DS-like): dataset programs injected into running background activity in the "
                "analysis VM, hidden in-kernel monitors, network captured on the Sink; compared with the paired "
                "dataset. Post hoc, never merged with the dataset, no model promoted.",
        "status": status,
        "attempts": attempts,
        "runs": summary,
        "sessions_scored": comp.get("sessions"),
        "kinds_scored": comp.get("kinds"),
        "not_started": comp.get("not_started"),
        "A_behaviour": {k: v for k, v in A.items() if k != "samples"},
        "A_samples": condensed_samples(A["samples"]),
        "B_benign_agreement": {"median_spearman": comp["B_benign_agreement"]["median_spearman"],
                               "tasks": len(comp["B_benign_agreement"]["tasks"])},
        "C_per_program": comp.get("C_per_program"),
        "C_all_rows_20s": comp.get("C_all_rows_20s"),
        "D_machine_windows_10s": comp.get("D_machine_windows"),
        "D_machine_windows_30s": comp.get("D_machine_windows_30s"),
        "D_machine_windows_10s_position_matched": comp.get("D_machine_windows_matched"),
        "D_machine_windows_30s_position_matched": comp.get("D_machine_windows_30s_matched"),
        "C_injection_time_by_class": comp.get("C_injection_time_by_class"),
        "E_lab_cue": comp.get("E_lab_cue"),
        "sources_sha256": sources,
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, indent=1, sort_keys=False)
        f.write("\n")
    os.replace(tmp, a.out)
    print("wrote %s (status %s, %d sources)" % (a.out, status, len(sources)))


if __name__ == "__main__":
    sys.exit(main())
