#!/usr/bin/env python3
"""Copy the CIC-YNU-IoTMal numbers used in the thesis and the journal into one JSON file.

Usage: export_thesis_json.py <thesis data/lab/cicynu.json>
Reads results.json, protocol.json and features/*.json next to this script; records their SHA-256.
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.abspath(os.path.join(HERE, *[".."] * 6))


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def rel(p):
    return os.path.relpath(p, WS)


r = json.load(open(os.path.join(HERE, "results.json")))
ARCHS = ["arm", "mips", "mipsel", "x86"]
feat = {a: json.load(open(os.path.join(HERE, "features", f"{a}.json"))) for a in ARCHS}
DET = ["host10", "net", "concat", "stacked", "act_host", "act_net", "act_both", "hostc50"]
NAME = {"host10": "host (whole trace)", "hostc50": "host (40 equal-count chunks)", "net": "network",
        "concat": "concatenated hybrid", "stacked": "stacked hybrid", "act_host": "volume: calls",
        "act_net": "volume: packets", "act_both": "volume: calls and packets"}
r3 = lambda x: round(float(x), 3)

fam_both, unknown = {}, 0
for a in ARCHS:
    for f, n in feat[a]["families_with_both"].items():
        fam_both[f] = fam_both.get(f, 0) + n
    unknown += feat[a]["pcap_families"].get("Unknown", 0)

out = {
    "dataset": "CIC-YNU-IoTMal (Dadkhah et al., Information Systems 140, 102722, 2026, doi:10.1016/j.is.2026.102722)",
    "used": "processed tables strace.parquet and pcap.parquet of arm, mips, mipsel, x86 (downloaded by the author 2026-11-23)",
    "sandbox": "one QEMU machine per sample with OpenWrt; x86 = qemu-system-i386 without KVM (public sandbox code); "
               "30-s runs; Internet on by default; benign programs written by language models (dataset page)",
    "features": {
        "host": "the release's host signals (features/host_model.py) over each whole trace; call sequences rebuilt "
                "exactly from the sliding-window counts (0 mismatched rows)",
        "network": "the dataset's own statistics per group of about 10 packets, summarized with the five statistics; "
                   "not the switch's 29 features (no raw packets)",
        "why_not_trained_detectors": "no raw packets and no call timestamps or process IDs, so neither the 0.5-s "
                                     "windows nor the switch's features can be computed",
    },
    "population": {"runs": r["n"], "benign": r["benign"], "malware": r["malware"],
                   "malware_by_family": {f: n for f, n in sorted(fam_both.items(), key=lambda kv: -kv[1]) if f != "Benign"},
                   "runs_by_arch": {a: feat[a]["samples_with_both_views"] for a in ARCHS},
                   "network_only_unknown_left_out": unknown,
                   "rebuild_mismatched_rows": sum(feat[a]["mismatched_rows"] for a in ARCHS)},
    "protocol": "RF500 balanced seed 42, threshold 0.5; random stratified 5-fold over fold seeds 42,0,1,2,3; "
                "leave one family out (Mirai, DarkNexus, Gafgyt, Generic; benign in 4 buckets); leave one "
                "architecture out; rules written before scoring (protocol.json)",
    "families_seen_random_folds": {NAME[d]: {"ba_mean": r3(r["P1_random"][d]["ba_mean"]),
                                             "ba_sd": r3(r["P1_random"][d]["ba_sd"]),
                                             "auc_mean": r3(r["P1_random"][d]["auc_mean"])} for d in DET},
    "family_held_out": {NAME[d]: {"ba_family_mean": r3(r["P2_family_out"][d]["pooled"]["ba_family_mean"]),
                                  "recall_family_mean": r3(r["P2_family_out"][d]["pooled"]["recall_family_mean"]),
                                  "specificity": r3(r["P2_family_out"][d]["pooled"]["specificity"]),
                                  "ba_by_family": {F: r3(r["P2_family_out"][d][F]["ba"]) for F in
                                                   ["Mirai", "DarkNexus", "Gafgyt", "Generic"]}} for d in DET},
    "architecture_held_out": {NAME[d]: {"ba_mean": r3(r["P3_arch_out"][d]["mean_ba"]),
                                        "ba_by_arch": {a: r3(r["P3_arch_out"][d][a]["ba"]) for a in ARCHS},
                                        "arm_specificity": r3(r["P3_arch_out"][d]["arm"]["specificity"])} for d in DET},
    "rules_written_before_scoring": {
        "host_beyond_volume": {"needed": 0.05,
                               "family_held_out": r3(r["decision_rules"]["R1_host_beyond_activity"]["host10_minus_activity_P2"]),
                               "architecture_held_out": r3(r["decision_rules"]["R1_host_beyond_activity"]["host10_minus_activity_P3"]),
                               "met": r["decision_rules"]["R1_host_beyond_activity"]["met"]},
        "fusion_gain": {"needed": "0.02 in at least 4 of 5 random-fold assignments and with families held out",
                        "random_folds_gain_per_assignment": [r3(g) for g in r["decision_rules"]["R2_fusion_helps"]["P1_gains"]],
                        "family_held_out_gain": r3(r["decision_rules"]["R2_fusion_helps"]["P2_gain_family_mean"]),
                        "met": r["decision_rules"]["R2_fusion_helps"]["met"]}},
    "importance_top3": {v: [k for k, _ in r["importance_full_data"][v][:3]] for v in ["host10", "net"]},
    "sources": {rel(p): sha(p) for p in [os.path.join(HERE, x) for x in
                ["results.json", "protocol.json", "extract_cicynu.py", "eval_cicynu.py", "README.md",
                 "export_thesis_json.py"] + [f"features/{a}.json" for a in ARCHS]]},
}
json.dump(out, open(sys.argv[1], "w"), indent=2, ensure_ascii=False)
print("wrote", sys.argv[1])
