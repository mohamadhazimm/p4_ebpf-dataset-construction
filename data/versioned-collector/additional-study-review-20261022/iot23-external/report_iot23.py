#!/usr/bin/env python3
"""Write REPORT.md for one evaluation of prepare_iot23.py / evaluate_iot23.py output.

    python3 -I report_iot23.py PREPARED_DIR EVALUATION_DIR
"""

import json
import sys
import time
from pathlib import Path

GROUP_ORDER = ("ddos", "scan", "attack", "cc", "other_malicious", "benign_device",
               "infected_quiet", "infected_idle", "benign_idle")
GROUP_NAMES = {
    "ddos": "DDoS (malware capture, DDoS flows overlap the chunk)",
    "scan": "Scan (horizontal port scan flows, no DDoS)",
    "attack": "Attack (other attack flows)",
    "cc": "C&C only (C&C, heartbeat or download flows)",
    "other_malicious": "Other malicious label",
    "benign_device": "Benign device traffic (Hue, Echo, Somfy)",
    "infected_quiet": "Control: infected device, only benign-labeled flows",
    "infected_idle": "Control: infected device, no flow",
    "benign_idle": "Control: benign device, no flow",
}


def pct(x):
    return "-" if x is None else "%.1f%%" % (100 * x)


def group_table(groups):
    lines = ["| Chunk category | Chunks | Scenarios | Flagged (mean over scenarios) | Flagged (pooled) | Median probability |",
             "|---|---:|---:|---:|---:|---:|"]
    for g in GROUP_ORDER:
        if g in groups:
            s = groups[g]
            lines.append("| %s | %d | %d | %s | %d (%s) | %.3f |" % (
                GROUP_NAMES[g], s["chunks"], s["scenarios"], pct(s["flagged_fraction_mean_over_scenarios"]),
                s["flagged_pooled"], pct(s["flagged_fraction_pooled"]), s["median_probability"]))
    return "\n".join(lines)


def scenario_table(groups, wanted):
    lines = ["| Category | Scenario | Family | Chunks | Flagged |", "|---|---|---|---:|---:|"]
    for g in wanted:
        if g in groups:
            for scenario, s in groups[g]["per_scenario"].items():
                lines.append("| %s | %s | %s | %d | %d (%s) |" % (g, scenario.replace("CTU-", ""), s["family"],
                                                                s["chunks"], s["flagged"], pct(s["fraction"])))
    return "\n".join(lines)


def headline(h):
    rows = [("DDoS recall", h.get("ddos_recall")), ("Scan recall", h.get("scan_recall")),
            ("Attack recall", h.get("attack_recall")), ("C&C-only recall", h.get("cc_recall")),
            ("False alarms on benign devices (mean of 3 devices)", h.get("benign_device_false_alarm")),
            ("Balanced accuracy, DDoS vs benign devices", h.get("balanced_accuracy_ddos_vs_benign"))]
    lines = ["| Measure | Value |", "|---|---:|"] + ["| %s | %s |" % (n, pct(v)) for n, v in rows]
    for key in sorted(k for k in h if k.startswith("auc_")):
        lines.append("| %s | %.3f |" % (key.replace("auc_", "AUC, ").replace("_vs_benign_device_pooled",
                                                                          " vs benign devices (pooled)"), h[key]))
    return "\n".join(lines)


def main():
    prepared, evaluation = Path(sys.argv[1]), Path(sys.argv[2])
    result = json.load(open(evaluation / "results.json"))
    protocol = json.load(open(evaluation / "protocol.json"))
    units = [json.load(open(p)) for p in sorted((prepared / "units").glob("*.json"))
             if not p.name.endswith((".rows.json", ".categories.json"))]

    data_lines = ["| Scenario | Family | Role | File | Hours | Frames | Chunks by category (all) | Sampled |",
                  "|---|---|---|---|---:|---:|---|---:|"]
    for u in sorted(units, key=lambda u: (u["role"], u["scenario"], u["pcap"])):
        hours = (u["last_us"] - u["first_us"]) / 3.6e9
        cats = ", ".join("%s %d" % kv for kv in sorted(u["chunks_by_category"].items()))
        data_lines.append("| %s | %s | %s | %s | %.1f | %d | %s | %d |" % (
            u["scenario"].replace("CTU-", ""), u["family"], u["role"], u["pcap"].split("/", 1)[1],
            hours, u["frames"], cats, u["sampled"]))

    audit_lines = ["| Scenario | Label | Published flows | Parsed flows | Match |", "|---|---|---:|---:|---|"]
    for scenario, labels in sorted(protocol["label_audit"].items()):
        for label, a in labels.items():
            audit_lines.append("| %s | %s | %d | %d | %s |" % (scenario.replace("CTU-", ""), label, a["published"],
                                                              a["parsed"], "yes" if a["match"] else "NO"))

    a, b = result["A_transfer"], result["B_within_iot23"]
    med = result["feature_medians"]
    feats = [k for k in next(iter(med.values())) if k != "n"]
    med_lines = ["| Group | n | " + " | ".join(f.replace("net_", "").replace("_delta", "") for f in feats) + " |",
                 "|---|---:|" + "---:|" * len(feats)]
    for name, m in med.items():
        med_lines.append("| %s | %d | " % (name, m["n"]) + " | ".join("%.3g" % m[f] for f in feats) + " |")

    report = f"""# IoT-23 external check of the switch features

Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} from `{evaluation.name}`
(protocol SHA-256 `{result['protocol_sha256']}`, release repository commit `{protocol['release_commit'][:12]}`).

Offline analysis of public packet captures. No virtual machine, no sample execution; the IoT-23 malware
binaries were never downloaded (only pcaps, labeled Zeek connection logs and READMEs).

## What was tested

IoT-23 (Stratosphere Laboratory, CC BY 4.0) has captures of real Linux IoT malware running on a
Raspberry Pi with Internet access, with per-flow labels, and captures of three benign IoT devices.
Every capture was cut into consecutive 20-s chunks. Each chunk is one observation in the dataset's
format: 40 windows of 0.5 s, the 29 window features of the switch model (`features/switch_model.py`,
fresh flow table per chunk), summarized into the 145 network columns (`features/summary.py`). A chunk's
category is the highest-priority label among the flows that overlap it (DDoS > scan > attack > C&C >
other > benign > none). At most 200 chunks per category and capture file were drawn with a fixed seed;
benign devices contribute 600 chunks each.

* **A. Transfer (primary).** The paper's network-only detector (random forest, 500 trees, balanced
  class weights, seed 42) trained on all 240 rows of `dataset/features.csv`, applied unchanged.
  Flagged = malicious probability >= 0.5.
* **B. Within IoT-23 (secondary).** The same random forest trained on IoT-23 chunks with
  leave-one-scenario-out folds (attack and C&C chunks vs benign-device chunks).

Fractions are computed per scenario and then averaged, so each capture counts once.

## Data

{chr(10).join(data_lines)}

Label files were checked against the flow counts published on the IoT-23 page:

{chr(10).join(audit_lines)}

## A. Transfer: the paper's network detector on IoT-23

Training rows: {a['training']['train_rows']} ({a['training']['train_malicious']} malicious).
Probability given to an all-zero network vector (no traffic): {a['probability_of_all_zero_vector']:.3f}.

{headline(a['headline'])}

{group_table(a['groups'])}

Per scenario:

{scenario_table(a['groups'], ('ddos', 'scan', 'attack', 'cc', 'benign_device', 'infected_quiet'))}

## B. Within IoT-23: same features, retrained, leave-one-scenario-out

{headline(b['headline'])}

{group_table(b['groups'])}

Per scenario:

{scenario_table(b['groups'], ('ddos', 'scan', 'attack', 'cc', 'benign_device', 'infected_quiet'))}

## Feature medians

IoT-23 chunk groups and the categories of the training dataset (`dataset:`):

{chr(10).join(med_lines)}
"""
    (evaluation / "REPORT.md").write_text(report)
    print("wrote", evaluation / "REPORT.md")


if __name__ == "__main__":
    main()
