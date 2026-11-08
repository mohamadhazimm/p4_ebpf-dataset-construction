#!/usr/bin/env python3
"""Write REPORT.md tables for one LID-DS evaluation (prepare_lidds.py + evaluate_lidds.py output).

    python3 -I report_lidds.py EVALUATION_DIR PREPARED_DIR [PREPARED_DIR ...]
"""

import json
import sys
from collections import Counter
from pathlib import Path

MODELS = ("host-only", "network-only", "hybrid", "concatenated", "activity-only", "position-only")
NAMES = {"CVE-2012-2122.zip": "MySQL login bypass (CVE-2012-2122)", "CVE-2014-0160.zip": "Heartbleed (CVE-2014-0160)",
         "Bruteforce_CWE-307.zip": "Password brute force (CWE-307)", "CWE-89-SQL-injection.zip": "SQL injection (CWE-89)",
         "PHP_CWE-434.zip": "PHP upload to web shell (CWE-434)", "CVE-2017-7529.zip": "nginx range overflow (CVE-2017-7529)",
         "CVE-2017-12635_6.zip": "CouchDB privilege escalation + RCE (CVE-2017-12635/12636)",
         "CVE-2018-3760.zip": "Sprockets path traversal (CVE-2018-3760)", "CVE-2019-5418.zip": "Rails file disclosure (CVE-2019-5418)",
         "CVE-2020-9484.zip": "Tomcat session deserialization (CVE-2020-9484)", "CVE-2020-13942.zip": "Apache Unomi RCE (CVE-2020-13942)",
         "CVE-2020-23839.zip": "CVE-2020-23839", "EPS_CWE-434.zip": "EPS file upload (CWE-434)",
         "Juice-Shop.zip": "OWASP Juice Shop", "ZipSlip.zip": "ZipSlip archive path traversal"}


def pct(x):
    return "-" if x is None else "%.1f%%" % (100 * x)


def table(entries, keys=("balanced_accuracy", "recall", "false_alarm", "end_control_false_alarm", "auc")):
    head = "| Detector | Bal. acc. | Attack recall | False alarms (normal) | False alarms (end control) | AUC |"
    lines = [head, "|---|---:|---:|---:|---:|---:|"]
    for m in MODELS:
        e = entries[m]
        lines.append("| %s | %s | %s | %s | %s | %s |" % (m, pct(e["balanced_accuracy"]), pct(e["recall"]), pct(e["false_alarm"]),
                                                          pct(e["end_control_false_alarm"]), "%.3f" % e["auc"] if e["auc"] is not None else "-"))
    return "\n".join(lines)


def main():
    evaluation, prepared_dirs = Path(sys.argv[1]), [Path(a) for a in sys.argv[2:]]
    result = json.load(open(evaluation / "results.json"))
    recordings, rows = [], []
    for prepared in prepared_dirs:
        recordings += json.load(open(prepared / "recordings.json"))
        rows += json.load(open(prepared / "rows.json"))

    data = ["| Scenario | Recordings | Attack windows | Normal windows | Skipped (shorter than 10 s) |", "|---|---:|---:|---:|---:|"]
    for s in sorted({r["scenario"] for r in recordings}):
        rec = [r for r in recordings if r["scenario"] == s]
        kinds = Counter(r["kind"] for r in rows if r["scenario"] == s)
        data.append("| %s | %d | %d | %d | %d |" % (NAMES.get(s, s), len(rec), kinds["attack"], kinds["normal"],
                                                    sum(1 for r in rec if r.get("skipped"))))

    e1, e2 = result["E1_leave_one_scenario_out"], result["E2_pooled_5fold"]
    words = {5: "Five", 10: "Ten", 15: "All"}
    used = words.get(len(e1["per_scenario"]), str(len(e1["per_scenario"])))
    per1 = []
    for s, entries in e1["per_scenario"].items():
        per1.append("\n**Held out: %s**\n\n%s" % (NAMES.get(s, s), table(entries)))
    per2 = []
    for s, entries in e2["per_scenario"].items():
        per2.append("\n**%s**\n\n%s" % (NAMES.get(s, s), table(entries)))

    report = f"""# LID-DS 2021 check of the host, network and hybrid detectors

From `{evaluation.name}` (protocol SHA-256 `{result['protocol_sha256']}`). Offline; no VM, nothing executed.

## Data

LID-DS 2021 (Leipzig University) records real exploits against services in Docker containers, with
benign users whose timing comes from real web-server logs. Each recording has the victim container's
system calls and packet capture. {used} of its 15 scenarios were used:

{chr(10).join(data)}

One 10-s observation (20 windows of 0.5 s) per recording, with the paper's 90 host and 145 network
columns: the host features from the call-entry events of the victim's processes (`features/host_model.py`),
the network features from the frames of the victim's Ethernet interface through `features/switch_model.py`
(loopback frames dropped: a switch never sees them). Attack windows start 2 s before the logged attack
time; normal windows follow the same rule around a pseudo attack time drawn from the same scenario's
attack offsets. Controls: a second window of every normal recording placed near its end the way attack
windows are; never trained on.

## E1. Unseen attack type: leave one scenario out (primary)

Mean over the {len(e1['per_scenario'])} held-out scenarios:

{table(e1['mean_over_scenarios'])}
{''.join(per1)}

## E2. Seen attack types: 5-fold cross-validation over the pooled scenarios

Pooled:

{table(e2['pooled'])}
{''.join(per2)}
"""
    (evaluation / "REPORT.md").write_text(report)
    print("wrote", evaluation / "REPORT.md")


if __name__ == "__main__":
    main()
