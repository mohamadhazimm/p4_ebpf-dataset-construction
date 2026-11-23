#!/usr/bin/env python3
"""Tables from score_short.py's scores.json: no refit. The variants share the fold assignments (the folds depend on
the labels and groups only), so a variant's balanced accuracy minus the 0.5-s one is paired per assignment.

    /usr/bin/python3 summarize_scores.py run-20261120/scores.json > run-20261120/scores.txt
"""
import json
import sys

import numpy as np

DET = ("host", "network", "concat", "stacked")
s = json.load(open(sys.argv[1]))
paper, session = s["paper"], s["session"]
ref = "0.5 s published"


def pm(d, k="balanced_accuracy"):
    return "%.3f ± %.3f" % (d[k]["mean"], d[k]["sd"])


print("## Paper dataset, Table V protocol (grouped CV, 10 fold assignments): balanced accuracy")
print("| variant | " + " | ".join(DET) + " | host lifetime | network lifetime |")
print("|---|" + "---|" * (len(DET) + 2))
for name, v in paper.items():
    t5, b = v["table5"], v["baselines"]
    print("| %s | " % name + " | ".join(pm(t5[d]) for d in DET)
          + " | %.3f | %.3f |" % (b["host_lifetime"]["table5_ba_mean"], b["network_lifetime"]["table5_ba_mean"]))
print()
print("## Paper dataset, Table V: change against 0.5 s published, per fold assignment (mean, assignments higher of 10)")
print("| variant | " + " | ".join(DET) + " |")
print("|---|" + "---|" * len(DET))
for name, v in paper.items():
    if name == ref:
        continue
    cells = []
    for d in DET:
        a = np.asarray(v["table5"][d]["per_assignment_ba"]) - np.asarray(paper[ref]["table5"][d]["per_assignment_ba"])
        cells.append("%+.3f (%d)" % (a.mean(), int((a > 0).sum())))
    print("| %s | " % name + " | ".join(cells) + " |")
print()
print("## Paper dataset, Table V: hybrid minus host, per fold assignment (mean, assignments higher of 10)")
print("| variant | concat − host | stacked − host |")
print("|---|---|---|")
for name, v in paper.items():
    t5 = v["table5"]
    print("| %s | %+.3f (%d) | %+.3f (%d) |" % (name, t5["concat"]["minus_host"]["mean"], t5["concat"]["minus_host"]["positive"],
                                             t5["stacked"]["minus_host"]["mean"], t5["stacked"]["minus_host"]["positive"]))
print()
print("## Paper dataset, Table V: share flagged at 0.5 (mean over the 10 assignments)")
cats = ("malware", "network_attack", "benign", "network_benign", "null")
print("| variant | detector | " + " | ".join(cats) + " |")
print("|---|---|" + "---|" * len(cats))
for name, v in paper.items():
    for d in DET:
        f = v["table5"][d]["flagged_share"]
        print("| %s | %s | " % (name, d) + " | ".join("%.2f" % f[c] for c in cats) + " |")
print()
print("## Paper dataset, Table IV (held-out split): BA at forest seed 42 (TN/FP/FN/TP), and mean ± sd over 11 seeds")
print("| variant | " + " | ".join(DET) + " |")
print("|---|" + "---|" * len(DET))
for name, v in paper.items():
    cells = []
    for d in DET:
        t = v["table4"][d]
        m = t["seed42"]
        cells.append("%.3f (%d/%d/%d/%d); %.3f ± %.3f" % (m["balanced_accuracy"], m["tn"], m["fp"], m["fn"], m["tp"],
                                                       t["ba_mean_11_seeds"], t["ba_sd_11_seeds"]))
    print("| %s | " % name + " | ".join(cells) + " |")
print()
print("## Session dataset (host at 0.5 s, network at the window shown): balanced accuracy over 10 fold assignments")
print("| span, network window | " + " | ".join(DET) + " | network lifetime | C2 subset: network | C2 subset: stacked |")
print("|---|" + "---|" * (len(DET) + 3))
for name, v in session.items():
    sc, c2 = v["scores"], v["c2_subset"]["scores"]
    print("| %s | " % name + " | ".join("%.3f ± %.3f" % (sc[d]["ba_mean"], sc[d]["ba_sd"]) for d in DET)
          + " | %.3f | %.3f | %.3f |" % (v["network_lifetime_baseline"]["ba_mean"], c2["network"]["ba_mean"],
                                         c2["stacked"]["ba_mean"]))
print()
print("## Session dataset: hybrid minus host per fold assignment (mean, assignments higher of 10)")
print("| span, network window | concat − host | stacked − host |")
print("|---|---|---|")
for name, v in session.items():
    mh = v["minus_host"]
    print("| %s | %+.3f (%d) | %+.3f (%d) |" % (name, mh["concat_minus_host"]["mean"], mh["concat_minus_host"]["positive"],
                                             mh["stacked_minus_host"]["mean"], mh["stacked_minus_host"]["positive"]))
print()
print("## Session dataset: recall (malicious strata) or specificity (benign strata), mean over assignments")
strata = list(next(iter(session.values()))["per_stratum"])
print("| span, network window | detector | " + " | ".join(strata) + " |")
print("|---|---|" + "---|" * len(strata))
for name, v in session.items():
    for d in DET:
        print("| %s | %s | " % (name, d) + " | ".join("%.2f" % v["per_stratum"][k][d] for k in strata) + " |")
