#!/usr/bin/env python3
"""Print the tables of a cross_eval.py result folder.   /usr/bin/python3 report_cross.py RESULT_DIR"""
import json
import sys
from pathlib import Path

M = ("host-only", "network-only", "hybrid", "concatenated", "activity-only")


def pct(x):
    return "  -  " if x is None else "%5.1f" % (100 * x)


def main():
    r = json.load(open(Path(sys.argv[1]) / "results.json"))
    for v in ("prologuefree", "ascollected"):
        a = r["A_train_lidds_test_ours"][v]
        print("\n== A: train LID-DS, test ours (%s); stacker %s" % (v, a["stacker"]))
        print("%-14s %6s %6s %6s %6s | %6s %6s | flagged at 0.5: %s" % ("model", "BA", "AUC", "rec", "FA", "BA204", "AUC204",
                                                                         " ".join(sorted(a["host-only"]["flagged_at_0.5"]))))
        for m in M:
            x, g = a[m]["all_240"], a[m]["malware_vs_benign_204"]
            f = a[m]["flagged_at_0.5"]
            print("%-14s %6s %6.3f %6s %6s | %6s %6.3f | %s" % (m, pct(x["balanced_accuracy"]), x["auc"], pct(x["recall"]),
                  pct(x["false_alarm"]), pct(g["balanced_accuracy"]), g["auc"], " ".join(pct(f[c]) for c in sorted(f))))
        print("  enrolled on our benign (recall at 2/5/10%% FA):")
        for m in M:
            e = a[m]["enrolled_all_240"]
            print("   %-14s %s" % (m, "  ".join("%s:%s(FA %s)" % (k, pct(e[k]["recall"]), pct(e[k]["false_alarm"])) for k in e)))
        b = r["B_train_ours_test_lidds"][v]
        print("\n== B: train ours (%s), test LID-DS; stacker %s" % (v, b["stacker"]))
        print("%-14s %6s %6s %6s %6s %8s | mean/scen BA AUC" % ("model", "BA", "AUC", "rec", "FA", "endctrl"))
        for m in M:
            x = b[m]["pooled"]
            ms = b[m]["mean_over_scenarios"]
            print("%-14s %6s %6.3f %6s %6s %8s | %6s %6.3f" % (m, pct(x["balanced_accuracy"]), x["auc"], pct(x["recall"]),
                  pct(x["false_alarm"]), pct(b[m]["end_control_flagged"]), pct(ms["balanced_accuracy"]), ms["auc"]))
        print("  enrolled on LID-DS normal: pooled recall at 2/5/10% FA | per-scenario threshold mean recall")
        for m in M:
            e, es = b[m]["enrolled_pooled"], b[m]["enrolled_per_scenario"]
            print("   %-14s %s | %s" % (m, " ".join(pct(e[k]["recall"]) for k in e), " ".join(pct(es[k]["mean_recall"]) for k in es)))
        print("  per scenario AUC (host / network / hybrid / concatenated):")
        for s in sorted(b["host-only"]["per_scenario"]):
            print("   %-28s %s" % (s, " ".join("%.3f" % b[m]["per_scenario"][s]["auc"] for m in M[:4])))
    print("\n== in-domain references")
    for v, d in r["reference_in_domain"]["ours_10s_grouped_cv_10_assignments"].items():
        print("  ours 10 s %s: %s" % (v, {m: "%.3f+-%.3f AUC %.3f" % (d[m]["balanced_accuracy"]["mean"], d[m]["balanced_accuracy"]["sd"],
                                                                         d[m]["auc"]["mean"]) for m in d}))
    for k, d in r["reference_in_domain"]["lidds_10s_stored"].items():
        print("  LID-DS %s: %s" % (k, {m: "%.3f AUC %.3f" % (d[m]["balanced_accuracy"], d[m]["auc"]) for m in d}))
    print("\n== dataset-of-origin AUC:", r["dataset_origin_auc"])
    for side, d in r["medians"].items():
        for g, x in sorted(d.items()):
            print("  %-26s %s" % (g, {k: round(v, 1) for k, v in x.items()}))


if __name__ == "__main__":
    main()
