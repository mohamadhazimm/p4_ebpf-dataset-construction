#!/usr/bin/env python3
"""Markdown tables for the session-lab report from summarize_runs.py --json and compare_session_lab.py output.

  /usr/bin/python3 tables_session_lab.py <summary.json> <comparison.json> > tables.md
"""
import json
import sys
from collections import Counter


def pct(x):
    return "%.0f%%" % (100 * x) if x == x else "-"


def f3(x):
    return "%.3f" % x if isinstance(x, (int, float)) and x == x else "-"


def main():
    summary = json.load(open(sys.argv[1]))
    comp = json.load(open(sys.argv[2]))
    print("## Sessions\n")
    print("| attempt | plan | run | accepted | rejected | failed | min/session (median) | Sink packets (median) | "
          "clock drift ms (range) | flows attributed |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in summary:
        st = r["by_status"]
        print("| %s | %s | %d of %d | %d | %d | %d | %.1f | %s | %.1f to %.1f | %s |" % (
            r["attempt"], r["plan"], sum(st.values()), r["planned"], st.get("accepted", 0), st.get("rejected", 0),
            st.get("failed", 0), (r["minutes"] or {}).get("median", float("nan")), (r["packets"] or {}).get("median", "-"),
            (r["drift_ms"] or {}).get("min", float("nan")), (r["drift_ms"] or {}).get("max", float("nan")),
            pct(r["flows_attributed_share"]) if r["flows_attributed_share"] is not None else "-"))
    print()
    for r in summary:
        for sid, kind, name, st, why in r["reasons"]:
            print("- %s %s %s (%s): %s" % (sid, kind, name, st, "; ".join(why)[:300]))
    ns_ = comp.get("not_started", [])
    if ns_:
        print("\nPrograms that never started (only the waiting shell's and the launch wrapper's calls in their cgroup; "
              "left out of detection, as the dataset left out runs without an observed exec):\n")
        for att, sid, kind, name in ns_:
            print("- %s %s %s (%s)" % (sid, kind, name, att))
    A = comp["A_behaviour"]
    print("\n## Malware behaviour: dataset run (20 s) vs session\n")
    print("Session class over the whole session after injection / over its first 20 s:\n")
    print("| dataset lab class | session class | count |\n|---|---|---|")
    for k, v in sorted(A["dataset_lab_vs_session"].items()):
        a, b = k.split(" -> ")
        print("| %s | %s | %d |" % (a, b, v))
    print("\n| dataset lab class | session class, first 20 s | count |\n|---|---|---|")
    for k, v in sorted(A["dataset_lab_vs_session_20s"].items()):
        a, b = k.split(" -> ")
        print("| %s | %s | %d |" % (a, b, v))
    print("\n| Triage (internet) class | session class | count |\n|---|---|---|")
    for k, v in sorted(A["triage_vs_session"].items()):
        a, b = k.split(" -> ")
        print("| %s | %s | %d |" % (a, b, v))
    print("\n| sample | family | dataset packets / calls (20 s) | session flows (20 s / all) | answered | remotes | "
          "first contact s | DNS via resolver | session calls (20 s) | Spearman vs dataset row |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for x in sorted(A["samples"], key=lambda x: (x["family"], x["sha256"])):
        print("| %s | %s | %s / %s | %s / %s | %s | %s | %s | %s | %s | %s |" % (
            x["sha256"][:10], x["family"], x["dataset_packets_20s"], x.get("dataset_host_calls_20s"),
            x["session_flows_20s"], x["session_flows"], x["session_answered"], x["session_remotes"],
            x["session_first_contact_s"], x.get("session_dns_relayed"), x["session_host_calls_20s"],
            f3(x.get("spearman_235_vs_dataset"))))
    B = comp["B_benign_agreement"]
    if B["tasks"]:
        print("\n## Benign tasks: session (first 20 s of the program) vs dataset row\n")
        print("Median Spearman over 235 columns: %s (%d tasks)\n" % (f3(B["median_spearman"]), len(B["tasks"])))
    it = comp.get("C_injection_time_by_class")
    if it:
        print("\nInjection times (a check that the seeded times carry no label): median %.1f s for malicious programs, "
              "%.1f s for benign and null; Mann-Whitney p = %.2f" % (it["malicious_median_s"], it["benign_median_s"],
                                                                    it["mannwhitney_p"]))
    for span, e in comp.get("C_per_program", {}).items():
        print("\n## Per-program rows, %s (n %d, malicious %d)\n" % (span, e["n"], e["malicious"]))
        if "C1_transfer" in e:
            print("Paper detectors trained on the 240 dataset rows, applied to the session rows:\n")
            print("| detector | BA | AUC | recall | specificity |\n|---|---|---|---|---|")
            for d, m in e["C1_transfer"].items():
                print("| %s | %s | %s | %s | %s |" % (d, f3(m["balanced_accuracy"]), f3(m["auc"]), f3(m["recall"]),
                                                    f3(m["specificity"])))
            print("\nShare flagged by kind:", json.dumps(e["C1_flagged_by_kind"]))
        if "launch_signature" in e:
            print("\nStart-up signature columns (dataset rows vs session rows, min / median / max):\n")
            print("| column | dataset | sessions |\n|---|---|---|")
            for k, v in e["launch_signature"].items():
                print("| %s | %s | %s |" % (k, " / ".join("%g" % x for x in v["dataset_min_median_max"]),
                                          " / ".join("%g" % x for x in v["sessions_min_median_max"])))
        if "C1_transfer_without_prologue_signals" in e:
            t = e["C1_transfer_without_prologue_signals"]
            print("\nSame transfer without the start-up-dominated host signals (%s; post hoc):\n"
                  % ", ".join(t["signals_dropped"]))
            print("| detector | BA | AUC | recall | specificity |\n|---|---|---|---|---|")
            for d, m in t["metrics"].items():
                print("| %s | %s | %s | %s | %s |" % (d, f3(m["balanced_accuracy"]), f3(m["auc"]), f3(m["recall"]),
                                                    f3(m["specificity"])))
            print("\nShare flagged by kind:", json.dumps(t["flagged_by_kind"]))
        cv = e["C2_grouped_cv"]
        print("\nGrouped CV within the session rows (families / projects held out):",
              "" if "skipped" not in cv else cv["skipped"])
        if "skipped" not in cv:
            print("\n| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |")
            print("|---|---|---|---|---|---|")
            rows = list(cv.items()) + [("baseline: " + k, v) for k, v in e.get("C2_baselines", {}).items()
                                       if "ba_mean" in v]
            for d, m in rows:
                print("| %s | %s +/- %s | %s | %s | %s | %s / %s |" % (
                    d, f3(m["ba_mean"]), f3(m["ba_sd"]), f3(m["auc_mean"]), f3(m["recall_mean"]),
                    f3(m["specificity_mean"]), f3(m.get("recall_at_5fa")), f3(m.get("recall_at_10fa"))))
        nr = e.get("C2_baseline_noise_reference", {})
        if "mean" in nr:
            print("\nOne-feature baselines on random noise (%d draws, same folds): BA mean %.3f, 95th percentile %.3f, "
                  "max %.3f" % (nr["draws"], nr["mean"], nr["p95"], nr["max"]))
        for k, v in e.get("C2_paired", {}).items():
            print("\n%s (BA, per fold assignment): %+.3f +/- %.3f, positive in %d of %d" % (
                k, v["mean"], v["sd"], v["positive"], v["assignments"]))
        sf = e.get("C2_seen_families")
        if sf and "skipped" not in sf:
            print("\nSeen families (stratified folds, rows of one family in training and test):\n")
            print("| detector | BA mean +/- sd | AUC | recall | specificity |\n|---|---|---|---|---|")
            for d, m in sf.items():
                print("| %s | %s +/- %s | %s | %s | %s |" % (d, f3(m["ba_mean"]), f3(m["ba_sd"]), f3(m["auc_mean"]),
                                                           f3(m["recall_mean"]), f3(m["specificity_mean"])))
        bg = e.get("C2_by_group")
        if bg:
            print("\nShare flagged per group (mean over fold assignments; malicious groups: recall):\n")
            print("| group | label | rows | host | network | concat | stacked |\n|---|---|---|---|---|---|---|")
            for grp, v in sorted(bg.items(), key=lambda kv: (-kv[1]["label"], kv[0])):
                print("| %s | %d | %d | %s | %s | %s | %s |" % (grp, v["label"], v["rows"], pct(v["host"]),
                                                              pct(v["network"]), pct(v["concat"]), pct(v["stacked"])))
    ar = comp.get("C_all_rows_20s")
    if ar and "skipped" not in ar["grouped_cv"]:
        print("\n## Sensitivity: per-program rows, 20 s, including the programs that never started (n %d, malicious %d)\n"
              % (ar["n"], ar["malicious"]))
        print("| detector | BA mean +/- sd | AUC | recall | specificity |\n|---|---|---|---|---|")
        for d, m in ar["grouped_cv"].items():
            print("| %s | %s +/- %s | %s | %s | %s |" % (d, f3(m["ba_mean"]), f3(m["ba_sd"]), f3(m["auc_mean"]),
                                                       f3(m["recall_mean"]), f3(m["specificity_mean"])))
    for key, title in (("D_machine_windows", "10-s"), ("D_machine_windows_30s", "30-s"),
                       ("D_machine_windows_matched", "10-s, position-matched (only the window at each session's "
                        "injection time; added after the interim look)"),
                       ("D_machine_windows_30s_matched", "30-s, position-matched (added after the interim look)")):
        D = comp.get(key)
        if not D:
            continue
        print("\n## %s machine windows (n %d, malicious %d)\n" % (title, D["n"], D["malicious"]))
        cv = D["grouped_cv"]
        if "skipped" in cv:
            print(cv["skipped"])
        else:
            print("| detector | BA mean +/- sd | AUC | recall | specificity | recall at 5% / 10% false alarms |")
            print("|---|---|---|---|---|---|")
            rows = list(cv.items()) + ([("activity baseline", D["activity_baseline"])] if "activity_baseline" in D else [])
            if "ba_mean" in D.get("position_baseline", {}):
                rows.append(("position baseline", D["position_baseline"]))
            for d, m in rows:
                print("| %s | %s +/- %s | %s | %s | %s | %s / %s |" % (
                    d, f3(m["ba_mean"]), f3(m["ba_sd"]), f3(m["auc_mean"]), f3(m["recall_mean"]),
                    f3(m["specificity_mean"]), f3(m.get("recall_at_5fa")), f3(m.get("recall_at_10fa"))))
            nr = D.get("baseline_noise_reference", {})
            if "mean" in nr:
                print("\nOne-feature baselines on random noise (%d draws): BA mean %.3f, 95th percentile %.3f, max %.3f"
                      % (nr["draws"], nr["mean"], nr["p95"], nr["max"]))
            for k, v in D.get("paired", {}).items():
                print("\n%s (BA, per fold assignment): %+.3f +/- %.3f, positive in %d of %d" % (
                    k, v["mean"], v["sd"], v["positive"], v["assignments"]))
            sf = D.get("seen_families")
            if sf and "skipped" not in sf:
                print("\nSeen families (stratified folds):\n")
                print("| detector | BA mean +/- sd | AUC | recall | specificity |\n|---|---|---|---|---|")
                for d, m in sf.items():
                    print("| %s | %s +/- %s | %s | %s | %s |" % (d, f3(m["ba_mean"]), f3(m["ba_sd"]),
                                                               f3(m["auc_mean"]), f3(m["recall_mean"]),
                                                               f3(m["specificity_mean"])))
    E = comp.get("E_lab_cue")
    if E:
        m = E["metrics"]
        print("\n## Lab cue (a connection left unanswered)\n")
        print("BA %s, recall %s, specificity %s; flagged by kind %s" % (f3(m["balanced_accuracy"]), f3(m["recall"]),
                                                                       f3(m["specificity"]), json.dumps(E["flagged_by_kind"])))


if __name__ == "__main__":
    main()
