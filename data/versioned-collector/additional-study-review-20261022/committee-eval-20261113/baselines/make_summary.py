"""Collects every baseline's saved scores into results.json and prints the README tables.

All numbers are recomputed from the saved score files (scores/*.npz), so results.json and the tables agree with
what a later pairwise comparison would load.

    /usr/bin/python3 make_summary.py
"""
import json
import sys
import time

import numpy as np

import bl_common as B

# (key, label, score file stem, which prediction array, kind)
ENTRIES = [
    ("thesis_host", "Thesis host (eBPF, 18 ADFA signals x 5)", "thesis_host", "pred", "thesis"),
    ("thesis_network", "Thesis network (switch, 29 signals x 5)", "thesis_network", "pred", "thesis"),
    ("thesis_concat", "Thesis hybrid, concatenated", "thesis_concat", "pred", "thesis"),
    ("thesis_stacked", "Thesis hybrid, stacked", "thesis_stacked", "pred", "thesis"),
    ("stide6_lfc", "STIDE k=6, max locality frame count (frame 20)", "stide6_collected_lfc", "pred", "HIDS-unsup"),
    ("stide6_frac", "STIDE k=6, mismatch fraction", "stide6_collected_frac", "pred", "HIDS-unsup"),
    ("stide6_pf_lfc", "STIDE k=6, LFC, prologue-free", "stide6_prologuefree_lfc", "pred", "HIDS-unsup"),
    ("stide6_pf_frac", "STIDE k=6, mismatch fraction, prologue-free", "stide6_prologuefree_frac", "pred", "HIDS-unsup"),
    ("lap8_lfc", "Lookahead pairs (window 8), LFC", "lap8_collected_lfc", "pred", "HIDS-unsup"),
    ("lap8_frac", "Lookahead pairs (window 8), anomalous-call fraction", "lap8_collected_frac", "pred", "HIDS-unsup"),
    ("ngram", "System-call 1-3-gram HIDS, RF500", "ngram", "pred", "HIDS-sup"),
    ("ngram_pf", "System-call 1-3-gram HIDS, RF500, prologue-free", "ngram_pf", "pred", "HIDS-sup"),
    ("kitsune_max", "Kitsune/KitNET, run score = max packet RMSE", "kitsune_max", "pred", "NIDS-unsup"),
    ("kitsune_p99", "Kitsune/KitNET, run score = 99th-pct packet RMSE", "kitsune_p99", "pred", "NIDS-unsup"),
    ("kitsune_mean", "Kitsune/KitNET, run score = mean packet RMSE", "kitsune_mean", "pred", "NIDS-unsup"),
    ("kitsune_rf", "Kitsune AfterImage aggregates (mean/max/std), RF500", "kitsune_rf", "pred", "NIDS-sup"),
    ("flow", "CICFlowMeter-like flow features, RF500", "flow", "pred", "NIDS-sup"),
    ("ngram_startup", "Diagnostic: n-grams of the target's first 50 calls only (start-up), RF500", "ngram_startup",
     "pred", "diagnostic"),
    ("ngram_nostart", "Diagnostic: n-gram HIDS without prologue and those 50 start-up calls, RF500",
     "ngram_nostart", "pred", "diagnostic"),
    ("sw_concat", "Software hybrid (n-gram + flows), concatenated RF500", "sw_concat", "pred", "hybrid-sw"),
    ("sw_stacked", "Software hybrid (n-gram + flows), stacked LR", "sw_stacked", "pred", "hybrid-sw"),
    ("sw_concat_nostart", "Diagnostic: software hybrid without start-up n-grams, concatenated", "sw_concat_nostart",
     "pred", "diagnostic"),
    ("sw_stacked_nostart", "Diagnostic: software hybrid without start-up n-grams, stacked", "sw_stacked_nostart",
     "pred", "diagnostic"),
]


def load_entry(stem, predkey):
    p5, p4 = B.SCORES / ("%s_table5.npz" % stem), B.SCORES / ("%s_table4.npz" % stem)
    if not (p5.exists() and p4.exists()):
        return None
    return np.load(p5), np.load(p4)


def diagnostics(rows, y, cat):
    """Facts quoted in the README, recomputed from caches and saved scores."""
    d = {}
    sc = np.asarray([int(r["syscall_count"]) for r in rows])          # post-target calls (total minus 178)
    fam = np.asarray([r["family"] for r in rows])
    at = np.asarray([r["attack_type"] for r in rows])

    def rate(stem, mask):
        p = B.SCORES / ("%s_table5.npz" % stem)
        return float(np.load(p)["pred"][:, mask].mean()) if p.exists() and mask.any() else None
    stems = ["thesis_host", "thesis_stacked", "ngram", "ngram_startup", "ngram_nostart", "sw_concat"]
    d["flag_rate_by_post_target_calls"] = {}
    for lo, hi in ((0, 100), (100, 300), (300, None)):
        for c in ("malware", "benign"):
            m = (cat == c) & (sc >= lo) & (sc < (hi if hi else 1 << 62))
            d["flag_rate_by_post_target_calls"]["%s_%d_%s" % (c, lo, hi or "inf")] = {
                "n": int(m.sum()), **{s: rate(s, m) for s in stems}}
    d["flag_rate_by_family"] = {f: {s: rate(s, fam == f) for s in stems} for f in ("Qilin", "Akira", "BrickStorm")}
    fl = B.CACHE / "flows" / "features.npz"
    if fl.exists():
        n = np.load(fl)["flows"]
        d["share_without_tcp_udp_flow"] = {c: float((n[cat == c] == 0).mean()) for c in B.CATS}
        m = cat == "malware"
        d["malware_recall_by_flow_presence"] = {s: {"with_flow": rate(s, m & (n > 0)), "without_flow": rate(s, m & (n == 0))}
                                                 for s in ("flow", "thesis_network")}
    for stem in ("stide6_collected_lfc", "lap8_collected_lfc"):
        p = B.SCORES / ("%s_table5.npz" % stem)
        if p.exists():
            raw = np.load(p)["raw"]
            d["%s_saturated_share" % stem] = {c: float((raw[:, cat == c] >= 20).mean()) for c in B.CATS}
            pred = (raw >= 20).astype(int)
            d["%s_post_hoc_rule_lfc_eq_20_ba" % stem] = float(np.mean(
                [B.binary_metrics(y, pred[k])["balanced_accuracy"] for k in range(len(pred))]))
    p = B.SCORES / "kitsune_max_table5.npz"
    if p.exists():
        z = np.load(p)
        d["kitsune_max_by_attack_type"] = {t: {"flag_rate": float(z["pred"][:, at == t].mean()),
                                               "median_raw": float(np.median(z["raw"][:, at == t]))}
                                           for t in ("syn_flood", "udp_flood", "slowloris", "goldeneye")}
        d["kitsune_max_median_raw"] = {c: float(np.median(z["raw"][:, cat == c])) for c in B.CATS}
        d["kitsune_threshold_median"] = float(np.median(z["threshold"]))
        d["kitsune_network_benign_raw_p90"] = float(np.percentile(z["raw"][:, cat == "network_benign"], 90))
    return d


def main():
    rows, y, g, cat, split, mode = B.dataset()
    tr, te = B.table4_split(cat, split)
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "reference_published": {"table5_ba": {"host": 0.784, "network": 0.756, "stacked": 0.823,
                                                 "concat_diagnostic": 0.809},
                                   "table4_ba": {"host": 0.929, "network": 0.750, "concat": 0.926}},
           "notes": "Table V: mean +/- sd over the ten published fold assignments (all 240 rows). Table IV: the "
                    "published held-out split (54 test rows). Unsupervised detectors: primary operating point = "
                    "95th percentile of held-out training-benign scores; AUC uses the score minus (or, for "
                    "Kitsune, divided by) the fold's threshold.",
           "baselines": {}}
    for key, label, stem, predkey, kind in ENTRIES:
        e = load_entry(stem, predkey)
        if e is None:
            continue
        z5, z4 = e
        s5 = B.summarize_table5(y, cat, z5["score"], z5[predkey])
        s4 = B.summarize_table4(y, cat, z4["test_index"], z4["score"], z4[predkey])
        rec = {"label": label, "kind": kind, "score_files": ["scores/%s_table5.npz" % stem,
                                                             "scores/%s_table4.npz" % stem],
               "table5": {k: s5[k] for k in ("balanced_accuracy", "auc", "recall", "specificity", "precision", "f1")},
               "table5_flag_rates": s5["flag_rates"], "table5_per_assignment": s5["per_assignment"],
               "table4": s4}
        if "pred_max" in z5.files:
            m5 = B.summarize_table5(y, cat, z5["score"], z5["pred_max"])
            m4 = B.summarize_table4(y, cat, z4["test_index"], z4["score"], z4["pred_max"])
            rec["second_operating_point_max"] = {
                "table5": {k: m5[k] for k in ("balanced_accuracy", "recall", "specificity")},
                "table5_flag_rates": m5["flag_rates"],
                "table4": {k: m4[k] for k in ("balanced_accuracy", "recall", "specificity", "tn", "fp", "fn", "tp")}}
        out["baselines"][key] = rec
    for extra in ("compare_thesis", "throughput", "stide", "kitsune", "supervised", "supervised_kitsune",
                  "supervised_startup"):
        p = B.RESULTS / ("%s.json" % extra)
        if p.exists():
            d = json.loads(p.read_text())
            if extra == "compare_thesis":
                out["pairwise_vs_thesis"] = {b: {"table5": v["table5_summary"],
                                                 "table5_vs_host": v["table5_summary_vs_host"],
                                                 "table5_vs_network": v["table5_summary_vs_network"],
                                                 "table4": v["table4"]}
                                             for b, v in d["baselines"].items()}
            elif extra == "throughput":
                out["throughput"] = d["summary"]
                out["throughput_runs"] = d["runs"]
            else:
                out.setdefault("settings", {})[extra] = d.get("settings")
                if extra == "kitsune":
                    out["kitsune_training"] = {"table4": d.get("training_info_table4"),
                                               "table5_first_fold": [x[0] for x in d.get("training_info_table5", [])]}
    ks = B.CACHE / "kitsune" / "summary.json"
    if ks.exists():
        d = json.loads(ks.read_text())
        out["kitsune_extraction"] = {k: v for k, v in d.items() if k != "per_run"}
        out["kitsune_extraction"]["capped_runs"] = [rows[m["row"]]["execution_id"] for m in d["per_run"] if m["capped"]]
    ss = B.CACHE / "syscalls_summary.json"
    if ss.exists():
        d = json.loads(ss.read_text())
        out["syscall_extraction"] = {k: v for k, v in d.items() if k != "per_run"}
    out["diagnostics"] = diagnostics(rows, y, cat)
    B.write_json(B.HERE / "results.json", out)

    # ---------------------------------------------------------------- markdown tables
    def pm(s):
        return "%.3f ± %.3f" % (s["mean"], s["sd"])

    print("\n### Table V protocol (240 rows, 10 fold assignments)\n")
    print("| detector | BA | AUC | recall | specificity | malware | attacks | CLI benign | net. benign | null |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for key, rec in out["baselines"].items():
        t, f = rec["table5"], rec["table5_flag_rates"]
        print("| %s | %s | %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f | %.2f |" % (
            rec["label"], pm(t["balanced_accuracy"]), pm(t["auc"]), t["recall"]["mean"], t["specificity"]["mean"],
            f["malware"]["mean"], f["network_attack"]["mean"], f["benign"]["mean"], f["network_benign"]["mean"],
            f["null"]["mean"]))
    print("\n### Table IV protocol (held-out split, 54 test rows)\n")
    print("| detector | BA | AUC | recall | specificity | TN/FP/FN/TP |")
    print("| --- | --- | --- | --- | --- | --- |")
    for key, rec in out["baselines"].items():
        t = rec["table4"]
        print("| %s | %.3f | %.3f | %.3f | %.3f | %d/%d/%d/%d |" % (rec["label"], t["balanced_accuracy"], t["auc"],
                                                               t["recall"], t["specificity"], t["tn"], t["fp"],
                                                               t["fn"], t["tp"]))
    if "pairwise_vs_thesis" in out:
        print("\n### Pairwise vs thesis (exact McNemar on identical rows)\n")
        print("Table V: mean ΔBA (baseline − thesis) over the ten assignments, and in how many assignments the baseline "
              "is significantly better / worse (p < 0.05). Table IV: ΔBA and p.\n")
        print("| baseline | vs thesis stacked | vs thesis host | vs thesis network | Table IV vs thesis concat | "
              "Table IV vs host | Table IV vs network |")
        print("| --- | --- | --- | --- | --- | --- | --- |")

        def c5(s):
            return "%+.3f (%d / %d)" % (s["delta_ba_mean"], s["assignments_baseline_better_p05"],
                                        s["assignments_thesis_better_p05"])

        def c4(t):
            return "%+.3f (p=%.3f)" % (t["delta_ba"], t["p"])
        order = [stem for _, _, stem, _, kind in ENTRIES if kind != "thesis"]
        for b in order:
            if b not in out["pairwise_vs_thesis"]:
                continue
            v = out["pairwise_vs_thesis"][b]
            print("| %s | %s | %s | %s | %s | %s | %s |" % (
                b, c5(v["table5"]), c5(v["table5_vs_host"]), c5(v["table5_vs_network"]),
                c4(v["table4"]["vs_thesis_concat"]), c4(v["table4"]["vs_thesis_host"]),
                c4(v["table4"]["vs_thesis_network"])))


if __name__ == "__main__":
    sys.exit(main())
