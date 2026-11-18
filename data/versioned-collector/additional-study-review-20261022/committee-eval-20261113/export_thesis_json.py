"""Key numbers of the committee analyses for the thesis (data/lab/committee_response.json). Offline.

Reads only result files (this folder's, and those of the live attribution check and the two C2 runs next to it),
records their SHA-256 and writes one JSON; nothing is typed by hand.

    /usr/bin/python3 export_thesis_json.py OUT.json
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
R = HERE / "results"


def load(name):
    p = R / name
    return (json.loads(p.read_text()), hashlib.sha256(p.read_bytes()).hexdigest()) if p.exists() else (None, None)


def main():
    out = {"status": "final", "date": "2026-11-16", "sources": {}}
    rig, h = load("rigor.json"); out["sources"]["rigor.json"] = h
    imp, h = load("importance.json"); out["sources"]["importance.json"] = h
    att, h = load("attribution_superposition.json"); out["sources"]["attribution_superposition.json"] = h
    gap, h = load("switch_gap.json"); out["sources"]["switch_gap.json"] = h
    bud, h = load("switch_budget.json"); out["sources"]["switch_budget.json"] = h
    eva, h = load("evasion.json"); out["sources"]["evasion.json"] = h
    A, B = rig["A_table_iv"], rig["B_table_v"]
    out["table_iv"] = {d: {"rf42": {k: A["rf42"][d][k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")},
                           "ba_ci95": A["bootstrap_ci95"][d]["balanced_accuracy"],
                           "ba_11_forest_seeds": A["rf_seed_robustness"][d]["balanced_accuracy"]}
                       for d in ("host", "network", "concat", "stacked")}
    out["table_iv_mcnemar"] = {k: v["mcnemar"] for k, v in A["paired"].items()}
    out["table_v"] = {d: {m: B["per_detector"][d][m] for m in ("balanced_accuracy", "auc", "recall", "specificity",
                                                               "precision", "f1", "ba_mean_ci95")}
                      for d in ("host", "network", "concat", "stacked")}
    out["table_v_paired"] = {k: {x: v[x] for x in ("ba_diff_mean", "ba_diff_sd", "a_better_in_assignments", "ba_diff_ci95",
                                                   "p_boot_diff_gt0", "mcnemar_p_median", "mcnemar_p_lt_0.05")}
                             for k, v in B["paired"].items()}
    out["table_v_baselines"] = {k: v["balanced_accuracy"]["mean"] for k, v in rig["B_baselines_table_v"].items()}
    out["per_unit_flag_rates"] = rig["C_flag_rates"]
    out["which_view_misses"] = rig["C_misses"]
    out["attack_groupings"] = {g: {"attack_recall": v["attack_recall"],
                                   "stacked_ba": v["overall"]["stacked"]["balanced_accuracy"]["mean"],
                                   "host_ba": v["overall"]["host"]["balanced_accuracy"]["mean"],
                                   "network_ba": v["overall"]["network"]["balanced_accuracy"]["mean"],
                                   "concat_ba": v["overall"]["concat"]["balanced_accuracy"]["mean"]}
                               for g, v in rig["D_attack_groupings"].items()}
    out["time_to_detection"] = rig["E_time_to_detection"]
    out["streaming"] = rig.get("F_streaming")
    out["importance"] = {"table_v_top_host": imp["table_v_permutation"]["host"][:8],
                         "table_v_top_network": imp["table_v_permutation"]["network"][:8],
                         "table_iv_network_families": [x for x in imp["table_iv_permutation"]["network"] if x["group"].startswith("ALL__")],
                         "host_drop_and_retrain": imp["host_drop_and_retrain"]}
    out["attribution"] = att["summary"]
    out["switch_gap"] = {"feature_level": {k: {"rows": v["rows_with_any_change"], "by_category": v["by_category"]}
                                           for k, v in gap["feature_level"].items()},
                         "table_v": gap["detection_table_v"], "table_iv": gap["detection_table_iv"],
                         "budget": bud}
    out["evasion"] = eva
    bd, h = load("bootstrap_designs.json"); out["sources"]["bootstrap_designs.json"] = h
    out["edge_interval_designs"] = bd
    st1, h = load("startup_check.json"); out["sources"]["startup_check.json"] = h
    st2, h = load("startup_check2.json"); out["sources"]["startup_check2.json"] = h
    st3, h = load("startup_rseq_by_mode.json"); out["sources"]["startup_rseq_by_mode.json"] = h
    out["startup_check"] = {"startup_calls_in_target_first_50": st1["startup_calls_in_first_50"],
                            "rseq_in_target_first_50_by_mode": st3["by_mode_category"],
                            "rseq_in_target_first_50_by_family_or_project": st3["by_family_or_project"],
                            "drop_first_calls": {k: v for k, v in st1.items() if k.startswith("drop_first_")},
                            "five_startup_flags_only": st2["toolchain_flags"],
                            "host_from_first_50_calls_only": st2["host_startup_only"]}
    base, h = load("../baselines/results.json")
    if base is not None:
        def t(rec):
            return {"table_v_ba_mean": rec["table5"]["balanced_accuracy"]["mean"],
                    "table_v_ba_sd": rec["table5"]["balanced_accuracy"]["sd"],
                    "table_v_auc_mean": rec["table5"]["auc"]["mean"],
                    "table_v_flag_rates": {c: x["mean"] for c, x in rec.get("table5_flag_rates", {}).items()},
                    "table_iv": {k: rec["table4"][k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")}}
        out["baselines"] = {"notes": base["notes"],
                            "detectors": {k: dict(label=v["label"], **t(v)) for k, v in base["baselines"].items()},
                            "throughput": base["throughput"], "diagnostics": base["diagnostics"]}
        out["sources"]["baselines/results.json"] = h
    def ext(rel):
        q = HERE.parent / rel
        if not q.exists():
            return None
        out["sources"][rel] = hashlib.sha256(q.read_bytes()).hexdigest()
        return json.loads(q.read_text())

    def compact(det):
        return {"n": det["n"], "malware": det["malware"], "benign": det["benign"], "groups": det["groups"],
                "scores": {k: {"ba_mean": v["ba"]["mean"], "ba_sd": v["ba"]["sd"], "auc_mean": v["auc"]["mean"]}
                           for k, v in det["scores"].items()},
                "comparisons": {k: {"ba_diff_mean": v["ba_diff"]["mean"], "assignments_higher": v["assignments_higher"],
                                    "verdict": v["verdict"]} for k, v in det["comparisons"].items()}}

    so = ext("sockowner-check/runs/20261113T202924619160Z/analysis.json")
    if so is not None:
        out["socket_attribution_live"] = {k: so[k] for k in (
            "kernel", "sockowner_health", "sockets_seen", "flow_sightings", "capture_flows", "per_client", "total",
            "coverage", "cgroup_accuracy", "process_accuracy_where_socket_seen", "sighting_minus_first_packet_ms",
            "window_vs_socket_join", "process_level_join_in_shared_cgroup", "udp_send_ns_per_datagram")}
    co = {}
    for run in ("20261113T222505186007Z", "20261113T222601723408Z", "20261113T222657189544Z"):
        a = ext("sockowner-check/runs-malware/%s/analysis.json" % run)
        if a is not None:
            co[a["sample"]["family"]] = {k: a[k] for k in (
                "sample", "sample_processes_alive_at_kill", "sockowner_health", "capture_flows", "receipts",
                "benign_total", "benign_cgroup_accuracy", "non_client_flows", "sample_socket_join",
                "window_vs_socket_join", "network_detector", "network_detector_flags",
                "network_detector_flags_normal_clients")}
    if co:
        out["socket_attribution_live_with_malware"] = co
    sk = ext("sinkhole-c2-5min/20261113T084625506148Z/analysis/results.json")
    sc = ext("sinkhole-c2-5min/20261113T084625506148Z/analysis/sample-check-20261113T204829Z.json")
    sl = ext("sliver-c2-5min/20261113T175035504465Z/analysis/results.json")
    sv = ext("sliver-c2-5min/20261113T175035504465Z/analysis/sliver_results.json")
    cp = ext("sliver-c2-5min/20261113T175035504465Z/analysis/command_phase_around.json")
    if sk is not None and sl is not None:
        pub = {setting: {d: {k: v for k, v in rec.items() if k != "by_run"} for d, rec in blk["per_detector"].items()}
               for setting, blk in sv["published_detectors"].items()} if sv else None
        out["c2"] = {
            "server_down_sinkhole": {"accepted_by_label": sk["accepted_by_label"],
                                     "runs_technically_sound": sc["runs_technically_sound"] if sc else None,
                                     "behaviour_categories": sc["categories"] if sc else None,
                                     "decision_rule": sk["decision_rule"],
                                     "all": compact(sk["detection_all"]),
                                     "wire_malware_only": compact(sk["detection_wire_malware_only"])},
            "server_up_sliver": {"accepted_by_label": sl["accepted_by_label"],
                                 "all": compact(sl["detection_all"]),
                                 "tasked_implants_only": compact(sl["detection_wire_malware_only"]),
                                 "taskings_total": sv["command_phase"]["taskings_total"] if sv else None,
                                 "command_phase_around_tasking": cp,
                                 "transports": sv["transports"] if sv else None,
                                 "thesis_detectors": pub,
                                 "sinkhole_trained_detectors": sv["server_down_vs_up"] if sv else None}}
    tc, h = load("toolchain_scores.json")
    if tc is not None:
        out["sources"]["toolchain_scores.json"] = h
        out["toolchain_matched_benign"] = tc
        tv = ext("toolchain21-collect/20261113T203411281909Z/validation-20261113T215354185340Z.json")
        ctl, h2 = load("toolchain_controls.json")
        out["sources"]["toolchain_controls.json"] = h2
        out["toolchain_matched_benign_collection"] = {
            "validation_summary": tv["summary"] if tv else None, "validation_by_class": tv["by_class"] if tv else None,
            "rejected": [r for r in tv["cases"] if r["status"] != "accepted"] if tv else None,
            "dataset_controls": ctl["controls"] if ctl else None}
    ng = ext("committee-eval-20261113/baselines/results/toolchain_ngram.json")
    npr = ext("committee-eval-20261113/baselines/results/toolchain_ngram_protocol.json")
    if ng is not None:
        keep = ("ngram", "ngram_pf", "ngram_startup", "ngram_nostart", "flow", "sw_concat", "sw_stacked",
                "sw_concat_nostart", "sw_stacked_nostart", "thesis_host", "thesis_network", "thesis_concat",
                "thesis_stacked")

        def cvp(p):
            return {"rows": p["rows"],
                    "detectors": {d: {k: p["detectors"][d][k] for k in (
                        "ba_mean", "ba_sd", "ba_min", "ba_max", "auc_mean", "flagged_by_category",
                        "new_benign_flagged_by_class", "low_activity_malware_recall")} for d in keep},
                    "paired": {k: {x: v[x] for x in ("ba_diff_mean", "a_better", "b_better", "ties",
                                                     "mcnemar_p_below_0.05")} for k, v in p["paired"].items()}}
        out["ngram_baseline_toolchain_matched"] = {
            "protocol_written_utc": npr["written_utc"] if npr else None,
            "decision_rule": npr["decision_rule"] if npr else None,
            "primary_verdict": ng["primary_verdict"], "checks": ng["checks"],
            "A_transfer_flag_rate": {d: ng["A_transfer_flag_rate"][d] for d in keep},
            "B_replacement_table_v": cvp(ng["B_table_v"]), "D_mixed_table_v": cvp(ng["D_table_v"]),
            "C_heldout": {"train": ng["C_heldout"]["train"], "test": ng["C_heldout"]["test"],
                          "test_new_benign": ng["C_heldout"]["test_new_benign"],
                          "detectors": {d: {k: v for k, v in ng["C_heldout"]["detectors"][d].items()}
                                        for d in keep}}}
    tp, h = load("temporal_split.json")
    if tp is not None:
        out["sources"]["temporal_split.json"] = h
        tpr, h2 = load("temporal_protocol.json")
        out["sources"]["temporal_protocol.json"] = h2
        out["temporal_split"] = {
            "protocol_written_utc": tpr["written_utc"] if tpr else None,
            "reading": tpr["reading"] if tpr else None,
            "cutoffs": tp["cutoffs"], "undated_excluded": tp["undated_excluded"],
            "splits": {n: {"train": s["train"], "test": s["test"],
                           "detectors": {d: {"rf42": {k: v["rf42"][k] for k in ("balanced_accuracy", "auc", "tn", "fp",
                                                                                "fn", "tp")},
                                             "ba_over_forest_seeds": v["ba_over_forest_seeds"],
                                             "auc_mean": v["auc_over_forest_seeds"]["mean"]}
                                         for d, v in s["detectors"].items()},
                           "paired": s["paired"]} for n, s in tp["splits"].items()},
            "random_dated_reference": tp["random_dated_reference"],
            "temporal_vs_family_heldout": tp["temporal_vs_family_heldout"],
            "baselines_ba": tp["baselines_ba"], "baseline_gate_triggered_primary": tp["baseline_gate_triggered_primary"],
            "bootstrap_primary_rf42": tp["bootstrap_primary_rf42"],
            "primary_test_families": tp["primary_test_families"],
            "primary_seen_vs_new_families": tp["primary_seen_vs_new_families"]}
    # 2026-11-15 additions: oversized frames, random timing, mitigation estimate, encrypted traffic
    def load_path(p):
        p = Path(p)
        return (json.loads(p.read_text()), hashlib.sha256(p.read_bytes()).hexdigest()) if p.exists() else (None, None)

    off, h = load("offload_resegment.json")
    if off is not None:
        out["sources"]["offload_resegment.json"] = h
        out["offload_resegment"] = off
    jit, h = load("evasion_jitter.json")
    if jit is not None:
        out["sources"]["evasion_jitter.json"] = h
        out["evasion_jitter"] = {"recall": jit["recall"], "dropped_packets": jit["dropped_packets"],
                                 "checks": jit["checks"]}
    mit, h = load_path(HERE / "mitigation" / "results.json")
    if mit is not None:
        out["sources"]["mitigation/results.json"] = h
        out["mitigation"] = {"protocol": mit["protocol"], "checks": mit["checks"],
                             "containment_L10ms": {k: v for k, v in mit["containment"].items() if k.endswith("|0.01")},
                             "benign_blocked_L10ms": {k: v for k, v in mit["benign_blocked"].items() if k.endswith("|0.01")}}
    enc, h = load_path(HERE / "encryption" / "results.json")
    if enc is not None:
        out["sources"]["encryption/results.json"] = h
        out["encryption_existing_data"] = {"dataset": enc["dataset"], "sliver": enc["sliver"]}
    pyb, h = load_path(HERE / "encryption" / "python_benign.json")
    if pyb is not None:
        out["sources"]["encryption/python_benign.json"] = h
        out["benign_python_programs"] = pyb["pools"]
    attempts = sorted((HERE.parent / "transport21-collect").glob("2*/analysis/transport_analysis.json"))
    if attempts:
        tr, h = load_path(attempts[-1])
        out["sources"][str(attempts[-1].relative_to(HERE.parent))] = h
        out["encryption_transport21"] = {k: tr[k] for k in ("attempt", "accepted_runs", "flagged_by_transport", "cells",
                                                           "switch_model_vs_telemetry_max_rel_diff") if k in tr}
    # the lab cue (connections nobody answered), protocol written before the analysis
    cue, h = load("unanswered_cue.json")
    if cue is not None:
        out["sources"]["unanswered_cue.json"] = h
        out["sources"]["unanswered_cue_protocol.json"] = load("unanswered_cue_protocol.json")[1]
        F = cue["F_sinkhole_vs_past"]
        pairs = [(F["per_sample"][2 * k], F["per_sample"][2 * k + 1]) for k in range(28)]
        out["lab_cue"] = {
            "protocol_written_utc": cue["protocol_written_utc"],
            "runs_by_class": cue["A_flows"]["runs_by_class"],
            "unanswered_flows_by_destination": cue["A_flows"]["unanswered_flows_by_destination"],
            "table_v": {k: cue["B_table_v"][k] for k in ("published_ba", "cue_rule_ba", "traffic_rule_ba",
                                                         "cue_rule_recall_malicious", "cue_rule_false_alarms_benign",
                                                         "share_of_network_true_positives_with_cue_mean",
                                                         "flag_rate_by_category_and_class")},
            "table_iv": cue["C_table_iv"],
            "cue_free_table_v": {k: v for k, v in cue["D_cue_free_table_v"].items() if k != "ba_per_assignment"},
            "cue_free_training_table_iv": cue["E_table_iv_cue_free_training"],
            "sinkhole_vs_unanswered_runs": {
                "flags_of_28": F["flags_of_28"], "past_runs_by_class": F["past_runs_by_class"],
                "now_runs_by_class": F["now_runs_by_class"], "benign_now_by_class": F["benign_now_by_class"],
                "per_implant": [{"family": a["family"], "class_unanswered_run": a["class"], "class_sinkhole_run": b["class"],
                                 "table_iv_network_prob": [a["prob"]["table_iv_detectors"]["network"],
                                                           b["prob"]["table_iv_detectors"]["network"]],
                                 "table_iv_host_prob": [a["prob"]["table_iv_detectors"]["host"],
                                                        b["prob"]["table_iv_detectors"]["host"]]}
                                for a, b in pairs]}}
    # LID-DS checked for the same cue (2026-11-15)
    lc, h = load("lidds_cue_check.json")
    if lc is not None:
        lg, h2 = load("lidds_gain_without_cue.json")
        out["sources"]["lidds_cue_check.json"] = h
        out["sources"]["lidds_gain_without_cue.json"] = h2
        P = lc["pooled"]
        out["lab_cue_lidds"] = {
            "proxy": "net_flow_count_seen__sum - net_flows_with_ba__sum > 0",
            "proxy_check_on_our_240_rows": lc["proxy_check_on_our_240_rows"]["confusion"],
            "share_with_unanswered": {"attack": P["attack"]["with_unanswered"], "normal": P["normal"]["with_unanswered"],
                                      "end_control": lc["end_control"]["with_unanswered"]},
            "no_reverse_packet_at_all": {"attack": P["attack"]["no_reverse_packet_at_all"],
                                         "normal": P["normal"]["no_reverse_packet_at_all"],
                                         "end_control": lc["end_control"]["no_reverse_packet_at_all"]},
            "pooled_rule": P["rule_flag_unanswered"], "pooled_auc_count": P["auc_unanswered_count"],
            "pooled_auc_share": P["auc_unanswered_share"], "pooled_auc_flow_windows": P["auc_flow_windows_reference"],
            "per_scenario": {sc: {"rule_ba": c["rule_flag_unanswered"]["balanced_accuracy"],
                                  "auc_count": c["auc_unanswered_count"],
                                  "e2_detectors_ba": c["e2_detectors_balanced_accuracy"]}
                             for sc, c in lc["per_scenario"].items()},
            "fusion_gain_by_scenario_set": {
                name: {"dropped": lg["sets"][name], "attack_windows": s["attack_windows"],
                       "normal_windows": s["normal_windows"],
                       "gain_over_better_sensor_mean": {m: {r: v["mean"] for r, v in g.items()}
                                                        for m, g in s["gain_over_better_sensor"].items()},
                       "gain_positive_in_assignments": s["gain_positive_in_assignments"],
                       "pooled_ba_mean": {m: v["mean"] for m, v in s["pooled_ba"].items()}}
                for name, s in lg["per_set"].items()}}
    # the switch-side first stage (committee item 5, estimate)
    fs, h = load("firststage.json")
    if fs is not None:
        out["sources"]["firststage.json"] = h
        out["sources"]["firststage_protocol.json"] = load("firststage_protocol.json")[1]
        out["sources"]["firststage_protocol_addendum.json"] = load("firststage_protocol_addendum.json")[1]
        out["firststage"] = {k: {kk: v[kk] for kk in ("k", "k0", "k0_from", "benign_max_by_category", "benign_alarms",
                                                      "attack_by_type", "attack_packets_stopped_pooled",
                                                      "malware_tripping")}
                             for k, v in fs["rules"].items()}
    # the Sliver testbed's within-run results without our server's stray WireGuard packets
    sl = HERE.parent / "sliver-c2-5min" / "20261113T175035504465Z" / "analysis"
    res, h = load_path(sl / "results_without_stray_wireguard.json")
    if res is not None:
        sres, h2 = load_path(sl / "sliver_results_without_stray_wireguard.json")
        cph, h3 = load_path(sl / "command_phase_around_without_stray_wireguard.json")
        for name, hh in (("results_without_stray_wireguard.json", h), ("sliver_results_without_stray_wireguard.json", h2),
                         ("command_phase_around_without_stray_wireguard.json", h3)):
            out["sources"]["sliver-c2-5min/20261113T175035504465Z/analysis/" + name] = hh

        def scores(det):
            return {n: {"ba": v["ba"], "auc": v["auc"]} for n, v in det["scores"].items()}
        out["sliver_without_stray_wireguard"] = {
            "rule": res["rule"], "reproduced_as_collected": res["reproduced_as_collected"],
            "dropped_packets": {k: v for k, v in res["dropped_packets"].items() if v["dropped_whole_capture"]},
            "detection_all": scores(res["detection_all"]),
            "detection_all_comparisons": res["detection_all"]["comparisons"],
            "detection_wire_malware_only": scores(res["detection_wire_malware_only"]),
            "published_detectors": {m: {d: {k: x[k] for k in ("implants_flagged", "implants", "benign_flagged", "benign",
                                                              "nulls_flagged") if k in x}
                                        for d, x in v["per_detector"].items()}
                                    for m, v in sres["published_detectors"].items()},
            "server_down_vs_up": {lab: {d: {k: x[k] for k in ("implants_flagged", "implants") if k in x}
                                        for d, x in v.items()} for lab, v in sres["server_down_vs_up"].items() if isinstance(v, dict)},
            "command_phase_around": cph["pooled_mean_per_window"]}
    hw = {}
    for name in ("basicfix_v3", "gtot_ba", "exact_collector", "exact_collector_with_bulkup", "sweep",
                 "sweep_with_bulkup", "sweep_coll", "sweep_coll_with_bulkup"):
        r, h = load_path(HERE / "results" / ("switch_replay_%s.json" % name))
        if r is None:
            continue
        out["sources"]["switch_replay_%s.json" % name] = h
        hw[name] = {"replayed_rows": r["replayed_rows"], "feature_columns_differing": len(r["feature_agreement"]),
                    "table_v": {d: {k: v[k] for k in ("ba_model", "ba_switch", "flips_per_assignment_mean")}
                                for d, v in r["table_v"].items()},
                    "table_iv": r["table_iv"]}
    if hw:
        out["switch_replay_hardware"] = {
            "what": "the dataset's captures replayed through the Wedge100BF-32X at the dataset's 0.5-s windows "
                    "(impl PC1.md Results parts 4-6e, 9c for the sweep build and 9d for the sweep build with the "
                    "collision counter, sweep_coll); rows scored with the published detectors trained on the software "
                    "model's rows; bulkup_200/400 (frames over the MTU) left out except in the *_with_bulkup builds. "
                    "sweep_coll's rows equal sweep's in every non-duration column of all 109 (durations differ: the "
                    "replays' switch arrival times)",
            "rows_equal_to_published_in_135_non_duration_columns_of_109": {"basic_fix": 61, "gtot_ba": 63, "exact": 102,
                                                                         "sweep": 103, "sweep_coll": 103},
            "program_resources": {
                "source": "bf-p4c 9.6.0 build reports: impl p4_perf.md 2 and 5.5-5.8, PC1.md results parts 6b, 9 and "
                          "9b and 9d (archives live_test/committee_replay/pc1_20261116_exact_v3.tar.xz, "
                          "pc1_20261117_part9.tar.xz builds/resources_fixes.md, pc1_20261117_part9d.tar.xz "
                          "builds_coll/resources_coll.md); latency = median, hairpin method (p4_perf.md 4.1), every "
                          "program with a same-day forwarding baseline of 246 ns",
                "forwarding_only": {"stages_ig_eg": "1/0", "sram": "1/960 (0.1%)", "map_ram": 0, "tcam": 0,
                                    "stateful_alus": 0, "latency_ns_median": 246},
                "basic_fix (deployed)": {"stages_ig_eg": "5/1", "sram": "197/960 (20.5%)", "map_ram": "196/576 (34.0%)",
                                         "tcam": "3/288 (1.0%)", "stateful_alus": "14/48", "ingress_cycles": 131,
                                         "latency_ns_median": 315},
                "basic_gtot_ba (seven whole-switch totals)": {"stages_ig_eg": "6/1", "sram": "211/960 (22.0%)",
                                         "map_ram": "210/576 (36.5%)", "tcam": "3/288 (1.0%)", "stateful_alus": "21/48",
                                         "ingress_cycles": 133, "latency_ns_median": 317},
                "sweep (basic_sweep_final, bucket table read by data-plane probes)": {"stages_ig_eg": "6/1",
                                         "sram": "239/960 (24.9%)", "map_ram": "216/576 (37.5%)", "tcam": "20/288 (6.9%)",
                                         "stateful_alus": "22/48", "ingress_cycles": 158, "latency_ns_median": 337,
                                         "note": "the build without the collision counter (PC1.md 9b, 9c)"},
                "sweep_coll (basic_sweep_coll, sweep with the collision counter reg_coll; the sources of "
                "perf/variants/sweep since de081f1)": {"stages_ig_eg": "7/1", "critical_path_stages": 5,
                                         "sram": "245/960 (25.5%)", "map_ram": "221/576 (38.4%)", "tcam": "20/288 (6.9%)",
                                         "stateful_alus": "23/48 (47.9%)", "ingress_cycles": 164,
                                         "latency_ns_median": 342, "latency_ns_p99": 346,
                                         "note": "PC1.md 9d: the counter costs a seventh ingress stage, 6 cycles and "
                                                 "5 ns"},
                "exact (basic_exact_v3, window features in the data plane)": {"stages_ig_eg": "11/1",
                                         "sram": "122/960 (12.7%)", "map_ram": "119/576 (20.7%)", "tcam": "7/288 (2.4%)",
                                         "stateful_alus": "23/48", "ingress_cycles": 260, "latency_ns_median": 421},
                "line_rate": "every program: the 27-run matrix of p4_perf.md 3.2 at basic_fix's rates within 0.01 "
                             "points (91.09% at 64 B, the generator's maximum; 99.87-99.90% paced and 100.00% "
                             "saturating from 128 to 1518 B), no loss beyond the saturating runs' excess, counters "
                             "exact for 13.1 billion packets; sweep_coll beside its own generator sweeping the same "
                             "pipe every 0.5 s (PC1.md 9f, form 2): 99.99% at 1518 B, 91.09% at 64 B, no drop, as "
                             "without the sweep; two apps on one pipe's generator take turns (73.88% at 1518 B "
                             "beside a 131-ms sweep every 500 ms)"},
            "sweep_program": {"probes_and_exports_in_109_replays": 475080, "rows_equal_to_its_model": "107/109",
                              "probes": "in band at each window boundary in the replays",
                              "generator_check": "15 whole sweeps of 65,536 probes every 0.5 s, every record equal "
                                                 "to the model (201 used buckets), no export lost at 2 us, 0.5 us "
                                                 "and the generator's full rate (a sweep in 0.64 ms); the same with "
                                                 "the collision counter (PC1.md 9d)",
                              "collision_counter_in_109_replays": {
                                  "captures_with_collisions": 4,
                                  "colliding_packets": {"syn_fan_150k": 90599, "chaos_d538053a": 55245,
                                                        "syn_fan_100k": 48461, "syn_fan_40k": 10050},
                                  "merged_buckets": {"syn_fan_150k": 43388, "chaos_d538053a": 14899,
                                                     "syn_fan_100k": 29463, "syn_fan_40k": 8185},
                                  "rows_vs_published_of_135": {"syn_fan_150k": 67, "chaos_d538053a": 67,
                                                               "syn_fan_100k": 70, "syn_fan_40k": 120},
                                  "reading": "the counter flags exactly the 4 captures whose rows the bucket table "
                                             "cannot make equal to the published row; the other 105 have none"},
                              "export_rate_pc1": {"what": "PC1.md 9e, 30,000 flows (17,788 used buckets): exports "
                                                          "lost by PC1's NIC (rx_out_of_buffer), tcpdump dropping none",
                                                  "ring_1024": {"2us": "251/193009", "1us": "3015/191901",
                                                                "0.5us": "3406/174251", "full_rate": "155224/173406"},
                                                  "ring_8192": {"2us": "0/190706", "1us": "0/175497",
                                                                "0.5us": "0/173857", "full_rate": "81942/175218"}},
                              "collector_on_the_sweep": {
                                  "what": "PC1.md 9g, hybrid_collector.py --switch-program sweep",
                                  "inband": "every window of 4 captures (cohort 0004b57f, bulk2000, syn_fan_40k, "
                                            "Chaos) equal to the model's, packets 9/9, 24,000/24,000, 39,847/39,847, "
                                            "221,733/221,733",
                                  "generator": "sweeps 1.1-2.6 ms after the collector's boundaries; every packet "
                                               "counted, but a bucket is cut when its probe passes (over 33 ms at "
                                               "0.5 us), so rows lose parity: cohort 91/135 columns, bulk2000 44/135; "
                                               "not scored on the 109 captures",
                                  "limits": "PC1 (2 cores, 3.9 GB) hung during syn_fan_40k in generator mode; its "
                                            "NIC dropped exports under a flood even with 8,192 descriptors (80,443 in "
                                            "syn_fan_40k, 27,812 in Chaos)"}},
            "exact_program": {"ingress_stages": 11, "basic_fix_ingress_stages": 5, "stateful_alus": 23,
                              "latency_ns_median": 421, "basic_fix_latency_ns_median": 315,
                              "forwarding_only_latency_ns_median": 246, "flow_slots": 65536,
                              "windows_exact": "4796/4796", "packets_counted": "1469778/1469778",
                              "packets_without_a_slot_in_5_floods": 121521},
            "builds": hw}
    bh, h = load("both_hybrids.json")
    if bh is not None:
        out["sources"]["both_hybrids.json"] = h
        nd, h2 = load_path(HERE.parent / "host-gap-check-20261107" / "nested_design_estimate.json")
        out["sources"]["host-gap-check-20261107/nested_design_estimate.json"] = h2

        def stat(s):
            return {k: s[k] for k in ("mean", "sd_sample", "min", "max")}

        def stat_nd(s):  # nested_design.py's summary (compare_host.py: sd with ddof 1)
            return {"mean": s["mean"], "sd_sample": s["sd"], "min": s["min"], "max": s["max"]}

        def version(v):
            return {"heldout_rf42": {d: {k: m[k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")}
                                     for d, m in v["heldout_rf42"].items()},
                    "heldout_11_forest_seeds": {d: stat(s) for d, s in v["heldout_forest_seeds"].items()},
                    "train_cv_fold_seed42": v["train_cv_fold_seed42"],
                    "train_cv_ten_assignments": {d: stat(s) for d, s in v["train_cv_ten_assignments"].items()},
                    "train_cv_differences": {k[len("train_cv_"):]: {"mean": v[k]["mean"],
                                                                    "positive_in": sum(x > 0 for x in v[k]["values"])}
                                             for k in ("train_cv_stacked_minus_concat", "train_cv_stacked_minus_host",
                                                       "train_cv_concat_minus_host")}}
        paper = nd["cohorts"]["paper@20s"]["fixed"]
        out["both_hybrids_robustness"] = {
            "what": "both hybrids under the protocols of the thesis's robustness table (first collection, general "
                    "malware, 204 executions); the stacked rule of Table V added to the concatenated design that the "
                    "table reports; every figure the table already prints reproduced first",
            "published_figures_reproduced": bh["published_figures_reproduced"],
            "versions": {name: version(v) for name, v in bh["versions"].items()},
            "all_204_grouped_cv_rf300": {"concat": stat_nd(paper["full|concat|fixed"]["ba"]),
                                         "stacked": stat_nd(paper["full|stacked|fixed"]["ba"])}}
    Path(sys.argv[1]).write_text(json.dumps(out, indent=1, sort_keys=True))
    print("wrote", sys.argv[1])


if __name__ == "__main__":
    main()
