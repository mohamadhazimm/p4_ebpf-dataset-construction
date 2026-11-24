"""Write the numbers of the 2026-11-23 thesis review into the thesis repository's data/lab/thesis_review_20261123.json.

Every value is copied from a saved result file (listed with its SHA-256 under "sources") or recomputed here from a saved
cache of out-of-fold probabilities. Nothing is fitted. Run from anywhere with /usr/bin/python3.

Usage: python3 export_thesis_json.py
"""
import csv
import hashlib
import json
import os
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
WS = ASR.parents[4]
THESIS = WS / "a-unified-p4-ebpf-architecture-for-host-and-network-malware-detection"
JOURNAL = WS / "P4-eBPF-Journal" / "docs" / "analyses"
FEATURES = WS / "p4-ebpf-malware-detection" / "dataset" / "features.csv"
CACHE = ASR / "committee-eval-20261113" / "cache"
SRC = {
    "activity_strata": HERE / "activity_strata.json",
    "activity_strata_controls": HERE / "activity_strata_controls.json",
    "learning_curve": HERE / "learning_curve.json",
    "model_family": HERE / "model_family.json",
    "session_operating_point": HERE / "session_operating_point.json",
    "triage": ASR / "sample-intel-20261113" / "triage_network-20261115.csv",
    "operating_point_20261122": ASR / "thesis-review-20261122" / "operating_point.json",
    "consecutive_windows": JOURNAL / "consecutive_windows.json",
    "flood_fulltable": JOURNAL / "flood_fulltable.json",
    "heldout": THESIS / "data" / "lab" / "heldout.json",
    "cv_published": CACHE / "cv_published_k40.npz",
    "cv_attacktype": CACHE / "cv_attacktype_k40.npz",
    "cv_implementation": CACHE / "cv_implementation_k40.npz",
    "features": FEATURES,
}
DET = ("host", "network", "concat", "stacked")


def r(x, n=3):
    return None if x is None else round(float(x), n)


def main():
    out = {"_about": "Numbers of the 2026-11-23 thesis review (offline, exploratory, on examined data). Written by "
                     "lab ASR/thesis-review-20261123/export_thesis_json.py.", "sources": {}}
    for k, p in SRC.items():
        out["sources"][k] = {"path": os.path.relpath(p, WS), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}

    # 1. detection by activity (both pools) and its controls
    a = json.load(open(SRC["activity_strata"]))
    ac = json.load(open(SRC["activity_strata_controls"]))
    act = {}
    for pool in ("A_first_collection_240", "S_session_base_435_20s"):
        st = a[pool]["strata"]
        act[pool] = {
            s: {"malware": v["malware"], "benign": v["benign"],
                **{d: {"ba": r(v[d]["ba_mean"]), "recall": r(v[d]["recall"], 2), "specificity": r(v[d]["specificity"], 2)}
                   for d in a[pool]["detectors"]}}
            for s, v in st.items()}
        act[pool]["one_cue_forests"] = {cue: {s: r(ac[pool][cue][s]["ba_trained_mean"]) for s in ("quiet", "active")}
                                        for cue in ("lifetime", "activity", "traffic")}
        act[pool]["bins"] = {k: {"n": v["n"], "flagged": {d: r(f, 2) for d, f in v["flagged"].items()}}
                             for k, v in a[pool]["bins"].items()}
    # Triage behaviour of the quiet and active malware of the first collection
    rows = list(csv.DictReader(open(FEATURES, newline="")))
    calls = {x["sha256"]: float(x["syscall_count"]) for x in rows if x["category"] == "malware"}
    tri = {x["sha256"]: x["triage_class"] for x in csv.DictReader(open(SRC["triage"], newline=""))}
    net = ("all_answered", "some_unanswered", "none_answered")
    for name, cond in (("quiet", lambda c: c < 300), ("active", lambda c: c >= 300)):
        s = [h for h, c in calls.items() if cond(c)]
        act["A_first_collection_240"]["strata_triage_%s" % name] = {
            "malware": len(s), "networked_on_triage": sum(tri[h] in net for h in s),
            "silent_on_triage": sum(tri[h] == "silent" for h in s), "uncertain": sum(tri[h] == "uncertain" for h in s)}
    act["boundary_note"] = ("300 system calls; first seen on the first collection on 2026-11-12, fixed before the "
                            "session dataset was split")
    out["detection_by_activity"] = act

    # 2. attack types held out (cached out-of-fold probabilities of the committee analysis)
    y = np.asarray([int(x["label"]) for x in rows])
    cat = np.asarray([x["category"] for x in rows])
    at = np.asarray([x["attack_type"] for x in rows])
    att = {}
    for key, cache in (("published_grouping", "cv_published"), ("attack_type_held_out", "cv_attacktype"),
                       ("implementation_held_out", "cv_implementation")):
        z = np.load(SRC[cache], allow_pickle=True)
        att[key] = {}
        for d in DET:
            P = z[d]
            ba = np.mean([0.5 * ((p[y == 1] >= 0.5).mean() + (p[y == 0] < 0.5).mean()) for p in P])
            att[key][d] = {"ba": r(ba), "malware_recall": r((P[:, cat == "malware"] >= 0.5).mean()),
                           **{t: r((P[:, at == t] >= 0.5).mean(), 2)
                              for t in ("syn_flood", "udp_flood", "slowloris", "goldeneye")}}
    att["runs_per_type"] = {t: int((at == t).sum()) for t in ("syn_flood", "udp_flood", "slowloris", "goldeneye")}
    att["note"] = ("The published grouping puts every attack run in its own group, so runs of the same type are in "
                   "training; held out by type, every run of a type is tested without its kind in training.")
    out["attack_types_held_out"] = att

    # 3. null runs in the combined pool
    z = np.load(SRC["cv_published"], allow_pickle=True)
    out["null_runs_combined_pool"] = {"runs": int((cat == "null").sum()), "groups": 1,
                                      "flagged": {d: r((z[d][:, cat == "null"] >= 0.5).mean(), 2) for d in DET},
                                      "session_dataset_15_nulls_flagged": act["S_session_base_435_20s"].get("bins")
                                      and json.load(open(SRC["activity_strata"]))["S_session_base_435_20s"]["other"]["null"]["flagged"]}

    # 4. held-out false alarms (Table IV)
    h = json.load(open(SRC["heldout"]))
    out["heldout_false_alarms"] = [
        {"sample": s["sample"], "project": s["group"].split("::")[-1], "mode": s["mode"],
         "post_target_syscalls": s["post_target_syscalls"], "packets": s["in_window_packets"],
         "p_host": r(s["p_host"]), "p_concatenated": r(s["p_hybrid"])}
        for s in h["samples"] if int(s["label"]) == 0 and (s["p_host"] >= 0.5 or s["p_hybrid"] >= 0.5)]

    # 5. operating points: first collection, end of observation (2026-11-22) and any window (journal analysis)
    op = json.load(open(SRC["operating_point_20261122"]))
    out["operating_points_first_collection_end"] = {
        pool: {d: {t: r(op[pool]["detectors"][d][t]["recall_mean"]) for t in ("0.01", "0.05", "0.1")
                   if t in op[pool]["detectors"][d]} for d in DET}
        for pool in ("published_240", "cue_free_191")}
    cw = json.load(open(SRC["consecutive_windows"]))["detectors"]
    out["streaming_any_window"] = {
        d: {rule: {op_: {k: r(v, 3) for k, v in cw[d][rule][op_].items()} for op_ in cw[d][rule]}
            for rule in ("single", "consecutive")} for d in DET}
    so = json.load(open(SRC["session_operating_point"]))
    out["operating_points_session_dataset"] = {
        span: {t: {d: r(v["recall_all"], 2) for d, v in so["spans"][span]["targets"][t].items()}
               for t in so["spans"][span]["targets"]} for span in ("20s", "80s")}

    # 6. flood full table (hardware replays of the window-feature build against the published rows)
    ft = json.load(open(SRC["flood_fulltable"]))
    out["flow_table_full"] = {
        "captures": [{"execution": d["execution"], "category": d["category"],
                      "flow_count_change": r(d["net_flow_count_seen__sum"]["relative_change"], 4),
                      "totals_exact": all(d["totals_exact"].values())} for d in ft["differing"]],
        "decision_flips": ft["decision_changes"]}

    # 7. learning curves and classifiers (summary)
    lc = json.load(open(SRC["learning_curve"]))["pools"]
    out["learning_curves"] = {
        pool: {f"{mode}@{frac}": {d: r(lc[pool]["curves"][f"{mode}@{frac}"][d]["ba_mean"]) for d in ("host", "network", "concat")}
               | {"train_rows": r(lc[pool]["curves"][f"{mode}@{frac}"]["train_rows"], 1)}
               for mode in ("groups", "rows") for frac in ("0.125", "0.25", "0.5", "0.75", "1")}
        for pool in lc}
    mf = json.load(open(SRC["model_family"]))["pools"]
    out["classifiers"] = {pool: {m: {v: r(mf[pool][m][v]["ba_mean"]) for v in mf[pool][m]} for m in mf[pool]}
                          for pool in mf}

    dest = THESIS / "data" / "lab" / "thesis_review_20261123.json"
    json.dump(out, open(dest, "w"), indent=1, sort_keys=False)
    print("wrote", dest, hashlib.sha256(dest.read_bytes()).hexdigest()[:12])


if __name__ == "__main__":
    main()
