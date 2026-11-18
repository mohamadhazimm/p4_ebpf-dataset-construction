#!/usr/bin/env python3
"""Pre-registered scoring of the network-active benign batch (run_session_netbenign.py; the questions and rules are in
its protocol "expectations", frozen before the batch ran). Nothing is executed; no new model type, threshold or
feature. Rows, groups, matrices and folds are build_base.py's (relaxed rule, "sessions" view, program windows from the
injection), run through with_runs.py's registration (the batch's batch_control repeats are left out of every pool).

Pools: paper_sb_nb (main + rest + floods + silent-server benign + this batch, the dataset's 2 rejected malware left
out) and base_nb (every run of base/20261117b + this batch); references: the same pools without this batch, recomputed
here on the same code and checked against base/20261117b/table45 (balanced accuracy equal to 1e-9).

Questions (protocol):
  Q1  network specificity on the earlier runs' network-active benign rows, with this batch in training: "fewer false
      alarms" if it rises by >= 0.10 over the reference, in both pools, 20 s
  Q2  concatenated or stacked minus host >= +0.02 in >= 8 of 10 assignments on base_nb, 20 s
  Q3  each detector's BA over the earlier rows only (this batch in training) next to the reference; reported
  Q4  detectors trained on all rows of base/20261117b applied once to this batch's benign rows: flag rate per detector,
      program and shape (forest seeds 42 and 0-9); reported
Also: Table V format at 20 s and 80 s, per stratum and per group, baselines and the random-feature reference; the lab
tools grouped by program instead of shape (sensitivity); the batch check (the 3 batch_control repeats against their
main/rest sessions of the same task); the new rows' own behaviour (host activity, packets, the silent-listener cue).

  /usr/bin/python3 score_netbenign.py --attempt runs/<batch> --out <dir>
"""
import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import with_runs as WR   # noqa: E402

BB = WR.BB
CS, C, lab = BB.CS, BB.C, BB.lab
SB = "20261117T013400746805Z"
BASE_RUNS = ["main", "tpilot", "floods", "triage", "rest", "silentbenign"]
PAPER_RUNS = ("main", "rest", "floods", "silentbenign")
COLS = ("balanced_accuracy", "recall", "specificity", "precision", "f1", "auc")
DETS = ("host", "network", "concat", "stacked")
REF = HERE / "base" / "20261117b" / "table45"
RF_SEEDS = [42] + list(range(10))


def all_rows(names):
    sessions, skipped = BB.load_runs(names)
    release = list(csv.DictReader(BB.RELEASE.open()))
    ds99 = {r["sha256"] for r in release if r["category"] == "malware"}
    rev5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
    rows, _u, _d = BB.build_views(sessions, "relaxed", ds99, rev5)
    return rows, skipped, ds99, rev5


def pool(name, rows):
    if name.startswith("paper"):
        runs = PAPER_RUNS + (("netbenign",) if name.endswith("_nb") else ())
        return [s for s in rows if s["run"] in runs and s["stratum"] != "malware_dataset_extra"]
    return list(rows)


def by_program_group(s):
    """Sensitivity: the lab tools' rows grouped by the tool instead of the traffic shape."""
    if s["kind"] == "benign" and s.get("source") == "tool" and not s.get("project"):
        return "project::" + s["tool"]
    return s["group"]


def score(ps, n, groups=None):
    y = np.asarray([CS.label(s) for s in ps])
    g = np.asarray(groups if groups is not None else [s["group"] for s in ps])
    Xh, Xn, pi, _, _ = BB.matrices(ps, n)
    sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
    out = {"rows": len(ps), "malicious": int(y.sum()), "benign": int((y == 0).sum()),
           "malicious_groups": len(set(g[y == 1])), "label0_groups": len(set(g[y == 0])), "detectors": {}}
    for d in DETS:
        per = [C.metrics(y, P[d][k]) for k in range(P[d].shape[0])]
        out["detectors"][d] = {c: {"mean": round(float(np.mean([m[c] for m in per])), 4),
                                   "sd": round(float(np.std([m[c] for m in per], ddof=1)), 4)} for c in COLS}
    st = np.asarray([s["stratum"] for s in ps])
    out["per_stratum"] = {}
    for name in sorted(set(st)):
        idx = np.where(st == name)[0]
        neg = name.startswith("benign") or name == "null"
        out["per_stratum"][name] = {"n": int(len(idx)), "measure": "specificity" if neg else "recall",
                                    **{d: round(float(((P[d][:, idx] < 0.5) if neg else (P[d][:, idx] >= 0.5)).mean()),
                                                4) for d in DETS}}
    out["minus_host"] = {k: {"mean": round(v["mean"], 4), "sd": round(v["sd"], 4),
                             "positive": "%d/%d" % (v["positive"], v["assignments"])}
                         for k, v in CS.paired(y, P).items()}
    out["per_group"] = {k: {kk: (round(vv, 3) if isinstance(vv, float) else vv) for kk, vv in v.items()}
                        for k, v in CS.by_group(y, g, P).items()}
    attempts = [BB.RUNS[r] for r in BB.ORDER]
    base = CS.program_baselines(ps, pi, n, attempts)
    out["baselines"] = {k: round(CS.baseline_cv(v, y, g).get("ba_mean", float("nan")), 4) for k, v in base.items()}
    out["noise_reference_p95"] = round(CS.noise_reference(y, g).get("p95", float("nan")), 4)
    return out, P, y


def rows_mask(ps, fn):
    return np.asarray([bool(fn(s)) for s in ps])


def spec_on(P, d, idx):
    return float((P[d][:, idx] < 0.5).mean()) if len(idx) else float("nan")


def ba_on(P, d, y, idx):
    vals = [C.metrics(y[idx], P[d][k][idx])["balanced_accuracy"] for k in range(P[d].shape[0])]
    return round(float(np.mean(vals)), 4), round(float(np.std(vals, ddof=1)), 4)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--attempt", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--skip-80s", action="store_true")
    a = p.parse_args()
    att = Path(a.attempt).resolve()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    protocol = lab.load(att / "protocol.json")
    WR.register("silentbenign", SB)
    WR.register("netbenign", att.name)
    WR.patch()
    result = {"attempt": att.name, "protocol_sha256": lab.sha256(att / "protocol.json"),
              "expectations": protocol["expectations"], "script_sha256": lab.sha256(__file__), "pools": {}}
    lines = []
    rows_nb, skipped, _ds99, _rev5 = all_rows(BASE_RUNS + ["netbenign"])
    controls = list(BB.BATCH_CONTROL_ROWS)      # read before the reference build resets the list
    rows_ref, _s, _a, _b = all_rows(BASE_RUNS)
    result["skipped"] = skipped
    new = [s for s in rows_nb if s["run"] == "netbenign"]
    result["new_rows"] = {"benign": sum(1 for s in new if s["kind"] == "benign"),
                          "null": sum(1 for s in new if s["kind"] == "null"),
                          "batch_control_left_out": len(controls)}
    # ---- references (recomputed) and the pools with the batch, 20 s
    n20 = BB.SPANS["20s"]
    ref_scores, P_ref, y_ref, ps_ref = {}, {}, {}, {}
    for name, saved in (("paper_sb", "table5_paper_sb.json"), ("base", "table5_base.json")):
        ps = pool(name, rows_ref)
        sc, P, y = score(ps, n20)
        stored = json.loads((REF / saved).read_text())["spans"]["20s"]["detectors"]
        for d in DETS:
            assert abs(sc["detectors"][d]["balanced_accuracy"]["mean"] - stored[d]["balanced_accuracy"]["mean"]) < 1e-4, \
                (name, d, sc["detectors"][d]["balanced_accuracy"]["mean"], stored[d]["balanced_accuracy"]["mean"])
        ref_scores[name], P_ref[name], y_ref[name], ps_ref[name] = sc, P, y, ps
        result["pools"][name + "_reference"] = {"20s": sc}
    nb_scores, P_nb, y_nb, ps_nb = {}, {}, {}, {}
    for name, refname in (("paper_sb_nb", "paper_sb"), ("base_nb", "base")):
        ps = pool(name, rows_nb)
        sc, P, y = score(ps, n20)
        nb_scores[name], P_nb[name], y_nb[name], ps_nb[name] = sc, P, y, ps
        result["pools"][name] = {"20s": sc}
    # ---- Q1: network specificity on the earlier runs' network-active benign rows
    q1 = {}
    for name, refname in (("paper_sb_nb", "paper_sb"), ("base_nb", "base")):
        key = lambda s: (s["run"], s["sid"])                                       # noqa: E731
        old_bn = {key(s) for s in ps_ref[refname] if s["stratum"] == "benign_network"}
        idx_new = np.where(rows_mask(ps_nb[name], lambda s: key(s) in old_bn))[0]
        idx_ref = np.where(rows_mask(ps_ref[refname], lambda s: key(s) in old_bn))[0]
        with_b = {d: round(spec_on(P_nb[name], d, idx_new), 4) for d in DETS}
        without = {d: round(spec_on(P_ref[refname], d, idx_ref), 4) for d in DETS}
        q1[name] = {"rows": int(len(idx_new)), "with_batch": with_b, "reference": without,
                    "network_rise": round(with_b["network"] - without["network"], 4)}
    q1["fewer_false_alarms"] = all(q1[k]["network_rise"] >= 0.10 for k in ("paper_sb_nb", "base_nb"))
    result["Q1_network_false_alarms"] = q1
    # ---- Q2: the hybrid over host on base_nb
    mh = nb_scores["base_nb"]["minus_host"]

    def passes(k):
        pos = int(mh[k]["positive"].split("/")[0])
        return mh[k]["mean"] >= 0.02 and pos >= 8
    result["Q2_hybrid_over_host"] = {"concat_minus_host": mh["concat_minus_host"],
                                     "stacked_minus_host": mh["stacked_minus_host"],
                                     "hybrid_adds_over_host": passes("concat_minus_host") or passes("stacked_minus_host")}
    # ---- Q3: BA over the earlier rows only
    q3 = {}
    for name, refname in (("paper_sb_nb", "paper_sb"), ("base_nb", "base")):
        idx = np.where(rows_mask(ps_nb[name], lambda s: s["run"] != "netbenign"))[0]
        q3[name] = {"rows": int(len(idx)),
                    "with_batch": {d: ba_on(P_nb[name], d, y_nb[name], idx) for d in DETS},
                    "reference": {d: (ref_scores[refname]["detectors"][d]["balanced_accuracy"]["mean"],
                                      ref_scores[refname]["detectors"][d]["balanced_accuracy"]["sd"]) for d in DETS}}
    result["Q3_original_rows"] = q3
    # ---- Q4: transfer to the new benign rows
    ps = ps_nb["base_nb"]
    y = y_nb["base_nb"]
    g = np.asarray([s["group"] for s in ps])
    Xh, Xn, _pi, _, _ = BB.matrices(ps, n20)
    tr = np.where(rows_mask(ps, lambda s: s["run"] != "netbenign"))[0]
    te = np.where(rows_mask(ps, lambda s: s["run"] == "netbenign" and s["kind"] == "benign"))[0]
    probs = {d: [] for d in DETS}
    for seed in (RF_SEEDS if len(te) else []):
        for d, pr in C.fit_predict(Xh, Xn, y, g, tr, te, rf_seed=seed).items():
            probs[d].append(pr)
    flags = {d: ((np.asarray(probs[d]) >= 0.5).mean(axis=0) if len(te) else np.zeros(0)) for d in DETS}
    q4 = {"rows": int(len(te)), "flag_rate": {d: (round(float(flags[d].mean()), 4) if len(te) else None) for d in DETS},
          "by_program": {}, "by_group": {}, "per_row": []}
    for key, fn in (("by_program", lambda s: s.get("program") or s.get("tool")), ("by_group", lambda s: s["group"])):
        vals = sorted({fn(ps[i]) for i in te})
        for v in vals:
            j = [k for k, i in enumerate(te) if fn(ps[i]) == v]
            q4[key][v] = {"rows": len(j), **{d: round(float(flags[d][j].mean()), 3) for d in DETS}}
    for k, i in enumerate(te):
        q4["per_row"].append({"sid": ps[i]["sid"], "name": ps[i]["name"], **{d: round(float(flags[d][k]), 2) for d in DETS}})
    result["Q4_transfer"] = q4
    # ---- sensitivity: the lab tools grouped by program
    sc, _P, _y = score(ps_nb["base_nb"], n20, groups=[by_program_group(s) for s in ps_nb["base_nb"]])
    result["sensitivity_tools_by_program"] = {"base_nb_20s": sc}
    # ---- 80 s, Table V format
    if not a.skip_80s:
        n80 = BB.SPANS["80s"]
        for name in ("paper_sb_nb", "base_nb"):
            sc, _P, _y = score(ps_nb[name], n80)
            result["pools"][name]["80s"] = sc
        for name, saved in (("paper_sb", "table5_paper_sb.json"), ("base", "table5_base.json")):
            result["pools"][name + "_reference"]["80s_saved"] = json.loads((REF / saved).read_text())["spans"]["80s"]
    # ---- batch check
    checks = []
    if controls:
        for s in controls:
            twins = [t for t in rows_nb if t["run"] in ("main", "rest") and t.get("archive") == s["archive"]
                     and t.get("args") == s["args"]]
            if not twins:
                checks.append({"sid": s["sid"], "name": s["name"], "twin": None})
                continue
            t = twins[0]
            Xh2, Xn2 = BB.matrices([s, t], n20)[:2]
            vh = np.concatenate([Xh2[0], Xn2[0]])          # the control's 90 host + 145 network columns
            vt = np.concatenate([Xh2[1], Xn2[1]])          # its earlier session's
            rho = float(spearmanr(vh, vt).correlation)
            act = [sum(float(w["host_total_syscalls_total"]) for w in r["W"]["program"]["host"][int(r["t_inject_s"] // 0.5):
                                                                                           int(r["t_inject_s"] // 0.5) + n20])
                   for r in (s, t)]
            pk = [sum(float(w["net_pkts_total_delta"]) for w in r["W"]["program"]["net"][int(r["t_inject_s"] // 0.5):
                                                                                     int(r["t_inject_s"] // 0.5) + n20])
                  for r in (s, t)]
            checks.append({"sid": s["sid"], "name": s["name"], "twin": "%s/%s" % (t["run"], t["sid"]),
                           "spearman_235": round(rho, 4), "host_calls": act, "net_packets": pk})
    result["batch_check"] = checks
    # ---- the new rows' own behaviour
    beh = []
    for s in new:
        if s["kind"] != "benign":
            continue
        i0 = int(s["t_inject_s"] // 0.5)
        host = s["W"]["program"]["host"][i0:i0 + BB.SPANS["80s"]]
        net = s["W"]["program"]["net"][i0:i0 + BB.SPANS["80s"]]
        beh.append({"sid": s["sid"], "name": s["name"], "group": s["group"], "program_ran": s.get("program_ran"),
                    "host_calls_20s": int(sum(float(w["host_total_syscalls_total"]) for w in host[:n20])),
                    "host_active_windows_80s": int(sum(1 for w in host if float(w["host_total_syscalls_total"]) > 0)),
                    "packets_20s": int(sum(float(w["net_pkts_total_delta"]) for w in net[:n20])),
                    "packets_80s": int(sum(float(w["net_pkts_total_delta"]) for w in net)),
                    "flows_with_reply_20s": int(sum(float(w["net_flows_with_ba"]) for w in net[:n20]))})
    result["new_rows_behaviour"] = beh
    result["new_rows_without_packets_20s"] = [b["name"] for b in beh if b["packets_20s"] == 0]
    (out / "netbenign_scores.json").write_text(json.dumps(result, indent=1, default=str))
    # ---- text summary
    for name in ("paper_sb_reference", "paper_sb_nb", "base_reference", "base_nb"):
        sc = result["pools"][name]["20s"]
        lines.append("%-20s 20s rows %d (%d mal / %d ben) " % (name, sc["rows"], sc["malicious"], sc["benign"]) +
                     " ".join("%s %.3f" % (d, sc["detectors"][d]["balanced_accuracy"]["mean"]) for d in DETS))
        lines.append("    minus host: " + ", ".join("%s %+.3f (%s)" % (k.replace("_minus_host", ""), v["mean"],
                                                                         v["positive"]) for k, v in sc["minus_host"].items()))
        bn = sc["per_stratum"].get("benign_network", {})
        lines.append("    benign_network specificity: " + " ".join("%s %.2f" % (d, bn.get(d, float("nan")))
                                                                       for d in DETS))
    lines.append("Q1 %s" % json.dumps(q1))
    lines.append("Q2 %s" % json.dumps(result["Q2_hybrid_over_host"]))
    lines.append("Q3 %s" % json.dumps(q3))
    lines.append("Q4 flag rate %s" % json.dumps(q4["flag_rate"]))
    lines.append("batch check %s" % json.dumps(checks))
    (out / "netbenign_scores.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
