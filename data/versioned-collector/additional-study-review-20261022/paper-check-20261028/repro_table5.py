"""Independent re-run of paper Table V (combined surface, 10 fold seeds).

Does NOT import the project's feature code: host ADFA-90 and P4-145 sample features are rebuilt here directly from
each run's per-window telemetry.csv (5 statistics over the 40 windows), labels/groups from the frozen case lists.
CV re-implemented with scikit-learn: outer StratifiedGroupKFold(5, shuffle, seed), RF500/balanced/rs42/n_jobs1 base
learners, inner StratifiedGroupKFold(min(5,groups), shuffle, 7) OOF -> LogisticRegression(balanced) stacker.
Also computes diagnostics on the same folds: concatenated 235-col hybrid, activity-only (log1p post-target syscalls),
return-code-only. Writes results to the scratchpad only.
"""
import csv, glob, json, math, sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

B = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022")
REV5 = B / "revision5-collection/20261025T100025568989Z"
RT = B / "realtools-collect/20261026T165642798242Z"
DV = B / "flood21-collect/20261026T154421063760Z"
X1 = B / "flood21-collect/20261026T150016786262Z"
X2 = B / "flood21-collect/20261026T151240756153Z"
ADFA = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/benign/revision3/labeled_sample_dataset.feature_columns.adfa-host.json")
OUT = Path(sys.argv[1])
SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
P4 = ["net_flow_count_seen", "net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta", "net_bytes_ab_delta",
      "net_pkts_ba_delta", "net_bytes_ba_delta", "net_min_len_mean", "net_max_len_mean", "net_min_len_min",
      "net_max_len_max", "net_avg_pkt_size_delta", "net_avg_pkt_size_ab_delta", "net_avg_pkt_size_ba_delta",
      "net_flow_duration_mean", "net_flow_duration_max", "net_bytes_per_sec_delta", "net_pkts_per_sec_delta",
      "net_down_up_ratio_delta", "net_ab_ratio_pkt_delta", "net_ba_ratio_pkt_delta", "net_ab_ratio_byte_delta",
      "net_ba_ratio_byte_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta", "net_flows_with_ab",
      "net_flows_with_ba", "net_dir_valid_count"]
STATS = ("mean", "max", "sum", "std", "active_windows")
HOSTCOLS = json.loads(ADFA.read_text())["host"]
P4COLS = ["network__p4_%s__%s" % (f, s) for f in P4 for s in STATS]


def five(v):
    v = np.asarray(v, dtype=float)
    return {"mean": float(v.mean()), "max": float(v.max()), "sum": float(v.sum()), "std": float(v.std()),
            "active_windows": float((v != 0).sum())}


def record(run_dir, name, label, stratum, group):
    rj = glob.glob(str(run_dir / "output" / "run_*" / "run.json"))
    assert len(rj) == 1, run_dir
    meta = json.loads(Path(rj[0]).read_text())
    tel = glob.glob(str(run_dir / "output" / "run_*" / "telemetry.csv"))
    rows = list(csv.DictReader(open(tel[0], newline="", encoding="utf-8-sig"))) if tel else []
    r = {"sample": name, "label": label, "stratum": stratum, "group": group,
         "quality": meta.get("collection_quality_status"), "exec": meta.get("target_exec", {}).get("status"),
         "schema": meta.get("telemetry_schema_version"), "runner": meta.get("malware_runner_sha256"),
         "windows": len(rows), "rc": meta.get("return_code"),
         "syscalls": int(meta.get("target_exec", {}).get("post_target_lineage_raw_syscalls", 0) or 0)}
    if len(rows) != 40:
        return r
    agg = {}
    for col in HOSTCOLS:
        sig, st = col.removeprefix("host__").rsplit("__", 1)
        if sig not in agg:
            agg[sig] = five([float(w[sig]) for w in rows])
        r[col] = agg[sig][st]
    for f in P4:
        a = five([float(w[f]) for w in rows])
        for s in STATS:
            r["network__p4_%s__%s" % (f, s)] = a[s]
    return r


def build():
    cases = {c["sample"]: c for c in json.loads((REV5 / "payload/cases.json").read_text())}
    val = json.loads(next(REV5.glob("validation-*.json")).read_text())
    acc = sorted(x["sample"] for x in val["results"] if x["status"] == "accepted" and x["label"] in ("benign", "malware"))
    pool = []
    for s in acc:
        c = cases[s]
        if c["label"] == "malware":
            pool.append(record(REV5 / "runs" / s, s, 1, "general_malware", "malware_signature::" + c["family"]))
        else:
            pool.append(record(REV5 / "runs" / s, s, 0, "cli_benign", "benign_project::" + c["project"]))
    floods = ["syn_fan_40k", "syn_fan_100k", "syn_fan_150k", "syn_sink_40k", "syn_sink_100k", "udp_fan_60k",
              "udp_fan_250k", "udp_sink_60k", "udp_sink_150k", "udp_sink_250k", "slowloris_150", "slowloris_300",
              "slowloris_500", "slowloris_800", "slowloris_1000", "goldeneye_g5", "goldeneye_g10", "goldeneye_g15",
              "goldeneye_p10", "goldeneye_r10"]
    extra = [(RT, n, 1, "flood_" + n.split("_")[0], "flood_" + n) for n in floods]
    for n in ["bulkup_200", "bulkup_400", "bulkup_700", "session_300", "session_600", "session_1000",
              "beacon_50", "beacon_100", "dns_2k", "dns_5k", "dns_10k"]:
        extra.append((DV, n, 0, "net_benign", "netb_" + n.rsplit("_", 1)[0]))
    extra += [(DV, "null1", 0, "null", "null"), (DV, "null2", 0, "null", "null"),
              (X1, "bulkdl", 0, "net_benign", "netb_bulkdl"), (X1, "nullidle", 0, "null", "null")]
    extra += [(X2, "bulk%d" % k, 0, "net_benign", "netb_bulkup") for k in (400, 700, 1000, 1300, 1600, 2000)]
    dropped = []
    for att, n, lab, st, grp in extra:
        r = record(att / "runs" / (n + ".zip"), n, lab, st, grp)
        if r["quality"] != "accepted" or r["windows"] != 40:
            dropped.append((n, r["quality"], r["windows"]))
            continue
        pool.append(r)
    return pool, dropped


def metrics(y, p):
    tp = int(((p == 1) & (y == 1)).sum()); fn = int(((p == 0) & (y == 1)).sum())
    tn = int(((p == 0) & (y == 0)).sum()); fp = int(((p == 1) & (y == 0)).sum())
    rec = tp / (tp + fn); spec = tn / (tn + fp); prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"BA": round((rec + spec) / 2, 3), "recall": round(rec, 3), "specificity": round(spec, 3),
            "precision": round(prec, 3), "f1": round(f1, 3), "tp": tp, "fn": fn, "tn": tn, "fp": fp}


def rf():
    return RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=42, n_jobs=1)


def run_seed(args):
    seed, Xh, Xp, Xa, Xr, y, g = args
    Xc = np.hstack([Xp, Xh])
    oof = {k: np.zeros(len(y)) for k in ("host", "p4", "hybrid", "concat235", "activity", "returncode")}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        hb = rf().fit(Xh[tr], y[tr]); pb = rf().fit(Xp[tr], y[tr])
        oof["host"][te] = hb.predict_proba(Xh[te])[:, 1]; oof["p4"][te] = pb.predict_proba(Xp[te])[:, 1]
        oh = np.zeros(len(tr)); op = np.zeros(len(tr)); gi = g[tr]; yi = y[tr]
        for itr, iva in StratifiedGroupKFold(min(5, len(set(gi))), shuffle=True, random_state=7).split(Xh[tr], yi, gi):
            oh[iva] = rf().fit(Xh[tr][itr], yi[itr]).predict_proba(Xh[tr][iva])[:, 1]
            op[iva] = rf().fit(Xp[tr][itr], yi[itr]).predict_proba(Xp[tr][iva])[:, 1]
        meta = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([oh, op]), yi)
        oof["hybrid"][te] = meta.predict_proba(np.column_stack([oof["host"][te], oof["p4"][te]]))[:, 1]
        oof["concat235"][te] = rf().fit(Xc[tr], y[tr]).predict_proba(Xc[te])[:, 1]
        oof["activity"][te] = rf().fit(Xa[tr], y[tr]).predict_proba(Xa[te])[:, 1]
        oof["returncode"][te] = rf().fit(Xr[tr], y[tr]).predict_proba(Xr[te])[:, 1]
    res = {"seed": seed}
    for k, v in oof.items():
        res[k] = metrics(y, (v >= .5).astype(int)); res[k]["auc"] = round(float(roc_auc_score(y, v)), 3)
        res[k]["pred"] = (v >= .5).astype(int).tolist()
    return res


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    pool, dropped = build()
    print("dropped:", dropped)
    bad = [r["sample"] for r in pool if r["schema"] != "2026-10-24.21" or not r["runner"].startswith("4933ff5c") or r["exec"] != "observed"]
    print("pool", len(pool), "labels", sum(r["label"] for r in pool), "benign", sum(1 - r["label"] for r in pool), "bad provenance", bad)
    json.dump(pool, open(OUT / "independent_pool.json", "w"))
    y = np.asarray([r["label"] for r in pool]); g = np.asarray([r["group"] for r in pool])
    Xh = np.asarray([[r[c] for c in HOSTCOLS] for r in pool]); Xp = np.asarray([[r[c] for c in P4COLS] for r in pool])
    Xa = np.log1p(np.asarray([[r["syscalls"]] for r in pool], dtype=float))
    Xr = np.asarray([[float(r["rc"] if r["rc"] is not None else 0)] for r in pool])
    print("Xh", Xh.shape, "Xp", Xp.shape, "finite", bool(np.isfinite(Xh).all() and np.isfinite(Xp).all()))
    with Pool(10) as p:
        R = p.map(run_seed, [(s, Xh, Xp, Xa, Xr, y, g) for s in SEEDS])
    strata = [r["stratum"] for r in pool]
    json.dump({"seeds": SEEDS, "per_seed": R, "strata": strata, "samples": [r["sample"] for r in pool]},
              open(OUT / "independent_cv.json", "w"))
    print("done")


if __name__ == "__main__":
    main()
