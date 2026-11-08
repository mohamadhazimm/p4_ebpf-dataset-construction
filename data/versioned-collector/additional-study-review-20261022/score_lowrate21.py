#!/usr/bin/env python3
"""Step 1 of the IoT-23 follow-ups: add the low-rate benign runs (collect_lowrate21.py) to the training
data and re-test.

Protocol (fixed before the runs were collected):
  A run counts if the collector accepted it (quality accepted, target exec observed, 40 windows) and
  the tool's receipt shows at least one answered operation for every activity it ran.
  Rows: the dataset's 235 columns, built from telemetry.csv exactly as the dataset was (same recipe as
  paper-check-20261028/repro_table5.py; checked to reproduce existing dataset rows exactly).
  T1, IoT-23 transfer: the network-only random forest (500 trees, balanced, seed 42) trained on the
  240 dataset rows (baseline, must reproduce the earlier IoT-23 result) and on the 240 rows plus the
  accepted low-rate rows (label 0), applied unchanged to the IoT-23 chunks of
  iot23-external/runs/20261105T202318Z.
  T2, the paper's combined evaluation (Table V procedure, 10 fold assignments, grouped nested CV,
  stacked hybrid) on the 240 rows and on the 240 rows plus the low-rate rows (one cv group per
  workload kind), with per-category rates from the out-of-fold predictions.

    python3 -I score_lowrate21.py LOWRATE_ATTEMPT_DIR
"""

import csv
import glob
import json
import site
import sys
from multiprocessing import Pool
from pathlib import Path

HERE = Path(__file__).resolve().parent
RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(RELEASE / "evaluation"))
sys.path.insert(0, str(HERE / "iot23-external"))
if site.getusersitepackages() not in sys.path:
    sys.path.append(site.getusersitepackages())

import numpy as np  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold  # noqa: E402

import common  # noqa: E402
import evaluate_iot23 as iot  # noqa: E402

ADFA = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/benign/revision3/"
            "labeled_sample_dataset.feature_columns.adfa-host.json")
IOT23_RUN = HERE / "iot23-external/runs/20261105T202318Z/prepared"
P4 = ["net_flow_count_seen", "net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta", "net_bytes_ab_delta",
      "net_pkts_ba_delta", "net_bytes_ba_delta", "net_min_len_mean", "net_max_len_mean", "net_min_len_min",
      "net_max_len_max", "net_avg_pkt_size_delta", "net_avg_pkt_size_ab_delta", "net_avg_pkt_size_ba_delta",
      "net_flow_duration_mean", "net_flow_duration_max", "net_bytes_per_sec_delta", "net_pkts_per_sec_delta",
      "net_down_up_ratio_delta", "net_ab_ratio_pkt_delta", "net_ba_ratio_pkt_delta", "net_ab_ratio_byte_delta",
      "net_ba_ratio_byte_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta", "net_flows_with_ab",
      "net_flows_with_ba", "net_dir_valid_count"]
STATS = ("mean", "max", "sum", "std", "active_windows")
FOLD_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
INNER_SEED = 7


def five(v):
    v = np.asarray(v, dtype=float)
    return {"mean": float(v.mean()), "max": float(v.max()), "sum": float(v.sum()), "std": float(v.std()),
            "active_windows": float((v != 0).sum())}


def build_row(run_dir):
    """235 dataset columns of one run (host from the ADFA contract, network from the P4 columns)."""
    tel = glob.glob(str(run_dir / "output" / "run_*" / "telemetry.csv"))
    windows = list(csv.DictReader(open(tel[0], newline="", encoding="utf-8-sig")))
    row = {}
    for col in json.loads(ADFA.read_text())["host"]:
        signal, statistic = col.removeprefix("host__").rsplit("__", 1)
        row["%s__%s" % (signal, statistic)] = five([float(w[signal]) for w in windows])[statistic]
    for feature in P4:
        stats = five([float(w[feature]) for w in windows])
        for s in STATS:
            row["%s__%s" % (feature, s)] = stats[s]
    return row, len(windows)


def accept(attempt):
    protocol = json.load(open(attempt / "protocol.json"))
    out = []
    for case in protocol["cases"]:
        run_dir = attempt / "runs" / case["sample"]
        meta_path = glob.glob(str(run_dir / "output" / "run_*" / "run.json"))
        entry = {"name": case["name"], "argv": case["argv"]}
        if len(meta_path) != 1:
            out.append({**entry, "accepted": False, "reason": "no run.json"})
            continue
        meta = json.load(open(meta_path[0]))
        receipt_path = Path(meta_path[0]).parent / "sample.stdout.log"
        try:
            receipt = json.loads(receipt_path.read_text().strip().splitlines()[-1])
        except Exception:
            receipt = None
        row, windows = build_row(run_dir)
        reasons = []
        if meta.get("collection_quality_status") != "accepted":
            reasons.append("quality %s" % meta.get("collection_quality_status"))
        if meta.get("target_exec", {}).get("status") != "observed":
            reasons.append("target exec not observed")
        if windows != 40:
            reasons.append("%d windows" % windows)
        if not receipt:
            reasons.append("no receipt")
        else:
            unanswered = [a["kind"] for a in receipt["activities"] if a["ok"] < 1]
            if unanswered:
                reasons.append("no answer for %s" % ",".join(unanswered))
        out.append({**entry, "accepted": not reasons, "reason": "; ".join(reasons), "receipt": receipt,
                    "return_code": meta.get("return_code"), "quality": meta.get("collection_quality_status"),
                    "runner_sha256": meta.get("malware_runner_sha256"), "schema": meta.get("telemetry_schema_version"),
                    "syscall_count": int(meta.get("target_exec", {}).get("post_target_lineage_raw_syscalls", 0) or 0),
                    "row": row})
    return protocol, out


def oof_run(args):
    """Table V procedure (evaluation/combined.py) returning out-of-fold probabilities."""
    seed, X_host, X_net, y, groups = args
    oof = {name: np.zeros(len(y)) for name in ("host-only", "network-only", "hybrid")}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X_host, y, groups):
        oof["host-only"][te] = common.random_forest().fit(X_host[tr], y[tr]).predict_proba(X_host[te])[:, 1]
        oof["network-only"][te] = common.random_forest().fit(X_net[tr], y[tr]).predict_proba(X_net[te])[:, 1]
        inner_host, inner_net = np.zeros(len(tr)), np.zeros(len(tr))
        inner = StratifiedGroupKFold(min(5, len(set(groups[tr]))), shuffle=True, random_state=INNER_SEED)
        for itr, ite in inner.split(X_host[tr], y[tr], groups[tr]):
            a, b = tr[itr], tr[ite]
            inner_host[ite] = common.random_forest().fit(X_host[a], y[a]).predict_proba(X_host[b])[:, 1]
            inner_net[ite] = common.random_forest().fit(X_net[a], y[a]).predict_proba(X_net[b])[:, 1]
        stacker = LogisticRegression(max_iter=2000, class_weight="balanced")
        stacker.fit(np.column_stack([inner_host, inner_net]), y[tr])
        oof["hybrid"][te] = stacker.predict_proba(np.column_stack([oof["host-only"][te], oof["network-only"][te]]))[:, 1]
    return {name: p.tolist() for name, p in oof.items()}


def combined(rows, host_cols, net_cols, categories, jobs=10):
    y = np.asarray([int(r["label"]) for r in rows])
    groups = np.asarray([r["cv_group"] for r in rows])
    X_host = np.asarray([[float(r[c]) for c in host_cols] for r in rows])
    X_net = np.asarray([[float(r[c]) for c in net_cols] for r in rows])
    with Pool(jobs) as pool:
        runs = pool.map(oof_run, [(s, X_host, X_net, y, groups) for s in FOLD_SEEDS])
    out = {}
    for name in ("host-only", "network-only", "hybrid"):
        metrics = [common.metrics(y, np.asarray(r[name])) for r in runs]
        summary = {k: {"mean": float(np.mean([m[k] for m in metrics])), "sd": float(np.std([m[k] for m in metrics], ddof=1))}
                   for k in ("balanced_accuracy", "recall", "specificity", "precision", "f1")}
        per_cat = {}
        for cat in sorted(set(categories)):
            idx = [i for i, c in enumerate(categories) if c == cat]
            flagged = [float(np.mean([r[name][i] >= 0.5 for i in idx])) for r in runs]
            per_cat[cat] = {"rows": len(idx), "flagged_fraction_mean": float(np.mean(flagged))}
        out[name] = {"summary": summary, "flagged_by_category": per_cat}
    return out


def self_test():
    """T1 baseline must reproduce the IoT-23 transfer result of iot23-external (same model, same chunks)."""
    data, _, net_cols = common.load()
    chunks, _ = iot.load_chunks(IOT23_RUN)
    Z = np.asarray([[float(c[k]) for k in net_cols] for c in chunks])
    X = np.asarray([[float(r[c]) for c in net_cols] for r in data])
    y = np.asarray([int(r["label"]) for r in data])
    p = common.random_forest().fit(X, y).predict_proba(Z)[:, 1]
    mine = iot.headline(iot.flagged_summary(chunks, p), chunks, p)
    earlier = json.load(open(next(IOT23_RUN.glob("evaluation-*/results.json"))))["A_transfer"]["headline"]
    same = all(abs(mine[k] - earlier[k]) < 1e-12 for k in earlier)
    print("T1 baseline reproduces the IoT-23 result:", same)
    sys.exit(0 if same else 1)


def main():
    if sys.argv[1] == "--self-test":
        self_test()
    attempt = Path(sys.argv[1]).resolve()
    protocol, runs = accept(attempt)
    accepted = [r for r in runs if r["accepted"]]
    print("accepted %d of %d: %s" % (len(accepted), len(runs), [(r["name"], r["reason"]) for r in runs if not r["accepted"]]))

    data, host_cols, net_cols = common.load()
    extra = []
    for r in accepted:
        kind = r["argv"][0] if r["argv"][0] != "device" else "device"
        extra.append({"execution_id": r["name"], "label": "0", "category": "network_benign_lowrate",
                      "cv_group": "netlow_" + kind, **{c: r["row"][c] for c in host_cols + net_cols}})

    # T1: IoT-23 transfer, baseline and with the low-rate rows
    chunks, _ = iot.load_chunks(IOT23_RUN)
    Z = np.asarray([[float(c[k]) for k in net_cols] for c in chunks])
    t1 = {}
    for name, train in (("baseline_240", data), ("with_lowrate", data + extra)):
        X = np.asarray([[float(r[c]) for c in net_cols] for r in train])
        y = np.asarray([int(r["label"]) for r in train])
        model = common.random_forest().fit(X, y)
        p = model.predict_proba(Z)[:, 1]
        summary = iot.flagged_summary(chunks, p)
        t1[name] = {"train_rows": len(train), "headline": iot.headline(summary, chunks, p),
                    "benign_false_alarm_per_device": summary["_benign_false_alarm_per_device"],
                    "groups": {g: {k: summary[g][k] for k in ("chunks", "flagged_fraction_mean_over_scenarios",
                                                               "flagged_fraction_pooled", "median_probability")}
                               for g in summary if not g.startswith("_")}}
        print("T1", name, json.dumps(t1[name]["headline"]), flush=True)

    # T2: combined evaluation, baseline and with the low-rate rows
    t2 = {}
    for name, rows in (("baseline_240", data), ("with_lowrate", data + extra)):
        categories = [r["category"] for r in rows]
        t2[name] = combined(rows, host_cols, net_cols, categories)
        print("T2", name, {m: round(t2[name][m]["summary"]["balanced_accuracy"]["mean"], 3) for m in t2[name]}, flush=True)

    result = {"attempt": str(attempt), "runner": protocol.get("runner"),
              "runs": [{k: v for k, v in r.items() if k != "row"} for r in runs],
              "accepted": len(accepted), "T1_iot23_transfer": t1, "T2_combined": t2}
    out = attempt / "scoring.json"
    with open(out, "x") as f:
        json.dump(result, f, indent=1)
    with open(attempt / "lowrate_rows.csv", "x", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["execution_id", "label", "category", "cv_group", *host_cols, *net_cols])
        w.writeheader()
        w.writerows(extra)
    print("wrote", out)


if __name__ == "__main__":
    main()
