#!/usr/bin/env python3
"""Evaluate the switch's network features on IoT-23 chunks (output of prepare_iot23.py).

Protocol (fixed before any IoT-23 chunk was scored; written to protocol.json first):

A. Transfer (primary). The paper's network-only detector, a random forest of 500 trees with balanced
   class weights and seed 42 (evaluation/common.py), is trained on the 145 network columns of all
   240 rows of dataset/features.csv and applied unchanged to every sampled chunk. A chunk is flagged
   when the malicious probability is at least 0.5.
B. Within IoT-23 (secondary). The same random forest, trained on IoT-23 chunks with
   leave-one-scenario-out folds: positives are chunks of malware captures whose overlapping flows
   include DDoS, scan, attack or C&C labels; negatives are chunks with traffic from the three benign
   devices. Every chunk of a held-out scenario is scored, including the controls below.

Reported for both: per chunk category, the fraction of chunks flagged, first per scenario and then
averaged over scenarios (each capture counts once, whatever its number of files or slices), plus
pooled counts. The headline numbers are DDoS
recall, scan recall, C&C recall, and the false-alarm rate on benign-device chunks averaged over the
three devices; balanced accuracy pairs DDoS recall with benign specificity. Controls, never used as
positives or negatives: chunks of malware captures whose overlapping flows are all labeled benign
(infected device, no labeled attack traffic) and chunks without any flow.

    python3 -I evaluate_iot23.py PREPARED_DIR [--dry-run]
"""

import argparse
import csv
import hashlib
import json
import platform
import site
import subprocess
import sys
import time
from pathlib import Path

RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(RELEASE / "evaluation"))
if site.getusersitepackages() not in sys.path:
    sys.path.append(site.getusersitepackages())

import numpy as np  # noqa: E402
import sklearn  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

import common  # noqa: E402

HERE = Path(__file__).resolve().parent
THRESHOLD = 0.5
ATTACK_CATEGORIES = ("ddos", "scan", "attack", "cc")
BENIGN_DEVICES = ("CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-7-1")


# Flow counts per detailed label published on https://www.stratosphereips.org/datasets-iot23.
PUBLISHED = {
    "CTU-IoT-Malware-Capture-34-1": {"DDoS": 14394, "PartOfAHorizontalPortScan": 122},
    "CTU-IoT-Malware-Capture-44-1": {"DDoS": 1},
    "CTU-IoT-Malware-Capture-60-1": {"DDoS": 3578457},
    "CTU-IoT-Malware-Capture-35-1": {"DDoS": 2185302},
    "CTU-IoT-Malware-Capture-7-1": {"DDoS": 39584},
    "CTU-IoT-Malware-Capture-49-1": {"PartOfAHorizontalPortScan": 5404959},
    "CTU-IoT-Malware-Capture-48-1": {"PartOfAHorizontalPortScan": 3386119},
    "CTU-IoT-Malware-Capture-9-1": {"PartOfAHorizontalPortScan": 6355745},
    "CTU-IoT-Malware-Capture-3-1": {"PartOfAHorizontalPortScan": 145597},
    "CTU-IoT-Malware-Capture-1-1": {"PartOfAHorizontalPortScan": 539465},
}


def label_audit(units):
    """Compare the parsed label counts with the published ones (exact detailed label)."""
    out = {}
    for u in units:
        if u["scenario"] in PUBLISHED and u["scenario"] not in out and "label_totals" in u:
            parsed = {}
            for key, n in u["label_totals"].items():
                detailed = key.split("|", 1)[1]
                parsed[detailed] = parsed.get(detailed, 0) + n
            out[u["scenario"]] = {label: {"published": n, "parsed": parsed.get(label, 0),
                                          "match": parsed.get(label, 0) == n}
                                  for label, n in PUBLISHED[u["scenario"]].items()}
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def group_of(row):
    """Category used for reporting: attack categories, benign-device traffic, or a control."""
    if row["role"] == "benign":
        return "benign_device" if row["category"] == "benign" else "benign_idle"
    if row["category"] in ATTACK_CATEGORIES:
        return row["category"]
    return {"benign": "infected_quiet", "idle": "infected_idle", "other": "other_malicious"}[row["category"]]


def load_chunks(prepared):
    rows, units = [], []
    for path in sorted((prepared / "units").glob("*.rows.json")):
        rows += json.load(open(path))
        units.append(json.load(open(str(path).replace(".rows.json", ".json"))))
    for row in rows:
        row["group"] = group_of(row)
    return rows, units


def flagged_summary(rows, probability):
    """Per report group: flagged fraction per scenario (one capture, or the slices or files of one
    capture), the mean over scenarios, and pooled counts."""
    out = {}
    for g in sorted({r["group"] for r in rows}):
        idx = [i for i, r in enumerate(rows) if r["group"] == g]
        per_scenario = {}
        for i in idx:
            per_scenario.setdefault(rows[i]["scenario"], []).append(probability[i] >= THRESHOLD)
        out[g] = {
            "chunks": len(idx),
            "scenarios": len(per_scenario),
            "flagged_pooled": int(sum(probability[i] >= THRESHOLD for i in idx)),
            "flagged_fraction_pooled": float(np.mean([probability[i] >= THRESHOLD for i in idx])),
            "flagged_fraction_mean_over_scenarios": float(np.mean([np.mean(v) for v in per_scenario.values()])),
            "median_probability": float(np.median([probability[i] for i in idx])),
            "per_scenario": {u: {"family": next(rows[i]["family"] for i in idx if rows[i]["scenario"] == u),
                                 "chunks": len(v), "flagged": int(sum(v)), "fraction": float(np.mean(v))}
                             for u, v in sorted(per_scenario.items())},
        }
    # Benign devices: average over the three devices (Somfy's six captures form one device).
    device = {}
    for i, r in enumerate(rows):
        if r["group"] == "benign_device":
            device.setdefault(r["scenario"], []).append(probability[i] >= THRESHOLD)
    out["_benign_false_alarm_mean_over_devices"] = float(np.mean([np.mean(v) for v in device.values()])) if device else None
    out["_benign_false_alarm_per_device"] = {d: float(np.mean(v)) for d, v in sorted(device.items())}
    return out


def headline(summary, rows, probability):
    def recall(g):
        return summary[g]["flagged_fraction_mean_over_scenarios"] if g in summary else None
    false_alarm = summary["_benign_false_alarm_mean_over_devices"]
    out = {g + "_recall": recall(g) for g in ATTACK_CATEGORIES}
    out["benign_device_false_alarm"] = false_alarm
    if out["ddos_recall"] is not None and false_alarm is not None:
        out["balanced_accuracy_ddos_vs_benign"] = (out["ddos_recall"] + 1 - false_alarm) / 2
    for g in ATTACK_CATEGORIES:
        idx = [i for i, r in enumerate(rows) if r["group"] in (g, "benign_device")]
        y = [int(rows[i]["group"] == g) for i in idx]
        if 0 < sum(y) < len(y):
            out["auc_%s_vs_benign_device_pooled" % g] = float(roc_auc_score(y, [probability[i] for i in idx]))
    return out


DESCRIBE = ("net_pkts_per_sec_delta__mean", "net_flow_count_seen__max", "net_syn_delta__sum", "net_ack_delta__sum",
            "net_flows_with_ba__max", "net_avg_pkt_size_delta__mean", "net_pkts_total_delta__active_windows")


def describe(rows):
    """Median of a few switch features per IoT-23 group and per category of the training dataset."""
    data, _, _ = common.load()
    out = {}
    for name, members in [("iot23:" + g, [r for r in rows if r["group"] == g]) for g in sorted({r["group"] for r in rows})] + \
                         [("dataset:" + c, [r for r in data if r["category"] == c]) for c in sorted({r["category"] for r in data})]:
        out[name] = {"n": len(members), **{f: float(np.median([float(r[f]) for r in members])) for f in DESCRIBE}}
    return out


def transfer(rows, columns):
    data, _, network = common.load()
    assert network == columns
    X = common.matrix(data, network)
    y = common.labels(data)
    model = common.random_forest().fit(X, y)
    Z = np.asarray([[float(r[c]) for c in network] for r in rows])
    probability = model.predict_proba(Z)[:, 1]
    zero = model.predict_proba(np.zeros((1, len(network))))[:, 1][0]
    return probability, float(zero), {"train_rows": len(y), "train_malicious": int(y.sum())}


def within(rows, columns):
    Z = np.asarray([[float(r[c]) for c in columns] for r in rows])
    target = np.asarray([1 if r["group"] in ATTACK_CATEGORIES else 0 if r["group"] == "benign_device" else -1
                         for r in rows])
    probability = np.full(len(rows), np.nan)
    folds = []
    for held in sorted({r["scenario"] for r in rows}):
        test = np.asarray([r["scenario"] == held for r in rows])
        train = (~test) & (target >= 0)
        model = RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=common.SEED, n_jobs=8)
        model.fit(Z[train], target[train])
        probability[test] = model.predict_proba(Z[test])[:, 1]
        folds.append({"held_out": held, "train_rows": int(train.sum()), "train_malicious": int(target[train].sum()),
                      "test_rows": int(test.sum())})
    return probability, folds


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("prepared", type=Path)
    parser.add_argument("--dry-run", action="store_true", help="check inputs and columns only; score nothing")
    args = parser.parse_args()

    rows, units = load_chunks(args.prepared)
    _, _, network = common.load()
    missing = [c for c in network if c not in rows[0]]
    assert not missing, missing
    counts = {}
    for r in rows:
        counts.setdefault(r["group"], 0)
        counts[r["group"]] += 1
    print("%d chunks from %d capture files; per group: %s" % (len(rows), len(units), counts))
    audit = label_audit(units)
    print("label audit:", json.dumps(audit))
    if args.dry_run:
        return

    out_dir = args.prepared / ("evaluation-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    out_dir.mkdir()
    release_commit = subprocess.run(["git", "-C", str(RELEASE), "rev-parse", "HEAD"], capture_output=True,
                                    text=True).stdout.strip()
    protocol = {
        "description": __doc__,
        "threshold": THRESHOLD,
        "model": "RandomForestClassifier(n_estimators=500, class_weight='balanced', random_state=42)",
        "attack_categories": ATTACK_CATEGORIES,
        "benign_devices": BENIGN_DEVICES,
        "release_commit": release_commit,
        "code_sha256": {p.name: sha256(p) for p in (HERE / "prepare_iot23.py", HERE / "evaluate_iot23.py",
                                                    RELEASE / "features/switch_model.py", RELEASE / "features/summary.py",
                                                    RELEASE / "evaluation/common.py", common.DATASET)},
        "units": [{k: u[k] for k in ("pcap", "pcap_sha256", "labels", "labels_sha256", "family", "role") if k in u}
                  for u in units],
        "chunks_per_group": counts,
        "label_audit": audit,
        "python": platform.python_version(), "numpy": np.__version__, "sklearn": sklearn.__version__,
    }
    with open(out_dir / "protocol.json", "x") as f:
        json.dump(protocol, f, indent=1)

    p_transfer, zero_score, train_info = transfer(rows, network)
    summary_a = flagged_summary(rows, p_transfer)
    result = {"protocol_sha256": sha256(out_dir / "protocol.json"),
              "A_transfer": {"training": train_info, "probability_of_all_zero_vector": zero_score,
                             "headline": headline(summary_a, rows, p_transfer), "groups": summary_a}}
    p_within, folds = within(rows, network)
    summary_b = flagged_summary(rows, p_within)
    result["B_within_iot23"] = {"folds": folds, "headline": headline(summary_b, rows, p_within), "groups": summary_b}
    result["feature_medians"] = describe(rows)
    with open(out_dir / "results.json", "x") as f:
        json.dump(result, f, indent=1)
    with open(out_dir / "chunk_scores.csv", "x", newline="") as f:
        w = csv.writer(f)
        w.writerow(["unit", "scenario", "family", "chunk", "start_us", "category", "group",
                    "p_transfer", "p_within"])
        for r, a, b in zip(rows, p_transfer, p_within):
            w.writerow([r["unit"], r["scenario"], r["family"], r["chunk"], r["start_us"], r["category"], r["group"],
                        "%.6f" % a, "%.6f" % b])
    print(json.dumps({"A": result["A_transfer"]["headline"], "B": result["B_within_iot23"]["headline"]}, indent=1))
    print("wrote", out_dir)


if __name__ == "__main__":
    main()
