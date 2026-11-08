"""E3: recompute every run's network features with the switch-faithful model and rerun the tables.

    /usr/bin/python3 e3_run.py [--jobs 10]

For each of the 240 dataset executions, computes the 145 network columns with the faithful model at four
readout caps (unlimited, 5000, 1000, 350), writes one dataset CSV per cap (host columns and metadata copied
from the released dataset, network columns replaced), measures how far each cap's features are from the
idealized model, and reruns Table IV (held-out split) and Table V (stacked hybrid) with each faithful CSV,
training and testing both on faithful features. Writes e3_results.json and faithful datasets under e3_data/.
"""
import argparse
import csv
import glob
import json
import sys
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import faithful_switch_model as fm
REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
sys.path.insert(0, str(REL / "evaluation"))
import summary  # noqa: E402
from common import labels, matrix, metrics, random_forest  # noqa: E402

B = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022")
POOL = B / "paper-check-20261028/independent_pool.json"
ROOTS = [B / "revision5-collection/20261025T100025568989Z/runs", B / "realtools-collect/20261026T165642798242Z/runs",
         B / "flood21-collect/20261026T154421063760Z/runs", B / "flood21-collect/20261026T150016786262Z/runs",
         B / "flood21-collect/20261026T151240756153Z/runs"]
CAPS = [None, 5000, 1000, 350]
FOLD_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
INNER_SEED = 7


def run_dir(sample):
    for r in ROOTS:
        for name in (sample, sample + ".zip"):
            d = glob.glob(str(r / name / "output" / "run_*"))
            if d:
                return Path(d[0])
    raise FileNotFoundError(sample)


def faithful_for(sample):
    d = run_dir(sample)
    meta = json.loads((d / "run.json").read_text())
    start_us, window_s = int(meta["sample_started_wall_us"]), float(meta["window_seconds"])
    tel = sum(1 for _ in csv.DictReader(open(d / "telemetry.csv", newline="", encoding="utf-8-sig")))
    out = {}
    for cap in CAPS:
        windows = fm.window_features(d / "packet_capture.pcap", start_us, window_s, tel, cap)
        out[str(cap)] = summary.summarize(windows, fm.FEATURES)
    return sample, out


def table4(rows, host, network):
    train = [r for r in rows if r["category"] in ("malware", "benign") and r["split"] == "train"]
    test = [r for r in rows if r["category"] in ("malware", "benign") and r["split"] == "test"]
    ytr, yte = labels(train), labels(test)
    res = {}
    for name, cols in (("network", network), ("host", host), ("hybrid", host + network)):
        m = metrics(yte, random_forest().fit(matrix(train, cols), ytr).predict_proba(matrix(test, cols))[:, 1])
        res[name] = {k: m[k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")}
    return res


def _stack(Xh, Xn, y, groups, idx):
    ih, inn = np.zeros(len(idx)), np.zeros(len(idx))
    inner = StratifiedGroupKFold(min(5, len(set(groups[idx]))), shuffle=True, random_state=INNER_SEED)
    for a, b in inner.split(Xh[idx], y[idx], groups[idx]):
        f, o = idx[a], idx[b]
        ih[b] = random_forest().fit(Xh[f], y[f]).predict_proba(Xh[o])[:, 1]
        inn[b] = random_forest().fit(Xn[f], y[f]).predict_proba(Xn[o])[:, 1]
    return LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([ih, inn]), y[idx])


def _cv(args):
    seed, Xh, Xn, y, groups = args
    oof = {d: np.zeros(len(y)) for d in ("host", "network", "stacked")}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, groups):
        h = random_forest().fit(Xh[tr], y[tr]).predict_proba(Xh[te])[:, 1]
        n = random_forest().fit(Xn[tr], y[tr]).predict_proba(Xn[te])[:, 1]
        s = _stack(Xh, Xn, y, groups, tr).predict_proba(np.column_stack([h, n]))[:, 1]
        oof["host"][te], oof["network"][te], oof["stacked"][te] = h, n, s
    return oof


def tableV(rows, host, network, jobs):
    y = labels(rows)
    groups = np.array([r["cv_group"] for r in rows])
    Xh, Xn = matrix(rows, host), matrix(rows, network)
    with Pool(jobs) as pool:
        res = pool.map(_cv, [(s, Xh, Xn, y, groups) for s in FOLD_SEEDS])
    out = {}
    for d in ("host", "network", "stacked"):
        ms = [metrics(y, r[d]) for r in res]
        out[d] = [float(np.mean([m["balanced_accuracy"] for m in ms])), float(np.std([m["balanced_accuracy"] for m in ms], ddof=1))]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=10)
    args = ap.parse_args()
    pool = json.loads(POOL.read_text())
    base_rows = list(csv.DictReader(open(REL / "dataset" / "features.csv")))
    header = list(base_rows[0])
    host = [c for c in header if c.startswith("host_")]
    network = [c for c in header if c.startswith("net_")]
    meta_cols = [c for c in header if not c.startswith(("host_", "net_"))]
    assert len(base_rows) == len(pool) == 240

    with Pool(args.jobs) as p:
        faithful = dict(p.map(faithful_for, [e["sample"] for e in pool]))

    (HERE / "e3_data").mkdir(exist_ok=True)
    out = {"created_utc": datetime.now(timezone.utc).isoformat(), "caps": {}}
    # cell differences vs idealized (the released net_ columns)
    for cap in CAPS:
        key = str(cap)
        rows = []
        diffs, by_family = 0, {}
        for base, entry in zip(base_rows, pool):
            f = faithful[entry["sample"]][key]
            row = {c: base[c] for c in meta_cols + host}
            for c in network:
                row[c] = f[c]
                if float(base[c]) != float(f[c]):
                    diffs += 1
                    fam = c.rsplit("__", 1)[0]
                    by_family[fam] = by_family.get(fam, 0) + 1
            rows.append(row)
        path = HERE / "e3_data" / ("features_faithful_cap_%s.csv" % key)
        with open(path, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=header, lineterminator="\n")
            w.writeheader(); w.writerows(rows)
        out["caps"][key] = {
            "net_cells_differing": diffs, "net_cells_total": 240 * len(network),
            "fraction": diffs / (240 * len(network)),
            "most_changed_features": sorted(by_family.items(), key=lambda x: -x[1])[:6],
            "table4": table4(rows, host, network),
            "tableV_ba": tableV(rows, host, network, args.jobs),
        }
    (HERE / "e3_results.json").write_text(json.dumps(out, indent=1, default=float) + "\n")
    print("Idealized Table IV (released): host 0.929, network 0.750, hybrid 0.926; Table V host 0.784 network 0.756 stacked 0.823\n")
    for cap in CAPS:
        c = out["caps"][str(cap)]
        t4 = c["table4"]
        print("cap=%-5s net cells changed %.1f%% | Table IV host %.3f network %.3f hybrid %.3f | Table V host %.3f network %.3f stacked %.3f" % (
            str(cap), 100 * c["fraction"], t4["host"]["balanced_accuracy"], t4["network"]["balanced_accuracy"], t4["hybrid"]["balanced_accuracy"],
            c["tableV_ba"]["host"][0], c["tableV_ba"]["network"][0], c["tableV_ba"]["stacked"][0]))
    print("\nmost-changed feature families (cap=None):", out["caps"]["None"]["most_changed_features"])
    print("written", HERE / "e3_results.json")


if __name__ == "__main__":
    main()
