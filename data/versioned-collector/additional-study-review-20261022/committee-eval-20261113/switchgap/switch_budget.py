"""Readout limits (committee item 1): the dataset-profile switch with a read budget per 0.5 s window. Offline.

Budget None must reproduce switch_gap.py's 'profile' features exactly; 800 is the measured raw-wire capacity,
350 the slower route. Detectors trained on the dataset features (as published), test rows scored with the
budgeted features, Table V (ten fold assignments) and Table IV (held-out).

    /usr/bin/python3 switch_budget.py [--jobs 6]
"""
import argparse
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402
import budget_rules as BR  # noqa: E402
import package_cohort as PC  # noqa: E402
from compute_oof import _fit_stream_models, _predict_stream  # noqa: E402

PROFILE = ("parsing", "key", "direction", "idle")
BUDGETS = {"budget_none": None, "budget_800": 800, "budget_350": 350}
D = {}


def features_job(args):
    i, run_dir = args
    out = C.output_dir(run_dir)
    start = int(json.loads((out / "run.json").read_text())["sample_started_wall_us"])
    _, records = PC.read_pcap(out / "packet_capture.pcap")
    rel = PC.load_release(C.RELEASE)
    res, stats = {}, {}
    for name, b in BUDGETS.items():
        m = BR.BudgetRules(rel, 0.5, 40, rules=PROFILE, budget=b)
        f = PC.five(m.run(records, start), D["signals"])
        res[name] = [f[c] for c in D["net_cols"]]
        stats[name] = (m.overloaded_windows, m.skipped_reads)
    return i, res, stats


def cv_job(seed):
    y, g, Xh = D["y"], D["g"], D["Xh"]
    preds = {name: {d: np.zeros(len(y)) for d in C.DETECTORS} for name in D["X"]}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        models = _fit_stream_models(Xh, D["Xn_model"], y, g, tr)
        for name, X in D["X"].items():
            for d, p in _predict_stream(models, Xh[te], X[te]).items():
                preds[name][d][te] = p
    return seed, preds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=6)
    a = ap.parse_args()
    rows, hc, nc = C.load()
    y, g = C.labels(rows), C.groups_published(rows)
    D.update(signals=C.signals(nc), net_cols=nc)
    with Pool(a.jobs) as p:
        res = sorted(p.map(features_job, list(enumerate(C.run_dirs(rows))), chunksize=1))
    X = {name: np.asarray([r[1][name] for r in res]) for name in BUDGETS}
    stats = {name: [r[2][name] for r in res] for name in BUDGETS}
    prof = np.load(C.CACHE / "switchgap_features.npz")["profile"]
    d = float(np.max(np.abs(X["budget_none"] - prof) / np.maximum(1, np.abs(prof))))
    print("budget None vs switch_gap profile: max relative difference %.2e" % d)
    assert d < 1e-12
    Xmodel = C.matrix(rows, nc)
    cats = np.asarray([r["category"] for r in rows])
    out = {"overload": {}, "detection_table_v": {}, "detection_table_iv": {}}
    for name in ("budget_800", "budget_350"):
        ov = [(rows[i]["execution_id"], rows[i]["category"], s[0], s[1]) for i, s in enumerate(stats[name]) if s[0]]
        out["overload"][name] = {"runs_with_overloaded_windows": len(ov),
                                 "runs": [{"execution_id": e, "category": c, "overloaded_windows": w, "skipped_bucket_reads": k}
                                          for e, c, w, k in ov]}
    D.update(y=y, g=g, Xh=C.matrix(rows, hc), Xn_model=Xmodel,
             X={"model": Xmodel, "profile": X["budget_none"], "budget_800": X["budget_800"], "budget_350": X["budget_350"]})
    with Pool(min(a.jobs, 10)) as p:
        cv = dict(p.map(cv_job, C.FOLD_SEEDS, chunksize=1))
    for name in D["X"]:
        r = {}
        for det in C.DETECTORS:
            ba = [C.metrics(y, cv[s][name][det])["balanced_accuracy"] for s in C.FOLD_SEEDS]
            flips = [int(((cv[s][name][det] >= .5) != (cv[s]["model"][det] >= .5)).sum()) for s in C.FOLD_SEEDS]
            att = [float((cv[s][name][det][cats == "network_attack"] >= .5).mean()) for s in C.FOLD_SEEDS]
            r[det] = {"ba_mean": round(float(np.mean(ba)), 4), "flips_mean": round(float(np.mean(flips)), 2),
                      "attack_recall_mean": round(float(np.mean(att)), 3)}
        out["detection_table_v"][name] = r
    gen = np.asarray([r["category"] in ("malware", "benign") for r in rows])
    split = np.asarray([r["split"] for r in rows])
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    models = _fit_stream_models(D["Xh"], Xmodel, y, g, tr)
    base = _predict_stream(models, D["Xh"][te], Xmodel[te])
    for name, Xc in D["X"].items():
        p = _predict_stream(models, D["Xh"][te], Xc[te])
        out["detection_table_iv"][name] = {det: {"ba": round(C.metrics(y[te], p[det])["balanced_accuracy"], 4),
                                                 "flips": int(((p[det] >= .5) != (base[det] >= .5)).sum())}
                                           for det in C.DETECTORS}
    C.write_json(C.HERE / "results" / "switch_budget.json", out)
    print("wrote results/switch_budget.json")


if __name__ == "__main__":
    main()
