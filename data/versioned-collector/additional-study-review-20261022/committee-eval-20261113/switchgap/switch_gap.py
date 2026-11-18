"""Gap between the switch and its software model (committee item 1), offline, at the dataset's 0.5 s window.

The release's software model idealises the switch. p4_ebpf/live_test/package_cohort.py implements the
switch's six rules (RUNBOOK 19.7.2), each switchable: lengths (IPv4 totalLen), parsing (fixed offsets),
key (CRC-16 bucket of 65,536: colliding flows merge), direction, time (low 32 bits of a ns clock), idle
(bucket cleared after three windows without a packet). Configurations evaluated on all 240 captures:
  model    no rule: equals the dataset (checked)
  profile  parsing, key, direction, idle: the live collector's dataset profile, which restores frame
           lengths (+14 B) and unwraps the 32-bit timestamps in the control plane (RUNBOOK 19.9)
  raw      all six rules: the registers without the control plane's corrections
  single   each rule alone
Not modelled: the read budget under overload (offline every active bucket is read) and Ethernet padding
of received frames under +14 B.

Detection: the detectors are trained on the dataset (model) features, as published, and the test rows are
scored with each configuration's features: decision flips and balanced accuracy, Table V (ten fold
assignments) and Table IV (held-out split).

    /usr/bin/python3 switch_gap.py [--jobs 6]
"""
import argparse
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4_ebpf/live_test")
import common as C  # noqa: E402
import package_cohort as PC  # noqa: E402

RULES = PC.RULES
CONFIGS = {"model": (), "profile": ("parsing", "key", "direction", "idle"), "raw": RULES,
           **{"only_" + r: (r,) for r in RULES}}
D = {}


def features_job(args):
    i, run_dir = args
    out = C.output_dir(run_dir)
    start = int(json.loads((out / "run.json").read_text())["sample_started_wall_us"])
    _, records = PC.read_pcap(out / "packet_capture.pcap")
    rel = PC.load_release(C.RELEASE)
    res = {}
    for name, rules in CONFIGS.items():
        win = PC.SwitchRules(rel, 0.5, 40, rules=rules).run(records, start)
        f = PC.five(win, D["signals"])
        res[name] = [f[c] for c in D["net_cols"]]
    return i, res


def fit(Xh, Xn, y, g, tr):
    from compute_oof import _fit_stream_models, _predict_stream  # same definitions as everywhere else
    return _fit_stream_models(Xh, Xn, y, g, tr), _predict_stream


def cv_job(seed):
    y, g, Xh = D["y"], D["g"], D["Xh"]
    preds = {name: {d: np.zeros(len(y)) for d in C.DETECTORS} for name in CONFIGS}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        models, pred = fit(Xh, D["Xn"]["model"], y, g, tr)
        for name in CONFIGS:
            for d, p in pred(models, Xh[te], D["Xn"][name][te]).items():
                preds[name][d][te] = p
    return seed, preds


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=6)
    a = ap.parse_args()
    rows, hc, nc = C.load()
    y, g = C.labels(rows), C.groups_published(rows)
    D.update(signals=C.signals(nc), net_cols=nc)
    cache = C.CACHE / "switchgap_features.npz"
    if cache.exists():
        z = np.load(cache)
        Xn = {name: z[name] for name in CONFIGS}
    else:
        with Pool(a.jobs) as p:
            res = dict(p.map(features_job, list(enumerate(C.run_dirs(rows))), chunksize=1))
        Xn = {name: np.asarray([res[i][name] for i in range(len(rows))]) for name in CONFIGS}
        np.savez_compressed(cache, **Xn)
    Xref = C.matrix(rows, nc)
    dmodel = float(np.max(np.abs(Xn["model"] - Xref) / np.maximum(1, np.abs(Xref))))
    print("model configuration vs dataset: max relative difference %.2e" % dmodel)
    assert dmodel < 1e-9

    out = {"feature_level": {}, "detection_table_v": {}, "detection_table_iv": {}}
    cats = np.asarray([r["category"] for r in rows])
    for name in CONFIGS:
        diff = ~np.isclose(Xn[name], Xref, rtol=1e-9, atol=1e-12)
        rows_changed = diff.any(1)
        out["feature_level"][name] = {
            "rows_with_any_change": int(rows_changed.sum()),
            "by_category": {c: int(rows_changed[cats == c].sum()) for c in sorted(set(cats))},
            "columns_changed_most": sorted(((nc[j], int(diff[:, j].sum())) for j in range(len(nc)) if diff[:, j].any()),
                                           key=lambda t: -t[1])[:8]}

    D.update(y=y, g=g, Xh=C.matrix(rows, hc), Xn=Xn)
    with Pool(min(a.jobs, 10)) as p:
        cv = dict(p.map(cv_job, C.FOLD_SEEDS, chunksize=1))
    for name in CONFIGS:
        res = {}
        for d in C.DETECTORS:
            ba = [C.metrics(y, cv[s][name][d])["balanced_accuracy"] for s in C.FOLD_SEEDS]
            flips = [int(((cv[s][name][d] >= .5) != (cv[s]["model"][d] >= .5)).sum()) for s in C.FOLD_SEEDS]
            res[d] = {"ba_mean": round(float(np.mean(ba)), 4), "ba_sd": round(float(np.std(ba, ddof=1)), 4),
                      "decision_flips_per_assignment_mean": round(float(np.mean(flips)), 2),
                      "flips_max": int(np.max(flips))}
        out["detection_table_v"][name] = res

    gen = np.asarray([r["category"] in ("malware", "benign") for r in rows])
    split = np.asarray([r["split"] for r in rows])
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    models, pred = fit(D["Xh"], Xn["model"], y, g, tr)
    base = pred(models, D["Xh"][te], Xn["model"][te])
    for name in CONFIGS:
        p = pred(models, D["Xh"][te], Xn[name][te])
        out["detection_table_iv"][name] = {d: {"ba": round(C.metrics(y[te], p[d])["balanced_accuracy"], 4),
                                               "flips": int(((p[d] >= .5) != (base[d] >= .5)).sum())}
                                           for d in C.DETECTORS}
    C.write_json(C.HERE / "results" / "switch_gap.json", out)
    print("wrote results/switch_gap.json")


if __name__ == "__main__":
    main()
