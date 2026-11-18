"""Score captures replayed through the real switch (committee item 1) against the software model. Offline.

Input: a CSV of dataset-shaped rows written by p4_ebpf/live_test/dataset_row.py from replays of the
dataset's captures through the Wedge (hybrid_collector.py --profile dataset, 0.5 s, 40 windows). Its
`execution_id` names the dataset row; only its 145 network columns are used (the host side of a replay is
not measured; the dataset's host columns are kept). Rows of the dataset that were not replayed keep their
software-model network features (all-zero for runs without TCP/UDP traffic in the observation).

Output: per feature, how far the switch's values are from the software model's; and detection with the
published detectors trained on the software-model features, scoring the replayed rows with the switch's
features: decision flips and balanced accuracy, Table V (ten fold assignments) and Table IV (held-out).

    /usr/bin/python3 score_switch_replay.py REPLAY_ROWS.csv [--out results/switch_replay.json]
    /usr/bin/python3 score_switch_replay.py --self-test      # uses the offline 'profile' emulation as stand-in
"""
import argparse
import csv
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import common as C  # noqa: E402
from compute_oof import _fit_stream_models, _predict_stream  # noqa: E402

D = {}


def read_replay(path, rows, net_cols):
    ids = {r["execution_id"]: i for i, r in enumerate(rows)}
    X = C.matrix(rows, net_cols)
    replayed = np.zeros(len(rows), bool)
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            i = ids.get(r["execution_id"])
            if i is None:
                raise SystemExit("unknown execution_id %r" % r["execution_id"])
            if replayed[i]:
                raise SystemExit("execution_id %r replayed twice" % r["execution_id"])
            X[i] = [float(r[c]) for c in net_cols]
            replayed[i] = True
    return X, replayed


def cv_job(seed):
    y, g, Xh, Xm, Xs = D["y"], D["g"], D["Xh"], D["Xm"], D["Xs"]
    pm = {d: np.zeros(len(y)) for d in C.DETECTORS}
    ps = {d: np.zeros(len(y)) for d in C.DETECTORS}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        models = _fit_stream_models(Xh, Xm, y, g, tr)
        for d, p in _predict_stream(models, Xh[te], Xm[te]).items():
            pm[d][te] = p
        for d, p in _predict_stream(models, Xh[te], Xs[te]).items():
            ps[d][te] = p
    return seed, pm, ps


def score(path, out_path):
    rows, hc, nc = C.load()
    y, g = C.labels(rows), C.groups_published(rows)
    Xm = C.matrix(rows, nc)
    Xs, replayed = read_replay(path, rows, nc)
    cats = np.asarray([r["category"] for r in rows])
    rel = np.abs(Xs - Xm) / np.maximum(1.0, np.abs(Xm))
    out = {"replayed_rows": int(replayed.sum()),
           "replayed_by_category": {c: int(replayed[cats == c].sum()) for c in sorted(set(cats))},
           "feature_agreement": {}, "table_v": {}, "table_iv": {}}
    for j, c in enumerate(nc):
        v = rel[replayed, j]
        if v.size and v.max() > 1e-9:
            out["feature_agreement"][c] = {"rows_differing": int((v > 1e-9).sum()), "max_rel": round(float(v.max()), 4),
                                           "median_rel_differing": round(float(np.median(v[v > 1e-9])), 4)}
    D.update(y=y, g=g, Xh=C.matrix(rows, hc), Xm=Xm, Xs=Xs)
    with Pool(10) as p:
        res = p.map(cv_job, C.FOLD_SEEDS, chunksize=1)
    for d in C.DETECTORS:
        bm = [C.metrics(y, r[1][d])["balanced_accuracy"] for r in res]
        bs = [C.metrics(y, r[2][d])["balanced_accuracy"] for r in res]
        flips = [int(((r[1][d] >= .5) != (r[2][d] >= .5)).sum()) for r in res]
        flipped = sorted({rows[i]["execution_id"] for r in res for i in np.flatnonzero((r[1][d] >= .5) != (r[2][d] >= .5))})
        out["table_v"][d] = {"ba_model": round(float(np.mean(bm)), 4), "ba_switch": round(float(np.mean(bs)), 4),
                             "flips_per_assignment_mean": round(float(np.mean(flips)), 2), "rows_ever_flipped": flipped}
    gen = np.asarray([r["category"] in ("malware", "benign") for r in rows])
    split = np.asarray([r["split"] for r in rows])
    tr, te = np.flatnonzero(gen & (split == "train")), np.flatnonzero(gen & (split == "test"))
    models = _fit_stream_models(D["Xh"], Xm, y, g, tr)
    a, b = _predict_stream(models, D["Xh"][te], Xm[te]), _predict_stream(models, D["Xh"][te], Xs[te])
    for d in C.DETECTORS:
        out["table_iv"][d] = {"ba_model": round(C.metrics(y[te], a[d])["balanced_accuracy"], 4),
                              "ba_switch": round(C.metrics(y[te], b[d])["balanced_accuracy"], 4),
                              "flips": int(((a[d] >= .5) != (b[d] >= .5)).sum())}
    C.write_json(out_path, out)
    return out


def self_test():
    """Write the offline 'profile' emulation of the replayable rows as if PC1 had sent it, and score it."""
    rows, hc, nc = C.load()
    prof = np.load(C.CACHE / "switchgap_features.npz")["profile"]
    pk = C.matrix(rows, ["net_pkts_total_delta__sum"])[:, 0]
    with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, newline="") as f:
        w = csv.writer(f)
        w.writerow(["execution_id", *nc])
        for i, r in enumerate(rows):
            if pk[i] > 0:
                w.writerow([r["execution_id"], *prof[i]])
        path = f.name
    out = score(path, C.HERE / "results" / "switch_replay_selftest.json")
    ref = __import__("json").load(open(C.HERE / "results" / "switch_gap.json"))["detection_table_v"]["profile"]
    for d in C.DETECTORS:
        assert abs(out["table_v"][d]["ba_switch"] - ref[d]["ba_mean"]) < 1e-3, (d, out["table_v"][d], ref[d])
    print("self-test passed: %d rows replayed (stand-in), Table V stacked %.4f -> %.4f"
          % (out["replayed_rows"], out["table_v"]["stacked"]["ba_model"], out["table_v"]["stacked"]["ba_switch"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rows", nargs="?")
    ap.add_argument("--out", default=str(C.HERE / "results" / "switch_replay.json"))
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.rows:
        ap.error("give REPLAY_ROWS.csv or --self-test")
    out = score(a.rows, a.out)
    print("replayed %d rows; Table V stacked %.4f (model) vs %.4f (switch)"
          % (out["replayed_rows"], out["table_v"]["stacked"]["ba_model"], out["table_v"]["stacked"]["ba_switch"]))


if __name__ == "__main__":
    main()
