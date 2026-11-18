"""Pairwise comparison of every baseline with the thesis detectors on identical rows and folds.

1. Reproduces the thesis detectors with the verified loader (common.cv_all / common.fit_predict, unchanged) and
   checks the published numbers: Table V BA host .784, network .756, stacked .823; Table IV host .929,
   network .750, concat .926 (Table V concat is not published; the loader gives .812, see PUBLISHED5). Their scores are saved in the same format as the baselines (scores/thesis_*).
2. For each baseline: per fold assignment, exact McNemar test of its decisions against the thesis's stacked hybrid,
   host and network detectors (Table V) and, on the held-out split, against the thesis's concatenated hybrid, host,
   network and stacked detectors.

    /usr/bin/python3 compare_thesis.py
"""
import sys

import numpy as np

import bl_common as B

C = B.C
PUBLISHED5 = {"host": 0.784, "network": 0.756, "stacked": 0.823}
# Table V concat is not a published table cell; common.py's concat (host columns first) gives .812, the earlier
# paper-check diagnostic (network columns first, same RF) gave .809: same model up to column order.
PUBLISHED4 = {"host": 0.929, "network": 0.750, "concat": 0.926}


def thesis_scores():
    rows, hc, nc = C.load()
    y, g = C.labels(rows), C.groups_published(rows)
    Xh, Xn = C.matrix(rows, hc), C.matrix(rows, nc)
    cat = np.asarray([r["category"] for r in rows]); split = np.asarray([r["split"] for r in rows])
    F = B.table5_folds(y, g)
    B.check_folds(F, y, g, Xh)
    if not (B.SCORES / "thesis_stacked_table5.npz").exists():
        P, F2 = C.cv_all(Xh, Xn, y, g, detectors=C.DETECTORS, jobs=B.MAX_JOBS)
        assert (F2 == F).all()
        tr, te = B.table4_split(cat, split)
        P4 = C.fit_predict(Xh, Xn, y, g, tr, te, detectors=C.DETECTORS)
        for d in C.DETECTORS:
            B.save_scores("thesis_%s_table5" % d, score=P[d], pred=(P[d] >= 0.5).astype(int), folds=F)
            B.save_scores("thesis_%s_table4" % d, test_index=te, score=P4[d], pred=(P4[d] >= 0.5).astype(int))
    out = {}
    for d in C.DETECTORS:
        z5 = np.load(B.SCORES / ("thesis_%s_table5.npz" % d)); z4 = np.load(B.SCORES / ("thesis_%s_table4.npz" % d))
        v = np.mean([B.binary_metrics(y, z5["pred"][k])["balanced_accuracy"] for k in range(len(C.FOLD_SEEDS))])
        te = z4["test_index"]
        b4 = B.binary_metrics(y[te], z4["pred"])["balanced_accuracy"]
        if d in PUBLISHED5:
            assert round(v, 3) == PUBLISHED5[d], (d, v)
        if d in PUBLISHED4:
            assert round(b4, 3) == PUBLISHED4[d], (d, b4)
        out[d] = {"table5_ba_mean": v, "table4_ba": b4}
    return rows, y, cat, split, out


def main():
    rows, y, cat, split, th = thesis_scores()
    B.log("thesis detectors reproduced", th)
    baselines = sorted(p.name[:-len("_table5.npz")] for p in B.SCORES.glob("*_table5.npz")
                       if not p.name.startswith("thesis_"))
    T5 = {d: np.load(B.SCORES / ("thesis_%s_table5.npz" % d))["pred"] for d in C.DETECTORS}
    T4 = {d: np.load(B.SCORES / ("thesis_%s_table4.npz" % d)) for d in C.DETECTORS}
    res = {"thesis": th, "baselines": {}}
    for b in baselines:
        z5 = np.load(B.SCORES / ("%s_table5.npz" % b)); z4 = np.load(B.SCORES / ("%s_table4.npz" % b))
        entry = {"table5_vs_thesis_stacked": [], "table5_vs_thesis_host": [], "table5_vs_thesis_network": [],
                 "table4": {}}
        for k in range(len(C.FOLD_SEEDS)):
            for d in ("stacked", "host", "network"):
                m = C.mcnemar_exact(y, z5["pred"][k], T5[d][k])
                m["delta_ba"] = float(B.binary_metrics(y, z5["pred"][k])["balanced_accuracy"]
                                      - B.binary_metrics(y, T5[d][k])["balanced_accuracy"])
                entry["table5_vs_thesis_" + d].append(m)
        te = z4["test_index"]
        for d in ("concat", "host", "network", "stacked"):
            assert (T4[d]["test_index"] == te).all()
            m = C.mcnemar_exact(y[te], z4["pred"], T4[d]["pred"])
            m["delta_ba"] = float(B.binary_metrics(y[te], z4["pred"])["balanced_accuracy"]
                                  - B.binary_metrics(y[te], T4[d]["pred"])["balanced_accuracy"])
            entry["table4"]["vs_thesis_" + d] = m
        def summ(lst):
            ps = [m["p"] for m in lst]
            db = [m["delta_ba"] for m in lst]
            return {"delta_ba_mean": float(np.mean(db)), "delta_ba_min": float(np.min(db)),
                    "delta_ba_max": float(np.max(db)),
                    "assignments_baseline_better_p05": int(sum(1 for m in lst if m["p"] < 0.05
                                                             and m["only_a_correct"] > m["only_b_correct"])),
                    "assignments_thesis_better_p05": int(sum(1 for m in lst if m["p"] < 0.05
                                                           and m["only_a_correct"] < m["only_b_correct"])),
                    "median_p": float(np.median(ps))}
        entry["table5_summary"] = summ(entry["table5_vs_thesis_stacked"])
        entry["table5_summary_vs_host"] = summ(entry["table5_vs_thesis_host"])
        entry["table5_summary_vs_network"] = summ(entry["table5_vs_thesis_network"])
        res["baselines"][b] = entry
        s = entry["table5_summary"]; t = entry["table4"]["vs_thesis_concat"]
        B.log("%-28s V dBA vs stacked %+.3f (better p<.05 in %d, worse in %d) | IV vs concat dBA %+.3f p %.3f" % (
            b, s["delta_ba_mean"], s["assignments_baseline_better_p05"], s["assignments_thesis_better_p05"],
            t["delta_ba"], t["p"]))
    B.write_json(B.RESULTS / "compare_thesis.json", res)


if __name__ == "__main__":
    sys.exit(main())
