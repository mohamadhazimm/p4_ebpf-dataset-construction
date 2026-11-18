"""Time-aware split of the 99 general malware samples (committee item 3: temporal split). Offline.

Malware is split by its MalwareBazaar first-seen date: older samples train, newer samples test. The 105 benign
workloads keep their Table IV split (they have no meaningful date), so the only change from Table IV is how the
malware is assigned: by time instead of by family. Same rows, features, detectors and forest settings as Table IV.

Dates: mb.first_seen from the threat-intel lookup of 2026-11-13 (sample-intel-20261113/intel99-paper-dataset-
20261113.json), read here offline; nothing is downloaded. 91 of the 99 samples have a date; the 8 without one
(collected from Triage, unknown to MalwareBazaar) are left out of every split below, so no sample of unknown age
can sit in training.

The protocol (results/temporal_protocol.json) is written before any model is trained and is never overwritten.

    /usr/bin/python3 temporal/temporal_split.py [--jobs 10]
"""
import argparse
import hashlib
import importlib.util
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as C  # noqa: E402  (committee loader and models)

INTEL = C.STUDY / "sample-intel-20261113" / "intel99-paper-dataset-20261113.json"
RIGOR = HERE.parent / "results" / "rigor.json"
OUT = HERE.parent / "results" / "temporal_split.json"
PROTOCOL = HERE.parent / "results" / "temporal_protocol.json"
RF_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
TEST_FRACTIONS = {"temporal_26": 26 / 99, "temporal_20": 0.20, "temporal_33": 1 / 3, "temporal_40": 0.40}
PRIMARY = "temporal_26"
RANDOM_DRAWS = list(range(10))
N_BOOT = 2000
GATE = 0.75
MATERIAL_DROP = 0.05

D = {}  # filled in main, read by forked workers


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def release_heldout():
    """The release's evaluation/heldout.py (artifact baselines), imported with the release's own common.py."""
    rc = load_module("release_common", C.RELEASE / "evaluation" / "common.py")
    saved = sys.modules.get("common")
    sys.modules["common"] = rc
    try:
        rh = load_module("release_heldout", C.RELEASE / "evaluation" / "heldout.py")
    finally:
        sys.modules["common"] = saved
    return rh


def write_protocol():
    if PROTOCOL.exists():
        sys.exit("protocol exists, refusing to overwrite: %s" % PROTOCOL)
    proto = {
        "written_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Temporal split requested by the thesis committee: train on older malware, test on newer.",
        "inspected_before_writing": "Only the first-seen dates by family and month and their coverage (91 of 99); "
                                    "no model had been trained on any temporal split.",
        "rows": "The 204 general rows of the release features.csv (99 malware, 105 benign); attack runs excluded, "
                "as in Table IV.",
        "dates": "MalwareBazaar first_seen of each malware SHA-256 from the 2026-11-13 intel lookup. The 8 malware "
                 "without a date are excluded from every split (they could be newer than the cutoff).",
        "benign": "Table IV split unchanged (77 train, 28 test; benign projects held out).",
        "primary_split": "Malware sorted by first_seen; test = the latest 24 of the 91 dated samples (24/91 = the "
                         "Table IV malware test fraction 26/99). Cutoff = first_seen of the 24th-latest sample; "
                         "samples with the same first_seen as the cutoff go to test.",
        "sensitivity_splits": "Same rule with test fractions 0.20, 1/3, 0.40.",
        "comparators": ["Table IV split on all 204 rows (reproduction check: must equal rigor.json at forest seed 42)",
                        "Table IV split with the 8 undated malware removed (family-held-out on the same 91 dated "
                        "malware: the direct comparator of the temporal split)",
                        "10 random malware splits of the 91 dated samples with the primary split's test size, "
                        "benign as Table IV (in-distribution reference), forest seed 42"],
        "detectors": "host (90), network (145), concat (235, the Table IV hybrid), stacked (logistic regression on "
                     "inner grouped out-of-fold probabilities, inner seed 7); RF500 balanced; threshold 0.5",
        "forest_seeds": RF_SEEDS,
        "baselines": "metadata, activity, mode (release evaluation/heldout.py code) on every temporal split; "
                     "if any reaches %.2f balanced accuracy on the primary split the temporal result is not "
                     "credited to detection" % GATE,
        "reading": ["Per detector: balanced accuracy on the primary temporal split minus the family-held-out split "
                    "on the same 91 dated malware, mean over the 11 forest seeds; a drop of %.2f or more is called "
                    "material." % MATERIAL_DROP,
                    "Hybrid edge: concat - host and stacked - host on the primary split, mean over 11 forest seeds "
                    "and the number of seeds with a positive difference; cluster-bootstrap 95%% interval "
                    "(%d resamples of whole groups within class) at forest seed 42." % N_BOOT,
                    "Per-family recall on the primary test set, split into families seen and not seen in its "
                    "training set."],
        "inputs_sha256": {"features.csv": sha256(C.FEATURES), "intel99": sha256(INTEL), "committee_common.py":
                          sha256(HERE.parent / "common.py"), "release_evaluation_common.py":
                          sha256(C.RELEASE / "evaluation" / "common.py"), "release_evaluation_heldout.py":
                          sha256(C.RELEASE / "evaluation" / "heldout.py"), "rigor.json": sha256(RIGOR),
                          "temporal_split.py": sha256(__file__)},
    }
    PROTOCOL.parent.mkdir(parents=True, exist_ok=True)
    with open(PROTOCOL, "x") as f:
        json.dump(proto, f, indent=1)
    return proto


def job(args):
    name, seed = args
    tr, te = D["splits"][name]
    return name, seed, C.fit_predict(D["Xh"], D["Xn"], D["y"], D["g"], tr, te, seed)


def summary(values):
    a = np.asarray(values, dtype=float)
    return {"mean": float(a.mean()), "sd": float(a.std(ddof=1)) if len(a) > 1 else 0.0,
            "min": float(a.min()), "max": float(a.max())}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=10)
    args = ap.parse_args()
    t0 = time.time()
    proto = write_protocol()

    rows, hcols, ncols = C.load()
    R = [r for r in rows if r["category"] in ("malware", "benign")]
    assert len(R) == 204
    Xh, Xn, y, g = C.matrix(R, hcols), C.matrix(R, ncols), C.labels(R), C.groups_published(R)
    split = np.asarray([r["split"] for r in R])
    intel = json.loads(INTEL.read_text())
    first = [None] * len(R)
    for i, r in enumerate(R):
        if y[i] == 1:
            v = (intel.get(r["sha256"], {}).get("mb") or {}).get("first_seen")
            first[i] = datetime.strptime(v, "%Y-%m-%d %H:%M:%S") if v else None
    mal = np.flatnonzero(y == 1)
    dated = np.asarray([i for i in mal if first[i] is not None])
    undated = np.asarray([i for i in mal if first[i] is None])
    assert len(mal) == 99 and len(dated) == 91 and len(undated) == 8
    ben_tr = np.flatnonzero((y == 0) & (split == "train"))
    ben_te = np.flatnonzero((y == 0) & (split == "test"))
    assert len(ben_tr) == 77 and len(ben_te) == 28

    order = sorted(dated, key=lambda i: (first[i], R[i]["sha256"]))
    splits, cut = {}, {}
    splits["table_iv_all"] = (np.flatnonzero(split == "train"), np.flatnonzero(split == "test"))
    keep = set(dated) | set(np.flatnonzero(y == 0))
    splits["table_iv_dated"] = tuple(np.asarray([i for i in s if i in keep]) for s in splits["table_iv_all"])
    for name, frac in TEST_FRACTIONS.items():
        m = int(round(frac * len(dated)))
        c = first[order[-m]]
        te_m = [i for i in order if first[i] >= c]
        tr_m = [i for i in order if first[i] < c]
        cut[name] = {"cutoff_first_seen": c.isoformat(sep=" "), "test_malware": len(te_m), "train_malware": len(tr_m),
                     "train_first_seen_range": [first[tr_m[0]].isoformat(sep=" "), first[tr_m[-1]].isoformat(sep=" ")],
                     "test_first_seen_range": [first[te_m[0]].isoformat(sep=" "), first[te_m[-1]].isoformat(sep=" ")]}
        splits[name] = (np.sort(np.concatenate([tr_m, ben_tr])), np.sort(np.concatenate([te_m, ben_te])))
    m_primary = cut[PRIMARY]["test_malware"]
    for s in RANDOM_DRAWS:
        te_m = np.random.default_rng(s).choice(dated, size=m_primary, replace=False)
        tr_m = np.setdiff1d(dated, te_m)
        splits["random_%d" % s] = (np.sort(np.concatenate([tr_m, ben_tr])), np.sort(np.concatenate([te_m, ben_te])))
    for name, (tr, te) in splits.items():
        assert not set(tr) & set(te) and set(y[tr]) == {0, 1} and set(y[te]) == {0, 1}, name

    D.update(Xh=Xh, Xn=Xn, y=y, g=g, splits=splits)
    jobs = [(n, s) for n in splits if not n.startswith("random_") for s in RF_SEEDS]
    jobs += [("random_%d" % s, 42) for s in RANDOM_DRAWS]
    with Pool(args.jobs) as p:
        res = p.map(job, jobs)
    P = defaultdict(dict)
    for name, seed, probs in res:
        P[name][seed] = probs

    # reproduction check against the saved Table IV results (forest seed 42)
    rig = json.loads(RIGOR.read_text())["A_table_iv"]["rf42"]
    te_all = splits["table_iv_all"][1]
    for d in C.DETECTORS:
        m = C.metrics(y[te_all], P["table_iv_all"][42][d])
        want = {k: rig[d][k] for k in ("tn", "fp", "fn", "tp")}
        assert {k: m[k] for k in want} == want, (d, m, want)
        assert abs(m["balanced_accuracy"] - rig[d]["balanced_accuracy"]) < 1e-12, d

    def per_split(name):
        tr, te = splits[name]
        yt = y[te]
        out = {"train": {"malware": int(y[tr].sum()), "benign": int((y[tr] == 0).sum())},
               "test": {"malware": int(yt.sum()), "benign": int((yt == 0).sum())}, "detectors": {}}
        for d in C.DETECTORS:
            m42 = C.metrics(yt, P[name][42][d])
            per = [C.metrics(yt, P[name][s][d]) for s in RF_SEEDS if s in P[name]]
            out["detectors"][d] = {"rf42": m42, "ba_over_forest_seeds": summary([x["balanced_accuracy"] for x in per]),
                                   "auc_over_forest_seeds": summary([x["auc"] for x in per]),
                                   "recall_over_forest_seeds": summary([x["recall"] for x in per]),
                                   "specificity_over_forest_seeds": summary([x["specificity"] for x in per])}
        paired = {}
        for a in ("concat", "stacked"):
            diffs = [C.metrics(yt, P[name][s][a])["balanced_accuracy"] - C.metrics(yt, P[name][s]["host"])["balanced_accuracy"]
                     for s in RF_SEEDS if s in P[name]]
            paired["%s_minus_host" % a] = {"ba_diff": summary(diffs), "positive": int(sum(x > 1e-12 for x in diffs)),
                                           "negative": int(sum(x < -1e-12 for x in diffs)),
                                           "mcnemar_rf42": C.mcnemar_exact(yt, (P[name][42][a] >= .5).astype(int),
                                                                           (P[name][42]["host"] >= .5).astype(int))}
        out["paired"] = paired
        return out

    result = {"protocol_written_utc": proto["written_utc"], "runtime_s": None, "cutoffs": cut,
              "reproduction_check": "table_iv_all at forest seed 42 equals rigor.json for all four detectors",
              "undated_excluded": [{"sha256": R[i]["sha256"], "family": R[i]["family"], "source": R[i]["source"],
                                    "table_iv_split": R[i]["split"]} for i in undated],
              "splits": {n: per_split(n) for n in splits if not n.startswith("random_")}}

    # random in-distribution reference (forest seed 42, 10 draws)
    rnd = {d: [C.metrics(y[splits["random_%d" % s][1]], P["random_%d" % s][42][d]) for s in RANDOM_DRAWS]
           for d in C.DETECTORS}
    result["random_dated_reference"] = {
        "test_malware": m_primary, "draws": len(RANDOM_DRAWS),
        "detectors": {d: {"ba": summary([x["balanced_accuracy"] for x in v]), "auc": summary([x["auc"] for x in v])}
                      for d, v in rnd.items()}}

    # reading 1: temporal minus family-held-out on the same 91 dated malware (mean over forest seeds)
    comp = {}
    for name in TEST_FRACTIONS:
        comp[name] = {}
        for d in C.DETECTORS:
            t = [C.metrics(y[splits[name][1]], P[name][s][d])["balanced_accuracy"] for s in RF_SEEDS]
            f = [C.metrics(y[splits["table_iv_dated"][1]], P["table_iv_dated"][s][d])["balanced_accuracy"] for s in RF_SEEDS]
            diff = float(np.mean(t) - np.mean(f))
            comp[name][d] = {"temporal_ba_mean": float(np.mean(t)), "family_heldout_dated_ba_mean": float(np.mean(f)),
                             "difference": diff, "material_drop": diff <= -MATERIAL_DROP}
    result["temporal_vs_family_heldout"] = comp

    # baselines (release heldout.py code, its own forest seed 42)
    rh = release_heldout()
    base = rh.baseline_inputs(R)
    bl = {}
    for name in list(TEST_FRACTIONS) + ["table_iv_dated", "table_iv_all"]:
        tr, te = splits[name]
        bl[name] = {}
        for b in ("metadata", "activity", "mode"):
            data = base[b]
            pick = (lambda idx: data[idx]) if b == "activity" else (lambda idx: [data[i] for i in idx])
            bl[name][b] = C.metrics(y[te], rh.fit_baseline(b, pick(tr), pick(te), y[tr]))["balanced_accuracy"]
    result["baselines_ba"] = bl
    result["baseline_gate_triggered_primary"] = any(v >= GATE for v in bl[PRIMARY].values())

    # reading 2: cluster bootstrap on the primary split at forest seed 42
    tr, te = splits[PRIMARY]
    yt, gt = y[te], g[te]
    pred = {d: (P[PRIMARY][42][d] >= .5).astype(int) for d in C.DETECTORS}
    boots = defaultdict(list)
    for idx in C.cluster_bootstrap_indices(yt, gt, N_BOOT, seed=0):
        b = {d: C.ba(yt[idx], pred[d][idx]) for d in C.DETECTORS}
        for d in C.DETECTORS:
            boots[d].append(b[d])
        boots["concat_minus_host"].append(b["concat"] - b["host"])
        boots["stacked_minus_host"].append(b["stacked"] - b["host"])
    result["bootstrap_primary_rf42"] = {k: {"ci95": [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))],
                                            "p_gt0": float(np.mean(np.asarray(v) > 0))} for k, v in boots.items()}

    # reading 3: per-family recall on the primary test set
    train_fams = {R[i]["family"] for i in tr if y[i] == 1}
    fam = defaultdict(list)
    for j, i in enumerate(te):
        if y[i] == 1:
            fam[R[i]["family"]].append(j)
    pf = {}
    for f, js in sorted(fam.items()):
        pf[f] = {"n": len(js), "seen_in_training": f in train_fams,
                 "first_seen": [min(first[te[j]] for j in js).isoformat(sep=" "), max(first[te[j]] for j in js).isoformat(sep=" ")],
                 "recall_rf42": {d: float(pred[d][js].mean()) for d in C.DETECTORS},
                 "recall_mean_forest_seeds": {d: float(np.mean([(P[PRIMARY][s][d][js] >= .5).mean() for s in RF_SEEDS]))
                                              for d in C.DETECTORS}}
    result["primary_test_families"] = pf
    seen = [j for f, v in pf.items() if v["seen_in_training"] for j in fam[f]]
    new = [j for f, v in pf.items() if not v["seen_in_training"] for j in fam[f]]
    result["primary_seen_vs_new_families"] = {
        "seen": {"n": len(seen), "recall_mean_forest_seeds": {d: float(np.mean([(P[PRIMARY][s][d][seen] >= .5).mean() for s in RF_SEEDS])) for d in C.DETECTORS}},
        "new": {"n": len(new), "families": sorted(f for f, v in pf.items() if not v["seen_in_training"]),
                "recall_mean_forest_seeds": {d: float(np.mean([(P[PRIMARY][s][d][new] >= .5).mean() for s in RF_SEEDS])) for d in C.DETECTORS} if new else None}}
    result["primary_mode_counts"] = {
        "train_malware": dict(Counter(R[i]["mode"] for i in tr if y[i] == 1)),
        "test_malware": dict(Counter(R[i]["mode"] for i in te if y[i] == 1))}
    result["runtime_s"] = round(time.time() - t0, 1)
    C.write_json(OUT, result)
    print("wrote", OUT, "in", result["runtime_s"], "s")


if __name__ == "__main__":
    main()
