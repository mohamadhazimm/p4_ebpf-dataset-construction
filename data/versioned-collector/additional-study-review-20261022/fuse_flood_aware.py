"""Flood-AWARE network head: does training on floods let P4/hybrid detect floods, and GENERALIZE across
flood shapes? ADFA-90 host, P4-145 net, hybrid = learned stacked late-fusion (LogisticRegression on grouped-OOF).

Base training always includes: revision5 train + one network-benign per shape (precision).
Two measurements over the diverse .21 flood captures (accepted only):
  (1) LOSO  - leave-one-flood-SHAPE-out: train on the other 3 shapes' floods, hold out the 4th shape entirely
              -> cross-shape generalization (catch an UNSEEN flood shape?).
  (2) WITHIN - train on ~half of each shape, hold out the rest -> upper bound when the shape IS represented.
Both also score revision5 validation + held-out network-benign + null for the full confusion.
Exploratory; no model promotion, no merge.  Usage: python3 fuse_flood_aware.py <diverse-attempt-dir>
"""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_v21 as base          # noqa: E402
import analyze_revision5 as rev5    # noqa: E402
import score_flood21 as sf          # noqa: E402
from sklearn.linear_model import LogisticRegression          # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold     # noqa: E402

ADFA = ROOT.parents[2] / "data/benign/revision3/labeled_sample_dataset.feature_columns.adfa-host.json"
AUG_BENIGN = ["bulkup_200", "session_300", "beacon_50", "dns_2k"]
HELD_BENIGN = ["bulkup_400", "bulkup_700", "session_600", "session_1000", "beacon_100", "dns_5k", "dns_10k"]
HELD_NULL = ["null1", "null2"]
SHAPES = {"syn": ["syn_fan_40k", "syn_fan_100k", "syn_fan_150k", "syn_sink_40k", "syn_sink_100k", "syn_sink_150k"],
          "udp": ["udp_fan_60k", "udp_fan_150k", "udp_fan_250k", "udp_sink_60k", "udp_sink_150k", "udp_sink_250k"],
          "slowloris": ["slowloris_128", "slowloris_256", "slowloris_512"],
          "http": ["httpflood_5k", "httpflood_10k", "httpflood_20k"]}

G = {}  # globals filled in main


def mat(rows, names):
    return G["np"].asarray([[float(r[name]) for name in names] for r in rows], dtype=float)


def fit_eval(training, held):
    np, trainer, host, P4 = G["np"], G["trainer"], G["host"], G["P4"]

    def rf():
        return trainer.random_forest()
    y = np.asarray([r["label"] for r in training]); groups = [r["group_id"] for r in training]
    hf = rf().fit(mat(training, host), y); pf = rf().fit(mat(training, P4), y)
    Xh = mat(training, host); Xp = mat(training, P4)
    oh = np.zeros(len(training)); op = np.zeros(len(training))
    for tr, va in StratifiedGroupKFold(5, shuffle=True, random_state=42).split(Xh, y, groups):
        oh[va] = rf().fit(Xh[tr], y[tr]).predict_proba(Xh[va])[:, 1]
        op[va] = rf().fit(Xp[tr], y[tr]).predict_proba(Xp[va])[:, 1]
    meta = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([oh, op]), y)
    hp = hf.predict_proba(mat(held, host))[:, 1]; pp = pf.predict_proba(mat(held, P4))[:, 1]
    yp = meta.predict_proba(np.column_stack([hp, pp]))[:, 1]
    return hp, pp, yp, (float(meta.coef_[0][0]), float(meta.coef_[0][1]))


def recall_on(held, hp, pp, yp):
    import numpy as np
    t = np.asarray([r["label"] for r in held])
    idx = [i for i, r in enumerate(held) if r["label"] == 1 and r.get("stratum", "").startswith("flood")]
    n = len(idx)
    return {m: (sum((v[i] >= .5) for i in idx), n) for m, v in (("host", hp), ("p4", pp), ("hybrid", yp))}


def main():
    att = Path(sys.argv[1])
    base.V21_ATTEMPT = rev5.ATTEMPT
    base.CASES_ORDER = rev5.ATTEMPT / "payload/cases.json"
    base.case_metadata = rev5.case_metadata
    base.HOST_CONTRACT = str(ADFA)
    trainer, data, _ = base.frozen.dependencies()
    import numpy as np
    records, host, *_ = base.prepare(trainer, data)
    assert len(host) == 90
    P4 = list(data.p4.P4_SAMPLE_FEATURES)
    host_signals = {n.removeprefix("host__").rsplit("__", 1)[0] for n in host}
    G.update(np=np, trainer=trainer, host=host, P4=P4)

    rc = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
    tr_idx, va_idx = trainer.split_indices(rc)
    rev5_train = [rc[i] for i in tr_idx]
    rev5_val = [rc[i] for i in va_idx]
    for r in rev5_val:
        r["stratum"] = "general_malware" if r["label"] == 1 else "cli_benign"

    def rec(name, label, stratum):
        r = sf.build_record(att / "runs" / (name + ".zip"), name, label, host, host_signals, trainer, data)
        r["stratum"] = stratum
        if r.get("quality") != "accepted" or r.get("p4_parity") != "True":
            return None
        return r

    aug = [x for x in (rec(n, 0, "net_benign") for n in AUG_BENIGN) if x]
    held_benign = [x for x in (rec(n, 0, "net_benign") for n in HELD_BENIGN) if x] + \
                  [x for x in (rec(n, 0, "null") for n in HELD_NULL) if x]
    floods = {s: [x for x in (rec(n, 1, "flood_" + s) for n in names) if x] for s, names in SHAPES.items()}
    print("accepted floods per shape:", {s: len(v) for s, v in floods.items()})

    out = {"loso": {}, "within": {}}
    base_train = rev5_train + aug

    # (1) LOSO: hold out each flood shape entirely
    print("\n=== (1) LEAVE-ONE-FLOOD-SHAPE-OUT (cross-shape generalization) ===")
    print("  held-out shape   n   host    p4      hybrid   (recall on the unseen shape)")
    for s in SHAPES:
        train_floods = [r for o in SHAPES if o != s for r in floods[o]]
        held = rev5_val + floods[s] + held_benign
        hp, pp, yp, coef = fit_eval(base_train + train_floods, held)
        rc_ = recall_on(held, hp, pp, yp)
        print("  %-14s %3d   %d/%-4d %d/%-4d %d/%-4d  (meta p4=%.2f)" %
              (s, len(floods[s]), rc_["host"][0], rc_["host"][1], rc_["p4"][0], rc_["p4"][1],
               rc_["hybrid"][0], rc_["hybrid"][1], coef[1]))
        out["loso"][s] = {m: "%d/%d" % rc_[m] for m in rc_}

    # (2) WITHIN-distribution: train on first half of each shape, hold out the rest
    tr_fl, te_fl = [], []
    for s, v in floods.items():
        k = max(1, len(v) // 2)
        tr_fl += v[:k]; te_fl += v[k:]
    held = rev5_val + te_fl + held_benign
    hp, pp, yp, coef = fit_eval(base_train + tr_fl, held)
    t = np.asarray([r["label"] for r in held])
    pred = {"host": (hp >= .5).astype(int), "p4": (pp >= .5).astype(int), "hybrid": (yp >= .5).astype(int)}

    def conf(p):
        tp = int(((p == 1) & (t == 1)).sum()); fn = int(((p == 0) & (t == 1)).sum())
        tn = int(((p == 0) & (t == 0)).sum()); fp = int(((p == 1) & (t == 0)).sum())
        r_ = tp / (tp + fn) if tp + fn else 0.0; s_ = tn / (tn + fp) if tn + fp else 0.0
        return tp, fp, fn, tn, r_, s_, (r_ + s_) / 2
    print("\n=== (2) WITHIN-DISTRIBUTION flood-aware (train %d floods, hold out %d) meta p4=%.2f ===" %
          (len(tr_fl), len(te_fl), coef[1]))
    print("  model   TP FP FN TN  recall  spec    BA")
    for m in ("host", "p4", "hybrid"):
        tp, fp, fn, tn, r_, s_, ba = conf(pred[m])
        print("  %-6s  %2d %2d %2d %2d  %.3f   %.3f   %.3f" % (m, tp, fp, fn, tn, r_, s_, ba))
        out["within"][m] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": round(r_, 3),
                            "specificity": round(s_, 3), "BA": round(ba, 3)}
    # per held-out flood shape recall in the within-dist fit
    print("  held-out flood recall by shape:")
    for s in SHAPES:
        idx = [i for i, r in enumerate(held) if r.get("stratum") == "flood_" + s]
        if idx:
            print("    %-10s p4=%d/%d  hybrid=%d/%d" %
                  (s, sum(pred["p4"][i] for i in idx), len(idx), sum(pred["hybrid"][i] for i in idx), len(idx)))
    (att / "adfa_flood_aware.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", att / "adfa_flood_aware.json")


if __name__ == "__main__":
    main()
