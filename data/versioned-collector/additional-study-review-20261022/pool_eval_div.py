"""Publishable-n pooled held-out evaluation (ADFA-90) over the DIVERSE flow-shape set + revision5.

Training (augmented): revision5 train  +  one network-benign capture per shape (bulkup/session/beacon/dns)
                       so P4 learns "network activity != malware".
Held-out (scored):     revision5 VALIDATION (general malware + CLI benign)
                     +  ALL 18 floods (OOD; never in training) broken out by shape
                     +  remaining network-benign shapes
                     +  nulls
Models: host-90 RF, P4-145 RF, hybrid = LEARNED stacked late-fusion (LogisticRegression on grouped-OOF base probs).
Shows host misses floods, P4 misses network-quiet general malware, hybrid recovers each one's blind spot.
httpflood is reported as its own (handshaked / shape-ambiguous) stratum. Exploratory/OOD; no promotion, no merge.
Usage: python3 pool_eval_div.py <diverse-attempt-dir>
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

# one capture per benign shape into training (teaches P4 that network activity can be benign)
AUG_BENIGN = ["bulkup_200", "session_300", "beacon_50", "dns_2k"]
# held-out benign (remaining shapes + varied volume) + nulls
HELD_BENIGN = ["bulkup_400", "bulkup_700", "session_600", "session_1000", "beacon_100", "dns_5k", "dns_10k"]
HELD_NULL = ["null1", "null2"]
# all floods held out (OOD), tagged by shape
FLOODS = {"flood_syn": ["syn_fan_40k", "syn_fan_100k", "syn_fan_150k", "syn_sink_40k", "syn_sink_100k", "syn_sink_150k"],
          "flood_udp": ["udp_fan_60k", "udp_fan_150k", "udp_fan_250k", "udp_sink_60k", "udp_sink_150k", "udp_sink_250k"],
          "flood_slowloris": ["slowloris_128", "slowloris_256", "slowloris_512"],
          "flood_http": ["httpflood_5k", "httpflood_10k", "httpflood_20k"]}


def main():
    att = Path(sys.argv[1])
    base.V21_ATTEMPT = rev5.ATTEMPT
    base.CASES_ORDER = rev5.ATTEMPT / "payload/cases.json"
    base.case_metadata = rev5.case_metadata
    base.HOST_CONTRACT = str(ADFA)
    trainer, data, _ = base.frozen.dependencies()
    np = trainer.np
    records, host, *_ = base.prepare(trainer, data)
    assert len(host) == 90
    P4 = list(data.p4.P4_SAMPLE_FEATURES)
    host_signals = {n.removeprefix("host__").rsplit("__", 1)[0] for n in host}

    rc = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
    tr_idx, va_idx = trainer.split_indices(rc)
    rev5_train = [rc[i] for i in tr_idx]
    rev5_val = [rc[i] for i in va_idx]
    for r in rev5_val:
        r["stratum"] = "general_malware" if r["label"] == 1 else "cli_benign"

    dropped = []

    def rec(name, label, stratum):
        r = sf.build_record(att / "runs" / (name + ".zip"), name, label, host, host_signals, trainer, data)
        r["stratum"] = stratum
        if r.get("quality") != "accepted":
            dropped.append((name, stratum, "quality=" + str(r.get("quality")), r.get("quality_reasons")))
            return None
        if r.get("p4_parity") != "True":
            dropped.append((name, stratum, r.get("p4_alignment_status"), r.get("windows")))
            return None
        return r

    aug = [x for x in (rec(n, 0, "net_benign") for n in AUG_BENIGN) if x]
    training = rev5_train + aug

    held = list(rev5_val)
    for st, names in FLOODS.items():
        held += [x for x in (rec(n, 1, st) for n in names) if x]
    held += [x for x in (rec(n, 0, "net_benign") for n in HELD_BENIGN) if x]
    held += [x for x in (rec(n, 0, "null") for n in HELD_NULL) if x]

    def mat(rows, names):
        return np.asarray([[float(r[name]) for name in names] for r in rows], dtype=float)

    def rf():
        return trainer.random_forest()

    y = np.asarray([r["label"] for r in training]); groups = [r["group_id"] for r in training]
    host_full = rf().fit(mat(training, host), y)
    p4_full = rf().fit(mat(training, P4), y)
    Xh = mat(training, host); Xp = mat(training, P4)
    oh = np.zeros(len(training)); op = np.zeros(len(training))
    for tr, va in StratifiedGroupKFold(5, shuffle=True, random_state=42).split(Xh, y, groups):
        oh[va] = rf().fit(Xh[tr], y[tr]).predict_proba(Xh[va])[:, 1]
        op[va] = rf().fit(Xp[tr], y[tr]).predict_proba(Xp[va])[:, 1]
    meta = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([oh, op]), y)

    hp = host_full.predict_proba(mat(held, host))[:, 1]
    pp = p4_full.predict_proba(mat(held, P4))[:, 1]
    yp = meta.predict_proba(np.column_stack([hp, pp]))[:, 1]
    truth = np.asarray([r["label"] for r in held])
    pred = {"host": (hp >= .5).astype(int), "p4": (pp >= .5).astype(int), "hybrid": (yp >= .5).astype(int)}

    if dropped:
        print("DROPPED (P4 not aligned):")
        for n, st, status, win in dropped:
            print("   %-14s %-16s %s win=%s" % (n, st, status, win))

    def conf(p):
        tp = int(((p == 1) & (truth == 1)).sum()); fn = int(((p == 0) & (truth == 1)).sum())
        tn = int(((p == 0) & (truth == 0)).sum()); fp = int(((p == 1) & (truth == 0)).sum())
        r_ = tp / (tp + fn) if tp + fn else float("nan"); s_ = tn / (tn + fp) if tn + fp else float("nan")
        return tp, fp, fn, tn, r_, s_, (r_ + s_) / 2

    out = {"n": len(held), "meta_coef": {"host": round(float(meta.coef_[0][0]), 3),
           "p4": round(float(meta.coef_[0][1]), 3), "intercept": round(float(meta.intercept_[0]), 3)},
           "models": {}, "by_stratum": {}, "complementarity": {}}
    print("\n=== pooled held-out (n=%d: attack=%d, benign=%d) | meta host=%.2f p4=%.2f b=%.2f ===" %
          (len(held), int((truth == 1).sum()), int((truth == 0).sum()),
           meta.coef_[0][0], meta.coef_[0][1], meta.intercept_[0]))
    print("  model   TP FP FN TN  recall  spec    BA")
    for m in ("host", "p4", "hybrid"):
        tp, fp, fn, tn, r_, s_, ba = conf(pred[m])
        print("  %-6s  %2d %2d %2d %2d  %.3f   %.3f   %.3f" % (m, tp, fp, fn, tn, r_, s_, ba))
        out["models"][m] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": round(r_, 3),
                            "specificity": round(s_, 3), "BA": round(ba, 3)}

    order = ["general_malware", "flood_syn", "flood_udp", "flood_slowloris", "flood_http", "cli_benign", "net_benign", "null"]
    print("\n=== per-stratum correct/n ===")
    print("  %-16s n   truth   host    p4      hybrid" % "stratum")
    for st in order:
        idx = [i for i, r in enumerate(held) if r["stratum"] == st]
        if not idx:
            continue
        t = "attack" if truth[idx[0]] == 1 else "benign"
        a = {m: sum(pred[m][i] == truth[i] for i in idx) for m in pred}
        print("  %-16s %-3d %-6s  %d/%-4d %d/%-4d %d/%-4d" % (st, len(idx), t, a["host"], len(idx), a["p4"], len(idx), a["hybrid"], len(idx)))
        out["by_stratum"][st] = {"n": len(idx), "truth": t, **{m: "%d/%d" % (a[m], len(idx)) for m in pred}}

    def wrong(m):
        return {i for i in range(len(held)) if pred[m][i] != truth[i]}
    wh, wp, wy = wrong("host"), wrong("p4"), wrong("hybrid")
    out["complementarity"] = {"host_wrong": len(wh), "p4_wrong": len(wp), "hybrid_wrong": len(wy),
                              "hybrid_recovers_host": len(wh - wy), "hybrid_recovers_p4": len(wp - wy),
                              "hybrid_regressions": len(wy - (wh & wp))}
    print("\n=== complementarity ===  host_wrong=%d p4_wrong=%d hybrid_wrong=%d" % (len(wh), len(wp), len(wy)))
    print("  hybrid recovers host's errors: %d   hybrid recovers p4's errors: %d   hybrid regressions: %d" %
          (len(wh - wy), len(wp - wy), len(wy - (wh & wp))))
    (att / "adfa_pool_eval_diverse.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", att / "adfa_pool_eval_diverse.json")


if __name__ == "__main__":
    main()
