"""COMPREHENSIVE scoring across EVERYTHING captured in the .21 collector: all revision5 general malware,
all diverse flood shapes (SYN/UDP/slowloris/HTTP), and all benign (CLI tools + network-active + null).

Every case scored exactly once by grouped cross-validation (StratifiedGroupKFold, 5 folds):
  - general malware : family-held-out
  - CLI / net benign : project/shape-held-out
  - floods           : instance-held-out (flood SHAPES represented in training = realistic flood-aware detector)
Models: host-90 RF, P4-145 RF, hybrid = LEARNED stacked late-fusion (nested: meta trained on inner grouped-OOF
of each outer training fold -> no leakage). ADFA-90 host contract.

Reports per model: accuracy / recall(attack) / specificity / precision / F1 / balanced-accuracy over the full pool,
a per-attack-class recall table, and complementarity (hybrid recovers host's and P4's misses).
Exploratory; no model promotion, no merge.  Usage: python3 score_all_21.py <diverse-attempt-dir>
"""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_v21 as base          # noqa: E402
import analyze_revision5 as rev5    # noqa: E402
import score_flood21 as sf          # noqa: E402
import numpy as np                  # noqa: E402
from sklearn.linear_model import LogisticRegression          # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold     # noqa: E402

ADFA = ROOT.parents[2] / "data/benign/revision3/labeled_sample_dataset.feature_columns.adfa-host.json"
BENIGN_NET = ["bulkup_200", "bulkup_400", "bulkup_700", "session_300", "session_600", "session_1000",
              "beacon_50", "beacon_100", "dns_2k", "dns_5k", "dns_10k"]
NULLS = ["null1", "null2"]
SHAPES = {"syn": ["syn_fan_40k", "syn_fan_100k", "syn_fan_150k", "syn_sink_40k", "syn_sink_100k", "syn_sink_150k"],
          "udp": ["udp_fan_60k", "udp_fan_150k", "udp_fan_250k", "udp_sink_60k", "udp_sink_150k", "udp_sink_250k"],
          "slowloris": ["slowloris_128", "slowloris_256", "slowloris_512"],
          "http": ["httpflood_5k", "httpflood_10k", "httpflood_20k"]}


def main():
    att = Path(sys.argv[1])
    base.V21_ATTEMPT = rev5.ATTEMPT
    base.CASES_ORDER = rev5.ATTEMPT / "payload/cases.json"
    base.case_metadata = rev5.case_metadata
    base.HOST_CONTRACT = str(ADFA)
    trainer, data, _ = base.frozen.dependencies()
    records, host, *_ = base.prepare(trainer, data)
    assert len(host) == 90
    P4 = list(data.p4.P4_SAMPLE_FEATURES)
    host_signals = {n.removeprefix("host__").rsplit("__", 1)[0] for n in host}

    pool = []
    for r in records:
        if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True":
            r["stratum"] = "general_malware" if r["label"] == 1 else "cli_benign"
            pool.append(r)

    def add(name, label, stratum, group):
        r = sf.build_record(att / "runs" / (name + ".zip"), name, label, host, host_signals, trainer, data)
        if r.get("quality") != "accepted" or r.get("p4_parity") != "True":
            return
        r["stratum"] = stratum; r["group_id"] = group
        pool.append(r)
    for s, names in SHAPES.items():
        for n in names:
            add(n, 1, "flood_" + s, "flood_" + n)          # instance-held-out
    for n in BENIGN_NET:
        add(n, 0, "net_benign", "netb_" + n.rsplit("_", 1)[0])
    for n in NULLS:
        add(n, 0, "null", "null")

    def mat(rows, names):
        return np.asarray([[float(r[name]) for name in names] for r in rows], dtype=float)

    def rf():
        return trainer.random_forest()
    y = np.asarray([r["label"] for r in pool])
    g = np.asarray([r["group_id"] for r in pool])
    Xh = mat(pool, host); Xp = mat(pool, P4)
    oof = {"host": np.zeros(len(pool)), "p4": np.zeros(len(pool)), "hybrid": np.zeros(len(pool))}

    outer = StratifiedGroupKFold(5, shuffle=True, random_state=42)
    for tr, te in outer.split(Xh, y, g):
        hb = rf().fit(Xh[tr], y[tr]); pb = rf().fit(Xp[tr], y[tr])
        oof["host"][te] = hb.predict_proba(Xh[te])[:, 1]
        oof["p4"][te] = pb.predict_proba(Xp[te])[:, 1]
        # nested inner OOF on the outer-training set to fit the stacking meta
        oh = np.zeros(len(tr)); op = np.zeros(len(tr))
        gi = g[tr]; yi = y[tr]
        inner = StratifiedGroupKFold(min(5, len(set(gi))), shuffle=True, random_state=7)
        for itr, iva in inner.split(Xh[tr], yi, gi):
            oh[iva] = rf().fit(Xh[tr][itr], yi[itr]).predict_proba(Xh[tr][iva])[:, 1]
            op[iva] = rf().fit(Xp[tr][itr], yi[itr]).predict_proba(Xp[tr][iva])[:, 1]
        meta = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([oh, op]), yi)
        oof["hybrid"][te] = meta.predict_proba(np.column_stack([oof["host"][te], oof["p4"][te]]))[:, 1]

    pred = {m: (oof[m] >= .5).astype(int) for m in oof}

    def metrics(p):
        tp = int(((p == 1) & (y == 1)).sum()); fn = int(((p == 0) & (y == 1)).sum())
        tn = int(((p == 0) & (y == 0)).sum()); fp = int(((p == 1) & (y == 0)).sum())
        acc = (tp + tn) / len(y)
        rec = tp / (tp + fn) if tp + fn else 0.0
        spec = tn / (tn + fp) if tn + fp else 0.0
        prec = tp / (tp + fp) if tp + fp else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return dict(tp=tp, fp=fp, fn=fn, tn=tn, accuracy=round(acc, 3), recall=round(rec, 3),
                    specificity=round(spec, 3), precision=round(prec, 3), f1=round(f1, 3), BA=round((rec + spec) / 2, 3))

    n_att = int((y == 1).sum()); n_ben = int((y == 0).sum())
    print("\n=== comprehensive .21 scoring (grouped CV OOF; n=%d: attack=%d, benign=%d) ===" % (len(y), n_att, n_ben))
    out = {"n": len(y), "n_attack": n_att, "n_benign": n_ben, "models": {}, "by_attack_class": {}, "complementarity": {}}
    print("  model   acc    recall  spec   prec   F1     BA   (TP/FP/FN/TN)")
    for m in ("host", "p4", "hybrid"):
        d = metrics(pred[m]); out["models"][m] = d
        print("  %-6s  %.3f  %.3f  %.3f  %.3f  %.3f  %.3f  (%d/%d/%d/%d)" %
              (m, d["accuracy"], d["recall"], d["specificity"], d["precision"], d["f1"], d["BA"],
               d["tp"], d["fp"], d["fn"], d["tn"]))

    print("\n=== recall by attack class (caught / n) ===")
    print("  %-16s n    host     p4       hybrid" % "attack class")
    for st in ["general_malware", "flood_syn", "flood_udp", "flood_slowloris", "flood_http"]:
        idx = [i for i, r in enumerate(pool) if r["stratum"] == st]
        if not idx:
            continue
        a = {m: sum(pred[m][i] for i in idx) for m in pred}
        print("  %-16s %-3d  %d/%-5d %d/%-5d %d/%-5d" % (st, len(idx), a["host"], len(idx), a["p4"], len(idx), a["hybrid"], len(idx)))
        out["by_attack_class"][st] = {"n": len(idx), **{m: "%d/%d" % (a[m], len(idx)) for m in pred}}
    print("\n=== benign specificity by class (correct / n) ===")
    for st in ["cli_benign", "net_benign", "null"]:
        idx = [i for i, r in enumerate(pool) if r["stratum"] == st]
        if not idx:
            continue
        a = {m: sum(pred[m][i] == 0 for i in idx) for m in pred}
        print("  %-16s %-3d  host=%d/%d p4=%d/%d hybrid=%d/%d" % (st, len(idx), a["host"], len(idx), a["p4"], len(idx), a["hybrid"], len(idx)))
        out["by_attack_class"][st] = {"n": len(idx), **{"benign_" + m: "%d/%d" % (a[m], len(idx)) for m in pred}}

    def wrong(m):
        return {i for i in range(len(pool)) if pred[m][i] != y[i]}
    wh, wp, wy = wrong("host"), wrong("p4"), wrong("hybrid")
    out["complementarity"] = {"host_wrong": len(wh), "p4_wrong": len(wp), "hybrid_wrong": len(wy),
                              "hybrid_recovers_host": len(wh - wy), "hybrid_recovers_p4": len(wp - wy),
                              "hybrid_regressions": len(wy - (wh & wp))}
    print("\n=== complementarity ===")
    print("  host wrong=%d  p4 wrong=%d  hybrid wrong=%d" % (len(wh), len(wp), len(wy)))
    print("  hybrid recovers host's misses=%d  recovers p4's misses=%d  regressions=%d" %
          (len(wh - wy), len(wp - wy), len(wy - (wh & wp))))
    (att / "adfa_score_all_21.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", att / "adfa_score_all_21.json")


if __name__ == "__main__":
    main()
