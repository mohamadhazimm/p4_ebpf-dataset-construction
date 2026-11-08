"""Balanced comprehensive scoring (ADFA-90) across all .21 attacks, with class-balanced reporting so the
99 general malware (host's regime) and the floods (network's regime) are weighted fairly.

Pool: revision5 general malware + CLI benign  +  REAL-tool floods (Slowloris/GoldenEye + volumetric, from the
realtools attempt)  +  network-active benign + null (from the diverse attempt).
Every case scored once by grouped nested CV (malware family-held-out, floods instance-held-out, benign shape-held-out;
hybrid = nested stacked late-fusion). Reports per model: raw pooled acc/recall/spec/prec/F1/BA, MACRO (class-balanced)
recall/precision/F1, a count-balanced pooled accuracy (malware subsampled to flood count, bootstrapped), per-attack-class
recall, and the host-vs-network regime balance. No promotion, no merge.
Usage: python3 score_balanced_21.py <realtools-attempt> <diverse-attempt>
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
FLOOD_SHAPE = {"syn_fan_40k": "syn", "syn_fan_100k": "syn", "syn_fan_150k": "syn", "syn_sink_40k": "syn",
               "syn_sink_100k": "syn", "udp_fan_60k": "udp", "udp_fan_250k": "udp", "udp_sink_60k": "udp",
               "udp_sink_150k": "udp", "udp_sink_250k": "udp",
               "slowloris_150": "slowloris", "slowloris_300": "slowloris", "slowloris_500": "slowloris",
               "slowloris_800": "slowloris", "slowloris_1000": "slowloris",
               "goldeneye_g5": "goldeneye", "goldeneye_g10": "goldeneye", "goldeneye_g15": "goldeneye",
               "goldeneye_p10": "goldeneye", "goldeneye_r10": "goldeneye"}
BENIGN_NET = ["bulkup_200", "bulkup_400", "bulkup_700", "session_300", "session_600", "session_1000",
              "beacon_50", "beacon_100", "dns_2k", "dns_5k", "dns_10k"]
NULLS = ["null1", "null2"]


def main():
    rt = Path(sys.argv[1]); dv = Path(sys.argv[2])
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

    def add(att, name, label, stratum, group):
        try:
            r = sf.build_record(att / "runs" / (name + ".zip"), name, label, host, host_signals, trainer, data)
        except Exception as e:
            print("  dropped %-14s (build failed: %s)" % (name, type(e).__name__)); return
        if r.get("quality") != "accepted" or r.get("p4_parity") != "True":
            print("  dropped %-14s (%s)" % (name, r.get("quality") if r.get("quality") != "accepted" else r.get("p4_alignment_status")))
            return
        r["stratum"] = stratum; r["group_id"] = group
        pool.append(r)
    print("building flood/benign records...")
    for n, shape in FLOOD_SHAPE.items():
        add(rt, n, 1, "flood_" + shape, "flood_" + n)
    for n in BENIGN_NET:
        add(dv, n, 0, "net_benign", "netb_" + n.rsplit("_", 1)[0])
    for n in NULLS:
        add(dv, n, 0, "null", "null")

    def mat(rows, names):
        return np.asarray([[float(r[name]) for name in names] for r in rows], dtype=float)

    def rf():
        return trainer.random_forest()
    y = np.asarray([r["label"] for r in pool]); g = np.asarray([r["group_id"] for r in pool])
    Xh = mat(pool, host); Xp = mat(pool, P4)
    oof = {"host": np.zeros(len(pool)), "p4": np.zeros(len(pool)), "hybrid": np.zeros(len(pool))}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=42).split(Xh, y, g):
        hb = rf().fit(Xh[tr], y[tr]); pb = rf().fit(Xp[tr], y[tr])
        oof["host"][te] = hb.predict_proba(Xh[te])[:, 1]; oof["p4"][te] = pb.predict_proba(Xp[te])[:, 1]
        oh = np.zeros(len(tr)); op = np.zeros(len(tr)); gi = g[tr]; yi = y[tr]
        for itr, iva in StratifiedGroupKFold(min(5, len(set(gi))), shuffle=True, random_state=7).split(Xh[tr], yi, gi):
            oh[iva] = rf().fit(Xh[tr][itr], yi[itr]).predict_proba(Xh[tr][iva])[:, 1]
            op[iva] = rf().fit(Xp[tr][itr], yi[itr]).predict_proba(Xp[tr][iva])[:, 1]
        meta = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([oh, op]), yi)
        oof["hybrid"][te] = meta.predict_proba(np.column_stack([oof["host"][te], oof["p4"][te]]))[:, 1]
    pred = {m: (oof[m] >= .5).astype(int) for m in oof}

    mal = np.array([r["stratum"] == "general_malware" for r in pool])
    flood = np.array([r["stratum"].startswith("flood") for r in pool])
    ben = (y == 0)

    def block(name):
        print("\n=== %s ===" % name)
    out = {"models": {}}
    block("raw pooled (grouped-CV OOF; n=%d: malware=%d, flood=%d, benign=%d)" %
          (len(y), int(mal.sum()), int(flood.sum()), int(ben.sum())))
    print("  model   acc    recall  spec   prec   F1     BA   | macroRecall  balAcc(bootstrap)")
    rng = np.random.default_rng(42)
    for m in ("host", "p4", "hybrid"):
        p = pred[m]
        tp = int((p[y == 1] == 1).sum()); fn = int((p[y == 1] == 0).sum())
        tn = int((p[y == 0] == 0).sum()); fp = int((p[y == 0] == 1).sum())
        acc = (tp + tn) / len(y); rec = tp / (tp + fn) if tp + fn else 0; spec = tn / (tn + fp) if tn + fp else 0
        prec = tp / (tp + fp) if tp + fp else 0; f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
        rec_mal = (p[mal] == 1).mean(); rec_flood = (p[flood] == 1).mean()
        macro_rec = (rec_mal + rec_flood + spec) / 3     # malware, flood, benign weighted equally
        # count-balanced pooled accuracy: subsample malware to flood count, equal benign, 200x
        mi = np.where(mal)[0]; fi = np.where(flood)[0]; bi = np.where(ben)[0]
        k = len(fi); accs = []
        for _ in range(200):
            idx = np.concatenate([rng.choice(mi, k, replace=False), fi, rng.choice(bi, 2 * k, replace=False)])
            accs.append((p[idx] == y[idx]).mean())
        bal = float(np.mean(accs))
        print("  %-6s  %.3f  %.3f  %.3f  %.3f  %.3f  %.3f  | %.3f        %.3f±%.3f" %
              (m, acc, rec, spec, prec, f1, (rec + spec) / 2, macro_rec, bal, float(np.std(accs))))
        out["models"][m] = dict(accuracy=round(acc, 3), recall=round(rec, 3), specificity=round(spec, 3),
                                precision=round(prec, 3), f1=round(f1, 3), BA=round((rec + spec) / 2, 3),
                                recall_general_malware=round(float(rec_mal), 3), recall_flood=round(float(rec_flood), 3),
                                macro_recall=round(float(macro_rec), 3), balanced_pooled_acc=round(bal, 3))

    block("recall by attack class (caught / n)")
    print("  %-18s n    host    p4      hybrid" % "class")
    out["by_class"] = {}
    for st in ["general_malware", "flood_syn", "flood_udp", "flood_slowloris", "flood_goldeneye"]:
        idx = [i for i, r in enumerate(pool) if r["stratum"] == st]
        if not idx:
            continue
        a = {m: sum(pred[m][i] for i in idx) for m in pred}
        print("  %-18s %-3d  %d/%-4d %d/%-4d %d/%-4d" % (st, len(idx), a["host"], len(idx), a["p4"], len(idx), a["hybrid"], len(idx)))
        out["by_class"][st] = {"n": len(idx), **{m: "%d/%d" % (a[m], len(idx)) for m in pred}}
    block("benign specificity (correct / n)")
    for st in ["cli_benign", "net_benign", "null"]:
        idx = [i for i, r in enumerate(pool) if r["stratum"] == st]
        if idx:
            a = {m: sum(pred[m][i] == 0 for i in idx) for m in pred}
            print("  %-18s %-3d  host=%d/%d p4=%d/%d hybrid=%d/%d" % (st, len(idx), a["host"], len(idx), a["p4"], len(idx), a["hybrid"], len(idx)))

    block("regime balance (host's regime = general malware; network's regime = floods)")
    print("  %-6s malware-recall  flood-recall  benign-spec" % "model")
    for m in ("host", "p4", "hybrid"):
        d = out["models"][m]
        print("  %-6s   %.3f          %.3f        %.3f" % (m, d["recall_general_malware"], d["recall_flood"], d["specificity"]))
    (rt / "adfa_score_balanced.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", rt / "adfa_score_balanced.json")


if __name__ == "__main__":
    main()
