"""ONE pooled held-out evaluation of the three models under ADFA-90, across EVERYTHING we can score:
  - revision5 VALIDATION split  : general malware (botnet/miner/ransomware) + CLI-tool benign  (family/project-held-out)
  - floods                      : floodsyn, floodudp  (.21-captured, rate-capped, OOD - no flood in training)
  - network-active benign       : held-out bulk1000, bulk1600, bulkdl
  - null                        : nullidle

Models (augmented training = revision5 train + network-active benign bulk):
  host   = ADFA-90 RF500/balanced/seed42
  p4     = P4-145 RF500/balanced/seed42
  hybrid = LEARNED stacked late-fusion: LogisticRegression(balanced) over the base learners' grouped OOF probabilities

Shows host misses floods, P4 misses some general malware, hybrid recovers most of each one's misses.
Exploratory/OOD (floods unseen in training); no model promotion, no merge.
Usage: python3 pool_eval_adfa.py <bulk-attempt-dir> <flood-attempt-dir>
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


def main():
    bulk_attempt = Path(sys.argv[1]); flood_attempt = Path(sys.argv[2])
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

    rev5_common = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
    tr_idx, va_idx = trainer.split_indices(rev5_common)
    rev5_train = [rev5_common[i] for i in tr_idx]
    rev5_val = [rev5_common[i] for i in va_idx]

    def rec(attempt, name, label, stratum):
        r = sf.build_record(attempt / "runs" / (name + ".zip"), name, label, host, host_signals, trainer, data)
        r["stratum"] = stratum
        return r

    aug = [rec(bulk_attempt, n, 0, "net_benign") for n in ("bulk400", "bulk700", "bulk1300", "bulk2000")]
    training = rev5_train + aug

    # tag revision5 strata
    for r in rev5_val:
        r["stratum"] = "general_malware" if r["label"] == 1 else "cli_benign"

    held = [rec(flood_attempt, "floodsyn", 1, "flood"), rec(flood_attempt, "floodudp", 1, "flood"),
            rec(bulk_attempt, "bulk1000", 0, "net_benign"), rec(bulk_attempt, "bulk1600", 0, "net_benign"),
            rec(flood_attempt, "bulkdl", 0, "net_benign"), rec(flood_attempt, "nullidle", 0, "null")]
    pool = rev5_val + held

    def mat(rows, names):
        return np.asarray([[float(r[name]) for name in names] for r in rows], dtype=float)

    def rf():
        return trainer.random_forest()

    y = np.asarray([r["label"] for r in training])
    groups = [r["group_id"] for r in training]
    host_full = rf().fit(mat(training, host), y)
    p4_full = rf().fit(mat(training, P4), y)

    Xh = mat(training, host); Xp = mat(training, P4)
    oof_h = np.zeros(len(training)); oof_p = np.zeros(len(training))
    for tr, va in StratifiedGroupKFold(5, shuffle=True, random_state=42).split(Xh, y, groups):
        oof_h[va] = rf().fit(Xh[tr], y[tr]).predict_proba(Xh[va])[:, 1]
        oof_p[va] = rf().fit(Xp[tr], y[tr]).predict_proba(Xp[va])[:, 1]
    meta = LogisticRegression(max_iter=2000, class_weight="balanced").fit(np.column_stack([oof_h, oof_p]), y)

    hp = host_full.predict_proba(mat(pool, host))[:, 1]
    pp = p4_full.predict_proba(mat(pool, P4))[:, 1]
    yp = meta.predict_proba(np.column_stack([hp, pp]))[:, 1]
    truth = np.asarray([r["label"] for r in pool])
    preds = {"host": (hp >= .5).astype(int), "p4": (pp >= .5).astype(int), "hybrid": (yp >= .5).astype(int)}

    def confusion(pred):
        tp = int(((pred == 1) & (truth == 1)).sum()); fn = int(((pred == 0) & (truth == 1)).sum())
        tn = int(((pred == 0) & (truth == 0)).sum()); fp = int(((pred == 1) & (truth == 0)).sum())
        rec_ = tp / (tp + fn) if tp + fn else float("nan")
        spec = tn / (tn + fp) if tn + fp else float("nan")
        return tp, fp, fn, tn, rec_, spec, (rec_ + spec) / 2

    print("\n=== pooled held-out (n=%d: attack=%d, benign=%d) ===" %
          (len(pool), int((truth == 1).sum()), int((truth == 0).sum())))
    print("  model   TP  FP  FN  TN   recall  spec    BA")
    out = {"n": len(pool), "models": {}, "by_stratum": {}, "complementarity": {}}
    for m in ("host", "p4", "hybrid"):
        tp, fp, fn, tn, r_, s_, ba = confusion(preds[m])
        print("  %-6s  %2d  %2d  %2d  %2d   %.3f   %.3f   %.3f" % (m, tp, fp, fn, tn, r_, s_, ba))
        out["models"][m] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                            "recall": round(r_, 3), "specificity": round(s_, 3), "BA": round(ba, 3)}

    strata = ["general_malware", "flood", "cli_benign", "net_benign", "null"]
    print("\n=== per-stratum accuracy (correct / n) ===")
    print("  %-16s n   truth   host    p4      hybrid" % "stratum")
    for st in strata:
        idx = [i for i, r in enumerate(pool) if r["stratum"] == st]
        if not idx:
            continue
        t = "attack" if truth[idx[0]] == 1 else "benign"
        accs = {m: sum(preds[m][i] == truth[i] for i in idx) for m in preds}
        print("  %-16s %-3d %-6s  %d/%-3d   %d/%-3d   %d/%-3d" %
              (st, len(idx), t, accs["host"], len(idx), accs["p4"], len(idx), accs["hybrid"], len(idx)))
        out["by_stratum"][st] = {"n": len(idx), "truth": t,
                                 **{m: "%d/%d" % (accs[m], len(idx)) for m in preds}}

    # complementarity: errors recovered
    def wrong(m):
        return {i for i in range(len(pool)) if preds[m][i] != truth[i]}
    wh, wp, wy = wrong("host"), wrong("p4"), wrong("hybrid")
    host_miss_hybrid_ok = sorted(wh - wy)
    p4_miss_hybrid_ok = sorted(wp - wy)
    hybrid_regress = sorted(wy - (wh & wp))   # hybrid wrong where at least one base was right
    print("\n=== complementarity ===")
    print("  host wrong: %d   p4 wrong: %d   hybrid wrong: %d" % (len(wh), len(wp), len(wy)))
    print("  hybrid RECOVERS host's error (host wrong, hybrid right): %d" % len(host_miss_hybrid_ok))
    for i in host_miss_hybrid_ok:
        print("      %-10s %-16s truth=%s  host=%.2f p4=%.2f hyb=%.2f" %
              (pool[i]["sample"][:10], pool[i]["stratum"], truth[i], hp[i], pp[i], yp[i]))
    print("  hybrid RECOVERS p4's error (p4 wrong, hybrid right): %d" % len(p4_miss_hybrid_ok))
    for i in p4_miss_hybrid_ok:
        print("      %-10s %-16s truth=%s  host=%.2f p4=%.2f hyb=%.2f" %
              (pool[i]["sample"][:10], pool[i]["stratum"], truth[i], hp[i], pp[i], yp[i]))
    print("  hybrid REGRESSES (hybrid wrong where a base was right): %d" % len(hybrid_regress))
    for i in hybrid_regress:
        print("      %-10s %-16s truth=%s  host=%.2f p4=%.2f hyb=%.2f" %
              (pool[i]["sample"][:10], pool[i]["stratum"], truth[i], hp[i], pp[i], yp[i]))
    out["complementarity"] = {"host_wrong": len(wh), "p4_wrong": len(wp), "hybrid_wrong": len(wy),
                              "hybrid_recovers_host": len(host_miss_hybrid_ok),
                              "hybrid_recovers_p4": len(p4_miss_hybrid_ok),
                              "hybrid_regressions": len(hybrid_regress)}
    (flood_attempt / "adfa_pool_eval.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", flood_attempt / "adfa_pool_eval.json")


if __name__ == "__main__":
    main()
