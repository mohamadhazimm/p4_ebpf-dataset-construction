"""ADFA-90 LEARNED late-fusion hybrid (stacked generalization), vs plain concatenation and a max rule.

Base learners (RF500/balanced/seed42, augmented training = revision5 + network-active benign):
  host  = ADFA-90 syscall-sequence descriptors
  p4    = 145 P4 flow features
Meta learner = LogisticRegression(balanced) trained on the base learners' GROUPED OUT-OF-FOLD
probabilities (StratifiedGroupKFold, group=family/project) so it learns the fusion without leakage.

Scored on the same .21-captured held-out set (held-out floods + held-out benign bulk + bulkdl + null).
Reports four hybrids side by side: concat-235 RF, stacked-LR (learned), mean rule, max rule.
Exploratory/OOD (no flood in training); no model promotion, no merge.
Usage: python3 fuse_adfa_hybrid.py <bulk-attempt-dir> <flood-attempt-dir>
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
    tr_idx, _ = trainer.split_indices(rev5_common)
    rev5_train = [rev5_common[i] for i in tr_idx]

    def rec(attempt, name, label):
        return sf.build_record(attempt / "runs" / (name + ".zip"), name, label, host, host_signals, trainer, data)

    aug = [rec(bulk_attempt, n, 0) for n in ("bulk400", "bulk700", "bulk1300", "bulk2000")]
    training = rev5_train + aug
    held = [("floodsyn", 1, flood_attempt), ("floodudp", 1, flood_attempt),
            ("bulk1000", 0, bulk_attempt), ("bulk1600", 0, bulk_attempt),
            ("bulkdl", 0, flood_attempt), ("nullidle", 0, flood_attempt)]
    held_recs = [(n, lab, rec(att, n, lab)) for n, lab, att in held]

    def mat(rows, names):
        return np.asarray([[float(r[name]) for name in names] for r in rows], dtype=float)
    y = np.asarray([r["label"] for r in training])
    groups = [r["group_id"] for r in training]

    def rf():
        return trainer.random_forest()

    # --- base learners on full augmented training ---
    host_full = rf().fit(mat(training, host), y)
    p4_full = rf().fit(mat(training, P4), y)
    concat_full = rf().fit(mat(training, host + P4), y)      # plain concatenation reference

    # --- grouped OOF base probabilities to train the meta learner (no leakage) ---
    Xh = mat(training, host); Xp = mat(training, P4)
    oof_h = np.zeros(len(training)); oof_p = np.zeros(len(training))
    skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    for tr, va in skf.split(Xh, y, groups):
        oof_h[va] = rf().fit(Xh[tr], y[tr]).predict_proba(Xh[va])[:, 1]
        oof_p[va] = rf().fit(Xp[tr], y[tr]).predict_proba(Xp[va])[:, 1]
    meta = LogisticRegression(max_iter=2000, class_weight="balanced")
    meta.fit(np.column_stack([oof_h, oof_p]), y)
    coef = meta.coef_[0]; intc = float(meta.intercept_[0])

    out = {"host_contract": "ADFA-90", "meta": "stacked_logistic",
           "meta_coef": {"host": round(float(coef[0]), 3), "p4": round(float(coef[1]), 3), "intercept": round(intc, 3)},
           "rows": []}
    print("\nmeta (stacked LR) learned weights:  host=%.3f  p4=%.3f  intercept=%.3f" % (coef[0], coef[1], intc))
    print("\n  %-9s %-6s  host90   p4-145 | concat235  stackedLR  mean   max" % ("case", "truth"))
    for n, lab, r in held_recs:
        if r.get("p4_parity") != "True":
            print("  %-9s %-6s  (not P4-aligned)" % (n, "FLOOD" if lab else "benign")); continue
        h = float(host_full.predict_proba(mat([r], host))[:, 1][0])
        p = float(p4_full.predict_proba(mat([r], P4))[:, 1][0])
        c = float(concat_full.predict_proba(mat([r], host + P4))[:, 1][0])
        s = float(meta.predict_proba([[h, p]])[:, 1][0])
        mn = (h + p) / 2.0; mx = max(h, p)
        tag = lambda v: "M" if v >= .5 else "b"  # noqa: E731
        print("  %-9s %-6s  %.3f(%s) %.3f(%s) | %.3f(%s)  %.3f(%s)  %.3f(%s) %.3f(%s)" %
              (n, "FLOOD" if lab else "benign", h, tag(h), p, tag(p), c, tag(c), s, tag(s), mn, tag(mn), mx, tag(mx)))
        out["rows"].append({"case": n, "truth": lab, "host": round(h, 3), "p4": round(p, 3),
                            "concat235": round(c, 3), "stacked_lr": round(s, 3),
                            "mean": round(mn, 3), "max": round(mx, 3)})
    (flood_attempt / "adfa_fusion.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", flood_attempt / "adfa_fusion.json")


if __name__ == "__main__":
    main()
