"""Faithful ADFA-descriptor contrast on the SAME revision5 held-out split.

The frozen trainer's host path hard-asserts 29 families / 145 columns, so the 90-column ADFA
descriptor contract cannot pass through analyze_v21's --host-contract pipeline. This probe instead
reuses analyze_v21.prepare() (identical revision5 cases, the cohort's own family/project-held-out
split, the same 5-stat aggregation and P4-alignment/parity gates) and fits RF500/balanced/seed42
DIRECTLY on all 90 ADFA behavioral columns (no 29/145 family selection), scoring the identical
54-case common validation ONCE. It answers one question: does the thesis-validated behavioral
descriptor representation separate held-out families, or does the deployed 0.964 rest on the
launch/process-structure counters? POST-HOC on consumed validation; not blind, no model promotion.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_v21 as base          # noqa: E402
import analyze_revision5 as rev5    # noqa: E402

ADFA = ROOT.parents[2] / "data/benign/revision3/labeled_sample_dataset.feature_columns.adfa-host.json"


def grouped_oof(trainer, np, mat, training, ytr, names):
    groups = np.asarray([r["group_id"] for r in training])
    oof = np.full(len(training), np.nan)
    for tr, held in trainer.make_splits(ytr, groups):
        est = trainer.random_forest()
        est.fit(mat([training[i] for i in tr], names), ytr[tr])
        oof[held] = est.predict_proba(mat([training[i] for i in held], names))[:, 1]
    return oof


def main():
    # Point analyze_v21 at the revision5 cohort + its folding-aware metadata, with the ADFA host contract.
    base.V21_ATTEMPT = rev5.ATTEMPT
    base.CASES_ORDER = rev5.ATTEMPT / "payload/cases.json"
    base.case_metadata = rev5.case_metadata
    base.HOST_CONTRACT = str(ADFA)

    trainer, data, _ = base.frozen.dependencies()
    np = trainer.np
    records, host, _elig, _align, parity = base.prepare(trainer, data)
    assert len(host) == 90, f"expected 90 ADFA host cols, got {len(host)}"
    P4 = list(data.p4.P4_SAMPLE_FEATURES)

    common = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
    tr_idx, val_idx = trainer.split_indices(common)
    training = [common[i] for i in tr_idx]
    validation = [common[i] for i in val_idx]
    ytr = np.asarray([r["label"] for r in training])
    yval = np.asarray([r["label"] for r in validation])
    counts = {"common": len(common), "training": len(training), "validation": len(validation),
              "val_benign": int((yval == 0).sum()), "val_malware": int(yval.sum()),
              "p4_parity_comparisons": parity}

    def mat(rows, names):
        return np.asarray([[float(r[name]) for name in names] for r in rows], dtype=float)

    def fit_score(names):
        est = trainer.random_forest()
        est.fit(mat(training, names), ytr)
        return est, est.predict_proba(mat(validation, names))[:, 1]

    host_est, host_p = fit_score(host)
    _, hyb_p = fit_score(host + P4)
    _, p4_p = fit_score(P4)

    held = {
        "adfa_host_90": trainer.binary_metrics(yval, host_p),
        "adfa_hybrid_90_plus_p4_145": trainer.binary_metrics(yval, hyb_p),
        "p4_145_sanity": trainer.binary_metrics(yval, p4_p),
    }
    oof = {
        "adfa_host_90": trainer.binary_metrics(ytr, grouped_oof(trainer, np, mat, training, ytr, host)),
        "adfa_hybrid_90_plus_p4_145": trainer.binary_metrics(ytr, grouped_oof(trainer, np, mat, training, ytr, host + P4)),
    }
    imp = sorted(zip(host, host_est.feature_importances_.tolist()), key=lambda kv: -kv[1])[:12]

    out = {
        "status": "adfa_descriptor_contrast_same_revision5_heldout_split",
        "note": "RF500/balanced/seed42 fit directly on all 90 ADFA behavioral columns (no 29/145 selection); "
                "same cases/split/P4-parity as the authoritative deployed-contract fit; validation consumed/post-hoc.",
        "adfa_contract": str(ADFA), "adfa_host_columns": len(host),
        "counts": counts,
        "held_out_validation": held,
        "training_grouped_oof": oof,
        "deployed_contract_reference_same_split": {
            "note": "from revision5-model-fit/20261025T133358975816Z (29/145 launch-structure counters)",
            "host_29_families_heldout_BA": 0.9643, "hybrid_heldout_BA": 0.9643, "p4_heldout_BA": 0.7500,
            "host_train_oof_BA": 0.7154, "hybrid_train_oof_BA": 0.7017},
        "adfa_host_top_importances": [{"feature": k, "importance": round(v, 5)} for k, v in imp],
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = ROOT / "revision5-model-fit" / "adfa-descriptor-contrast" / stamp
    dest.mkdir(parents=True, exist_ok=False)
    (dest / "adfa_contrast.json").write_text(json.dumps(out, indent=2))
    print("COUNTS:", json.dumps(counts))
    for k, v in held.items():
        print(f'HELD-OUT {k}: BA={v["balanced_accuracy"]:.4f} AUC={v["roc_auc"]:.4f} cm={v["confusion_matrix_tn_fp_fn_tp"]}')
    for k, v in oof.items():
        print(f'TRAIN-OOF {k}: BA={v["balanced_accuracy"]:.4f} AUC={v["roc_auc"]:.4f}')
    print("ADFA host top features:", ", ".join(k for k, _ in imp[:6]))
    print("WROTE:", dest / "adfa_contrast.json")


if __name__ == "__main__":
    main()
