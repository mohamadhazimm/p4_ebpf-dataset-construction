"""Offline host-feature representation probe on the .21 cohort (no VM, no consumed-validation reuse).

Motivated by the thesis feature design: the host side was validated on ADFA-LD using statistical syscall-SEQUENCE
descriptors (unique_syscalls, entropy, avg_run_length, first100_unique, rare_syscall_ratio, total_syscalls), yet the
deployed classifier's host contract (labeled_sample_dataset.feature_columns.json) uses 35 raw ebpf_*_count per-syscall
COUNTERS and omits those descriptors. This probe compares representations the SAME way the thesis probed (RF, grouped
training-only out-of-fold), on our own .21 data, against the return_code/activity confound baselines. It uses ONLY the
140 family/project-held-out TRAINING cases (the 46-case validation is consumed); it fits nothing on validation.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[0] / "cohort-expansion-100x100-v18-20261021"))
import run_i386_holdout_collection as frozen   # noqa: E402
sys.path.insert(0, str(ROOT))
import analyze_v21 as av                        # noqa: E402

# ADFA-validated syscall-sequence descriptor telemetry columns (present in the 169-feature telemetry, NOT in the
# 35-family host model contract). These are the thesis's validated host features.
ADFA_COLS = [
    "host_total_syscalls_total", "host_unique_syscalls_mean", "host_unique_syscalls_max",
    "host_entropy_mean", "host_entropy_max", "host_avg_run_length_mean", "host_avg_run_length_max",
    "host_max_run_length_mean", "host_max_run_length_max", "host_transition_count_total",
    "host_rare_syscall_ratio_mean", "host_rare_syscall_ratio_max",
    "host_first50_unique_mean", "host_first50_unique_max",
    "host_first100_unique_mean", "host_first100_unique_max",
    "host_top_syscall_freq_mean", "host_top_syscall_freq_max",
]


def main():
    trainer, data, _ = frozen.dependencies()
    host = list(__import__("json").loads(trainer.HOST_FEATURE_PATH.read_text())["host"])  # 175 deployed counter cols
    records, _host, _elig, _align, _parity = av.prepare(trainer, data)
    order = {c["sample"]: int(c["position"]) for c in __import__("json").loads(av.CASES_ORDER.read_text())}
    # Augment each record with aggregated ADFA descriptors from its telemetry (same 5-stat aggregate as host families).
    adfa_cols = []
    for r in records:
        r["position"] = order[r["sample"]]
        telemetry = data.p4.load_telemetry_rows(av.V21_ATTEMPT / "runs" / r["sample"])
        for col in ADFA_COLS:
            agg = data.aggregate([float(w[col]) for w in telemetry])
            for stat, val in agg.items():
                key = "adfa__" + col + "__" + stat
                r[key] = val
                if key not in adfa_cols:
                    adfa_cols.append(key)
    train_idx, _ = trainer.split_indices(records)
    tr = [records[i] for i in train_idx]
    rc0 = "--rc0" in sys.argv  # exit-status control: keep only clean-completion (rc0) cases, removing the crash leak
    if rc0:
        tr = [r for r in tr if str(r["return_code"]) == "0"]
    y = trainer.np.asarray([r["label"] for r in tr])
    groups = trainer.np.asarray([r["group_id"] for r in tr])
    splits = trainer.make_splits(y, groups)

    def goof_numeric(cols):
        X = trainer.np.asarray([[float(r[c]) for c in cols] for r in tr])
        oof = trainer.np.full(len(tr), trainer.np.nan)
        for a, b in splits:
            est = trainer.model_pipeline()
            est.fit(X[a], y[a])
            oof[b] = est.predict_proba(X[b])[:, 1]
        return trainer.binary_metrics(y, oof)

    def goof_rc():
        rows = [{"rc": str(r["return_code"])} for r in tr]
        oof = trainer.np.full(len(tr), trainer.np.nan)
        for a, b in splits:
            vec = trainer.DictVectorizer(sparse=False); est = trainer.random_forest()
            est.fit(vec.fit_transform([rows[i] for i in a]), y[a])
            oof[b] = est.predict_proba(vec.transform([rows[i] for i in b]))[:, 1]
        return trainer.binary_metrics(y, oof)

    def goof_activity():
        return trainer.binary_metrics(y, trainer.grouped_oof_auxiliary(tr, "activity_only")[0])

    p4 = list(data.p4.P4_SAMPLE_FEATURES)
    reps = {
        "NETWORK  p4 (145)": goof_numeric(p4),
        "HOST     deployed counters (175)": goof_numeric(host),
        "HOST     adfa descriptors (%d)" % len(adfa_cols): goof_numeric(adfa_cols),
        "HYBRID   p4+counters (deployed)": goof_numeric(host + p4),
        "HYBRID   p4+adfa (fixed features)": goof_numeric(adfa_cols + p4),
        "BASELINE return_code": goof_rc(),
        "BASELINE activity (log syscalls)": goof_activity(),
    }
    print("HOST-FEATURE REPRESENTATION PROBE  (.21 training only, %d cases, %d malware / %d benign, %d groups)"
          % (len(tr), int(y.sum()), int((y == 0).sum()), len(set(groups))))
    print("family/project grouped out-of-fold (StratifiedGroupKFold-5, RF500); NO validation used")
    for name, m in reps.items():
        print("  %-38s BA=%.3f  AUC=%.3f" % (name, m["balanced_accuracy"], m["roc_auc"]))

    # Which features a full-training counter vs descriptor RF leans on (impurity importance, top 6).
    import numpy as np
    for label, cols in (("deployed_host35_counters", host), ("adfa_validated_descriptors", adfa_cols)):
        X = np.asarray([[float(r[c]) for c in cols] for r in tr])
        est = trainer.model_pipeline(); est.fit(X, y)
        rf = est[-1] if hasattr(est, "__getitem__") else est
        imp = getattr(rf, "feature_importances_", None)
        if imp is not None:
            top = sorted(zip(cols, imp), key=lambda t: -t[1])[:6]
            print("\nTop impurity importances [%s]:" % label)
            for c, v in top:
                print("  %-44s %.3f" % (c, v))


if __name__ == "__main__":
    main()
