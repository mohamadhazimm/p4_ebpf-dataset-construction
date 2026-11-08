"""Group label-permutation test (same procedure as train_model.group_permutation_null: 100 permutations of labels
among training groups, rng=default_rng(42), grouped 5-fold OOF via trainer.make_splits, RF500) applied to the
paper's ACTUAL detectors: ADFA host-90, P4-145, and the 235-col hybrid (host+P4). Read-only on the study tree."""
import json, sys
from multiprocessing import Pool
from pathlib import Path

ROOT = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022")
sys.path.insert(0, str(ROOT))
import analyze_v21 as base          # noqa: E402
import analyze_revision5 as rev5    # noqa: E402

base.V21_ATTEMPT = rev5.ATTEMPT
base.CASES_ORDER = rev5.ATTEMPT / "payload/cases.json"
base.case_metadata = rev5.case_metadata
base.HOST_CONTRACT = str(ROOT.parents[2] / "data/benign/revision3/labeled_sample_dataset.feature_columns.adfa-host.json")
trainer, data, _ = base.frozen.dependencies()
np = trainer.np
from sklearn.metrics import balanced_accuracy_score  # noqa: E402

records, host, *_ = base.prepare(trainer, data)
P4 = list(data.p4.P4_SAMPLE_FEATURES)
common = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
tr_idx, _ = trainer.split_indices(common)
training = [common[i] for i in tr_idx]
X = {"host": np.asarray([[float(r[c]) for c in host] for r in training]),
     "p4": np.asarray([[float(r[c]) for c in P4] for r in training])}
X["hybrid"] = np.hstack([X["host"], X["p4"]])
G = np.asarray([r["group_id"] for r in training])
y_obs = np.asarray([r["label"] for r in training])


def oof_ba(labels, name):
    oof = np.full(len(labels), np.nan)
    for tr, held in trainer.make_splits(labels, G):
        est = trainer.random_forest().fit(X[name][tr], labels[tr])
        oof[held] = est.predict_proba(X[name][held])[:, 1]
    return float(balanced_accuracy_score(labels, oof >= 0.5))


def job(labels):
    return {m: oof_ba(labels, m) for m in ("host", "p4", "hybrid")}


if __name__ == "__main__":
    groups = sorted(set(G.tolist()))
    glab = [int({r["label"] for r in training if r["group_id"] == g}.pop()) for g in groups]
    rng = np.random.default_rng(42); perms = []; rejected = 0
    while len(perms) < 100:
        lm = dict(zip(groups, rng.permutation(glab)))
        lab = np.asarray([lm[g] for g in G], dtype=int)
        try:
            trainer.make_splits(lab, G)
        except ValueError as e:
            if "training partition is missing a class" not in str(e):
                raise
            rejected += 1; continue
        perms.append(lab)
    with Pool(20) as p:
        obs = p.apply_async(job, (y_obs,))
        null = p.map(job, perms)
        obs = obs.get()
    out = {"training_samples": len(training), "training_groups": len(groups), "rejected": rejected, "observed": obs}
    for m in ("host", "p4", "hybrid"):
        s = np.asarray([n[m] for n in null])
        out[m] = {"observed_oof_BA": round(obs[m], 4), "null_mean": round(float(s.mean()), 4),
                  "null_95": [round(float(np.quantile(s, .025)), 4), round(float(np.quantile(s, .975)), 4)],
                  "p_upper": round(float((1 + (s >= obs[m]).sum()) / 101), 4)}
    json.dump(out, open(sys.argv[1], "w"), indent=1)
    print(json.dumps(out, indent=1))
