#!/usr/bin/env python3
"""Re-run the grouped 29x29 protocol with launcher-neutral (post-target-exec) host features."""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parents[1]
STUDY = EXPERIMENT.parents[2]
sys.path.insert(0, str(STUDY / "src"))
import exec_boundary as eb  # noqa: E402
from build_dataset import aggregate  # noqa: E402

SOURCE = EXPERIMENT / "modeling/p4_29x29/aligned_p4_host_candidate_dataset.csv"
STATS = ("mean", "max", "sum", "std", "active_windows")
SEED = 42
PERMUTATIONS = 20
FOLD_SEEDS = tuple(range(100, 110))
STARTUP = {"dup2", "dup3", "execve", "execveat", "openat", "openat_success", "close", "mmap",
           "mprotect", "fork", "exit", "event", "unique_threads"}


def family_of(feature):
    return feature.rpartition("__")[0]


def score(labels, probabilities):
    predictions = (probabilities >= 0.5).astype(int)
    return {
        "balanced_accuracy": float(balanced_accuracy_score(labels, predictions)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "tn_fp_fn_tp": confusion_matrix(labels, predictions, labels=[0, 1]).ravel().tolist(),
    }


def top29(train_matrix, labels, features, seed):
    information = mutual_info_classif(train_matrix, labels, random_state=seed)
    groups = defaultdict(list)
    for index, feature in enumerate(features):
        groups[family_of(feature)].append(index)
    ranked = sorted(groups, key=lambda f: (-float(np.mean(information[groups[f]])), f))[:29]
    return [index for index, feature in enumerate(features) if family_of(feature) in set(ranked)]


def cross_validate(host, network, features, labels, splits, mode, trees=300):
    probabilities = np.full(len(labels), np.nan)
    for fold, (train, test) in enumerate(splits, start=1):
        h_train, h_test = host[train], host[test]
        if mode != "network":
            chosen = top29(h_train, labels[train], features, SEED + fold)
            h_train, h_test = h_train[:, chosen], h_test[:, chosen]
        parts_train = {"network": [network[train]], "host": [h_train],
                       "hybrid": [h_train, network[train]]}[mode]
        parts_test = {"network": [network[test]], "host": [h_test],
                      "hybrid": [h_test, network[test]]}[mode]
        model = RandomForestClassifier(n_estimators=trees, max_features="sqrt", min_samples_leaf=2,
                                       class_weight="balanced_subsample", random_state=SEED + fold,
                                       n_jobs=-1)
        model.fit(np.hstack(parts_train), labels[train])
        probabilities[test] = model.predict_proba(np.hstack(parts_test))[:, 1]
    assert np.isfinite(probabilities).all()
    return probabilities


def make_splits(labels, groups, seed):
    return list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
                .split(np.zeros((len(labels), 1)), labels, groups))


def summarize(post_rows, stat_names):
    out = {}
    for family in eb.FAMILIES:
        values = [window[family] for _, window in sorted(post_rows.items())]
        summary = aggregate(values)
        for stat in stat_names:
            out[f"host__{family}__{stat}"] = summary[stat]
    return out


def main():
    with SOURCE.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    network_features = [c for c in rows[0] if c.startswith("network__p4_")]
    host_features = [f"host__{family}__{stat}" for family in eb.FAMILIES for stat in STATS]
    labels = np.array([int(r["label"]) for r in rows])
    groups = np.array([r["group_id"] for r in rows])
    network = np.array([[float(r[c]) for c in network_features] for r in rows])

    post_matrix, pre_matrix, unresolved = [], [], []
    first_dup2 = {"benign": [], "malware": []}
    for row in rows:
        cohort = row["class_name"]
        run = next((EXPERIMENT / "runs" / cohort / row["sample_artifact"] / "output").glob("run_*"))
        post = eb.derive_run(run, 2)
        _, _, _, stored = eb.load_run(run)
        pre = {w: {f: float(stored[w][f]) - post[w][f] for f in eb.FAMILIES} for w in post}
        post_summary, pre_summary = summarize(post, STATS), summarize(pre, STATS)
        post_matrix.append([post_summary[f] for f in host_features])
        pre_matrix.append([pre_summary[f] for f in host_features])
        first_dup2[cohort].append(max(post[w]["ebpf_dup2_count"] for w in post))
    host_post = np.array(post_matrix)
    host_pre = np.array(pre_matrix)
    constant_post = int(np.sum(np.ptp(host_post, axis=0) == 0))

    splits = make_splits(labels, groups, SEED)
    report = {"samples": len(rows), "class_counts": dict(Counter(labels.tolist())),
              "host_columns": len(host_features), "constant_post_exec_columns": constant_post,
              "protocol": "StratifiedGroupKFold seed 42, 29 host families chosen per training fold, RF 300 trees",
              "models": {}, "controls": {}}

    for mode in ("network", "host", "hybrid"):
        p = cross_validate(host_post, network, host_features, labels, splits, mode)
        report["models"][f"{mode}_post_exec"] = score(labels, p)
        if mode == "host":
            host_probabilities = p
    p_pre = cross_validate(host_pre, network, host_features, labels, splits, "host")
    report["controls"]["launcher_only_features_(removed_portion)"] = score(labels, p_pre)

    # Remaining one-feature shortcut: best dup2 stump on post-exec peak, fit per training fold.
    dup2_index = host_features.index("host__ebpf_dup2_count__max")
    stump = np.zeros(len(labels))
    for train, test in splits:
        tree = DecisionTreeClassifier(max_depth=1, random_state=SEED).fit(host_post[train][:, [dup2_index]], labels[train])
        stump[test] = tree.predict_proba(host_post[test][:, [dup2_index]])[:, 1]
    report["controls"]["post_exec_dup2_max_stump"] = score(labels, stump)
    report["post_exec_dup2_peak_distribution"] = {
        c: sorted(Counter(v).items()) for c, v in first_dup2.items()}

    keep = [i for i, f in enumerate(host_features) if family_of(f).removeprefix("host__").removeprefix("ebpf_").removesuffix("_count") not in STARTUP]
    p_ns = cross_validate(host_post[:, keep], network, [host_features[i] for i in keep], labels, splits, "host")
    report["controls"]["post_exec_without_startup_families"] = {**score(labels, p_ns), "columns": len(keep)}

    permutation_scores = []
    rng = np.random.default_rng(SEED)
    for _ in range(PERMUTATIONS):
        shuffled = rng.permutation(labels)
        p = cross_validate(host_post, network, host_features, shuffled, splits, "host", trees=100)
        permutation_scores.append(float(balanced_accuracy_score(shuffled, (p >= 0.5).astype(int))))
    report["controls"]["label_permutations_host_post_exec"] = {
        "mean_balanced_accuracy": float(np.mean(permutation_scores)),
        "min": float(np.min(permutation_scores)), "max": float(np.max(permutation_scores)),
        "repeats": PERMUTATIONS}

    seed_scores = {"host": [], "hybrid": []}
    for seed in FOLD_SEEDS:
        other = make_splits(labels, groups, seed)
        for mode in seed_scores:
            p = cross_validate(host_post, network, host_features, labels, other, mode, trees=200)
            seed_scores[mode].append(float(balanced_accuracy_score(labels, (p >= 0.5).astype(int))))
    report["fold_seed_stability"] = {
        mode: {"balanced_accuracy": values, "mean": float(np.mean(values)),
               "min": float(np.min(values)), "max": float(np.max(values))}
        for mode, values in seed_scores.items()}

    wrong = Counter()
    for row, prob in zip(rows, host_probabilities):
        if int(prob >= 0.5) != int(row["label"]):
            wrong[row["group_id"]] += 1
    report["host_post_exec_errors_by_group"] = dict(wrong)
    (HERE / "post_exec_results.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
