#!/usr/bin/env python3
"""Separate offline, training-only controlled experiments for hybrid RF behavior."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.stats import binomtest, spearmanr
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.metrics import balanced_accuracy_score, brier_score_loss, log_loss, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

import explore_within_family_split as experiment


SOURCE = experiment.OUTPUT / "20261022T103648547175Z"
SEEDS = (7, 42, 137)
VARIANTS = (
    "host", "network", "hybrid", "host_mtry24", "hybrid_mtry24",
    "host_mtry_all", "hybrid_mtry_all", "hybrid_zero_network",
    "hybrid_shuffled_network", "host_duplicated", "hybrid_top5_network",
    "host_regularized", "hybrid_regularized", "host_extra_trees", "hybrid_extra_trees",
    "host_log", "hybrid_log", "host_activity_residual", "hybrid_activity_residual",
    "post_raw_counts", "post_raw_presence", "post_raw_hybrid", "post_raw_transitions",
    "pre_raw_counts", "activity_only",
    "host_activity_weighted", "hybrid_activity_weighted", "nested_logistic_fusion",
)
FUSIONS = ("mean", "host75", "or", "and", "uncertainty_gate")
FIT_COUNTS = {"forests": 0, "trees": 0, "logistic_models": 0}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def signed_log(values):
    return np.sign(values) * np.log1p(np.abs(values))


def metrics(labels, scores, weights=None):
    labels, scores = np.asarray(labels), np.asarray(scores)
    if len(labels) != len(scores) or not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError("Invalid prediction vector")
    calls = scores >= 0.5
    return {"samples": len(labels), "balanced_accuracy": float(balanced_accuracy_score(labels, calls, sample_weight=weights)) if len(set(labels)) == 2 else None,
        "accuracy": float(np.average(calls == labels, weights=weights)),
        "roc_auc": float(roc_auc_score(labels, scores, sample_weight=weights)) if len(set(labels)) == 2 else None,
        "brier": float(brier_score_loss(labels, scores, sample_weight=weights)),
        "log_loss": float(log_loss(labels, scores, labels=[0, 1], sample_weight=weights)),
        "confusion_tn_fp_fn_tp": [int(np.sum((labels == truth) & (calls == prediction)))
            for truth, prediction in ((0, 0), (0, 1), (1, 0), (1, 1))]}


def paired(labels, host, hybrid):
    host_correct = (np.asarray(host) >= 0.5) == labels
    hybrid_correct = (np.asarray(hybrid) >= 0.5) == labels
    host_only, hybrid_only = int(np.sum(host_correct & ~hybrid_correct)), int(np.sum(hybrid_correct & ~host_correct))
    return {"host_only_correct": host_only, "hybrid_only_correct": hybrid_only,
        "balanced_accuracy_delta": metrics(labels, hybrid)["balanced_accuracy"] - metrics(labels, host)["balanced_accuracy"],
        "mcnemar_exact_descriptive_p": float(binomtest(hybrid_only, host_only + hybrid_only, 0.5).pvalue) if host_only + hybrid_only else 1.0,
        "caution": "Post-hoc descriptive paired test; related cases and multiplicity preclude confirmatory significance"}


def folds(labels, groups):
    result = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(np.zeros(len(labels)), labels, groups))
    seen = Counter()
    for train, held in result:
        if set(np.asarray(groups)[train]) & set(np.asarray(groups)[held]) or set(np.asarray(labels)[train]) != {0, 1}:
            raise ValueError("Invalid grouped fold")
        seen.update(held.tolist())
    if seen != Counter(range(len(labels))):
        raise ValueError("OOF cases missing or duplicated")
    return result


def fuse(host, network):
    return {"mean": (host + network) / 2, "host75": 0.75 * host + 0.25 * network,
        "or": np.maximum(host, network), "and": np.minimum(host, network),
        "uncertainty_gate": np.where((host >= 0.35) & (host <= 0.65), (host + network) / 2, host)}


def forest_scores(train_x, test_x, labels, trees, seed=42, max_features="sqrt", leaf=1, extra=False, weights=None):
    if train_x.shape[1] != test_x.shape[1] or not np.isfinite(train_x).all() or not np.isfinite(test_x).all():
        raise ValueError("Incompatible/nonfinite matrix")
    factory = ExtraTreesClassifier if extra else RandomForestClassifier
    estimator = factory(n_estimators=trees, class_weight="balanced", random_state=seed, n_jobs=1,
        max_features=max_features, min_samples_leaf=leaf)
    estimator.fit(train_x, labels, sample_weight=weights)
    FIT_COUNTS["forests"] += 1
    FIT_COUNTS["trees"] += trees
    return estimator.predict_proba(test_x)[:, 1], estimator


def connected_groups(rows, host, raw):
    parents = list(range(len(rows)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    owners = {}
    for index, row in enumerate(rows):
        keys = [("program_unit", row["split_unit"]), ("host175", tuple(host[index]))]
        if raw[index]["post_calls"]:
            keys.append(("post_sequence", row["mode"], raw[index]["sequence_sha256"]))
        for key in keys:
            if key in owners:
                parents[root(index)] = root(owners[key])
            else:
                owners[key] = index
    return np.asarray([str(root(index)) for index in range(len(rows))])


def raw_trace(row):
    root = experiment.ready.STUDY / row["source_run_dir"]
    metadata = experiment.ready.load(root / "run.json")
    root_pid = int(metadata["sample_root_pid"])
    executions = experiment.load_rows(root / "exec_events.csv")
    targets = [event for event in executions if event["event"] == "exec_success" and int(event["pid"]) == root_pid
        and event["detail"].partition("filename=")[2] == metadata["target_exec"]["expected_path"]]
    if len(targets) != 1:
        raise ValueError("Nonunique exact target boundary")
    boundary = int(targets[0]["timestamp_ns"])
    counts = {"pre": Counter(), "post": Counter(), "transitions": Counter()}
    sequence = hashlib.sha256()
    previous = None
    post_calls = 0
    with (root / "syscall_events.csv").open(newline="") as stream:
        for event in csv.DictReader(stream):
            parts = dict(part.split("=", 1) for part in event["detail"].split() if "=" in part)
            call = int(parts["id"])
            role = "root" if int(event["pid"]) == root_pid else "descendant"
            token = f"{role}:numeric_id={call}"
            post = int(event["timestamp_ns"]) > boundary
            counts["post" if post else "pre"][token] += 1
            if post:
                post_calls += 1
                sequence.update(f"{event['window_id']}:{token};".encode())
                if previous is not None:
                    counts["transitions"][previous + ">" + token] += 1
                previous = token
    if post_calls != int(row["post_target_lineage_raw_syscalls"]):
        raise ValueError("Post-target raw calls differ from frozen metadata")
    return {**{name: dict(values) for name, values in counts.items()}, "post_calls": post_calls,
        "sequence_sha256": sequence.hexdigest()}


def activity_cell(row):
    count = int(row["post_target_lineage_raw_syscalls"])
    return row["mode"], next(index for index, upper in enumerate((20, 45, 100, 1000, 10000, float("inf"))) if count < upper)


def nested_fusion(rows, indices, host, network, labels, host_features, groups, test_scores, trainer, trees):
    inner = np.full((len(indices), 2), np.nan)
    inner_groups = np.asarray(groups)[indices]
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    for train, held in splitter.split(np.zeros(len(indices)), labels[indices], inner_groups):
        if set(inner_groups[train]) & set(inner_groups[held]) or set(labels[indices[train]]) != {0, 1}:
            raise ValueError("Invalid nested stacking fold")
        training_indices, held_indices = indices[train], indices[held]
        _, selected, _ = trainer.feature_family_selection(host[training_indices], labels[training_indices], host_features)
        inner[held, 0], _ = forest_scores(host[training_indices][:, selected], host[held_indices][:, selected], labels[training_indices], trees)
        inner[held, 1], _ = forest_scores(network[training_indices], network[held_indices], labels[training_indices], trees)
    if not np.isfinite(inner).all():
        raise ValueError("Nested fusion missing inner OOF predictions")
    estimator = LogisticRegression(C=1.0, class_weight="balanced", random_state=42, max_iter=1000)
    estimator.fit(inner, labels[indices])
    FIT_COUNTS["logistic_models"] += 1
    return estimator.predict_proba(np.column_stack(test_scores))[:, 1], estimator.coef_[0].tolist()


def run_scope(rows, host, network, raw, host_features, trainer, groups, scope, trees, variants, output):
    labels = np.asarray([row["label"] for row in rows])
    predictions = {name: np.full(len(rows), np.nan) for name in (*variants, *FUSIONS)}
    for seed in SEEDS:
        for model in ("host", "hybrid"):
            predictions[f"{model}_seed{seed}"] = np.full(len(rows), np.nan)
    for count in (50, 100, 250, 500):
        for model in ("host", "hybrid"):
            predictions[f"{model}_trees{count}"] = np.full(len(rows), np.nan)
    for block in ("network", "host", "network_within_activity"):
        for repeat in range(10):
            predictions[f"permute_{block}_{repeat}"] = np.full(len(rows), np.nan)
    fold_rows, selections, stacking = [], [], []
    for fold, (train, held) in enumerate(folds(labels, groups), 1):
        _, selected, _ = trainer.feature_family_selection(host[train], labels[train], host_features)
        host_train, host_test = host[train][:, selected], host[held][:, selected]
        net_train, net_test = network[train], network[held]
        hybrid_train, hybrid_test = np.hstack((net_train, host_train)), np.hstack((net_test, host_test))
        if hybrid_train.shape[1] != 290 or not np.array_equal(hybrid_train[:, 145:], host_train):
            raise ValueError("Host block changed during concatenation")
        selections.append({"fold": fold, "features": [host_features[index] for index in selected]})
        vectorizer = DictVectorizer(sparse=False)
        nuisance = [{"log_activity": float(np.log1p(int(row["post_target_lineage_raw_syscalls"]))),
            "mode": row["mode"], "cohort": row["cohort"]} for row in rows]
        nuisance_train = vectorizer.fit_transform([nuisance[index] for index in train])
        nuisance_test = vectorizer.transform([nuisance[index] for index in held])
        residualizer = Ridge(alpha=1.0).fit(nuisance_train, signed_log(hybrid_train))
        residual_train = signed_log(hybrid_train) - residualizer.predict(nuisance_train)
        residual_test = signed_log(hybrid_test) - residualizer.predict(nuisance_test)
        rng = np.random.default_rng(42000 + fold)
        shuffled_train, shuffled_test = net_train[rng.permutation(len(train))], net_test[rng.permutation(len(held))]
        family_indices = trainer.p4.feature_family_indices(trainer.p4.P4_SAMPLE_FEATURES)
        scores = trainer.mutual_info_classif(net_train, labels[train], random_state=42)
        top = sorted(family_indices, key=lambda name: (-float(np.mean(scores[family_indices[name]])), name))[:5]
        net_selected = [index for index, name in enumerate(trainer.p4.P4_SAMPLE_FEATURES) if name.rpartition("__")[0] in top]
        raw_matrices = {}
        for name in ("post", "pre", "transitions"):
            vectorizer = DictVectorizer(sparse=False)
            raw_train = vectorizer.fit_transform([raw[index][name] for index in train])
            raw_test = vectorizer.transform([raw[index][name] for index in held])
            raw_matrices[name] = signed_log(raw_train), signed_log(raw_test)
        counts = Counter((activity_cell(rows[index]), int(labels[index])) for index in train)
        weights = np.ones(len(train))
        for position, index in enumerate(train):
            cell, label = activity_cell(rows[index]), int(labels[index])
            if counts[cell, 0] and counts[cell, 1]:
                weights[position] = min(counts[cell, 0], counts[cell, 1]) / counts[cell, label]
        matrices = {
            "host": (host_train, host_test), "network": (net_train, net_test), "hybrid": (hybrid_train, hybrid_test),
            "host_mtry24": (host_train, host_test), "hybrid_mtry24": (hybrid_train, hybrid_test),
            "host_mtry_all": (host_train, host_test), "hybrid_mtry_all": (hybrid_train, hybrid_test),
            "hybrid_zero_network": (np.hstack((np.zeros_like(net_train), host_train)), np.hstack((np.zeros_like(net_test), host_test))),
            "hybrid_shuffled_network": (np.hstack((shuffled_train, host_train)), np.hstack((shuffled_test, host_test))),
            "host_duplicated": (np.hstack((host_train, host_train)), np.hstack((host_test, host_test))),
            "hybrid_top5_network": (np.hstack((net_train[:, net_selected], host_train)), np.hstack((net_test[:, net_selected], host_test))),
            "host_regularized": (host_train, host_test), "hybrid_regularized": (hybrid_train, hybrid_test),
            "host_extra_trees": (host_train, host_test), "hybrid_extra_trees": (hybrid_train, hybrid_test),
            "host_log": (signed_log(host_train), signed_log(host_test)), "hybrid_log": (signed_log(hybrid_train), signed_log(hybrid_test)),
            "host_activity_residual": (residual_train[:, 145:], residual_test[:, 145:]),
            "hybrid_activity_residual": (residual_train, residual_test),
            "post_raw_counts": raw_matrices["post"], "pre_raw_counts": raw_matrices["pre"],
            "post_raw_transitions": raw_matrices["transitions"],
            "post_raw_presence": tuple((matrix > 0).astype(float) for matrix in raw_matrices["post"]),
            "post_raw_hybrid": (np.hstack((net_train, raw_matrices["post"][0])), np.hstack((net_test, raw_matrices["post"][1]))),
            "activity_only": tuple(np.asarray([nuisance[index]["log_activity"] for index in indices]).reshape(-1, 1) for indices in (train, held)),
            "host_activity_weighted": (host_train, host_test), "hybrid_activity_weighted": (hybrid_train, hybrid_test),
        }
        fitted = {}
        for variant in variants:
            if variant == "nested_logistic_fusion":
                values, coefficients = nested_fusion(rows, train, host, network, labels, host_features, groups,
                    (predictions["host"][held], predictions["network"][held]), trainer, trees)
                predictions[variant][held] = values
                stacking.append({"fold": fold, "host_network_coefficients": coefficients})
                continue
            train_x, test_x = matrices[variant]
            max_features = 24 if variant.endswith("mtry24") else None if variant.endswith("mtry_all") else "sqrt"
            predictions[variant][held], fitted[variant] = forest_scores(train_x, test_x, labels[train], trees,
                max_features=max_features, leaf=3 if variant.endswith("regularized") else 1,
                extra=variant.endswith("extra_trees"), weights=weights if variant.endswith("activity_weighted") else None)
        for seed in SEEDS:
            for name in ("host", "hybrid"):
                predictions[f"{name}_seed{seed}"][held] = predictions[name][held] if seed == 42 else forest_scores(
                    *matrices[name], labels[train], trees, seed=seed)[0]
        for name in ("host", "hybrid"):
            cumulative = np.zeros(len(held))
            for count, tree in enumerate(fitted[name].estimators_, 1):
                cumulative += tree.predict_proba(matrices[name][1])[:, 1]
                if count in (50, 100, 250, 500):
                    predictions[f"{name}_trees{count}"][held] = cumulative / count
        for name, values in fuse(predictions["host"][held], predictions["network"][held]).items():
            predictions[name][held] = values
        for repeat in range(10):
            rng = np.random.default_rng(100000 + 100 * fold + repeat)
            for block in ("network", "host", "network_within_activity"):
                modified = hybrid_test.copy()
                order = rng.permutation(len(held))
                if block == "network_within_activity":
                    order = np.arange(len(held))
                    strata = defaultdict(list)
                    for position, index in enumerate(held):
                        strata[activity_cell(rows[index])].append(position)
                    for members in strata.values():
                        order[members] = rng.permutation(members)
                start, end = (145, 290) if block == "host" else (0, 145)
                modified[:, start:end] = hybrid_test[order, start:end]
                predictions[f"permute_{block}_{repeat}"][held] = fitted["hybrid"].predict_proba(modified)[:, 1]
        fold_rows.extend({"fold": fold, "sample": rows[index]["sample"], "role": role, "group": str(groups[index])}
            for indices, role in ((train, "fit"), (held, "held")) for index in indices)
        print(f"{scope}: completed fold {fold}/5; {FIT_COUNTS}", flush=True)
    if any(not np.isfinite(values).all() for values in predictions.values()):
        raise ValueError("Incomplete OOF prediction")
    experiment.save_rows(output / f"{scope}_predictions.csv", [{"sample": row["sample"], "label": row["label"],
        "model": name, "probability_malware": float(values[index])} for name, values in predictions.items() for index, row in enumerate(rows)])
    experiment.save_rows(output / f"{scope}_folds.csv", fold_rows)
    experiment.ready.save(output / f"{scope}_selection.json", selections)
    results = {name: metrics(labels, values) for name, values in predictions.items()}
    group_counts = Counter(row["group_id"] for row in rows)
    group_weights = np.asarray([1 / group_counts[row["group_id"]] for row in rows])
    return {"metrics": results, "equal_group_metrics": {name: metrics(labels, values, group_weights) for name, values in predictions.items()},
        "paired_hybrid_host": paired(labels, predictions["host"], predictions["hybrid"]), "nested_coefficients": stacking,
        "seed_deltas": [paired(labels, predictions[f"host_seed{seed}"], predictions[f"hybrid_seed{seed}"]) for seed in SEEDS],
        "host_errors_network_correct": int(np.sum(((predictions["host"] >= .5) != labels) & ((predictions["network"] >= .5) == labels))),
        "oracle_correct_if_either": int(np.sum(((predictions["host"] >= .5) == labels) | ((predictions["network"] >= .5) == labels)))}


def saved_diagnostics(source, rows, trainer, host_features):
    verification = experiment.verify(source)
    training = [row for row in rows if row["split"] == "training"]
    validation = [row for row in rows if row["split"] == "validation"]
    selected = experiment.ready.load(source / "model-fit/selected_features.json")["selected_host_features"]
    labels = np.asarray([row["label"] for row in validation])
    probabilities, details = {}, {}
    for name in trainer.EXPECTED_MODELS:
        features = trainer.p4.P4_SAMPLE_FEATURES if name == "network_p4" else selected if name == "host_29_families" else [*trainer.p4.P4_SAMPLE_FEATURES, *selected]
        train_x, test_x = trainer.matrix(training, features), trainer.matrix(validation, features)
        estimator = trainer.joblib.load(source / "model-fit" / (name + ".joblib"))
        np.testing.assert_array_equal(estimator.named_steps["simpleimputer"].statistics_, np.median(train_x, axis=0))
        np.testing.assert_array_equal(estimator.classes_, [0, 1])
        scores = estimator.predict_proba(test_x)[:, 1]
        order = np.random.default_rng(42).permutation(len(validation))
        np.testing.assert_array_equal(estimator.predict_proba(test_x[order])[:, 1], scores[order])
        forest = estimator.named_steps["randomforestclassifier"]
        probabilities[name] = scores
        node_counts = Counter()
        for tree in forest.estimators_:
            for feature in tree.tree_.feature:
                if feature >= 0:
                    node_counts["network" if features[feature].startswith("network__") else "host"] += 1
        details[name] = {"metrics": metrics(labels, scores), "split_node_counts": dict(node_counts),
            "width": len(features), "max_features_per_node": forest.estimators_[0].max_features_}
    host, hybrid, network = (probabilities[name] for name in ("host_29_families", "hybrid_29_plus_29", "network_p4"))
    disagreements = [{"sample": row["sample"], "label": row["label"], "group_id": row["group_id"],
        "host_probability": float(host[index]), "hybrid_probability": float(hybrid[index]), "network_probability": float(network[index])}
        for index, row in enumerate(validation) if (host[index] >= .5) != (hybrid[index] >= .5)]
    return {"verification": verification, "models": details, "paired": paired(labels, host, hybrid), "disagreements": disagreements,
        "host_errors_network_correct": int(np.sum(((host >= .5) != labels) & ((network >= .5) == labels))),
        "oracle_correct_if_either": int(np.sum(((host >= .5) == labels) | ((network >= .5) == labels))),
        "oracle_note": "Label-informed upper bound, not an implementable detector or a newly fitted fusion"}


def write_report(output, result):
    lines = ["# Hybrid Explanation Experiments", "", "## Scope", "",
        "User-authorized offline exploratory tests. Original data, roles, models and probabilities are unchanged. No VM operation, sample execution or collection. No alternative fitted model was scored on validation. All new model comparisons use only the 182 original training cases.", "",
        "The data and hypotheses were previously examined. Frozen diagnostic choices prevent score-driven additions within this attempt, but do not make it preregistered blind confirmation.", "",
        "## Theory", "",
        "The best possible classifier with both sensors can ignore network features, so its minimum achievable population 0-1 risk cannot exceed that with host alone. A finite, greedily trained RF500 is not that optimal classifier. Extra noisy or redundant predictors alter feature sampling, split choices, variance and calibration. Strict benefit also needs useful conditional network information. Neither a hybrid win nor an OR-rule accuracy improvement is guaranteed.", "",
        "## Saved Implementation", "", "```json", json.dumps(result["saved_models"], indent=2), "```", "",
        "## Training-Only Comparisons", "", "BA is sample-weighted at the fixed 0.5 threshold. All variants, including losses, are retained. Equal-group metrics, seed runs, calibration, tree-count curves and block permutations are in result.json.", "",
        "| Variant | Program/Hash Unit OOF BA | Family/Project OOF BA | Behavior-Cluster OOF BA |", "| --- | ---: | ---: | ---: |"]
    for name in (*VARIANTS, *FUSIONS):
        values = [result["scopes"][scope]["metrics"].get(name, {}).get("balanced_accuracy") for scope in ("unit", "family", "behavior_cluster")]
        lines.append("| " + name + " | " + " | ".join("not run" if value is None else f"{value:.4%}" for value in values) + " |")
    lines += ["", "## Interpretation Boundaries", "",
        "- Unit folds keep benign program/build variants together but can share families and equivalent behaviors. Family folds answer a different, unseen-group question. Behavior-cluster folds join program units, identical full-host175 vectors and identical nonempty canonical post-target sequences within declared mode. These are behavioral clusters, NOT certified malware lineages; changing folds changes the estimand.",
        "- The hybrid has 290 candidate columns; sqrt offers17 total, approximately8.5 host on average versus12 in host-only. mtry24 approximately restores12 host candidates; all-feature controls and matching host controls distinguish this from a guaranteed causal explanation. Actual splitter search can inspect additional columns.",
        "- Zero, shuffled and duplicated blocks isolate feature-space effects; noise rows are shuffled without labels and separately in fit/held partitions. Inference block permutation breaks correlations and can be out-of-distribution, even within broad activity/mode bins. It is sensitivity evidence, not causal attribution.",
        "- Top-five network-family MI, residualization, weighting and feature vocabularies use only each fitting fold. Residualization uses log activity/mode/cohort and is not a causal adjustment. Activity weighting balances only both-label fitting cells; one-label cells keep weight1 and no original case is deleted.",
        "- Raw features are newly derived archived numeric syscall-ID counts/presence/transitions, split before/after exact root target exec. They do NOT reproduce the 35-family named/fallback contract, use different widths and do not establish malicious activation. Numeric IDs are not assigned syscall names: per-event ABI is unavailable in this archive and descendants may change ABI. Loader/runtime/task/mode confounding remains.",
        "- Nested logistic fusion uses three inner grouped folds and redoes MI inside every inner fit. Fixed mean/75%-host/OR/AND/uncertainty-gate rules are not tuned. Max/mean scores are not calibrated probabilities; Brier/log-loss are descriptive score checks.",
        "- Seed42 is retained alongside fixed seeds7/137; no seed is selected. Tree prefixes and all mtry/regularization/ExtraTrees/log controls are sensitivity experiments, not a replacement model release. Exact paired p-values ignore related-case dependence/multiple comparisons and are descriptive, not confirmatory tests.",
        "- Earlier offline reconstruction and 64,050 host-summary comparisons passed. Prior attribution controls demonstrated background connectivity HTTP, but general packet-to-process ownership is unverified. This experiment does not rerun those captures, repair missing events, certify binary lineage, acquire independent projects, or create untouched evaluation.", "",
        "## Reproduction", "", "Run test_hybrid_explanations.py --self-test, then --run. Each run freezes protocol/input hashes before fits and refuses output overwrite. --verify <attempt> independently recomputes every saved training OOF metric and rechecks inputs and fold separation.", "",
        "All original consumed-validation limitations remain. Do not select a method or threshold from this report and claim fresh generalization or force hybrid superiority.", ""]
    with (output / "REPORT.md").open("x") as stream:
        stream.write("\n".join(lines))


def run():
    rows, source_protocol = experiment.verify_prepared(SOURCE)
    common = [row for row in rows if experiment.existing.aligned(row)]
    training = [row for row in common if row["split"] == "training"]
    trainer, _, _ = experiment.existing.combined.frozen.dependencies()
    host_features = experiment.ready.load(trainer.HOST_FEATURE_PATH)["host"]
    paths = [Path(__file__), SOURCE / "protocol.json", SOURCE / "split_dataset.csv", SOURCE / "split_audit.json",
        SOURCE / "model-fit/metrics.json", SOURCE / "model-fit/selected_features.json", SOURCE / "model-fit/validation_predictions.csv",
        Path(experiment.__file__), Path(trainer.__file__), trainer.HOST_FEATURE_PATH, Path(trainer.p4.__file__)]
    paths.extend(sorted((SOURCE / "model-fit").glob("*.joblib")))
    for row in training:
        paths.extend(experiment.ready.STUDY / row["source_run_dir"] / name for name in ("run.json", "exec_events.csv", "syscall_events.csv"))
    hashes = {str(path.relative_to(experiment.ready.STUDY)) if path.is_relative_to(experiment.ready.STUDY) else str(path): experiment.ready.digest(path) for path in paths}
    output = SOURCE / "hybrid-explanation-tests" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True, exist_ok=False)
    experiment.ready.save(output / "protocol.json", {"authorization": "User requested testing possible explanations for hybrid not winning",
        "frozen_utc": datetime.now(timezone.utc).isoformat(), "source": str(SOURCE), "variants": list(VARIANTS), "fusions": list(FUSIONS),
        "trees": 500, "seeds": list(SEEDS), "outer_folds": 5, "inner_stacking_folds": 3,
        "scope": "New fits restricted to original training182; validation only replays original saved models",
        "rf": source_protocol["rf"], "selection": "Training-fold-only MI and nuisance/raw transforms; no validation tuning",
        "limitations": source_protocol["limitations"], "input_hashes": hashes})
    print("FROZEN ATTEMPT", output, flush=True)
    saved = saved_diagnostics(SOURCE, common, trainer, host_features)
    experiment.ready.save(output / "saved_model_checks.json", saved)
    raw = []
    for index, row in enumerate(training, 1):
        raw.append(raw_trace(row))
        if index % 20 == 0:
            print(f"Reconciled archived training raw traces {index}/{len(training)}", flush=True)
    experiment.ready.save(output / "training_raw_features.json", [{"sample": row["sample"], **evidence} for row, evidence in zip(training, raw)])
    host = trainer.matrix(training, host_features)
    network = trainer.matrix(training, trainer.p4.P4_SAMPLE_FEATURES)
    groups = {"unit": np.asarray([row["split_unit"] for row in training]),
        "family": np.asarray([row["group_id"] for row in training]), "behavior_cluster": connected_groups(training, host, raw)}
    labels = np.asarray([row["label"] for row in training])
    for values in groups.values():
        folds(labels, values)
    scopes = {}
    for scope, values in groups.items():
        variants = VARIANTS if scope != "behavior_cluster" else ("host", "network", "hybrid", "hybrid_mtry24", "hybrid_shuffled_network", "post_raw_counts", "post_raw_hybrid")
        scopes[scope] = run_scope(training, host, network, raw, host_features, trainer, values, scope, 500, variants, output)
        experiment.ready.save(output / f"{scope}_results.json", scopes[scope])
    frozen_metrics = experiment.ready.load(SOURCE / "model-fit/metrics.json")
    for name, old_name in (("host", "host_29_families"), ("network", "network_p4"), ("hybrid", "hybrid_29_plus_29")):
        old = frozen_metrics["training_family_grouped_oof"][old_name]
        for key in ("accuracy", "balanced_accuracy", "roc_auc"):
            if not np.isclose(scopes["family"]["metrics"][name][key], old[key], rtol=0, atol=1e-12):
                raise ValueError("Original family OOF baseline failed reproduction")
    result = {"status": "complete", "saved_models": saved, "scopes": scopes, "fit_counts": dict(FIT_COUNTS),
        "training_cases": len(training), "new_validation_models_scored": 0, "vm_operations": 0, "sample_executions": 0,
        "cluster_counts": {name: len(set(values)) for name, values in groups.items()},
        "training_feature_constants": {"host175": int(np.sum(np.ptp(host, axis=0) == 0)), "network145": int(np.sum(np.ptp(network, axis=0) == 0))},
        "training_activity_network_total_spearman": float(spearmanr(np.log1p([row["post_target_lineage_raw_syscalls"] for row in training]), network[:, trainer.p4.P4_SAMPLE_FEATURES.index("network__p4_net_pkts_total_delta__sum")]).statistic)}
    experiment.ready.save(output / "result.json", result)
    write_report(output, result)
    verify(output)
    print(json.dumps({"attempt": str(output), "fit_counts": FIT_COUNTS, "saved_paired": saved["paired"],
        "baselines": {scope: {name: values["metrics"][name]["balanced_accuracy"] for name in ("host", "network", "hybrid")} for scope, values in scopes.items()}}), flush=True)


def verify(output):
    protocol = experiment.ready.load(output / "protocol.json")
    for name, checksum in protocol["input_hashes"].items():
        if experiment.ready.digest(experiment.ready.STUDY / name) != checksum:
            raise ValueError("Frozen diagnostic input changed: " + name)
    result = experiment.ready.load(output / "result.json")
    checked = 0
    for scope, details in result["scopes"].items():
        rows = experiment.load_rows(output / f"{scope}_predictions.csv")
        models = defaultdict(list)
        seen = set()
        for row in rows:
            identity = row["model"], row["sample"]
            if identity in seen:
                raise ValueError("Duplicated prediction identity")
            seen.add(identity)
            models[row["model"]].append(row)
        for name, members in models.items():
            values = metrics([int(row["label"]) for row in members], [float(row["probability_malware"]) for row in members])
            if values != details["metrics"][name] or len(members) != result["training_cases"]:
                raise ValueError("Diagnostic metrics failed independent reproduction")
            checked += 1
        assignment = experiment.load_rows(output / f"{scope}_folds.csv")
        for fold in range(1, 6):
            fit = {row["group"] for row in assignment if int(row["fold"]) == fold and row["role"] == "fit"}
            held = {row["group"] for row in assignment if int(row["fold"]) == fold and row["role"] == "held"}
            if fit & held:
                raise ValueError("Fitting/evaluation cluster overlap")
    experiment.verify_prepared(SOURCE)
    value = {"status": "verified", "metric_vectors_recomputed": checked, "input_hashes_checked": len(protocol["input_hashes"]),
        "original_source_models_and_split_unchanged": True, "new_fitted_validation_scores": 0}
    path = output / "verification.json"
    if not path.exists():
        experiment.ready.save(path, value)
    print(json.dumps(value), flush=True)


def self_test():
    labels = np.tile([0, 1], 30)
    host = np.zeros((60, 145))
    host[:, 0] = labels
    zeros = np.zeros_like(host)
    scores, estimator = forest_scores(np.hstack((zeros, host)), np.hstack((zeros, host)), labels, 20, max_features=None)
    assert estimator.n_features_in_ == 290 and metrics(labels, scores)["balanced_accuracy"] == 1.0
    assert paired(labels, labels.astype(float), labels.astype(float))["mcnemar_exact_descriptive_p"] == 1
    assert all(np.isfinite(value).all() for value in fuse(scores, 1 - scores).values())
    assert np.all(fuse(scores, 1 - scores)["or"] >= scores)
    assert len(folds(labels, np.asarray([str(index) for index in range(60)]))) == 5
    rows = [{"split_unit": str(index), "mode": "native"} for index in range(3)]
    raw = [{"post_calls": 0, "sequence_sha256": "same"} for _ in rows]
    groups = connected_groups(rows, np.asarray([[1, 2], [1, 2], [2, 3]]), raw)
    assert groups[0] == groups[1] and groups[1] != groups[2]
    for invalid in (np.array([np.nan]), np.array([1.1])):
        try:
            metrics(np.array([0]), invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid probability accepted")
    print("PASS: synthetic 290-column fit, paired/fusion metrics, clustered folds and invalid-score guards", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--verify", type=Path)
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    elif arguments.verify:
        verify(arguments.verify)
    elif arguments.run:
        run()
    else:
        parser.error("Choose --self-test, --run or --verify <attempt>")