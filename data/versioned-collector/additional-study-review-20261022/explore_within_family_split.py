#!/usr/bin/env python3
"""Freeze a separate exploratory within-family split of existing accepted captures."""

import argparse
import csv
import json
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp

import analyze_matched45 as existing

ready = existing.ready
SOURCE = ready.ROOT / "combined-analysis/20261022T092936019065Z"
OUTPUT = ready.ROOT / "within-family-exploratory"
SEED = 42


def unit_key(row):
    if row["class"] == "benign":
        if not row.get("program"):
            raise ValueError("Benign program identity unavailable")
        return row["group_id"] + "::program::" + row["program"]
    return row["group_id"] + "::sha256::" + row["executable_sha256"]


def check_identities(rows):
    for key in ("sample", "executable_sha256"):
        if len({row[key] for row in rows}) != len(rows):
            raise ValueError("Duplicate identity: " + key)
    for row in rows:
        if row["group_id"] in existing.combined.EXCLUDED_GROUPS:
            raise ValueError("Globally excluded group reintroduced")
        if row["label"] != int(row["class"] == "malware"):
            raise ValueError("Label/class disagreement")
        unit_key(row)


def balanced_split(rows):
    check_identities(rows)
    units = sorted({unit_key(row) for row in rows})
    index = {name: position for position, name in enumerate(units)}
    strata = []
    hard = []
    fixed_training = set()
    for scope in ("all_host_eligible", "common_aligned"):
        subset = rows if scope == "all_host_eligible" else [row for row in rows if existing.aligned(row)]
        if not subset:
            continue
        groups = defaultdict(list)
        modes = defaultdict(list)
        for row in subset:
            groups[row["group_id"]].append(row)
            modes[(row["class"], row["mode"])].append(row)
        for label in (0, 1):
            selected = [row for row in subset if row["label"] == label]
            target = len(selected) // 2
            if not selected or target == 0:
                raise ValueError("Population too small to split both labels")
            hard.append((selected, target, target))
        for group, members in sorted(groups.items()):
            distinct = {unit_key(row) for row in members}
            if len(distinct) == 1:
                fixed_training.update(distinct)
            else:
                hard.append((members, 1, len(members) - 1))
            strata.append((scope + ":family:" + group, members, 1.0 / len(members)))
        for mode, members in sorted(modes.items()):
            if len({unit_key(row) for row in members}) >= 2:
                hard.append((members, 1, len(members) - 1))
            strata.append((scope + ":mode:" + str(mode), members, 2.0 / len(members)))
    width = len(units) + len(strata)
    constraints, lower, upper = [], [], []

    def coefficients(members):
        vector = np.zeros(width)
        for row in members:
            vector[index[unit_key(row)]] += 1
        return vector

    for members, minimum, maximum in hard:
        constraints.append(coefficients(members))
        lower.append(minimum)
        upper.append(maximum)
    cost = np.zeros(width)
    cost[:len(units)] = np.random.default_rng(SEED).uniform(0, 1e-7, len(units))
    for position, (_name, members, weight) in enumerate(strata, len(units)):
        vector = coefficients(members)
        positive, negative = vector.copy(), -vector
        positive[position] = negative[position] = -1
        constraints.extend((positive, negative))
        lower.extend((-np.inf, -np.inf))
        upper.extend((len(members) / 2, -len(members) / 2))
        cost[position] = weight
    minimum = np.zeros(width)
    maximum = np.concatenate((np.ones(len(units)), np.full(len(strata), np.inf)))
    for name in fixed_training:
        minimum[index[name]] = 1
    result = milp(cost, integrality=np.concatenate((np.ones(len(units)), np.zeros(len(strata)))),
        bounds=Bounds(minimum, maximum), constraints=LinearConstraint(np.asarray(constraints), lower, upper),
        options={"mip_rel_gap": 0.0})
    if not result.success:
        raise ValueError("Requested independent-unit coverage/balance infeasible: " + result.message)
    assignment = {name: "training" if result.x[position] >= 0.5 else "validation" for name, position in index.items()}
    output = [{**row, "original_split": row.get("split", ""), "split": assignment[unit_key(row)], "split_unit": unit_key(row)} for row in rows]
    coverage = []
    for scope in ("all_host_eligible", "common_aligned"):
        subset = output if scope == "all_host_eligible" else [row for row in output if existing.aligned(row)]
        for group in sorted({row["group_id"] for row in subset}):
            members = [row for row in subset if row["group_id"] == group]
            training = sum(row["split"] == "training" for row in members)
            distinct = len({row["split_unit"] for row in members})
            if distinct > 1 and (training == 0 or training == len(members)):
                raise AssertionError("Feasible family missing from a partition")
            coverage.append({"scope": scope, "group_id": group, "cases": len(members), "independent_units": distinct,
                "training": training, "validation": len(members) - training,
                "coverage": "both" if 0 < training < len(members) else "one_unit_training_only"})
    return output, coverage, {"method": "scipy.optimize.milp", "seed": SEED, "status": result.message,
        "objective": float(result.fun), "mip_gap": float(result.mip_gap), "units": len(units)}


def save_rows(path, rows):
    if not rows:
        raise ValueError("Refusing empty CSV")
    with path.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def load_rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def source_rows():
    existing.verify_inputs()
    manifest = ready.load(SOURCE / "combined_manifest.json")
    for name, checksum in manifest["data_hashes"].items():
        if ready.digest(SOURCE / "analysis" / name) != checksum:
            raise ValueError("Source prepared artifact changed: " + name)
    if ready.digest(SOURCE / "analysis/model-fit/metrics.json") != "a2a770501763a5634658173788e81386774f688dc41adf3b1253c92da3a3835c":
        raise ValueError("Source model result changed")
    rows = load_rows(SOURCE / "analysis/eligible_dataset.csv")
    for row in rows:
        row["label"] = int(row["label"])
        for key in ("position", "post_target_lineage_raw_syscalls", "watched_path_count"):
            row[key] = int(row[key])
        metadata_path = ready.STUDY / row["source_run_dir"] / "run.json"
        if ready.digest(metadata_path) != row["source_metadata_sha256"]:
            raise ValueError("Source metadata changed")
        metadata = ready.load(metadata_path)
        if any(metadata.get(key) != value for key, value in existing.combined.EXPECTED_SETTINGS.items()):
            raise ValueError("Nonaccepted/incompatible capture reached source")
        if metadata["target_exec"]["status"] != "observed" or metadata["target_exec"]["match"] != "exact":
            raise ValueError("Exact target execution missing")
    check_identities(rows)
    return rows


def prepare():
    rows = source_rows()
    attempt = OUTPUT / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    trainer, _, _ = existing.combined.frozen.dependencies()
    files = [Path(__file__), Path(trainer.__file__), SOURCE / "combined_manifest.json", SOURCE / "protocol.json",
        SOURCE / "analysis/eligible_dataset.csv", SOURCE / "analysis/model-fit/metrics.json", trainer.HOST_FEATURE_PATH]
    files.extend(sorted((SOURCE / "analysis/model-fit").glob("*.joblib")))
    protocol = {"authorization": "User requested the proposed evenly spread within-family exploratory resplit",
        "frozen_utc": datetime.now(timezone.utc).isoformat(), "role": "Post-hoc known-family/program-disjoint exploratory evaluation, NOT blind or unseen-family generalization",
        "source": str(SOURCE.relative_to(ready.STUDY)), "source_cases": len(rows),
        "common_cases": sum(existing.aligned(row) for row in rows), "training_fraction_target": 0.5,
        "split_rule": "Floor half of each label in training, independently for full host and common-feature populations; feasible families/projects in both; unsplittable units training-only",
        "units": "Malware exact executable identities; benign project/program blocks keep architecture/build variants together",
        "balancing": "Use every eligible case once, no oversampling/downsampling; optimize metadata-only family/mode proportions without looking at scores",
        "primary": "Balanced accuracy on the common-aligned identical validation population",
        "rf": {"n_estimators": 500, "class_weight": "balanced", "random_state": 42, "n_jobs": 1, "max_features": "sqrt", "threshold": 0.5},
        "feature_columns": {"p4": 145, "host": 145, "hybrid": 290},
        "selection": "Training-only mutual information selects 29 complete host families; no validation tuning or seed search",
        "secondary": "Training-only family-grouped OOF, activity/nuisance controls, equal-group metrics, per-mode/group metrics and paired 2000 group-bootstrap replicates; no new permutation/significance claim",
        "excluded_groups": sorted(existing.combined.EXCLUDED_GROUPS),
        "limitations": ["All data were already examined; original validation is consumed",
            "Within-family split intentionally shares family/project labels, unlike previous unseen-family evaluations",
            "Exact identity and benign program leakage controlled; malware near-duplicate/lineage separation NOT certified",
            "Singleton groups cannot occur on both sides; no synthetic duplication to hide this",
            "Attack categories are not independently verified and are not inferred from signature names",
            "Task/toolchain/acquisition/background-traffic confounding remains; no new captures or traffic filtering"],
        "source_hashes": {str(path.relative_to(ready.STUDY)): ready.digest(path) for path in files}}
    ready.save(attempt / "protocol.json", protocol)
    split, coverage, solver = balanced_split(rows)
    save_rows(attempt / "split_dataset.csv", split)
    save_rows(attempt / "coverage.csv", coverage)
    counts = {scope: {partition: dict(Counter(row["class"] for row in split if row["split"] == partition and (scope == "all_host_eligible" or existing.aligned(row))))
        for partition in ("training", "validation")} for scope in ("all_host_eligible", "common_aligned")}
    ready.save(attempt / "split_audit.json", {"status": "prepared", "counts": counts, "solver": solver,
        "singleton_exceptions": [row for row in coverage if row["coverage"] != "both"],
        "identity_overlap": 0, "program_unit_overlap": 0,
        "original_artifacts_modified": False, "sample_executions": 0, "vm_operations": 0,
        "split_sha256": ready.digest(attempt / "split_dataset.csv"), "coverage_sha256": ready.digest(attempt / "coverage.csv")})
    print(json.dumps({"attempt": str(attempt), "counts": counts, "solver": solver}), flush=True)
    return attempt


def verify_prepared(attempt):
    protocol = ready.load(attempt / "protocol.json")
    for name, checksum in protocol["source_hashes"].items():
        if ready.digest(ready.STUDY / name) != checksum:
            raise ValueError("Frozen source/model changed: " + name)
    audit = ready.load(attempt / "split_audit.json")
    for filename, key in (("split_dataset.csv", "split_sha256"), ("coverage.csv", "coverage_sha256")):
        if ready.digest(attempt / filename) != audit[key]:
            raise ValueError("Frozen split/coverage changed")
    rows = load_rows(attempt / "split_dataset.csv")
    for row in rows:
        row["label"] = int(row["label"])
        row["post_target_lineage_raw_syscalls"] = int(row["post_target_lineage_raw_syscalls"])
        row["position"] = int(row["position"])
    check_identities(rows)
    training_units = {row["split_unit"] for row in rows if row["split"] == "training"}
    validation_units = {row["split_unit"] for row in rows if row["split"] == "validation"}
    if training_units & validation_units or any(row["split_unit"] != unit_key(row) for row in rows):
        raise ValueError("Split-unit leakage or identity disagreement")
    if any(row["split"] not in ("training", "validation") for row in rows):
        raise ValueError("Unrecognized split")
    return rows, protocol


def train(attempt):
    rows, protocol = verify_prepared(attempt)
    output = attempt / "model-fit"
    output.mkdir(exist_ok=False)
    trainer, _, _ = existing.combined.frozen.dependencies()
    features = ready.load(trainer.HOST_FEATURE_PATH)["host"]
    common = [row for row in rows if existing.aligned(row)]
    training = [row for row in common if row["split"] == "training"]
    validation = [row for row in common if row["split"] == "validation"]
    labels = np.asarray([row["label"] for row in validation])
    training_labels = np.asarray([row["label"] for row in training])
    print("Fitting fixed primary RF500 models; held-out scores not used for selection", flush=True)
    probabilities, selection, details = trainer.fit_final_models(training, validation, features, output, "within_family_exploratory")
    ready.save(output / "selected_features.json", details)
    save_rows(output / "host_family_selection.csv", selection)
    primary = {name: trainer.binary_metrics(labels, values) for name, values in probabilities.items()}
    trainer.save_predictions(output / "validation_predictions.csv", validation, probabilities, "exploratory_known_family_validation")
    print("Running training-only grouped OOF and predeclared nuisance/activity controls", flush=True)
    oof, selections, folds = trainer.grouped_oof_main(training, features, training_labels)
    trainer.save_predictions(output / "training_oof_predictions.csv", training, oof, "training_family_grouped_oof_different_estimand")
    save_rows(output / "training_fold_selection.csv", selections)
    save_rows(output / "training_folds.csv", folds)
    auxiliary = trainer.fit_auxiliary_models(training, validation, output)
    trainer.save_predictions(output / "auxiliary_predictions.csv", validation, auxiliary, "exploratory_nuisance_controls")
    all_training = [row for row in rows if row["split"] == "training"]
    all_validation = [row for row in rows if row["split"] == "validation"]
    host_scores, _, _ = trainer.fit_host_sensitivity(all_training, all_validation, features, output)
    host_metrics = trainer.binary_metrics(np.asarray([row["label"] for row in all_validation]), host_scores)
    trainer.save_predictions(output / "host_all_eligible_predictions.csv", all_validation, {"host_all_eligible": host_scores}, "different_population_sensitivity")
    weights = trainer.equal_group_weights(validation)
    group_weighted = {name: trainer.binary_metrics(labels, values, weights) for name, values in probabilities.items()}
    per_group, per_mode = {}, {}
    for field, target in (("group_id", per_group), ("mode", per_mode)):
        for value in sorted({row[field] for row in validation}):
            indices = np.asarray([index for index, row in enumerate(validation) if row[field] == value])
            if len(set(labels[indices])) == 2:
                target[value] = {name: trainer.binary_metrics(labels[indices], scores[indices]) for name, scores in probabilities.items()}
            else:
                target[value] = {name: {"samples": len(indices), "correct": int(np.sum((scores[indices] >= 0.5) == labels[indices])),
                    "label": int(labels[indices][0])} for name, scores in probabilities.items()}
    print("Computing paired group-bootstrap differences without refitting", flush=True)
    vectors = trainer.bootstrap_weight_vectors(validation)
    paired_delta = []
    for vector in vectors:
        host_ba = trainer.binary_metrics(labels, probabilities["host_29_families"], vector)["balanced_accuracy"]
        hybrid_ba = trainer.binary_metrics(labels, probabilities["hybrid_29_plus_29"], vector)["balanced_accuracy"]
        paired_delta.append(hybrid_ba - host_ba)
    metrics = {"role": protocol["role"], "status": "complete", "counts": ready.load(attempt / "split_audit.json")["counts"],
        "primary_validation": primary, "equal_group_weighted_validation": group_weighted,
        "training_family_grouped_oof": {name: trainer.binary_metrics(training_labels, values) for name, values in oof.items()},
        "training_oof_scope": "Family/project-disjoint within training; different estimand from known-family final validation",
        "activity_nuisance_validation": {name: trainer.binary_metrics(labels, values) for name, values in auxiliary.items()},
        "host_all_eligible_sensitivity": host_metrics, "per_group": per_group, "per_mode": per_mode,
        "paired_hybrid_minus_host_ba": {"observed": primary["hybrid_29_plus_29"]["balanced_accuracy"] - primary["host_29_families"]["balanced_accuracy"],
            "replicates": len(vectors), "group_bootstrap_95pct_interval": [float(np.quantile(paired_delta, 0.025)), float(np.quantile(paired_delta, 0.975))],
            "interpretation": "Descriptive post-hoc interval, not confirmatory significance"},
        "feature_columns": protocol["feature_columns"], "limitations": protocol["limitations"],
        "activity_nuisance_sample_ba_ge_075": any(trainer.binary_metrics(labels, values)["balanced_accuracy"] >= 0.75 for values in auxiliary.values()),
        "model_hashes": {path.name: ready.digest(path) for path in sorted(output.glob("*.joblib"))}}
    ready.save(output / "metrics.json", metrics)
    verification = verify(attempt)
    ready.save(output / "verification.json", verification)
    report(attempt, metrics)
    ready.save(attempt / "status.json", {"stage": "complete", "metrics_sha256": ready.digest(output / "metrics.json"),
        "verification_sha256": ready.digest(output / "verification.json"), "sample_executions": 0, "vm_operations": 0})
    print(json.dumps({"attempt": str(attempt), "primary_validation": primary, "paired_delta": metrics["paired_hybrid_minus_host_ba"]}), flush=True)


def verify(attempt):
    rows, protocol = verify_prepared(attempt)
    trainer, _, _ = existing.combined.frozen.dependencies()
    output = attempt / "model-fit"
    metrics = ready.load(output / "metrics.json")
    validation = [row for row in rows if row["split"] == "validation" and existing.aligned(row)]
    training = [row for row in rows if row["split"] == "training" and existing.aligned(row)]
    labels = np.asarray([row["label"] for row in validation])
    details = ready.load(output / "selected_features.json")
    host_features = ready.load(trainer.HOST_FEATURE_PATH)["host"]
    families, _, _ = trainer.feature_family_selection(trainer.matrix(training, host_features), np.asarray([row["label"] for row in training]), host_features)
    if families != details["selected_host_families"]:
        raise ValueError("Training-only selection does not reproduce")
    host = trainer.matrix(validation, details["selected_host_features"])
    network = trainer.matrix(validation, trainer.p4.P4_SAMPLE_FEATURES)
    matrices = {"network_p4": network, "host_29_families": host, "hybrid_29_plus_29": np.hstack((network, host))}
    predictions = load_rows(output / "validation_predictions.csv")
    max_error = 0.0
    for name, matrix in matrices.items():
        path = output / (name + ".joblib")
        if ready.digest(path) != metrics["model_hashes"][path.name]:
            raise ValueError("Saved model hash differs")
        estimator = trainer.joblib.load(path)
        forest = estimator.named_steps["randomforestclassifier"]
        if matrix.shape[1] != (290 if name == "hybrid_29_plus_29" else 145) or estimator.n_features_in_ != matrix.shape[1]:
            raise ValueError("Fitted feature width differs")
        if any(forest.get_params()[key] != value for key, value in protocol["rf"].items() if key != "threshold"):
            raise ValueError("Saved RF configuration differs")
        scores = estimator.predict_proba(matrix)[:, 1]
        if trainer.binary_metrics(labels, scores) != metrics["primary_validation"][name]:
            raise ValueError("Saved metrics do not reproduce")
        selected = [row for row in predictions if row["model"] == name]
        if len(selected) != len(validation):
            raise ValueError("Missing or duplicate primary predictions")
        indexed = {row["sample"]: row for row in selected}
        if len(indexed) != len(validation):
            raise ValueError("Duplicate primary predictions")
        for index, row in enumerate(validation):
            max_error = max(max_error, abs(float(indexed[row["sample"]]["probability_malware"]) - scores[index]))
    if max_error != 0:
        raise ValueError("Saved probabilities differ")
    verify_prepared(attempt)
    return {"status": "verified", "primary_cases": len(validation), "model_widths": [145, 145, 290],
        "maximum_probability_error": max_error, "training_only_selection_reproduced": True,
        "original_sources_and_models_unchanged": True, "split_unit_overlap": 0}


def report(attempt, metrics):
    coverage = load_rows(attempt / "coverage.csv")
    common = [row for row in coverage if row["scope"] == "common_aligned"]
    counts = metrics["counts"]["common_aligned"]
    lines = ["# Within-Family Exploratory Resplit", "", "## Scope", "",
        "User-authorized offline reallocation and fixed-model refit. Original data, splits, models and production collector are unchanged. No VM, sample execution or new collection occurred.", "",
        "This answers known-family/project evaluation, NOT unseen-family generalization. All data were already examined, so this is post-hoc exploratory rather than fresh blind validation.", "",
        "## Split", "", f"Primary training: {counts['training']}. Primary validation: {counts['validation']}.",
        "All366 common-aligned cases are used once; all417 host-eligible cases remain in a separately labeled sensitivity analysis. Exact class halves differ by at most one case. No oversampling or deletion to force equal class totals.",
        "Benign project/program units keep architecture/build variants together. Malware hashes are distinct, but near-duplicate malware lineages have NOT been certified disjoint.", "",
        "Both-side primary coverage: " + str(sum(row["coverage"] == "both" and row["group_id"].startswith("malware_signature::") for row in common)) + "/20 malware signatures and " + str(sum(row["coverage"] == "both" and row["group_id"].startswith("benign_project::") for row in common)) + "/36 benign projects.",
        "Remaining unsplittable groups are training-only; duplicating them into validation would leak samples. Full assignments and exceptions are in [coverage.csv](coverage.csv) and [split_dataset.csv](split_dataset.csv). Attack categories are not independently verified or invented from family names.", "",
        "## Primary Results", "", "| Model | Accuracy | Balanced Accuracy | ROC-AUC | TN / FP / FN / TP |", "| --- | ---: | ---: | ---: | --- |"]
    for name, values in metrics["primary_validation"].items():
        lines.append(f"| {name} | {values['accuracy']:.4%} | {values['balanced_accuracy']:.4%} | {values['roc_auc']:.6f} | " + " / ".join(str(int(value)) for value in values['confusion_matrix_tn_fp_fn_tp']) + " |")
    delta = metrics["paired_hybrid_minus_host_ba"]
    lines += ["", "Hybrid minus host balanced accuracy: " + f"{delta['observed'] * 100:.4f} percentage points; paired group-bootstrap95% descriptive interval " + str([round(value * 100, 4) for value in delta['group_bootstrap_95pct_interval']]) + ".",
        "", "## Controls And Limitations", "",
        "Fixed RF500/balanced/seed42/n_jobs1/sqrt/threshold0.5; training-only MI selects29 complete host families. P4/host/hybrid widths145/145/290. One frozen metadata-only optimized split; no search for favorable scores.",
        "Equal-group weighting, per-mode/per-group results, training-only family-grouped OOF and activity/nuisance baselines are in [model-fit/metrics.json](model-fit/metrics.json). OOF tests unseen training groups and is a different estimand from the final known-family split. The host-all-eligible sensitivity uses a different population and is not the primary sensor comparison.",
        "The previous attribution pilot found unrelated background connectivity traffic in all controls. Resplitting does not repair that issue. Family concentration, related malware, task/toolchain/acquisition shortcuts, tiny groups and selection bias remain. This result cannot establish that balancing caused a model improvement or that one method generally outperforms another.", "",
        "## Reproduction And Evidence", "",
        "Run the owning script with --self-test, --prepare-only, then --train <prepared-attempt>. --verify <attempt> checks source/model/split hashes, zero split-unit overlap, training-only selection, actual fitted widths/settings and exact saved probabilities. Original protocol/result/model hashes are frozen in [protocol.json](protocol.json).", "",
        "Metrics SHA-256: `" + ready.digest(attempt / "model-fit/metrics.json") + "`.", ""]
    with (attempt / "REPORT.md").open("x") as stream:
        stream.write("\n".join(lines))


def self_test():
    rows = []
    for label in (0, 1):
        for position in range(8):
            rows.append({"sample": f"case-{label}-{position}", "class": "malware" if label else "benign",
                "label": label, "executable_sha256": f"hash-{label}-{position}", "group_id": f"group-{label}",
                "program": "repeated" if position < 2 else f"program-{position}", "split": "old",
                "mode": "native_amd64_static", "p4_alignment_status": "unique", "p4_parity": "True"})
    first, coverage, _ = balanced_split(rows)
    second, _, _ = balanced_split(list(reversed(rows)))
    assert {row["sample"]: row["split"] for row in first} == {row["sample"]: row["split"] for row in second}
    assert all(row["training"] == row["validation"] == 4 for row in coverage)
    assert first[0]["split"] == first[1]["split"]
    for key in ("sample", "executable_sha256"):
        invalid = [dict(row) for row in rows]
        invalid[-1][key] = invalid[0][key]
        try:
            balanced_split(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Duplicate identity was accepted")
    singletons = [dict(row) for row in rows]
    for label in (0, 1):
        singletons[label * 8 + 7]["group_id"] = f"singleton-{label}"
    singleton_split, singleton_coverage, _ = balanced_split(singletons)
    assert all(row["split"] == "training" for row in singleton_split if row["group_id"].startswith("singleton"))
    assert sum(row["coverage"] == "one_unit_training_only" for row in singleton_coverage) == 4
    trainer, _, _ = existing.combined.frozen.dependencies()
    features = ready.load(trainer.HOST_FEATURE_PATH)["host"]
    generator = np.random.default_rng(SEED)
    for row in first:
        row.update(dict(zip(features, generator.random(len(features)), strict=True)))
        row.update(dict(zip(trainer.p4.P4_SAMPLE_FEATURES, generator.random(145), strict=True)))
    with tempfile.TemporaryDirectory(prefix="known-family-synthetic-") as directory:
        output = Path(directory)
        fitted, _, details = trainer.fit_final_models([row for row in first if row["split"] == "training"],
            [row for row in first if row["split"] == "validation"], features, output, "synthetic_test_only")
        assert len(details["selected_host_features"]) == 145
        for name, scores in fitted.items():
            estimator = trainer.joblib.load(output / (name + ".joblib"))
            assert estimator.n_features_in_ == (290 if name == "hybrid_29_plus_29" else 145)
            assert np.isfinite(scores).all()
    print("PASS: deterministic balance, singleton handling, program blocking, duplicate rejection and synthetic RF500 fits at145/145/290 columns")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--train", type=Path)
    parser.add_argument("--verify", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    elif options.prepare_only:
        prepare()
    elif options.train:
        train(options.train.resolve())
    elif options.verify:
        print(json.dumps(verify(options.verify.resolve()), indent=2))
    else:
        parser.error("Choose --self-test, --prepare-only, --train or --verify")


if __name__ == "__main__":
    main()