#!/usr/bin/env python3
"""Read-only investigation of saved activity predictions and host-vector collisions."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

import explore_within_family_split as experiment

SOURCE = experiment.OUTPUT / "20261022T103648547175Z"
ACTIVITY_EDGES = (0, 20, 45, 100, 1000, 10000, float("inf"))


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def vector(row, features):
    values = tuple(float(row[key]) for key in features)
    if not np.isfinite(values).all():
        raise ValueError("Nonfinite feature vector")
    return values


def collisions(rows, features):
    groups = defaultdict(list)
    for row in rows:
        groups[vector(row, features)].append(row)
    return [members for members in groups.values() if {row["split"] for row in members} == {"training", "validation"}]


def prediction_index(records):
    result = {}
    for row in records:
        key = (row["model"], row["sample"])
        if key in result:
            raise ValueError("Duplicate model/sample prediction")
        if row["split"] != "validation":
            raise ValueError("Nonvalidation prediction in validation audit")
        probability = float(row["probability_malware"])
        if not np.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("Invalid saved probability")
        result[key] = row
    return result


def saved_metrics(rows, predictions, model, trainer, weights=None):
    labels, values = [], []
    for row in rows:
        prediction = predictions[(model, row["sample"])]
        if int(prediction["label"]) != row["label"] or prediction["group_id"] != row["group_id"]:
            raise ValueError("Prediction label/group mismatch")
        labels.append(row["label"])
        values.append(float(prediction["probability_malware"]))
    if not rows:
        return {"samples": 0}
    labels, values = np.asarray(labels), np.asarray(values)
    if len(set(labels)) < 2:
        return {"samples": len(rows), "label": int(labels[0]), "correct": int(np.sum((values >= 0.5) == labels))}
    return trainer.binary_metrics(labels, values, weights)


def raw_evidence(row, input_hashes):
    root = experiment.ready.STUDY / row["source_run_dir"]
    paths = [root / name for name in ("run.json", "exec_events.csv", "syscall_events.csv", "ebpf_events.csv")]
    for path in paths:
        input_hashes[str(path.relative_to(experiment.ready.STUDY))] = experiment.ready.digest(path)
    metadata = experiment.ready.load(root / "run.json")
    root_pid = int(metadata["sample_root_pid"])
    expected_path = metadata["target_exec"]["expected_path"]
    exec_rows = experiment.load_rows(root / "exec_events.csv")
    successes = [event for event in exec_rows if event["event"] == "exec_success" and int(event["pid"]) == root_pid
        and event["detail"].partition("filename=")[2] == expected_path]
    if len(successes) != 1:
        raise ValueError("Exact target boundary is not unique")
    boundary = int(successes[0]["timestamp_ns"])
    after = []
    before = []
    for event in experiment.load_rows(root / "syscall_events.csv"):
        fields = dict(part.split("=", 1) for part in event["detail"].split() if "=" in part)
        call = int(fields["id"])
        item = (int(event["window_id"]), "root" if int(event["pid"]) == root_pid else "descendant", call)
        (after if int(event["timestamp_ns"]) > boundary else before).append(item)
    if len(after) != int(row["post_target_lineage_raw_syscalls"]) or len(after) != metadata["target_exec"]["post_target_lineage_raw_syscalls"]:
        raise ValueError("Archived post-target activity does not reconcile")
    events = experiment.load_rows(root / "ebpf_events.csv")
    named_before = Counter(event["event"] for event in events if int(event["timestamp_ns"]) <= boundary)
    named_after = Counter(event["event"] for event in events if int(event["timestamp_ns"]) > boundary)
    histogram = Counter(item[2] for item in after)
    by_window = Counter((item[0], item[2]) for item in after)
    pid_counts = Counter(item[1] for item in after)
    return {"sample": row["sample"], "split": row["split"], "group_id": row["group_id"], "mode": row["mode"],
        "cohort": row["cohort"], "source_run_dir": row["source_run_dir"], "target_timestamp_ns": boundary,
        "post_target_calls": len(after), "pre_target_calls": len(before), "post_target_root_descendant_counts": dict(pid_counts),
        "syscall_ids_after_target": dict(sorted(histogram.items())), "syscall_histogram_sha256": fingerprint(sorted(histogram.items())),
        "syscall_window_histogram_sha256": fingerprint(sorted(by_window.items())),
        "syscall_archived_sequence_sha256": fingerprint(after), "named_events_before_target": dict(named_before),
        "named_events_after_target": dict(named_after), "return_code": row["return_code"],
        "raw_identity_note": "Numeric IDs compared within the same native ABI only; canonical sequence retains CSV order/window/root-vs-descendant, omits timestamps, PID and arguments"}


def audit():
    rows, source_protocol = experiment.verify_prepared(SOURCE)
    common = [row for row in rows if experiment.existing.aligned(row)]
    trainer, data, _ = experiment.existing.combined.frozen.dependencies()
    selected = experiment.ready.load(SOURCE / "model-fit/selected_features.json")["selected_host_features"]
    host_features = experiment.ready.load(trainer.HOST_FEATURE_PATH)["host"]
    metrics = experiment.ready.load(SOURCE / "model-fit/metrics.json")
    for filename, checksum in metrics["model_hashes"].items():
        if experiment.ready.digest(SOURCE / "model-fit" / filename) != checksum:
            raise ValueError("Source model changed")
    fixed_files = [Path(__file__), SOURCE / "protocol.json", SOURCE / "split_dataset.csv", SOURCE / "coverage.csv",
        SOURCE / "model-fit/metrics.json", SOURCE / "model-fit/selected_features.json", SOURCE / "model-fit/validation_predictions.csv",
        SOURCE / "model-fit/auxiliary_predictions.csv", Path(trainer.__file__), Path(data.__file__)]
    input_hashes = {str(path.relative_to(experiment.ready.STUDY)): experiment.ready.digest(path) for path in fixed_files}
    attempt = SOURCE / "activity-vector-investigation" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    experiment.ready.save(attempt / "protocol.json", {"scope": "Read-only post-hoc diagnostic; no refit, new model predictions, threshold selection, split change or sample execution",
        "source": str(SOURCE.relative_to(experiment.ready.STUDY)), "frozen_utc": datetime.now(timezone.utc).isoformat(),
        "checks": ["Full/selected host and network collision groups", "Raw telemetry reaggregation for all common cases",
            "Post-target raw-event reconciliation and pre-target named counts for every selected-host collision member",
            "Saved predictions by overlap and fixed activity range", "Activity common-support reweighting of saved predictions only"],
        "activity_bin_edges": [0, 20, 45, 100, 1000, 10000, "infinity"],
        "caution": "Subsets/reweighting are descriptive, not corrected performance or model comparisons on fresh data; no removal from original dataset",
        "initial_source_hashes": dict(input_hashes), "inherited_limitations": source_protocol["limitations"]})
    primary = prediction_index(experiment.load_rows(SOURCE / "model-fit/validation_predictions.csv"))
    auxiliary = prediction_index(experiment.load_rows(SOURCE / "model-fit/auxiliary_predictions.csv"))
    predictions = {**primary, **auxiliary}
    validation = [row for row in common if row["split"] == "validation"]
    models = (*trainer.EXPECTED_MODELS, "activity_only", "nuisance_only")
    for name in trainer.EXPECTED_MODELS:
        if saved_metrics(validation, predictions, name, trainer) != metrics["primary_validation"][name]:
            raise ValueError("Original primary metrics do not reproduce")
    for name in ("activity_only", "nuisance_only"):
        if saved_metrics(validation, predictions, name, trainer) != metrics["activity_nuisance_validation"][name]:
            raise ValueError("Original control metrics do not reproduce")
    cases, group_details = [], []
    selected_groups = collisions(common, selected)
    comparisons = 0
    for row in common:
        root = experiment.ready.STUDY / row["source_run_dir"]
        path = root / "telemetry.csv"
        input_hashes[str(path.relative_to(experiment.ready.STUDY))] = experiment.ready.digest(path)
        telemetry = experiment.load_rows(path)
        if len(telemetry) != 40:
            raise ValueError("Telemetry length differs")
        families = sorted({feature.rpartition("__")[0] for feature in host_features})
        for family in families:
            values = [float(window[family.removeprefix("host__")]) for window in telemetry]
            aggregates = data.aggregate(values)
            for suffix, expected in aggregates.items():
                key = family + "__" + suffix
                if not np.isclose(float(row[key]), expected, rtol=1e-9, atol=1e-9):
                    raise ValueError("Telemetry/feature mismatch: " + row["sample"] + " " + key)
                comparisons += 1
    for number, members in enumerate(selected_groups, 1):
        evidence = [raw_evidence(row, input_hashes) for row in members]
        for item in evidence:
            item["collision_group"] = number
            cases.append(item)
        full_vectors = {vector(row, host_features) for row in members}
        omitted_differences = [feature for feature in host_features if feature not in selected and len({float(row[feature]) for row in members}) > 1]
        group_details.append({"collision_group": number, "samples": len(members), "training": sum(row["split"] == "training" for row in members),
            "validation": sum(row["split"] == "validation" for row in members), "labels": dict(Counter(row["class"] for row in members)),
            "groups": dict(Counter(row["group_id"] for row in members)), "modes": sorted({row["mode"] for row in members}),
            "full_host175_distinct_vectors": len(full_vectors), "omitted_host_columns_with_variation": omitted_differences,
            "post_target_call_counts": sorted({item["post_target_calls"] for item in evidence}),
            "post_target_histogram_distinct": len({item["syscall_histogram_sha256"] for item in evidence}),
            "post_target_window_histogram_distinct": len({item["syscall_window_histogram_sha256"] for item in evidence}),
            "post_target_archived_sequence_distinct": len({item["syscall_archived_sequence_sha256"] for item in evidence})})
    experiment.ready.save(attempt / "raw_collision_cases.json", cases)
    experiment.ready.save(attempt / "collision_groups.json", group_details)
    overlap_names = {row["sample"] for members in selected_groups for row in members if row["split"] == "validation"}
    overlap, nonoverlap = [row for row in validation if row["sample"] in overlap_names], [row for row in validation if row["sample"] not in overlap_names]
    overlap_metrics = {scope: {name: saved_metrics(subset, predictions, name, trainer) for name in models}
        for scope, subset in (("overlap", overlap), ("nonoverlap", nonoverlap))}
    activity = []
    for field in ("class", "group_id", "mode", "cohort"):
        for split in ("training", "validation"):
            for value in sorted({row[field] for row in common}):
                subset = [row for row in common if row["split"] == split and row[field] == value]
                if not subset:
                    continue
                counts = np.asarray([int(row["post_target_lineage_raw_syscalls"]) for row in subset])
                activity.append({"field": field, "value": value, "split": split, "samples": len(subset),
                    "min": int(counts.min()), "median": float(np.median(counts)), "max": int(counts.max()),
                    "q10": float(np.quantile(counts, .1)), "q90": float(np.quantile(counts, .9)),
                    "zero_activity": int(np.sum(counts == 0)), "calls_at_most45": int(np.sum(counts <= 45)),
                    "models": {name: saved_metrics(subset, predictions, name, trainer) for name in models} if split == "validation" else {}})
    bins = []
    cell_indices = defaultdict(list)
    for lower, upper in zip(ACTIVITY_EDGES, ACTIVITY_EDGES[1:]):
        for mode in sorted({row["mode"] for row in validation}):
            indices = [index for index, row in enumerate(validation) if row["mode"] == mode and lower <= int(row["post_target_lineage_raw_syscalls"]) < upper]
            members = [validation[index] for index in indices]
            if not members:
                continue
            class_counts = Counter(row["class"] for row in members)
            key = f"{mode}:[{lower},{upper})"
            cell_indices[key] = indices
            bins.append({"cell": key, "counts": dict(class_counts), "both_classes": len(class_counts) == 2,
                "models": {name: saved_metrics(members, predictions, name, trainer) for name in models}})
    weights = np.zeros(len(validation))
    for indices in cell_indices.values():
        benign = [index for index in indices if validation[index]["label"] == 0]
        malware = [index for index in indices if validation[index]["label"] == 1]
        if benign and malware:
            mass = min(len(benign), len(malware))
            weights[benign] = mass / len(benign)
            weights[malware] = mass / len(malware)
    if not weights.any():
        raise ValueError("No class/mode/activity common support")
    collision_summary = {}
    for name, features in (("selected_host145", selected), ("all_host175", host_features), ("network145", trainer.p4.P4_SAMPLE_FEATURES),
        ("selected_host_plus_network290", selected + trainer.p4.P4_SAMPLE_FEATURES)):
        groups = collisions(common, features)
        collision_summary[name] = {"cross_partition_groups": len(groups),
            "validation_cases": sum(row["split"] == "validation" for members in groups for row in members),
            "mixed_class_groups": sum(len({row["class"] for row in members}) > 1 for members in groups)}
    result = {"scope": "Read-only diagnostic of saved predictions; no estimator fitted or modified", "primary_cases": len(common),
        "validation_cases": len(validation), "collision_summary": collision_summary, "overlap_metrics": overlap_metrics,
        "telemetry_host_summary_comparisons": comparisons, "raw_collision_cases_reconciled": len(cases),
        "collision_groups_with_raw_histogram_variation": sum(item["post_target_histogram_distinct"] > 1 for item in group_details),
        "collision_groups_with_raw_sequence_variation": sum(item["post_target_archived_sequence_distinct"] > 1 for item in group_details),
        "activity_common_support_reweighting": {"rule": "Fixed mode/activity bins; within each both-label cell equal mass min(n_benign,n_malware), no refit",
            "nonzero_weight_cases": int(np.sum(weights > 0)), "effective_total_weight": float(weights.sum()),
            "metrics": {name: saved_metrics(validation, predictions, name, trainer, weights) for name in models},
            "warning": "Changed post-hoc population/weighting, NOT corrected performance or a causal estimate"},
        "original_files_unchanged": True, "model_fits": 0, "new_predictions": 0, "sample_executions": 0,
        "vm_operations": 0, "malware_near_duplicate_lineages_certified_disjoint": False}
    experiment.ready.save(attempt / "activity_by_stratum.json", activity)
    experiment.ready.save(attempt / "activity_bins.json", bins)
    for name, checksum in input_hashes.items():
        if experiment.ready.digest(experiment.ready.STUDY / name) != checksum:
            raise ValueError("Diagnostic input changed: " + name)
    experiment.verify_prepared(SOURCE)
    experiment.ready.save(attempt / "input_hashes.json", input_hashes)
    experiment.ready.save(attempt / "result.json", result)
    write_report(attempt, result, activity)
    print(json.dumps({"attempt": str(attempt), "result": result}, indent=2))


def write_report(attempt, result, activity):
    lines = ["# Activity Shortcuts And Host-Vector Collisions", "", "Read-only, post-hoc investigation. Original captures, split, models, probabilities and primary results were not changed. No sample execution or VM operation.", "",
        "## Activity", "", "The activity-only model uses exactly log(1 + post-target lineage raw-syscall count), not syscall identities or paths. Activity can reflect the assigned task or execution conditions, not maliciousness.", ""]
    for row in activity:
        if row["field"] == "class":
            lines.append(f"- {row['split']} {row['value']}: n={row['samples']}, median={row['median']}, q10={row['q10']}, q90={row['q90']}, zero={row['zero_activity']}.")
    lines += ["", "Activity-only BA was 82.34% on the original184 validation cases. This breaches the prior0.75 confounding-warning reference and blocks a clean malicious-behavior interpretation.", "",
        "## Vector Collisions", "", "Exact executable hashes and benign program units differ across partitions. They can nevertheless map to identical coarse summaries. A collision does not by itself prove a copied capture, corrupt export, or near-identical executable.", ""]
    for name, stats in result["collision_summary"].items():
        lines.append(f"- {name}: {stats['cross_partition_groups']} cross-split groups, {stats['validation_cases']} validation cases, {stats['mixed_class_groups']} mixed-label groups.")
    lines += ["", f"Reaggregation checked {result['telemetry_host_summary_comparisons']} host-summary cells from recorded telemetry without mismatch. Raw exec/syscall evidence reconciled every collision member: {result['raw_collision_cases_reconciled']} cases. Among collision groups, {result['collision_groups_with_raw_histogram_variation']} had different post-target syscall-ID histograms and {result['collision_groups_with_raw_sequence_variation']} had different canonical raw sequences. See collision_groups.json and raw_collision_cases.json for exact identities, source paths and pre/post-exec counts.", "",
        "## Saved-Score Diagnostics", "", "Overlap/nonoverlap and fixed activity/mode-bin results are in result.json and activity_bins.json. They use saved probabilities only, without refitting, filtering the original dataset or tuning thresholds.", "",
        "| Subset | Cases | P4 BA | Host BA | Hybrid BA | Activity BA |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for subset, models in result["overlap_metrics"].items():
        values = [models[name].get("balanced_accuracy", float("nan")) for name in ("network_p4", "host_29_families", "hybrid_29_plus_29", "activity_only")]
        lines.append(f"| {subset} | {models['host_29_families']['samples']} | " + " | ".join(f"{value:.2%}" for value in values) + " |")
    matched = result["activity_common_support_reweighting"]
    lines += ["", f"Post-hoc equalization within fixed activity/mode cells retains nonzero weight on {matched['nonzero_weight_cases']} of184 cases. It changes the population: NOT a corrected test score, causal estimate or model-selection criterion.", ""]
    for name, values in matched["metrics"].items():
        lines.append(f"- {name}: descriptive weighted BA={values['balanced_accuracy']:.4%}.")
    lines += ["", "## Interpretation And Next Gate", "",
        "High activity-only discrimination confirms activity-label association in these data, not that the host model uses only that shortcut. Identical host-vector overlap makes independence weaker than unique hashes suggest. Removing overlapping validation cases after seeing scores does not create clean validation.",
        "For a future reviewed design, group related malware binaries before splitting, expand independent benign projects with overlapping task/activity ranges, retain startup/low-activity outcomes, and reserve an untouched evaluation. Verify source lineage/near-duplicates statically without executing samples. Compare richer post-target/sequence representations only with training-only selection and explicit new-analysis authorization; never remove features or tune against consumed validation to force a preferred winner.",
        "The existing background-traffic attribution issue remains separate and unresolved. These diagnostics do not certify completeness, malicious activation, causal shortcut dependence or generalization. No new collection or model release is authorized by this report.", ""]
    with (attempt / "REPORT.md").open("x") as stream:
        stream.write("\n".join(lines))


def self_test():
    rows = [{"sample": "first", "split": "training", "feature": 1}, {"sample": "second", "split": "validation", "feature": 1},
        {"sample": "third", "split": "validation", "feature": 2}]
    assert len(collisions(rows, ["feature"])) == 1
    assert fingerprint([(0, "root", 1)]) != fingerprint([(0, "root", 2)])
    record = {"model": "host", "sample": "sample", "split": "validation", "probability_malware": "0.5"}
    assert len(prediction_index([record])) == 1
    for invalid in ([record, record], [{**record, "split": "training"}], [{**record, "probability_malware": "nan"}]):
        try:
            prediction_index(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid prediction accepted")
    print("PASS: exact collisions, raw fingerprints, duplicate/split/nonfinite prediction guards")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        audit()


if __name__ == "__main__":
    main()