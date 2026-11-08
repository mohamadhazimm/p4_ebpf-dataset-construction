#!/usr/bin/env python3
"""Audit and analyze existing cohorts without operating a VM or changing captures."""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import run_i386_holdout_collection as frozen


ROOT = Path(__file__).resolve().parent
OLD = frozen.LEGACY
NEW = frozen.RELEASE / "collection/derived-analysis/20261022T042419139084Z"
EXCLUDED_GROUPS = {"malware_signature::DDoSAgent", "benign_project::util-linux"}
EXPECTED_SETTINGS = {
    "telemetry_schema_version": "2026-10-20.18",
    "malware_runner_sha256": "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49",
    "timeout_seconds": 20.0,
    "window_seconds": 0.5,
    "observation_mode": "fixed",
    "common_launch_wrapper": True,
    "interface": "enp0s3",
    "packet_capture_buffer_kb_requested": 65536,
    "packet_capture_drain_ms": 1000,
    "packet_capture_immediate_mode": True,
    "bpftrace_perf_rb_pages": 16384,
    "p4_network_active_ttl_windows": 3,
    "windows": 40,
    "collection_quality_status": "accepted",
    "ebpf_status": "active",
    "packet_capture_status": "active",
    "ebpf_lost_event_count": 0,
    "packet_capture_dropped_by_kernel": 0,
    "packet_capture_counter_discrepancy": 0,
}


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        return list(reader), list(reader.fieldnames or [])


def populations(rows):
    return {split: {
        "samples": len(subset := [row for row in rows if row["split"] == split]),
        "labels": dict(Counter(row["class"] for row in subset)),
        "groups": len({row["group_id"] for row in subset}),
        "strata": {mode: dict(Counter(row["class"] for row in subset if row["mode"] == mode))
                   for mode in sorted({row["mode"] for row in subset})},
    } for split in ("training", "validation")}


def audit():
    trainer, data, _ = frozen.dependencies()
    new_manifest = json.loads((NEW / "derived_manifest.json").read_text())
    frozen.verify_hashes(new_manifest["frozen_workflow_hashes"])
    old_audit = json.loads((OLD / "analysis/preparation_audit.json").read_text())
    old_metrics = json.loads((OLD / "analysis/model-fit-r3/metrics.json").read_text())
    new_audit = json.loads((NEW / "analysis/preparation_audit.json").read_text())
    old_workloads_path = OLD.parent.parent / "manifests/benign-workloads.json"
    old_frozen = json.loads((OLD / "frozen_hashes.json").read_text())
    if frozen.digest(old_workloads_path) != old_frozen["manifests/benign-workloads.json"]:
        raise ValueError("Original executable identities changed")
    old_workloads = {case["sample"]: case for case in json.loads(old_workloads_path.read_text())["cases"]}
    new_cases = {case["sample"]: case for case in json.loads((frozen.RELEASE / "case_order.json").read_text())}
    host = list(json.loads(trainer.HOST_FEATURE_PATH.read_text())["host"])
    network = list(data.p4.P4_SAMPLE_FEATURES)
    if len(host) != 175 or len(network) != 145:
        raise ValueError("Feature budgets differ")
    if not all(name.startswith("host__ebpf_") for name in host):
        raise ValueError("Watch-path independence requires explicit review of the host contract")
    if frozen.digest(trainer.HOST_FEATURE_PATH) != old_audit["host_feature_contract_sha256"]:
        raise ValueError("Host contract changed")
    if frozen.digest(Path(data.p4.__file__)) != old_audit["p4_extractor_sha256"]:
        raise ValueError("P4 extractor changed")
    if frozen.digest(OLD / "analysis/eligible_dataset.csv") != old_metrics["data_provenance"]["prepared_dataset_sha256"]:
        raise ValueError("Original x64 dataset changed")
    if frozen.digest(OLD / "analysis/preparation_audit.json") != old_metrics["data_provenance"]["preparation_audit_sha256"]:
        raise ValueError("Original x64 preparation audit changed")
    for name, checksum in new_audit["data_hashes"].items():
        if frozen.digest(NEW / "analysis" / name) != checksum:
            raise ValueError("Expansion prepared data changed: " + name)
    rows, exclusions, evidence = [], [], []
    inputs = {}
    feature_names = set(host + network)
    telemetry_contract = None
    for cohort, dataset, captures in (
        ("native_x64", OLD / "analysis/eligible_dataset.csv", OLD / "collection/runs"),
        ("native_expansion", NEW / "analysis/eligible_dataset.csv", frozen.RELEASE / "collection/runs"),
    ):
        inputs[str(dataset.relative_to(frozen.STUDY))] = frozen.digest(dataset)
        source_rows, fields = read_csv(dataset)
        if {name for name in fields if name.startswith(("host__", "network__"))} != feature_names:
            raise ValueError("Feature columns differ: " + cohort)
        for original in source_rows:
            row = dict(original)
            paths = list((captures / row["sample"]).glob("output/run_*/run.json"))
            if len(paths) != 1:
                raise ValueError("Expected one original run metadata file: " + row["sample"])
            metadata_path = paths[0]
            metadata = json.loads(metadata_path.read_text())
            for key, expected in EXPECTED_SETTINGS.items():
                if metadata.get(key) != expected:
                    raise ValueError(f"{cohort}/{row['sample']}: {key} differs: {metadata.get(key)!r}")
            if metadata["target_exec"]["status"] != "observed":
                raise ValueError("Target execution not observed")
            contract = metadata["telemetry_feature_groups"]
            if telemetry_contract is None:
                telemetry_contract = contract
            elif contract != telemetry_contract:
                raise ValueError("Telemetry feature definitions differ")
            artifact = metadata["target_artifact"]
            if artifact["e_machine"] not in (3, 62) or artifact["linkage"] not in ("static", "dynamic"):
                raise ValueError("Unexpected architecture/linkage")
            architecture = "i386" if artifact["e_machine"] == 3 else "amd64"
            expected_execution = "native_compat" if architecture == "i386" else "native"
            if artifact["execution_mode"] != expected_execution:
                raise ValueError("Non-native target")
            row.update(cohort=cohort, mode=f"native_{architecture}_{artifact['linkage']}",
                       source_run_dir=str(metadata_path.parent.relative_to(frozen.STUDY)),
                       source_metadata_sha256=frozen.digest(metadata_path),
                       watched_path_count=len(metadata["filesystem_watch_paths"]))
            if cohort == "native_expansion":
                identity = new_cases[row["sample"]]
                row["executable_sha256"] = identity["sha256"]
                row["program"] = identity.get("program", "")
            elif row["class"] == "malware":
                row["executable_sha256"] = row["sample"].split(".")[0]
                row["program"] = ""
            else:
                identity = old_workloads[row["sample"]]
                row["executable_sha256"] = identity["staged_sha256"]
                row["program"] = identity["program"]
            if len(row["executable_sha256"]) != 64:
                raise ValueError("Missing executable identity")
            for name in ("label", "position", "post_target_lineage_raw_syscalls"):
                row[name] = int(row[name])
            if row["label"] != {"benign": 0, "malware": 1}[row["class"]]:
                raise ValueError("Label differs from class")
            for name in host:
                row[name] = float(row[name])
                if not math.isfinite(row[name]):
                    raise ValueError("Nonfinite host feature")
            if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True":
                for name in network:
                    row[name] = float(row[name])
                    if not math.isfinite(row[name]):
                        raise ValueError("Nonfinite P4 feature")
            evidence.append({name: row[name] for name in (
                "sample", "cohort", "split", "class", "group_id", "mode", "watched_path_count",
                "source_run_dir", "source_metadata_sha256", "executable_sha256", "program")})
            if row["group_id"] in EXCLUDED_GROUPS:
                exclusions.append({**evidence[-1], "reason": "user_excluded_cross_cohort_group"})
            else:
                rows.append(row)
    if len({row["sample"] for row in rows}) != len(rows):
        raise ValueError("Duplicate sample identifier; identity review required")
    if len({row["executable_sha256"] for row in rows}) != len(rows):
        raise ValueError("Duplicate executable identity; explicit deduplication required")
    training_groups = {row["group_id"] for row in rows if row["split"] == "training"}
    validation_groups = {row["group_id"] for row in rows if row["split"] == "validation"}
    if training_groups & validation_groups:
        raise ValueError("A group crosses the combined split")
    common = [row for row in rows if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True"]
    for population in (rows, common):
        for split in ("training", "validation"):
            for mode in {row["mode"] for row in population if row["split"] == split}:
                if {row["label"] for row in population if row["split"] == split and row["mode"] == mode} != {0, 1}:
                    raise ValueError("Architecture/linkage stratum is label-exclusive")
    report = {
        "status": "metadata_and_prepared_feature_contracts_compatible",
        "source_datasets_sha256": inputs,
        "settings_verified": EXPECTED_SETTINGS,
        "feature_columns": {"host_candidates": len(host), "p4": len(network)},
        "excluded_groups": sorted(EXCLUDED_GROUPS),
        "excluded_cases": len(exclusions),
        "host_eligible": populations(rows),
        "common_aligned": populations(common),
        "global_group_overlap": [],
        "watch_path_counts_by_cohort": {cohort: sorted({row["watched_path_count"] for row in evidence if row["cohort"] == cohort})
                                        for cohort in ("native_x64", "native_expansion")},
        "watch_path_difference": "Recorded nuisance; the shared 35-family host contract contains only ebpf syscall counters, not filesystem-watch summaries",
        "raw_feature_reconciliation": "Pending before combined training",
        "evaluation_role": "Post-hoc exploratory reuse of consumed validation sets; no confirmatory claim",
    }
    return rows, common, host, report, exclusions, evidence


def save_rows(path, rows):
    trainer, _, _ = frozen.dependencies()
    fields = list(dict.fromkeys(key for row in rows for key in row))
    trainer.write_csv(path, rows, fields)


def prepare():
    rows, common, host, report, exclusions, evidence = audit()
    trainer, data, pcap_reader = frozen.dependencies()
    attempt = ROOT / "combined-analysis" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = attempt / "analysis"
    output.mkdir(parents=True, exist_ok=False)
    protocol = {
        "role": report["evaluation_role"], "excluded_groups": sorted(EXCLUDED_GROUPS),
        "split_rule": "Preserve source training/validation roles after excluding both whole groups globally",
        "feature_columns": {"network_p4": 145, "host_selected": 145, "hybrid": 290},
        "rf": {"n_estimators": 500, "class_weight": "balanced", "random_state": 42, "n_jobs": 1},
        "threshold": 0.5, "training_folds": 5, "bootstrap_replicates": 2000,
        "training_group_label_permutations": 100, "validation_tuning": "none",
        "low_activity_exclusions": 0,
        "limitations": [
            "Both original validation sets were previously examined; this is post-hoc exploratory evaluation.",
            "Architecture/linkage and cohort counts are not proportional across labels and splits.",
            "The cohorts differ in watched paths and workload/toolchain/acquisition conditions.",
            "Malware signatures are acquisition labels; repeated programs within a project are not independent projects.",
            "Quality, execution and P4 alignment exclusions can introduce selection bias.",
            "P4 features are offline PCAP reconstructions, not live-switch measurements.",
        ],
    }
    frozen.write_json(attempt / "protocol.json", protocol)
    frozen.write_json(attempt / "status.json", {"stage": "reconciling_original_captures"})
    counts = Counter()
    alignment_rows = []
    signals = {name.removeprefix("host__").rsplit("__", 1)[0] for name in host}
    try:
        for index, row in enumerate(rows, start=1):
            run_dir = frozen.STUDY / row["source_run_dir"]
            sample_dir = run_dir.parents[1]
            metadata = json.loads((run_dir / "run.json").read_text())
            if data.host_status(sample_dir) != "completed" or metadata["target_exec"].get("match") != "exact":
                raise ValueError("Retrieval/target-exec contract differs: " + row["sample"])
            if metadata["ebpf_event_diagnostics"].get("raw_syscalls_unresolved_abi") != 0:
                raise ValueError("Unresolved raw syscall ABI")
            telemetry = data.p4.load_telemetry_rows(sample_dir)
            features = [name for names in metadata["telemetry_feature_groups"].values() for name in names]
            if len(telemetry) != 40 or len(features) != 169 or not all(
                math.isfinite(float(window[name])) for window in telemetry for name in features
            ):
                raise ValueError("Invalid raw telemetry")
            counts["finite_raw_feature_cells"] += len(telemetry) * len(features)
            counts["archive_regular_members_hash_matched"] += frozen.HELPER.verify_output_archive(sample_dir)
            with pcap_reader(str(run_dir / "packet_capture.pcap")) as reader:
                packets = sum(1 for _packet in reader)
            if any(metadata["packet_capture_statistics"].get(name) != packets
                   for name in ("packets_captured", "packets_received_by_filter")):
                raise ValueError("Independent PCAP count differs")
            counts["pcap_records"] += packets
            summaries = {signal: data.aggregate([float(window[signal]) for window in telemetry])
                         for signal in signals | set(data.p4.P4_FEATURES)}
            for name in host:
                signal, statistic = name.removeprefix("host__").rsplit("__", 1)
                if not math.isclose(row[name], summaries[signal][statistic], rel_tol=1e-9, abs_tol=1e-9):
                    raise ValueError("Prepared host feature differs from raw telemetry: " + name)
                counts["host_summary_comparisons"] += 1
            extracted, _, diagnostic = data.p4.derive_p4_features(
                run_dir / "packet_capture.pcap", telemetry, metadata,
                byte_layer="ethernet", rate_window="nominal")
            if diagnostic["alignment_status"] != row["p4_alignment_status"]:
                raise ValueError("Stored alignment status changed")
            alignment_rows.append({"sample": row["sample"], "cohort": row["cohort"], **diagnostic})
            if diagnostic["alignment_status"] == "unique":
                for signal in data.p4.P4_FEATURES:
                    for statistic, stored in summaries[signal].items():
                        name = f"network__p4_{signal}__{statistic}"
                        if not math.isclose(float(extracted[name]), stored, rel_tol=1e-9, abs_tol=1e-9):
                            raise ValueError("PCAP/stored-telemetry P4 mismatch")
                        if not math.isclose(float(extracted[name]), row[name], rel_tol=1e-9, abs_tol=1e-9):
                            raise ValueError("Prepared/raw-PCAP P4 mismatch")
                        counts["p4_summary_comparisons"] += 1
            if index % 25 == 0 or index == len(rows):
                print(f"RECONCILED {index}/{len(rows)} original captures", flush=True)
        labels = trainer.np.asarray([row["label"] for row in common if row["split"] == "training"])
        groups = trainer.np.asarray([row["group_id"] for row in common if row["split"] == "training"])
        trainer.make_splits(labels, groups)
        trainer.split_indices(rows)
        trainer.split_indices(common)
        report.update(status="compatible_and_reconciled_for_combined_exploratory_training",
                      raw_feature_reconciliation="passed", counts=dict(counts),
                      executable_identity_overlap=0, feature_value_mismatches=0,
                      low_activity_exclusions=0)
        for name, values in (("eligible_dataset.csv", rows), ("excluded_groups.csv", exclusions),
                             ("source_metadata_audit.csv", evidence), ("p4_alignment_audit.csv", alignment_rows)):
            save_rows(output / name, values)
        frozen.write_json(output / "compatibility_audit.json", report)
        source_paths = [Path(__file__), OLD / "analysis/model-fit-r3/metrics.json",
                        OLD / "analysis/preparation_audit.json", old_manifest := OLD.parent.parent / "manifests/benign-workloads.json",
                        OLD / "frozen_hashes.json", NEW / "derived_manifest.json",
                        NEW / "analysis/preparation_audit.json"]
        source_hashes = {str(path.relative_to(frozen.STUDY)): frozen.digest(path) for path in source_paths}
        source_hashes.update(report["source_datasets_sha256"])
        manifest = {
            "authorization": "User requested both cohorts, excluding DDoSAgent/util-linux, after alignment checks",
            "source_hashes": source_hashes,
            "frozen_workflow_hashes": json.loads((NEW / "derived_manifest.json").read_text())["frozen_workflow_hashes"],
            "data_hashes": {path.name: frozen.digest(path) for path in output.iterdir() if path.is_file()},
            "protocol_sha256": frozen.digest(attempt / "protocol.json"),
            "sample_execution": False, "original_data_modified": False,
        }
        frozen.write_json(attempt / "combined_manifest.json", manifest)
        frozen.write_json(attempt / "status.json", {"stage": "prepared", "host_cases": len(rows), "common_cases": len(common)})
        print(json.dumps({"attempt": str(attempt), "audit": report}, indent=2), flush=True)
    except BaseException as error:
        frozen.write_json(attempt / "status.json", {"stage": "stopped_requires_review", "error": str(error)})
        raise


def cohort_nuisance(training, validation, output):
    trainer, _, _ = frozen.dependencies()
    def features(records):
        return [{"cohort": row["cohort"], "mode": row["mode"], "watch_path_count": row["watched_path_count"]}
                for row in records]
    labels = trainer.np.asarray([row["label"] for row in training])
    groups = trainer.np.asarray([row["group_id"] for row in training])
    training_features, validation_features = features(training), features(validation)
    oof = trainer.np.full(len(training), trainer.np.nan)
    for train_indices, held_indices in trainer.make_splits(labels, groups):
        vectorizer = trainer.DictVectorizer(sparse=False)
        train_matrix = vectorizer.fit_transform([training_features[index] for index in train_indices])
        estimator = trainer.random_forest()
        estimator.fit(train_matrix, labels[train_indices])
        oof[held_indices] = estimator.predict_proba(vectorizer.transform(
            [training_features[index] for index in held_indices]))[:, 1]
    vectorizer = trainer.DictVectorizer(sparse=False)
    estimator = trainer.random_forest()
    estimator.fit(vectorizer.fit_transform(training_features), labels)
    probabilities = estimator.predict_proba(vectorizer.transform(validation_features))[:, 1]
    trainer.joblib.dump({"vectorizer": vectorizer, "model": estimator}, output / "cohort_mode_watch_only.joblib")
    return oof, probabilities


def train(attempt):
    attempt = attempt.resolve()
    if not attempt.is_relative_to((ROOT / "combined-analysis").resolve()):
        raise ValueError("Output must be a new combined-analysis attempt")
    manifest = json.loads((attempt / "combined_manifest.json").read_text())
    frozen.verify_hashes(manifest["frozen_workflow_hashes"])
    for path, checksum in manifest["source_hashes"].items():
        if frozen.digest(frozen.STUDY / path) != checksum:
            raise ValueError("Combined analysis source changed: " + path)
    for name, checksum in manifest["data_hashes"].items():
        if frozen.digest(attempt / "analysis" / name) != checksum:
            raise ValueError("Prepared combined evidence changed: " + name)
    if frozen.digest(attempt / "protocol.json") != manifest["protocol_sha256"]:
        raise ValueError("Combined protocol changed")
    trainer, data, _ = frozen.dependencies()
    host = list(json.loads(trainer.HOST_FEATURE_PATH.read_text())["host"])
    records, _ = read_csv(attempt / "analysis/eligible_dataset.csv")
    for row in records:
        for name in ("label", "position", "post_target_lineage_raw_syscalls", "watched_path_count"):
            row[name] = int(row[name])
        if row["group_id"] in EXCLUDED_GROUPS or row["class"] not in ("benign", "malware"):
            raise ValueError("Excluded group/control reached model input")
        for name in host:
            row[name] = float(row[name])
        if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True":
            for name in data.p4.P4_SAMPLE_FEATURES:
                row[name] = float(row[name])
    common = [row for row in records if row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True"]
    train_indices, validation_indices = trainer.split_indices(common)
    training = [common[index] for index in train_indices]
    validation = [common[index] for index in validation_indices]
    all_train, all_validation = trainer.split_indices(records)
    all_training = [records[index] for index in all_train]
    all_held_out = [records[index] for index in all_validation]
    output = attempt / "analysis/model-fit"
    output.mkdir(exist_ok=False)
    models = output / "models"
    models.mkdir()
    frozen.write_json(attempt / "status.json", {"stage": "training", "exploratory": True})
    try:
        labels = trainer.np.asarray([row["label"] for row in training])
        print("COMBINED TRAINING: RF500; globally disjoint groups; training-only selection", flush=True)
        oof, selections, folds = trainer.grouped_oof_main(training, host, labels)
        trainer.save_predictions(output / "training_grouped_oof_predictions.csv", training, oof, "combined_training_only_oof")
        host_oof, host_selections, _ = trainer.grouped_oof_host(all_training, host)
        selections.extend(host_selections)
        trainer.save_predictions(output / "host_sensitivity_training_oof_predictions.csv", all_training,
                                 {"host_all_eligible": host_oof}, "combined_training_only_oof")
        auxiliary_oof = {kind: trainer.grouped_oof_auxiliary(training, kind)[0]
                         for kind in ("activity_only", "nuisance_only")}
        print("COMBINED FIT: scoring already-consumed validation sets without tuning", flush=True)
        probabilities, selected, selection_details = trainer.fit_final_models(
            training, validation, host, models, "combined_training_final_fit")
        selections.extend(selected)
        probabilities.update(trainer.fit_auxiliary_models(training, validation, models))
        auxiliary_oof["cohort_mode_watch_only"], probabilities["cohort_mode_watch_only"] = cohort_nuisance(training, validation, models)
        trainer.save_predictions(output / "auxiliary_training_oof_predictions.csv", training, auxiliary_oof, "combined_training_only_oof")
        sensitivity, selected, sensitivity_details = trainer.fit_host_sensitivity(all_training, all_held_out, host, models)
        selections.extend(selected)
        trainer.save_predictions(output / "validation_predictions.csv", validation, probabilities, "posthoc_combined_exploratory_validation_no_tuning")
        trainer.save_predictions(output / "host_only_all_eligible_validation_predictions.csv", all_held_out,
                                 {"host_all_eligible": sensitivity}, "combined_all_eligible_sensitivity")
        validation_labels = trainer.np.asarray([row["label"] for row in validation])
        metrics = {name: trainer.binary_metrics(validation_labels, values) for name, values in probabilities.items()}
        weights = trainer.bootstrap_weight_vectors(validation)
        strata = {}
        for field in ("cohort", "mode"):
            strata[field] = {}
            for value in sorted({row[field] for row in validation}):
                indices = [index for index, row in enumerate(validation) if row[field] == value]
                strata[field][value] = {name: trainer.binary_metrics(validation_labels[indices], values[indices])
                                       for name, values in probabilities.items()}
        summary = {
            "status": "primary_scored_secondary_checks_pending", "evaluation_role": "posthoc_combined_exploratory",
            "protocol": json.loads((attempt / "protocol.json").read_text()),
            "compatibility": json.loads((attempt / "analysis/compatibility_audit.json").read_text()),
            "primary_counts": populations(common), "host_sensitivity_counts": populations(records),
            "feature_columns": {"p4": 145, "host": 145, "hybrid": 290},
            "held_out_validation": metrics,
            "training_grouped_oof": {name: trainer.binary_metrics(labels, values) for name, values in oof.items()},
            "auxiliary_training_oof": {name: trainer.binary_metrics(labels, values) for name, values in auxiliary_oof.items()},
            "host_all_eligible_sensitivity": trainer.binary_metrics(trainer.np.asarray([row["label"] for row in all_held_out]), sensitivity),
            "group_weighted": {name: trainer.binary_metrics(validation_labels, values, trainer.equal_group_weights(validation))
                               for name, values in probabilities.items()},
            "cluster_bootstrap": {name: trainer.bootstrap_summary(validation_labels, values, weights)
                                  for name, values in probabilities.items()},
            "by_cohort_and_mode": strata,
            "activity_or_nuisance_claim_gate_triggered": any(metrics[kind]["balanced_accuracy"] >= 0.75
                for kind in ("activity_only", "nuisance_only", "cohort_mode_watch_only")),
            "validation_previously_consumed": True, "validation_tuning": "none",
        }
        group_rows = []
        for group in sorted({row["group_id"] for row in validation}):
            indices = [index for index, row in enumerate(validation) if row["group_id"] == group]
            for name, values in probabilities.items():
                group_rows.append({"group_id": group, "model": name, "samples": len(indices),
                    "label": int(validation_labels[indices[0]]),
                    "recall_for_group_label": float(trainer.np.mean((values[indices] >= 0.5) == validation_labels[indices]))})
        save_rows(output / "validation_by_group.csv", group_rows)
        save_rows(output / "host_family_selection.csv", selections)
        save_rows(output / "grouped_training_folds.csv", folds)
        frozen.write_json(output / "feature_selection.json", {"primary": selection_details, "sensitivity": sensitivity_details})
        frozen.write_json(output / "model_sha256.json", {path.name: frozen.digest(path) for path in models.glob("*.joblib")})
        frozen.write_json(output / "metrics-primary.json", summary)
        print("COMBINED PRIMARY RESULTS: " + json.dumps(metrics), flush=True)
        print("SECONDARY: 100 training-only whole-group label permutations", flush=True)
        permutations = trainer.group_permutation_null(training, host, summary["training_grouped_oof"]["hybrid_29_plus_29"]["balanced_accuracy"])
        frozen.write_json(output / "training_group_label_permutations.json", permutations)
        summary.update(status="complete_combined_exploratory_evaluation", training_group_label_permutations=permutations)
        frozen.write_json(output / "metrics.json", summary)
        frozen.verify_hashes(manifest["frozen_workflow_hashes"])
        frozen.write_json(attempt / "status.json", {"stage": "complete", "metrics_sha256": frozen.digest(output / "metrics.json"),
            "sample_execution": False, "original_data_modified": False})
        print("COMPLETE: " + str(output / "metrics.json"), flush=True)
    except BaseException as error:
        frozen.write_json(attempt / "status.json", {"stage": "stopped_requires_review", "error": str(error)})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--audit-only", action="store_true")
    actions.add_argument("--prepare-only", action="store_true")
    actions.add_argument("--train", type=Path)
    args = parser.parse_args()
    lock_path = frozen.gates.preparation.validation_checks.allocation.prepare_inventory.PREPARATION / "readiness.lock"
    with lock_path.open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.audit_only:
            _, _, _, report, _, _ = audit()
            print(json.dumps(report, indent=2), flush=True)
        elif args.prepare_only:
            prepare()
        else:
            train(args.train)


if __name__ == "__main__":
    main()