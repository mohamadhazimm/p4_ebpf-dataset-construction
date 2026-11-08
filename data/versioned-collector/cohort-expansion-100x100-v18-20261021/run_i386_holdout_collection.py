#!/usr/bin/env python3
"""One-shot capture and frozen analysis of the approved i386-held-out cohort."""

from __future__ import annotations

import argparse
import csv
import fcntl
import importlib.util
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import audit_i386_holdout_readiness as readiness_audit


gates = readiness_audit.gates
HELPER = gates.HELPER
STUDY = gates.STUDY
ROOT = Path(__file__).resolve().parent
RELEASE = ROOT / "i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z"
GATE = RELEASE / "gates/20261021T203538557730Z"
LEGACY = STUDY / "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/readiness/20261021T104951987641Z"
write_json = gates.native.write_json
digest = gates.digest


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def batch_command(run, snapshot, guest_root):
    return ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"),
            "--vm", HELPER.VM, "--guest-user", HELPER.GUEST_USER,
            "--guest-malware-dir", guest_root + "/samples",
            "--guest-runner", "/home/csci/Downloads/malware_runner.py",
            "--snapshot", snapshot, "--schema-version", HELPER.SCHEMA,
            "--guest-arguments-dir", guest_root + "/arguments",
            "--sample-list", str(RELEASE / "all-cases.txt"),
            "--output-dir", str(run / "runs"), "--timeout", "20",
            "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
            "--fixed-observation", "--common-launch-wrapper"]


def dependencies():
    trainer = load_module("heldout_training_utilities", LEGACY / "train_model.py")
    data = load_module("heldout_feature_utilities", LEGACY / "prepare_model_data.py")
    from scapy.utils import RawPcapReader
    return trainer, data, RawPcapReader


def preflight():
    report = readiness_audit.audit(GATE)
    protocol = json.loads((RELEASE / "protocol.json").read_text())
    preregistration = json.loads((RELEASE / "preregistration.json").read_text())
    if preregistration["estimator"] != {"name": "RandomForestClassifier", "n_estimators": 500,
            "class_weight": "balanced", "random_state": 42, "n_jobs": 1,
            "threshold": 0.5, "tuning": "none"}:
        raise ValueError("Frozen estimator differs")
    if preregistration["feature_columns"] != {"p4": 145, "selected_host": 145, "hybrid": 290}:
        raise ValueError("Frozen feature budget differs")
    trainer, data, _ = dependencies()
    ordered = json.loads((RELEASE / "case_order.json").read_text())
    training = [case for case in ordered if case["split"] == "training"]
    labels = trainer.np.asarray([int(case["label"] == "malware") for case in training])
    groups = trainer.np.asarray([case["group_id"] for case in training])
    trainer.make_splits(labels, groups)
    contract = json.loads(trainer.HOST_FEATURE_PATH.read_text())["host"]
    if len(contract) != 175 or len(data.p4.P4_SAMPLE_FEATURES) != 145:
        raise ValueError("Feature utilities differ from preregistration")
    return report, protocol


def frozen_hashes():
    trainer, data, _ = dependencies()
    paths = [Path(__file__), Path(readiness_audit.__file__), LEGACY / "train_model.py",
             LEGACY / "prepare_model_data.py", trainer.HOST_FEATURE_PATH,
             data.P4_DIR / "analyze_p4_pcap_ablation.py", STUDY / "src/build_dataset.py",
             RELEASE / "protocol.json", RELEASE / "preregistration.json",
             RELEASE / "case_order.json", RELEASE / "all-cases.txt", GATE / "readiness.json"]
    return {os.path.relpath(path, STUDY): digest(path) for path in paths}


def verify_hashes(expected):
    HELPER.verify_production()
    for name, checksum in expected.items():
        if digest(STUDY / name) != checksum:
            raise ValueError("Frozen workflow input changed: " + name)


def stream_capture(command, log_path):
    with log_path.open("x") as log:
        child = subprocess.Popen(command, cwd=STUDY, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, errors="replace",
                                 bufsize=1, start_new_session=True)
        try:
            for line in child.stdout:
                print(line, end="", flush=True)
                log.write(line)
                log.flush()
            return child.wait()
        except BaseException:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            raise
        finally:
            child.stdout.close()


def restore_guest(run):
    if HELPER.vm_info(HELPER.VM)["VMState"] != '"poweroff"':
        HELPER.vbox("controlvm", HELPER.VM, "poweroff")
    HELPER.vbox("snapshot", HELPER.VM, "restore", HELPER.ORIGINAL)
    state = {"guest": HELPER.isolated(HELPER.VM), "sink": HELPER.isolated("Sink")}
    write_json(run / "final_vm_state.json", state)
    if (state["guest"]["VMState"] != '"poweroff"' or
            state["guest"]["CurrentSnapshotName"] != '"' + HELPER.ORIGINAL + '"'):
        raise ValueError("Guest cleanup failed")


def prepare_data(run, protocol, output):
    trainer, data, pcap_reader = dependencies()
    output.mkdir(parents=True, exist_ok=False)
    host_features = list(json.loads(trainer.HOST_FEATURE_PATH.read_text())["host"])
    signals = {name.removeprefix("host__").rsplit("__", 1)[0] for name in host_features}
    host_records, common_records, audits, alignment_rows = [], [], [], []
    nulls = {"amd64": [], "i386": []}
    totals = Counter()
    ordered = json.loads((RELEASE / "case_order.json").read_text())
    for position, case in enumerate(ordered, start=1):
        sample_dir = run / "runs" / case["sample"]
        paths = list(sample_dir.glob("output/run_*/run.json"))
        row = {"sample": case["sample"], "class": case["label"], "split": case["split"],
             "group_id": "" if case["label"] == "null" else case["group_id"],
             "arch": case["arch"], "position": position,
               "host_status": data.host_status(sample_dir), "quality_status": "unavailable",
               "target_exec_status": "unavailable", "p4_alignment_status": "not_attempted",
               "exclusion_reason": "", "host_eligible": 0, "common_aligned": 0}
        audits.append(row)
        if len(paths) == 0:
            row["exclusion_reason"] = "output_not_retrieved_or_run_metadata_missing"
            totals["unretrieved"] += 1
            continue
        if len(paths) != 1:
            raise ValueError("Ambiguous run metadata: " + case["sample"])
        metadata = json.loads(paths[0].read_text())
        if (metadata.get("telemetry_schema_version") != HELPER.SCHEMA or
                metadata.get("malware_runner_sha256") != HELPER.PINNED["src/malware_runner.py"]):
            raise ValueError("Runner provenance mismatch: " + case["sample"])
        telemetry = data.p4.load_telemetry_rows(sample_dir)
        features = [name for values in metadata["telemetry_feature_groups"].values() for name in values]
        if (len(telemetry) != 40 or len(features) != 169 or len(set(features)) != 169 or
                not all(math.isfinite(float(window[name])) for window in telemetry for name in features)):
            raise ValueError("Nonfinite/incomplete telemetry: " + case["sample"])
        totals["finite_cells"] += 40 * 169
        totals["archive_members"] += HELPER.verify_output_archive(sample_dir)
        with pcap_reader(str(paths[0].parent / "packet_capture.pcap")) as reader:
            packet_records = sum(1 for _packet in reader)
        if packet_records != metadata["packet_capture_statistics"].get("packets_captured"):
            raise ValueError("PCAP records differ from tcpdump: " + case["sample"])
        totals["pcap_records"] += packet_records
        row["quality_status"] = metadata.get("collection_quality_status", "unavailable")
        totals["quality_" + row["quality_status"]] += 1
        if row["host_status"] != "completed" or row["quality_status"] != "accepted":
            row["exclusion_reason"] = "retrieval_or_collection_quality_not_accepted"
            continue
        if (any(metadata.get(name) != 0 for name in ("ebpf_lost_event_count",
                "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel")) or
                metadata.get("ebpf_status") != "active" or metadata.get("packet_capture_status") != "active" or
                metadata["packet_capture_statistics"].get("packets_received_by_filter") != packet_records or
                metadata["ebpf_event_diagnostics"].get("raw_syscalls_unresolved_abi") != 0):
            raise ValueError("Accepted status contradicts sensor evidence: " + case["sample"])
        execution = metadata.get("target_exec", {})
        row["target_exec_status"] = execution.get("status", "unavailable")
        if execution.get("status") != "observed" or execution.get("match") != "exact":
            row["exclusion_reason"] = "exact_target_exec_not_observed"
            continue
        artifact = metadata["target_artifact"]
        expected_mode = "native_compat" if case["arch"] == "i386" else "native"
        expected_machine = 3 if case["arch"] == "i386" else 62
        if (artifact["execution_mode"] != expected_mode or artifact["linkage"] != "static" or
            artifact["e_machine"] != expected_machine):
            raise ValueError("Target architecture/linkage differs: " + case["sample"])
        if case["label"] == "null":
            if metadata["return_code"] != 0:
                raise ValueError("Null workload failed")
            nulls[case["arch"]].append(execution["post_target_lineage_raw_syscalls"])
            row["exclusion_reason"] = "null_control_not_classifier_input"
            continue
        if set(metadata["telemetry_feature_groups"]["p4_network"]) != set(data.p4.P4_FEATURES):
            raise ValueError("P4 contract differs")
        summaries = {name: data.aggregate([float(window[name]) for window in telemetry])
                     for name in signals | set(data.p4.P4_FEATURES)}
        record = {"sample": case["sample"], "class": case["label"],
                  "label": int(case["label"] == "malware"), "split": case["split"],
                  "mode": expected_mode + "_" + case["arch"] + "_static",
                  "group_id": case["group_id"], "position": position,
                  "return_code": metadata["return_code"], "run_id": metadata.get("run_id"),
                  "post_target_lineage_raw_syscalls": execution["post_target_lineage_raw_syscalls"]}
        record.update({name: summaries[name.removeprefix("host__").rsplit("__", 1)[0]][name.rsplit("__", 1)[1]]
                       for name in host_features})
        extracted, _, diagnostics = data.p4.derive_p4_features(paths[0].parent / "packet_capture.pcap",
            telemetry, metadata, byte_layer="ethernet", rate_window="nominal")
        alignment = diagnostics["alignment_status"]
        record["p4_alignment_status"] = row["p4_alignment_status"] = alignment
        record["p4_parity"] = False
        row["host_eligible"] = 1
        alignment_rows.append({"sample": case["sample"], **diagnostics})
        if alignment == "unique":
            for name in data.p4.P4_FEATURES:
                for statistic, stored in summaries[name].items():
                    feature = "network__p4_" + name + "__" + statistic
                    if not math.isclose(stored, float(extracted[feature]), rel_tol=1e-9, abs_tol=1e-9):
                        raise ValueError("Stored/reconstructed P4 mismatch: " + case["sample"] + ":" + feature)
                    totals["parity_comparisons"] += 1
            record.update(extracted)
            record["p4_parity"] = True
            row["common_aligned"] = 1
            common_records.append(record)
        else:
            row["exclusion_reason"] = "p4_alignment_not_unique"
        host_records.append(record)
        print(f"Validated [{position}/204] {case['sample']}: P4 {alignment}", flush=True)
    for name, values in (("eligibility_audit.csv", audits), ("p4_alignment_audit.csv", alignment_rows),
                         ("eligible_dataset.csv", host_records)):
        if values:
            fields = list(dict.fromkeys(key for value in values for key in value))
            trainer.write_csv(output / name, values, fields)
    report = {"status": "prepared_for_modeling", "totals": dict(totals),
              "exclusions": dict(Counter(row["exclusion_reason"] for row in audits if row["exclusion_reason"])),
              "host_eligible": len(host_records), "common_aligned": len(common_records),
              "null_maxima": {arch: max(counts) if counts else None for arch, counts in nulls.items()},
              "activity_floors": {arch: max(counts) + 25 if counts else None for arch, counts in nulls.items()},
              "low_activity_exclusions": 0,
              "fresh_nulls_complete": all(len(counts) == 2 for counts in nulls.values())}
    write_json(output / "preparation_audit.json", report)
    return host_records, common_records, host_features, report


def fit_models(run, host_records, common, host_features, preparation):
    trainer, _, _ = dependencies()
    if not preparation["fresh_nulls_complete"]:
        raise ValueError("Fresh nulls incomplete; preserve data for protocol review")
    train_indices, validation_indices = trainer.split_indices(common)
    training = [common[index] for index in train_indices]
    validation = [common[index] for index in validation_indices]
    all_training_indices, all_validation_indices = trainer.split_indices(host_records)
    all_training = [host_records[index] for index in all_training_indices]
    all_validation = [host_records[index] for index in all_validation_indices]
    output = run / "analysis/model-fit"
    output.mkdir(parents=True, exist_ok=False)
    model_dir = output / "models"
    model_dir.mkdir()
    labels = trainer.np.asarray([row["label"] for row in training])
    print("TRAINING: fixed 500-tree RF; training-only grouped OOF and 29-family selection", flush=True)
    oof, selections, folds = trainer.grouped_oof_main(training, host_features, labels)
    trainer.save_predictions(output / "training_grouped_oof_predictions.csv", training, oof, "training_only_oof")
    oof_host, host_selection, _ = trainer.grouped_oof_host(all_training, host_features)
    selections.extend(host_selection)
    trainer.save_predictions(output / "host_sensitivity_training_oof_predictions.csv", all_training,
        {"host_all_eligible": oof_host}, "training_only_oof")
    auxiliary_oof = {}
    for kind in ("activity_only", "nuisance_only"):
        auxiliary_oof[kind], _ = trainer.grouped_oof_auxiliary(training, kind)
    trainer.save_predictions(output / "auxiliary_training_oof_predictions.csv", training,
                             auxiliary_oof, "training_only_oof")
    print("TRAINING: fitting on training only; scoring frozen held-out i386 split once", flush=True)
    probabilities, final_selection, details = trainer.fit_final_models(training, validation,
        host_features, model_dir, "training_final_fit")
    selections.extend(final_selection)
    probabilities.update(trainer.fit_auxiliary_models(training, validation, model_dir))
    sensitivity, sensitivity_selection, sensitivity_details = trainer.fit_host_sensitivity(
        all_training, all_validation, host_features, model_dir)
    selections.extend(sensitivity_selection)
    trainer.save_predictions(output / "validation_predictions.csv", validation, probabilities,
                             "frozen_i386_validation_scored_once_no_tuning")
    trainer.save_predictions(output / "host_only_all_eligible_validation_predictions.csv", all_validation,
                             {"host_all_eligible": sensitivity}, "all_eligible_sensitivity")
    validation_labels = trainer.np.asarray([row["label"] for row in validation])
    weights = trainer.bootstrap_weight_vectors(validation)
    metrics = {name: trainer.binary_metrics(validation_labels, values) for name, values in probabilities.items()}
    summary = {"status": "primary_models_scored_secondary_checks_pending", "preparation": preparation,
               "feature_columns": {"p4": 145, "host": 145, "hybrid": 290},
               "training_samples": len(training), "validation_samples": len(validation),
               "training_counts": dict(Counter(row["class"] for row in training)),
               "validation_counts": dict(Counter(row["class"] for row in validation)),
               "held_out_validation": metrics,
               "training_grouped_oof": {name: trainer.binary_metrics(labels, values) for name, values in oof.items()},
               "auxiliary_training_oof": {name: trainer.binary_metrics(labels, values) for name, values in auxiliary_oof.items()},
               "group_weighted": {name: trainer.binary_metrics(validation_labels, values,
                   trainer.equal_group_weights(validation)) for name, values in probabilities.items()},
               "cluster_bootstrap": {name: trainer.bootstrap_summary(validation_labels, values, weights)
                                     for name, values in probabilities.items()},
               "host_all_eligible_sensitivity": trainer.binary_metrics(
                   trainer.np.asarray([row["label"] for row in all_validation]), sensitivity),
               "activity_or_nuisance_claim_gate_triggered": any(metrics[kind]["balanced_accuracy"] >= 0.75
                   for kind in ("activity_only", "nuisance_only")),
               "limitations": json.loads((RELEASE / "preregistration.json").read_text())["limitations"],
               "validation_consumed": True, "validation_tuning": "none", "low_activity_exclusions": 0}
    write_json(output / "metrics-primary.json", summary)
    group_rows = []
    for group in sorted({row["group_id"] for row in validation}):
        indices = [index for index, row in enumerate(validation) if row["group_id"] == group]
        for name, values in probabilities.items():
            group_rows.append({"group_id": group, "mode": validation[indices[0]]["mode"],
                "label": int(validation_labels[indices[0]]), "model": name, "samples": len(indices),
                "recall_for_group_label": float(trainer.np.mean(
                    (values[indices] >= 0.5) == validation_labels[indices]))})
    trainer.write_csv(output / "validation_by_group.csv", group_rows, list(group_rows[0]))
    trainer.write_csv(output / "host_family_selection.csv", selections, list(selections[0]))
    trainer.write_csv(output / "grouped_training_folds.csv", folds, list(folds[0]))
    write_json(output / "feature_selection.json", {"primary": details, "sensitivity": sensitivity_details})
    write_json(output / "model_sha256.json", {path.name: digest(path) for path in model_dir.glob("*.joblib")})
    print("PRIMARY HELD-OUT RESULTS: " + json.dumps(metrics), flush=True)
    print("SECONDARY: 100 training-only whole-group label permutations; no held-out tuning", flush=True)
    permutation = trainer.group_permutation_null(training, host_features,
        summary["training_grouped_oof"]["hybrid_29_plus_29"]["balanced_accuracy"])
    write_json(output / "training_group_label_permutations.json", permutation)
    summary["training_group_label_permutations"] = permutation
    summary["status"] = "complete_exploratory_i386_heldout_evaluation"
    write_json(output / "metrics.json", summary)


def execute():
    lock_path = gates.preparation.validation_checks.allocation.prepare_inventory.PREPARATION / "readiness.lock"
    with lock_path.open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print("PRELAUNCH: rechecking accepted release hashes, isolation and model dependencies", flush=True)
        report, protocol = preflight()
        expected = frozen_hashes()
        run = RELEASE / "collection"
        run.mkdir(exist_ok=False)
        manifest = {"status": "capture_starting", "started_utc": datetime.now(timezone.utc).isoformat(),
                    "pid": os.getpid(), "authorization": "User requested capture followed by frozen model training",
                    "snapshot": report["snapshot"], "snapshot_uuid": report["snapshot_uuid"],
                    "schema": HELPER.SCHEMA, "production_hashes": HELPER.PINNED,
                    "workflow_hashes": expected, "readiness_audit": report,
                    "sample_count": 204, "malware": 100, "benign": 100, "nulls": 4,
                    "automatic_retry": False, "automatic_replacement": False, "resume": False}
        write_json(run / "launch_manifest.json", manifest)
        write_json(run / "status.json", {"stage": "capturing", "pid": os.getpid()})
        try:
            try:
                print("CAPTURE: 204 frozen interleaved positions; no retries/replacements/resume", flush=True)
                command = batch_command(run, report["snapshot"], protocol["guest_root"])
                exit_code = stream_capture(command, run / "collection.log")
                if exit_code:
                    raise RuntimeError(f"Batch exited {exit_code}; preserve outputs, no automatic rerun or training")
            finally:
                restore_guest(run)
            verify_hashes(expected)
            write_json(run / "status.json", {"stage": "validating_and_reconstructing", "pid": os.getpid()})
            print("VALIDATION: archives, provenance, quality, exact exec, PCAP/window alignment and parity", flush=True)
            host_records, common, host_features, preparation = prepare_data(run, protocol, run / "analysis")
            write_json(run / "collection_validation.json", preparation)
            verify_hashes(expected)
            write_json(run / "status.json", {"stage": "training", "pid": os.getpid(), "preparation": preparation})
            fit_models(run, host_records, common, host_features, preparation)
            verify_hashes(expected)
            write_json(run / "status.json", {"stage": "complete", "finished_utc": datetime.now(timezone.utc).isoformat(),
                "metrics": "analysis/model-fit/metrics.json", "preparation": preparation})
            print("COMPLETE: " + str(run / "analysis/model-fit/metrics.json"), flush=True)
        except BaseException as error:
            write_json(run / "status.json", {"stage": "stopped_requires_review", "error": str(error),
                "finished_utc": datetime.now(timezone.utc).isoformat(), "automatic_retry": False})
            print("STOPPED: outputs preserved; no automatic retry. " + str(error), flush=True)
            raise


def self_test():
    from contextlib import redirect_stdout
    from io import StringIO
    from unittest.mock import patch

    report, protocol = preflight()
    verify_hashes(frozen_hashes())
    with tempfile.TemporaryDirectory(prefix="hazim-heldout-pipeline-check-") as temporary:
        host, common, features, preparation = prepare_data(GATE, protocol, Path(temporary) / "analysis")
        assert len(host) == 3 and len(features) == 175
        assert all(row["class"] == "benign" for row in host)
        assert len(common) <= 3 and preparation["fresh_nulls_complete"]
        assert preparation["totals"]["finite_cells"] == 47320
        assert preparation["totals"]["archive_members"] == 86
        assert preparation["totals"]["pcap_records"] == 479
        assert preparation["activity_floors"] == {"amd64": 45, "i386": 45}
        trainer, data, reader = dependencies()
        rng = trainer.np.random.default_rng(42)
        synthetic = []
        for split, group_counts in (("training", (3, 4)), ("validation", (2, 2))):
            for label, group_count in enumerate(group_counts):
                for group in range(group_count):
                    for repeat in range(4):
                        case = {"sample": f"synthetic-{split}-{label}-{group}-{repeat}",
                                "split": split, "label": label, "class": "malware" if label else "benign",
                                "group_id": f"synthetic-{split}-{label}-{group}", "mode": "native_compat_i386_static",
                                "position": len(synthetic) + 1, "return_code": 0,
                                "post_target_lineage_raw_syscalls": 50 + repeat}
                        case.update({name: float(rng.normal() + label) for name in features + data.p4.P4_SAMPLE_FEATURES})
                        synthetic.append(case)
        synthetic_run = Path(temporary) / "synthetic"
        with (patch(__name__ + ".dependencies", return_value=(trainer, data, reader)),
              patch.object(trainer, "random_forest", side_effect=lambda: trainer.RandomForestClassifier(
                  n_estimators=2, class_weight="balanced", random_state=42, n_jobs=1)),
              patch.object(trainer, "BOOTSTRAP_REPLICATES", 3),
              patch.object(trainer, "LABEL_PERMUTATIONS", 2), redirect_stdout(StringIO())):
            fit_models(synthetic_run, synthetic, synthetic, features, {"fresh_nulls_complete": True})
        model_dir = synthetic_run / "analysis/model-fit"
        for name, width in (("network_p4", 145), ("host_29_families", 145), ("hybrid_29_plus_29", 290)):
            assert trainer.joblib.load(model_dir / "models" / (name + ".joblib")).n_features_in_ == width
        assert json.loads((model_dir / "metrics.json").read_text())["validation_tuning"] == "none"
    command = batch_command(Path("not-created"), report["snapshot"], protocol["guest_root"])
    assert "--resume" not in command
    print("PASS: saved-capture preparation, exclusions, archives, finite features, PCAP/P4 parity and null floors")
    print("PASS: synthetic training wrapper, disjoint folds, 145/145/290 budgets and secondary checks; no real validation used")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--execute-and-train", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if sum((args.check_only, args.execute_and_train, args.self_test)) != 1:
        parser.error("Choose exactly one of --check-only, --self-test or --execute-and-train")
    if args.self_test:
        self_test()
        return
    if args.check_only:
        report, protocol = preflight()
        command = batch_command(Path("not-created"), report["snapshot"], protocol["guest_root"])
        assert "--resume" not in command and len(protocol["cases"]) == 204
        print(json.dumps({"status": "launch_preflight_passed", "cases": 204,
                          "snapshot": report["snapshot"], "malware_executed": False}, indent=2))
        return
    signal.signal(signal.SIGTERM, lambda _signal, _frame: sys.exit("Termination requested"))
    execute()


if __name__ == "__main__":
    main()