#!/usr/bin/env python3
"""Training-only fixed fusion comparison and passive capture-attribution audit."""

import argparse
import csv
import json
import math
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import investigate_hybrid as diagnostic

ATTEMPT = Path(__file__).resolve().parent
analysis = diagnostic.analysis
MODELS = diagnostic.MODELS
RULES = (*MODELS, "late_or", "late_equal_mean")


def fusion_scores(host, network):
    if not all(math.isfinite(value) and 0 <= value <= 1 for value in (host, network)):
        raise ValueError("Non-finite or out-of-range fusion input")
    return {"late_or": max(host, network), "late_equal_mean": (host + network) / 2}


def paired_training(records, predictions):
    expected = {row["sample"]: row for row in records}
    if len(expected) != len(records) or any(row["split"] != "training" for row in records):
        raise ValueError("Expected unique training identities only")
    index = diagnostic.index_predictions(predictions)
    if {sample for sample, _ in index} != set(expected):
        raise ValueError("OOF population differs from primary training identities")
    result = []
    for row in records:
        scores = {}
        for model in MODELS:
            prediction = index[row["sample"], model]
            if prediction["split"] != "training" or prediction["group_id"] != row["group_id"]:
                raise ValueError("OOF split/group mismatch")
            if int(prediction["label"]) != int(row["label"]):
                raise ValueError("OOF label mismatch")
            score = float(prediction["probability_malware"])
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError("Invalid saved OOF probability")
            if int(prediction["prediction"]) != int(score >= 0.5):
                raise ValueError("OOF prediction does not use frozen threshold")
            scores[model] = score
        scores.update(fusion_scores(scores["host_29_families"], scores["network_p4"]))
        result.append({"sample": row["sample"], "label": int(row["label"]),
            "group_id": row["group_id"], "mode": row["mode"], **scores})
    return result


def training_comparison(records, trainer):
    predictions = diagnostic.load_csv(ATTEMPT / "analysis/model-fit/training_grouped_oof_predictions.csv")
    paired = paired_training(records, predictions)
    labels = trainer.np.asarray([row["label"] for row in paired])
    groups = trainer.np.asarray([row["group_id"] for row in paired])
    fold_by_sample, fold_checks = {}, []
    for fold, (fitting, held_out) in enumerate(trainer.make_splits(labels, groups), start=1):
        if set(groups[fitting]) & set(groups[held_out]):
            raise ValueError("Training-only fold contains group overlap")
        fold_checks.append({"fold": fold, "train_samples": len(fitting), "oof_samples": len(held_out),
            "train_groups": len(set(groups[fitting])), "oof_groups": len(set(groups[held_out]))})
        for index in held_out:
            fold_by_sample[paired[index]["sample"]] = fold
    saved_folds = diagnostic.load_csv(ATTEMPT / "analysis/model-fit/grouped_training_folds.csv")
    if len(saved_folds) != len(fold_checks):
        raise ValueError("Saved fold count differs")
    for computed, saved in zip(fold_checks, saved_folds):
        if any(computed[key] != int(saved[key]) for key in computed):
            raise ValueError("Reconstructed fold summaries differ from saved folds")
    for row in paired:
        row["fold"] = fold_by_sample[row["sample"]]
    weights = trainer.np.asarray([1 / Counter(groups)[group] for group in groups])
    metrics, per_fold, per_group, changes = {}, [], [], []
    for rule in RULES:
        scores = trainer.np.asarray([row[rule] for row in paired])
        metrics[rule] = {"sample_weighted": trainer.binary_metrics(labels, scores),
            "group_weighted": trainer.binary_metrics(labels, scores, weights)}
        for fold in range(1, len(fold_checks) + 1):
            selected = trainer.np.asarray([row["fold"] == fold for row in paired])
            per_fold.append({"rule": rule, "fold": fold, "cases": int(selected.sum()),
                **trainer.binary_metrics(labels[selected], scores[selected])})
        for group in sorted(set(groups)):
            selected = groups == group
            per_group.append({"rule": rule, "group_id": group, "cases": int(selected.sum()),
                "label": int(labels[selected][0]),
                "correct": int(((scores[selected] >= 0.5) == labels[selected]).sum())})
    for row in paired:
        host_alert = row["host_29_families"] >= 0.5
        if host_alert and row["late_or"] < 0.5:
            raise ValueError("OR did not preserve a host alert")
        for rule in ("late_or", "late_equal_mean", "hybrid_29_plus_29"):
            if (row[rule] >= 0.5) != host_alert:
                changes.append({"sample": row["sample"], "rule": rule, "label": row["label"],
                    "group_id": row["group_id"], "fold": row["fold"],
                    "host_score": row["host_29_families"], "rule_score": row[rule],
                    "host_correct": int(host_alert == row["label"]),
                    "rule_correct": int((row[rule] >= 0.5) == row["label"])})
    original = analysis.ready.load(ATTEMPT / "analysis/model-fit/metrics.json")["training_grouped_oof"]
    for model in MODELS:
        for key, value in metrics[model]["sample_weighted"].items():
            if isinstance(value, (int, float)) and not math.isclose(value, original[model][key], abs_tol=1e-12):
                raise ValueError("Saved training OOF metric differs")
    return {"cases": len(paired), "groups": len(set(groups)), "threshold": 0.5,
        "metrics": metrics, "fold_checks": fold_checks}, paired, per_fold, per_group, changes


def traffic_audit(records, output):
    if not shutil.which("tshark"):
        raise RuntimeError("Tshark is required for passive attribution evidence")
    contexts, flags = [], []
    for position, row in enumerate(records, start=1):
        context = diagnostic.packet_context(row)
        context["split"] = row["split"]
        context["class"] = row["class"]
        context["mode"] = row["mode"]
        context["pcap_sha256"] = analysis.ready.digest(
            analysis.ready.STUDY / row["source_run_dir"] / "packet_capture.pcap")
        context["ambient_signature_with_zero_recorded_connect"] = (
            context["target_connect_count"] == 0 and
            "connectivity-check.ubuntu.com" in context["in_window_http_hosts"])
        contexts.append(context)
        flags.append({key: context[key] for key in ("sample", "split", "class", "cohort", "mode",
            "target_connect_count", "in_window_tcp_udp_packets", "p4_alignment", "p4_parity",
            "ambient_signature_with_zero_recorded_connect")})
        if position % 25 == 0 or position == len(records):
            print(f"Passive capture audit: {position}/{len(records)}", flush=True)
    analysis.ready.save(output / "traffic_context.json", contexts)
    analysis.combined.save_rows(output / "traffic_flags.csv", flags)
    summary = []
    for split in ("training", "validation"):
        for label in ("benign", "malware"):
            selected = [row for row in contexts if row["split"] == split and row["class"] == label]
            summary.append({"split": split, "class": label, "cases": len(selected),
                "with_in_window_connectivity_check": sum("connectivity-check.ubuntu.com" in row["in_window_http_hosts"] for row in selected),
                "zero_recorded_connect": sum(row["target_connect_count"] == 0 for row in selected),
                "ambient_signature_with_zero_recorded_connect": sum(row["ambient_signature_with_zero_recorded_connect"] for row in selected)})
    return summary


def run():
    analysis.verify_inputs()
    records = diagnostic.load_csv(ATTEMPT / "analysis/eligible_dataset.csv")
    training = [row for row in records if row["split"] == "training" and analysis.aligned(row)]
    trainer, _, _ = analysis.combined.frozen.dependencies()
    paths = [Path(__file__), ATTEMPT / "investigate_hybrid.py", ATTEMPT / "analysis/eligible_dataset.csv",
        ATTEMPT / "analysis/model-fit/training_grouped_oof_predictions.csv",
        ATTEMPT / "analysis/model-fit/grouped_training_folds.csv", ATTEMPT / "analysis/model-fit/metrics.json"]
    hashes = {str(path): analysis.ready.digest(path) for path in paths}
    output = ATTEMPT / "fusion-readiness" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True, exist_ok=False)
    protocol = {"scope": "Exploratory training-only fixed-rule comparison and passive capture audit",
        "rules": {"late_or": "max(host OOF score, network OOF score), threshold 0.5",
            "late_equal_mean": "arithmetic mean of host/network OOF scores, threshold 0.5"},
        "tuning": False, "refits": 0, "validation_predictions_read": False,
        "validation_scoring": False, "new_capture": False, "vm_operations": 0,
        "eligibility_changes": False, "input_hashes": hashes,
        "fresh_untouched_evaluation_available": False,
        "collection_gate": "Not released: source process ownership and reviewed common background/null baseline required",
        "limitations": ["OOF scores are reused; rules are fixed before this comparison, not fitted on OOF labels",
            "Same fold OOF models overlap training sets; these are exploratory diagnostics, not independent trials",
            "Max/mean forest scores are not calibrated probabilities",
            "Ambient signature plus absent connect is not packet ownership proof; UDP can be connectionless",
            "No packet is removed and no reconstructed feature is changed",
            "A future baseline/service change requires an explicitly authorized new common snapshot and benign-only pilot",
            "Consumed validation may not be reused to select or confirm fusion superiority"]}
    analysis.ready.save(output / "protocol.json", protocol)
    comparison, paired, folds, groups, changes = training_comparison(training, trainer)
    analysis.ready.save(output / "training_comparison.json", comparison)
    for name, rows in (("training_fusion_predictions.csv", paired), ("training_by_fold.csv", folds),
                       ("training_by_group.csv", groups), ("training_changes_vs_host.csv", changes)):
        analysis.combined.save_rows(output / name, rows)
    traffic = traffic_audit(records, output)
    for path, expected in hashes.items():
        if analysis.ready.digest(Path(path)) != expected:
            raise ValueError("An input changed during diagnostics")
    result = {"status": "complete", "output": str(output), "training": comparison,
        "passive_traffic_audit": traffic, "untouched_validation": "Unavailable; no new performance claim",
        "collection_ready": False, "reason": "Attribution and a new common baseline require reviewed pilot evidence"}
    analysis.ready.save(output / "result.json", result)
    print(json.dumps(result, indent=2))


def self_test():
    for host in (0, 0.49, 0.5, 1):
        for network in (0, 0.49, 0.5, 1):
            scores = fusion_scores(host, network)
            assert (scores["late_or"] >= 0.5) == (host >= 0.5 or network >= 0.5)
    for host, network in ((float("nan"), 0), (0, float("inf")), (-0.1, 0), (0, 1.1)):
        try:
            fusion_scores(host, network)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid fusion input accepted")
    records = [{"sample": "fixture", "split": "training", "group_id": "group", "label": "1", "mode": "native"}]
    predictions = [{**records[0], "model": model, "prediction": "1", "probability_malware": "0.6"} for model in MODELS]
    assert paired_training(records, predictions)[0]["late_or"] == 0.6
    for bad in ([dict(prediction, split="validation") for prediction in predictions], predictions + [predictions[0]],
                [dict(prediction, group_id="other") for prediction in predictions]):
        try:
            paired_training(records, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid OOF population accepted")
    print("PASS: OR alert preservation, boundary scores, numeric guards and training-only OOF joins")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    self_test() if options.self_test else run()