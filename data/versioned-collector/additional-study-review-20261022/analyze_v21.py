"""Exploratory family/project-held-out fit on the .21 quiet collection ALONE (no merge with any other dataset).

Reuses the study's exact feature extraction (prepare_model_data + analyze_p4_pcap_ablation) and the frozen trainer
(train_model: RF500/balanced/seed42, training-only 29-family host MI, grouped StratifiedGroupKFold OOF, 145/145/290
P4/host/hybrid), PLUS the standard confound controls: activity-only and nuisance-only baselines, group-weighted BA,
2000-replicate group bootstrap, and the 100 training-only whole-group label-permutation null. It fits ONLY the .21
accepted classifier cases (benign + malware; nulls are controls, not inputs), using the frozen .21 family-held-out
split. This is POST-HOC EXPLORATORY on a consumed, examined cohort -- not blind, not a detector/generalization claim.
No VM operation, no capture change, no dataset merge, no model promotion.
"""

import argparse
import csv
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[0] / "cohort-expansion-100x100-v18-20261021"))
import run_i386_holdout_collection as frozen   # noqa: E402  resolves trainer/data/pcap_reader with correct sys.path

V21_ATTEMPT = ROOT / "v21-collection/20261024T194347772138Z"
CASES_ORDER = V21_ATTEMPT / "payload/cases.json"  # true seed-42 interleaved collection order (sample -> position)
MALWARE_SEL = ROOT / "v21-collection-selection/20261024T170741270302Z/malware_selection.json"
BENIGN_BIND = ROOT / "v21-collection-selection/benign-binding-20261024T193834394034Z/benign_binding.json"
SCHEMA = "2026-10-24.21"
RUNNER = "4933ff5c9c56bd097ce565d14a7173bd281dd124aca43d1df0dbe76315e64b9c"
OUT_DIR = ROOT / "v21-model-fit"
HOST_CONTRACT = None  # optional path override; None -> trainer.HOST_FEATURE_PATH (deployed 35 ebpf counters)
# FlyLegitBot and Gafgyt each have amd64-static members in training and i386-static members in validation in the
# frozen mode-matched selection, so that split is not strictly family-held-out for them. D4 is family-held-out, so
# fold these two families WHOLLY into training: every validation malware family is then strictly never-seen in
# training. This moves the handful of their validation cases into training (counted/named in the metrics report).
FOLD_FAMILIES_INTO_TRAINING = {"FlyLegitBot", "Gafgyt"}


def save_rows(path, rows):
    if not rows:
        return
    fields = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with Path(path).open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore", restval="")
        writer.writeheader()
        writer.writerows(rows)


def latest_validation():
    reports = sorted(V21_ATTEMPT.glob("validation-*.json"))
    return json.loads(reports[-1].read_text())


def case_metadata():
    """sample -> {class,label,mode,group_id,split} from the frozen selection + binding."""
    meta = {}
    for case in json.loads(MALWARE_SEL.read_text())["cases"]:
        sample = case["member_sha256"] + ".zip"
        split = "training" if case["family"] in FOLD_FAMILIES_INTO_TRAINING else case["split"]
        meta[sample] = {"class": "malware", "label": 1, "mode": case["mode"],
                        "group_id": "malware_signature::" + case["family"], "split": split,
                        "frozen_split": case["split"], "family": case["family"]}
    for case in json.loads(BENIGN_BIND.read_text())["cases"]:
        sample = case["sample"] if case["sample"].endswith(".zip") else case["sample"] + ".zip"
        meta[sample] = {"class": "benign", "label": 0, "mode": case["mode"],
                        "group_id": "benign_project::" + case["project"], "split": case["split"],
                        "frozen_split": case["split"], "family": case["project"]}
    return meta


def prepare(trainer, data):
    contract = Path(HOST_CONTRACT) if HOST_CONTRACT else trainer.HOST_FEATURE_PATH
    host = list(json.loads(contract.read_text())["host"])
    if HOST_CONTRACT is None and len(host) != 175:
        raise ValueError("Deployed host contract must be 35 families x 5 summaries")
    host_signals = {name.removeprefix("host__").rsplit("__", 1)[0] for name in host}
    meta = case_metadata()
    validation = latest_validation()
    accepted = [r["sample"] for r in validation["results"]
                if r["status"] == "accepted" and r["label"] in ("benign", "malware")]
    records, eligibility, alignment = [], [], []
    parity = 0
    for sample in sorted(accepted):
        case = meta[sample]
        sample_dir = V21_ATTEMPT / "runs" / sample
        run_json = next(sample_dir.glob("output/run_*/run.json"))
        metadata = json.loads(run_json.read_text())
        if metadata.get("telemetry_schema_version") != SCHEMA or metadata.get("malware_runner_sha256") != RUNNER:
            raise ValueError("schema/runner mismatch: " + sample)
        if metadata.get("collection_quality_status") != "accepted" or metadata["target_exec"].get("status") != "observed":
            raise ValueError("non-accepted/exec-unobserved reached the dataset: " + sample)
        telemetry = data.p4.load_telemetry_rows(sample_dir)
        if len(telemetry) != 40:
            raise ValueError("telemetry != 40 windows: " + sample)
        summary = {signal: data.aggregate([float(w[signal]) for w in telemetry])
                   for signal in host_signals | set(data.p4.P4_FEATURES)}
        host_values = {name: summary[name.removeprefix("host__").rsplit("__", 1)[0]][name.rsplit("__", 1)[1]]
                       for name in host}
        extracted, _, diag = data.p4.derive_p4_features(
            sample_dir.glob("output/run_*/packet_capture.pcap").__next__(), telemetry, metadata,
            byte_layer="ethernet", rate_window="nominal")
        aligned = diag["alignment_status"] == "unique"
        p4_values = {}
        if aligned:
            for signal in data.p4.P4_FEATURES:
                for statistic, stored in summary[signal].items():
                    name = "network__p4_" + signal + "__" + statistic
                    if not math.isclose(float(extracted[name]), stored, rel_tol=1e-9, abs_tol=1e-9):
                        raise ValueError("P4 parity mismatch: " + sample + " " + name)
                    parity += 1
            p4_values = {name: float(extracted[name]) for name in data.p4.P4_SAMPLE_FEATURES}
        row = {"sample": sample, "class": case["class"], "label": case["label"], "split": case["split"],
               "frozen_split": case.get("frozen_split", case["split"]), "family": case.get("family", ""),
               "mode": case["mode"], "group_id": case["group_id"], "position": 0,
               "run_id": metadata.get("run_id", ""), "return_code": metadata.get("return_code"),
               "post_target_lineage_raw_syscalls": int(metadata["target_exec"]["post_target_lineage_raw_syscalls"]),
               "p4_alignment_status": diag["alignment_status"], "p4_parity": "True" if aligned else "False"}
        row.update(host_values)
        row.update(p4_values)
        records.append(row)
        alignment.append({"sample": sample, "class": case["class"], "split": case["split"],
                          "group_id": case["group_id"], **diag})
        eligibility.append({"sample": sample, "class": case["class"], "mode": case["mode"],
                            "split": case["split"], "group_id": case["group_id"],
                            "p4_alignment_status": diag["alignment_status"]})
    return records, host, eligibility, alignment, parity


def populations(records):
    out = {}
    for split in ("training", "validation"):
        subset = [r for r in records if r["split"] == split]
        out[split] = {"samples": len(subset), "benign": sum(r["label"] == 0 for r in subset),
                      "malware": sum(r["label"] == 1 for r in subset),
                      "groups": len({r["group_id"] for r in subset})}
    return out


def mode_nuisance(training, validation, trainer, models):
    """Nuisance baseline over mode only (single cohort; no watch/cohort field)."""
    def features(rows):
        return [{"mode": r["mode"]} for r in rows]
    labels = trainer.np.asarray([r["label"] for r in training])
    oof = trainer.np.full(len(training), trainer.np.nan)
    train_feats = features(training)
    for train_idx, held_idx in trainer.make_splits(labels, trainer.np.asarray([r["group_id"] for r in training])):
        vec = trainer.DictVectorizer(sparse=False)
        est = trainer.random_forest()
        est.fit(vec.fit_transform([train_feats[i] for i in train_idx]), labels[train_idx])
        oof[held_idx] = est.predict_proba(vec.transform([train_feats[i] for i in held_idx]))[:, 1]
    vec = trainer.DictVectorizer(sparse=False)
    est = trainer.random_forest()
    est.fit(vec.fit_transform(train_feats), labels)
    probs = est.predict_proba(vec.transform(features(validation)))[:, 1]
    return oof, probs


def run():
    trainer, data, _pcap = frozen.dependencies()
    records, host, eligibility, alignment, parity = prepare(trainer, data)
    # Use the TRUE seed-42 interleaved collection order as the nuisance "position". (A class-sorted rank would
    # make position a trivial label proxy and spuriously inflate the nuisance baseline.)
    order = {c["sample"]: int(c["position"]) for c in json.loads(CASES_ORDER.read_text())}
    for r in records:
        r["position"] = order[r["sample"]]
    common = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = OUT_DIR / stamp
    analysis = attempt / "analysis"
    analysis.mkdir(parents=True, exist_ok=False)
    feature_fields = [*host, *data.p4.P4_SAMPLE_FEATURES]
    base = ["sample", "class", "label", "split", "mode", "group_id", "position", "run_id",
            "return_code", "post_target_lineage_raw_syscalls", "p4_alignment_status", "p4_parity"]
    save_rows(analysis / "eligible_dataset.csv", [{k: r.get(k, "") for k in base + feature_fields} for r in records])
    save_rows(analysis / "eligibility_audit.csv", eligibility)
    save_rows(analysis / "p4_alignment_audit.csv", alignment)

    output = analysis / "model-fit"
    models = output / "models"
    models.mkdir(parents=True)
    train_idx, val_idx = trainer.split_indices(common)
    training = [common[i] for i in train_idx]
    validation = [common[i] for i in val_idx]
    labels = trainer.np.asarray([r["label"] for r in training])
    all_train_idx, all_val_idx = trainer.split_indices(records)
    all_training = [records[i] for i in all_train_idx]
    all_held = [records[i] for i in all_val_idx]

    print("V21 EXPLORATORY: RF500, family/project-held-out, training-only selection", flush=True)
    oof, selections, folds = trainer.grouped_oof_main(training, host, labels)
    trainer.save_predictions(output / "training_grouped_oof_predictions.csv", training, oof, "v21_training_only_oof")
    host_oof, host_sel, _ = trainer.grouped_oof_host(all_training, host)
    selections.extend(host_sel)
    aux_oof = {kind: trainer.grouped_oof_auxiliary(training, kind)[0] for kind in ("activity_only", "nuisance_only")}
    aux_oof["mode_only"], _mode_val = mode_nuisance(training, validation, trainer, models)

    print("V21 FIT: scoring the .21 family-held-out validation (exploratory, no tuning)", flush=True)
    probabilities, selected, selection_details = trainer.fit_final_models(training, validation, host, models, "v21_final_fit")
    selections.extend(selected)
    probabilities.update(trainer.fit_auxiliary_models(training, validation, models))
    _oof2, probabilities["mode_only"] = mode_nuisance(training, validation, trainer, models)
    sensitivity, sens_sel, sens_details = trainer.fit_host_sensitivity(all_training, all_held, host, models)
    selections.extend(sens_sel)
    trainer.save_predictions(output / "validation_predictions.csv", validation, probabilities, "v21_exploratory_validation_no_tuning")
    trainer.save_predictions(output / "host_only_all_eligible_validation_predictions.csv", all_held,
                             {"host_all_eligible": sensitivity}, "v21_all_eligible_sensitivity")

    val_labels = trainer.np.asarray([r["label"] for r in validation])
    metrics = {name: trainer.binary_metrics(val_labels, values) for name, values in probabilities.items()}
    weights = trainer.bootstrap_weight_vectors(validation)
    strata = {}
    for value in sorted({r["mode"] for r in validation}):
        idx = [i for i, r in enumerate(validation) if r["mode"] == value]
        block = {"n": len(idx), "malware": int(val_labels[idx].sum()), "benign": int((val_labels[idx] == 0).sum())}
        if len(set(val_labels[idx].tolist())) == 2:   # ROC-AUC/BA undefined for a single-class stratum
            block.update({name: trainer.binary_metrics(val_labels[idx], values[idx]) for name, values in probabilities.items()})
        else:
            block["note"] = "single_class_stratum_metrics_skipped (expected for amd64-dynamic: malware is training-only)"
        strata[value] = block
    folded = sorted(r["sample"] for r in records if r.get("frozen_split") == "validation" and r["split"] == "training")
    held_out_val_families = sorted({r["family"] for r in validation if r["label"] == 1})
    summary = {
        "status": "complete_v21_exploratory_single_cohort", "evaluation_role": "posthoc_exploratory_no_merge",
        "dataset": str(V21_ATTEMPT), "primary_counts": populations(common), "host_sensitivity_counts": populations(records),
        "family_held_out_adjustment": {
            "families_folded_into_training": sorted(FOLD_FAMILIES_INTO_TRAINING),
            "reason": "frozen mode-matched split placed these families' amd64-static in training and i386-static in "
                      "validation; folded wholly into training so validation malware families are strictly held-out",
            "validation_malware_cases_moved_to_training": len(folded),
            "moved_samples": folded,
            "strictly_held_out_validation_malware_families": held_out_val_families},
        "feature_columns": {"p4": 145, "host": 145, "hybrid": 290}, "p4_parity_comparisons": parity,
        "held_out_validation": metrics,
        "training_grouped_oof": {name: trainer.binary_metrics(labels, values) for name, values in oof.items()},
        "auxiliary_training_oof": {name: trainer.binary_metrics(labels, values) for name, values in aux_oof.items()},
        "host_all_eligible_sensitivity": trainer.binary_metrics(trainer.np.asarray([r["label"] for r in all_held]), sensitivity),
        "group_weighted": {name: trainer.binary_metrics(val_labels, values, trainer.equal_group_weights(validation))
                           for name, values in probabilities.items()},
        "group_bootstrap_95pct": {name: trainer.bootstrap_summary(val_labels, values, weights) for name, values in probabilities.items()},
        "by_mode": strata,
        "activity_or_nuisance_claim_gate_triggered": any(
            metrics[k]["balanced_accuracy"] >= 0.75 for k in ("activity_only", "nuisance_only", "mode_only")),
        "validation_previously_consumed": True, "validation_tuning": "none",
        "limitations": [
            "Single examined cohort; post-hoc exploratory, not blind confirmation or generalization.",
            "Benign are CLI tools, not representative software; malware are acquisition-labelled ELF samples.",
            "amd64-dynamic malware is training-only (singleton families); that mode's validation is benign-only.",
            "Small N / family concentration -> high-variance estimates; P4 is offline PCAP reconstruction.",
            "Activity/nuisance baselines quantify shortcut risk; interpret accuracy only relative to them.",
        ]}
    save_rows(output / "host_family_selection.csv", selections)
    save_rows(output / "grouped_training_folds.csv", folds)
    frozen.write_json(output / "feature_selection.json", {"primary": selection_details, "sensitivity": sens_details})
    frozen.write_json(output / "model_sha256.json", {p.name: frozen.digest(p) for p in models.glob("*.joblib")})
    frozen.write_json(output / "metrics-primary.json", summary)
    print("V21 PRIMARY: " + json.dumps(metrics), flush=True)
    print("V21 SECONDARY: 100 training-only whole-group label permutations", flush=True)
    permutations = trainer.group_permutation_null(training, host, summary["training_grouped_oof"]["hybrid_29_plus_29"]["balanced_accuracy"])
    frozen.write_json(output / "training_group_label_permutations.json", permutations)
    summary["training_group_label_permutations"] = permutations
    frozen.write_json(output / "metrics.json", summary)
    print("COMPLETE: " + str(output / "metrics.json"), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--host-contract", default=None,
                        help="alternate host feature-columns JSON (e.g. the ADFA-validated descriptor contract)")
    args = parser.parse_args()
    global HOST_CONTRACT
    HOST_CONTRACT = args.host_contract
    run()


if __name__ == "__main__":
    main()
