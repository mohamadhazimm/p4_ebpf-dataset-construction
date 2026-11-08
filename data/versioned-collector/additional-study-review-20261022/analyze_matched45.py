#!/usr/bin/env python3
"""Validate the matched extension and fit exploratory models without VM operations."""

import argparse
import fcntl
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import collect_matched45 as collection
import ready_matched45 as ready

sys.path.insert(0, str(ready.EXPANSION))
import analyze_combined_cohorts as combined


BASE = ready.EXPANSION / "combined-analysis/20261022T044439885696Z"
CAPTURE = collection.RELEASE / "collection"
OUTPUT_ROOT = ready.ROOT / "combined-analysis"


def aligned(record):
    return record["p4_alignment_status"] == "unique" and record["p4_parity"] in (True, "True")


def check_population(records):
    trainer, _, _ = combined.frozen.dependencies()
    for key in ("sample", "executable_sha256"):
        if len({row[key] for row in records}) != len(records):
            raise ValueError("Duplicate merged identity: " + key)
    for row in records:
        if row["group_id"] in combined.EXCLUDED_GROUPS or row["class"] not in ("benign", "malware"):
            raise ValueError("Excluded group/control reached model input")
        if row["label"] != int(row["class"] == "malware"):
            raise ValueError("Label/class disagreement")
    for population in (records, [row for row in records if aligned(row)]):
        trainer.split_indices(population)
        for split in ("training", "validation"):
            for mode in {row["mode"] for row in population if row["split"] == split}:
                if {row["label"] for row in population if row["split"] == split and row["mode"] == mode} != {0, 1}:
                    raise ValueError("Label-exclusive mode/split stratum")


def verify_inputs():
    ready.verify_release(collection.RELEASE)
    launch = ready.load(CAPTURE / "launch_manifest.json")
    for name, checksum in launch["frozen_hashes"].items():
        if ready.digest(ready.STUDY / name) != checksum:
            raise ValueError("Capture workflow changed: " + name)
    if ready.load(CAPTURE / "status.json")["stage"] != "capture_complete_retrieval_audited":
        raise ValueError("Capture is not complete and audited")
    final = ready.load(CAPTURE / "final_vm_state.json")
    if final["guest"]["VMState"] != '"poweroff"' or final["guest"]["CurrentSnapshotName"] != '"' + ready.helper.ORIGINAL + '"':
        raise ValueError("Saved clean cleanup evidence missing")
    base = ready.load(BASE / "combined_manifest.json")
    combined.frozen.verify_hashes(base["frozen_workflow_hashes"])
    for name, checksum in base["source_hashes"].items():
        if ready.digest(ready.STUDY / name) != checksum:
            raise ValueError("Prior source changed: " + name)
    for name, checksum in base["data_hashes"].items():
        if ready.digest(BASE / "analysis" / name) != checksum:
            raise ValueError("Prior prepared data changed: " + name)
    if ready.digest(BASE / "protocol.json") != base["protocol_sha256"]:
        raise ValueError("Prior protocol changed")
    return base


def prepare():
    base = verify_inputs()
    trainer, data, pcap_reader = combined.frozen.dependencies()
    host = list(ready.load(trainer.HOST_FEATURE_PATH)["host"])
    if len(host) != 175 or len(data.p4.P4_SAMPLE_FEATURES) != 145 or not all(name.startswith("host__ebpf_") for name in host):
        raise ValueError("Frozen host/P4 feature contract differs")
    attempt = OUTPUT_ROOT / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = attempt / "analysis"
    output.mkdir(parents=True, exist_ok=False)
    protocol = ready.load(collection.RELEASE / "preregistration.json")
    protocol["authorization"] = "User requested completion checks and model accuracy if validation passes"
    protocol["role"] = "Exploratory joint refit with eligible matched45 additions; inherited consumed validation, no tuning"
    ready.save(attempt / "protocol.json", protocol)
    combined.frozen.write_json(attempt / "status.json", {"stage": "validating_extension_and_prior_raw_captures"})
    counts, eligibility, diagnostics, records = Counter(), [], [], []
    nulls = defaultdict(list)
    signals = {name.removeprefix("host__").rsplit("__", 1)[0] for name in host}
    telemetry_contract = None

    def reconcile(record, run_dir, previous=False):
        nonlocal telemetry_contract
        metadata = ready.load(run_dir / "run.json")
        for key, expected in combined.EXPECTED_SETTINGS.items():
            if metadata.get(key) != expected:
                raise ValueError("Eligible collection contract differs: " + record["sample"] + ":" + key)
        execution = metadata["target_exec"]
        artifact = metadata["target_artifact"]
        machine = 3 if record["mode"] == "native_i386_static" else 62
        linkage = "dynamic" if record["mode"].endswith("dynamic") else "static"
        if (data.host_status(run_dir.parents[1]) != "completed"
                or execution.get("status") != "observed" or execution.get("match") != "exact"
                or artifact["e_machine"] != machine or artifact["linkage"] != linkage
                or artifact["execution_mode"] != ("native_compat" if machine == 3 else "native")
                or metadata["ebpf_event_diagnostics"].get("raw_syscalls_unresolved_abi") != 0):
            raise ValueError("Exact target/mode/ABI contract differs: " + record["sample"])
        if metadata["packet_capture_rmem_max_before"] != metadata["packet_capture_rmem_max_after_capture"]:
            raise ValueError("Capture buffer not restored")
        if metadata["packet_capture_interface_link_state_before_sample"] != {"operstate": "up", "carrier": 1}:
            raise ValueError("Interface link not verified up")
        if telemetry_contract is None:
            telemetry_contract = metadata["telemetry_feature_groups"]
        if metadata["telemetry_feature_groups"] != telemetry_contract:
            raise ValueError("Telemetry feature definitions differ")
        telemetry = data.p4.load_telemetry_rows(run_dir.parents[1])
        names = [name for values in telemetry_contract.values() for name in values]
        if len(telemetry) != 40 or len(set(names)) != 169 or len(names) != 169 or not all(
                math.isfinite(float(window[name])) for window in telemetry for name in names):
            raise ValueError("Invalid raw feature cells")
        counts["eligible_finite_raw_cells"] += 40 * 169
        counts["eligible_archive_members"] += ready.helper.verify_output_archive(run_dir.parents[1])
        with pcap_reader(str(run_dir / "packet_capture.pcap")) as reader:
            packets = sum(1 for _packet in reader)
        if any(metadata["packet_capture_statistics"].get(key) != packets for key in ("packets_captured", "packets_received_by_filter")):
            raise ValueError("Accepted PCAP records/counters differ")
        counts["eligible_pcap_records"] += packets
        summaries = {name: data.aggregate([float(window[name]) for window in telemetry])
                     for name in signals | set(data.p4.P4_FEATURES)}
        for name in host:
            signal, statistic = name.removeprefix("host__").rsplit("__", 1)
            value = summaries[signal][statistic]
            if previous and not math.isclose(float(record[name]), value, rel_tol=1e-9, abs_tol=1e-9):
                raise ValueError("Prior host summary changed")
            record[name] = value
            counts["host_summary_comparisons"] += 1
        extracted, _, diagnostic = data.p4.derive_p4_features(run_dir / "packet_capture.pcap", telemetry, metadata,
            byte_layer="ethernet", rate_window="nominal")
        if previous and record["p4_alignment_status"] != diagnostic["alignment_status"]:
            raise ValueError("Prior P4 alignment changed")
        diagnostics.append({"sample": record["sample"], "cohort": record["cohort"], **diagnostic})
        record["p4_alignment_status"] = diagnostic["alignment_status"]
        record["p4_parity"] = diagnostic["alignment_status"] == "unique"
        if record["p4_parity"]:
            for signal in data.p4.P4_FEATURES:
                for statistic, value in summaries[signal].items():
                    name = f"network__p4_{signal}__{statistic}"
                    if not math.isclose(float(extracted[name]), value, rel_tol=1e-9, abs_tol=1e-9):
                        raise ValueError("PCAP/stored-summary mismatch: " + record["sample"] + ":" + name)
                    if previous and not math.isclose(float(record[name]), value, rel_tol=1e-9, abs_tol=1e-9):
                        raise ValueError("Prior P4 summary changed")
                    counts["p4_summary_comparisons"] += 1
            record.update(extracted)
        record.update(source_run_dir=str(run_dir.relative_to(ready.STUDY)),
            source_metadata_sha256=ready.digest(run_dir / "run.json"), watched_path_count=len(metadata["filesystem_watch_paths"]))
        return record

    try:
        retrieval = collection.validate_retrieval(CAPTURE)
        if retrieval != ready.load(CAPTURE / "retrieval_validation.json"):
            raise ValueError("Fresh retrieval audit disagrees with saved completion evidence")
        ready.save(output / "extension_retrieval_validation.json", retrieval)
        previous, _ = combined.read_csv(BASE / "analysis/eligible_dataset.csv")
        for position, original in enumerate(previous, start=1):
            row = dict(original)
            for key in ("label", "position", "post_target_lineage_raw_syscalls", "watched_path_count"):
                row[key] = int(row[key])
            run_dir = ready.STUDY / row["source_run_dir"]
            if ready.digest(run_dir / "run.json") != row["source_metadata_sha256"]:
                raise ValueError("Prior metadata changed")
            records.append(reconcile(row, run_dir, previous=True))
            if position % 25 == 0 or position == len(previous):
                print(f"PRIOR RECONCILED {position}/{len(previous)}", flush=True)
        for case in ready.load(collection.RELEASE / "case_order.json"):
            audit_row = {key: case.get(key, "") for key in ("sample", "label", "split", "mode", "group_id", "position")}
            audit_row.update(reason="", host_eligible=0, common_aligned=0)
            eligibility.append(audit_row)
            sample_dir = CAPTURE / "runs" / case["sample"]
            paths = list(sample_dir.glob("output/run_*/run.json"))
            if not paths:
                audit_row["reason"] = "output_not_retrieved"
                continue
            if len(paths) != 1:
                raise ValueError("Ambiguous extension metadata")
            metadata = ready.load(paths[0])
            if data.host_status(sample_dir) != "completed" or metadata["collection_quality_status"] != "accepted":
                audit_row["reason"] = "retrieval_or_quality_not_accepted"
                continue
            execution = metadata["target_exec"]
            if execution.get("status") != "observed" or execution.get("match") != "exact":
                audit_row["reason"] = "exact_target_exec_not_observed"
                continue
            if case["label"] == "null":
                artifact = metadata["target_artifact"]
                machine = 3 if case["mode"] == "native_i386_static" else 62
                if (metadata["return_code"] != 0 or artifact["e_machine"] != machine
                        or artifact["execution_mode"] != ("native_compat" if machine == 3 else "native")
                        or artifact["linkage"] != ("dynamic" if case["mode"].endswith("dynamic") else "static")
                        or metadata["ebpf_event_diagnostics"].get("raw_syscalls_unresolved_abi") != 0):
                    raise ValueError("Null execution/mode/ABI failed")
                nulls[case["mode"]].append(execution["post_target_lineage_raw_syscalls"])
                audit_row["reason"] = "null_not_classifier_input"
                continue
            if case["label"] == "benign" and Path(execution["expected_path"]).name != case["program"]:
                raise ValueError("Benign executable basename differs")
            row = {"sample": case["sample"], "class": case["label"], "label": int(case["label"] == "malware"),
                "split": case["split"], "group_id": case["group_id"], "mode": case["mode"],
                "cohort": "matched45", "position": case["position"], "return_code": metadata["return_code"],
                "run_id": metadata.get("run_id"), "post_target_lineage_raw_syscalls": execution["post_target_lineage_raw_syscalls"],
                "executable_sha256": case["sha256"], "program": case.get("program", "")}
            records.append(reconcile(row, paths[0].parent))
            audit_row["host_eligible"] = 1
            audit_row["common_aligned"] = int(aligned(row))
            if not aligned(row):
                audit_row["reason"] = "p4_alignment_not_unique_host_sensitivity_retained"
            print("EXTENSION VALIDATED " + case["sample"] + ": " + row["p4_alignment_status"], flush=True)
        modes = {"native_amd64_dynamic", "native_amd64_static", "native_i386_static"}
        if set(nulls) != modes or any(len(values) != 2 for values in nulls.values()):
            raise ValueError("Fresh per-mode null calibration incomplete")
        check_population(records)
        common = [row for row in records if aligned(row)]
        labels = trainer.np.asarray([row["label"] for row in common if row["split"] == "training"])
        groups = trainer.np.asarray([row["group_id"] for row in common if row["split"] == "training"])
        trainer.make_splits(labels, groups)
        report = {"status": "compatible_and_reconciled_for_merged_exploratory_training",
            "host_eligible": combined.populations(records), "common_aligned": combined.populations(common),
            "extension_host_eligible": combined.populations([row for row in records if row["cohort"] == "matched45"]),
            "extension_common_aligned": combined.populations([row for row in common if row["cohort"] == "matched45"]),
            "extension_exclusions": dict(Counter(row["reason"] for row in eligibility if row["reason"])),
            "extension_retrieval_totals": retrieval["totals"], "counts": dict(counts),
            "feature_value_mismatches": 0, "executable_identity_overlap": 0, "global_group_overlap": [],
            "excluded_groups": sorted(combined.EXCLUDED_GROUPS), "low_activity_exclusions": 0,
            "null_maxima": {mode: max(values) for mode, values in nulls.items()},
            "activity_floors": {mode: max(values) + 25 for mode, values in nulls.items()},
            "settings_verified": combined.EXPECTED_SETTINGS,
            "evaluation_role": "Exploratory; inherited consumed validation, no tuning or confirmatory claim"}
        for name, values in (("eligible_dataset.csv", records), ("extension_eligibility_audit.csv", eligibility),
                             ("p4_alignment_audit.csv", diagnostics)):
            combined.save_rows(output / name, values)
        ready.save(output / "compatibility_audit.json", report)
        paths = [Path(__file__), Path(combined.__file__), BASE / "combined_manifest.json", BASE / "protocol.json",
            BASE / "analysis/eligible_dataset.csv", BASE / "analysis/model-fit/metrics.json",
            collection.RELEASE / "protocol.json", collection.RELEASE / "preregistration.json",
            collection.RELEASE / "case_order.json", CAPTURE / "launch_manifest.json", CAPTURE / "status.json",
            CAPTURE / "retrieval_validation.json", CAPTURE / "final_vm_state.json"]
        source_hashes = {str(path.relative_to(ready.STUDY)): ready.digest(path) for path in paths}
        source_hashes.update(base["source_hashes"])
        manifest = {"authorization": protocol["authorization"], "source_hashes": source_hashes,
            "frozen_workflow_hashes": base["frozen_workflow_hashes"],
            "data_hashes": {path.name: ready.digest(path) for path in output.iterdir() if path.is_file()},
            "protocol_sha256": ready.digest(attempt / "protocol.json"),
            "sample_execution": False, "original_data_modified": False}
        ready.save(attempt / "combined_manifest.json", manifest)
        verify_inputs()
        combined.frozen.write_json(attempt / "status.json", {"stage": "prepared", "host_cases": len(records), "common_cases": len(common)})
        print("PREPARED " + json.dumps({"attempt": str(attempt), "audit": report}), flush=True)
    except BaseException as error:
        combined.frozen.write_json(attempt / "status.json", {"stage": "stopped_requires_review", "error": str(error)})
        raise


def self_test():
    records = [{"sample": f"{split}-{label}", "executable_sha256": f"{split}-{label}",
                "split": split, "class": "malware" if label else "benign", "label": label,
                "group_id": f"{split}-{label}", "mode": "native_i386_static",
                "p4_alignment_status": "unique", "p4_parity": True}
               for split in ("training", "validation") for label in (0, 1)]
    check_population(records)
    for field, value in (("sample", records[0]["sample"]), ("executable_sha256", records[0]["executable_sha256"]),
                         ("group_id", records[0]["group_id"])):
        bad = [dict(row) for row in records]
        bad[-1][field] = value
        try:
            check_population(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("Failed to reject overlap: " + field)
    verify_inputs()
    print("PASS: frozen capture/base inputs; reject duplicate sample/hash and cross-split group; no VM/sample/model execution")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--self-test", action="store_true")
    actions.add_argument("--prepare-only", action="store_true")
    actions.add_argument("--train", type=Path)
    args = parser.parse_args()
    with (ready.NATIVE / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.self_test:
            self_test()
        elif args.prepare_only:
            prepare()
        else:
            original = combined.ROOT
            try:
                combined.ROOT = ready.ROOT
                combined.train(args.train)
            finally:
                combined.ROOT = original


if __name__ == "__main__":
    main()