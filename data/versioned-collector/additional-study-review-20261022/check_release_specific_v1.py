#!/usr/bin/env python3
"""Audit exact engineering-release inputs offline without promoting component evidence."""

import argparse
import copy
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import audit_remediation as binary_audit
import freeze_scoped_contract as regions
import propose_scoped_release as proposal
import run_performance_v3 as version


ROOT = Path(__file__).resolve().parent
DATASET = ROOT / "combined-analysis/20261022T092936019065Z/analysis/eligible_dataset.csv"
DATASET_SHA256 = "30793b92049be5d5e4ed3f4cd1b12ee1ba4699b1bde99d6140231289cf5e24ca"
SPLIT = ROOT / "within-family-exploratory/20261022T103648547175Z/split_dataset.csv"
SPLIT_SHA256 = "dddfab0d94729590fabd1264250ad0ac1a61002891f888ee0fcbceb414faaff0"
REQUIRED = ("performance", "common_payload", "helper_allowlists", "collection_form_tasks_fixtures",
            "scoped_fail_closed_coverage", "benign_null_order_rehearsal")


def promotable(gates):
    return all(gates.get(name) == "passed" for name in REQUIRED)


def self_test():
    gates = {name: "passed" for name in REQUIRED}
    assert promotable(gates)
    guards = []
    for name in REQUIRED:
        for status in ("failed", "blocked", "not_verified", None, True):
            changed = copy.deepcopy(gates)
            changed[name] = status
            assert not promotable(changed), (name, status)
        changed = copy.deepcopy(gates)
        del changed[name]
        assert not promotable(changed)
        guards.append(name)
    return guards


def assess(attempt, audit_path):
    inputs = {}

    def track(path, expected=None):
        path = Path(path).resolve()
        observed = version.identity.digest(path)
        if expected is not None and observed != expected:
            raise ValueError("Frozen release input changed: " + str(path))
        inputs[str(path)] = observed
        return path

    contract = version.gate.approved_contract()
    proposal.validate(contract["pairs"])
    track(contract["source_correction"], contract["source_correction_sha256"])
    correction = json.loads(Path(contract["source_correction"]).read_text())
    for name, digest in correction["input_hashes"].items():
        track(name, digest)
    assessment_path = track(proposal.ASSESSMENT, proposal.ASSESSMENT_SHA256)
    component = json.loads(assessment_path.read_text())
    for name, digest in component["input_hashes"].items():
        track(name, digest)
    for path, digest in ((DATASET, DATASET_SHA256), (SPLIT, SPLIT_SHA256)):
        track(path, digest)
        with path.open(newline="") as stream:
            if len(list(csv.DictReader(stream))) != 417:
                raise ValueError("Existing 417-case population changed")
    records = []
    for pair in contract["pairs"]:
        track(pair["source"], pair["source_sha256"])
        track(pair["benign_path"], pair["benign_sha256"])
        variants = [row for row in component["benign_build_variants"]
                    if (row["unit"], row["mode"], row["sha256"]) ==
                    (pair["unit"], pair["mode"], pair["benign_sha256"])]
        if len(variants) != 1:
            raise ValueError("Selected benign identity lacks exact component binding")
        for label, path, digest in (("malware", pair["source"], pair["malware_sha256"]),
                                    ("benign", pair["benign_path"], pair["benign_sha256"])):
            content = binary_audit.read_binary(Path(path), digest)
            facts = regions.executable_regions(content)
            expected = (1, 3) if pair["mode"] == proposal.I386 else (2, 62)
            if not facts["strict_static"] or (facts["elf_class"], facts["machine"]) != expected:
                raise ValueError("Selected executable mode differs")
            records.append({"id": digest, "label": label, "unit": pair["unit"],
                            "mode": pair["mode"], "role": pair["proposed_role"], **facts})
    relationships = regions.relationships([row for row in records if row["label"] == "malware"])
    if not relationships["effective_roles_allowed"] or relationships["exact_region_groups"]:
        raise ValueError("Corrected malware executable regions collide")
    audit = json.loads(track(audit_path).read_text())
    for name, digest in audit["input_hashes"].items():
        path = Path(name)
        track(path if path.is_absolute() else attempt / path, digest)
    track(ROOT / "audit_performance_v3.py", audit["auditor_sha256"])
    if audit["collection_ready"] or audit["malware_executions"]:
        raise ValueError("Benchmark audit asserts an unauthorized release")
    protocol = json.loads(track(attempt / "protocol.json").read_text())
    for name, digest in protocol["source_hashes"].items():
        track(name, digest)
    for name, digest in protocol["files"].items():
        track(attempt / name, digest)
    for name in ("guest_result.json", "evidence.tgz", "startup-readiness.json",
                 "staged_snapshot.json", "final_vm_state.json"):
        track(attempt / name)
    manifest = json.loads((attempt / "manifest.json").read_text())
    if manifest["cases"] != version.gate.plan() or protocol["schema"] != version.performance.SCHEMA:
        raise ValueError("Benchmark version or design differs")
    selected_hashes = {row["benign_sha256"] for row in contract["pairs"]}
    payload_coverage = selected_hashes.intersection(manifest["files"].values())
    gates = {"performance": "passed" if audit["performance_accepted"] else "failed",
             "common_payload": "blocked", "helper_allowlists": "not_verified",
             "collection_form_tasks_fixtures": "not_verified", "scoped_fail_closed_coverage": "not_verified",
             "benign_null_order_rehearsal": "blocked"}
    track(Path(__file__))
    return {"schema": "scoped-release-specific-assessment-v1", "status": "blocked_before_collection_release",
            "collection_ready": promotable(gates), "performance_accepted": audit["performance_accepted"],
            "malware_executions": 0, "vm_operations": 0, "model_fits": 0,
            "existing_417_assignments_unchanged": True, "contract": contract,
            "binary_records": records, "lineage_review": relationships,
            "selected_benign_component_bindings_verified": 16,
            "selected_benign_hashes_in_benchmark_payload": sorted(payload_coverage),
            "benchmark_is_final_release_payload": False, "release_gates": gates,
            "actual_performance_attempt": str(attempt), "independent_performance_audit": str(audit_path),
            "performance_status": audit["status"], "actual_benchmark_cases": audit["actual_cases"],
            "accepted_measurements": audit["accepted_measurements"], "negative_guards": self_test(),
            "limitations": [
                "32 bounded in-memory ELF inspections; no malware member written or executed.",
                "Component guest/build input hashes are reused, not a new release task/fixture rehearsal.",
                "Benchmark payload has performance tasks, not the selected 16 benign release tasks.",
                "No exact final helper allowlists, collection-form arguments/fixtures or 32-case/null order accepted.",
                "No new arbitrary namespace/non-leader/ABI/bypass coverage or library/interpreter attestation.",
                "No accepted performance median can be inferred from an incomplete prefix.",
                "Exact executable-region uniqueness is not source/configuration-lineage independence.",
                "No automatic retry, gate amendment, full collection, fitting or historical merge authorized."],
            "input_hashes": inputs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path, nargs="?")
    parser.add_argument("--audit", type=Path)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    guards = self_test()
    print("PASS fail-closed release promotion guards:", ", ".join(guards))
    if options.self_test:
        return
    if options.attempt is None or options.audit is None:
        parser.error("attempt and --audit are required for a saved release assessment")
    attempt, audit_path = options.attempt.resolve(), options.audit.resolve()
    if audit_path.parent != attempt:
        raise ValueError("Independent audit must belong to the actual attempt")
    report = assess(attempt, audit_path)
    destination = ROOT / "release-specific-assessments" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    version.identity.save(destination / "assessment.json", report)
    version.identity.save(destination / "output_hashes.json", {"assessment.json": hashlib.sha256(
        (destination / "assessment.json").read_bytes()).hexdigest()})
    print(destination)
    print(json.dumps({key: report[key] for key in ("status", "performance_accepted", "collection_ready",
                      "selected_benign_component_bindings_verified", "release_gates")}, indent=2))


if __name__ == "__main__":
    main()