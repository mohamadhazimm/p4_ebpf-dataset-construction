#!/usr/bin/env python3
"""Reassess exact matching after additional guest checks, without assigning roles."""

import argparse
import copy
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import assess_current_release as prior
import check_additional_benign as additional
from validate_remediation_workloads import digest, expect, save


ROOT = prior.ROOT
PREVIOUS = ROOT / "current-release-assessments/20261023T060937943623Z"
GUEST = ROOT / "additional-benign-guest-readiness/20261023T065653342361Z"


def cases_match(cases, results):
    expected = {(row["unit"], row["mode"]): row["sha256"] for row in cases}
    expect(len(cases) == len(expected) == len(results) == 24, "Case population differs")
    seen = set()
    for row in results:
        identity = row["unit"], row["mode"]
        expect(identity in expected and identity not in seen and row["status"] == "accepted" and row["executable_sha256"] == expected[identity], "Case status/identity differs")
        expect(all(receipt["returncode"] == receipt["expected_returncode"] for receipt in row["receipts"]), "Unaccepted command")
        seen.add(identity)


def self_test():
    cases = [{"unit": "unit-%02d" % index, "mode": "static", "sha256": str(index)} for index in range(24)]
    results = [{"unit": row["unit"], "mode": row["mode"], "executable_sha256": row["sha256"], "status": "accepted", "receipts": [{"returncode": 0, "expected_returncode": 0}]} for row in cases]
    cases_match(cases, results)
    for kind in ("missing", "duplicate", "identity", "return", "status"):
        changed = copy.deepcopy(results)
        if kind == "missing":
            changed.pop()
        elif kind == "duplicate":
            changed[-1] = changed[0]
        elif kind == "identity":
            changed[0]["executable_sha256"] = "changed"
        elif kind == "return":
            changed[0]["receipts"][0]["returncode"] = 1
        else:
            changed[0]["status"] = "failed_preserved"
        try:
            cases_match(cases, changed)
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupted case population accepted: " + kind)
    return {"case_guards": 5, "matching_guards": prior.self_test()}


def run():
    inputs = {}

    def track(path, expected=None):
        actual = digest(path)
        expect(expected is None or actual == expected, "Frozen assessment input changed: " + str(path))
        inputs[str(path)] = actual
        return json.loads(path.read_text()) if path.suffix == ".json" else None

    from export_original_sources import helper_module
    helper_module().verify_production()
    old = track(PREVIOUS / "readiness.json", "ac0d89bd02e1e8a6279826f753aad17b51a63c2f6bae797c85cd77fcb7faa3a7")
    output_hashes = track(PREVIOUS / "output_hashes.json")
    inventory = track(PREVIOUS / "remaining_malware_inventory.json", output_hashes["remaining_malware_inventory.json"])
    for name, expected in old["input_hashes"].items():
        track(Path(name), expected)
    manifest = track(GUEST / "manifest.json")
    protocol = track(GUEST / "protocol.json", "8282823554a2322a3591c43b31ad9cf578b601e05db984f53c21c9f7e9778b64")
    accepted = track(GUEST / "readiness.json", "bc0bd754c44ee8a25077a6d2ca16eb6caa2f41df645eaa2d3bf263ef21a8d71c")
    guest = track(GUEST / "guest_validation.json", accepted["guest_report_sha256"])
    track(GUEST / "evidence.tgz", accepted["evidence_sha256"])
    state = track(GUEST / "final_vm_state.json")
    for group in ("source_hashes", "payload_source_hashes"):
        for name, expected in protocol[group].items():
            track(Path(name), expected)
    for name, expected in protocol["hashes"].items():
        track(GUEST / name, expected)
    cases_match(manifest["cases"], guest["results"])
    expect(accepted["status"] == "accepted_24_benign_guest_tasks_and_host_generated_output_checks" and len(accepted["generated_outputs_compiled_and_exercised_on_host"]) == 8, "Guest generated-output checks incomplete")
    expect(state["guest"]["VMState"] == '"poweroff"' and state["guest"]["CurrentSnapshotName"] == '"clean-tls-paired-2026-10-19"' and state["sink"]["VMState"] == '"running"', "Saved cleanup differs")
    files = additional.evidence(GUEST)
    for result in guest["results"]:
        row = next(case for case in manifest["cases"] if (case["unit"], case["mode"]) == (result["unit"], result["mode"]))
        prefix = row["project"] + "-" + row["mode"] + "/"
        for name, expected in dict(result["inputs"], **result["outputs"]).items():
            expect(Path(name).name == name and hashlib.sha256(files[prefix + name]).hexdigest() == expected, "Saved guest task bytes differ")
    index, _manifests = prior.audit.source_index()
    used_hashes, used_programs, used_projects = prior.feasibility.prior_units(index)
    variants = list(old["benign_build_variants"])
    for row in manifest["cases"]:
        path = Path(row["path"])
        track(path, row["sha256"])
        with path.open("rb") as stream:
            facts = prior.elf_header(stream.read(1048576))
        program = prior.feasibility.canonical_program(row["project"], path.name)
        expect(facts["mode"] == row["mode"] and facts["elf_type"] == 2 and row["sha256"] not in used_hashes and (row["project"], program) not in used_programs and row["project"] not in used_projects, "Additional source mode/prior program exclusion differs")
        variants.append({"project": row["project"], "program": program, "unit": row["unit"], "mode": row["mode"], "path": str(path), "sha256": row["sha256"]})
    units = [{"unit": unit, "modes": sorted({row["mode"] for row in variants if row["unit"] == unit}), "prospective_role": "unassigned_pending_review"} for unit in sorted({row["unit"] for row in variants})]
    expect(len(units) == 16 and len(variants) == len({row["sha256"] for row in variants}) == 32, "Independent unit/variant boundary differs")
    matches = prior.maximum_matching(units, inventory)
    expect(len(matches) == 16 and len({row["malware_sha256"] for row in matches}) == 16, "Exact matching cardinality differs")
    destination = ROOT / "current-release-assessments" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    for path in (Path(__file__), Path(prior.__file__), Path(additional.__file__)):
        track(path)
    report = {"schema": "extended-benign-release-assessment-v1", "collection_ready": False, "collection_started": False,
              "status": "sixteen_guest_validated_program_units_release_contract_pending", "independent_program_units": units,
              "benign_build_variants": variants, "maximum_potential_matched_pairs_from_these_sixteen_units": 16,
              "hypothetical_matching_witness_not_a_selection": matches, "prospective_roles_assigned": False,
              "remaining_source_modes": dict(Counter(row["mode"] for row in inventory)),
              "mode_range_without_role_family_or_precision_constraints": {"amd64_static_minimum": 4, "amd64_static_maximum": 10, "i386_static_minimum": 6, "i386_static_maximum": 12, "total_pairs": 16},
              "known_family_anchor": old["known_family_anchor"], "existing_417_assignments_unchanged": True,
              "known_family_evaluation_is_exploratory_not_blind": True, "prior_plan_hashes_excluded": len(used_hashes),
              "prior_program_units_excluded": len(used_programs), "guest_task_variants": 24,
              "saved_guest_evidence_members_rehashed": len(files), "generated_output_checks_on_host_not_guest": 8,
              "vm_operations_in_this_assessment": 0, "sample_executions_in_this_assessment": 0, "model_fits": 0,
              "blockers": ["Exact prospective task/program/lineage units, known-family roles, mode quotas and precision target still require review; matching alone assigns none.",
                           *old["blockers"][2:]], "negative_guards": self_test(), "input_hashes": inputs}
    save(destination / "readiness.json", report)
    save(destination / "output_hashes.json", {"readiness.json": digest(destination / "readiness.json")})
    print(destination, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--run", action="store_true")
    options = parser.parse_args()
    print("PASS", self_test()) if options.self_test else run()