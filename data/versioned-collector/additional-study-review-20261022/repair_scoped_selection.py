#!/usr/bin/env python3
"""Propose deterministic source-boundary/code-duplicate corrections, never launch."""

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import freeze_scoped_contract as contract
import propose_scoped_release as selection
from validate_remediation_workloads import digest, expect, save


ROOT = Path(__file__).resolve().parent
REVIEW = ROOT / "release-contracts/20261023T081114963922Z/contract.json"
REVIEW_SHA256 = "e8532573dceb0c376c13afff8c21d7ed955815b9760f5deb39d455e4cffc5987"


def revise(pairs, candidates):
    used_hashes, used_code = set(), set()
    result, changes = [], []
    for original in pairs:
        compatible = sorted((row for row in candidates if row["family"] == original["family"] and row["mode"] == original["mode"]), key=lambda row: row["sha256"])
        compatible.sort(key=lambda row: row["sha256"] != original["malware_sha256"])
        target = next((row for row in compatible if row["sha256"] not in used_hashes and row["code_key"] not in used_code), None)
        expect(target is not None, "No valid unique-code replacement within approved family/mode quota")
        used_hashes.add(target["sha256"])
        used_code.add(target["code_key"])
        revised = {**original, "malware_sha256": target["sha256"], "source": target["source"], "source_sha256": target["source_sha256"]}
        result.append(revised)
        if revised["malware_sha256"] != original["malware_sha256"]:
            changes.append({"old_sha256": original["malware_sha256"], "new_sha256": revised["malware_sha256"],
                            "role": original["proposed_role"], "family": original["family"], "mode": original["mode"],
                            "basis": "Declared ELF region boundary or exact executable-region duplication, not runtime outcome or score"})
    selection.validate(result)
    return result, changes


def run():
    expect(digest(REVIEW) == REVIEW_SHA256 and digest(contract.PROPOSAL) == contract.PROPOSAL_SHA256, "Frozen source review or proposal changed")
    approved = json.loads(REVIEW.read_text())
    for path, expected in approved["input_hashes"].items():
        expect(digest(Path(path)) == expected, "Changed original approved input")
    inventory = json.loads(selection.INVENTORY.read_text())
    candidates, rejected = [], []
    for row in inventory:
        expect(digest(Path(row["source"])) == row["source_sha256"], "Changed inventory container")
        content = contract.binary_audit.read_binary(Path(row["source"]), row["sha256"])
        try:
            facts = contract.executable_regions(content)
            expect(facts["strict_static"] and (facts["elf_class"], facts["machine"]) == ((1, 3) if row["mode"] == selection.I386 else (2, 62)), "Source mode differs")
        except ValueError as error:
            rejected.append({"sha256": row["sha256"], "family": row["family"], "mode": row["mode"], "error": str(error)})
            continue
        candidates.append({**row, "code_key": (row["mode"], facts["representation"], facts["code_sha256"]), "code_facts": facts})
    pairs, changes = revise(approved["pairs"], candidates)
    expect(revise(approved["pairs"], list(reversed(candidates))) == (pairs, changes), "Correction depends on inventory order")
    for original, revised in zip(approved["pairs"], pairs):
        for key in ("unit", "proposed_role", "mode", "family", "benign_sha256", "benign_path", "benign_mode"):
            expect(original[key] == revised[key], "Correction changed approved non-source allocation")
    selected = [row for row in candidates if row["sha256"] in {pair["malware_sha256"] for pair in pairs}]
    expect(len(selected) == len({row["code_key"] for row in selected}) == 16, "Corrected identities/code units are not unique")
    expect(changes, "No source changes to propose")
    destination = ROOT / "release-proposals" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    report = {"schema": "scoped-source-correction-proposal-v1", "status": "awaiting_explicit_source_amendment_approval",
              "previous_contract": str(REVIEW), "previous_contract_sha256": REVIEW_SHA256,
              "unchanged_scope_and_performance_approval": approved["approval"], "pairs": pairs, "changes": changes,
              "inventory_candidates_reviewed": len(inventory), "valid_region_candidates": len(candidates),
              "rejected_region_candidates": rejected, "selected_code_facts": selected,
              "selection_rule": "Preserve each previously approved source where bounded and code-unique; otherwise choose first ascending source SHA within the identical family/mode slot with unused executable-region fingerprint. No execution, outcome, model score or role-budget change.",
              "existing_417_assignments_unchanged": True, "roles_effective": False, "collection_ready": False,
              "malware_launch_authorized": False, "malware_executions": 0, "vm_operations": 0, "model_fits": 0,
              "limits": "Exact-region uniqueness is not source/configuration lineage certification; this amendment remains unapproved and old proposal/review remain immutable.",
              "input_hashes": {**approved["input_hashes"], str(REVIEW): REVIEW_SHA256,
                                str(Path(__file__).resolve()): digest(Path(__file__))}}
    save(destination / "source-correction.json", report)
    save(destination / "output_hashes.json", {"source-correction.json": digest(destination / "source-correction.json")})
    print(json.dumps({"proposal": str(destination / "source-correction.json"), "sha256": digest(destination / "source-correction.json"),
                      "changes": changes, "reviewed": len(inventory), "valid": len(candidates), "rejected": len(rejected)}))


if __name__ == "__main__":
    run()