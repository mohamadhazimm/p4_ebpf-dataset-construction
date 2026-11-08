#!/usr/bin/env python3
"""Freeze a reviewable release proposal without assigning effective roles or launching."""

import argparse
import copy
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from validate_remediation_workloads import digest, expect, save


ROOT = Path(__file__).resolve().parent
ASSESSMENT = ROOT / "current-release-assessments/20261023T065959031921Z/readiness.json"
ASSESSMENT_SHA256 = "0edd6d33fedc193608f8d9cc79b125c68d406baf5797847811ef1bfcbb2e1c06"
INVENTORY = ROOT / "current-release-assessments/20261023T060937943623Z/remaining_malware_inventory.json"
IDENTITY = ROOT / "exec-identity-readiness/20261023T075642576210Z/identity-validation-complete-20261023T080126521309Z.json"
IDENTITY_SHA256 = "dc9ac2b3bc097bb994738a648229c2ab906895602c5f93841bee8f1acf117b58"
AMD64 = "native_amd64_static"
I386 = "native_i386_static"


def validate(pairs):
    expect(len(pairs) == 16, "Expected sixteen proposed pairs")
    for key in ("unit", "malware_sha256", "benign_sha256"):
        expect(len({row[key] for row in pairs}) == 16, "Repeated proposal identity: " + key)
    expect(Counter(row["mode"] for row in pairs) == {AMD64: 8, I386: 8}, "Proposed ABI budgets differ")
    expect(Counter(row["family"] for row in pairs) == {"FlyLegitBot": 2, "Mirai": 7, "XorDDoS": 7}, "Proposed family budgets differ")
    for role in ("training", "validation"):
        rows = [row for row in pairs if row["proposed_role"] == role]
        expect(len(rows) == 8 and Counter(row["mode"] for row in rows) == {AMD64: 4, I386: 4}, "Proposed role/ABI balance differs")
    expect(all(row["mode"] == row["benign_mode"] and row["proposed_role"] in ("training", "validation") for row in pairs), "Unmatched proposed mode or role")
    return True


def propose(assessment, inventory):
    variants = assessment["benign_build_variants"]
    units = assessment["independent_program_units"]
    fixed = sorted(row["unit"] for row in units if I386 not in row["modes"])
    flexible = sorted(row["unit"] for row in units if I386 in row["modes"])
    expect(len(fixed) == 4 and len(flexible) == 12, "Validated unit boundary changed")
    benign = []
    for index, unit in enumerate(fixed):
        benign.append({"unit": unit, "mode": AMD64, "proposed_role": "training" if index % 2 == 0 else "validation"})
    for index, unit in enumerate(flexible):
        benign.append({"unit": unit, "mode": AMD64 if index % 6 < 2 else I386,
                       "proposed_role": "training" if index < 6 else "validation"})
    malware = []
    for family, mode, count, training in (("FlyLegitBot", AMD64, 1, 1), ("FlyLegitBot", I386, 1, 0),
                                           ("Mirai", AMD64, 7, 3), ("XorDDoS", I386, 7, 4)):
        available = sorted((row for row in inventory if row["family"] == family and row["mode"] == mode), key=lambda row: row["sha256"])
        expect(len(available) >= count, "Source quota unavailable")
        for index, row in enumerate(available[:count]):
            malware.append({**row, "proposed_role": "training" if index < training else "validation"})
    pairs = []
    for role in ("training", "validation"):
        for mode in (AMD64, I386):
            left = sorted((row for row in benign if row["proposed_role"] == role and row["mode"] == mode), key=lambda row: row["unit"])
            right = sorted((row for row in malware if row["proposed_role"] == role and row["mode"] == mode), key=lambda row: (row["family"], row["sha256"]))
            expect(len(left) == len(right), "Pairing quota differs")
            for control, target in zip(left, right):
                build = next(row for row in variants if row["unit"] == control["unit"] and row["mode"] == mode)
                pairs.append({"unit": control["unit"], "proposed_role": role, "mode": mode,
                              "family": target["family"], "malware_sha256": target["sha256"],
                              "source": target["source"], "source_sha256": target["source_sha256"],
                              "benign_sha256": build["sha256"], "benign_path": build["path"], "benign_mode": build["mode"]})
    validate(pairs)
    return pairs


def self_test():
    assessment = json.loads(ASSESSMENT.read_text())
    inventory = json.loads(INVENTORY.read_text())
    pairs = propose(assessment, inventory)
    expect(propose(assessment, list(reversed(inventory))) == pairs, "Proposal depends on input ordering")
    guards = []
    for kind in ("duplicate_unit", "duplicate_malware", "duplicate_benign", "wrong_mode", "wrong_role"):
        changed = copy.deepcopy(pairs)
        if kind.startswith("duplicate_"):
            key = {"duplicate_unit": "unit", "duplicate_malware": "malware_sha256", "duplicate_benign": "benign_sha256"}[kind]
            changed[1][key] = changed[0][key]
        elif kind == "wrong_mode":
            changed[0]["benign_mode"] = I386
        else:
            changed[0]["proposed_role"] = "validation"
        try:
            validate(changed)
        except ValueError:
            guards.append(kind)
        else:
            raise AssertionError("Invalid proposed allocation accepted: " + kind)
    return guards


def run():
    inputs = {}

    def track(path, expected=None):
        observed = digest(path)
        expect(expected is None or observed == expected, "Changed frozen proposal input: " + str(path))
        inputs[str(path.resolve())] = observed
        return json.loads(path.read_text()) if path.suffix == ".json" else None

    assessment = track(ASSESSMENT, ASSESSMENT_SHA256)
    identity = track(IDENTITY, IDENTITY_SHA256)
    expect(identity["executed_inodes_verified"] == 4 and identity["p4_window_comparisons"] == 4640, "Identity evidence incomplete")
    for name, expected in assessment["input_hashes"].items():
        track(Path(name), expected)
    inventory = track(INVENTORY)
    pairs = propose(assessment, inventory)
    for row in pairs:
        track(Path(row["source"]), row["source_sha256"])
        track(Path(row["benign_path"]), row["benign_sha256"])
    anchor = Path(assessment["known_family_anchor"])
    track(anchor / "split_dataset.csv", "dddfab0d94729590fabd1264250ad0ac1a61002891f888ee0fcbceb414faaff0")
    with (anchor / "split_dataset.csv").open(newline="") as stream:
        expect(len(list(csv.DictReader(stream))) == 417, "Existing known-family population differs")
    track(Path(__file__))
    destination = ROOT / "release-proposals" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    report = {"schema": "scoped-release-proposal-v1", "status": "awaiting_explicit_contract_approval",
              "collection_ready": False, "roles_effective": False, "launch_authorized": False,
              "malware_executions": 0, "vm_operations": 0, "model_fits": 0,
              "existing_417_assignments_unchanged": True, "pairs": pairs,
              "selection_rule": "No score/runtime filtering: fixed family/mode budgets, ascending source SHA256, sorted distinct benign units; sixteen is maximum from currently validated benign units, not a global source limit.",
              "proposed_scope": "32-case engineering pilot only; known-family exploratory roles, eight training/eight validation pairs; no detector precision, superiority, blind evaluation or malware-lineage-independence claim; no .18 capture merge.",
              "prospective_performance_acceptance_proposal": {
                  "conditions": "Same owned cgroup and substantive benign task; baseline, original sensors, and full identity candidate; freeze command/input/order and boundaries before new measurements.",
                  "design": "Five counterbalanced paired repetitions per ABI and substantive file/network task; two unscored warmups per condition; task-scoped wait4 CPU/wall and separate recorder CPU/RSS; report full paired values and failures.",
                  "full_vs_original_task_wall_median_ratio_max": 1.10,
                  "full_vs_original_task_wall_any_pair_ratio_max": 1.25,
                  "full_vs_original_task_cpu_median_ratio_max": 1.15,
                  "recorder_rss_mib_max": 256,
                  "observed_sensor_error_loss_or_packet_counter_gaps_max": 0,
                  "rate_scope": "Fixed application requests/owned bytes and measured event rate from approved tasks only; refuse extrapolation to arbitrary rate or global-hook/kernel-map cost.",
                  "failure_policy": "Preserve every failure; no automatic retries or post-result budget changes; acceptance is bounded to the frozen benign envelope, not arbitrary malware performance. These proposed limits are not yet approved.",
              },
              "required_before_any_collection_release": [
                  "Explicit approval of pilot-only precision scope, proposed new roles/mode/family budgets and prospective performance tolerances; no malware launch approval is implied.",
                  "Offline conservative executable-region/lineage review before making proposed roles effective; exact hashes alone do not establish independent malware units.",
                  "Release-specific fail-closed unsupported namespace/ABI/network-bypass contract; no general packet ownership or bypass-completeness claim.",
                  "Fresh versioned common payload with exact helper allowlists, task fixtures/outcomes, pinned identity runner and saved-only acceptance audit; preserve existing .18 and .19/.20 evidence.",
                  "Approved bounded performance checks and common-snapshot benign/null/order rehearsal with strict quality/exec/hash/archive/P4 gates; then separate explicit launch authorization.",
              ], "negative_guards": self_test(), "input_hashes": inputs}
    save(destination / "proposal.json", report)
    save(destination / "output_hashes.json", {"proposal.json": digest(destination / "proposal.json")})
    print(destination)
    print(json.dumps({"pairs": len(pairs), "input_hashes_verified": len(inputs), "collection_ready": False, "proposal_sha256": digest(destination / "proposal.json")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    print("PASS", self_test()) if options.self_test else run()