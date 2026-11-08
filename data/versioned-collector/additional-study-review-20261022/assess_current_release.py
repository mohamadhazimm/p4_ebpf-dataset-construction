#!/usr/bin/env python3
"""Audit current benign readiness and maximum matching without allocating roles."""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import audit_remediation as audit
from audit_original_cohorts import elf_header
import assess_remediation_feasibility as feasibility
import check_live_attribution as probe
import validate_remediation_workloads as tasks


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source-recovery/20261022T055952526099Z/source_verification.json"
KNOWN = ROOT / "within-family-exploratory/20261022T103648547175Z"
STATIC = tasks.PREPARATION / "static-workload-builds/20261022T132929517727Z/result.json"
LIVE = ROOT / "attribution-live-capability/20261023T055432338935Z"
OVERHEAD = ROOT / "attribution-live-capability/20261023T060303975236Z"


def maximum_matching(units, malware):
    import numpy as np
    from scipy.sparse import csr_matrix
    from scipy.sparse.csgraph import maximum_bipartite_matching

    if len({row["unit"] for row in units}) != len(units) or len({row["sha256"] for row in malware}) != len(malware):
        raise ValueError("Duplicate program unit or executable identity")
    if not units or not malware:
        return []
    edges = np.array([[row["mode"] in unit["modes"] for row in malware] for unit in units], dtype=np.int8)
    assignments = maximum_bipartite_matching(csr_matrix(edges), perm_type="column")
    return [{"unit": units[index]["unit"], "malware_sha256": malware[int(column)]["sha256"],
             "mode": malware[int(column)]["mode"], "role": "unassigned_not_a_release"}
            for index, column in enumerate(assignments) if column >= 0]


def self_test():
    units = [{"unit": "flexible", "modes": ["static", "dynamic"]}, {"unit": "static-only", "modes": ["static"]}]
    malware = [{"sha256": "first", "mode": "static"}, {"sha256": "second", "mode": "dynamic"}]
    result = maximum_matching(units, malware)
    assert len(result) == 2 and next(row for row in result if row["unit"] == "static-only")["malware_sha256"] == "first"
    assert len(maximum_matching(units[:1], malware)) == 1
    assert not maximum_matching(units, [{"sha256": "other", "mode": "i386"}])
    for changed_units, changed_malware in ((units + units[:1], malware), (units, malware + malware[:1])):
        try:
            maximum_matching(changed_units, changed_malware)
        except ValueError:
            continue
        raise AssertionError("Duplicate matching identity accepted")
    return 5


def run():
    inputs = {}

    def track(path, expected=None):
        observed = probe.digest(path)
        if expected is not None and observed != expected:
            raise ValueError("Changed frozen assessment input: " + str(path))
        inputs[str(path)] = observed
        return json.loads(path.read_text()) if path.suffix == ".json" else None

    from export_original_sources import helper_module
    helper_module().verify_production()
    inherited = json.loads((feasibility.EVIDENCE / "input_hashes.json").read_text())
    index, manifests = audit.source_index()
    for path in manifests:
        track(path, inherited[str(path.resolve())])
    used_hashes, used_programs, used_projects = feasibility.prior_units(index)
    source = track(SOURCE, "796e319e937fd7fce1776c885cc4719dbe5a3dc5f4dbab35dff34ab0ff865b89")
    labels_path = ROOT / "attempts/20261022T052110153141Z/malware-535-review.json"
    labels = {row["sha256"]: row for row in track(labels_path, "6de58c766683cd07170b73c2247cc522021fe338bc8cb7ec8e15f5c6181290a3")}
    track(KNOWN / "protocol.json", "ca839ea66bf4aeff2ac7d2bc7651905fc87c48d434bb34829ba97183a5e36eb3")
    track(KNOWN / "split_dataset.csv", "dddfab0d94729590fabd1264250ad0ac1a61002891f888ee0fcbceb414faaff0")
    with (KNOWN / "split_dataset.csv").open(newline="") as stream:
        known_cases = list(csv.DictReader(stream))
    if len(known_cases) != 417 or {row["split"] for row in known_cases} != {"training", "validation"}:
        raise ValueError("Existing known-family assignments differ")
    candidates = []
    for row in source["sources"]:
        label = labels[row["sha256"]]
        family = label["family_labels"].split(";")[0]
        if row["sha256"] in used_hashes or row["mode"] not in feasibility.SUPPORTED_MODES or family.casefold() == "ddosagent" or label["family_status"] != "known":
            continue
        if not row["source_member_verified"]:
            raise ValueError("Unverified remaining source member")
        path = audit.STUDY / row["source_archive_path"]
        track(path, row["archive_sha256"])
        facts = elf_header(audit.read_binary(path, row["sha256"])[:1048576])
        if facts["mode"] != row["mode"]:
            raise ValueError("Remaining source strict ELF mode differs")
        candidates.append({"sha256": row["sha256"], "family": family, "mode": row["mode"],
                           "source": str(path), "source_sha256": row["archive_sha256"], "role": "unassigned_pending_review"})
    candidates.sort(key=lambda row: (row["family"], row["mode"], row["sha256"]))
    dynamic = track(tasks.PREPARATION / "executables.json", tasks.PINS["executables.json"])
    static = track(STATIC, "04a0ae6da4edc8aea6fc3dbc7f4861ee55b39328ef05b51c5521b84a77eb6e68")["executables"]
    variants = []
    for row in dynamic + static:
        path = Path(row["path"])
        track(path, row["sha256"])
        with path.open("rb") as stream:
            facts = elf_header(stream.read(1048576))
        mode = facts["mode"]
        program = feasibility.canonical_program(row["project"], path.name)
        if mode != row["mode"] or row["sha256"] in used_hashes or (row["project"], program) in used_programs:
            raise ValueError("Benign mode, executable or program exclusion differs")
        variants.append({"project": row["project"], "program": program, "unit": row["project"] + "::" + program,
                         "mode": mode, "path": str(path), "sha256": row["sha256"]})
    units = [{"unit": unit, "modes": sorted({row["mode"] for row in variants if row["unit"] == unit}),
              "new_project_relative_to_recent_plans": unit.split("::")[0] not in used_projects,
              "prospective_role": "unassigned_pending_review"} for unit in sorted({row["unit"] for row in variants})]
    if len(units) != 4 or len(variants) != 8:
        raise ValueError("The four-program/eight-build boundary differs")
    live = probe.audit_saved(LIVE, publish=False)
    overhead = probe.audit_saved(OVERHEAD, publish=False)
    for attempt in (LIVE, OVERHEAD):
        for name in ("protocol.json", "manifest.json", "guest_result.json", "evidence.tgz", "final_vm_state.json"):
            track(attempt / name)
    proposals = maximum_matching(units, candidates)
    for match in proposals:
        match["benign_variant"] = next(row for row in variants if row["unit"] == match["unit"] and row["mode"] == match["mode"])
    report = {"schema": "current-remediation-release-assessment-v1", "collection_ready": False,
              "status": "measured_benign_progress_release_contract_incomplete", "collection_started": False,
              "sample_executions_in_this_assessment": 0, "vm_operations_in_this_assessment": 0, "model_fits": 0,
              "known_family_anchor": str(KNOWN), "existing_417_assignments_unchanged": True,
              "prospective_roles_assigned": False, "known_family_evaluation_is_exploratory_not_blind": True,
              "prior_plan_hashes_excluded": len(used_hashes), "prior_program_units_excluded": len(used_programs),
              "remaining_source_modes": dict(Counter(row["mode"] for row in candidates)),
              "remaining_source_families": dict(Counter(row["family"] for row in candidates)),
              "validated_new_program_units": units, "benign_build_variants": variants,
              "maximum_potential_matched_pairs_from_these_four_units": len(proposals),
              "hypothetical_pairs_not_a_selected_or_authorized_release": proposals,
              "approved_new_role_allocations": 0, "v6_actual_capability": live["facts"],
              "bounded_overhead": {key: value for key, value in overhead.items() if key not in ("measurements", "inputs")},
              "blockers": [
                  "Exact prospective program/task/lineage units, known-family roles, per-mode quotas and precision target need review; four validated programs are not eight independent samples or a global maximum over unbuilt/unvalidated software.",
                  "No unused amd64-dynamic malware in this checked pool, and no independently sourced i386 benign programs among these four validated project outputs; changing ABI builds does not create new units.",
                  "The sidecar remains separate from the immutable .18 production collector; no new common runner/schema/launcher/payload/snapshot integration release has passed.",
                  "Three short paired UDP tasks measure latency/CPU/fork-exec RSS only; acceptance budget, bounded rate/stress and global-hook/kernel-map accounting remain unapproved or unmeasured.",
                  "Exact executable-file/hash/lineage integration and remaining scoped namespace/bypass/allocator coverage are not complete; bounded capability passes are not general ownership/frame certification.",
                  "After these gates, freeze and validate the exact release-specific benign/null common snapshot and order before separately authorized full collection."
              ], "input_hashes": inputs, "negative_matching_guards": self_test()}
    for path in (Path(__file__), Path(probe.__file__), Path(feasibility.__file__), Path(audit.__file__)):
        track(path)
    destination = ROOT / "current-release-assessments" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True, exist_ok=False)
    probe.save(destination / "remaining_malware_inventory.json", candidates)
    probe.save(destination / "readiness.json", report)
    probe.save(destination / "output_hashes.json", {name: probe.digest(destination / name) for name in ("readiness.json", "remaining_malware_inventory.json")})
    print(destination, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--run", action="store_true")
    options = parser.parse_args()
    print("PASS exact-unit maximum matching guards:", self_test()) if options.self_test else run()