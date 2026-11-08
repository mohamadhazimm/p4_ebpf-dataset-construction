#!/usr/bin/env python3
"""Freeze the approved 45+45 extension allocation without executing samples."""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from audit_original_cohorts import ROOT, STUDY, digest, elf_header
from check_merge_readiness import BASE, load, validate_addition


GATE = ROOT / "merge-readiness/20261022T060242194318Z"
EXPANSION = ROOT.parent / "cohort-expansion-100x100-v18-20261021"
NATIVE = ROOT.parent / "cohort-100x100-v18-20261021/redesign-native-x64"
OLD_IDENTITIES = NATIVE / "manifests/benign-executables.json"
NEW_ORDER = EXPANSION / "i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z/case_order.json"


def select_malware(candidates):
    families = defaultdict(lambda: defaultdict(list))
    for row in candidates:
        if row["class"] == "malware" and row["source_stage_candidate"]:
            families[row["group_id"]][row["mode"]].append(row)
    selected = []
    for family in sorted(families):
        modes = {mode: sorted(rows, key=lambda row: row["sha256"])
                 for mode, rows in sorted(families[family].items())}
        chosen = []
        while len(chosen) < 10 and any(modes.values()):
            for rows in modes.values():
                if rows and len(chosen) < 10:
                    chosen.append(rows.pop(0))
        selected.extend({**row, "split": row["inherited_role"]} for row in chosen)
    return selected


def prior_benign():
    old = load(OLD_IDENTITIES)["executables"]
    new = [row for row in load(NEW_ORDER) if row["label"] == "benign"]
    identities = {row["sha256"] for row in old + new}
    programs = {(row["project"], row["program"]) for row in old}
    programs.update((row["group_id"].removeprefix("benign_project::"), row["program"]) for row in new)
    return identities, programs


def benign_catalog(roles, excluded):
    prior_hashes, prior_programs = prior_benign()
    inventory = load(EXPANSION / "inventory.json")
    result = []
    for row in inventory["benign_build_candidates"]:
        group = "benign_project::" + row["project"]
        if (group.casefold() in excluded or group.casefold() not in roles
                or row["sha256"] in prior_hashes or (row["project"], row["program"]) in prior_programs):
            continue
        path = STUDY / row["path"]
        if digest(path) != row["sha256"]:
            raise ValueError("Unused benign identity changed: " + row["path"])
        with path.open("rb") as stream:
            observed = elf_header(stream.read(1024 * 1024))
        if observed["mode"] not in ("native_amd64_static", "native_amd64_dynamic", "native_i386_static"):
            continue
        result.append({**row, "group_id": group, "split": roles[group.casefold()],
                       "mode": observed["mode"], "workload_status": "not_preflighted_for_this_release"})
    return result


def self_test():
    rows = [{"class": "malware", "source_stage_candidate": True, "group_id": "family",
             "mode": mode, "sha256": f"{number:064x}", "inherited_role": "training"}
            for mode in ("native_amd64_static", "native_i386_static") for number in range(1 if mode.endswith("amd64_static") else 21, 21 if mode.endswith("amd64_static") else 41)]
    selected = select_malware(rows)
    assert len(selected) == 10 and Counter(row["mode"] for row in selected) == {"native_amd64_static": 5, "native_i386_static": 5}
    assert selected == select_malware(list(reversed(rows)))
    assert len({row["sha256"] for row in selected}) == 10
    print("PASS: family cap, mode coverage, input-order independence and unique selection")


def prepare():
    gate = load(GATE / "readiness.json")
    for relative, expected in gate["input_hashes"].items():
        if digest(STUDY / relative) != expected:
            raise ValueError("Merge-readiness input changed: " + relative)
    candidates = load(GATE / "candidate_audit.json")
    selected = select_malware(candidates)
    if len(selected) != 45 or len({row["sha256"] for row in selected}) != 45:
        raise ValueError("Approved 45-case source allocation is infeasible")
    excluded = {name.casefold() for name in gate["excluded_groups"]}
    prior_hashes, _programs = prior_benign()
    for row in selected:
        validate_addition(row, gate["global_group_roles"], prior_hashes, excluded)
        if digest(STUDY / row["source_archive_path"]) != row["source_archive_sha256"]:
            raise ValueError("Selected malware source changed")
    quotas = Counter((row["split"], row["mode"]) for row in selected)
    catalog = benign_catalog(gate["global_group_roles"], excluded)
    available = {key: {(row["project"], row["program"]) for row in catalog
                       if (row["split"], row["mode"]) == key} for key in quotas}
    output = ROOT / "matched45-preparation" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "status": "approved_target_frozen_malware_benign_workloads_pending",
        "authorization": "User approved 45 malware plus 45 matched benign preparation target; collection not authorized",
        "collection_ready": False, "collection_started": False, "sample_executions": 0, "vm_operations": 0,
        "malware_count": 45, "benign_target": 45, "malware_family_cap": 10,
        "selection": "Sort families/modes/hashes; round-robin modes within each family up to cap; no runtime outcome filtering",
        "existing_anchor": str(BASE.relative_to(STUDY)),
        "existing_validation_consumed": True,
        "malware_split_counts": dict(Counter(row["split"] for row in selected)),
        "malware_group_counts": dict(Counter(row["group_id"] for row in selected)),
        "benign_quotas": [{"split": split, "mode": mode, "required": count,
            "unused_existing_x64_project_programs": len(available[(split, mode)]),
            "shortfall_before_other_build_catalogs": max(0, count - len(available[(split, mode)]))}
            for (split, mode), count in sorted(quotas.items())],
        "protocol_inherited": gate["model_protocol_required"], "settings_required": gate["settings_required"],
        "remaining_gates": ["Exact distinct authenticated benign executables and safe substantive workloads",
            "Matched split/mode allocation with globally fixed project roles",
            "Frozen common payload/snapshot, interleaved order and preregistration",
            "Benign dependency/exec/outcome and release-specific sensor/null validation before collection authorization"],
        "input_hashes": {str(path.relative_to(STUDY)): digest(path) for path in (
            Path(__file__), GATE / "readiness.json", GATE / "candidate_audit.json",
            EXPANSION / "inventory.json", OLD_IDENTITIES, NEW_ORDER)},
    }
    for name, content in (("allocation.json", report), ("malware-selection.json", selected), ("unused-benign-catalog.json", catalog)):
        with (output / name).open("x") as stream:
            json.dump(content, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(json.dumps({"attempt": str(output), "collection_ready": False, "malware_count": 45,
                      "split_counts": report["malware_split_counts"], "benign_quotas": report["benign_quotas"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        prepare()


if __name__ == "__main__":
    main()