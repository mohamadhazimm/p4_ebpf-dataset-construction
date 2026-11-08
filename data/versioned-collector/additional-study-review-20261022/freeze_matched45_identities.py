#!/usr/bin/env python3
"""Freeze matched additional identities offline, not a collection release."""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from audit_original_cohorts import elf_header
from prepare_matched45 import (
    BASE, EXPANSION, GATE, NATIVE, NEW_ORDER, OLD_IDENTITIES, ROOT, STUDY,
    digest, load, prior_benign,
)
from check_merge_readiness import validate_addition
from build_matched45_controls import audit_redesign, prepare_inventory


ALLOCATION = ROOT / "matched45-preparation/20261022T064127687805Z"
BUILDS = ROOT / "matched45-builds/20261022T065930151864Z"
AMENDMENT = EXPANSION / "i386-heldout-amendment/20261021T201119747468Z"
STATIC_AMD64 = (
    "dircolors", "env", "groups", "id", "mv", "printf", "rm", "rmdir",
    "shred", "sum", "sync", "tee", "test", "timeout", "users", "who",
)
STATIC_I386 = ("echo", "link", "mkfifo", "pwd", "printenv", "unlink")
E2FS = {
    "badblocks": "misc/badblocks", "resize2fs": "resize/resize2fs", "mklost+found": "misc/mklost+found",
    "uuidgen": "misc/uuidgen", "e2undo": "misc/e2undo", "blkid": "misc/blkid",
    "logsave": "misc/logsave", "e4defrag": "misc/e4defrag",
}


def main():
    expected = {
        ALLOCATION / "allocation.json": "753be5b8089c8b0bf045e82cf8311cbb494d455e513caf550bb5fa3a51170698",
        ALLOCATION / "malware-selection.json": "bd5b8cbc65b491e3058de712d94b3fa0a3ba0605c3999d39765a6b13f83a619e",
        GATE / "readiness.json": "85b375232998789b2216c797c4461a498078601ecbc92ec94e6d4bb66aecb1aa",
    }
    for path, checksum in expected.items():
        if digest(path) != checksum:
            raise ValueError("Approved allocation or anchor changed: " + str(path))
    allocation = load(ALLOCATION / "allocation.json")
    gate = load(GATE / "readiness.json")
    for relative, checksum in {**allocation["input_hashes"], **gate["input_hashes"]}.items():
        if digest(STUDY / relative) != checksum:
            raise ValueError("Pinned input changed: " + relative)
    inputs = dict(expected)
    catalog = load(ALLOCATION / "unused-benign-catalog.json")
    inputs[ALLOCATION / "unused-benign-catalog.json"] = digest(ALLOCATION / "unused-benign-catalog.json")
    build_report = load(BUILDS / "build.json")
    if build_report["status"] != "accepted_build_only":
        raise ValueError("Do not credit failed or partial builds")
    if digest(ROOT / "build_matched45_controls.py") != build_report["builder_sha256"]:
        raise ValueError("Accepted builder changed")
    inputs[ROOT / "build_matched45_controls.py"] = build_report["builder_sha256"]
    inputs[BUILDS / "build.json"] = digest(BUILDS / "build.json")
    inputs[BUILDS / "source-authentication.json"] = build_report["source_authentication_sha256"]
    for name, checksum in build_report["logs"].items():
        inputs[BUILDS / name] = checksum
    selected = [{**row, "split": "training" if row["project"] == "coreutils" else "validation",
                 "provenance_record": str((BUILDS / "build.json").relative_to(STUDY))}
                for row in build_report["artifacts"]]
    for program in STATIC_AMD64:
        row = next(row for row in catalog if row["project"] == "coreutils" and row["program"] == program
                   and row["mode"] == "native_amd64_static")
        selected.append({**row, "provenance_record": str((NATIVE / "preparation-audit.json").relative_to(STUDY))})
    old_i386 = EXPANSION / "i386-toolchain-probe/20261021T153000Z/i386-controls-20261021T161011Z"
    old_report = old_i386 / "i386-control-build-results.json"
    inputs[old_report] = digest(old_report)
    for program in STATIC_I386:
        path = old_i386 / "sources/coreutils/coreutils-8.32/src" / program
        selected.append({"project": "coreutils", "program": program, "mode": "native_i386_static",
            "split": "training", "path": str(path.relative_to(STUDY)), "sha256": digest(path),
            "provenance_record": str(old_report.relative_to(STUDY)),
            "provenance_scope": "Previously uncredited output from accepted full source build; hash frozen now"})
    for project, programs in {"e2fsprogs": E2FS, "sharutils": {"uuencode": "src/uuencode", "uudecode": "src/uudecode"}}.items():
        reports = sorted(path for path in (AMENDMENT / "project-builds" / project).glob("*/build.json")
                         if load(path)["status"] == "accepted_static_i386_build_only")
        report = reports[-1]
        inputs[report] = digest(report)
        for program, relative in programs.items():
            path = report.parent / "source" / relative
            selected.append({"project": project, "program": program, "mode": "native_i386_static",
                "split": "validation", "path": str(path.relative_to(STUDY)), "sha256": digest(path),
                "provenance_record": str(report.relative_to(STUDY)),
                "provenance_scope": "Previously uncredited output from accepted full source build; hash frozen now"})
    if len(selected) != 45:
        raise ValueError("Expected 45 matched benign identities")
    projects = {row["project"] for row in selected}
    prior_auth = load(AMENDMENT / "source-authentication.json")
    old_audit = load(NATIVE / "preparation-audit.json")
    sources = old_audit["authenticated_sources"] + prior_auth["authenticated_sources"]
    source_records = {row["project"]: row for row in sources if row["project"] in projects}
    releases, authenticated = audit_redesign.audit_sources(prepare_inventory.load_builder(), projects,
        {project: (NATIVE / row["descriptor"]).parent for project, row in source_records.items()})
    prior_hashes, prior_programs = prior_benign()
    excluded = {name.casefold() for name in gate["excluded_groups"]}
    for row in selected:
        path = STUDY / row["path"]
        if path.is_symlink() or digest(path) != row["sha256"]:
            raise ValueError("Changed or aliased benign executable")
        with path.open("rb") as stream:
            observed = elf_header(stream.read(1048576))
        if observed["mode"] != row["mode"] or (row["project"], row["program"]) in prior_programs:
            raise ValueError("Wrong linkage or previously used project/program")
        row.update({"class": "benign", "group_id": "benign_project::" + row["project"],
                    "elf_header": observed, "workload_status": "not_preflighted_for_this_release"})
        validate_addition(row, gate["global_group_roles"], prior_hashes, excluded)
        source = next(source for source in authenticated if source["project"] == row["project"])
        row["source_descriptor_sha256"] = source["descriptor_sha256"]
    if len({row["sha256"] for row in selected}) != 45 or len({(row["project"], row["program"]) for row in selected}) != 45:
        raise ValueError("Repeated hash or alternate build/profile of a program")
    malware = load(ALLOCATION / "malware-selection.json")
    expected_quota = Counter((row["split"], row["mode"]) for row in malware)
    if Counter((row["split"], row["mode"]) for row in selected) != expected_quota:
        raise ValueError("Per-label split/mode mismatch")
    for row in malware:
        source = STUDY / row["source_archive_path"]
        if digest(source) != row["source_archive_sha256"]:
            raise ValueError("Frozen malware source changed")
        inputs[source] = row["source_archive_sha256"]
    for row in selected:
        inputs[STUDY / row["path"]] = row["sha256"]
    for path in (Path(__file__), NATIVE / "preparation-audit.json", AMENDMENT / "source-authentication.json",
                 OLD_IDENTITIES, NEW_ORDER):
        inputs[path] = digest(path)
    for path, checksum in inputs.items():
        if digest(path) != checksum:
            raise ValueError("Evidence changed before identity freeze")
    output = ROOT / "matched45-identities" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "status": "matched_identities_frozen_workload_and_guest_gates_pending", "collection_ready": False,
        "authorization": "Approved 45+45 preparation and continued local build repair only; no guest workload or collection launch",
        "collection_started": False, "sample_executions": 0, "guest_operations": 0, "model_fits": 0,
        "malware_count": 45, "benign_count": 45, "existing_anchor": str(BASE.relative_to(STUDY)),
        "split_counts_per_label": {"training": 27, "validation": 18},
        "matched_quotas_per_label": [{"split": split, "mode": mode, "count": count}
                                    for (split, mode), count in sorted(expected_quota.items())],
        "benign_project_counts": dict(Counter(row["project"] for row in selected)),
        "training_validation_group_overlap": 0, "prior_identity_overlap": 0, "prior_project_program_overlap": 0,
        "malware_family_cap": 10, "protocol_inherited": gate["model_protocol_required"],
        "settings_required": gate["settings_required"],
        "authenticated_releases": releases, "authenticated_sources": authenticated,
        "limitations": ["Coreutils provides all 27 additional training controls; these are not 27 independent projects.",
            "Header/source/hash verification is not substantive workload, runtime, exec or sensor acceptance.",
            "Some old build-tree outputs were not individually hashed in their old artifact lists; current hashes freeze them as new candidates, not prior accepted workloads.",
            "Prior validation sets remain consumed; extension follows inherited roles and is exploratory only.",
            "No compiler reproducibility, upstream test suite or general capture completeness claim."],
        "pending_gates": ["Freeze safe DEVNULL-compatible arguments, data-only fixtures and exact substantive outcomes for all 45 benign targets",
            "Authorize and pass benign-only host/guest workload validation; preserve failures without weakening success criteria",
            "Common payload/clean snapshot, interleaved 90-case order plus nulls and preregistration",
            "Release-specific benign/null sensor, target-exec, ABI, finite telemetry, loss/counter and archive checks",
            "Explicit separate full-collection authorization and fresh safety/hash checks",
            "Post-capture strict acceptance and unique Ethernet/nominal-rate P4 parity before merging"],
        "input_hashes": {str(path.relative_to(STUDY)): checksum for path, checksum in inputs.items()},
    }
    for name, value in (("identity-readiness.json", report), ("benign-executables.json", selected), ("malware-selection.json", malware)):
        with (output / name).open("x") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(json.dumps({"attempt": str(output), "status": report["status"], "collection_ready": False,
        "matched_quotas_per_label": report["matched_quotas_per_label"], "benign_project_counts": report["benign_project_counts"]}, indent=2))


if __name__ == "__main__":
    main()