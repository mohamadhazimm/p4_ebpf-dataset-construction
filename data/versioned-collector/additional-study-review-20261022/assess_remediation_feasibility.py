#!/usr/bin/env python3
"""Offline-only source/task feasibility; never execute candidate workloads."""

import argparse
import importlib.util
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import audit_remediation as audit


ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "remediation-audit/20261022T114711085419Z"
NATIVE = audit.NATIVE
SUPPORTED_MODES = {
    "native_amd64_dynamic", "native_amd64_static", "native_i386_static"
}
ALIASES = {
    "binutils": {"nm-new": "nm", "strip-new": "strip", "as-new": "as",
                 "ld-new": "ld", "c++filt": "cxxfilt"},
    "coreutils": {"ginstall": "install"},
    "procps": {"pscommand": "ps"},
}
SOURCE_TASKS = {
    "libarchive": ("bsdtar", "Create and recover a deterministic multi-file archive; compare every path and content hash."),
    "openssh": ("sftp", "Transfer a fixed data-only tree to an isolated authenticated fixture; verify bytes at both ends and decode the encrypted session."),
    "perl": ("perl", "Run a fixed text/record transformation fixture through the native ELF interpreter; compare exact output records."),
    "netcat-openbsd": ("nc", "Receive a bounded marked stream from the isolated fixture; verify target output and fixture receipts under DEVNULL stdin."),
    "imagemagick": ("convert", "Convert a fixed image corpus; check decoded dimensions and a pinned deterministic pixel result, not output existence alone."),
    "lighttpd": ("lighttpd", "Serve a bounded data-only tree on the isolated interface; verify exact response bodies and request receipts."),
    "nginx": ("nginx", "Serve a bounded static tree in foreground on the isolated interface; verify response hashes and worker ownership."),
    "gnutls28": ("certtool", "Generate and parse disposable certificates with fixed semantic checks; validate TLS with a dissector if a network task is later chosen."),
}


def canonical_program(project, program):
    return ALIASES.get(project, {}).get(program, program)


def prior_units(index):
    programs, projects = set(), set()
    for candidates in index.values():
        for candidate in candidates:
            record = candidate["record"]
            project = record.get("project")
            if not project and record.get("group_id", "").startswith("benign_project::"):
                project = record["group_id"].split("::", 1)[1]
            if project:
                program = record.get("program") or candidate["path"].name
                projects.add(project)
                programs.add((project, canonical_program(project, program)))
    return set(index), programs, projects


def candidate_decision(candidate, used_hashes, used_programs, used_projects):
    project = candidate["project"]
    program = canonical_program(project, candidate["program"])
    reasons = []
    if project in {"coreutils", "util-linux"}:
        reasons.append("dominant_or_globally_excluded_project")
    if candidate["sha256"] in used_hashes:
        reasons.append("previously_planned_executable")
    if (project, program) in used_programs:
        reasons.append("previously_planned_project_program")
    if candidate["mode"] not in SUPPORTED_MODES:
        reasons.append("unsupported_mode")
    if not candidate["source_hashes_match"] or not candidate["build_identity_matches"]:
        reasons.append("unverified_local_source_or_build_identity")
    if project == "nano":
        reasons.append("known_terminal_requirement_under_current_devnull_launcher")
    return {
        "status": "excluded_from_shortlist" if reasons else "offline_shortlist_only",
        "reasons": reasons,
        "new_project_relative_to_recent_plans": project not in used_projects,
        "activity_range_measured": False,
        "task_semantics_validated": False,
        "guest_dependencies_validated": False,
        "collection_ready": False,
    }


def mode_from_facts(facts):
    machines = {("EM_X86_64", 64): "amd64", ("EM_386", 32): "i386"}
    architecture = machines.get((facts["machine"], facts["elf_class"]))
    return f"native_{architecture}_{facts['linkage']}" if architecture else "unsupported"


def candidate_task(project, program):
    key = (project, canonical_program(project, program))
    drafts = {
        ("binutils", "as"): "Assemble a pinned generated assembly fixture; independently check ELF machine, symbols and sections without executing the output.",
        ("binutils", "ld"): "Link pinned benign object fixtures; independently check ELF entry, sections and symbols without executing the output.",
        ("binutils", "gprof"): "Analyze a fixed benign profiling fixture and compare exact symbol/count records; upstream format/version compatibility must be checked.",
        ("psmisc", "prtstat"): "Read statistics for a disposable controlled process; validate PID identity, fields and observation interval.",
    }
    return {
        "status": "semantic_draft_unexecuted" if key in drafts else "substantive_safe_task_not_yet_specified",
        "proposal": drafts.get(key),
        "arguments_fixtures_and_outcomes_frozen": False,
        "activity_target": "Unmeasured; no promise of 1000 or 10000 calls and no padding or favorable-activity selection",
        "safe_scope": "Owned regular files/processes or isolated fixture only; never system policy, arbitrary PIDs, block devices or public endpoints",
    }


def load_module(path):
    specification = importlib.util.spec_from_file_location("feasibility_source_auditor", path)
    if specification is None or specification.loader is None:
        raise ValueError("Cannot load existing source authentication helper")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def source_directories(records, base):
    return {row["project"]: (base / row["descriptor"]).parent for row in records}


def verify(attempt):
    inputs = json.loads((attempt / "input_hashes.json").read_text())
    outputs = json.loads((attempt / "output_hashes.json").read_text())
    for name, expected in inputs.items():
        if audit.sha256(Path(name)) != expected:
            raise ValueError("Input changed: " + name)
    for name, expected in outputs.items():
        if audit.sha256(attempt / name) != expected:
            raise ValueError("Output changed: " + name)
    summary = json.loads((attempt / "summary.json").read_text())
    cases = json.loads((attempt / "build_candidates.json").read_text())
    assert len(cases) == summary["build_records_checked"]
    shortlisted = [row for row in cases if row["decision"]["status"] == "offline_shortlist_only"]
    assert len(shortlisted) == summary["shortlisted_build_records"]
    assert all(not row["decision"]["collection_ready"] for row in cases)
    assert all(not summary[field] for field in ("collection_ready", "sample_executions", "model_fits", "vm_operations"))
    result = {"status": "verified", "input_hashes_checked": len(inputs),
              "output_hashes_checked": len(outputs), "collection_ready": False}
    path = attempt / "verification.json"
    if path.exists():
        assert json.loads(path.read_text()) == result
    else:
        audit.save(path, result)
    return result


def run():
    inputs = {}
    inherited = json.loads((EVIDENCE / "input_hashes.json").read_text())

    def track(path, expected=None):
        path = path.resolve()
        observed = audit.sha256(path)
        expected = expected or inherited.get(str(path))
        if expected and observed != expected:
            raise ValueError("Recorded input hash differs: " + str(path))
        inputs[str(path)] = observed
        return observed

    for path in (Path(__file__), ROOT / "audit_remediation.py", EVIDENCE / "summary.json",
                 EVIDENCE / "input_hashes.json", EVIDENCE / "remediation_protocol.json"):
        track(path)
    track(ROOT / "audit_remediation.py", "a540ed8d9ceb880600ea3dbf22fccdbe7de74b57c1e193411246e509a5f2b83c")
    track(EVIDENCE / "summary.json", "443da4df747ec372edf164a45dc2d0646f2d52c3d6861e1e7a690c28d939adeb")
    index, manifests = audit.source_index()
    for path in manifests:
        track(path)
    used_hashes, used_programs, used_projects = prior_units(index)
    catalog_path = NATIVE / "preparation-audit.json"
    track(catalog_path)
    catalog = json.loads(catalog_path.read_text())["verified_build_candidates"]
    records = [{**row, "path": str(NATIVE / row["path"]), "catalog": str(catalog_path),
                "catalog_kind": "native_build_audit"} for row in catalog]
    matched_path = ROOT / "matched45-builds/20261022T065930151864Z/build.json"
    track(matched_path)
    matched = json.loads(matched_path.read_text())
    authentication_path = matched_path.parent / "source-authentication.json"
    track(authentication_path, matched["source_authentication_sha256"])
    matched_sources = json.loads(authentication_path.read_text())["authenticated_sources"]
    for row in matched["artifacts"]:
        records.append({**row, "path": str(audit.STUDY / row["path"]),
                        "catalog": str(matched_path), "catalog_kind": "matched_build_manifest"})
    helper_path = NATIVE / "audit_redesign.py"
    track(helper_path)
    track(NATIVE.parent / "prepare_selection.py")
    helper = load_module(helper_path)
    projects = {row["project"] for row in records}
    releases, sources = helper.audit_sources(helper.load_builder(), projects,
                                             source_directories(matched_sources, NATIVE))
    source_index = {row["project"]: row for row in sources}
    for release in releases:
        track(NATIVE / release["path"], release["sha256"])
    track(Path(helper.KEYRING))
    for source in sources:
        track(NATIVE / source["descriptor"], source["descriptor_sha256"])
        for member in source["files"]:
            track(NATIVE / member["path"], member["sha256"])
    source_requests = {project: [] for project in SOURCE_TASKS}
    for release in releases:
        release_path = NATIVE / release["path"]
        fields = helper.read_descriptor(release_path)
        checksums = helper.checksum_rows(fields["SHA256"])
        prefix = release_path.name.removesuffix("_InRelease")
        for component in ("main", "universe"):
            path = release_path.parent / f"{prefix}_{component}_source_Sources"
            expected, size = checksums[f"{component}/source/Sources"]
            assert path.stat().st_size == size
            track(path, expected)
            with path.open("rb") as stream:
                for section in helper.apt_pkg.TagFile(stream):
                    project = section["Package"]
                    if project in source_requests:
                        source_requests[project].append({"source_version": section["Version"],
                            "architecture_field": section.get("Architecture"),
                            "directory": section["Directory"], "source_index": str(path),
                            "checksums": helper.checksum_rows(section["Checksums-Sha256"])})
    attempt = ROOT / "remediation-feasibility" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    audit.save(attempt / "protocol.json", {
        "status": "offline_source_and_task_feasibility_only", "collection_ready": False,
        "catalogs": [str(catalog_path), str(matched_path)],
        "scope": "Bounded existing catalogs, not exhaustive discovery of all possible local or remote programs",
        "exclusions": "All recent planned hashes/programs including failed/rejected, Coreutils concentration, util-linux exclusion, unsupported modes, known nano DEVNULL failure",
        "independence": "A new program in an old project is not a new project; aliases normalized; neither proves behavioral independence",
        "source_authentication": "Reverified cached InRelease signatures and signed-index/descriptor/archive hashes offline; no acquisition or build",
        "activity": "Missing amd64 dynamic 1000-9999 and >=10000; i386 static >=10000. No workload executed or activity quota certified",
        "preserved_widths": [145, 145, 290], "primary_metric": "sample-weighted balanced accuracy",
        "new_group_roles": "Unassigned; no resplit or change of known-family evaluation target",
        "never_authorizes": ["Workload execution", "VM operation", "production edits", "new collection", "model fitting"]})
    checked = []
    for record in records:
        path = Path(record["path"])
        digest = track(path, record["sha256"])
        content = audit.checked_content(path.read_bytes(), digest)
        facts = audit.elf_facts(content)
        provenance = None
        if record["catalog_kind"] == "native_build_audit":
            provenance = next((parent / "build-provenance.txt" for parent in path.parents
                               if (parent / "build-provenance.txt").is_file()), None)
            if provenance is None:
                raise ValueError("Missing recorded build provenance")
            track(provenance, record["build_provenance_sha256"])
        candidate = {
            "project": record["project"], "program": record.get("program", path.name),
            "canonical_program": canonical_program(record["project"], record.get("program", path.name)),
            "sha256": digest, "path": str(path), "catalog": record["catalog"],
            "build_provenance": str(provenance) if provenance else record["catalog"],
            "mode": mode_from_facts(facts), "elf_class": facts["elf_class"],
            "machine": facts["machine"], "linkage": facts["linkage"],
            "source": source_index[record["project"]], "source_hashes_match": True,
            "build_identity_matches": True,
        }
        candidate["decision"] = candidate_decision(candidate, used_hashes, used_programs, used_projects)
        candidate["task"] = candidate_task(candidate["project"], candidate["program"])
        candidate["targets_missing_mode"] = candidate["mode"] in {"native_amd64_dynamic", "native_i386_static"}
        checked.append(candidate)
    _elf, tlsh = audit.libraries()
    tool_paths = [Path(tlsh.__file__)]
    tool_paths.extend((audit.TOOLS / "elftools").rglob("*.py"))
    for path in tool_paths:
        track(path)
    proposals = []
    for project, (program, task) in SOURCE_TASKS.items():
        proposals.append({"project": project, "proposed_program": program, "task_draft": task,
            "new_project_relative_to_recent_plans": project not in used_projects,
            "signed_index_records": source_requests[project],
            "status": "cached_signed_metadata_only" if source_requests[project] else "not_in_checked_indexes",
            "architecture_feasibility": "Source Architecture field is not proof of amd64 dynamic/i386 static builds; dependencies, licensing and actual ELF remain pending",
            "source_archives_acquired_this_phase": False, "program_built_this_phase": False,
            "executable_identity_frozen": False, "task_validated": False,
            "activity_range_measured": False, "collection_ready": False,
            "historical_exposure_review": "Recent full-plan absence only; not a globally unseen project or untouched evaluation claim"})
    shortlisted = [row for row in checked if row["decision"]["status"] == "offline_shortlist_only"]
    summary = {"status": "offline_feasibility_complete_release_blocked", "collection_ready": False,
        "build_records_checked": len(checked), "distinct_build_hashes_checked": len({row["sha256"] for row in checked}),
        "shortlisted_build_records": len(shortlisted),
        "shortlisted_unique_project_programs": len({(row["project"], row["canonical_program"]) for row in shortlisted}),
        "shortlisted_modes": dict(Counter(row["mode"] for row in shortlisted)),
        "shortlisted_projects": dict(Counter(row["project"] for row in shortlisted)),
        "shortlisted_new_projects": sorted({row["project"] for row in shortlisted if row["decision"]["new_project_relative_to_recent_plans"]}),
        "exclusion_reasons": dict(Counter(reason for row in checked for reason in row["decision"]["reasons"])),
        "source_only_projects_with_cached_metadata": sum(bool(row["signed_index_records"]) for row in proposals),
        "new_source_projects_with_cached_metadata": sum(bool(row["signed_index_records"]) and row["new_project_relative_to_recent_plans"] for row in proposals),
        "prior_planned_hashes": len(used_hashes), "prior_planned_benign_project_programs": len(used_programs),
        "sample_executions": 0, "model_fits": 0, "vm_operations": 0,
        "measured_new_activity_cells": 0, "prospective_evaluation_reserved": False,
        "next_gate": "Review source-only choices and task constraints; approve exact acquisition/build and later benign validation separately. No quotas, pilot release or detector selection yet"}
    for path, expected in inputs.items():
        if audit.sha256(Path(path)) != expected:
            raise ValueError("Input changed during assessment: " + path)
    audit.save(attempt / "build_candidates.json", checked)
    audit.save(attempt / "source_task_proposals.json", proposals)
    audit.save(attempt / "summary.json", summary)
    audit.save(attempt / "input_hashes.json", inputs)
    audit.save(attempt / "output_hashes.json", {path.name: audit.sha256(path) for path in attempt.glob("*.json")})
    print(json.dumps({"attempt": str(attempt), "summary": summary, "verification": verify(attempt)}, indent=2))


def self_test():
    candidate = {
        "project": "example", "program": "tool", "sha256": "new",
        "mode": "native_amd64_dynamic", "source_hashes_match": True,
        "build_identity_matches": True,
    }
    accepted = candidate_decision(candidate, {"old"}, {("example", "old")}, {"example"})
    assert accepted["status"] == "offline_shortlist_only"
    assert not accepted["new_project_relative_to_recent_plans"]
    assert not accepted["collection_ready"] and not accepted["activity_range_measured"]
    probes = [
        ({"sha256": "old"}, "previously_planned_executable"),
        ({"program": "old"}, "previously_planned_project_program"),
        ({"project": "coreutils"}, "dominant_or_globally_excluded_project"),
        ({"project": "util-linux"}, "dominant_or_globally_excluded_project"),
        ({"mode": "native_i386_dynamic"}, "unsupported_mode"),
        ({"mode": "qemu_armel_static"}, "unsupported_mode"),
        ({"mode": "native_i386_static-pie"}, "unsupported_mode"),
        ({"source_hashes_match": False}, "unverified_local_source_or_build_identity"),
        ({"build_identity_matches": False}, "unverified_local_source_or_build_identity"),
        ({"project": "nano"}, "known_terminal_requirement_under_current_devnull_launcher"),
    ]
    for changes, reason in probes:
        rejected = candidate_decision({**candidate, **changes}, {"old"}, {("example", "old")}, set())
        assert rejected["status"] == "excluded_from_shortlist"
        assert reason in rejected["reasons"] and not rejected["collection_ready"]
    alias = {**candidate, "project": "binutils", "program": "nm-new"}
    assert "previously_planned_project_program" in candidate_decision(alias, set(), {("binutils", "nm")}, set())["reasons"]
    fixture_index = {"failed_hash": [{"path": Path("some/tool"), "record": {
        "label": "benign", "project": "example", "program": "tool", "status": "runner_failed"}}]}
    hashes, programs, projects = prior_units(fixture_index)
    assert hashes == {"failed_hash"} and programs == {("example", "tool")} and projects == {"example"}
    assert mode_from_facts({"machine": "EM_386", "elf_class": 32, "linkage": "static-pie"}) not in SUPPORTED_MODES
    assert mode_from_facts({"machine": "EM_X86_64", "elf_class": 64, "linkage": "dynamic"}) in SUPPORTED_MODES
    directories = source_directories([{"project": "net-tools", "descriptor": "../i386/sources/net-tools/source.dsc"}], Path("/example/native"))
    assert directories["net-tools"].resolve() == Path("/example/i386/sources/net-tools")
    assert all(len(task) == 2 for task in SOURCE_TASKS.values())
    print("PASS: prior identity/program, excluded-project, mode and provenance guards")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument("--self-test", action="store_true")
    options.add_argument("--run", action="store_true")
    options.add_argument("--verify", type=Path)
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    elif arguments.verify:
        print(json.dumps(verify(arguments.verify), indent=2))
    else:
        run()


if __name__ == "__main__":
    main()