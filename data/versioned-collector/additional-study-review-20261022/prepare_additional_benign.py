#!/usr/bin/env python3
"""Authenticate additional independent benign source projects in a fresh attempt."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import apt_pkg

import assess_remediation_feasibility as feasibility
import audit_remediation as audit
import prepare_remediation_sources as sources


ROOT = Path(__file__).resolve().parent
TASKS = {
    "bison": "Generate and compile a parser; compare accepted and rejected fixture expressions.",
    "bmake": "Build an owned data fixture with explicit make rules and compare its content.",
    "brotli": "Compress and decompress owned deterministic bytes; compare the complete round trip.",
    "byacc": "Generate and compile a parser; compare accepted and rejected fixture expressions.",
    "diffstat": "Summarize an owned unified diff and check exact changed-line/file totals.",
    "dos2unix": "Convert owned CRLF text and compare all output bytes with an independent reference.",
    "expat": "Parse valid and malformed data-only XML with xmlwf and check actual outcomes.",
    "flex": "Generate and compile a lexer; check complete token output for an owned input.",
    "indent": "Format an owned C fixture and check its parsed tokens and compiled behavior.",
    "lz4": "Compress and decompress owned deterministic bytes; compare the complete round trip.",
    "ncompress": "Compress and decompress owned deterministic bytes; compare the complete round trip.",
    "xxhash": "Hash an owned fixture and compare with an independently implemented fixed reference.",
}


def select(records):
    apt_pkg.init_system()
    result = []
    for project in sorted(TASKS):
        choices = [row for row in records if row["project"] == project]
        if not choices:
            raise ValueError("Missing signed source project: " + project)
        newest = choices[0]
        for row in choices[1:]:
            comparison = apt_pkg.version_compare(row["source_version"], newest["source_version"])
            if comparison == 0 and (row["checksums"] != newest["checksums"] or row["directory"] != newest["directory"]):
                raise ValueError("Conflicting same-version signed source records")
            if comparison > 0:
                newest = row
        directory = Path(newest["directory"])
        if directory.is_absolute() or ".." in directory.parts or not directory.parts or directory.parts[0] != "pool":
            raise ValueError("Unsafe source directory")
        for name in newest["checksums"]:
            sources.safe_name(name)
        result.append({**newest, "task_draft_not_a_validated_workload": TASKS[project]})
    return result


def acquire():
    apt_pkg.init_system()
    helper = sources.auditor()
    previous = ROOT / "current-release-assessments/20261023T060937943623Z/readiness.json"
    sources.verify_file(previous, ("ac0d89bd02e1e8a6279826f753aad17b51a63c2f6bae797c85cd77fcb7faa3a7", previous.stat().st_size))
    prior = json.loads(previous.read_text())
    for path, expected in prior["input_hashes"].items():
        if sources.digest(Path(path)) != expected:
            raise ValueError("Current assessment input changed: " + path)
    index, manifests = audit.source_index()
    _, _, prior_projects = feasibility.prior_units(index)
    if set(TASKS) & prior_projects:
        raise ValueError("Additional project is not independent of recent plans")
    records = []
    for path in sorted((sources.NATIVE / "apt-lists").glob("*_source_Sources")):
        with path.open("rb") as stream:
            for section in apt_pkg.TagFile(stream):
                if section["Package"] in TASKS:
                    records.append({"project": section["Package"], "source_version": section["Version"],
                                    "directory": section["Directory"], "source_index": str(path),
                                    "checksums": {name: list(value) for name, value in helper.checksum_rows(section["Checksums-Sha256"]).items()}})
    selected = select(records)
    inputs = sources.authenticate_indexes(selected, helper)
    for path in [previous, Path(__file__), Path(sources.__file__), *manifests]:
        inputs[str(path)] = sources.digest(path)
    if sum(value[1] for row in selected for value in row["checksums"].values()) > 128 * 1024 * 1024:
        raise ValueError("Additional source batch exceeds its 128MiB bound")
    attempt = ROOT / "additional-benign-preparation" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    sources.save(attempt / "protocol.json", {
        "schema": "additional-independent-benign-source-preparation-v1", "selection": selected,
        "authorization": "Explicit approval for additional authenticated independent benign sources/builds, native-i386 variants and bounded readiness checks; no malware/full collection, fitting, policy change or silent existing/prospective role allocation.",
        "input_hashes": inputs, "metadata_freshness": "Cached signed metadata, not current-security certification",
        "source_batch_limit_bytes": 128 * 1024 * 1024, "collection_ready": False,
        "source_projects_are_not_yet_accepted_study_units": True})
    try:
        for row in selected:
            directory = attempt / "sources" / row["project"]
            directory.mkdir(parents=True)
            for name, expected in sorted(row["checksums"].items()):
                if expected[1] > 64 * 1024 * 1024:
                    raise ValueError("Individual source exceeds its bound")
                sources.download(sources.ORIGIN + row["directory"] + "/" + name, directory / name, expected)
            descriptors = list(directory.glob("*.dsc"))
            if len(descriptors) != 1:
                raise ValueError("Expected exactly one authenticated descriptor")
            fields = helper.read_descriptor(descriptors[0])
            if fields["Source"] != row["project"] or fields["Version"] != row["source_version"]:
                raise ValueError("Descriptor identity differs from signed index")
            for name, expected in helper.checksum_rows(fields["Checksums-Sha256"]).items():
                sources.safe_name(name)
                if list(expected) != row["checksums"].get(name):
                    raise ValueError("Descriptor archive differs from signed index")
                sources.verify_file(directory / name, expected)
            print("AUTHENTICATED", row["project"], row["source_version"], flush=True)
        for path, expected in inputs.items():
            if sources.digest(Path(path)) != expected:
                raise ValueError("Source authentication input changed during acquisition")
        sources.save(attempt / "source-authentication.json", {
            "status": "authenticated_sources_builds_pending", "projects": selected,
            "files": {str(path.relative_to(attempt)): sources.digest(path) for path in sorted((attempt / "sources").rglob("*")) if path.is_file()},
            "collection_ready": False, "target_workload_executions": 0, "vm_operations": 0,
            "model_fits": 0, "roles_or_quotas_assigned": False})
    except Exception as error:
        sources.save(attempt / "failure.json", {"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error), "collection_ready": False})
        raise
    finally:
        print(attempt, flush=True)


def self_test():
    records = [{"project": project, "source_version": "1.0-1", "directory": "pool/main/p/project", "checksums": {"source.dsc": ["0" * 64, 1]}} for project in TASKS]
    assert len(select(records)) == 12
    assert select(records + [{**records[0], "source_version": "2:0.1-1"}])[0]["source_version"] == "2:0.1-1"
    probes = [records[1:], records + [{**records[0], "checksums": {"changed.dsc": ["1" * 64, 1]}}],
              [{**records[0], "directory": "../escape"}, *records[1:]],
              [{**records[0], "checksums": {"../escape": ["0" * 64, 1]}}, *records[1:]]]
    for changed in probes:
        try:
            select(changed)
        except ValueError:
            continue
        raise AssertionError("Invalid additional source selection accepted")
    print("PASS twelve-project source selection, epoch ordering and four missing/conflict/path guards; no acquisition")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--acquire", action="store_true")
    options = parser.parse_args()
    self_test() if options.self_test else acquire()