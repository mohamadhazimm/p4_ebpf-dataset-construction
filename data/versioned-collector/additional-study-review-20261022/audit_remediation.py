#!/usr/bin/env python3
"""Offline relationship audit and evidence-gated detector remediation protocol."""

import argparse
import csv
import hashlib
import io
import json
import math
import subprocess
import sys
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
SOURCE = ROOT / "within-family-exploratory/20261022T103648547175Z"
OUTPUT = ROOT / "remediation-audit"
ACTIVITY_EDGES = (20, 45, 100, 1000, 10000, math.inf)
TOOLS = ROOT / "remediation-tools"
NATIVE = ROOT.parent / "cohort-100x100-v18-20261021/redesign-native-x64"
EXPANSION = ROOT.parent / "cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z"
MAX_BYTES = 64 * 1024 * 1024
TLSH_REVIEW_DISTANCE = 60
TLSH_CLOSE_DISTANCE = 30


def sha256(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def checked_rows(rows):
    for key in ("sample", "executable_sha256"):
        if len({row[key] for row in rows}) != len(rows):
            raise ValueError("Duplicate accepted identity: " + key)
    for row in rows:
        if int(row["label"]) != int(row["class"] == "malware"):
            raise ValueError("Class/label mismatch")
        if row["group_id"] in ("malware_signature::DDoSAgent", "benign_project::util-linux"):
            raise ValueError("Globally excluded group reintroduced")
        if row["split"] not in ("training", "validation"):
            raise ValueError("Unknown split")
    return rows


def host_key(row):
    names = sorted(key for key in row if key.startswith("host__"))
    if len(names) != 175:
        raise ValueError("Expected all 175 host candidates")
    values = [float(row[key]) for key in names]
    if not all(math.isfinite(value) for value in values):
        raise ValueError("Nonfinite host candidate")
    return fingerprint(values)


def activity_bin(count):
    if count < 0:
        raise ValueError("Negative activity")
    return next(index for index, upper in enumerate(ACTIVITY_EDGES) if count < upper)


def components(samples, edges, kinds):
    parents = {sample: sample for sample in samples}

    def root(sample):
        while parents[sample] != sample:
            parents[sample] = parents[parents[sample]]
            sample = parents[sample]
        return sample

    for edge in edges:
        if edge["left"] not in parents or edge["right"] not in parents:
            raise ValueError("Relationship references unknown case")
        if edge["kind"] in kinds:
            left, right = root(edge["left"]), root(edge["right"])
            parents[max(left, right)] = min(left, right)
    groups = defaultdict(list)
    for sample in sorted(samples):
        groups[root(sample)].append(sample)
    return sorted(groups.values(), key=lambda members: (-len(members), members))


def equal_edges(records, field, kind, require_nonempty=False, by_mode=False):
    groups = defaultdict(list)
    for row in records:
        if require_nonempty and not row["post_calls"]:
            continue
        key = (row["mode"] if by_mode else "all", row[field])
        groups[key].append(row["sample"])
    edges = []
    for members in groups.values():
        for sample in sorted(members)[1:]:
            edges.append({"left": min(members), "right": sample, "kind": kind})
    return edges


def libraries():
    sys.path.insert(0, str(TOOLS))
    import elftools
    import tlsh
    from elftools.elf.elffile import ELFFile

    if elftools.__version__ != "0.32" or tlsh.__version__ != "4.5.0":
        raise ValueError("Unexpected analysis-library version")
    return ELFFile, tlsh


def elf_facts(content):
    elf_file, tlsh = libraries()
    if not content.startswith(b"\x7fELF"):
        raise ValueError("Source is not ELF")
    parsed = elf_file(io.BytesIO(content))
    pieces, regions = [], []
    for section in sorted(parsed.iter_sections(), key=lambda item: item["sh_offset"]):
        if section["sh_flags"] & 4 and section["sh_type"] != "SHT_NOBITS" and section["sh_size"]:
            offset, size = int(section["sh_offset"]), int(section["sh_size"])
            if offset < 0 or offset + size > len(content):
                raise ValueError("Executable section outside bounded input")
            piece = section.data()
            pieces.append(piece)
            regions.append({"name": section.name, "bytes": len(piece), "sha256": hashlib.sha256(piece).hexdigest()})
    representation = "executable_sections"
    if not pieces:
        representation = "executable_load_segments"
        for segment in parsed.iter_segments():
            if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1 and segment["p_filesz"]:
                offset, size = int(segment["p_offset"]), int(segment["p_filesz"])
                if offset < 0 or offset + size > len(content):
                    raise ValueError("Executable segment outside bounded input")
                piece = segment.data()
                pieces.append(piece)
                regions.append({"name": "PT_LOAD", "bytes": len(piece), "sha256": hashlib.sha256(piece).hexdigest()})
    code = b"".join(pieces)
    interpreter = any(segment["p_type"] == "PT_INTERP" for segment in parsed.iter_segments())
    return {"elf_class": parsed.elfclass, "machine": parsed["e_machine"], "elf_type": parsed["e_type"],
        "linkage": "dynamic" if interpreter else "static-pie" if parsed["e_type"] == "ET_DYN" else "static",
        "code_representation": representation, "code_bytes": len(code), "code_regions": regions,
        "code_sha256": fingerprint(regions) if code else None,
        "whole_tlsh": tlsh.hash(content), "code_tlsh": tlsh.hash(code) if code else "TNULL"}


def checked_content(content, expected):
    if len(content) > MAX_BYTES or hashlib.sha256(content).hexdigest() != expected:
        raise ValueError("Source content exceeds bound or differs from executable identity")
    return content


def read_binary(path, expected):
    with path.open("rb") as stream:
        prefix = stream.read(4)
        if prefix == b"\x7fELF":
            stream.seek(0)
            return checked_content(stream.read(MAX_BYTES + 1), expected)
    process = subprocess.Popen(["7z", "x", "-so", "-pinfected", str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    pieces, size = [], 0
    try:
        while chunk := process.stdout.read(1024 * 1024):
            pieces.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("Archive stream exceeds 64-MiB bound")
        if process.wait(timeout=30) != 0:
            raise ValueError("Archive reader failed")
        return checked_content(b"".join(pieces), expected)
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def payload_binary(path, program, expected):
    matches = []
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if member.isfile() and Path(member.name).name == program and member.size <= MAX_BYTES:
                with archive.extractfile(member) as stream:
                    content = stream.read(MAX_BYTES + 1)
                if hashlib.sha256(content).hexdigest() == expected:
                    matches.append((content, member.name))
    if not matches:
        raise ValueError("Exact derived benign executable not found in frozen payload")
    return matches[0]


def source_index():
    specifications = [(NATIVE / "manifests/benign-executables.json", NATIVE),
        (NATIVE / "manifests/benign-workloads.json", NATIVE),
        (NATIVE / "manifests/malware-selection.json", STUDY),
        (EXPANSION / "case_order.json", STUDY),
        (ROOT / "matched45-identities/20261022T070700658382Z/benign-executables.json", STUDY),
        (ROOT / "matched45-preparation/20261022T064127687805Z/malware-selection.json", STUDY),
        (ROOT / "matched45-readiness/20261022T072823231146Z/case_order.json", STUDY)]
    index = defaultdict(list)
    for manifest, base in specifications:
        value = json.loads(manifest.read_text())
        records = value if isinstance(value, list) else [item for items in value.values()
            if isinstance(items, list) for item in items if isinstance(item, dict)]
        for item in records:
            identity = item.get("staged_sha256") or item.get("sha256") or item.get("member_sha256")
            if not identity:
                continue
            name = item.get("source_archive_path") or item.get("source") or item.get("path")
            if not name:
                continue
            path = Path(name)
            path = path if path.is_absolute() else base / path
            index[identity].append({"path": path, "manifest": manifest,
                "expected_container_sha256": item.get("source_archive_sha256"), "record": item})
    return index, [path for path, _base in specifications]


def binary_record(row, index, inputs):
    identity = row["executable_sha256"]
    candidates = index.get(identity, [])
    if not candidates:
        return {"status": "source_unlocated", "errors": ["No matching frozen source identity"]}
    errors = []
    for candidate in candidates:
        path = candidate["path"]
        if not path.is_file():
            errors.append(str(path) + ": missing")
            continue
        actual = sha256(path)
        inputs[str(path)] = actual
        if candidate["expected_container_sha256"] and actual != candidate["expected_container_sha256"]:
            raise ValueError("Frozen source container changed: " + str(path))
        try:
            derived = candidate["record"].get("derived_zip_appended", False)
            if derived:
                payload = NATIVE / "readiness/20261021T104951987641Z/payload.tgz"
                inputs[str(payload)] = sha256(payload)
                content, member = payload_binary(payload, row["program"], identity)
                source = {"path": str(payload), "member": member}
            else:
                content = read_binary(path, identity)
                source = {"path": str(path)}
            facts = elf_facts(content)
        except (ValueError, OSError, KeyError) as error:
            errors.append(str(path) + ": " + str(error))
            continue
        expected_machine = "EM_386" if "i386" in row["mode"] else "EM_X86_64"
        expected_class = 32 if expected_machine == "EM_386" else 64
        expected_linkage = "dynamic" if row["mode"].endswith("_dynamic") else "static"
        if (facts["machine"], facts["elf_class"], facts["linkage"]) != (expected_machine, expected_class, expected_linkage):
            raise ValueError("Accepted case/source ELF mode mismatch: " + row["sample"])
        record = candidate["record"]
        return {"status": "verified", "source": source, "source_manifest": str(candidate["manifest"]),
            "executable_sha256": identity, "bytes": len(content), **facts,
            "source_version": record.get("source_version"),
            "source_descriptor_sha256": record.get("source_descriptor_sha256"),
            "acquisition_group": row["group_id"],
            "provider_category": record.get("malwarebazaar_category", record.get("attack_type_label")),
            "category_caution": "Acquisition metadata, not independently verified attack behavior",
            "declared_network_task": record.get("network_case"), "arguments": record.get("collection_arguments", record.get("arguments"))}
    return {"status": "source_not_verified", "errors": errors}


def binary_edges(records):
    _elf, tlsh = libraries()
    edges, eligible = [], [row for row in records if row["binary"]["status"] == "verified"]
    comparisons = 0
    for left, right in combinations(eligible, 2):
        if left["mode"] != right["mode"]:
            continue
        comparisons += 1
        first, second = left["binary"], right["binary"]
        base = {"left": left["sample"], "right": right["sample"]}
        if first["code_sha256"] and first["code_representation"] == second["code_representation"] and first["code_sha256"] == second["code_sha256"]:
            edges.append({**base, "kind": "identical_executable_regions"})
        distances = {}
        for field in ("whole_tlsh", "code_tlsh"):
            if first[field] not in ("", "TNULL") and second[field] not in ("", "TNULL"):
                distances[field] = int(tlsh.diff(first[field], second[field]))
        if distances and min(distances.values()) <= TLSH_REVIEW_DISTANCE:
            minimum = min(distances.values())
            edges.append({**base, "kind": "tlsh_review_candidate", "distances": distances,
                "tier": "close" if minimum <= TLSH_CLOSE_DISTANCE else "review",
                "caution": "Heuristic similarity, possibly shared runtime/library/compiler; NOT proven lineage"})
    return edges, comparisons


def coverage(rows):
    cells = []
    for mode in sorted({row["mode"] for row in rows}):
        for activity in range(len(ACTIVITY_EDGES)):
            subset = [row for row in rows if row["mode"] == mode and activity_bin(int(row["post_target_lineage_raw_syscalls"])) == activity]
            counts = Counter(row["class"] for row in subset)
            cells.append({"mode": mode, "activity_bin": activity, "benign": counts["benign"], "malware": counts["malware"],
                "benign_projects": len({row["group_id"] for row in subset if row["class"] == "benign"}),
                "malware_signatures": len({row["group_id"] for row in subset if row["class"] == "malware"}),
                "has_both_labels": bool(counts["benign"] and counts["malware"]),
                "cases": [row["sample"] for row in subset]})
    return cells


def design_protocol():
    return {"status": "frozen_offline_design_not_collection_release", "collection_ready": False,
        "authorized_now": ["Offline identity/similarity/coverage audit", "Evidence-gap protocol"],
        "not_authorized": ["VM or sample operation", "collector changes", "new collection", "model fitting", "dataset or split mutation"],
        "existing_data_role": "All examined cohorts and validation scores are development/exploratory only; resplitting does not restore untouched evaluation",
        "preserved_contract": {"primary_metric": "sample-weighted balanced accuracy", "p4_host_hybrid_widths": [145, 145, 290],
            "rf_trees": 500, "seed": 42, "threshold": 0.5, "selection": "29 host families by training-fold-only MI",
            "p4": "Recorded windows, captured Ethernet bytes, nominal rates; offline reconstruction, not live P4",
            "global_exclusions": ["malware_signature::DDoSAgent", "benign_project::util-linux"]},
        "binary_screen": {"libraries": {"pyelftools": "0.32", "python-tlsh": "4.5.0"},
            "same_mode_pairs_only": True, "close_distance": TLSH_CLOSE_DISTANCE, "review_distance": TLSH_REVIEW_DISTANCE,
            "interpretation": "Fixed heuristic review tiers, not universally validated clone thresholds; transitive fuzzy links are not automatic split units",
            "no_link_interpretation": "No candidate found is NOT evidence of unrelated lineage; packing, builds and architecture can hide similarity"},
        "gates": [
            {"id": "lineage", "required": "Review exact-code/TLSH/provenance candidates, cross-signature links and uncertain relationships; retain signed decisions and unresolved cases. Freeze conservative related-case units before any future split.", "passed": False},
            {"id": "tasks", "required": "Source distinct authenticated benign projects/tasks overlapping activity and native modes, not repeated profiles or extra helpers; declare task outcomes and retain low activity. Coarse common support does not prove behavioral matching.", "passed": False},
            {"id": "attribution", "required": "Separate versioned instrumentation design: socket/process/descendant lifetime, TCP and unconnected UDP, pre-existing sockets, PID reuse, mixed ABI and clock alignment. Benign null/file/network controls must reconcile intended operations and TCP/UDP application receipts with marker/tuple/time evidence, strict loss/quality, and explicitly unknown residual traffic.", "passed": False},
            {"id": "compatibility", "required": "Keep .18 captures immutable. New sensor semantics require new schema/hash and explicit compatibility review; do not silently filter interface traffic or substitute attributed-only P4 features for the frozen primary contract.", "passed": False},
            {"id": "evaluation", "required": "Choose known-family versus unseen-family target before allocation; keep task/program/lineage units whole and report both questions separately. Reserve independently sourced prospective evaluation groups/time before model selection; an independent evaluator holds labels. Review mode quotas, independent group counts and precision/power target before collection.", "passed": False},
            {"id": "release", "required": "Freeze exact source/executable/workload hashes, common baseline, interleaved order, nulls and analysis; obtain explicit launch approval. No automatic retry/replacement; strict archive/quality/exec/finite/PCAP/P4 parity gates. Lost events cannot be reconstructed.", "passed": False},
            {"id": "selection", "required": "Bounded training-only nested grouped comparison of host, P4, concatenated hybrid and nested fusion with fold-local selection/calibration. Predefine a justified complexity budget and primary BA; false-positive/recall/calibration/group metrics are supporting. Retain host-only if fusion lacks robust incremental utility; no favorable-seed or metric selection.", "passed": False},
            {"id": "final_test", "required": "Lock one candidate and host comparator before one prospective evaluation. Report paired differences and group-aware uncertainty, failures, denominators and strata. Do not change threshold/model after final outcomes. No universal best-system or guaranteed hybrid-superiority claim.", "passed": False}],
        "irreparable_history": ["Missing/lost events are unrecoverable", "Consumed validation cannot become blind again"],
        "next_execution": "Offline human review and exact task/source feasibility; benign instrumentation pilot requires separate authorization"}


def summarize_groups(groups, rows):
    index = {row["sample"]: row for row in rows}
    result = []
    for members in groups:
        if len(members) == 1:
            continue
        selected = [index[sample] for sample in members]
        result.append({"cluster_id": fingerprint(members)[:16], "cases": members,
            "resplit_cross_partition": len({row["split"] for row in selected}) > 1,
            "original_cross_partition": len({row["original_split"] for row in selected}) > 1,
            "groups": sorted({row["group_id"] for row in selected}),
            "labels": sorted({row["class"] for row in selected})})
    return result


def run():
    import explore_within_family_split as experiment
    import test_hybrid_explanations as behavior

    rows, _source_protocol = experiment.verify_prepared(SOURCE)
    checked_rows(rows)
    index, manifests = source_index()
    binary_sources = {candidate["path"] for row in rows for candidate in index.get(row["executable_sha256"], []) if candidate["path"].is_file()}
    fixed = [Path(__file__), Path(experiment.__file__), Path(behavior.__file__), SOURCE / "split_dataset.csv", SOURCE / "protocol.json",
        ROOT / "remediation-tools-install.log", NATIVE / "readiness/20261021T104951987641Z/payload.tgz", *manifests, *binary_sources]
    fixed.extend(path for path in TOOLS.rglob("*") if path.is_file() and path.suffix in (".py", ".so") and "__pycache__" not in path.parts)
    for row in rows:
        fixed.extend(STUDY / row["source_run_dir"] / name for name in ("run.json", "exec_events.csv", "syscall_events.csv"))
    inputs = {str(path): sha256(path) for path in sorted(set(fixed))}
    attempt = OUTPUT / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    protocol = {"frozen_utc": datetime.now(timezone.utc).isoformat(), "source_cases": len(rows),
        "scope": "No model score access, fitting, sample execution, VM operation or original artifact change",
        "hashes": dict(inputs), **design_protocol()}
    save(attempt / "protocol.json", protocol)
    records = []
    for position, row in enumerate(rows, 1):
        raw = behavior.raw_trace(row)
        record = {key: row[key] for key in ("sample", "class", "label", "mode", "split", "original_split", "split_unit", "group_id", "cohort", "program", "executable_sha256", "source_run_dir")}
        record.update({"host175_sha256": host_key(row), "post_calls": raw["post_calls"],
            "sequence_sha256": raw["sequence_sha256"], "binary": binary_record(row, index, inputs)})
        records.append(record)
        if position % 25 == 0:
            print(f"Audited {position}/{len(rows)} sources and archived traces", flush=True)
    edges = equal_edges(records, "split_unit", "same_program_or_hash_unit")
    edges += equal_edges(records, "host175_sha256", "identical_host175")
    edges += equal_edges(records, "sequence_sha256", "identical_nonempty_post_sequence", True, True)
    code_edges, comparisons = binary_edges(records)
    edges += code_edges
    groups = {}
    kinds = {edge["kind"] for edge in edges}
    for kind in sorted(kinds):
        groups[kind] = summarize_groups(components([row["sample"] for row in rows], edges, {kind}), rows)
    exact_kinds = kinds - {"tlsh_review_candidate"}
    groups["combined_exact_evidence_review_units"] = summarize_groups(components([row["sample"] for row in rows], edges, exact_kinds), rows)
    cells = coverage(rows)
    verified = [row for row in records if row["binary"]["status"] == "verified"]
    summary = {"cases": len(rows), "common_aligned_cases": sum(experiment.existing.aligned(row) for row in rows),
        "binary_sources_verified": len(verified), "source_gaps": [{"sample": row["sample"], **row["binary"]} for row in records if row["binary"]["status"] != "verified"],
        "same_mode_binary_pairs_screened": comparisons, "edges_by_kind": dict(Counter(edge["kind"] for edge in edges)),
        "clusters_by_kind": {kind: {"nontrivial_clusters": len(value), "resplit_cross_partition": sum(item["resplit_cross_partition"] for item in value),
            "original_cross_partition": sum(item["original_cross_partition"] for item in value), "cross_acquisition_groups": sum(len(item["groups"]) > 1 for item in value),
            "mixed_label_clusters": sum(len(item["labels"]) > 1 for item in value)} for kind, value in groups.items()},
        "activity_mode_cells_both_labels": sum(cell["has_both_labels"] for cell in cells), "activity_mode_cells": len(cells),
        "cases_in_both_label_cells": sum(cell["benign"] + cell["malware"] for cell in cells if cell["has_both_labels"]),
        "zero_post_target_cases": [row["sample"] for row in records if row["post_calls"] == 0],
        "cases_by_mode_class": {mode: dict(Counter(row["class"] for row in rows if row["mode"] == mode)) for mode in sorted({row["mode"] for row in rows})},
        "cases_by_acquisition_group": dict(Counter(row["group_id"] for row in rows)),
        "code_tlsh_unavailable": sum(row["binary"]["code_tlsh"] in ("", "TNULL") for row in verified),
        "certified_lineages": False, "collection_ready": False, "new_split_created": False,
        "model_fits": 0, "model_predictions": 0, "sample_executions": 0, "vm_operations": 0}
    save(attempt / "binary_and_behavior_cases.json", records)
    save(attempt / "relationship_edges.json", edges)
    save(attempt / "relationship_clusters.json", groups)
    save(attempt / "activity_mode_coverage.json", cells)
    save(attempt / "remediation_protocol.json", design_protocol())
    save(attempt / "summary.json", summary)
    save(attempt / "input_hashes.json", inputs)
    write_report(attempt, summary)
    outputs = {path.name: sha256(path) for path in attempt.iterdir() if path.is_file()}
    save(attempt / "output_hashes.json", outputs)
    verify(attempt)
    print(json.dumps({"attempt": str(attempt), "summary": summary}), flush=True)
    return attempt


def write_report(attempt, summary):
    counts = summary["clusters_by_kind"]
    table = "\n".join(f"| {kind} | {value['nontrivial_clusters']} | {value['resplit_cross_partition']} | {value['original_cross_partition']} | {value['cross_acquisition_groups']} |"
        for kind, value in counts.items())
    text = f"""# Offline Remediation Audit

## Scope

All {summary['cases']} accepted host cases ({summary['common_aligned_cases']} common-aligned) were audited without reading model predictions, fitting models, modifying splits, executing sample code or operating a VM. Existing .18 data, global exclusions and historical results remain unchanged. All prior evaluation is consumed/exploratory. This is not a new capture/archive/PCAP completeness audit.

## Binary And Behavioral Relationships

Verified original executable hashes for {summary['binary_sources_verified']}/{summary['cases']} cases, screened {summary['same_mode_binary_pairs_screened']} same-mode binary pairs, and reconciled every recorded exact-target boundary/post-target syscall count. Malware archive members were streamed into bounded memory only, never written to disk or executed. Benign code was also only read.

| Evidence | Clusters | Cross Resplit | Cross Original | Cross Acquisition Groups |
| --- | ---: | ---: | ---: | ---: |
{table}

Executable-region identity means identical selected file-backed code regions, not identical whole programs, arguments, data or malicious intent. TLSH distances <=30 and <=60 are frozen heuristic close/review tiers, NOT validated malware-lineage thresholds. Static runtimes and toolchains can dominate similarity. Conversely no match cannot establish independence, particularly across modes, packers or rebuilt variants. Similarity graphs can chain; fuzzy edges are not automatically promoted into split units. Exact behavioral identity also does not certify source lineage. No case is deleted or reassigned here.

`binary_and_behavior_cases.json` gives original source/manifests, executable hashes, section/segment fingerprints, TLSH and archived-trace fingerprints. `relationship_edges.json` retains distances and reasons; `relationship_clusters.json` retains exact identities and partition effects. Original roles and within-family resplit roles are both shown, not conflated. Acquisition signatures/categories are provider evidence, not independently verified attack taxonomies. Source gaps: {len(summary['source_gaps'])}; unavailable code TLSH: {summary['code_tlsh_unavailable']}.

## Coverage And Remaining Gates

{summary['cases_in_both_label_cells']}/{summary['cases']} cases fall in mode/activity cells containing both labels; {summary['activity_mode_cells_both_labels']}/{summary['activity_mode_cells']} declared cells contain both. This is descriptive coarse support, NOT corrected performance, task equivalence or a causal estimate. Counts and independent project/signature coverage are in `activity_mode_coverage.json`; no case was removed. Activity is target progress, not malicious activation. Per-event ABI, arguments and general packet ownership remain unavailable from these fingerprints; mixed-ABI descendants remain possible.

The frozen `remediation_protocol.json` separates eight gates: reviewed lineage units, independent overlapping tasks, process/flow attribution, schema compatibility, prospective evaluation design, capture release, nested development selection, and one locked final test. All launch/model gates remain false. Historical missing events and consumed validation cannot be repaired retrospectively. Exact future inputs, meaningful task diversity, independent group counts and a precision/power target must be reviewed before a collection release; no arbitrary new sample quota is asserted.

Keep the primary 145/145/290 comparison, sample-weighted BA, RF500/seed42/threshold0.5 and fold-local host MI unless explicitly amended. Do not choose a favorable grouping, seed or metric, force hybrid superiority, or deploy the highest score from the prior exploratory battery. Host-only remains a valid comparator/candidate. Newly attributed traffic would change feature semantics and needs explicit review, not silent filtering of .18 captures. Prior benign attribution/quality evidence is reused, not rerun or upgraded into general completeness.

## Next Action

Review the exact candidate pairs and source/task feasibility offline, then seek separate approval for a new-schema benign-only attribution pilot. No sample/VM/collector/model operation is authorized by this artifact. Genuinely new independent evaluation must be reserved before model selection; existing data may support development but cannot become fresh confirmation through resplitting. No fresh VM-state claim is made.

## Reproduction

From the study root, run `python3 data/versioned-collector/additional-study-review-20261022/audit_remediation.py --self-test`, `--run`, or `--verify <attempt>`. The audit depends on workspace-local pyelftools0.32 and python-tlsh4.5.0, pinned with input hashes. Inputs and outputs are rehashed on verification; output directories refuse overwrite.
"""
    with (attempt / "REPORT.md").open("x") as stream:
        stream.write(text)


def verify(attempt):
    inputs = json.loads((attempt / "input_hashes.json").read_text())
    for name, expected in inputs.items():
        if sha256(Path(name)) != expected:
            raise ValueError("Audit input changed: " + name)
    for name, expected in json.loads((attempt / "output_hashes.json").read_text()).items():
        if sha256(attempt / name) != expected:
            raise ValueError("Audit output changed: " + name)
    records = json.loads((attempt / "binary_and_behavior_cases.json").read_text())
    edges = json.loads((attempt / "relationship_edges.json").read_text())
    checked_rows(records)
    summary = json.loads((attempt / "summary.json").read_text())
    assert len(records) == summary["cases"] and summary["model_fits"] == summary["sample_executions"] == summary["vm_operations"] == 0
    assert dict(Counter(edge["kind"] for edge in edges)) == summary["edges_by_kind"]
    for kind, groups in json.loads((attempt / "relationship_clusters.json").read_text()).items():
        selected = {edge["kind"] for edge in edges} - {"tlsh_review_candidate"} if kind == "combined_exact_evidence_review_units" else {kind}
        recomputed = summarize_groups(components([row["sample"] for row in records], edges, selected), records)
        if recomputed != groups:
            raise ValueError("Relationship graph does not reproduce")
    result = {"status": "verified", "input_hashes_checked": len(inputs), "cases_checked": len(records),
        "relationship_edges_checked": len(edges), "collection_ready": False, "original_inputs_unchanged": True}
    path = attempt / "verification.json"
    if path.exists():
        if json.loads(path.read_text()) != result:
            raise ValueError("Prior verification differs")
    else:
        save(path, result)
    print(json.dumps(result), flush=True)


def self_test():
    edges = [{"left": "alpha", "right": "beta", "kind": "exact"},
             {"left": "beta", "right": "gamma", "kind": "candidate"}]
    assert components(("alpha", "beta", "gamma"), edges, {"exact"}) == [["alpha", "beta"], ["gamma"]]
    assert components(("alpha", "beta", "gamma"), edges, {"exact", "candidate"}) == [["alpha", "beta", "gamma"]]
    records = [{"sample": "alpha", "mode": "amd64", "post_calls": 0, "sequence": "empty"},
               {"sample": "beta", "mode": "amd64", "post_calls": 0, "sequence": "empty"}]
    assert equal_edges(records, "sequence", "sequence", True, True) == []
    records[0]["post_calls"] = records[1]["post_calls"] = 2
    assert len(equal_edges(records, "sequence", "sequence", True, True)) == 1
    records[1]["mode"] = "i386"
    assert equal_edges(records, "sequence", "sequence", True, True) == []
    assert activity_bin(19) == 0 and activity_bin(20) == 1 and activity_bin(45) == 2
    try:
        components(("alpha",), edges, {"exact"})
    except ValueError:
        pass
    else:
        raise AssertionError("Unknown case accepted")
    _elf, tlsh = libraries()
    content = bytes(range(256)) * 100
    assert checked_content(content, hashlib.sha256(content).hexdigest()) == content
    assert tlsh.diff(tlsh.hash(content), tlsh.hash(content)) == 0
    parsed = elf_facts(Path(sys.executable).read_bytes())
    assert parsed["code_bytes"] > 0 and parsed["code_sha256"]
    for invalid in ("0" * 64, "bad"):
        try:
            checked_content(content, invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Wrong source identity accepted")
    assert all(not gate["passed"] for gate in design_protocol()["gates"])
    print("PASS: transitive relationships, explicit evidence kinds, no empty/ABI sequence joins, activity boundaries")
    print("PASS: actual ELF parser/TLSH, bounded identity rejection, no automatic collection/model release")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.verify:
        verify(args.verify.resolve())
    elif args.run:
        run()
    else:
        parser.error("Choose --self-test, --run or --verify")


if __name__ == "__main__":
    main()