#!/usr/bin/env python3
"""Assess additional-source readiness against the existing joint dataset offline."""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from audit_original_cohorts import ROOT, STUDY, digest


REVIEW = ROOT / "attempts/20261022T052110153141Z"
BASE = ROOT.parent / "cohort-expansion-100x100-v18-20261021/combined-analysis/20261022T044439885696Z"
PINS = {
    "src/malware_runner.py": "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49",
    "scripts/vbox_malware_batch.sh": "4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f",
    "scripts/stage_versioned_runner_snapshot.sh": "5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103",
}
ANCHOR_PINS = {
    "combined_manifest.json": "27d835953c1daf2d1e303770ccdd1b6a80c96c532bd4c0ce25cc8fbc21b81ef1",
    "protocol.json": "faa71b48be8e51cb6bd8ffbd65208441425d9475cdb6476232817731f6b63371",
    "analysis/model-fit/metrics.json": "f6395245ad75f7fc6e43edd3421548a7eb2ed77d5f8777896041c2b9332b66c0",
}


def load(path):
    return json.loads(path.read_text())


def group_roles(rows):
    roles = {}
    for row in rows:
        group = row["group_id"].casefold()
        if row["split"] not in ("training", "validation"):
            raise ValueError("Unexpected dataset role")
        if group in roles and roles[group] != row["split"]:
            raise ValueError("Global family/project role collision: " + group)
        roles[group] = row["split"]
    return roles


def validate_addition(case, roles, identities, excluded):
    group = case["group_id"].casefold()
    if group in excluded:
        raise ValueError("Globally excluded group")
    if case["sha256"] in identities:
        raise ValueError("Previously planned or retained executable identity")
    if group in roles and case["split"] != roles[group]:
        raise ValueError("Addition crosses an existing group role")
    if case["mode"] not in ("native_amd64_static", "native_amd64_dynamic", "native_i386_static"):
        raise ValueError("Mode outside the existing merge contract")


def self_test():
    rows = [{"group_id": "malware_signature::XorDDoS", "split": "validation"}]
    roles = group_roles(rows)
    good = {"group_id": rows[0]["group_id"], "split": "validation",
            "sha256": "a" * 64, "mode": "native_i386_static"}
    validate_addition(good, roles, {"b" * 64}, {"malware_signature::ddosagent"})
    probes = [
        {**good, "split": "training"},
        {**good, "sha256": "b" * 64},
        {**good, "mode": "native_i386_static-pie"},
        {**good, "group_id": "malware_signature::DDoSAgent"},
    ]
    for case in probes:
        try:
            validate_addition(case, roles, {"b" * 64}, {"malware_signature::ddosagent"})
        except ValueError:
            continue
        raise AssertionError("Invalid addition accepted: " + str(case))
    try:
        group_roles(rows + [{**rows[0], "split": "training"}])
    except ValueError:
        pass
    else:
        raise AssertionError("Existing group overlap accepted")
    print("PASS: inherited role, duplicate identity, excluded group, static-PIE and global-overlap checks")


def assess(source_verification=None):
    inputs = {}
    for relative, expected in PINS.items():
        path = STUDY / relative
        if digest(path) != expected:
            raise ValueError("Production pin differs; compatibility review required: " + relative)
        inputs[relative] = expected
    for relative, expected in ANCHOR_PINS.items():
        path = BASE / relative
        if digest(path) != expected:
            raise ValueError("Existing analysis anchor changed: " + relative)
        inputs[str(path.relative_to(STUDY))] = expected
    manifest = load(BASE / "combined_manifest.json")
    for relative, expected in manifest["data_hashes"].items():
        path = BASE / "analysis" / relative
        if digest(path) != expected:
            raise ValueError("Existing prepared data changed: " + relative)
        inputs[str(path.relative_to(STUDY))] = expected
    summary = load(REVIEW / "summary.json")
    for relative, expected in summary["input_hashes"].items():
        if digest(STUDY / relative) != expected:
            raise ValueError("Original pool audit input changed: " + relative)
        inputs[relative] = expected
    for name in ("summary.json", "malware-535-review.json", "benign-500-review.json"):
        inputs[str((REVIEW / name).relative_to(STUDY))] = digest(REVIEW / name)
    with (BASE / "analysis/eligible_dataset.csv").open(newline="") as stream:
        existing = list(csv.DictReader(stream))
    roles = group_roles(existing)
    existing_hashes = {row["executable_sha256"] for row in existing}
    if len(existing_hashes) != len(existing):
        raise ValueError("Duplicate executable identity in anchor")
    protocol = load(BASE / "protocol.json")
    excluded = {name.casefold() for name in protocol["excluded_groups"]}
    contract = load(BASE / "analysis/compatibility_audit.json")
    if protocol["feature_columns"] != {"network_p4": 145, "host_selected": 145, "hybrid": 290}:
        raise ValueError("Feature contract changed")
    malware = load(REVIEW / "malware-535-review.json")
    benign = load(REVIEW / "benign-500-review.json")
    recovery_reference = None
    if source_verification:
        source_verification = source_verification.resolve()
        recovery = load(source_verification)
        if (recovery["requested"] != 535 or recovery["recovered"] != 535 or recovery["missing"]
                or recovery["sample_executions"] != 0):
            raise ValueError("Incomplete or unexpected source-recovery scope")
        for name, key in (("guest_source_index.json", "guest_source_index_sha256"),
                          ("final_vm_state.json", "final_vm_state_sha256"),
                          ("source-archives.tar", "transport_sha256")):
            path = source_verification.parent / name
            if digest(path) != recovery[key]:
                raise ValueError("Source-recovery evidence changed: " + name)
            inputs[str(path.relative_to(STUDY))] = recovery[key]
        if digest(ROOT / "export_original_sources.py") != recovery["exporter_sha256"]:
            raise ValueError("Source inspector changed since verification")
        inputs[str((ROOT / "export_original_sources.py").relative_to(STUDY))] = recovery["exporter_sha256"]
        inputs[str(source_verification.relative_to(STUDY))] = digest(source_verification)
        recovered = {row["sha256"]: row for row in recovery["sources"]}
        if set(recovered) != {row["sha256"] for row in malware} or len(recovery["sources"]) != 535:
            raise ValueError("Recovered identities differ from original review")
        malware = [{**row, **recovered[row["sha256"]],
                "source_archive_sha256": recovered[row["sha256"]]["archive_sha256"]}
               for row in malware]
        recovery_reference = str(source_verification.relative_to(STUDY))
    candidates = []
    for original in malware + benign:
        is_malware = "family_labels" in original
        if is_malware:
            family = original["family_labels"].split(";")[0]
            group = "malware_signature::" + family
        else:
            group = "benign_project::" + original["candidate_project"]
        role = roles.get(group.casefold(), "pending_whole_group_allocation")
        reasons = []
        if group.casefold() in excluded:
            reasons.append("globally_excluded_group")
        if original["sha256"] in existing_hashes or original.get("prior_native_case", False):
            reasons.append("previously_planned_or_retained_identity")
        if role == "pending_whole_group_allocation":
            reasons.append("new_group_role_needs_protocol_freeze")
        mode = original.get("mode", "script_shebang")
        if is_malware:
            if original["family_status"] != "known":
                reasons.append("unresolved_family_label")
            if original["source_member_verified"]:
                source = STUDY / original["source_archive_path"]
                if not source.is_file() or digest(source) != original["source_archive_sha256"]:
                    raise ValueError("Reviewed source changed: " + original["sample"])
                inputs[str(source.relative_to(STUDY))] = original["source_archive_sha256"]
            else:
                reasons.append("source_member_and_elf_not_verified")
            if mode not in ("native_amd64_static", "native_amd64_dynamic", "native_i386_static"):
                reasons.append("mode_not_verified_within_existing_contract")
        else:
            reasons.append("native_executable_and_workload_manifest_required")
        candidates.append({"sample": original["sample"], "class": "malware" if is_malware else "benign",
            "sha256": original["sha256"], "group_id": group, "mode": mode,
            "inherited_role": role, "old_training_role_conflicts": role == "validation",
            "source_archive_path": original.get("source_archive_path", ""),
            "source_archive_sha256": original.get("archive_sha256", original.get("source_archive_sha256", "")),
            "source_format": original.get("source_format", "script" if not is_malware else "archive"),
            "preparation_reasons": reasons, "source_stage_candidate": not reasons})
    gate_reasons = [
        "The 500 scripts are task ideas, not a new authenticated native executable/workload release.",
        "Exact additional identities, per-label mode quotas and whole-group roles are not frozen.",
        "Common snapshot/payload, interleaved order and preregistration have not been staged and checked.",
        "Exact new benign executable/workload preflight and release-specific sensor/null gates are absent.",
        "Collection remains separately authorized; this assessment cannot launch samples.",
    ]
    if not recovery_reference:
        gate_reasons.insert(0, "Original sources are incompletely verified; recover source members and strict ELF modes first.")
    report = {
        "status": "blocked_before_release_preflight", "collection_ready": False,
        "collection_started": False, "vm_operations": 0, "sample_executions": 0, "model_fits": 0,
        "anchor": str(BASE.relative_to(STUDY)), "anchor_host_eligible": len(existing),
        "anchor_common_aligned": sum(row["p4_alignment_status"] == "unique" and row["p4_parity"] == "True" for row in existing),
        "anchor_validation_already_consumed": True,
        "source_recovery_reference": recovery_reference,
        "reviewed_malware_mode_counts": dict(Counter(row["mode"] for row in malware)),
        "additional_source_stage_modes": dict(Counter(row["mode"] for row in candidates if row["source_stage_candidate"])),
        "additional_source_stage_groups": dict(Counter(row["group_id"] for row in candidates if row["source_stage_candidate"])),
        "evaluation_role": "Exploratory development extension; inherited validation is not fresh or confirmatory",
        "settings_required": contract["settings_verified"], "feature_columns_required": protocol["feature_columns"],
        "model_protocol_required": protocol, "excluded_groups": protocol["excluded_groups"],
        "global_group_roles": roles, "candidate_counts": {}, "blockers": gate_reasons,
        "post_collection_requirements": [
            "Verify per-run schema/hash/settings, retrieval, safe archive/member hashes and exact target exec/native mode.",
            "Require active sensors, 40x169 finite telemetry, independent PCAP counters, zero reported loss/discrepancy/unresolved ABI.",
            "Compute fresh unique recorded-window P4 alignment and Ethernet/nominal-rate parity before primary merging.",
            "Preserve failed/rejected/missing, exec and alignment exclusions; retain low activity; no automatic retries/replacements.",
            "Recheck global group roles, duplicate executables/programs, per-mode label coverage and raw/prepared feature parity.",
        ],
        "input_hashes": inputs,
    }
    for label in ("malware", "benign"):
        subset = [row for row in candidates if row["class"] == label]
        report["candidate_counts"][label] = {
            "reviewed": len(subset),
            "inherited_roles": dict(Counter(row["inherited_role"] for row in subset)),
            "old_training_role_conflicts": sum(row["old_training_role_conflicts"] for row in subset),
            "source_stage_candidates_not_collection_ready": sum(row["source_stage_candidate"] for row in subset),
            "preparation_reason_counts": dict(Counter(reason for row in subset for reason in row["preparation_reasons"])),
        }
    output = ROOT / "merge-readiness" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True, exist_ok=False)
    inputs[str(Path(__file__).relative_to(STUDY))] = digest(Path(__file__))
    for name, content in (("candidate_audit.json", candidates), ("readiness.json", report)):
        (output / name).write_text(json.dumps(content, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"attempt": str(output), "status": report["status"],
                      "collection_ready": False, "candidate_counts": report["candidate_counts"]}, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--require-ready", action="store_true")
    parser.add_argument("--source-verification", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif not assess(args.source_verification)["collection_ready"] and args.require_ready:
        raise SystemExit(2)


if __name__ == "__main__":
    main()