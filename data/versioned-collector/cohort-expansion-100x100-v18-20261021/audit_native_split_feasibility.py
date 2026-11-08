#!/usr/bin/env python3
"""Audit whether current native candidates support the grouped 70/30 split."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def subset_sums(counts: Counter[str]) -> list[int]:
    possible = {0}
    for count in counts.values():
        possible |= {value + count for value in tuple(possible)}
    return sorted(possible)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x64-preparation", type=Path, required=True)
    parser.add_argument("--i386-report", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    preparation = args.x64_preparation.resolve()
    drafts_path = preparation / "benign-x64-workload-drafts.json"
    x64_preflight_path = preparation / "x64-host-preflight.json"
    i386_report_path = args.i386_report.resolve()
    inventory_path = ROOT / "inventory.json"
    drafts = json.loads(drafts_path.read_text())
    x64_preflight = json.loads(x64_preflight_path.read_text())
    i386_report = json.loads(i386_report_path.read_text())
    inventory = json.loads(inventory_path.read_text())

    if (x64_preflight["status"] != "accepted_host_preflight_only"
            or len(x64_preflight["cases"]) != 49
            or any(case["status"] != "accepted" for case in x64_preflight["cases"])
            or x64_preflight["guest_preflight"]):
        raise ValueError("x64 host workload evidence is not the accepted 49-case report")
    if (i386_report["status"] != "accepted_host_i386_build_and_semantic_preflight"
            or i386_report["unique_programs"] != 51 or i386_report["unique_binary_hashes"] != 51
            or i386_report["guest_preflight"]):
        raise ValueError("i386 evidence is not the accepted 51-case host report")

    x64_cases = drafts["cases"]
    i386_artifacts = i386_report["artifacts"]
    if len(x64_cases) != 49 or len(i386_artifacts) != 51:
        raise ValueError("mode-matched benign control counts differ from 49/51")
    project_counts = Counter(case["project"] for case in x64_cases)
    project_counts.update(artifact["project"] for artifact in i386_artifacts)
    project_sums = subset_sums(project_counts)

    native_modes = {"native_x86_64_static", "native_i386_static"}
    malware_candidates = [row for row in inventory["malware_candidates"]
                          if row["execution_mode"] in native_modes
                          and row["group_id"] != "malware_signature::unassigned"]
    malware_mode_counts = Counter(row["execution_mode"] for row in malware_candidates)
    malware_group_counts = Counter(row["group_id"] for row in malware_candidates)
    groups_by_mode = {
        mode: sorted({row["group_id"] for row in malware_candidates if row["execution_mode"] == mode})
        for mode in sorted(native_modes)
    }
    group_target = {"training_groups": 9, "validation_groups": 10}
    result = {
        "status": "not_ready_group_split_infeasible",
        "collection_ready": False,
        "collection_started": False,
        "guest_preflight_performed": False,
        "malware_executed": False,
        "inputs": {
            "x64_workload_drafts": str(drafts_path.relative_to(STUDY)),
            "x64_workload_drafts_sha256": sha256(drafts_path),
            "x64_host_preflight": str(x64_preflight_path.relative_to(STUDY)),
            "x64_host_preflight_sha256": sha256(x64_preflight_path),
            "i386_build_report": str(i386_report_path.relative_to(STUDY)),
            "i386_build_report_sha256": sha256(i386_report_path),
            "candidate_inventory": str(inventory_path.relative_to(STUDY)),
            "candidate_inventory_sha256": sha256(inventory_path),
        },
        "benign_controls": {
            "total": len(x64_cases) + len(i386_artifacts),
            "mode_counts": {"native_x86_64_static": len(x64_cases),
                            "native_i386_static": len(i386_artifacts)},
            "projects": dict(sorted(project_counts.items())),
            "whole_project_validation_size_options": project_sums,
            "whole_project_70_30_feasible": 30 in project_sums,
        },
        "malware_candidates": {
            "native_candidate_count": len(malware_candidates),
            "mode_counts": dict(sorted(malware_mode_counts.items())),
            "signature_group_count": len(malware_group_counts),
            "signature_counts": dict(sorted(malware_group_counts.items())),
            "groups_by_mode": groups_by_mode,
            "prior_grouped_design_reference": group_target,
            "group_budget_feasible": len(malware_group_counts) >= sum(group_target.values()),
        },
        "blockers": [
            "No subset of the four benign software-project groups yields a 30-case whole-project validation set from these 100 controls.",
            "The local native malware pool contains seven signature groups, fewer than the existing 9-train/10-validation grouped-design reference.",
            "Host-only workload checks do not replace guest dependency, activation, sensor-smoke, or final-order preflight.",
        ],
    }
    output = args.output.resolve() if args.output else preparation / "split-feasibility.json"
    if output.exists():
        raise FileExistsError(f"preserving existing report: {output}")
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "collection_ready": False,
                      "project_groups": result["benign_controls"]["projects"],
                      "signature_group_count": result["malware_candidates"]["signature_group_count"],
                      "report": str(output)}, indent=2))


if __name__ == "__main__":
    main()