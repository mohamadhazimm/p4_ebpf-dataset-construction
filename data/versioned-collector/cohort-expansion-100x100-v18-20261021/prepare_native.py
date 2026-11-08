#!/usr/bin/env python3
"""Prepare additional native candidates; no sample execution or VM operation."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import prepare_inventory


ROOT = Path(__file__).resolve().parent


def prepare_x64_workloads(attempt, candidates, builder):
    profiles = {
        "coreutils": {
            "b2sum": ["fixture.txt"], "base32": ["fixture.txt"], "basenc": ["--base64", "fixture.txt"],
            "csplit": ["--prefix=piece-", "fixture.txt", "3"],
            "dd": ["if=fixture.txt", "of=dd-copy.txt", "bs=64", "count=4", "status=none"],
            "expand": ["--tabs=4", "tabs.txt"],
            "fmt": ["--width=40", "paragraph.txt"], "fold": ["--width=20", "paragraph.txt"],
            "nl": ["--body-numbering=a", "fixture.txt"], "numfmt": ["--to=iec", "1048576"],
            "pr": ["--omit-header", "fixture.txt"], "ptx": ["--width=60", "fixture.txt"],
            "sha1sum": ["fixture.txt"], "sha224sum": ["fixture.txt"],
            "sha384sum": ["fixture.txt"], "sha512sum": ["fixture.txt"],
            "shuf": ["--random-source=entropy.bin", "--head-count=3", "fixture.txt"],
            "tac": ["fixture.txt"], "tsort": ["edges.txt"],
            "unexpand": ["--all", "tabs.txt"], "uname": ["-s"], "nproc": ["--all"],
            "basename": ["--suffix=.txt", "inputs/fixture.txt"], "dirname": ["inputs/fixture.txt"],
            "realpath": ["fixture.txt"], "readlink": ["--canonicalize-existing", "fixture.txt"],
            "pathchk": ["--portability", "fixture.txt"], "date": ["--utc", "--date=@946684800", "+%Y-%m-%d"],
            "expr": ["12345", "+", "67890"], "factor": ["1234567890"], "seq": ["1", "1000"],
            "mkdir": ["-p", "generated/one/two"], "chmod": ["u=rw,go=r", "permissions.txt"],
            "mktemp": ["--tmpdir=.", "generated.XXXXXX"],
            "touch": ["--date=@946684800", "touched.txt"], "truncate": ["--size=8192", "sparse.bin"],
            "ln": ["fixture.txt", "linked.txt"], "df": ["--block-size=1024", "."],
        },
        "procps": {
            "sysctl": ["-n", "kernel.ostype"],
        },
        "util-linux": {
            "flock": ["--exclusive", "lockfile", "--command", "printf lock-ok"],
            "fallocate": ["--length", "65536", "allocated.bin"],
            "hardlink": ["--dry-run", "--verbose", "duplicates"],
            "ipcs": ["--summary"], "lsipc": ["--global"],
            "lsns": ["--type", "mnt", "--output", "NS,TYPE"], "mcookie": [],
            "mountpoint": ["--quiet", "/"], "prlimit": ["--pid", "0"],
            "taskset": ["0x1", "/bin/true"],
        },
    }
    fixtures = attempt / "x64-workspace-seed"
    fixtures.mkdir()
    for name, data in {
        "fixture.txt": b"alpha one\nbeta two\ngamma three\ndelta four\nepsilon five\n",
        "tabs.txt": b"alpha\tbeta\n        gamma\tdelta\n",
        "paragraph.txt": b"Bounded local text processing with deterministic fixture content and no network access.\n",
        "edges.txt": b"alpha beta\nbeta gamma\ngamma delta\n",
        "entropy.bin": bytes(range(256)) * 16, "permissions.txt": b"workspace-only permission fixture\n",
        "duplicates/one.txt": b"same content\n", "duplicates/two.txt": b"same content\n",
    }.items():
        path = fixtures / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    source_audit = json.loads((prepare_inventory.PREPARATION / "preparation-audit.json").read_text())
    sources = {row["project"]: row for row in source_audit["authenticated_sources"]}
    output_checks = {
        "dd": {"file_equals_fixture": ["dd-copy.txt", "fixture.txt"]},
        "csplit": {"concatenated_files_equal_fixture": [["piece-00", "piece-01"], "fixture.txt"]},
        "mkdir": {"directory_exists": "generated/one/two"},
        "chmod": {"file_mode": ["permissions.txt", "0644"]},
        "mktemp": {"new_regular_file_glob": "generated.??????"},
        "touch": {"file_mtime": ["touched.txt", 946684800]},
        "truncate": {"file_size": ["sparse.bin", 8192]},
        "ln": {"same_inode": ["fixture.txt", "linked.txt"]},
        "fallocate": {"file_size": ["allocated.bin", 65536]},
        "numfmt": {"stdout_equals": "1.0M\n"}, "date": {"stdout_equals": "2000-01-01\n"},
        "expr": {"stdout_equals": "80235\n"}, "basename": {"stdout_equals": "fixture\n"},
        "dirname": {"stdout_equals": "inputs\n"}, "flock": {"stdout_equals": "lock-ok"},
        "pathchk": {"successful_path_validation": "fixture.txt"},
        "mountpoint": {"successful_mountpoint_query": "/"},
        "sysctl": {"stdout_equals": "Linux\n"},
        "uname": {"stdout_equals": "Linux\n"},
        "nproc": {"positive_integer_cpu_count": True},
    }
    records = []
    identities = set()
    for project, programs in profiles.items():
        for program, arguments in programs.items():
            matches = [row for row in candidates if row["project"] == project and row["program"] == program]
            if not matches:
                raise ValueError(f"missing unused static control: {project}/{program}")
            row = sorted(matches, key=lambda entry: (entry.get("compatible_static_runtime", False), entry["path"]))[0]
            if row["sha256"] in identities:
                raise ValueError("duplicate x64 control identity")
            identities.add(row["sha256"])
            records.append({**row, "arguments": arguments, "stdin": "DEVNULL", "timeout_s": 20,
                            "working_directory": "fresh copy of x64-workspace-seed",
                            "expected_return_code": 0,
                            "outcome_check": output_checks.get(program, {"stdout_nonempty": True, "exact_semantic_check_pending": True}),
                            "source_descriptor": sources[project]["descriptor"],
                            "source_descriptor_sha256": sources[project]["descriptor_sha256"],
                            "workload_status": "draft_not_guest_preflighted"})
    if len(records) != 49:
        raise ValueError(f"expected 49 x64 control drafts, got {len(records)}")
    return {"status": "49_distinct_x64_controls_drafted_not_ready", "collection_ready": False,
            "cases": records, "project_counts": dict(Counter(row["project"] for row in records)),
            "fixture_hashes": {str(path.relative_to(attempt)): builder.sha256_file(path)
                               for path in sorted(fixtures.rglob("*")) if path.is_file()},
            "limitations": ["Three upstream projects, not 49 independent software families.",
                            "No help/version, interactive, public-network or privileged workload is intended.",
                            "All actual guest outcomes and remaining exact semantic checks are pending.",
                            "Old source-authentication evidence is referenced; it is not freshly reauthenticated here."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-x64-workloads", action="store_true")
    parser.add_argument("--i386-validation", type=Path)
    args = parser.parse_args()
    builder = prepare_inventory.load_builder()
    gate_evidence = None
    if args.i386_validation:
        gate_path = args.i386_validation.resolve()
        gate = json.loads(gate_path.read_text())
        if (gate["status"] != "accepted" or not gate["i386_gate_passed"] or gate["errors"]
                or len(gate["cases"]) != 12 or gate["malware_executions"] != 0):
            raise ValueError("i386 compatibility gate was not accepted")
        if gate["validator_sha256"] != builder.sha256_file(ROOT / "validate_native_checks.py"):
            raise ValueError("derived validator hash changed")
        if gate["protocol_sha256"] != builder.sha256_file(gate_path.parent / "protocol.json"):
            raise ValueError("compatibility protocol hash changed")
        gate_evidence = {"path": str(gate_path.relative_to(prepare_inventory.STUDY)),
                         "sha256": builder.sha256_file(gate_path),
                         "scope": "static native BusyBox null/file/net checks; two repeats per mode"}
    inventory_path = ROOT / "inventory.json"
    inventory = json.loads(inventory_path.read_text())
    for name, expected in inventory["input_hashes"].items():
        if builder.sha256_file(prepare_inventory.STUDY / name) != expected:
            raise ValueError(f"inventory input changed: {name}")
    selected = []
    for row in inventory["malware_candidates"]:
        if row["execution_mode"] not in {"native_x86_64_static", "native_i386_static"}:
            continue
        if row["group_id"] == "malware_signature::unassigned":
            continue
        archive = prepare_inventory.STUDY / row["source_archive_path"]
        if builder.sha256_file(archive) != row["source_archive_sha256"]:
            raise ValueError(f"source archive changed: {row['sample']}")
        observed = builder.inspect_archive(row["sample"], row, archive, strict_linkage=True)
        if observed["member_sha256"] != row["member_sha256"] or observed["execution_mode"] != row["execution_mode"]:
            raise ValueError(f"archive member or native mode changed: {row['sample']}")
        selected.append(row)
    if len({row["sha256"] for row in selected}) != len(selected):
        raise ValueError("duplicate native candidate identity")
    benign = [row for row in inventory["benign_build_candidates"]
              if row["execution_mode"] == "native_x86_64_static"
              and not row["same_project_program_in_previous_cohort"]]
    for row in benign:
        if builder.sha256_file(prepare_inventory.STUDY / row["path"]) != row["sha256"]:
            raise ValueError(f"benign build changed: {row['program']}")
    attempt = ROOT / "native-preparation" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    for mode in ("native_x86_64_static", "native_i386_static"):
        (attempt / f"{mode}-candidates.txt").write_text(
            "".join(row["sample"] + "\n" for row in selected if row["execution_mode"] == mode)
        )
    if args.prepare_x64_workloads:
        controls = prepare_x64_workloads(attempt, benign, builder)
        (attempt / "benign-x64-workload-drafts.json").write_text(json.dumps(controls, indent=2, sort_keys=True) + "\n")
    result = {
        "status": "native_candidates_verified_i386_gate_passed" if gate_evidence else "native_candidates_verified_i386_check_pending",
        "collection_ready": False,
        "malware_execution_authorized": False,
        "full_collection_started": False,
        "i386_compatibility_evidence": gate_evidence,
        "architecture_scope": ["native_x86_64_static", "native_i386_static"] if gate_evidence else ["native_x86_64_static"],
        "target_counts": {"malware": 100, "benign": 100},
        "inventory_sha256": builder.sha256_file(inventory_path),
        "preparer_sha256": builder.sha256_file(Path(__file__)),
        "malware_candidates": selected,
        "malware_mode_counts": dict(Counter(row["execution_mode"] for row in selected)),
        "malware_signature_counts": dict(Counter(row["group_id"] for row in selected)),
        "benign_x64_build_candidates": benign,
        "benign_i386_build_candidates": [],
        "limitations": [
            "Candidate pool is not the final 100-case selection or an executable collection manifest.",
            "Unused means absent from the preceding 100x100 identity manifests, not historically unseen.",
            "Named native x86-64 candidates are Mirai only; group imbalance cannot be fixed by a random split.",
            "No new holdout is assigned; the previously scored holdout is preserved and remains consumed.",
            "Benign x64 files are build candidates, not accepted safe workloads; i386 sources/builds are pending.",
        ],
        "pending_gates": [
            *([] if gate_evidence else ["Fresh benign-only .18 i386 known-answer checks with native x64 comparators."]),
            "Authenticated i386 benign builds, exact identities and bounded workload/outcome checks.",
            "Select 100 distinct cases per label with equal architecture/linkage quotas across labels.",
            "Agree and freeze grouping, dataset role, nulls and interleaved order before collection.",
            "Full readiness and separate full-collection authorization.",
        ],
    }
    (attempt / "preparation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"attempt": str(attempt), "collection_ready": False,
                      "malware_mode_counts": result["malware_mode_counts"],
                      "malware_signature_counts": result["malware_signature_counts"],
                      "benign_x64_build_candidates": len(benign), "benign_i386_build_candidates": 0}, indent=2))


if __name__ == "__main__":
    main()