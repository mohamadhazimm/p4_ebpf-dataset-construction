#!/usr/bin/env python3
"""Select exact benign executables without executing them or operating a VM."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

import audit_redesign


ROOT = Path(__file__).resolve().parent
COMPATIBLE_PROGRAMS = {"traceroute", "ping", "ftp", "whois", "top"}
PROGRAMS = {
    "coreutils": "cat sort uniq wc head tail cut paste od cksum md5sum sha256sum base64 stat ls du comm join split cp".split(),
    "binutils": "addr2line ar as-new cxxfilt elfedit ld-new nm-new objcopy objdump ranlib readelf size strings strip-new".split(),
    "inetutils": "hostname dnsdomainname logger traceroute ping ftp inetd telnet whois rcp".split(),
    "procps": "free pgrep pidof pscommand uptime vmstat w top".split(),
    "psmisc": "pstree fuser prtstat".split(),
    "findutils": ["find", "xargs"],
    "gzip": ["gzip"],
    "bzip2": ["bzip2", "bzip2recover"],
    "grep": ["grep"],
    "sed": ["sed"],
    "gawk": ["gawk"],
    "git": ["git", "git-daemon"],
    "zip": ["zip", "zipnote", "zipsplit"],
    "unzip": ["unzip", "unzipsfx"],
    "util-linux": "cal column hexdump look rev uuidgen uuidparse getopt lsblk lscpu findmnt namei whereis fincore lslocks lsmem".split(),
    "diffutils": ["cmp", "diff", "diff3", "sdiff"],
    "patch": ["patch"],
    "curl": ["curl"],
    "wget": ["wget"],
    "rsync": ["rsync"],
    "jq": ["jq"],
    "less": ["less"],
    "xz-utils": ["xz"],
    "libzstd": ["zstd"],
    "tar": ["tar"],
    "openssl": ["openssl"],
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dynamic_dependencies(path):
    result = subprocess.run(
        ["readelf", "--wide", "--dynamic", str(path)],
        capture_output=True, text=True, check=True,
    )
    needed = []
    for line in result.stdout.splitlines():
        if "(NEEDED)" in line:
            needed.append(line.split("[", 1)[1].split("]", 1)[0])
    return sorted(needed)


def select_executables(plan, candidates, sources, builder):
    records = []
    hashes = set()
    basenames = set()
    for split in ("training", "validation"):
        for mode, allocations in plan[split].items():
            for project, required in allocations.items():
                programs = PROGRAMS[project]
                if len(programs) != required or len(set(programs)) != required:
                    raise ValueError(f"program allocation differs for {project}")
                for program in programs:
                    matches = [row for row in candidates
                               if row["project"] == project and row["mode"] == mode
                               and Path(row["path"]).name == program
                               and row.get("compatible_static_runtime", False) == (program in COMPATIBLE_PROGRAMS)]
                    if len(matches) != 1:
                        raise ValueError(f"expected one audited {project}/{program}, got {len(matches)}")
                    candidate = matches[0]
                    path = ROOT / candidate["path"]
                    observed = digest(path)
                    if observed != candidate["sha256"] or observed in hashes:
                        raise ValueError(f"changed or duplicate executable: {path}")
                    if program in basenames:
                        raise ValueError(f"basename collision requiring explicit staging review: {program}")
                    execution_mode, little_endian = builder.inspect_elf(path.read_bytes(), strict_linkage=True)
                    if execution_mode != f"native_x86_64_{mode}" or not little_endian:
                        raise ValueError(f"executable linkage changed: {path}")
                    hashes.add(observed)
                    basenames.add(program)
                    records.append({
                        **candidate,
                        "split": split,
                        "program": program,
                        "execution_mode": execution_mode,
                        "source_descriptor": sources[project]["descriptor"],
                        "source_descriptor_sha256": sources[project]["descriptor_sha256"],
                        "source_version": sources[project]["version"],
                        "needed_libraries": dynamic_dependencies(path),
                        "workload_status": "not_validated",
                        "special_preflight_requirement": {
                            "unzipsfx": "Requires a separately hashed appended data-only ZIP fixture; bare stub is not a usable workload.",
                            "xargs": "Requires an explicit --arg-file because collector stdin is DEVNULL.",
                        }.get(program),
                    })
    for split, expected in (("training", 70), ("validation", 30)):
        subset = [row for row in records if row["split"] == split]
        if len(subset) != expected:
            raise ValueError(f"incorrect {split} count")
        if Counter(row["mode"] for row in subset) != Counter({
            mode: sum(allocations.values()) for mode, allocations in plan[split].items()
        }):
            raise ValueError(f"incorrect {split} linkage quotas")
    groups = {split: {row["project"] for row in records if row["split"] == split}
              for split in ("training", "validation")}
    if groups["training"] & groups["validation"] or len(hashes) != 100:
        raise ValueError("duplicate executables or crossing project groups")
    return records


def main():
    report_path = ROOT / "preparation-audit.json"
    report = json.loads(report_path.read_text())
    plan_path = ROOT / "benign-project-plan.json"
    plan = json.loads(plan_path.read_text())
    if not report["build_allocations_complete"] or report["unfilled_allocated_builds"]:
        raise ValueError("complete independently audited build coverage is required")
    for name in ("benign-project-plan.json", "prepare_benign_source.sh", "audit_redesign.py"):
        if digest(ROOT / name) != report["code_hashes"][name]:
            raise ValueError(f"preparation audit is stale for {name}")
    sources = {row["project"]: row for row in report["authenticated_sources"]}
    records = select_executables(plan, report["verified_build_candidates"], sources, audit_redesign.load_builder())
    result = {
        "status": "exact_build_identities_selected_workloads_not_validated",
        "collection_ready": False,
        "unit": "distinct_executable_sha256_grouped_by_upstream_project",
        "benign_project_plan_sha256": digest(plan_path),
        "preparation_audit_sha256": digest(report_path),
        "builder_sha256": digest(Path(__file__)),
        "executables": records,
        "pending_gates": [
            "safe arguments, fixtures and outcome checks for every executable",
            "identify and verify required guest libraries and support programs",
            "independently hash and audit any derived self-extracting fixture artifact",
            "guest workload/exec/activation preflight, frozen preregistration and interleaved order",
        ],
    }
    output = ROOT / "manifests" / "benign-executables.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "status": result["status"],
        "collection_ready": False,
        "executables": len(records),
        "unique_hashes": len({row["sha256"] for row in records}),
        "split_counts": dict(Counter(row["split"] for row in records)),
        "mode_counts": dict(Counter(row["execution_mode"] for row in records)),
        "required_dynamic_libraries": sorted({name for row in records for name in row["needed_libraries"]}),
    }, indent=2))


if __name__ == "__main__":
    main()