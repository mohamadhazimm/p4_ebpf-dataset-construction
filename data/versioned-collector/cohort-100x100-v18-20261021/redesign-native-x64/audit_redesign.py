#!/usr/bin/env python3
"""Audit preparation artifacts only; never execute sample binaries or operate VMs."""

from __future__ import annotations

import importlib.util
import json
import os
import struct
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

import apt_pkg


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[3]
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"


def load_builder():
    spec = importlib.util.spec_from_file_location("selection_builder", ROOT.parent / "prepare_selection.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load selection builder")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def read_descriptor(path):
    with os.fdopen(apt_pkg.open_maybe_clear_signed_file(str(path)), "rb") as source:
        tags = apt_pkg.TagFile(source)
        if not tags.step():
            raise ValueError(f"empty descriptor: {path}")
        return dict(tags.section)


def checksum_rows(value):
    rows = {}
    for line in value.splitlines():
        if line.strip():
            digest, size, name = line.split()
            if name in rows:
                raise ValueError(f"duplicate checksum name: {name}")
            rows[name] = (digest, int(size))
    return rows


def audit_sources(builder, projects, source_directories=None):
    authenticated_descriptors = {}
    release_records = []
    for release in sorted((ROOT / "apt-lists").glob("*InRelease")):
        result = subprocess.run(["gpgv", "--keyring", KEYRING, str(release)],
                                capture_output=True, text=True, check=True)
        fields = read_descriptor(release)
        checksums = checksum_rows(fields["SHA256"])
        prefix = release.name.removesuffix("_InRelease")
        for component in ("main", "universe"):
            index = release.parent / f"{prefix}_{component}_source_Sources"
            digest, size = checksums[f"{component}/source/Sources"]
            if index.stat().st_size != size or builder.sha256_file(index) != digest:
                raise ValueError(f"source index not bound to signed Release: {index}")
            with index.open("rb") as source:
                for section in apt_pkg.TagFile(source):
                    if section["Package"] in projects:
                        for name, checksum in checksum_rows(section["Checksums-Sha256"]).items():
                            if name.endswith(".dsc"):
                                authenticated_descriptors.setdefault(name, set()).add(checksum)
        release_records.append({"path": str(release.relative_to(ROOT)),
                                "sha256": builder.sha256_file(release),
                                "date": fields.get("Date"),
                                "valid_until": fields.get("Valid-Until"),
                                "signature_verified": result.returncode == 0})
    if len(release_records) != 3:
        raise ValueError("expected three authenticated repository Release files")
    source_records = []
    for project in sorted(projects):
        directory = (source_directories or {}).get(project, ROOT / "benign-sources" / project)
        descriptors = list(directory.glob("*.dsc"))
        if len(descriptors) != 1:
            raise ValueError(f"expected one source descriptor for {project}")
        descriptor = descriptors[0]
        identity = (builder.sha256_file(descriptor), descriptor.stat().st_size)
        if identity not in authenticated_descriptors.get(descriptor.name, set()):
            raise ValueError(f"descriptor not authenticated by source indexes: {descriptor}")
        fields = read_descriptor(descriptor)
        if fields["Source"] != project:
            raise ValueError(f"source project differs: {descriptor}")
        files = []
        for name, (digest, size) in checksum_rows(fields["Checksums-Sha256"]).items():
            if Path(name).name != name:
                raise ValueError(f"unsafe source filename: {name}")
            path = descriptor.parent / name
            if path.stat().st_size != size or builder.sha256_file(path) != digest:
                raise ValueError(f"source archive checksum differs: {path}")
            files.append({"path": str(path.relative_to(ROOT)), "sha256": digest, "size": size})
        source_records.append({"project": project, "version": fields["Version"],
                               "descriptor": str(descriptor.relative_to(ROOT)),
                               "descriptor_sha256": identity[0], "files": files})
    return release_records, source_records


def audit_compatible_runtime(builder):
    packages = {"musl", "musl-dev", "musl-tools"}
    trusted = set()
    for release in sorted((ROOT / "apt-lists").glob("*InRelease")):
        fields = read_descriptor(release)
        checksums = checksum_rows(fields["SHA256"])
        prefix = release.name.removesuffix("_InRelease")
        for component in ("main", "universe"):
            paths = list(release.parent.glob(f"{prefix}_{component}_binary-amd64_Packages*"))
            if len(paths) != 1:
                raise ValueError("ambiguous or missing authenticated binary index")
            with tempfile.TemporaryFile() as output:
                subprocess.run(["/usr/lib/apt/apt-helper", "cat-file", str(paths[0])], stdout=output, check=True)
                output.seek(0)
                data = output.read()
                expected_hash, expected_size = checksums[f"{component}/binary-amd64/Packages"]
                if len(data) != expected_size or builder.sha256_bytes(data) != expected_hash:
                    raise ValueError("binary index differs from signed Release")
                output.seek(0)
                for section in apt_pkg.TagFile(output):
                    if section["Package"] in packages:
                        trusted.add((section["Package"], section["Version"], section["Architecture"],
                                     section["SHA256"], int(section["Size"])))
    records = []
    for path in sorted((ROOT / "compatible-static/musl-debs").glob("*.deb")):
        control = subprocess.run(["dpkg-deb", "-f", str(path)], capture_output=True, text=True, check=True)
        fields = apt_pkg.TagSection(control.stdout)
        identity = (fields["Package"], fields["Version"], fields["Architecture"], builder.sha256_file(path), path.stat().st_size)
        if identity not in trusted:
            raise ValueError("musl package not authenticated by signed binary index")
        records.append({"package": identity[0], "version": identity[1], "path": str(path.relative_to(ROOT)),
                        "sha256": identity[3], "size": identity[4]})
    if {row["package"] for row in records} != packages:
        raise ValueError("compatible static compiler packages incomplete")
    _, sources = audit_sources(builder, {"ncurses"}, {"ncurses": ROOT / "compatible-static/ncurses-archives"})
    return {"family": "musl", "authenticated_packages": records, "authenticated_support_sources": sources,
            "compiler_helper_sha256": builder.sha256_file(ROOT / "prepare_compatible_static.sh"),
            "limitation": "files/DNS lookup, not guest systemd/SSS NSS plugins; guest policy unchanged"}


def audit_builds(builder):
    records = []
    for build in sorted((ROOT / "builds").glob("*")):
        provenance = build / "build-provenance.txt"
        if not provenance.is_file():
            continue
        fields = dict(line.split("=", 1) for line in provenance.read_text().splitlines()
                      if line.startswith(("project=", "mode=")))
        project = fields["project"]
        if project not in {"coreutils", "diffutils", "findutils"} and not (build / "build-success.sha256").is_file():
            continue
        compatible = "runtime_target=musl-static-no-guest-nss-plugins" in provenance.read_text()
        if compatible:
            for name in ("compatible-static/musl-package-sha256.txt", "prepare_compatible_static.sh"):
                if f"{builder.sha256_file(ROOT / name)}  {ROOT / name}" not in provenance.read_text():
                    raise ValueError("compatible build runtime provenance changed")
        directories = {"coreutils": ("src",), "diffutils": ("src",),
                       "findutils": ("find", "xargs"), "util-linux": (".",),
                       "binutils": ("binutils", "gas", "ld", "gprof"),
                       "grep": ("src",), "sed": ("sed",), "gawk": (".",),
                       "gzip": (".",), "patch": ("src",), "bzip2": (".",),
                       "zip": (".",), "unzip": (".",), "git": (".",),
                       "libzstd": ("programs",), "openssl": ("apps",),
                       "inetutils": ("src", "ping", "ftp", "telnet", "whois", "talk"),
                       "procps": (".", "ps", "top", ".libs"), "psmisc": ("src",),
                       "curl": ("src",), "wget": ("src",), "rsync": (".",),
                       "jq": (".",), "less": (".",), "nano": ("src",), "tar": ("src",),
                       "xz-utils": ("src/xz",)}.get(project, ())
        hashes = set()
        for directory in directories:
            for path in sorted((build / directory).glob("*")):
                if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
                    continue
                if project == "binutils" and path.name not in {
                    "addr2line", "ar", "c++filt", "elfedit", "nm", "objcopy", "objdump",
                    "ranlib", "readelf", "size", "strings", "strip", "as-new", "ld-new", "gprof",
                    "nm-new", "strip-new", "cxxfilt",
                }:
                    continue
                if project in {"grep", "sed", "gawk", "gzip", "patch", "curl", "wget", "rsync", "jq", "less", "nano", "tar"} and path.name != project:
                    continue
                program_names = {
                    "bzip2": {"bzip2", "bzip2recover"},
                    "zip": {"zip", "zipcloak", "zipnote", "zipsplit"},
                    "unzip": {"unzip", "funzip", "unzipsfx"},
                    "git": {"git", "git-shell", "git-daemon"}, "libzstd": {"zstd"}, "openssl": {"openssl"},
                    "xz-utils": {"xz"},
                    "inetutils": {"hostname", "dnsdomainname", "logger", "traceroute", "ping", "ping6", "ftp", "tftp", "telnet", "whois", "rcp", "rlogin", "rsh", "talk", "inetd"},
                    "procps": {"free", "pmap", "pgrep", "pidof", "pidwait", "pkill", "pscommand", "ps", "skill", "slabtop", "snice", "sysctl", "tload", "top", "uptime", "vmstat", "w", "watch"},
                    "psmisc": {"pstree", "fuser", "killall", "peekfd", "prtstat", "pslog"},
                }
                if project in program_names and path.name not in program_names[project]:
                    continue
                data = path.read_bytes()
                if data[:4] != b"\x7fELF" or struct.unpack_from("<H", data, 16)[0] not in (2, 3):
                    continue
                mode, little_endian = builder.inspect_elf(data, strict_linkage=True)
                if mode != f"native_x86_64_{fields['mode']}" or not little_endian:
                    raise ValueError(f"build mode and ELF disagree: {path}")
                digest = builder.sha256_bytes(data)
                if digest in hashes:
                    continue
                hashes.add(digest)
                records.append({"project": project, "mode": fields["mode"],
                                "compatible_static_runtime": compatible,
                                "path": str(path.relative_to(ROOT)), "sha256": digest,
                                "build_provenance_sha256": builder.sha256_file(provenance)})
    return records


def check_elf_regression(builder):
    def fixture(program_types):
        data = bytearray(64 + 56 * len(program_types))
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, 62)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, len(program_types))
        for index, program_type in enumerate(program_types):
            struct.pack_into("<I", data, 64 + 56 * index, program_type)
        return bytes(data)
    assert builder.inspect_elf(fixture([1]), strict_linkage=True)[0] == "native_x86_64_static"
    assert builder.inspect_elf(fixture([1, 2, 3]), strict_linkage=True)[0] == "native_x86_64_dynamic"
    assert builder.inspect_elf(fixture([1, 2]), strict_linkage=True)[0] == "unsupported"
    assert builder.inspect_elf(fixture([1, 2]))[0] == "native_x86_64_dynamic"


def main():
    builder = load_builder()
    check_elf_regression(builder)
    selection = json.loads((ROOT / "manifests/malware-selection.json").read_text())
    plan = json.loads((ROOT / "benign-project-plan.json").read_text())
    source_groups = {}
    sample_hashes = set()
    archive_records = []
    for split, count in (("training", 70), ("validation", 30)):
        records = selection[f"malware_{split}"]
        assert len(records) == count
        assert Counter(record["execution_mode"] for record in records) == Counter(selection["mode_counts"][split])
        source_groups[split] = set()
        for mode, allocations in plan[split].items():
            assert sum(allocations.values()) == selection["mode_counts"][split][f"native_x86_64_{mode}"]
            assert all(0 < total <= plan["maximum_executables_per_project"] for total in allocations.values())
            source_groups[split].update(allocations)
        for record in records:
            assert record["sha256"] not in sample_hashes
            sample_hashes.add(record["sha256"])
            archive = STUDY / record["source_archive_path"]
            assert builder.sha256_file(archive) == record["source_archive_sha256"]
            observed = builder.inspect_archive(record["sample"], record, archive, strict_linkage=True)
            assert observed["member_sha256"] == record["member_sha256"]
            assert observed["execution_mode"] == record["execution_mode"]
            archive_records.append({"sample": record["sample"], "split": split,
                                    "source_archive_path": record["source_archive_path"],
                                    "source_archive_sha256": record["source_archive_sha256"]})
    assert not source_groups["training"] & source_groups["validation"]
    assert not set(selection["training_signature_groups"]) & set(selection["validation_signature_groups"])
    projects = source_groups["training"] | source_groups["validation"]
    releases, sources = audit_sources(builder, projects)
    compatible_runtime = audit_compatible_runtime(builder)
    binaries = audit_builds(builder)
    coverage = []
    for split in ("training", "validation"):
        for mode, allocations in plan[split].items():
            for project, required in allocations.items():
                available = sum(record["project"] == project and record["mode"] == mode for record in binaries)
                coverage.append({"split": split, "mode": mode, "project": project,
                                 "required": required, "verified_build_candidates": available,
                                 "build_shortfall": max(0, required - available)})
    report = {
        "status": "preparation_audit_passed_collection_not_ready",
        "collection_ready": False,
        "malware_unique_samples": len(sample_hashes),
        "malware_groups": {split: len(selection[f"{split}_signature_groups"]) for split in source_groups},
        "benign_projects": {split: len(groups) for split, groups in source_groups.items()},
        "authenticated_releases": releases,
        "authenticated_sources": sources,
        "compatible_static_runtime": compatible_runtime,
        "malware_archives": archive_records,
        "verified_build_candidates": binaries,
        "build_coverage": coverage,
        "unfilled_allocated_builds": sum(row["build_shortfall"] for row in coverage),
        "build_allocations_complete": all(row["build_shortfall"] == 0 for row in coverage),
        "pending_gates": (["complete all allocated distinct executable builds"]
                  if any(row["build_shortfall"] for row in coverage) else []) + [
                  "freeze safe noninteractive workloads and fixtures; check guest dependencies and activation",
                          "freeze preregistration, nuisance controls, and balanced interleaved order",
                          "reverify runner hashes, isolation, snapshot and no competing collectors before staging"],
        "code_hashes": {path.name: builder.sha256_file(path) for path in
                        (Path(__file__), ROOT.parent / "prepare_selection.py", ROOT / "prepare_benign_source.sh",
                         ROOT / "prepare_build_tools.sh", ROOT / "build-tool-env.sh",
                         ROOT / "prepare_compatible_static.sh",
                         ROOT / "benign-project-plan.json", ROOT / "ubuntu-sources.list")},
    }
    (ROOT / "preparation-audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("status", "collection_ready", "malware_unique_samples", "malware_groups",
                       "benign_projects", "unfilled_allocated_builds")}, indent=2))
    print("Authenticated source projects:", len(sources))
    print("Distinct build outputs by mode:", dict(Counter(record["mode"] for record in binaries)))


if __name__ == "__main__":
    main()