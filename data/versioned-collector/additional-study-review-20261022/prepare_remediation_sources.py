#!/usr/bin/env python3
"""Acquire four authenticated benign sources without VM or workload operations."""

import argparse
import hashlib
import importlib.util
import json
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import cmp_to_key
from pathlib import Path
from urllib.request import urlopen

import apt_pkg


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
NATIVE = STUDY / "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64"
FEASIBILITY = ROOT / "remediation-feasibility/20261022T121416376772Z"
PROJECTS = {"libarchive", "perl", "imagemagick", "netcat-openbsd"}
ORIGIN = "https://archive.ubuntu.com/ubuntu/"
DEPENDENCIES = {"libbsd-dev", "libbsd0", "libmd-dev", "libmd0", "clang-14", "libllvm14", "libclang-cpp14", "libclang1-14", "libelf-dev", "libelf1"}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else stream_digest(source)


def stream_digest(source):
    result = hashlib.sha256()
    for block in iter(lambda: source.read(1024 * 1024), b""):
        result.update(block)
    return result.hexdigest()


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def auditor():
    specification = importlib.util.spec_from_file_location("remediation_source_audit", NATIVE / "audit_redesign.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def safe_name(name):
    if not name or Path(name).name != name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError("Unsafe source filename")
    return name


def select_sources(proposals):
    selected = []
    for project in sorted(PROJECTS):
        matches = [row for row in proposals if row["project"] == project]
        if len(matches) != 1:
            raise ValueError("Missing or duplicate proposed project: " + project)
        records = matches[0]["signed_index_records"]
        ordered = sorted(records, key=cmp_to_key(lambda left, right: apt_pkg.version_compare(left["source_version"], right["source_version"])))
        newest = ordered[-1]
        peers = [row for row in records if row["source_version"] == newest["source_version"]]
        if any(row["checksums"] != newest["checksums"] for row in peers):
            raise ValueError("Conflicting signed records for the same version")
        for name in newest["checksums"]:
            safe_name(name)
        directory = Path(newest["directory"])
        if directory.is_absolute() or ".." in directory.parts or directory.parts[0] != "pool":
            raise ValueError("Unsafe repository directory")
        selected.append({"project": project, **newest})
    return selected


def verify_file(path, expected):
    expected_hash, expected_size = expected
    if not path.is_file() or path.is_symlink() or path.stat().st_size != expected_size or digest(path) != expected_hash:
        raise ValueError("Source hash or size mismatch: " + str(path))


def download(url, path, expected):
    with urlopen(url, timeout=60) as response, path.open("xb") as output:
        if not response.geturl().startswith("https://"):
            raise ValueError("Download redirected away from HTTPS")
        total = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > expected[1]:
                raise ValueError("Download exceeds signed size")
            output.write(block)
    verify_file(path, expected)


def dependencies(attempt):
    apt_pkg.init_system()
    helper = auditor()
    protocol = json.loads((attempt / "protocol.json").read_text())
    for name, expected in protocol["input_hashes"].items():
        if digest(Path(name)) != expected:
            raise ValueError("Authentication inputs changed")
    selected = {}
    evidence = {}
    for release in sorted((NATIVE / "apt-lists").glob("*InRelease")):
        subprocess.run(["gpgv", "--keyring", helper.KEYRING, str(release)], check=True, capture_output=True)
        checksums = helper.checksum_rows(helper.read_descriptor(release)["SHA256"])
        prefix = release.name.removesuffix("_InRelease")
        for component in ("main", "universe"):
            indexes = list(release.parent.glob(f"{prefix}_{component}_binary-amd64_Packages*"))
            if len(indexes) != 1:
                raise ValueError("Missing or ambiguous binary index")
            index = indexes[0]
            with tempfile.TemporaryFile() as unpacked:
                subprocess.run(["/usr/lib/apt/apt-helper", "cat-file", str(index)], stdout=unpacked, check=True)
                size = unpacked.tell()
                unpacked.seek(0)
                observed = stream_digest(unpacked)
                if (observed, size) != checksums[f"{component}/binary-amd64/Packages"]:
                    raise ValueError("Binary index not authenticated")
                unpacked.seek(0)
                for section in apt_pkg.TagFile(unpacked):
                    package = section["Package"]
                    if package not in DEPENDENCIES or section["Architecture"] not in {"amd64", "all"}:
                        continue
                    row = {field: section[field] for field in ("Package", "Version", "Architecture", "Filename", "Size", "SHA256")}
                    previous = selected.get(package)
                    if previous and row["Version"] == previous["Version"] and row != previous:
                        raise ValueError("Conflicting dependency records")
                    if previous is None or apt_pkg.version_compare(row["Version"], previous["Version"]) > 0:
                        selected[package] = row
            evidence[str(index)] = digest(index)
    if set(selected) != DEPENDENCIES:
        raise ValueError("Missing authenticated dependencies: " + str(DEPENDENCIES - set(selected)))
    target = attempt / "dependencies"
    target.mkdir(exist_ok=False)
    save(target / "protocol.json", {"packages": selected, "index_hashes": evidence, "driver_sha256": digest(Path(__file__)), "system_installation": False})
    packages = target / "packages"
    packages.mkdir()
    install = target / "root"
    install.mkdir()
    for package, row in sorted(selected.items()):
        repository_path = Path(row["Filename"])
        if repository_path.is_absolute() or ".." in repository_path.parts or repository_path.parts[0] != "pool":
            raise ValueError("Unsafe binary package path")
        path = packages / safe_name(repository_path.name)
        download(ORIGIN + str(repository_path), path, (row["SHA256"], int(row["Size"])))
        subprocess.run(["dpkg-deb", "-x", str(path), str(install)], check=True)
        print("Extracted", package, row["Version"], flush=True)
    save(target / "authentication.json", {"status": "authenticated_and_extracted_without_installation", "packages": selected, "index_hashes": evidence, "extracted_files": {str(path.relative_to(install)): digest(path) for path in sorted(install.rglob("*")) if path.is_file() and not path.is_symlink()}, "maintainer_scripts_executed": False, "system_installation": False})


def authenticate_indexes(selected, helper):
    frozen = json.loads((FEASIBILITY / "input_hashes.json").read_text())
    for path in [NATIVE / "audit_redesign.py", FEASIBILITY / "source_task_proposals.json"]:
        expected = frozen.get(str(path))
        if path.name == "source_task_proposals.json":
            expected = json.loads((FEASIBILITY / "output_hashes.json").read_text())[path.name]
        if expected is None or digest(path) != expected:
            raise ValueError("Frozen source policy changed: " + str(path))
    evidence = {}
    for release in sorted((NATIVE / "apt-lists").glob("*InRelease")):
        subprocess.run(["gpgv", "--keyring", helper.KEYRING, str(release)], check=True, capture_output=True)
        checksums = helper.checksum_rows(helper.read_descriptor(release)["SHA256"])
        prefix = release.name.removesuffix("_InRelease")
        evidence[str(release)] = digest(release)
        for row in selected:
            index = Path(row["source_index"])
            if not index.name.startswith(prefix + "_"):
                continue
            relative = index.name[len(prefix) + 1:].replace("_source_Sources", "/source/Sources")
            verify_file(index, checksums[relative])
            evidence[str(index)] = digest(index)
            found = False
            with index.open("rb") as source:
                for section in apt_pkg.TagFile(source):
                    if section["Package"] == row["project"] and section["Version"] == row["source_version"]:
                        checks = {name: list(value) for name, value in helper.checksum_rows(section["Checksums-Sha256"]).items()}
                        if checks != row["checksums"] or section["Directory"] != row["directory"]:
                            raise ValueError("Proposal differs from signed source index")
                        found = True
            if not found:
                raise ValueError("Selected version absent from authenticated index")
    if not all(row["source_index"] in evidence for row in selected):
        raise ValueError("Not all selected indexes authenticated")
    evidence[str(NATIVE / "audit_redesign.py")] = digest(NATIVE / "audit_redesign.py")
    evidence[str(FEASIBILITY / "source_task_proposals.json")] = digest(FEASIBILITY / "source_task_proposals.json")
    evidence[helper.KEYRING] = digest(Path(helper.KEYRING))
    return evidence


def acquire():
    apt_pkg.init_system()
    helper = auditor()
    selected = select_sources(json.loads((FEASIBILITY / "source_task_proposals.json").read_text()))
    inputs = authenticate_indexes(selected, helper)
    attempt = ROOT / "remediation-preparation" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    save(attempt / "protocol.json", {"schema": "remediation-build-inputs-v1", "authorization": "four benign sources and builds only; no target workloads, VM, attachment or fit", "selection": selected, "origin": ORIGIN, "input_hashes": inputs, "driver_sha256": digest(Path(__file__)), "collection_ready": False})
    try:
        for row in selected:
            directory = attempt / "sources" / row["project"]
            directory.mkdir(parents=True)
            for name, expected in sorted(row["checksums"].items()):
                path = directory / safe_name(name)
                url = ORIGIN + row["directory"] + "/" + name
                download(url, path, expected)
            descriptors = list(directory.glob("*.dsc"))
            if len(descriptors) != 1:
                raise ValueError("Expected exactly one descriptor")
            fields = helper.read_descriptor(descriptors[0])
            if fields["Source"] != row["project"] or fields["Version"] != row["source_version"]:
                raise ValueError("Descriptor identity differs")
            for name, expected in helper.checksum_rows(fields["Checksums-Sha256"]).items():
                safe_name(name)
                if list(expected) != row["checksums"].get(name):
                    raise ValueError("Descriptor differs from authenticated index")
                verify_file(directory / name, expected)
        for name, expected in inputs.items():
            if digest(Path(name)) != expected:
                raise ValueError("Authentication input changed during acquisition")
        save(attempt / "source-authentication.json", {"status": "authenticated", "projects": selected, "files": {str(path.relative_to(attempt)): digest(path) for path in sorted((attempt / "sources").rglob("*")) if path.is_file()}, "metadata_freshness": "cached signed indexes, not current security certification", "collection_ready": False, "target_workload_executions": 0, "vm_operations": 0, "model_fits": 0})
    except Exception as error:
        save(attempt / "failure.json", {"error": str(error), "collection_ready": False})
        raise
    print(attempt)


def self_test():
    for name in ["../archive.tar", "/archive", "..", "", "folder\\archive"]:
        try:
            safe_name(name)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe filename accepted")
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "source"
        path.write_bytes(b"verified")
        expected = [digest(path), 8]
        verify_file(path, expected)
        path.write_bytes(b"tampered")
        try:
            verify_file(path, expected)
        except ValueError:
            pass
        else:
            raise AssertionError("Tampered bytes accepted")
    apt_pkg.init_system()
    selected = select_sources(json.loads((FEASIBILITY / "source_task_proposals.json").read_text()))
    assert {row["project"] for row in selected} == PROJECTS
    assert next(row for row in selected if row["project"] == "libarchive")["source_version"] == "3.6.0-1ubuntu1.9"
    print("PASS: four exact versions, unsafe paths and tampered source rejection; no acquisition")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--acquire", action="store_true")
    action.add_argument("--dependencies", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    elif options.dependencies:
        dependencies(options.dependencies.resolve())
    else:
        acquire()