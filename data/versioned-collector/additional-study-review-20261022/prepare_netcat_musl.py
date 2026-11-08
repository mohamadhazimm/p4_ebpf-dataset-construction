#!/usr/bin/env python3
"""Authenticate isolated build dependencies for the static netcat repair."""

import argparse
import datetime
import json
import subprocess
from pathlib import Path

import apt_pkg

import prepare_remediation_sources as sources


ROOT = Path(__file__).resolve().parent
PROJECTS = {"libbsd", "libmd", "openssh"}


def acquire():
    apt_pkg.init_system()
    helper = sources.auditor()
    selected, inputs = {}, {}
    releases = sorted((sources.NATIVE / "apt-lists").glob("*InRelease"))
    if len(releases) != 3:
        raise ValueError("Expected three signed Release files")
    for release in releases:
        subprocess.run(["gpgv", "--keyring", helper.KEYRING, str(release)], check=True, capture_output=True)
        checksums = helper.checksum_rows(helper.read_descriptor(release)["SHA256"])
        inputs[str(release)] = sources.digest(release)
        prefix = release.name.removesuffix("_InRelease")
        for component in ("main", "universe"):
            index = release.parent / (prefix + "_" + component + "_source_Sources")
            sources.verify_file(index, checksums[component + "/source/Sources"])
            inputs[str(index)] = sources.digest(index)
            with index.open("rb") as source:
                for section in apt_pkg.TagFile(source):
                    project = section["Package"]
                    if project not in PROJECTS:
                        continue
                    row = {"project": project, "version": section["Version"], "directory": section["Directory"],
                           "checksums": helper.checksum_rows(section["Checksums-Sha256"])}
                    previous = selected.get(project)
                    if previous and row["version"] == previous["version"] and row != previous:
                        raise ValueError("Conflicting signed dependency records")
                    if previous is None or apt_pkg.version_compare(row["version"], previous["version"]) > 0:
                        selected[project] = row
    if set(selected) != PROJECTS:
        raise ValueError("Missing authenticated dependency source")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "netcat-musl-dependencies" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    inputs.update({str(Path(__file__)): sources.digest(Path(__file__)),
                   str(Path(sources.__file__)): sources.digest(Path(sources.__file__)),
                   str(Path(helper.__file__)): sources.digest(Path(helper.__file__)),
                   helper.KEYRING: sources.digest(Path(helper.KEYRING))})
    sources.save(attempt / "protocol.json", {"sources": selected, "input_hashes": inputs,
                 "scope": "Benign local netcat dependency preparation only; no system install, VM, workload or collection",
                 "collection_ready": False})
    try:
        for project, row in sorted(selected.items()):
            repository = Path(row["directory"])
            if repository.is_absolute() or ".." in repository.parts or repository.parts[0] != "pool":
                raise ValueError("Unsafe dependency repository path")
            directory = attempt / "sources" / project
            directory.mkdir(parents=True)
            for name, expected in sorted(row["checksums"].items()):
                sources.safe_name(name)
                sources.download(sources.ORIGIN + str(repository) + "/" + name, directory / name, expected)
            descriptors = list(directory.glob("*.dsc"))
            if len(descriptors) != 1:
                raise ValueError("Expected one dependency descriptor")
            fields = helper.read_descriptor(descriptors[0])
            if fields["Source"] != project or fields["Version"] != row["version"]:
                raise ValueError("Dependency descriptor identity differs")
            for name, expected in helper.checksum_rows(fields["Checksums-Sha256"]).items():
                if expected != row["checksums"].get(name):
                    raise ValueError("Descriptor differs from signed index")
                sources.verify_file(directory / sources.safe_name(name), expected)
            print("Authenticated", project, row["version"], flush=True)
        for name, expected in inputs.items():
            if sources.digest(Path(name)) != expected:
                raise ValueError("Dependency authentication input changed")
        sources.save(attempt / "authentication.json", {"status": "authenticated", "sources": selected,
                     "files": {str(path.relative_to(attempt)): sources.digest(path)
                               for path in sorted((attempt / "sources").rglob("*")) if path.is_file()},
                     "metadata_freshness": "Cached signed indexes, not current security certification",
                     "system_installation": False, "vm_operations": 0, "target_executions": 0})
    except Exception as error:
        sources.save(attempt / "failure.json", {"error": str(error), "collection_ready": False})
        raise
    finally:
        print(attempt, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquire-only", required=True, action="store_true")
    parser.parse_args()
    acquire()