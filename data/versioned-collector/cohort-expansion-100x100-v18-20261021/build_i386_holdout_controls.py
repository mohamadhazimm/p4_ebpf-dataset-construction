#!/usr/bin/env python3
"""Authenticate and build additional benign held-out project sources only."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import prepare_inventory
import prepare_i386_holdout


ROOT = Path(__file__).resolve().parent
STUDY = prepare_inventory.STUDY
REDESIGN = prepare_inventory.PREPARATION
TOOLCHAIN = ROOT / "i386-toolchain-probe/20261021T153000Z"
sys.path.insert(0, str(REDESIGN))
sys.path.insert(0, str(TOOLCHAIN))
import audit_redesign
import audit_toolchain_packages


def authenticate(attempt):
    allocation_path = attempt / "allocation.json"
    allocation = json.loads(allocation_path.read_text())
    projects = set(allocation["benign_validation_project_slots"])
    if projects != set(prepare_i386_holdout.VALIDATION_PROJECT_SLOTS):
        raise ValueError("project allocation changed")
    output = attempt / "source-authentication.json"
    if output.exists():
        raise FileExistsError("preserve accepted source authentication")
    source_root = REDESIGN / "benign-sources-i386-holdout" / attempt.name
    source_root.mkdir(parents=True, exist_ok=False)
    directories = {}
    apt_options = ["-o", "Dir::Etc::main=-", "-o", "Dir::Etc::parts=-",
                   "-o", "Dir::Etc::sourcelist=" + str(REDESIGN / "ubuntu-sources.list"),
                   "-o", "Dir::Etc::sourceparts=-", "-o", "Dir::State::lists=" + str(REDESIGN / "apt-lists"),
                   "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
                   "-o", "Debug::NoLocking=true"]
    logs = attempt / "logs"
    logs.mkdir(exist_ok=True)
    for project in sorted(projects):
        if project == "ncurses":
            directory = REDESIGN / "compatible-static/ncurses-archives"
        else:
            directory = source_root / project
            directory.mkdir()
            print("Fetching benign source: " + project, flush=True)
            with (logs / (project + "-download.log")).open("w") as log:
                subprocess.run(["apt-get", *apt_options, "source", "--only-source", "--download-only", project],
                               cwd=directory, stdout=log, stderr=subprocess.STDOUT, check=True)
        directories[project] = directory
    builder = prepare_inventory.load_builder()
    releases, sources = audit_redesign.audit_sources(builder, projects, directories)
    packages = audit_toolchain_packages.authenticate_packages()
    result = {"status": "accepted_signed_sources_and_toolchain", "source_projects": len(sources),
              "allocation_sha256": prepare_i386_holdout.digest(allocation_path),
              "source_directories": {name: str(path.relative_to(STUDY)) for name, path in directories.items()},
              "signed_releases": releases, "authenticated_sources": sources,
              "authenticated_toolchain": packages, "collection_ready": False,
              "malware_executions": 0,
              "script_hashes": {str(path.relative_to(STUDY)): prepare_i386_holdout.digest(path) for path in (
                  Path(__file__), Path(audit_redesign.__file__), Path(audit_toolchain_packages.__file__),
              )}}
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "projects": len(sources), "output": str(output)}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    parser.add_argument("--fetch-sources", action="store_true", required=True)
    args = parser.parse_args()
    attempt = args.attempt.resolve()
    if attempt.parent != ROOT / "i386-heldout-amendment":
        raise ValueError("expected a direct child of the amendment root")
    authenticate(attempt)


if __name__ == "__main__":
    main()