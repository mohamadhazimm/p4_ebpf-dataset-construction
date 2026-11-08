#!/usr/bin/env python3
"""Build missing benign control candidates locally; never operate a guest."""

import argparse
import json
import os
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from prepare_matched45 import EXPANSION, NATIVE, ROOT, STUDY, digest
from audit_original_cohorts import elf_header


TOOLCHAIN = EXPANSION / "i386-toolchain-probe/20261021T153000Z"
SYSROOT = TOOLCHAIN / "i386-controls-20261021T161011Z/sysroot"
sys.path.insert(0, str(TOOLCHAIN))
sys.path.insert(0, str(EXPANSION))
sys.path.insert(0, str(NATIVE))
import audit_redesign
import audit_toolchain_packages
import build_i386_controls
import prepare_inventory


RECIPES = {
    "coreutils": {"mode": "native_amd64_dynamic", "programs": {
        "chgrp": "src/chgrp", "chown": "src/chown", "ginstall": "src/ginstall",
        "nice": "src/nice", "nohup": "src/nohup"},
        "configure": ["--disable-nls", "--disable-dependency-tracking", "--without-gmp",
                      "--without-libcap", "--without-libacl", "--without-selinux"]},
    "less": {"mode": "native_amd64_static", "programs": {"lesskey": "lesskey", "lessecho": "lessecho"},
             "configure": []},
    "xz-utils": {"mode": "native_i386_static", "programs": {
        "xzdec": "src/xzdec/xzdec", "lzmadec": "src/xzdec/lzmadec", "lzmainfo": "src/lzmainfo/lzmainfo"},
        "configure": ["--host=i686-linux-gnu", "--disable-shared", "--enable-static", "--disable-nls"]},
    "net-tools": {"mode": "native_i386_static", "programs": {"ipmaddr": "ipmaddr", "iptunnel": "iptunnel"}},
    "sqlite3": {"mode": "native_amd64_static", "programs": {"lemon": "lemon"}},
}


def check_artifact(path, expected_mode):
    if path.is_symlink():
        raise ValueError("Do not credit program aliases")
    with path.open("rb") as stream:
        observed = elf_header(stream.read(1048576))
    if observed["mode"] != expected_mode:
        raise ValueError("Built program has incorrect actual linkage: " + str(path))
    return {"path": str(path.relative_to(STUDY)), "sha256": digest(path), "mode": expected_mode,
            "elf_header": observed, "size": path.stat().st_size}


def build():
    builder = prepare_inventory.load_builder()
    audit = json.loads((NATIVE / "preparation-audit.json").read_text())
    old_auth = EXPANSION / "i386-heldout-amendment/20261021T201119747468Z/source-authentication.json"
    sources = audit["authenticated_sources"] + json.loads(old_auth.read_text())["authenticated_sources"]
    records = {row["project"]: row for row in sources if row["project"] in RECIPES}
    directories = {project: (NATIVE / row["descriptor"]).parent for project, row in records.items()}
    releases, authenticated = audit_redesign.audit_sources(builder, set(RECIPES), directories)
    packages = audit_toolchain_packages.authenticate_packages()
    output = ROOT / "matched45-builds" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    artifacts = []
    authentication = {"signed_releases": releases, "authenticated_sources": authenticated,
        "authenticated_i386_toolchain": packages,
        "auditor_sha256": digest(Path(audit_redesign.__file__)),
        "toolchain_auditor_sha256": digest(Path(audit_toolchain_packages.__file__))}
    (output / "source-authentication.json").write_text(json.dumps(authentication, indent=2, sort_keys=True) + "\n")

    def run(command, cwd, env, log, input_text=None):
        commands.append(command)
        with (output / log).open("x") as stream:
            result = subprocess.run(command, cwd=cwd, env=env, input=input_text, text=True,
                                    stdout=stream, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise RuntimeError("Benign build failed; preserve " + str(output / log))

    try:
        for project, recipe in RECIPES.items():
            record = next(row for row in authenticated if row["project"] == project)
            upstream = [entry for entry in record["files"] if ".orig.tar." in entry["path"] and not entry["path"].endswith(".asc")]
            if len(upstream) != 1:
                raise ValueError("Expected a single authenticated upstream source archive")
            source_parent = output / project
            source_parent.mkdir()
            with tarfile.open(NATIVE / upstream[0]["path"], "r:*") as archive:
                archive.extractall(source_parent, filter="data")
            roots = list(source_parent.iterdir())
            if len(roots) != 1 or not roots[0].is_dir():
                raise ValueError("Unexpected source layout")
            source = roots[0]
            env = os.environ.copy()
            env.update({"LC_ALL": "C", "CC": "gcc", "CFLAGS": "-O2", "CPPFLAGS": "", "LDFLAGS": ""})
            if project == "less":
                tool_root = NATIVE / "build-tools/root/usr"
                env["C_INCLUDE_PATH"] = str(tool_root / "include") + ":" + str(tool_root / "include/x86_64-linux-gnu")
                env["LIBRARY_PATH"] = str(tool_root / "lib/x86_64-linux-gnu")
                env["LD_LIBRARY_PATH"] = env["LIBRARY_PATH"]
            if recipe["mode"] == "native_i386_static":
                env.update(build_i386_controls.toolchain_environment(SYSROOT))
                for name in ("C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "PKG_CONFIG_PATH"):
                    env.pop(name, None)
            print("Building benign " + project + " " + recipe["mode"], flush=True)
            flags = "-static" if recipe["mode"] == "native_amd64_static" else env["LDFLAGS"]
            if project == "xz-utils":
                flags = flags.replace("-static", "-all-static", 1)
            targets = list(recipe["programs"].values()) if project == "less" else []
            if project == "sqlite3":
                run(["gcc", "-O2", "-static", "-o", "lemon", "tool/lemon.c"], source, env, project + "-make.log")
            elif project == "net-tools":
                run(["make", "config"], source, env, project + "-configure.log", "\n" * 200)
                includes = " ".join("-I" + str(source / part) for part in (".", "include", "lib"))
                run(["make", "-j2", "CC=" + env["CC"], "CFLAGS=" + env["CFLAGS"],
                     "CPPFLAGS=" + env["CPPFLAGS"] + " " + includes,
                     "LDFLAGS=" + flags + " -L" + str(source / "lib"), *recipe["programs"].values()],
                    source, env, project + "-make.log")
            else:
                run(["./configure", *recipe["configure"]], source, env, project + "-configure.log")
                run(["make", "-j2", "MAKEINFO=true", "LDFLAGS=" + flags, *targets], source, env, project + "-make.log")
            for program, relative in recipe["programs"].items():
                artifacts.append({"project": project, "program": program,
                    **check_artifact(source / relative, recipe["mode"]),
                    "source_descriptor_sha256": record["descriptor_sha256"],
                    "source_variant": "authenticated_upstream_archive_no_distribution_patches",
                    "workload_status": "pending_substantive_host_and_guest_checks"})
        report = {"status": "accepted_build_only", "collection_ready": False, "sample_executions": 0,
            "vm_operations": 0, "artifacts": artifacts, "commands": commands,
            "source_authentication_sha256": digest(output / "source-authentication.json"),
            "builder_sha256": digest(Path(__file__)),
            "logs": {path.name: digest(path) for path in output.glob("*.log")}}
        (output / "build.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"attempt": str(output), "status": report["status"], "artifacts": len(artifacts), "collection_ready": False}, indent=2))
    except Exception as error:
        (output / "failure.json").write_text(json.dumps({"error": str(error), "commands": commands}, indent=2) + "\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-benign-controls", action="store_true")
    args = parser.parse_args()
    if args.build_benign_controls:
        build()
    else:
        assert sum(len(recipe["programs"]) for recipe in RECIPES.values()) == 13
        assert len({name for recipe in RECIPES.values() for name in recipe["programs"]}) == 13
        print("PASS: thirteen distinct planned benign build targets; no build or workload executed")


if __name__ == "__main__":
    main()