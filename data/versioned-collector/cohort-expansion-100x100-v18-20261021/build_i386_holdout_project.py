#!/usr/bin/env python3
"""Build one authenticated held-out benign project as native static i386."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import prepare_inventory
import prepare_i386_holdout


ROOT = Path(__file__).resolve().parent
STUDY = prepare_inventory.STUDY
REDESIGN = prepare_inventory.PREPARATION
TOOLCHAIN = ROOT / "i386-toolchain-probe/20261021T153000Z"
SYSROOT = TOOLCHAIN / "i386-controls-20261021T161011Z/sysroot"
sys.path.insert(0, str(TOOLCHAIN))
import build_i386_controls as original_build


PROGRAMS = {
    "e2fsprogs": {name: path for name, path in (
        ("mke2fs", "misc/mke2fs"), ("tune2fs", "misc/tune2fs"),
        ("dumpe2fs", "misc/dumpe2fs"), ("e2image", "misc/e2image"),
        ("e2freefrag", "misc/e2freefrag"), ("filefrag", "misc/filefrag"),
        ("lsattr", "misc/lsattr"), ("chattr", "misc/chattr"),
        ("debugfs", "debugfs/debugfs"), ("e2fsck", "e2fsck/e2fsck"),
    )},
    "ncurses": {name: "progs/" + name for name in ("tic", "toe", "infocmp", "tput", "clear")},
    "net-tools": {name: name for name in ("arp", "hostname", "ifconfig", "netstat", "route")},
    "bc": {"bc": "bc/bc", "dc": "dc/dc"},
    "ed": {"ed": "ed"},
    "m4": {"m4": "src/m4"},
    "cpio": {"cpio": "src/cpio"},
    "sharutils": {"shar": "src/shar", "unshar": "src/unshar"},
    "make-dfsg": {"make": "make"},
    "file": {"file": "src/file"},
    "sqlite3": {"sqlite3": "sqlite3"},
}
OPTIONS = {
    "e2fsprogs": ["--enable-libuuid", "--enable-libblkid", "--disable-elf-shlibs",
                  "--disable-fuse2fs", "--disable-nls", "--disable-uuidd"],
    "ncurses": ["--without-shared", "--with-normal", "--without-debug", "--without-cxx",
                "--without-cxx-binding", "--without-ada", "--without-tests", "--without-manpages",
                "--disable-db-install"],
    "bc": ["--disable-nls", "--without-readline", "--without-libedit"],
    "ed": [],
    "m4": ["--disable-nls", "--without-libsigsegv"],
    "cpio": ["--disable-nls"],
    "sharutils": ["--disable-nls"],
    "make-dfsg": ["--disable-nls", "--without-guile"],
    "file": ["--disable-shared", "--enable-static", "--disable-libseccomp", "--disable-zlib",
             "--disable-bzlib", "--disable-xzlib", "--disable-zstdlib", "--disable-lzlib"],
    "sqlite3": ["--disable-shared", "--enable-static", "--disable-readline", "--disable-editline",
                "--disable-tcl"],
}


def build(attempt, project):
    authentication_path = attempt / "source-authentication.json"
    authentication = json.loads(authentication_path.read_text())
    if authentication["status"] != "accepted_signed_sources_and_toolchain":
        raise ValueError("source authentication not accepted")
    if prepare_i386_holdout.digest(attempt / "allocation.json") != authentication["allocation_sha256"]:
        raise ValueError("allocation changed")
    record = next(row for row in authentication["authenticated_sources"] if row["project"] == project)
    descriptor = REDESIGN / record["descriptor"]
    if prepare_i386_holdout.digest(descriptor) != record["descriptor_sha256"]:
        raise ValueError("descriptor changed")
    for entry in record["files"]:
        path = REDESIGN / entry["path"]
        if path.stat().st_size != entry["size"] or prepare_i386_holdout.digest(path) != entry["sha256"]:
            raise ValueError("source archive changed")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = attempt / "project-builds" / project / run_id
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    environment = original_build.toolchain_environment(SYSROOT)
    for key in ("C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "PKG_CONFIG_PATH"):
        environment.pop(key, None)
    environment["LC_ALL"] = "C"
    commands = []

    def run(command, log_name, stdin=None):
        commands.append(command)
        with (output / log_name).open("w") as log:
            result = subprocess.run(command, cwd=source if source.is_dir() else output,
                                    env=environment, input=stdin, text=True,
                                    stdout=log, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise RuntimeError(project + " failed: " + str(output / log_name))

    try:
        print("Building static i386 project: " + project, flush=True)
        run(["dpkg-source", "-x", str(descriptor), str(source)], "unpack.log")
        if project in {"bc", "file", "make-dfsg"}:
            run(["autoreconf", "-fi"], "autoreconf.log")
        if project == "net-tools":
            run(["make", "config"], "configure.log", "\n" * 200)
            command = ["make", "-j2", "CC=" + environment["CC"],
                       "CFLAGS=" + environment["CFLAGS"],
                       "CPPFLAGS=" + environment["CPPFLAGS"] + " " + " ".join(
                           "-I" + str(source / directory) for directory in (".", "include", "lib")),
                       "LDFLAGS=" + environment["LDFLAGS"] + " -L" + str(source / "lib"),
                       *PROGRAMS[project].values()]
        else:
            configure = ["./configure", *([] if project == "ed" else ["--host=i686-linux-gnu"]), *OPTIONS[project]]
            if project == "ed":
                configure.extend(key + "=" + environment[key] for key in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS"))
            run(configure, "configure.log")
            command = ["make", "-j2", "MAKEINFO=true"]
            if project in {"file", "sqlite3"}:
                command.append("LDFLAGS=" + environment["LDFLAGS"].replace("-static", "-all-static", 1))
            if project == "sqlite3":
                command.extend(["BCC=gcc", "LTLINK_EXTRAS=-all-static"])
        run(command, "make.log")
        artifacts = []
        for program, relative in PROGRAMS[project].items():
            path = source / relative
            if path.is_symlink():
                raise ValueError("program alias is not a distinct executable: " + program)
            observed = original_build.validate_elf(path)
            artifacts.append({"project": project, "program": program, "arch": "i386", "machine": 3,
                              "path": str(path.relative_to(STUDY)), "sha256": observed["sha256"],
                              "size": observed["size"], "elf_description": observed["description"],
                              "execution_mode": "native_i386_static", "workload_status": "pending"})
        if len({row["sha256"] for row in artifacts}) != len(artifacts):
            raise ValueError("program aliases have identical hashes")
        result = {"status": "accepted_static_i386_build_only", "project": project,
                  "artifacts": artifacts, "collection_ready": False, "guest_preflight": False,
                  "source_authentication_sha256": prepare_i386_holdout.digest(authentication_path),
                  "source_descriptor_sha256": record["descriptor_sha256"], "commands": commands,
                  "environment": {key: environment[key] for key in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "PKG_CONFIG_LIBDIR")},
                  "builder_sha256": prepare_i386_holdout.digest(Path(__file__)),
                  "logs": {path.name: prepare_i386_holdout.digest(path) for path in output.glob("*.log")}}
        (output / "build.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": result["status"], "project": project,
                          "programs": len(artifacts), "report": str(output / "build.json")}), flush=True)
    except Exception as error:
        (output / "failure.json").write_text(json.dumps({"status": "not_accepted", "error": str(error),
                                                        "commands": commands}, indent=2) + "\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    parser.add_argument("project", choices=sorted(PROGRAMS))
    args = parser.parse_args()
    attempt = args.attempt.resolve()
    if attempt.parent != ROOT / "i386-heldout-amendment":
        raise ValueError("invalid amendment attempt")
    build(attempt, args.project)


if __name__ == "__main__":
    main()