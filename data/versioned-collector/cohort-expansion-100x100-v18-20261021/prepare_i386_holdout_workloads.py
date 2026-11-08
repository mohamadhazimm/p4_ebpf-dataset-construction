#!/usr/bin/env python3
"""Identify and substantively preflight the 30 held-out static i386 controls."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import build_i386_holdout_project as builds
import prepare_i386_holdout as allocation


ROOT = allocation.ROOT
STUDY = allocation.STUDY
TERM = "hazim-expansion-i386"
ARGUMENTS = {
    "mke2fs": ["-q", "-t", "ext2", "-F", "created.img", "8192"],
    "tune2fs": ["-l", "filesystem.img"],
    "dumpe2fs": ["-h", "filesystem.img"],
    "e2image": ["-r", "filesystem.img", "metadata.img"],
    "e2freefrag": ["filesystem.img"],
    "filefrag": ["fixture.txt"],
    "lsattr": ["fixture.txt"],
    "chattr": ["+d", "fixture.txt"],
    "debugfs": ["-R", "stats", "filesystem.img"],
    "e2fsck": ["-f", "-n", "filesystem.img"],
    "tic": ["-o", "compiled-terminfo", "terminal.src"],
    "toe": ["terminfo"],
    "infocmp": ["-A", "terminfo", TERM],
    "tput": ["-T", TERM, "cols"],
    "clear": ["-T", TERM],
    "arp": ["-n"],
    "hostname": ["-s"],
    "ifconfig": ["-a"],
    "netstat": ["-an"],
    "route": ["-n"],
    "bc": ["calculation.bc"],
    "dc": ["calculation.dc"],
    "ed": ["fixture.txt"],
    "m4": ["macro.m4"],
    "cpio": ["-it", "-F", "fixture.tar"],
    "shar": ["-o", "packed.sh", "fixture.txt"],
    "unshar": ["-f", "-d", "extracted", "fixture.sh.01"],
    "make": ["-f", "workload.mk"],
    "file": ["-m", "magic.txt", "fixture.txt"],
    "sqlite3": ["workload.db", "CREATE TABLE t(x); INSERT INTO t VALUES(7),(11),(13); SELECT sum(x) FROM t;"],
}


def check_result(case, completed, work, manifest, root):
    program = case["program"]
    stdout = completed.stdout
    if completed.returncode != 0:
        raise ValueError("workload returned " + str(completed.returncode))
    required = {"tune2fs": "Filesystem UUID:", "dumpe2fs": "Filesystem UUID:",
                "e2freefrag": "Blocksize:", "filefrag": "fixture.txt:",
                "debugfs": "Block size:", "e2fsck": "files",
                "toe": TERM, "infocmp": TERM, "arp": "Address",
                "ifconfig": "lo", "netstat": "Active", "route": "Kernel IP routing table",
                "cpio": "fixture.txt", "file": "HAZIM_fixture"}
    if program in required and required[program] not in stdout:
        raise ValueError("expected semantic output missing: " + required[program])
    exact = {"tput": "80\n", "bc": "31\n", "dc": "31\n", "m4": "value=31\n",
             "sqlite3": "31\n", "ed": str(len((work / "fixture.txt").read_bytes())) + "\n"}
    if program in exact and stdout != exact[program]:
        raise ValueError("semantic output differs: " + repr(stdout))
    if program == "hostname" and not re.fullmatch(r"[A-Za-z0-9_.-]+\n", stdout):
        raise ValueError("hostname output invalid")
    if program == "clear" and "\x1b[H\x1b[2J" not in stdout:
        raise ValueError("clear did not emit fixture clear-screen sequence")
    if program in {"mke2fs", "e2image"}:
        image = work / ("created.img" if program == "mke2fs" else "metadata.img")
        with image.open("rb") as stream:
            stream.seek(1080)
            if stream.read(2) != b"\x53\xef":
                raise ValueError("output lacks ext2 superblock magic")
    if program == "tic":
        if not any(path.is_file() for path in (work / "compiled-terminfo").rglob(TERM)):
            raise ValueError("tic did not compile the terminal fixture")
    if program in {"lsattr", "chattr"}:
        observed = completed
        if program == "chattr":
            helper = next(row for row in manifest["cases"] if row["program"] == "lsattr")
            observed = subprocess.run([str(root / helper["payload_path"]), "fixture.txt"], cwd=work,
                                      stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                      timeout=10, check=True)
        flags, name = observed.stdout.split()
        if name != "fixture.txt" or (program == "chattr" and "d" not in flags):
            raise ValueError("file attribute output differs")
    if program == "shar":
        if not (work / "packed.sh.01").is_file() or "fixture.txt" not in (work / "packed.sh.01").read_text():
            raise ValueError("shar archive missing fixture")
    if program == "unshar" and (work / "extracted/fixture.txt").read_bytes() != (work / "fixture.txt").read_bytes():
        raise ValueError("unshar content differs")
    if program == "make" and (work / "make-output.txt").read_text() != "built\n":
        raise ValueError("make did not build the fixture target")
    if program == "sqlite3" and not (work / "workload.db").read_bytes().startswith(b"SQLite format 3\0"):
        raise ValueError("SQLite database output invalid")


def run_cases(root, manifest):
    root = Path(root).resolve()
    fixtures = root / "fixtures"
    for name, expected in manifest["fixtures"].items():
        if allocation.digest(fixtures / name) != expected:
            raise ValueError("fixture changed: " + name)
    results = []
    workspaces = root / "workspaces"
    workspaces.mkdir(exist_ok=True)
    for case in manifest["cases"]:
        result = {"case_id": case["case_id"], "sha256": case["sha256"], "status": "not_accepted"}
        try:
            binary = root / case["payload_path"]
            if allocation.digest(binary) != case["sha256"]:
                raise ValueError("binary changed")
            with tempfile.TemporaryDirectory(prefix=case["program"] + "-", dir=workspaces) as temporary:
                work = Path(temporary)
                shutil.copytree(fixtures, work, dirs_exist_ok=True)
                (work / "extracted").mkdir()
                environment = os.environ.copy()
                environment.update(LC_ALL="C", TERMINFO=str(work / "terminfo"))
                completed = subprocess.run([str(binary), *case["arguments"]], cwd=work,
                                           stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                           timeout=20, env=environment, check=False)
                result.update(returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
                check_result(case, completed, work, manifest, root)
                result["status"] = "accepted"
        except Exception as error:
            result["error"] = type(error).__name__ + ": " + str(error)
        results.append(result)
        print(json.dumps(result), flush=True)
    accepted = sum(row["status"] == "accepted" for row in results)
    return {"status": "accepted" if accepted == 30 and len(results) == 30 else "not_accepted",
            "accepted": accepted, "total": len(results), "cases": results,
            "collection_ready": False, "malware_executions": 0,
            "limitations": ["Benign workload checks only; no sensor or malware certification.",
                            "Terminal fixture must be staged identically for both labels before collection."]}


def prepare(attempt):
    plan = json.loads((attempt / "allocation.json").read_text())
    old = json.loads((allocation.prepare_inventory.PREPARATION / "manifests/benign-executables.json").read_text())["executables"]
    prior_programs = {(row["project"], row["program"]) for row in old}
    prior_hashes = {row["sha256"] for row in old}
    rows = []
    reports = []
    for project, count in allocation.VALIDATION_PROJECT_SLOTS.items():
        candidates = sorted((attempt / "project-builds" / project).glob("*/build.json"))
        if not candidates:
            raise ValueError("no accepted build: " + project)
        path = candidates[-1]
        report = json.loads(path.read_text())
        if report["status"] != "accepted_static_i386_build_only" or len(report["artifacts"]) != count:
            raise ValueError("build quota differs: " + project)
        reports.append(path)
        for artifact in report["artifacts"]:
            source = STUDY / artifact["path"]
            observed = builds.original_build.validate_elf(source)
            if observed["sha256"] != artifact["sha256"] or artifact["sha256"] in prior_hashes:
                raise ValueError("changed or previous binary")
            if (project, artifact["program"]) in prior_programs:
                raise ValueError("previous program reused")
            case_id = "i386-" + project + "-" + artifact["program"]
            rows.append({**artifact, "case_id": case_id, "machine": 3, "source": artifact["path"],
                         "arguments": ARGUMENTS[artifact["program"]],
                         "payload_path": "binaries/" + case_id + "/" + artifact["program"]})
    if len(rows) != 30 or len({row["sha256"] for row in rows + plan["benign_training"]}) != 100:
        raise ValueError("expected 100 unique benign hashes")
    if {row["project"] for row in rows} & {row["project"] for row in plan["benign_training"]}:
        raise ValueError("benign project leakage")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = attempt / "workload-preflight" / run_id
    output.mkdir(parents=True, exist_ok=False)
    fixtures = output / "fixtures"
    fixtures.mkdir()
    for case in rows:
        destination = output / case["payload_path"]
        destination.parent.mkdir(parents=True)
        shutil.copy2(STUDY / case["source"], destination)
    contents = {"fixture.txt": "HAZIM fixture content\n", "calculation.bc": "7+11+13\nquit\n",
                "calculation.dc": "7 11 + 13 + p\n", "macro.m4": "define(`value', `31')`value'=value\n",
                "magic.txt": "0 string HAZIM HAZIM_fixture\n",
                "workload.mk": "all:\n\t@printf 'built\\n' > make-output.txt\n",
                "terminal.src": TERM + "|Hazim fixture,\n\tcols#80, lines#24, clear=\\E[H\\E[2J,\n"}
    for name, content in contents.items():
        (fixtures / name).write_text(content)
    with tarfile.open(fixtures / "fixture.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
        data = contents["fixture.txt"].encode()
        entry = tarfile.TarInfo("fixture.txt")
        entry.size, entry.mode = len(data), 0o644
        archive.addfile(entry, io.BytesIO(data))
    binaries = {row["program"]: output / row["payload_path"] for row in rows}
    commands = [[str(binaries["mke2fs"]), "-q", "-t", "ext2", "-F", "filesystem.img", "8192"],
                [str(binaries["tic"]), "-o", "terminfo", "terminal.src"],
                [str(binaries["shar"]), "-o", "fixture.sh", "fixture.txt"]]
    for index, command in enumerate(commands):
        result = subprocess.run(command, cwd=fixtures, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=20, env={**os.environ, "LC_ALL": "C"}, check=False)
        (output / ("fixture-" + str(index) + ".log")).write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise ValueError("benign fixture generation failed: " + str(command))
    manifest = {"cases": rows, "fixtures": {str(path.relative_to(fixtures)): allocation.digest(path)
                                              for path in sorted(fixtures.rglob("*")) if path.is_file()},
                "allocation_sha256": allocation.digest(attempt / "allocation.json"),
                "build_reports": {str(path.relative_to(STUDY)): allocation.digest(path) for path in reports},
                "checker_sha256": allocation.digest(Path(__file__)), "fixture_commands": commands,
                "collection_ready": False, "malware_executions": 0}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    report = run_cases(output, manifest)
    (output / "host_preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(output), "status": report["status"], "accepted": report["accepted"]}), flush=True)
    if report["status"] != "accepted":
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    args = parser.parse_args()
    attempt = args.attempt.resolve()
    if attempt.parent != ROOT / "i386-heldout-amendment":
        raise ValueError("invalid amendment attempt")
    prepare(attempt)


if __name__ == "__main__":
    main()