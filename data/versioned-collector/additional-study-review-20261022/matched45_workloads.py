#!/usr/bin/env python3
"""Bounded benign-only workload definitions and portable outcome checks."""

import argparse
import base64
import hashlib
import json
import lzma
import os
import re
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile
from pathlib import Path


CONTENT = b"alpha\nbeta\nalpha\n"
ARGUMENTS = {
    "chgrp": ["--reference={F}/file.txt", "{F}/owner.txt"],
    "chown": ["--reference={F}/file.txt", "{F}/owner.txt"],
    "ginstall": ["-m", "0640", "{F}/file.txt", "installed.txt"],
    "nice": ["-n", "5", "/bin/cat", "{F}/file.txt"],
    "nohup": ["/bin/cat", "{F}/file.txt"],
    "dircolors": ["--bourne-shell", "{F}/colors.txt"],
    "env": ["--ignore-environment", "HAZIM_MATCHED45=ready", "/usr/bin/printenv", "HAZIM_MATCHED45"],
    "groups": [], "id": ["--user"],
    "mv": ["{F}/move.txt", "moved.txt"], "printf": ["%s\n", "matched45"],
    "rm": ["--verbose", "--", "{F}/remove.txt"], "rmdir": ["--verbose", "{F}/empty"],
    "shred": ["--iterations=1", "--zero", "--", "{F}/shred.bin"],
    "sum": ["{F}/file.txt"], "sync": ["--data", "{F}/file.txt"],
    "tee": ["tee-output.txt"], "test": ["-s", "{F}/file.txt"],
    "timeout": ["--signal=TERM", "2", "/bin/cat", "{F}/file.txt"],
    "users": ["{F}/session.utmp"], "who": ["{F}/session.utmp"],
    "echo": ["matched45"], "link": ["{F}/file.txt", "linked.txt"],
    "mkfifo": ["{F}/pipe"], "pwd": ["--physical"],
    "printenv": ["LC_ALL"], "unlink": ["{F}/unlink.txt"],
    "lesskey": ["-o", "keys.bin", "{F}/lesskey.txt"],
    "lessecho": ["-a", "-p0x22", "-d0x22", "alpha beta"],
    "lemon": ["-d.", "-T{F}/lempar.c", "{F}/parser.y"],
    "xzdec": ["{F}/fixture.xz"], "lzmadec": ["{F}/fixture.lzma"],
    "lzmainfo": ["{F}/fixture.lzma"], "ipmaddr": ["show", "lo"], "iptunnel": ["show"],
    "uuencode": ["-m", "{F}/file.txt", "result.txt"],
    "uudecode": ["--output=decoded.txt", "{F}/fixture.uue"],
    "badblocks": ["-b", "1024", "-c", "64", "{F}/blocks.img", "127"],
    "resize2fs": ["-f", "{F}/fs.img", "20M"], "mklost+found": [], "uuidgen": ["-r"],
    "e2undo": ["{F}/undo.e2undo", "{F}/fs.img"],
    "blkid": ["-c", "/dev/null", "-w", "/dev/null", "{F}/fs.img"],
    "logsave": ["log.txt", "/bin/echo", "matched45-log"],
    "e4defrag": ["-c", "{F}/extent.bin"],
}


def sha256(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def fixture_files(directory):
    return {str(path.relative_to(directory)): sha256(path)
            for path in sorted(directory.rglob("*")) if path.is_file()}


def make_fixtures(site, cases, helpers, lemon_template):
    helper_logs = []
    for case in cases:
        fixtures = site / "fixtures" / case["case_id"]
        fixtures.mkdir(parents=True, exist_ok=False)
        for name in ("file.txt", "owner.txt", "move.txt", "remove.txt", "unlink.txt"):
            (fixtures / name).write_bytes(CONTENT)
        (fixtures / "empty").mkdir()
        (fixtures / "shred.bin").write_bytes(b"disposable owned data\n" * 16)
        (fixtures / "colors.txt").write_text("TERM *\nDIR 01;34\nNORMAL 0\n")
        (fixtures / "lesskey.txt").write_text("#command\nq quit\n")
        (fixtures / "parser.y").write_text("%token_type {int}\nstart ::= NUMBER.\n")
        record = bytearray(384)
        struct.pack_into("<hi", record, 0, 7, 0)
        struct.pack_into("<i", record, 4, 1234)
        record[8:13] = b"pts/9"
        record[44:55] = b"fixtureuser"
        struct.pack_into("<i", record, 340, 1577836800)
        (fixtures / "session.utmp").write_bytes(record)
        (fixtures / "fixture.xz").write_bytes(lzma.compress(CONTENT))
        (fixtures / "fixture.lzma").write_bytes(lzma.compress(CONTENT, format=lzma.FORMAT_ALONE))
        (fixtures / "fixture.uue").write_bytes(b"begin-base64 644 result.txt\n" + base64.b64encode(CONTENT) + b"\n====\n")
        if case["program"] == "lemon":
            shutil.copyfile(lemon_template, fixtures / "lempar.c")
        if case["program"] == "badblocks":
            (fixtures / "blocks.img").write_bytes(bytes(128 * 1024))
        if case["program"] == "e4defrag":
            (fixtures / "extent.bin").write_bytes(b"x" * 131072)
        if case["program"] in {"resize2fs", "e2undo", "blkid"}:
            image = fixtures / "fs.img"
            with image.open("xb") as stream:
                stream.truncate(16 * 1024 * 1024)
            commands = [[helpers["mke2fs"], "-q", "-F", "-t", "ext2", "-L", "matched45-base", str(image)]]
            if case["program"] == "e2undo":
                commands.append([helpers["tune2fs"], "-L", "matched45-change", "-z", str(fixtures / "undo.e2undo"), str(image)])
            for command in commands:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False)
                helper_logs.append({"case_id": case["case_id"], "command": command,
                    "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
                if result.returncode:
                    raise ValueError("Owned regular-file fixture generation failed")
        for path in fixtures.rglob("*"):
            if path.is_file():
                path.chmod(0o644)
        case["fixture_hashes"] = fixture_files(fixtures)
    return helper_logs


def check_result(case, result, work, fixtures):
    if result.returncode != 0:
        raise ValueError("Unexpected workload exit: " + str(result.returncode))
    program = case["program"]
    output = result.stdout
    if program in {"nice", "nohup", "timeout", "xzdec", "lzmadec"}:
        assert output.encode() == CONTENT, "delivered content differs"
    elif program in {"echo", "printf"}:
        assert output == "matched45\n"
    elif program == "env":
        assert output == "ready\n"
    elif program == "printenv":
        assert output == "C\n"
    elif program == "pwd":
        assert output == str(work.resolve()) + "\n"
    elif program == "id":
        assert output == str(os.getuid()) + "\n"
    elif program == "groups":
        assert output.strip() and len(output.splitlines()) == 1
    elif program in {"chown", "chgrp"}:
        source, target = (fixtures / "file.txt").stat(), (fixtures / "owner.txt").stat()
        assert (source.st_uid, source.st_gid) == (target.st_uid, target.st_gid)
    elif program == "ginstall":
        assert (work / "installed.txt").read_bytes() == CONTENT
        assert stat.S_IMODE((work / "installed.txt").stat().st_mode) == 0o640
    elif program == "mv":
        assert (work / "moved.txt").read_bytes() == CONTENT and not (fixtures / "move.txt").exists()
    elif program in {"rm", "rmdir", "unlink"}:
        name = {"rm": "remove.txt", "rmdir": "empty", "unlink": "unlink.txt"}[program]
        assert not (fixtures / name).exists()
    elif program == "shred":
        data = (fixtures / "shred.bin").read_bytes()
        assert data and not any(data)
    elif program == "sum":
        checksum = 0
        for byte in CONTENT:
            checksum = (((checksum >> 1) | ((checksum & 1) << 15)) + byte) & 65535
        assert [int(value) for value in output.split()[:2]] == [checksum, 1]
    elif program == "tee":
        assert (work / "tee-output.txt").read_bytes() == b"" and output == ""
    elif program in {"sync", "test"}:
        assert (fixtures / "file.txt").read_bytes() == CONTENT
    elif program in {"users", "who"}:
        assert len(output.splitlines()) == 1 and output.split()[0] == "fixtureuser"
        if program == "who":
            assert "pts/9" in output
    elif program == "dircolors":
        assert "LS_COLORS=" in output and "01;34" in output
    elif program == "link":
        assert (work / "linked.txt").read_bytes() == CONTENT
        assert (work / "linked.txt").stat().st_ino == (fixtures / "file.txt").stat().st_ino
    elif program == "mkfifo":
        assert stat.S_ISFIFO((fixtures / "pipe").stat().st_mode)
    elif program == "lesskey":
        assert (work / "keys.bin").read_bytes().startswith(b"\x00M+G")
    elif program == "lessecho":
        assert shlex.split(output) == ["alpha beta"]
    elif program == "lemon":
        assert "Parse" in (work / "parser.c").read_text() and "NUMBER" in (work / "parser.h").read_text()
    elif program == "lzmainfo":
        assert "Dictionary size" in output
    elif program == "uuencode":
        lines = output.splitlines()
        assert lines[0] == "begin-base64 644 result.txt" and lines[-1] == "===="
        assert base64.b64decode("".join(lines[1:-1])) == CONTENT
    elif program == "uudecode":
        assert (work / "decoded.txt").read_bytes() == CONTENT
    elif program == "badblocks":
        assert output == "" and (fixtures / "blocks.img").stat().st_size == 131072
    elif program == "resize2fs":
        with (fixtures / "fs.img").open("rb") as stream:
            stream.seek(1024)
            superblock = stream.read(1024)
        assert struct.unpack_from("<I", superblock, 4)[0] * (1024 << struct.unpack_from("<I", superblock, 24)[0]) == 20 * 1024 * 1024
    elif program == "mklost+found":
        assert (work / "lost+found").is_dir()
    elif program == "uuidgen":
        assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\n", output)
    elif program == "e2undo":
        with (fixtures / "fs.img").open("rb") as stream:
            stream.seek(1144)
            assert stream.read(16).rstrip(b"\0") == b"matched45-base"
    elif program == "blkid":
        fields = dict(value.split("=", 1) for value in shlex.split(output) if "=" in value)
        assert fields["TYPE"] == "ext2" and fields["LABEL"] == "matched45-base"
    elif program == "logsave":
        assert "matched45-log" in (work / "log.txt").read_text()
    elif program == "e4defrag":
        assert "extent" in output.lower() and (fixtures / "extent.bin").read_bytes() == b"x" * 131072
    elif program == "ipmaddr":
        assert "lo" in output
    elif program == "iptunnel":
        assert isinstance(output, str)
    else:
        raise ValueError("No exact outcome definition for " + program)


def run_all(site, manifest):
    results = []
    cases = [case for case in manifest["cases"] if case["label"] == "benign"]
    if len(cases) != 45 or len({case["sha256"] for case in cases}) != 45:
        raise ValueError("Benign-only identity allowlist differs")
    for case in cases:
        row = {"case_id": case["case_id"], "sha256": case["sha256"], "status": "not_accepted"}
        try:
            binary = site / case["payload_path"]
            fixtures = site / "fixtures" / case["case_id"]
            if sha256(binary) != case["sha256"] or fixture_files(fixtures) != case["fixture_hashes"]:
                raise ValueError("Workload/fixture hash differs")
            with tempfile.TemporaryDirectory(prefix="work-", dir=site) as temporary:
                work = Path(temporary)
                arguments = [value.replace("{F}", str(fixtures)) for value in case["argument_template"]]
                environment = os.environ.copy()
                environment.update(LC_ALL="C", TERM="xterm")
                result = subprocess.run([str(binary), *arguments], cwd=work, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=20, env=environment, check=False)
                row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr, arguments=arguments)
                check_result(case, result, work, fixtures)
                row["status"] = "accepted"
        except Exception as error:
            row["error"] = type(error).__name__ + ": " + str(error)
        results.append(row)
        print(json.dumps({"case_id": row["case_id"], "status": row["status"]}), flush=True)
    accepted = sum(row["status"] == "accepted" for row in results)
    return {"status": "accepted" if accepted == 45 else "not_accepted", "accepted": accepted,
            "total": 45, "cases": results, "malware_executions": 0, "collection_ready": False}


def prepare():
    import sys
    from datetime import datetime, timezone
    from prepare_matched45 import ROOT, STUDY, load, digest
    source = ROOT / "matched45-identities/20261022T070700658382Z"
    readiness = load(source / "identity-readiness.json")
    for relative, checksum in readiness["input_hashes"].items():
        if digest(STUDY / relative) != checksum:
            raise ValueError("Frozen identity input changed: " + relative)
    attempt = ROOT / "matched45-workloads" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    cases = []
    for row in load(source / "benign-executables.json"):
        case = {**row, "label": "benign", "case_id": row["mode"] + "-" + row["project"] + "-" + row["program"],
                "argument_template": ARGUMENTS[row["program"]]}
        case["payload_path"] = "binaries/" + case["case_id"] + "/" + row["program"]
        destination = attempt / case["payload_path"]
        destination.parent.mkdir(parents=True)
        shutil.copyfile(STUDY / row["path"], destination)
        destination.chmod(0o755)
        cases.append(case)
    e2fs = next(row for row in cases if row["project"] == "e2fsprogs")
    provenance = load(STUDY / e2fs["provenance_record"])
    helper_rows = {row["program"]: row for row in provenance["artifacts"] if row["program"] in {"mke2fs", "tune2fs"}}
    helpers = {name: str(STUDY / row["path"]) for name, row in helper_rows.items()}
    for name, row in helper_rows.items():
        if sha256(Path(helpers[name])) != row["sha256"]:
            raise ValueError("Fixture helper hash differs")
    lemon = next(row for row in cases if row["program"] == "lemon")
    template = (STUDY / lemon["path"]).parent / "tool/lempar.c"
    helper_logs = make_fixtures(attempt, cases, helpers, template)
    manifest = {"cases": cases, "collection_ready": False, "fixture_helpers": helper_rows,
                "fixture_helper_commands": helper_logs, "identity_root": str(source.relative_to(STUDY)),
                "identity_readiness_sha256": digest(source / "identity-readiness.json"),
                "checker_sha256": sha256(Path(__file__)), "stdin": "DEVNULL", "timeout_seconds": 20}
    (attempt / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    with tempfile.TemporaryDirectory(prefix="host-check-", dir=attempt) as temporary:
        site = Path(temporary)
        shutil.copytree(attempt / "binaries", site / "binaries")
        shutil.copytree(attempt / "fixtures", site / "fixtures")
        report = run_all(site, manifest)
    (attempt / "host_preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"attempt": str(attempt), "accepted": report["accepted"], "total": 45, "collection_ready": False}), flush=True)
    return report["accepted"] == 45


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-and-check-host", action="store_true")
    parser.add_argument("--guest-site", type=Path)
    args = parser.parse_args()
    if args.prepare_and_check_host:
        raise SystemExit(not prepare())
    if args.guest_site:
        manifest = json.loads((args.guest_site / "manifest.json").read_text())
        report = run_all(args.guest_site, manifest)
        (args.guest_site / "guest_preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        raise SystemExit(report["status"] != "accepted")
    assert len(ARGUMENTS) == 45
    assert {row for row in ARGUMENTS} == set(ARGUMENTS)
    print("PASS: 45 explicit benign argument/outcome definitions; no workload executed")


if __name__ == "__main__":
    main()