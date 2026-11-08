#!/usr/bin/env python3
"""Run bounded host-side semantic checks for drafted benign x64 workloads."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import prepare_inventory


ROOT = Path(__file__).resolve().parent
STUDY = prepare_inventory.STUDY
DEFAULT_PREPARATION = ROOT / "native-preparation/20261021T151822271708Z"


def check_result(case, result, work, fixtures):
    program = case["program"]
    stdout = result.stdout
    if case["project"] == "coreutils":
        if program in {"b2sum", "sha1sum", "sha224sum", "sha384sum", "sha512sum"}:
            algorithm = "blake2b" if program == "b2sum" else program.removesuffix("sum")
            if algorithm == "blake2b":
                expected = hashlib.blake2b(fixtures["fixture.txt"], digest_size=64).hexdigest()
            else:
                expected = hashlib.new(algorithm, fixtures["fixture.txt"]).hexdigest()
            assert stdout.startswith(expected + "  fixture.txt\n")
        elif program == "base32":
            assert "".join(stdout.splitlines()) == base64.b32encode(fixtures["fixture.txt"]).decode()
        elif program == "basenc":
            assert "".join(stdout.splitlines()) == base64.b64encode(fixtures["fixture.txt"]).decode()
        elif program == "csplit":
            assert (work / "piece-00").read_bytes() + (work / "piece-01").read_bytes() == fixtures["fixture.txt"]
        elif program == "dd":
            assert (work / "dd-copy.txt").read_bytes() == fixtures["fixture.txt"]
        elif program in {"dir", "vdir"}:
            assert "fixture.txt" in stdout and "tabs.txt" in stdout
        elif program == "expand":
            assert stdout == fixtures["tabs.txt"].decode().expandtabs(4)
        elif program == "fmt":
            assert "Bounded local text processing" in " ".join(stdout.split()) and all(len(line) <= 40 for line in stdout.splitlines())
        elif program == "fold":
            expected = fixtures["paragraph.txt"].decode()
            assert "".join(stdout.split()) == "".join(expected.split())
            assert all(len(line) <= 20 for line in stdout.splitlines())
        elif program == "nl":
            assert stdout.splitlines() == [f"{index:>6}\t{line}" for index, line in enumerate(fixtures["fixture.txt"].decode().splitlines(), 1)]
        elif program == "numfmt":
            assert stdout == "1.0M\n"
        elif program == "pr":
            assert "alpha one" in stdout and "epsilon five" in stdout
        elif program == "ptx":
            assert "alpha" in stdout and "epsilon" in stdout
        elif program == "shuf":
            values = stdout.splitlines()
            assert len(values) == 3 and len(set(values)) == 3
            assert set(values) <= set(fixtures["fixture.txt"].decode().splitlines())
        elif program == "sum":
            assert re.fullmatch(r"\d+\s+\d+\n", stdout)
        elif program == "tac":
            assert stdout.splitlines() == list(reversed(fixtures["fixture.txt"].decode().splitlines()))
        elif program == "tsort":
            order = stdout.splitlines()
            assert len(order) == 4 and order.index("alpha") < order.index("beta") < order.index("gamma") < order.index("delta")
        elif program == "wc":
            assert stdout == "5 fixture.txt\n"
        elif program == "unexpand":
            assert "\t" in stdout and "alpha" in stdout and "delta" in stdout
        elif program == "uname":
            assert stdout == "Linux\n"
        elif program in {"basename", "dirname", "date", "expr"}:
            expected = {"basename": "fixture\n", "dirname": "inputs\n", "date": "2000-01-01\n", "expr": "80235\n"}[program]
            assert stdout == expected
        elif program in {"realpath", "readlink"}:
            assert stdout == str(work / "fixture.txt") + "\n"
        elif program == "pathchk":
            assert not stdout and result.returncode == 0
        elif program == "factor":
            assert stdout.startswith("1234567890: ") and set(stdout.split(": ", 1)[1].split()) == {"2", "3", "5", "3607", "3803"}
        elif program == "seq":
            assert stdout.splitlines() == [str(number) for number in range(1, 1001)]
        elif program == "mkdir":
            assert (work / "generated/one/two").is_dir()
        elif program == "chmod":
            assert (work / "permissions.txt").stat().st_mode & 0o777 == 0o644
        elif program == "mktemp":
            assert len(list(work.glob("generated.??????"))) == 1
        elif program == "touch":
            assert int((work / "touched.txt").stat().st_mtime) == 946684800
        elif program == "truncate":
            assert (work / "sparse.bin").stat().st_size == 8192
        elif program == "ln":
            assert os.stat(work / "fixture.txt").st_ino == os.stat(work / "linked.txt").st_ino
        elif program == "df":
            rows = stdout.splitlines()
            assert rows and rows[0].startswith("Filesystem") and len(rows) > 1
        elif program == "nproc":
            assert re.fullmatch(r"[1-9][0-9]*\n", stdout)
        else:
            raise ValueError("missing exact coreutils check: " + program)
    elif program in {"flock", "fallocate", "hardlink", "ipcs", "lsipc", "lsns", "mcookie", "mountpoint", "prlimit", "taskset"}:
        if program == "flock":
            assert stdout == "lock-ok"
        elif program == "fallocate":
            assert (work / "allocated.bin").stat().st_size == 65536
        elif program == "hardlink":
            assert "one.txt" in stdout and "two.txt" in stdout
        elif program == "mcookie":
            assert re.fullmatch(r"[0-9a-f]{32}\n", stdout)
        elif program == "mountpoint":
            assert not stdout and result.returncode == 0
        elif program == "ipcs":
            assert "Messages Status" in stdout and "Shared Memory Status" in stdout
        elif program == "lsipc":
            assert "RESOURCE" in stdout
        elif program == "lsns":
            assert "NS" in stdout and "TYPE" in stdout
        elif program == "prlimit":
            assert "RESOURCE" in stdout and "NOFILE" in stdout
        elif program == "taskset":
            assert not stdout
    elif case["project"] == "procps":
        if program == "sysctl":
            assert stdout == "Linux\n"
        else:
            raise ValueError("unapproved procps workload: " + program)
    else:
        raise ValueError("unapproved project: " + case["project"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--preparation", type=Path, default=DEFAULT_PREPARATION)
    args = parser.parse_args()
    preparation = args.preparation.resolve()
    if preparation.parent != (ROOT / "native-preparation").resolve():
        raise ValueError("preparation must be a direct child of native-preparation")
    if not preparation.is_dir():
        raise FileNotFoundError(preparation)
    drafts_path = preparation / "benign-x64-workload-drafts.json"
    drafts = json.loads(drafts_path.read_text())
    builder = prepare_inventory.load_builder()
    fixture_root = preparation / "x64-workspace-seed"
    fixtures = {path.relative_to(fixture_root).as_posix(): path.read_bytes()
                for path in fixture_root.rglob("*") if path.is_file()}
    for name, expected in drafts["fixture_hashes"].items():
        relative = Path(name).relative_to("x64-workspace-seed").as_posix()
        if hashlib.sha256(fixtures[relative]).hexdigest() != expected:
            raise ValueError("fixture hash mismatch: " + name)
    results = []
    for case in drafts["cases"]:
        executable = STUDY / case["path"]
        if builder.sha256_file(executable) != case["sha256"]:
            raise ValueError("executable hash mismatch: " + case["program"])
        work = Path(tempfile.mkdtemp(prefix="hazim-benign-x64-"))
        try:
            for name, data in fixtures.items():
                destination = work / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            result = subprocess.run([str(executable), *case["arguments"]], cwd=work,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=case["timeout_s"], check=False)
            if result.returncode != case["expected_return_code"]:
                raise ValueError(f"{case['program']} returned {result.returncode}: {result.stderr[-500:]}")
            check_result(case, result, work, fixtures)
            results.append({"project": case["project"], "program": case["program"],
                            "sha256": case["sha256"], "status": "accepted",
                            "returncode": result.returncode, "stdout_bytes": len(result.stdout.encode()),
                            "stderr_bytes": len(result.stderr.encode())})
        finally:
            shutil.rmtree(work)
    report = {"status": "accepted_host_preflight_only", "guest_preflight": False,
              "collection_ready": False, "cases": results,
              "draft_sha256": builder.sha256_file(drafts_path),
              "preflight_sha256": builder.sha256_file(Path(__file__)),
              "limitations": ["Host-side static x64 execution only; no guest execution or sensor validation.",
                              "Does not freshly authenticate source repositories.",
                              "Per-workload semantic checks do not validate representativeness or independent project groups."]}
    output = args.output.resolve() if args.output else preparation / "x64-host-preflight.json"
    if output.exists():
        raise FileExistsError("preserve existing preflight report: " + str(output))
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "accepted": len(results),
                      "total": len(drafts["cases"]), "guest_preflight": False,
                      "report": str(output)}, indent=2))


if __name__ == "__main__":
    main()