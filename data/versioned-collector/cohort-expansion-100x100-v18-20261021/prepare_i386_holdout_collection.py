#!/usr/bin/env python3
"""Freeze collection-compatible inputs; execute only explicit benign checks."""

from __future__ import annotations

import argparse
import base64
import csv
import fcntl
import hashlib
import inspect
import io
import json
import os
import random
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import check_native_control_sensors as sensors
import preflight_x64_workloads as training_checks
import prepare_i386_holdout_workloads as validation_checks
import run_i386_holdout_preflight as guest_checks


ROOT = validation_checks.ROOT
STUDY = validation_checks.STUDY
HELPER = guest_checks.helper
TERM = validation_checks.TERM


def collection_arguments(case, fixture_root, fixture_names):
    if case["program"] in {"basename", "dirname", "pathchk"}:
        return case["arguments"]
    paths = set(fixture_names)
    paths.update(str(parent) for name in fixture_names for parent in Path(name).parents if str(parent) != ".")
    arguments = []
    for argument in case["arguments"]:
        prefix, separator, value = argument.partition("=")
        if argument in paths:
            argument = fixture_root + "/" + argument
        elif separator and value in paths:
            argument = prefix + "=" + fixture_root + "/" + value
        elif case["program"] == "dir" and argument == ".":
            argument = fixture_root
        arguments.append(argument)
    if case["program"] == "unshar":
        arguments[arguments.index("-d") + 1] = "."
    return arguments


def check_collection_result(case, completed, work, manifest, root):
    if completed.returncode:
        raise ValueError("workload returned " + str(completed.returncode))
    fixture_root = Path(case["fixture_root"])
    fixtures = {name: (fixture_root / name).read_bytes() for name in manifest["fixtures"][case["split"]]}
    program = case["program"]
    if case["split"] == "training":
        if program in {"realpath", "readlink"}:
            if completed.stdout != str(fixture_root / "fixture.txt") + "\n":
                raise ValueError("canonical path output differs")
        elif program == "chmod":
            if (fixture_root / "permissions.txt").stat().st_mode & 0o777 != 0o644:
                raise ValueError("fixture permissions differ")
        elif program == "ln":
            if (fixture_root / "fixture.txt").stat().st_ino != (work / "linked.txt").stat().st_ino:
                raise ValueError("hardlink does not refer to fixture")
        else:
            normalized = SimpleNamespace(returncode=completed.returncode, stderr=completed.stderr,
                                         stdout=completed.stdout.replace(str(fixture_root) + "/", ""))
            training_result(case, normalized, work, fixtures)
    elif program == "chattr":
        helper = next(row for row in manifest["cases"] if row.get("program") == "lsattr")
        observed = subprocess.run([str(root / helper["payload_path"]), str(fixture_root / "fixture.txt")],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=True)
        if "d" not in observed.stdout.split()[0]:
            raise ValueError("nodump attribute was not set")
    elif program == "unshar":
        if (work / "fixture.txt").read_bytes() != fixtures["fixture.txt"]:
            raise ValueError("extracted fixture differs")
    else:
        normalized = SimpleNamespace(returncode=completed.returncode, stderr=completed.stderr,
                                     stdout=completed.stdout.replace(str(fixture_root) + "/", ""))
        validation_result(case, normalized, work, manifest, root)


def guest_main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest.json").read_text())
    for split, files in manifest["fixtures"].items():
        for name, expected in files.items():
            if hashlib.sha256((root / "fixtures" / split / name).read_bytes()).hexdigest() != expected:
                raise ValueError("fixture hash differs")
    results = []
    for case in manifest["cases"]:
        if case["label"] != "benign":
            continue
        row = {"case_id": case["case_id"], "sha256": case["sha256"], "status": "not_accepted"}
        try:
            binary = root / case["payload_path"]
            if hashlib.sha256(binary.read_bytes()).hexdigest() != case["sha256"]:
                raise ValueError("binary hash differs")
            workspaces = root / "preflight-workspaces"
            workspaces.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=case["case_id"], dir=workspaces) as temporary:
                work = Path(temporary)
                environment = os.environ.copy()
                environment.pop("TERMINFO", None)
                environment["LC_ALL"] = "C"
                completed = subprocess.run([str(binary), *case["collection_arguments"]], cwd=work,
                                           stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                           timeout=20, env=environment, check=False)
                row.update(returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
                check_collection_result(case, completed, work, manifest, root)
                row["status"] = "accepted"
        except Exception as error:
            row["error"] = type(error).__name__ + ": " + str(error)
        results.append(row)
        print(json.dumps({key: row[key] for key in ("case_id", "status")}), flush=True)
    accepted = sum(row["status"] == "accepted" for row in results)
    report = {"status": "accepted" if accepted == 100 and len(results) == 100 else "not_accepted",
              "accepted": accepted, "total": len(results), "cases": results,
              "collection_ready": False, "malware_executions": 0}
    (root / "collection_preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    raise SystemExit(report["status"] != "accepted")


training_result = training_checks.check_result
validation_result = validation_checks.check_result


def freeze(amendment, host, guest):
    HELPER.verify_production()
    allocation_path = amendment / "allocation.json"
    allocation = json.loads(allocation_path.read_text())
    host_manifest = json.loads((host / "manifest.json").read_text())
    guest_report = json.loads((guest / "guest_preflight.json").read_text())
    if guest_report["status"] != "accepted" or guest_report["accepted"] != 30:
        raise ValueError("changed controls have not passed guest preflight")
    if {row["case_id"]: row["sha256"] for row in guest_report["cases"]} != {
            row["case_id"]: row["sha256"] for row in host_manifest["cases"]}:
        raise ValueError("changed-control evidence identities differ")
    previous = validation_checks.allocation.GUEST_ATTEMPT
    old_manifest = json.loads((previous / "manifest.json").read_text())
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = amendment / "collection-readiness" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/native-heldout-release-" + run_id
    fixture_sources = {"training": sensors.preparation.PREPARATION / "x64-workspace-seed",
                       "validation": host / "fixtures"}
    fixtures = {"training": old_manifest["fixtures"], "validation": host_manifest["fixtures"]}
    cases = []
    for split, rows in (("training", allocation["benign_training"]), ("validation", host_manifest["cases"])):
        for row in rows:
            source = row["source"]
            case = {**row, "source": source, "split": split, "label": "benign",
                    "fixture_root": guest_root + "/fixtures/" + split,
                    "sample": row["case_id"] + ".zip", "group_id": "benign_project::" + row["project"],
                    "payload_path": "binaries/" + row["case_id"] + "/" + row["program"]}
            case["collection_arguments"] = collection_arguments(case, case["fixture_root"], fixtures[split])
            cases.append(case)
    for split in ("training", "validation"):
        for row in allocation["malware_" + split]:
            cases.append({**row, "case_id": "malware-" + row["sha256"], "label": "malware", "split": split,
                          "sample": row["sha256"] + ".zip", "collection_arguments": [],
                          "arch": "amd64" if row["execution_mode"] == "native_x86_64_static" else "i386"})
    native_attempt = ROOT / "native-checks/20261021T150457461296Z"
    null_protocol = json.loads((native_attempt / "protocol.json").read_text())
    nulls = [row for row in null_protocol["cases"] if row["workload"] == "null"]
    if len(nulls) != 4:
        raise ValueError("expected two per-mode null repeats")
    for row in nulls:
        cases.append({**row, "case_id": "null-" + row["sample"], "label": "null", "split": "null",
                      "sha256": row["binary_sha256"], "program": "busybox",
                      "collection_arguments": ["true"]})
    if Counter((row["label"], row["split"]) for row in cases) != {
            ("benign", "training"): 70, ("benign", "validation"): 30,
            ("malware", "training"): 70, ("malware", "validation"): 30, ("null", "null"): 4}:
        raise ValueError("case budgets differ")
    rng = random.Random(42)
    ordered = []
    for split, arch in (("training", "amd64"), ("training", "i386"), ("validation", "i386")):
        benign = [row for row in cases if row["split"] == split and row["arch"] == arch and row["label"] == "benign"]
        malware = [row for row in cases if row["split"] == split and row["arch"] == arch and row["label"] == "malware"]
        rng.shuffle(benign)
        rng.shuffle(malware)
        if len(benign) != len(malware):
            raise ValueError("per-mode label balance differs")
        for pair in zip(benign, malware):
            pair = list(pair)
            rng.shuffle(pair)
            ordered.extend(pair)
    ordered[0:0] = [row for row in cases if row["label"] == "null" and row["repeat"] == 1]
    ordered.extend(row for row in cases if row["label"] == "null" and row["repeat"] == 2)
    inputs = {str(path.relative_to(STUDY)): validation_checks.allocation.digest(path) for path in (
        allocation_path, host / "manifest.json", host / "host_preflight.json", guest / "guest_preflight.json",
        previous / "guest_preflight.json", Path(__file__), Path(validation_checks.__file__),
        Path(training_checks.__file__), amendment / "source-authentication.json", native_attempt / "protocol.json")}
    manifest = {"cases": cases, "fixtures": fixtures, "guest_root": guest_root,
                "snapshot": "clean-native-heldout-release-v18-" + run_id, "inputs": inputs,
                "collection_ready": False, "malware_executions": 0}
    checker = ("import base64,hashlib,json,os,re,shutil,subprocess,tempfile\nfrom pathlib import Path\n"
               "from types import SimpleNamespace\nTERM=" + repr(TERM) + "\n"
               + inspect.getsource(training_checks.check_result) + "\ntraining_result=check_result\n"
               + inspect.getsource(validation_checks.check_result).replace(
                   '(work / "fixture.txt").read_bytes()',
                   '(Path(case["fixture_root"]) / "fixture.txt").read_bytes()')
               + "\nvalidation_result=check_result\n"
               + inspect.getsource(check_collection_result) + "\n" + inspect.getsource(guest_main)
               + "\nif __name__=='__main__':guest_main()\n")
    compile(checker, "collection_check.py", "exec")
    with tarfile.open(attempt / "payload.tgz", "w:gz") as archive:
        def add(name, data, mode=0o644):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), mode
            archive.addfile(member, io.BytesIO(data))

        for split, files in fixtures.items():
            for name, expected in files.items():
                source = fixture_sources[split] / name
                if validation_checks.allocation.digest(source) != expected:
                    raise ValueError("fixture changed")
                add("fixtures/" + split + "/" + name, source.read_bytes())
        with tarfile.open(native_attempt / "payload.tgz", "r:gz") as null_payload:
            for case in cases:
                if case["label"] == "benign":
                    data = (STUDY / case["source"]).read_bytes()
                    if hashlib.sha256(data).hexdigest() != case["sha256"]:
                        raise ValueError("benign binary changed")
                    add(case["payload_path"], data, 0o755)
                    packed = io.BytesIO()
                    with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED) as transport:
                        member = zipfile.ZipInfo(case["program"])
                        member.external_attr = 0o100755 << 16
                        transport.writestr(member, data)
                    data = packed.getvalue()
                elif case["label"] == "malware":
                    data = (STUDY / case["source_archive_path"]).read_bytes()
                    if hashlib.sha256(data).hexdigest() != case["source_archive_sha256"]:
                        raise ValueError("malware archive changed")
                else:
                    members = [member for member in null_payload if member.name.endswith("/" + case["sample"])]
                    if len(members) != 1:
                        null_payload.members = []
                        members = [member for member in null_payload.getmembers() if member.name.endswith("/" + case["sample"])]
                    if len(members) != 1:
                        raise ValueError("null transport unavailable")
                    data = null_payload.extractfile(members[0]).read()
                    if hashlib.sha256(data).hexdigest() != case["transport_sha256"]:
                        raise ValueError("null transport changed")
                case["transport_sha256"] = hashlib.sha256(data).hexdigest()
                add("samples/" + case["sample"], data)
                add("arguments/" + case["sample"] + ".json", json.dumps(case["collection_arguments"]).encode())
        add("manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode())
        add("collection_check.py", checker.encode())
    native = guest_checks.native
    native.write_json(attempt / "manifest.json", manifest)
    native.write_json(attempt / "case_order.json", ordered)
    (attempt / "all-cases.txt").write_text("".join(row["sample"] + "\n" for row in ordered))
    smoke = [row for row in cases if row["label"] == "null" or (
        row["label"] == "benign" and row["program"] in {"tput", "unshar", "mke2fs"})]
    (attempt / "benign-smoke.txt").write_text("".join(row["sample"] + "\n" for row in smoke))
    preregistration = {"dataset_role": allocation["dataset_role"], "scope": "Native static i386 held-out transfer; x64 training only.",
        "counts": {"training_per_label": 70, "validation_per_label": 30, "null_repeats": 4},
        "feature_columns": {"p4": 145, "selected_host": 145, "hybrid": 290},
        "host_selection": "29 whole families ranked by mean mutual information on training summaries only",
        "estimator": {"name": "RandomForestClassifier", "n_estimators": 500, "class_weight": "balanced", "random_state": 42,
                      "n_jobs": 1, "threshold": 0.5, "tuning": "none"},
        "primary": "One held-out i386 evaluation; quality accepted, exact target exec observed, unique P4 alignment with stored-counter parity; identical model cases.",
        "secondary": ["Host-only all eligible alignment sensitivity", "Per-mode/per-group metrics and group-bootstrap intervals",
                      "Training-only grouped OOF; nuisance/activity-only baselines; training group-label permutations"],
        "activation": "Per-mode max fresh null post-target syscall count plus 25; descriptive only, never a primary exclusion.",
        "quality": "Pinned .18 runner, active sensors, finite rows, safe archive hashes, zero reported PCAP drops/gap/eBPF loss, independent PCAP counts.",
        "retries": "No automatic retry, replacement or resume; preserve failures and report exclusions.",
        "validation_usage": "No tuning or threshold/feature selection using validation; earlier consumed validation untouched.",
        "limitations": allocation["limitations"] + ["Only three training benign projects; toolchain/task/activity confounds remain possible.",
            "P4 features are offline PCAP reconstructions; no live-switch claim."],
        "frozen_utc": datetime.now(timezone.utc).isoformat(), "full_collection_started": False}
    native.write_json(attempt / "preregistration.json", preregistration)
    encoded = base64.b64encode((attempt / "payload.tgz").read_bytes()).decode()
    setup = """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(GUEST_ROOT)
data=base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest()!=EXPECTED:
    raise SystemExit('existing root or changed payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    seen=set()
    for member in archive:
        target=root/member.name
        if not member.isfile() or member.name in seen or not target.resolve().is_relative_to(root):
            raise SystemExit('unsafe member')
        seen.add(member.name)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(archive.extractfile(member).read())
        target.chmod(member.mode & 0o777)
for source in (root/'fixtures/validation/terminfo').rglob('*'):
    if source.is_file():
        target=Path.home()/'.terminfo'/source.relative_to(root/'fixtures/validation/terminfo')
        if target.exists() and target.read_bytes()!=source.read_bytes():
            raise SystemExit('refusing to replace terminal entry')
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(source.read_bytes())
print('Both labels staged identically; no sample executed')
PY
"""
    setup = setup.replace("GUEST_ROOT", repr(guest_root)).replace("PAYLOAD", repr(encoded))
    setup = setup.replace("EXPECTED", repr(validation_checks.allocation.digest(attempt / "payload.tgz")))
    (attempt / "setup_guest.sh").write_text(setup)
    protocol = {"cases": cases, "schema": HELPER.SCHEMA, "production_hashes": HELPER.PINNED,
        "baseline": HELPER.BASELINE, "snapshot": manifest["snapshot"], "guest_root": guest_root,
        "collection_ready": False, "malware_executions": 0,
        "input_hashes": {**inputs, **{str(path.relative_to(STUDY)): validation_checks.allocation.digest(path)
            for path in attempt.iterdir() if path.is_file()}},
        "limitations": preregistration["limitations"]}
    native.write_json(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "cases": len(cases), "collection_ready": False}), flush=True)
    return attempt, protocol


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("amendment", type=Path)
    parser.add_argument("host_attempt", type=Path)
    parser.add_argument("guest_attempt", type=Path)
    args = parser.parse_args()
    freeze(args.amendment.resolve(), args.host_attempt.resolve(), args.guest_attempt.resolve())


if __name__ == "__main__":
    main()