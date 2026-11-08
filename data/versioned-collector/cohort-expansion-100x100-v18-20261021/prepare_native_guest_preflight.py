#!/usr/bin/env python3
"""Prepare benign native workload guest checks without changing frozen inputs."""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import inspect
import io
import json
import os
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import preflight_x64_workloads as host_checks
import prepare_inventory
import run_native_checks as native_checks


ROOT = Path(__file__).resolve().parent
STUDY = prepare_inventory.STUDY
PREPARATION = ROOT / "native-preparation/20261021T154925322129Z"
I386_REPORT = ROOT / "i386-toolchain-probe/20261021T153000Z/i386-controls-20261021T161011Z/i386-control-build-results.json"
EXPECTED = {
    PREPARATION / "benign-x64-workload-drafts.json": "23a769e6d59d6fbe5f1097ce6d33a497edbd7931cb01a4f9087991233773644a",
    PREPARATION / "x64-host-preflight.json": "33ca57873c13d9d673cd102dd3adecb54cfa0996aa9c3f59ddd1a3fd5d650da2",
    I386_REPORT: "dff8555b507d0042684b49a2f12145df569b1727212edb914cf4f2e58496e6d2",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


GUEST_MAIN = '''
def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest.json").read_text())
    fixtures = {}
    for name, expected in manifest["fixtures"].items():
        data = (root / "fixtures" / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("fixture hash differs: " + name)
        fixtures[name] = data
    results = []
    for case in manifest["cases"]:
        result = {"case_id": case["case_id"], "arch": case["arch"],
                  "project": case["project"], "program": case["program"],
                  "sha256": case["sha256"], "status": "not_accepted"}
        try:
            binary = root / case["payload_path"]
            data = binary.read_bytes()
            if hashlib.sha256(data).hexdigest() != case["sha256"]:
                raise ValueError("binary hash differs")
            if data[:4] != b"\\x7fELF" or int.from_bytes(data[18:20], "little") != case["machine"]:
                raise ValueError("ELF architecture differs")
            work_root = root / "workspaces"
            work_root.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=case["case_id"] + "-", dir=work_root) as temporary:
                work = Path(temporary)
                for name, content in fixtures.items():
                    destination = work / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                environment = os.environ.copy()
                environment["LC_ALL"] = "C"
                completed = subprocess.run([str(binary), *case["arguments"]], cwd=work,
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    timeout=20, env=environment, check=False)
                result.update(returncode=completed.returncode, stdout=completed.stdout,
                              stderr=completed.stderr)
                if completed.returncode != 0:
                    raise ValueError("workload returned " + str(completed.returncode))
                if case["project"] == "diffutils":
                    if completed.stdout or completed.stderr:
                        raise ValueError("comparison emitted output for identical fixtures")
                elif case["program"] == "findmnt":
                    if completed.stdout != "/\\n":
                        raise ValueError("findmnt did not report root mount")
                elif case["program"] == "getopt":
                    if completed.stdout != " -a -- 'foo'\\n":
                        raise ValueError("getopt output differs")
                else:
                    check_result(case, completed, work, fixtures)
                result["status"] = "accepted"
        except Exception as error:
            result["error"] = type(error).__name__ + ": " + str(error)
        results.append(result)
        print(json.dumps({key: result[key] for key in ("case_id", "status")}), flush=True)
    accepted = sum(row["status"] == "accepted" for row in results)
    report = {"status": "accepted" if accepted == 100 and len(results) == 100 else "not_accepted",
              "guest_workloads_passed": accepted == 100 and len(results) == 100,
              "accepted": accepted, "total": len(results), "cases": results,
              "collection_ready": False, "malware_executions": 0,
              "limitations": ["Direct benign guest workload checks only; no sensor/activation certification.",
                              "No family/project split, collection order or dataset role is approved by this report."]}
    (root / "guest_preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\\n")
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}), flush=True)
    if report["status"] != "accepted":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
'''


def freeze():
    native_checks.previous_readiness.verify_production()
    for path, expected in EXPECTED.items():
        if digest(path) != expected:
            raise ValueError("accepted input changed: " + str(path))
    drafts = json.loads((PREPARATION / "benign-x64-workload-drafts.json").read_text())
    host = json.loads((PREPARATION / "x64-host-preflight.json").read_text())
    i386 = json.loads(I386_REPORT.read_text())
    if host["status"] != "accepted_host_preflight_only" or i386["status"] != "accepted_host_i386_build_and_semantic_preflight":
        raise ValueError("host workload evidence not accepted")
    builder = prepare_inventory.load_builder()
    cases = []
    for row in drafts["cases"]:
        cases.append({"case_id": "amd64-" + row["project"] + "-" + row["program"],
                      "arch": "amd64", "machine": 62, "project": row["project"],
                      "program": row["program"], "source": row["path"], "sha256": row["sha256"],
                      "arguments": row["arguments"]})
    for row in i386["artifacts"]:
        source = I386_REPORT.parent / row["relative_path"]
        cases.append({"case_id": "i386-" + row["project"] + "-" + row["program"],
                      "arch": "i386", "machine": 3, "project": row["project"],
                      "program": row["program"], "source": str(source.relative_to(STUDY)),
                      "sha256": row["artifact"]["sha256"],
                      "arguments": row["semantic_validation"]["command"][1:]})
    if len(cases) != 100 or len({row["sha256"] for row in cases}) != 100:
        raise ValueError("expected 100 distinct benign executable identities")
    fixture_root = PREPARATION / "x64-workspace-seed"
    fixtures = {path.relative_to(fixture_root).as_posix(): path.read_bytes()
                for path in sorted(fixture_root.rglob("*")) if path.is_file()}
    for name, expected in drafts["fixture_hashes"].items():
        relative = Path(name).relative_to("x64-workspace-seed").as_posix()
        if hashlib.sha256(fixtures[relative]).hexdigest() != expected:
            raise ValueError("draft fixture changed: " + name)
    if fixtures.get("copy.txt") != fixtures["fixture.txt"]:
        raise ValueError("i386 identical-file fixture differs")
    checker = ("import base64, hashlib, json, os, re, subprocess, tempfile\nfrom pathlib import Path\n\n"
               + inspect.getsource(host_checks.check_result) + "\n" + GUEST_MAIN)
    compile(checker, "guest_check.py", "exec")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "operational-readiness" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    manifest = {"cases": cases, "fixtures": {name: hashlib.sha256(data).hexdigest()
                                             for name, data in fixtures.items()},
                "guest_root": "/home/csci/Downloads/native-control-preflight-" + run_id,
                "snapshot": "clean-native-control-preflight-v18-" + run_id,
                "collection_ready": False, "malware_executions": 0,
                "inputs": {str(path.relative_to(STUDY)): digest(path) for path in
                           (*EXPECTED, Path(__file__), Path(host_checks.__file__),
                            Path(native_checks.__file__),
                            Path(native_checks.previous_readiness.__file__))}}
    with tarfile.open(attempt / "payload.tgz", "w:gz") as archive:
        def add(name, data, mode=0o644):
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = mode, len(data)
            archive.addfile(entry, io.BytesIO(data))

        for case in cases:
            source = STUDY / case["source"]
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != case["sha256"]:
                raise ValueError("benign binary changed: " + case["case_id"])
            expected_mode = "native_i386_static" if case["arch"] == "i386" else "native_x86_64_static"
            if builder.inspect_elf(data, strict_linkage=True)[0] != expected_mode:
                raise ValueError("benign executable mode differs")
            case["payload_path"] = "binaries/" + case["case_id"] + "/" + case["program"]
            add(case["payload_path"], data, 0o755)
        for name, data in fixtures.items():
            add("fixtures/" + name, data)
        add("guest_check.py", checker.encode())
        add("manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode())
    (attempt / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    encoded = base64.b64encode((attempt / "payload.tgz").read_bytes()).decode()
    setup = '''#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64, hashlib, io, tarfile
from pathlib import Path
root = Path(GUEST_ROOT)
data = base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest() != EXPECTED_HASH:
    raise SystemExit('existing guest path or changed payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    seen = set()
    for member in archive:
        target = root / member.name
        if not member.isfile() or member.name in seen or not target.resolve().is_relative_to(root):
            raise SystemExit('unsafe or duplicate payload member')
        seen.add(member.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.extractfile(member).read())
        target.chmod(member.mode & 0o777)
print('100 benign native controls staged; no sample executed')
PY
'''
    setup = setup.replace("GUEST_ROOT", repr(manifest["guest_root"]))
    setup = setup.replace("PAYLOAD", repr(encoded))
    setup = setup.replace("EXPECTED_HASH", repr(digest(attempt / "payload.tgz")))
    (attempt / "setup_guest.sh").write_text(setup)
    protocol = {"manifest_sha256": digest(attempt / "manifest.json"),
                "payload_sha256": digest(attempt / "payload.tgz"),
                "setup_sha256": digest(attempt / "setup_guest.sh"),
                "scope": "100 benign workload guest checks only; no malware or collection release",
                "production_hashes": native_checks.previous_readiness.PINNED,
                "collection_ready": False, "malware_executions": 0}
    (attempt / "protocol.json").write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"attempt": str(attempt), "cases": len(cases),
                      "payload_sha256": digest(attempt / "payload.tgz"),
                      "collection_ready": False, "guest_checks_performed": False}, indent=2), flush=True)
    return attempt, manifest


def execute(attempt, manifest):
    helper = native_checks.previous_readiness
    helper.verify_production()
    initial = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
    if initial["guest"]["VMState"] != '"poweroff"' or initial["sink"]["VMState"] != '"running"':
        raise ValueError("guest must be powered off and isolated Sink running")
    competing = subprocess.run(["pgrep", "-af", "[v]box_malware_batch|[s]tage_versioned_runner|[r]un_versioned_cohorts|[r]un_readiness.py"],
                              capture_output=True, text=True, check=False)
    if competing.returncode != 1:
        raise ValueError("competing collector/stager or process check failed")
    native_checks.write_json(attempt / "initial_vm_state.json", initial)
    for name, expected in manifest["inputs"].items():
        if digest(STUDY / name) != expected:
            raise ValueError("frozen input changed: " + name)
    protocol = json.loads((attempt / "protocol.json").read_text())
    for name, key in (("manifest.json", "manifest_sha256"), ("payload.tgz", "payload_sha256"),
                      ("setup_guest.sh", "setup_sha256")):
        if digest(attempt / name) != protocol[key]:
            raise ValueError("staging input changed: " + name)
    with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-native-guest-auth-") as password:
        os.chmod(password.name, 0o600)
        password.write(helper.credentials())
        password.flush()
        auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
        try:
            print("Staging fresh benign-only native-control preflight snapshot", flush=True)
            with (attempt / "staging.log").open("w") as output:
                subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
                                "--vm", helper.VM, "--guest-user", helper.GUEST_USER,
                                "--baseline-snapshot", helper.BASELINE, "--new-snapshot", manifest["snapshot"],
                                "--schema-version", helper.SCHEMA,
                                "--guest-setup", str(attempt / "setup_guest.sh")],
                               stdout=output, stderr=subprocess.STDOUT, check=True, cwd=STUDY)
            staged = helper.isolated(helper.VM)
            if staged["CurrentSnapshotName"] != '"' + manifest["snapshot"] + '"':
                raise ValueError("staged snapshot differs")
            native_checks.write_json(attempt / "staged_snapshot.json", staged)
            with (attempt / "guest_ready.log").open("w") as log:
                for probe in range(3):
                    waiter = subprocess.Popen(["VBoxManage", "guestproperty", "wait", helper.VM,
                                               "/VirtualBox/GuestInfo/OS/LoggedInUsers",
                                               "--timeout", "120000", "--fail-on-timeout"],
                                              stdout=log, stderr=subprocess.STDOUT)
                    try:
                        if probe == 0:
                            helper.vbox("startvm", helper.VM, "--type", "headless")
                        if waiter.wait(timeout=150):
                            raise RuntimeError("guest login readiness event timed out")
                    finally:
                        if waiter.poll() is None:
                            waiter.terminate()
                            waiter.wait()
                    ready = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/bin/true",
                                        "--wait-stdout", "--wait-stderr", "--timeout", "5000", "--", check=False)
                    log.write(ready.stdout + ready.stderr)
                    log.flush()
                    if ready.returncode == 0:
                        break
                else:
                    raise RuntimeError("Guest Control not ready; inspect guest_ready.log")
            print("Checking 100 actual benign workloads in isolated guest", flush=True)
            result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                                 "--wait-stdout", "--wait-stderr", "--timeout", "900000", "--",
                                 manifest["guest_root"] + "/guest_check.py", check=False)
            (attempt / "guest_preflight.log").write_text(result.stdout + result.stderr)
            helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth,
                        manifest["guest_root"] + "/guest_preflight.json", str(attempt / "guest_preflight.json"))
            report = json.loads((attempt / "guest_preflight.json").read_text())
            if {row["case_id"]: row["sha256"] for row in report["cases"]} != {
                    row["case_id"]: row["sha256"] for row in manifest["cases"]}:
                raise ValueError("guest report identities differ")
            helper.verify_production()
            for name, expected in manifest["inputs"].items():
                if digest(STUDY / name) != expected:
                    raise ValueError("frozen input changed during preflight: " + name)
            print(json.dumps({key: value for key, value in report.items() if key != "cases"}, indent=2), flush=True)
            if result.returncode or report["status"] != "accepted" or report["accepted"] != 100:
                raise RuntimeError("benign guest workload checks did not all pass; inspect guest_preflight.json")
        finally:
            if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                helper.vbox("controlvm", helper.VM, "poweroff")
            helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
            final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
            native_checks.write_json(attempt / "final_vm_state.json", final)
            if (final["guest"]["VMState"] != '"poweroff"'
                    or final["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"'):
                raise RuntimeError("cleanup did not restore powered-off original snapshot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-benign-checks", action="store_true")
    args = parser.parse_args()
    with (prepare_inventory.PREPARATION / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt, manifest = freeze()
        if args.execute_benign_checks:
            try:
                execute(attempt, manifest)
            except Exception as error:
                native_checks.write_json(attempt / "failure.json", {
                    "status": "not_accepted", "error": type(error).__name__ + ": " + str(error),
                    "collection_ready": False, "malware_executions": 0})
                raise


if __name__ == "__main__":
    main()