#!/usr/bin/env python3
"""Stage and optionally run only the 30 amended benign guest workloads."""

from __future__ import annotations

import argparse
import base64
import fcntl
import inspect
import io
import json
import os
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import prepare_i386_holdout_workloads as workloads
import run_native_checks as native


ROOT = workloads.ROOT
STUDY = workloads.STUDY
helper = native.previous_readiness


def freeze(host):
    manifest = json.loads((host / "manifest.json").read_text())
    report = json.loads((host / "host_preflight.json").read_text())
    if (report["status"] != "accepted" or report["accepted"] != 30
            or manifest["checker_sha256"] != workloads.allocation.digest(Path(workloads.__file__))):
        raise ValueError("changed controls need current accepted host preflight")
    if {row["case_id"]: row["sha256"] for row in report["cases"]} != {
            row["case_id"]: row["sha256"] for row in manifest["cases"]}:
        raise ValueError("host evidence does not bind exact binaries")
    helper.verify_production()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = host.parent.parent / "guest-preflight" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    checker = ("import hashlib,json,os,re,shutil,subprocess,tempfile\nfrom pathlib import Path\n"
               "from types import SimpleNamespace\n"
               "allocation=SimpleNamespace(digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest())\n"
               "TERM=" + repr(workloads.TERM) + "\n"
               + inspect.getsource(workloads.check_result) + "\n"
               + inspect.getsource(workloads.run_cases) + "\n"
               "root=Path(__file__).resolve().parent\n"
               "manifest=json.loads((root/'manifest.json').read_text())\n"
               "report=run_cases(root,manifest)\n"
               "(root/'guest_preflight.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\\n')\n"
               "raise SystemExit(report['status']!='accepted')\n")
    compile(checker, "guest_check.py", "exec")
    manifest.update(guest_root="/home/csci/Downloads/i386-heldout-preflight-" + run_id,
                    snapshot="clean-i386-heldout-preflight-v18-" + run_id,
                    inputs={str(path.relative_to(STUDY)): workloads.allocation.digest(path)
                            for path in (host / "manifest.json", host / "host_preflight.json",
                                         Path(workloads.__file__), Path(__file__))})
    with tarfile.open(attempt / "payload.tgz", "w:gz") as archive:
        def add(name, content, mode=0o644):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(content), mode
            archive.addfile(member, io.BytesIO(content))

        for case in manifest["cases"]:
            source = host / case["payload_path"]
            if workloads.allocation.digest(source) != case["sha256"]:
                raise ValueError("changed binary")
            add(case["payload_path"], source.read_bytes(), 0o755)
        for name, expected in manifest["fixtures"].items():
            source = host / "fixtures" / name
            if workloads.allocation.digest(source) != expected:
                raise ValueError("changed fixture")
            add("fixtures/" + name, source.read_bytes())
        add("guest_check.py", checker.encode())
        add("manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode())
    native.write_json(attempt / "manifest.json", manifest)
    setup = """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(GUEST_ROOT)
data=base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest()!=EXPECTED:
    raise SystemExit('existing guest root or changed payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    seen=set()
    for member in archive:
        target=root/member.name
        if not member.isfile() or member.name in seen or not target.resolve().is_relative_to(root):
            raise SystemExit('unsafe payload member')
        seen.add(member.name)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(archive.extractfile(member).read())
        target.chmod(member.mode & 0o777)
for source in (root/'fixtures/terminfo').rglob('*'):
    if source.is_file():
        target=Path.home()/'.terminfo'/source.relative_to(root/'fixtures/terminfo')
        if target.exists() and target.read_bytes()!=source.read_bytes():
            raise SystemExit('refusing to replace terminal entry')
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(source.read_bytes())
print('30 hash-bound benign controls staged; no workload executed')
PY
"""
    setup = setup.replace("GUEST_ROOT", repr(manifest["guest_root"]))
    setup = setup.replace("PAYLOAD", repr(base64.b64encode((attempt / "payload.tgz").read_bytes()).decode()))
    setup = setup.replace("EXPECTED", repr(workloads.allocation.digest(attempt / "payload.tgz")))
    (attempt / "setup_guest.sh").write_text(setup)
    native.write_json(attempt / "protocol.json", {
        "scope": "Thirty changed benign workloads only; no malware, collection or model fitting.",
        "collection_ready": False, "malware_executions": 0, "production_hashes": helper.PINNED,
        "manifest_sha256": workloads.allocation.digest(attempt / "manifest.json"),
        "payload_sha256": workloads.allocation.digest(attempt / "payload.tgz"),
        "setup_sha256": workloads.allocation.digest(attempt / "setup_guest.sh")})
    return attempt, manifest


def execute(attempt, manifest):
    helper.verify_production()
    initial = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
    if initial["guest"]["VMState"] != '"poweroff"' or initial["sink"]["VMState"] != '"running"':
        raise ValueError("guest must be off and isolated Sink running")
    competing = subprocess.run(["pgrep", "-af", "[v]box_malware_batch|[s]tage_versioned_runner|[r]un_versioned_cohorts|[r]un_readiness.py"],
                               capture_output=True, text=True, check=False)
    if competing.returncode != 1:
        raise ValueError("competing collection or process check failed")
    native.write_json(attempt / "initial_vm_state.json", initial)
    for name, expected in manifest["inputs"].items():
        if workloads.allocation.digest(STUDY / name) != expected:
            raise ValueError("frozen input changed: " + name)
    protocol = json.loads((attempt / "protocol.json").read_text())
    for name, key in (("manifest.json", "manifest_sha256"), ("payload.tgz", "payload_sha256"),
                      ("setup_guest.sh", "setup_sha256")):
        if workloads.allocation.digest(attempt / name) != protocol[key]:
            raise ValueError("staging input changed")
    with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-heldout-auth-") as password:
        os.chmod(password.name, 0o600)
        password.write(helper.credentials())
        password.flush()
        auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
        try:
            print("Staging changed benign controls in a fresh isolated snapshot", flush=True)
            with (attempt / "staging.log").open("w") as log:
                subprocess.run(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
                                "--vm", helper.VM, "--guest-user", helper.GUEST_USER,
                                "--baseline-snapshot", helper.BASELINE, "--new-snapshot", manifest["snapshot"],
                                "--schema-version", helper.SCHEMA, "--guest-setup", str(attempt / "setup_guest.sh")],
                               stdout=log, stderr=subprocess.STDOUT, cwd=STUDY, check=True)
            staged = helper.isolated(helper.VM)
            if staged["CurrentSnapshotName"] != '"' + manifest["snapshot"] + '"':
                raise ValueError("staged snapshot differs")
            native.write_json(attempt / "staged_snapshot.json", staged)
            with (attempt / "guest_ready.log").open("w") as log:
                for probe in range(3):
                    waiter = subprocess.Popen(["VBoxManage", "guestproperty", "wait", helper.VM,
                                               "/VirtualBox/GuestInfo/OS/LoggedInUsers", "--timeout", "120000",
                                               "--fail-on-timeout"], stdout=log, stderr=subprocess.STDOUT)
                    try:
                        if probe == 0:
                            helper.vbox("startvm", helper.VM, "--type", "headless")
                        if waiter.wait(timeout=150):
                            raise RuntimeError("guest login event timed out")
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
                    raise RuntimeError("Guest Control not ready")
            print("Running only the 30 changed benign guest workloads", flush=True)
            result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                                 "--wait-stdout", "--wait-stderr", "--timeout", "900000", "--",
                                 manifest["guest_root"] + "/guest_check.py", check=False)
            (attempt / "guest_preflight.log").write_text(result.stdout + result.stderr)
            helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth,
                        manifest["guest_root"] + "/guest_preflight.json", str(attempt / "guest_preflight.json"))
            report = json.loads((attempt / "guest_preflight.json").read_text())
            if {row["case_id"]: row["sha256"] for row in report["cases"]} != {
                    row["case_id"]: row["sha256"] for row in manifest["cases"]}:
                raise ValueError("guest result identities differ")
            helper.verify_production()
            print(json.dumps({"attempt": str(attempt), "status": report["status"],
                              "accepted": report["accepted"], "total": report["total"]}), flush=True)
            if result.returncode or report["status"] != "accepted" or report["accepted"] != 30:
                raise RuntimeError("changed benign guest workloads did not all pass")
        finally:
            if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                helper.vbox("controlvm", helper.VM, "poweroff")
            helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
            final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
            native.write_json(attempt / "final_vm_state.json", final)
            if (final["guest"]["VMState"] != '"poweroff"'
                    or final["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"'):
                raise RuntimeError("cleanup did not restore original powered-off snapshot")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host_attempt", type=Path)
    parser.add_argument("--execute-benign-checks", action="store_true")
    args = parser.parse_args()
    with (workloads.allocation.prepare_inventory.PREPARATION / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt, manifest = freeze(args.host_attempt.resolve())
        print(json.dumps({"attempt": str(attempt), "cases": 30, "collection_ready": False}), flush=True)
        if args.execute_benign_checks:
            try:
                execute(attempt, manifest)
            except Exception as error:
                native.write_json(attempt / "failure.json", {"error": str(error), "collection_ready": False,
                                                           "malware_executions": 0})
                raise


if __name__ == "__main__":
    main()