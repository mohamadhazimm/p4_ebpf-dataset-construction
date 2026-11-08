#!/usr/bin/env python3
"""Export hash-allowlisted source archives; never launch a sample or collector."""

import argparse
import fcntl
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from audit_original_cohorts import ORIGINAL, ROOT, STUDY, digest, elf_header, identity, inspect_member


SOURCE_SNAPSHOT = "clean-malware-training-staged-20261017"
GUEST_SOURCE = "/home/csci/Downloads/model training"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def helper_module():
    path = ROOT.parent / "cohort-100x100-v18-20261021/redesign-native-x64/run_readiness.py"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("source_export_access", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def guest_code(names, destination):
    return f"""import hashlib,json,tarfile,io
from pathlib import Path
root=Path({GUEST_SOURCE!r})
names={names!r}
records=[]
missing=[]
total=0
for name in names:
    path=root/name
    if path.is_symlink(): raise ValueError('source symlink refused')
    if not path.is_file():
        missing.append(name)
        continue
    size=path.stat().st_size
    total+=size
    if size>{MAX_ARCHIVE} or total>{MAX_TOTAL}: raise ValueError('source size bound exceeded')
    checksum=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1048576),b''): checksum.update(chunk)
    records.append({{'sample':name,'archive_sha256':checksum.hexdigest(),'archive_bytes':size}})
index={{'source_directory':str(root),'requested':len(names),'present':len(records),'missing':missing,'archives':records}}
with tarfile.open({destination!r},'x') as bundle:
    for row in records: bundle.add(root/row['sample'],arcname=row['sample'],recursive=False)
    data=json.dumps(index,sort_keys=True).encode()
    member=tarfile.TarInfo('source_index.json');member.size=len(data);member.mode=0o600
    bundle.addfile(member,io.BytesIO(data))
print(json.dumps({{'requested':len(names),'present':len(records),'missing':len(missing),'bytes':total}}))
"""


def unpack_sources(bundle_path, output, names):
    with tarfile.open(bundle_path, "r:") as bundle:
        members = bundle.getmembers()
        if len({member.name for member in members}) != len(members):
            raise ValueError("Duplicate transport member")
        if any(not member.isfile() or member.name not in set(names) | {"source_index.json"}
               or member.size > MAX_ARCHIVE for member in members):
            raise ValueError("Unexpected transport member")
        if sum(member.size for member in members) > MAX_TOTAL + MAX_ARCHIVE:
            raise ValueError("Transport size bound exceeded")
        with bundle.extractfile("source_index.json") as stream:
            index = json.load(stream)
        records = index["archives"]
        if len(records) != len({row["sample"] for row in records}):
            raise ValueError("Duplicate source index")
        expected = {row["sample"] for row in records}
        if (expected | set(index["missing"]) != set(names) or expected & set(index["missing"])
                or {member.name for member in members} != expected | {"source_index.json"}):
            raise ValueError("Source index and allowlist differ")
        output.mkdir()
        for row in records:
            path = output / row["sample"]
            with bundle.extractfile(row["sample"]) as stream, path.open("xb") as target:
                while chunk := stream.read(1024 * 1024):
                    target.write(chunk)
            path.chmod(0o600)
            if path.stat().st_size != row["archive_bytes"] or digest(path) != row["archive_sha256"]:
                raise ValueError("Source copy differs from guest hash")
        return index


def inspect_source(path, expected):
    with path.open("rb") as stream:
        prefix = stream.read(1024 * 1024)
    if prefix.startswith(b"\x7fELF"):
        if digest(path) != expected:
            raise ValueError("Raw ELF source hash differs from sample identity")
        return {**elf_header(prefix), "member_sha256": expected,
                "member_bytes": path.stat().st_size, "source_format": "raw_elf"}
    return {**inspect_member(path, expected), "source_format": "archive"}


def review_sources(attempt, output_name="source_recovery.json"):
    index = json.loads((attempt / "guest_source_index.json").read_text())
    frozen = json.loads((ORIGINAL / "collection_manifest.json").read_text())
    details = frozen["cohorts"]["malware-training-535"]
    manifest = ORIGINAL / details["manifest"]
    if digest(manifest) != details["manifest_sha256"]:
        raise ValueError("Original allowlist changed")
    names = set(manifest.read_text().splitlines())
    if ({row["sample"] for row in index["archives"]} | set(index["missing"]) != names
            or len(index["archives"]) != len({row["sample"] for row in index["archives"]})):
        raise ValueError("Saved index and original allowlist differ")
    results = []
    for number, row in enumerate(index["archives"], 1):
        path = attempt / "archives" / row["sample"]
        if path.is_symlink() or not path.is_file() or digest(path) != row["archive_sha256"]:
            raise ValueError("Copied source hash changed")
        record = {**row, "sha256": identity(row["sample"]),
                  "source_archive_path": str(path.relative_to(STUDY))}
        try:
            record.update(inspect_source(path, record["sha256"]), source_member_verified=True)
        except ValueError as error:
            record.update(source_member_verified=False, inspection_error=str(error))
        results.append(record)
        if number % 100 == 0:
            print("SOURCE HEADERS", number, "of", len(index["archives"]), flush=True)
    report = {"status": "source_export_and_header_review_complete", "collection_ready": False,
              "collection_started": False, "sample_executions": 0, "model_fits": 0,
              "vm_operation": "authorized source export only; original clean powered-off state restored",
              "manifest_sha256": digest(manifest), "exporter_sha256": digest(Path(__file__)),
              "transport_sha256": digest(attempt / "source-archives.tar"), "source_snapshot": SOURCE_SNAPSHOT,
              "guest_source_index_sha256": digest(attempt / "guest_source_index.json"),
              "final_vm_state_sha256": digest(attempt / "final_vm_state.json"),
              "requested": 535, "recovered": len(results), "missing": index["missing"],
              "sources": results}
    save(attempt / output_name, report)
    print(json.dumps({"attempt": str(attempt), "recovered": len(results), "missing": len(index["missing"]),
                      "verified_members": sum(row["source_member_verified"] for row in results)}, indent=2))


def check_competitors():
    blocked = {"vbox_malware_batch.sh", "run_versioned_cohorts_20261017.sh",
               "stage_versioned_runner_snapshot.sh", "run_i386_holdout_collection.py", "run_readiness.py"}
    for path in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            arguments = path.read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if any(Path(os.fsdecode(argument)).name in blocked for argument in arguments if argument):
            raise ValueError("Competing collection/staging process: " + path.parent.name)


def wait_guest(helper, auth, log_path):
    with log_path.open("x") as log:
        for probe in range(3):
            waiter = subprocess.Popen(["VBoxManage", "guestproperty", "wait", helper.VM,
                "/VirtualBox/GuestInfo/OS/LoggedInUsers", "--timeout", "120000", "--fail-on-timeout"],
                stdout=log, stderr=subprocess.STDOUT)
            try:
                if probe == 0:
                    helper.vbox("startvm", helper.VM, "--type", "headless")
                if waiter.wait(timeout=150):
                    raise ValueError("Guest login event timed out")
            finally:
                if waiter.poll() is None:
                    waiter.terminate()
                    waiter.wait()
            result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/bin/true",
                "--wait-stdout", "--wait-stderr", "--timeout", "5000", "--", check=False)
            log.write(result.stdout + result.stderr)
            log.flush()
            if result.returncode == 0:
                return
        raise ValueError("Guest Control not ready after bounded login events")


def export():
    helper = helper_module()
    helper.verify_production()
    frozen = json.loads((ORIGINAL / "collection_manifest.json").read_text())
    details = frozen["cohorts"]["malware-training-535"]
    manifest = ORIGINAL / details["manifest"]
    if digest(manifest) != details["manifest_sha256"]:
        raise ValueError("Original allowlist changed")
    names = manifest.read_text().splitlines()
    if len(names) != 535 or len(set(names)) != 535:
        raise ValueError("Original allowlist differs")
    for name in names:
        identity(name)
        if Path(name).name != name:
            raise ValueError("Non-basename source entry")
    attempt = ROOT / "source-recovery" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        if (before["guest"]["VMState"] != '"poweroff"' or before["sink"]["VMState"] != '"running"'
                or before["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"'):
            raise ValueError("Expected original clean powered-off guest and running isolated Sink")
        save(attempt / "initial_vm_state.json", before)
        save(attempt / "authorization.json", {
            "scope": "User approved source export only via clarification; no workloads or collection",
            "snapshot": SOURCE_SNAPSHOT, "source_directory": GUEST_SOURCE,
            "manifest_sha256": digest(manifest), "exporter_sha256": digest(Path(__file__)),
            "access_helper_sha256": digest(Path(helper.__file__)), "production_hashes": helper.PINNED,
        })
        touched = False
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-export-auth-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                touched = True
                helper.vbox("snapshot", helper.VM, "restore", SOURCE_SNAPSHOT)
                source_state = helper.isolated(helper.VM)
                if source_state["CurrentSnapshotName"] != '"' + SOURCE_SNAPSHOT + '"':
                    raise ValueError("Restored source snapshot differs")
                save(attempt / "source_snapshot.json", source_state)
                wait_guest(helper, auth, attempt / "guest-login.log")
                destination = "/tmp/hazim-original-source-export-" + attempt.name + ".tar"
                result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                    "--wait-stdout", "--wait-stderr", "--timeout", "300000", "--", "-c",
                    guest_code(names, destination), check=False)
                (attempt / "export.log").write_text(result.stdout + result.stderr)
                if result.returncode:
                    raise ValueError("Source packaging failed; inspect export.log")
                bundle = attempt / "source-archives.tar"
                helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, destination, str(bundle))
                index = unpack_sources(bundle, attempt / "archives", names)
                save(attempt / "guest_source_index.json", index)
        except Exception as error:
            save(attempt / "failure.json", {"error": str(error), "sample_executions": 0})
            raise
        finally:
            if touched:
                if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                    helper.vbox("controlvm", helper.VM, "poweroff")
                helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
                final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
                save(attempt / "final_vm_state.json", final)
                if final["guest"]["VMState"] != '"poweroff"' or final["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"':
                    raise ValueError("Source-export cleanup incomplete")
    helper.verify_production()
    review_sources(attempt)


def self_test():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for name, kind in (("../../escape.zip", "path"), ("a.zip", "symlink")):
            path = root / (kind + ".tar")
            with tarfile.open(path, "w") as bundle:
                member = tarfile.TarInfo(name)
                if kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/etc/passwd"
                bundle.addfile(member, io.BytesIO(b""))
            try:
                unpack_sources(path, root / (kind + "-output"), ["a.zip"])
            except ValueError:
                pass
            else:
                raise AssertionError("Unsafe source transport accepted")
        raw = root / "sample.triage"
        content = bytearray(64)
        content[:6] = b"\x7fELF\x01\x01"
        content[16:20] = b"\x02\x00\x03\x00"
        content[42:44] = b"\x20\x00"
        raw.write_bytes(content)
        inspected = inspect_source(raw, digest(raw))
        assert inspected["mode"] == "native_i386_static" and inspected["source_format"] == "raw_elf"
        try:
            inspect_source(raw, "0" * 64)
        except ValueError:
            pass
        else:
            raise AssertionError("Wrong raw ELF identity accepted")
    compile(guest_code(["a" * 64 + ".zip"], "/tmp/export-test.tar"), "<guest-source-packaging>", "exec")
    with tempfile.TemporaryDirectory() as temporary:
        responses = iter([SimpleNamespace(returncode=0, stdout="", stderr=""),
                          SimpleNamespace(returncode=1, stdout="", stderr="not yet logged in"),
                          SimpleNamespace(returncode=0, stdout="", stderr="")])
        helper = SimpleNamespace(VM="test", vbox=lambda *arguments, **keywords: next(responses))
        with patch("subprocess.Popen") as process:
            process.return_value.wait.return_value = 0
            process.return_value.poll.return_value = 0
            wait_guest(helper, [], Path(temporary) / "login.log")
            assert process.call_count == 2
    print("PASS: transport safety, raw ELF identity/mode, packaging syntax and early-login-event regression; no VM operation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--export-sources", action="store_true")
    parser.add_argument("--inspect-recovered", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.inspect_recovered:
        review_sources(args.inspect_recovered.resolve(), "source_verification.json")
    elif args.export_sources:
        export()
    else:
        parser.error("Choose --self-test, --inspect-recovered or explicitly authorized --export-sources")


if __name__ == "__main__":
    main()