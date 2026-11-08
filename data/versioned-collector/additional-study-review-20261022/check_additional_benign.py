#!/usr/bin/env python3
"""Freeze and check the approved additional benign programs in one clean guest."""

import argparse
import base64
import csv
import fcntl
import hashlib
import inspect
import io
import json
import os
import re
import signal
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import additional_benign_workloads as original
import validate_additional_benign as validation
from validate_remediation_workloads import digest, expect, save


ROOT = original.ROOT
STUDY = original.builds.shared.STUDY
HOST = ROOT / "additional-benign-workloads/20261023T065054122807Z"
HOST_SHA256 = "0c5c7a4f1c129f0e2b4060aafc6257efe88d09325b398821c9a3f5d2f16da971"


def safe_member(name):
    relative = Path(name)
    expect(bool(relative.parts) and not relative.is_absolute() and ".." not in relative.parts, "Unsafe evidence member")
    return relative


def guest_source():
    imports = "import argparse,csv,hashlib,io,json,os,re,subprocess,tarfile\nfrom pathlib import Path\nfrom types import SimpleNamespace\n"
    constants = "GRAMMAR=" + repr(original.GRAMMAR) + "\nLEXER=" + repr(original.LEXER) + "\n"
    definitions = "\n\n".join(inspect.getsource(function) for function in (digest, expect, save, original.tokens, original.fixtures, validation.xml_error))
    source = imports + constants + definitions + "\n\n" + validation.adapted_task()[1]
    source += '''
def hash_reference(content,bits):
    return manifest["xxhash_references"][str(bits)][hashlib.sha256(content).hexdigest()]

def main(root):
    global manifest,M4_I386,M4_AMD64,builds
    manifest=json.loads((root/"manifest.json").read_text())
    M4_I386=root/"dependencies/m4-i386"
    M4_AMD64=root/"dependencies/m4-amd64"
    builds=SimpleNamespace(shared=SimpleNamespace(NATIVE=root/"support"))
    report={"status":"running","results":[],"collection_ready":False,"bpf_loaded":False,"malware_executions":0,"model_fits":0,"generated_outputs_compiled_in_guest":False}
    try:
        for name,expected in manifest["payload_hashes"].items():
            expect(digest(root/name)==expected,"Guest payload differs: "+name)
        for case in manifest["cases"]:
            row=dict(case,path=str(root/case["payload_path"]))
            try:
                result=task(row,root/(row["project"]+"-"+row["mode"]),compile_generated=False)
            except Exception as error:
                result={"status":"failed_preserved","unit":row["unit"],"mode":row["mode"],"error":type(error).__name__+": "+str(error)}
            report["results"].append(result)
            print(result["status"],row["unit"],row["mode"],flush=True)
        expect(all(digest(root/name)==expected for name,expected in manifest["payload_hashes"].items()),"Guest input changed")
        report["status"]="accepted_guest_tasks_host_generated_output_checks_pending" if all(row["status"]=="accepted" for row in report["results"]) else "failed_preserved"
    except Exception as error:
        report.update(status="failed_preserved",error=type(error).__name__+": "+str(error))
        raise
    finally:
        save(root/"guest_validation.json",report)
        with tarfile.open(root/"evidence.tgz","x:gz") as archive:
            archive.add(root/"guest_validation.json",arcname="guest_validation.json",recursive=False)
            for case in manifest["cases"]:
                work=root/(case["project"]+"-"+case["mode"])
                if work.is_dir():
                    for path in sorted(work.rglob("*")):
                        expect(not path.is_symlink(),"Unexpected task symlink")
                        if path.is_file():archive.add(path,arcname=str(path.relative_to(root)),recursive=False)
    return report["status"]!="failed_preserved"

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("root",type=Path)
    raise SystemExit(0 if main(parser.parse_args().root.resolve()) else 2)
'''
    compile(source, "frozen-additional-benign-guest", "exec")
    return source


def freeze():
    expect(digest(HOST / "result.json") == HOST_SHA256, "Accepted host task report changed")
    host = json.loads((HOST / "result.json").read_text())
    protocol = json.loads((HOST / "protocol.json").read_text())
    expect(host["status"] == "accepted_host_tasks_guest_pending" and len(host["results"]) == 24, "Need all24 host tasks")
    for name, expected in protocol["input_hashes"].items():
        expect(digest(Path(name)) == expected, "Host input changed: " + name)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "additional-benign-guest-readiness" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    driver = attempt / Path(__file__).name
    with driver.open("x") as output:
        output.write(guest_source())
    rows = protocol["executables"]
    payload = {driver.name: driver, "dependencies/m4-amd64": original.M4_AMD64, "dependencies/m4-i386": original.M4_I386}
    library_root = original.builds.shared.NATIVE / "build-tools/root/usr/lib/x86_64-linux-gnu"
    libraries = list(library_root.glob("libsigsegv.so.2*"))
    expect(bool(libraries), "Missing scoped m4 runtime dependency")
    for path in libraries:
        payload["support/build-tools/root/usr/lib/x86_64-linux-gnu/" + path.name] = path.resolve()
    cases = []
    for row in rows:
        source = Path(row["path"])
        expect(digest(source) == row["sha256"], "Benign identity changed")
        prefix = "binaries/" + row["project"] + "-" + row["mode"]
        relative = prefix + ("/src/" if row["project"] == "bison" else "/") + source.name
        expect(relative not in payload, "Duplicate payload target")
        payload[relative] = source
        if row["project"] == "bison":
            data = source.parent.parent / "data"
            for path in sorted(data.rglob("*")):
                if path.is_file():
                    expect(not path.is_symlink(), "Unresolved Bison data symlink")
                    payload[prefix + "/data/" + str(path.relative_to(data))] = path
        cases.append(dict(row, payload_path=relative))
    with tempfile.TemporaryDirectory(prefix="hazim-reference-fixture-") as temporary:
        content = original.fixtures(Path(temporary))
    references = {str(bits): {hashlib.sha256(body).hexdigest(): original.hash_reference(body, bits) for body in (b"", b"abc", content)} for bits in (32, 64)}
    manifest = {"schema": "additional-benign-guest-tasks-v1", "cases": cases, "guest_root": "/home/csci/Downloads/additional-benign-" + stamp,
                "snapshot": "clean-additional-benign-" + stamp, "xxhash_references": references,
                "payload_hashes": {name: digest(path) for name, path in payload.items()},
                "scope": "24 bounded substantive benign task variants; no BPF, collection, malware, policy change or allocation",
                "generated_output_validation": "guest generates C; host compiles/exercises retrieved actual guest output, not guest compiler certification",
                "collection_ready": False, "roles_or_quotas_assigned": False}
    save(attempt / "manifest.json", manifest)
    with tarfile.open(attempt / "payload.tgz", "x:gz") as archive:
        for name, source in payload.items():
            safe_member(name)
            archive.add(source, arcname=name, recursive=False)
        data = (attempt / "manifest.json").read_bytes()
        member = tarfile.TarInfo("manifest.json")
        member.size, member.mode = len(data), 0o600
        archive.addfile(member, io.BytesIO(data))
    setup_python = '''import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(GUEST_ROOT)
data=base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest()!=EXPECTED:raise SystemExit("Changed payload or existing path")
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as archive:
    seen=set()
    for member in archive:
        relative=Path(member.name)
        if not member.isfile() or member.name in seen or relative.is_absolute() or ".." in relative.parts:raise SystemExit("Unsafe payload")
        seen.add(member.name)
        path=root/relative
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(archive.extractfile(member).read())
        path.chmod(0o755 if member.mode & 0o111 else 0o600)
print("Additional benign payload staged; no target executed")
'''
    setup_python = setup_python.replace("GUEST_ROOT", repr(manifest["guest_root"])).replace("PAYLOAD", repr(base64.b64encode((attempt / "payload.tgz").read_bytes()).decode())).replace("EXPECTED", repr(digest(attempt / "payload.tgz")))
    compile(setup_python, "additional-benign-setup", "exec")
    with (attempt / "setup_guest.sh").open("x") as output:
        output.write("#!/usr/bin/env bash\nset -euo pipefail\n/usr/bin/python3 - <<'PY'\n" + setup_python + "\nPY\n")
    subprocess.run(["bash", "-n", str(attempt / "setup_guest.sh")], check=True)
    inputs = dict(protocol["input_hashes"])
    inputs.update({str(path): digest(path) for path in (Path(__file__), ROOT / "export_original_sources.py", ROOT / "check_remediation_guest.py", HOST / "result.json", HOST / "protocol.json")})
    save(attempt / "protocol.json", {"scope": manifest["scope"], "frozen_before_guest_execution": True,
         "source_hashes": inputs, "payload_source_hashes": {str(path): digest(path) for path in payload.values()},
         "hashes": {name: digest(attempt / name) for name in ("manifest.json", "payload.tgz", "setup_guest.sh", driver.name)},
         "collection_ready": False, "generated_output_checks": manifest["generated_output_validation"],
         "failure_policy": "preserve failures, no silent retry/replacement; restore original clean TLS/off on every exit"})
    print(attempt, flush=True)
    return attempt, manifest


def evidence(attempt):
    files, total = {}, 0
    with tarfile.open(attempt / "evidence.tgz") as archive:
        for member in archive:
            safe_member(member.name)
            total += member.size
            expect(member.isfile() and member.name not in files and 0 <= member.size <= 32 * 1024 * 1024 and total <= 64 * 1024 * 1024 and len(files) < 1500, "Unsafe or excessive guest evidence")
            files[member.name] = archive.extractfile(member).read()
    expect(files["guest_validation.json"] == (attempt / "guest_validation.json").read_bytes(), "Retrieved and archived reports differ")
    return files


def audit(attempt, manifest):
    protocol = json.loads((attempt / "protocol.json").read_text())
    for group in ("source_hashes", "payload_source_hashes"):
        for name, expected in protocol[group].items():
            expect(digest(Path(name)) == expected, "Frozen input changed")
    for name, expected in protocol["hashes"].items():
        expect(digest(attempt / name) == expected, "Frozen payload changed")
    files = evidence(attempt)
    guest = json.loads(files["guest_validation.json"])
    expect(guest["status"] == "accepted_guest_tasks_host_generated_output_checks_pending" and len(guest["results"]) == 24, "Guest task failures remain preserved")
    cases = {(row["unit"], row["mode"]): row for row in manifest["cases"]}
    seen, checked, compiled = set(), 0, []
    for result in guest["results"]:
        identity = result["unit"], result["mode"]
        expect(identity in cases and identity not in seen and result["status"] == "accepted", "Unexpected guest case")
        seen.add(identity)
        row = cases[identity]
        expect(result["executable_sha256"] == row["sha256"], "Guest identity differs")
        prefix = row["project"] + "-" + row["mode"] + "/"
        for name, expected in dict(result["inputs"], **result["outputs"]).items():
            expect(Path(name).name == name and hashlib.sha256(files[prefix + name]).hexdigest() == expected, "Guest artifact differs")
            checked += 1
        for index, receipt in enumerate(result["receipts"]):
            expect(receipt["executable"] == manifest["guest_root"] + "/" + row["payload_path"] and receipt["role"] == "target" and receipt["returncode"] == receipt["expected_returncode"], "Unexpected guest command/return/helper")
            for stream in ("stdout", "stderr"):
                expect(hashlib.sha256(files[prefix + "%s-%02d.bin" % (stream, index)]).hexdigest() == receipt[stream + "_sha256"], "Guest command receipt differs")
            expect(json.loads(files[prefix + "command-%02d.json" % index]) == receipt, "Persistent command receipt differs")
        if row["project"] == "expat":
            expect([receipt["returncode"] for receipt in result["receipts"]] == [0, 2] and validation.xml_error(files[prefix + "stdout-01.bin"], files[prefix + "stderr-01.bin"]), "XML rejection contract differs")
        if row["project"] in {"indent", "byacc", "bison", "flex"}:
            with tempfile.TemporaryDirectory(prefix="hazim-guest-generated-") as temporary:
                work = Path(temporary)
                name = "formatted.c" if row["project"] == "indent" else "generated.c"
                (work / name).write_bytes(files[prefix + name])
                build = subprocess.run(["/usr/bin/gcc", name, "-o", "verified"], cwd=work, stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
                expect(build.returncode == 0, "Retrieved generated output fails compilation")
                result_run = subprocess.run([str(work / "verified")], cwd=work, input=b"alpha 12 beta 30 gamma 7\n" if row["project"] == "flex" else b"", capture_output=True, timeout=20, check=False)
                expected = b"3 3 49\n" if row["project"] == "flex" else b"" if row["project"] == "indent" else b"23\n"
                expect(result_run.returncode == 0 and result_run.stdout == expected, "Retrieved generated output semantics differ")
                compiled.append({"unit": row["unit"], "mode": row["mode"], "source_sha256": digest(work / name), "compiled_sha256": digest(work / "verified"), "stdout_sha256": hashlib.sha256(result_run.stdout).hexdigest(), "checked_on": "host, not guest"})
    expect(len(seen) == 24 and len(compiled) == 8, "Incomplete guest/generated output population")
    return {"status": "accepted_24_benign_guest_tasks_and_host_generated_output_checks", "guest_variants": 24,
            "independent_program_units": 12, "archive_regular_members": len(files), "artifact_hashes_checked": checked,
            "generated_outputs_compiled_and_exercised_on_host": compiled, "host_compiler_sha256": digest(Path("/usr/bin/gcc")),
            "guest_report_sha256": digest(attempt / "guest_validation.json"), "evidence_sha256": digest(attempt / "evidence.tgz"),
            "collection_ready": False, "malware_executions": 0, "bpf_loaded": False, "model_fits": 0,
            "limits": "Direct benign task checks, not sensor/collection/new-schema acceptance; variants are not independent units; no prospective roles/quotas"}


def execute(attempt, manifest):
    from export_original_sources import check_competitors, helper_module, wait_guest
    helper = helper_module()
    helper.verify_production()
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        expect(before["guest"]["VMState"] == '"poweroff"' and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"' and before["sink"]["VMState"] == '"running"', "Need original clean/off and isolated running Sink")
        save(attempt / "initial_vm_state.json", before)
        protocol = json.loads((attempt / "protocol.json").read_text())
        for group in ("source_hashes", "payload_source_hashes"):
            for name, expected in protocol[group].items():
                expect(digest(Path(name)) == expected, "Source changed before staging")
        for name, expected in protocol["hashes"].items():
            expect(digest(attempt / name) == expected, "Payload changed before staging")
        try:
            with (attempt / "staging.log").open("x") as output:
                process = subprocess.Popen(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", helper.VM, "--guest-user", helper.GUEST_USER, "--baseline-snapshot", helper.BASELINE, "--new-snapshot", manifest["snapshot"], "--schema-version", helper.SCHEMA, "--guest-setup", str(attempt / "setup_guest.sh")], cwd=STUDY, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    expect(process.wait(timeout=600) == 0, "Staging failed; see saved log")
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
            staged = helper.isolated(helper.VM)
            expect(staged["CurrentSnapshotName"] == '"' + manifest["snapshot"] + '"', "Staged snapshot differs")
            save(attempt / "staged_snapshot.json", staged)
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-additional-auth-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                wait_guest(helper, auth, attempt / "guest-login.log")
                print("Executing24 bounded benign variants; no sensor or malware", flush=True)
                result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3", "--wait-stdout", "--wait-stderr", "--timeout", "600000", "--", manifest["guest_root"] + "/" + Path(__file__).name, manifest["guest_root"], check=False)
                (attempt / "guest-check.log").write_text(result.stdout + result.stderr)
                for name in ("guest_validation.json", "evidence.tgz"):
                    copied = helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, manifest["guest_root"] + "/" + name, str(attempt / name), check=False)
                    expect(copied.returncode == 0, "Guest evidence retrieval failed: " + name)
                expect(result.returncode == 0, "Guest tasks failed; preserve evidence")
            helper.verify_production()
        except BaseException as error:
            save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error), "collection_ready": False})
            raise
        finally:
            if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                helper.vbox("controlvm", helper.VM, "poweroff")
            helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
            final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
            save(attempt / "final_vm_state.json", final)
            expect(final["guest"]["VMState"] == '"poweroff"' and final["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"' and final["sink"]["VMState"] == '"running"', "Guest/Sink cleanup differs")
    save(attempt / "readiness.json", audit(attempt, manifest))


def self_test():
    validation.self_test()
    source = guest_source()
    namespace = {"__name__": "frozen_guest_self_test"}
    exec(compile(source, "frozen-guest-test", "exec"), namespace)
    with tempfile.TemporaryDirectory(prefix="hazim-guest-fixture-") as temporary:
        payload = namespace["fixtures"](Path(temporary))
        expect(hashlib.sha256(payload).hexdigest() == hashlib.sha256(bytes(range(256)) * 128 + b"owned compression fixture\n" * 1024).hexdigest(), "Guest fixture differs")
    for name in ("../escape", "/absolute", ""):
        try:
            safe_member(name)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe evidence path accepted")
    print("PASS generated guest task/fixture syntax and evidence path guards; no VM or target execution")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--audit-saved", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    elif options.audit_saved:
        attempt = options.audit_saved.resolve()
        save(attempt / ("validation-derived-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"), audit(attempt, json.loads((attempt / "manifest.json").read_text())))
    else:
        attempt, manifest = freeze()
        if options.execute_benign_checks:
            signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
            execute(attempt, manifest)