#!/usr/bin/env python3
"""Freeze four benign guest checks and read kernel capabilities without BPF load."""

import argparse
import base64
import datetime
import fcntl
import hashlib
import io
import json
import os
import platform
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import validate_remediation_workloads as tasks


ROOT = Path(__file__).resolve().parent
HOST = ROOT / "remediation-workload-readiness/20261022T125709447491Z"
STUDY = ROOT.parents[2]
HOOKS = {"sock_sendmsg": 2, "sock_recvmsg": 3, "fd_install": 2,
         "filp_close": 2, "__fput": 1, "sock_release": 1, "close_files": 1,
         "kmem_cache_free": 2, "put_files_struct": 1,
         "security_file_receive": 1, "security_socket_post_create": 5,
         "security_socket_accept": 2, "security_socket_connect": 3}


def btf_functions(data):
    tasks.expect(len(data) >= 24, "Short BTF")
    magic, version, flags, header, type_offset, type_length, string_offset, string_length = struct.unpack_from("<HBBIIIII", data)
    tasks.expect((magic, version, flags) == (0xeb9f, 1, 0) and header >= 24, "Unsupported BTF")
    types_start, strings_start = header + type_offset, header + string_offset
    types_end, strings_end = types_start + type_length, strings_start + string_length
    tasks.expect(types_end <= len(data) and strings_end <= len(data), "BTF bounds differ")
    strings = data[strings_start:strings_end]

    def name(offset):
        tasks.expect(offset < len(strings), "BTF string outside table")
        return strings[offset:strings.index(b"\0", offset)].decode("ascii")

    records, position = [None], types_start
    while position < types_end:
        tasks.expect(position + 12 <= types_end, "Truncated BTF type")
        label, info, target = struct.unpack_from("<III", data, position)
        kind, count = (info >> 24) & 31, info & 65535
        extra = {1: 4, 2: 0, 3: 12, 4: count * 12, 5: count * 12,
                 6: count * 8, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0,
                 13: count * 8, 14: 4, 15: count * 12, 16: 0, 17: 4,
                 18: 0, 19: count * 12}.get(kind)
        tasks.expect(extra is not None and position + 12 + extra <= types_end, "Unsupported or truncated BTF kind")
        parameters = []
        if kind == 13:
            for index in range(count):
                label_offset, type_id = struct.unpack_from("<II", data, position + 12 + index * 8)
                parameters.append({"name": name(label_offset), "type_id": type_id})
        records.append({"name": name(label), "kind": kind, "target": target, "parameters": parameters})
        position += 12 + extra
    tasks.expect(position == types_end, "BTF type alignment differs")

    def describe(type_id, seen=()):
        tasks.expect(type_id < len(records) and type_id not in seen, "Invalid BTF reference")
        if type_id == 0:
            return "void"
        record = records[type_id]
        if record["kind"] == 2:
            return describe(record["target"], seen + (type_id,)) + "*"
        if record["kind"] in (8, 9, 10, 11, 18):
            return describe(record["target"], seen + (type_id,))
        return record["name"] or "kind-" + str(record["kind"])

    result = {}
    for record in records[1:]:
        if record["kind"] == 12 and record["name"] in HOOKS:
            prototype = records[record["target"]]
            tasks.expect(prototype["kind"] == 13, "Function without prototype")
            parameters = [{**parameter, "type": describe(parameter["type_id"])} for parameter in prototype["parameters"]]
            result[record["name"]] = {"parameters": parameters, "return_type": describe(prototype["target"]),
                                      "expected_parameter_count": HOOKS[record["name"]],
                                      "count_matches": len(parameters) == HOOKS[record["name"]]}
    return result


def guest_check(root):
    manifest = json.loads((root / "manifest.json").read_text())
    for name, expected in manifest["payload_hashes"].items():
        tasks.expect(tasks.digest(root / name) == expected, "Guest payload changed: " + name)
    report = {"status": "running", "results": [], "collection_ready": False,
              "bpf_loaded": False, "hooks_attached": False, "malware_executions": 0, "model_fits": 0}
    try:
        report["kernel"] = platform.uname()._asdict()
        btf = Path("/sys/kernel/btf/vmlinux")
        report["btf"] = {"available": btf.is_file()}
        if btf.is_file():
            content = btf.read_bytes()
            report["btf"].update({"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content), "functions": btf_functions(content)})
            (root / "kernel.btf").write_bytes(content)
        report["files_cache_sysfs_present"] = Path("/sys/kernel/slab/files_cache").is_dir()
        report["cgroup_v2"] = Path("/sys/fs/cgroup/cgroup.controllers").exists()
        report["cgroup_controllers"] = Path("/sys/fs/cgroup/cgroup.controllers").read_text().split() if report["cgroup_v2"] else []
        report["capability_status"] = {name: Path("/proc/self/status").read_text().split(name + ":", 1)[1].splitlines()[0].strip() for name in ("CapEff", "CapBnd")}
        report["sysctls"] = {name: Path("/proc/sys/kernel", name).read_text().strip() for name in ("unprivileged_bpf_disabled", "perf_event_paranoid") if Path("/proc/sys/kernel", name).exists()}
        report["service_policy"] = subprocess.run(["/usr/bin/systemctl", "list-units", "--all", "--type=service", "--no-pager", "--plain"], capture_output=True, text=True, timeout=20, check=True).stdout
        report["interfaces"] = json.loads(subprocess.run(["/usr/sbin/ip", "-j", "address"], capture_output=True, text=True, timeout=10, check=True).stdout)
        environment = dict(os.environ, LC_ALL="C", HOME=str(root), OMP_NUM_THREADS="1")
        for name in ("PERL5OPT", "PERL5LIB", "PERLLIB", "MAGICK_CONFIGURE_PATH", "MAGICK_HOME", "LD_PRELOAD", "LD_LIBRARY_PATH"):
            environment.pop(name, None)
        members, pixels = tasks.fixtures(root / "inputs")
        for row in manifest["cases"]:
            row = {**row, "path": str(root / row["payload_path"])}
            report["results"].append(tasks.run_task(row, root / row["project"], root / "inputs", members, pixels, environment))
        report["reused_guest_results"] = manifest.get("reused_guest_results", [])
        report["status"] = "repair_guest_workload_accepted_kernel_inventoried_no_attachment" if report["reused_guest_results"] else "four_guest_workloads_accepted_kernel_inventoried_no_attachment"
    except Exception as error:
        report.update({"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error)})
        raise
    finally:
        tasks.save(root / "guest_validation.json", report)
        with tarfile.open(root / "evidence.tgz", "x:gz") as archive:
            for path in sorted(root.rglob("*")):
                relative = path.relative_to(root)
                if relative.parts[0] in {"inputs", "binaries"} or path.name in {"evidence.tgz", "manifest.json"}:
                    continue
                if path.is_file() and not path.is_symlink() and path.suffix != ".py":
                    archive.add(path, arcname=str(relative), recursive=False)


def reuse_static_guest(previous, cases):
    previous_report = previous / "guest_validation.json"
    tasks.expect(tasks.digest(previous_report) == "998117c47afb19c51c89ba271670efe9d8c21b692dfc347012e2ade73894b82e", "Prior three static guest passes changed")
    observed = json.loads(previous_report.read_text())
    manifest = json.loads((previous / "manifest.json").read_text())
    protocol = json.loads((previous / "protocol.json").read_text())
    for name, expected in protocol["hashes"].items():
        tasks.expect(tasks.digest(previous / name) == expected, "Prior static guest input changed")
    tasks.expect(manifest["payload_hashes"][Path(tasks.__file__).name] == tasks.digest(Path(tasks.__file__)), "Task semantics changed since prior guest passes")
    accepted = {row["project"] for row in observed["results"]}
    tasks.expect(accepted == {"libarchive", "perl", "imagemagick"}, "Need exactly three prior accepted tasks")
    old_cases = {row["project"]: row for row in manifest["cases"]}
    for row in cases:
        if row["project"] in accepted:
            tasks.expect(row["sha256"] == old_cases[row["project"]]["sha256"], "Reused static guest binary differs")
    with tarfile.open(previous / "evidence.tgz") as archive:
        seen = set()
        for member in archive:
            relative = Path(member.name)
            tasks.expect(member.isfile() and member.name not in seen and not relative.is_absolute() and ".." not in relative.parts, "Unsafe prior evidence")
            seen.add(member.name)
            if relative.parts[0] in accepted and relative.name == "stdout.bin":
                expected = next(row["stdout_sha256"] for row in observed["results"] if row["project"] == relative.parts[0])
                tasks.expect(hashlib.sha256(archive.extractfile(member).read()).hexdigest() == expected, "Prior accepted stdout differs")
        tasks.expect(all(project + "/stdout.bin" in seen for project in accepted), "Missing prior accepted stdout")
    return observed["results"], {"path": str(previous), "guest_report_sha256": tasks.digest(previous_report),
                                 "evidence_sha256": tasks.digest(previous / "evidence.tgz")}


def freeze(static_build=None, previous_guest=None):
    host = static_build if static_build else HOST
    result_name = "result.json" if static_build else "host_validation.json"
    report = json.loads((host / result_name).read_text())
    status = "four_static_builds_and_host_workloads_accepted_guest_pending" if static_build else "four_host_workloads_accepted_guest_and_sensor_pending"
    tasks.expect(report["status"] == status and len(report["results"]) == 4, "Need accepted four-host checks")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / ("remediation-static-guest-readiness" if static_build else "remediation-guest-readiness") / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    cases = report["executables"] if static_build else json.loads((tasks.PREPARATION / "executables.json").read_text())
    tasks.expect(len(cases) == 4 and {row["project"] for row in cases} == set(tasks.PROJECTS), "Four approved projects required")
    if static_build:
        from build_static_remediation import static_elf
        for row in cases:
            tasks.expect(static_elf(Path(row["path"])) == "native_amd64_static", "Static guest input mode differs")
    reused, evidence = [], None
    if previous_guest:
        tasks.expect(static_build is not None, "Reuse is only supported for static repair")
        reused, evidence = reuse_static_guest(previous_guest, cases)
        cases = [row for row in cases if row["project"] == "netcat-openbsd"]
    payload = {Path(tasks.__file__).name: Path(tasks.__file__), Path(__file__).name: Path(__file__)}
    for row in cases:
        source = Path(row["path"])
        tasks.expect(tasks.digest(source) == row["sha256"], "Benign identity changed")
        row["payload_path"] = "binaries/" + row["project"] + "/" + source.name
        payload[row["payload_path"]] = source
    manifest = {"cases": cases, "guest_root": "/home/csci/Downloads/remediation-benign-" + stamp,
                "snapshot": "clean-remediation-benign-" + stamp,
                "payload_hashes": {name: tasks.digest(path) for name, path in payload.items()},
                "scope": "One repaired benign netcat task, three verified prior passes and read-only capability inventory; no BPF load or collection" if reused else "Four benign direct guest workloads and read-only capability inventory; no BPF load or collection",
                "collection_ready": False, "malware_executions": 0, "bpf_loaded": False}
    manifest.update(reused_guest_results=reused, reused_guest_evidence=evidence)
    tasks.save(attempt / "manifest.json", manifest)
    with tarfile.open(attempt / "payload.tgz", "w:gz") as archive:
        for name, source in payload.items():
            archive.add(source, arcname=name, recursive=False)
        data = (attempt / "manifest.json").read_bytes()
        member = tarfile.TarInfo("manifest.json")
        member.size, member.mode = len(data), 0o600
        archive.addfile(member, io.BytesIO(data))
    setup = """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(GUEST_ROOT)
data=base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest()!=EXPECTED:
    raise SystemExit('Existing guest path or payload changed')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    seen=set()
    for member in archive:
        path=root/member.name
        if not member.isfile() or member.name in seen or not path.resolve().is_relative_to(root):
            raise SystemExit('Unsafe payload entry')
        seen.add(member.name)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(archive.extractfile(member).read())
        path.chmod(0o755 if member.mode & 0o111 else 0o600)
print('Benign repair payload staged; no target or BPF executed')
PY
"""
    setup = setup.replace("GUEST_ROOT", repr(manifest["guest_root"])).replace("PAYLOAD", repr(base64.b64encode((attempt / "payload.tgz").read_bytes()).decode())).replace("EXPECTED", repr(tasks.digest(attempt / "payload.tgz")))
    (attempt / "setup_guest.sh").write_text(setup)
    subprocess.run(["bash", "-n", str(attempt / "setup_guest.sh")], check=True)
    compile(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0], "generated-setup", "exec")
    tasks.save(attempt / "protocol.json", {"scope": manifest["scope"], "frozen_before_guest_execution": True,
               "host_protocol_sha256": tasks.digest(host / "protocol.json"), "host_result_sha256": tasks.digest(host / result_name),
               "host_result_path": str(host / result_name), "variant": "static" if static_build else "dynamic",
               "hashes": {name: tasks.digest(attempt / name) for name in ("manifest.json", "payload.tgz", "setup_guest.sh")},
               "source_hashes": {str(path): tasks.digest(path) for path in (Path(__file__), Path(tasks.__file__))},
               "failure_policy": "Preserve failures; no workload retry/replacement; always restore original clean powered-off snapshot",
               "collection_ready": False})
    print(attempt, flush=True)
    return attempt, manifest


def execute(attempt, manifest):
    from export_original_sources import check_competitors, helper_module, wait_guest
    helper = helper_module()
    helper.verify_production()
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        tasks.expect(before["guest"]["VMState"] == '"poweroff"' and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"' and before["sink"]["VMState"] == '"running"', "Expected isolated original powered-off guest and running Sink")
        tasks.save(attempt / "initial_vm_state.json", before)
        protocol = json.loads((attempt / "protocol.json").read_text())
        for name, expected in protocol["hashes"].items():
            tasks.expect(tasks.digest(attempt / name) == expected, "Frozen readiness file changed")
        try:
            print("Staging", len(manifest["cases"]), "benign identities; no collection or attachment", flush=True)
            with (attempt / "staging.log").open("x") as output:
                process = subprocess.Popen(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", helper.VM, "--guest-user", helper.GUEST_USER,
                    "--baseline-snapshot", helper.BASELINE, "--new-snapshot", manifest["snapshot"], "--schema-version", helper.SCHEMA,
                    "--guest-setup", str(attempt / "setup_guest.sh")], cwd=STUDY, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    tasks.expect(process.wait(timeout=600) == 0, "Staging failed; inspect staging.log")
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
            staged = helper.isolated(helper.VM)
            tasks.expect(staged["CurrentSnapshotName"] == '"' + manifest["snapshot"] + '"', "Staged snapshot differs")
            tasks.save(attempt / "staged_snapshot.json", staged)
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-benign-auth-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                wait_guest(helper, auth, attempt / "guest-login.log")
                print("Executing", len(manifest["cases"]), "substantive benign tasks and reading BTF capabilities", flush=True)
                result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3", "--wait-stdout", "--wait-stderr", "--timeout", "180000", "--",
                                     manifest["guest_root"] + "/" + Path(__file__).name, "--guest-check", manifest["guest_root"], check=False)
                (attempt / "guest-check.log").write_text(result.stdout + result.stderr)
                for name in ("guest_validation.json", "evidence.tgz"):
                    copied = helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, manifest["guest_root"] + "/" + name, str(attempt / name), check=False)
                    tasks.expect(copied.returncode == 0, "Guest evidence retrieval failed: " + name)
                tasks.expect(result.returncode == 0, "Guest validation failed; preserved report/log")
                guest = json.loads((attempt / "guest_validation.json").read_text())
                reused = manifest.get("reused_guest_results", [])
                expected_status = "repair_guest_workload_accepted_kernel_inventoried_no_attachment" if reused else "four_guest_workloads_accepted_kernel_inventoried_no_attachment"
                tasks.expect(guest["status"] == expected_status and len(guest["results"]) == len(manifest["cases"]), "Not all requested guest tasks passed")
                tasks.expect(len(guest["results"]) + len(reused) == 4, "Four program units not covered")
                helper.verify_production()
                tasks.save(attempt / "readiness.json", {"benign_host_tasks_accepted": 4, "benign_guest_tasks_accepted": 4,
                    "guest_tasks_executed_this_attempt": len(guest["results"]), "guest_tasks_reused": len(reused),
                    "capability_inventory_complete": True, "bpf_loaded": False, "hooks_attached": False,
                    "collection_ready": False, "new_sensor_live_validated": False, "malware_executions": 0, "model_fits": 0,
                    "guest_result_sha256": tasks.digest(attempt / "guest_validation.json"), "evidence_sha256": tasks.digest(attempt / "evidence.tgz")})
        except BaseException as error:
            tasks.save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error), "collection_ready": False, "malware_executions": 0})
            raise
        finally:
            if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                helper.vbox("controlvm", helper.VM, "poweroff")
            helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
            final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
            tasks.save(attempt / "final_vm_state.json", final)
            tasks.expect(final["guest"]["VMState"] == '"poweroff"' and final["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"', "Guest cleanup failed")


def self_test():
    strings = b"\0sock_sendmsg\0socket\0"
    records = struct.pack("<III", 14, 4 << 24, 0) + struct.pack("<III", 0, 2 << 24, 1)
    records += struct.pack("<III", 0, (13 << 24) | 2, 0) + struct.pack("<IIII", 0, 2, 0, 2)
    records += struct.pack("<III", 1, 12 << 24, 3)
    data = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(records), len(records), len(strings)) + records + strings
    parsed = btf_functions(data)
    tasks.expect(parsed["sock_sendmsg"]["count_matches"] and parsed["sock_sendmsg"]["parameters"][0]["type"] == "socket*", "BTF prototype parser failed")
    for invalid in (data[:23], data[:-1], b"xx" + data[2:]):
        try:
            btf_functions(invalid)
        except ValueError:
            continue
        raise AssertionError("Truncated BTF accepted")
    tasks.self_test()
    prior = ROOT / "remediation-static-guest-readiness/20261022T131433642524Z"
    if prior.exists():
        cases = json.loads((prior / "manifest.json").read_text())["cases"]
        reuse_static_guest(prior, cases)
        changed = [{**row, "sha256": "0" * 64} for row in cases]
        try:
            reuse_static_guest(prior, changed)
        except ValueError:
            pass
        else:
            raise AssertionError("Changed reused binary accepted")
    print("PASS: BTF signature/bounds and benign fixture guards; no VM/BPF operation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--guest-check", type=Path)
    parser.add_argument("--static-build", type=Path)
    parser.add_argument("--reuse-static-guest", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    elif options.guest_check:
        guest_check(options.guest_check.resolve())
    else:
        attempt, manifest = freeze(options.static_build.resolve() if options.static_build else None,
                       options.reuse_static_guest.resolve() if options.reuse_static_guest else None)
        if options.execute_benign_checks:
            signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
            execute(attempt, manifest)