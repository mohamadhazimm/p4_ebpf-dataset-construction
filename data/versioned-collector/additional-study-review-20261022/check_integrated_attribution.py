#!/usr/bin/env python3
"""Freeze and rehearse the new collector using four allowlisted benign tasks."""

import argparse
import base64
import csv
import fcntl
import hashlib
import io
import json
import math
import os
import signal
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import integrated_attribution as integration


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]


def expect(condition, message):
    if not condition:
        raise ValueError(message)


def runner_command(root, case, password_files):
    return ["/usr/bin/python3", str(root / "integrated_runner.py"), str(root / case["binary"]),
            "--allow-execution", "--output-dir", str(root / ("output-" + case["mode"])),
            "--sample-args-file", str(root / (case["mode"] + "-args.json")),
            "--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--fixed-observation",
            "--common-launch-wrapper", "--packet-capture-password-file", str(password_files[0]),
            "--ebpf-password-file", str(password_files[1])]


def audit_run(directory, manifest, case):
    metadata = json.loads((directory / "run.json").read_text())
    expect(metadata["telemetry_schema_version"] == integration.SCHEMA and metadata["malware_runner_sha256"] == manifest["files"]["integrated_runner.py"], "Candidate schema/hash differs")
    expect(metadata["return_code"] == 0 and metadata["collection_quality_status"] == "accepted", "Integrated run or collection quality failed")
    expect(metadata["ebpf_status"] == "active" and metadata["packet_capture_status"] == "active", "Original sensors inactive")
    expect(metadata["target_exec"]["status"] == "observed" and metadata["target_exec"]["match"] == "exact", "Exact target exec missing")
    expect(metadata["ebpf_lost_event_count"] == 0 and metadata["packet_capture_counter_discrepancy"] == 0 and metadata["packet_capture_dropped_by_kernel"] == 0, "Original sensor losses")
    expect(metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"], "Capture buffer not restored")
    expect(metadata["attribution"]["status"] == "accepted" and metadata["attribution"]["temporary_cgroup_removed"], "Attribution or cleanup failed")
    rows = [json.loads(line) for line in (directory / "attribution.jsonl").read_text().splitlines()]
    facts = integration.audit_records(rows)
    events = [row for row in rows if row.get("record") == "observation"]
    expect({row["pid"] for row in events if row["kind"] in (1, 2, 9, 10, 22)} == {metadata["sample_root_pid"]}, "Collector/helper or unexplained task entered attribution")
    fields = [field for group in metadata["telemetry_feature_groups"].values() for field in group]
    with (directory / "telemetry.csv").open() as stream:
        telemetry = list(csv.DictReader(stream))
    expect(len(telemetry) == 40 and len(fields) == 169 and all(math.isfinite(float(row[field])) for row in telemetry for field in fields), "Telemetry contract differs")
    capture = (directory / "packet_capture.pcap").read_bytes()
    expect(capture[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"), "Not classic PCAP")
    import struct
    order = "<" if capture[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    offset, count = 24, 0
    while offset < len(capture):
        expect(offset + 16 <= len(capture), "Truncated PCAP header")
        size = struct.unpack_from(order + "I", capture, offset + 8)[0]
        offset += 16 + size
        expect(offset <= len(capture), "Truncated PCAP frame")
        count += 1
    stats = metadata["packet_capture_statistics"]
    expect(count == stats["packets_captured"] == stats["packets_received_by_filter"], "Independent PCAP count differs")
    stdout = (directory / "sample.stdout.log").read_text()
    if case["mode"] == "file":
        expect((directory / "workspace/pilot-file.bin").read_bytes() == (case["marker"] + "\n").encode() * 128, "File task output differs")
    if case["mode"] == "net":
        expect(b"200" in (directory / "workspace/pilot-http-response.bin").read_bytes().split(b"\r\n", 1)[0], "Internal HTTP response failed")
        expect(stdout.count("udp_sent,") == 6 and "done," in stdout, "Network task receipt incomplete")
        packets = [bytes.fromhex(row["snapshot_hex"]) for row in events if row["kind"] in (7, 8)]
        for index in range(6):
            marker = ("HAZIM_ATTR_" + case["marker"] + "_%03d" % index).encode()
            expect(any(marker in packet for packet in packets) and marker in capture, "Known UDP marker absent from sensor or broad PCAP")
    if case["mode"] == "null":
        expect(not any(row["kind"] in (3, 4, 5, 6, 7, 8) for row in events), "Null task unexpectedly generated socket traffic")
    if case["mode"] == "i386-hash":
        expect(stdout.split()[0].lower() == "ef46db3751d8e999" and any(row["kind"] == 22 for row in events), "i386 hash or ABI-changing return differs")
    return {"status": "accepted", "mode": case["mode"], "root_pid": metadata["sample_root_pid"],
            "feature_cells": len(telemetry) * len(fields), "pcap_records": count, **facts,
            "run_directory": str(directory), "target_sha256": integration.digest(directory.parent.parent / case["binary"])}


def guest(root):
    manifest = json.loads((root / "manifest.json").read_text())
    report = {"status": "failed_preserved", "results": [], "collection_ready": False, "malware_executions": 0, "model_fits": 0}
    try:
        for name, expected in manifest["files"].items():
            expect(integration.digest(root / name) == expected, "Frozen payload differs")
        config = {field: str(root / name) for field, name in (("sensor", "attribution-v6"), ("object", "lifecycle.bpf.o"))}
        config.update({field + "_sha256": integration.digest(config[field]) for field in ("sensor", "object")})
        config["guest_btf_sha256"] = manifest["guest_btf_sha256"]
        integration.save(root / "config.json", config)
        (root / "empty-input").write_bytes(b"")
        for case in manifest["cases"]:
            password_files = [root / ".pcap-auth", root / ".ebpf-auth"]
            for path in password_files:
                path.write_bytes((root / ".sudo-password").read_bytes())
                path.chmod(0o600)
            arguments = [str(root / "empty-input")] if case["mode"] == "i386-hash" else [case["mode"], case["marker"], "1"]
            argument_path = root / (case["mode"] + "-args.json")
            integration.save(argument_path, arguments)
            output = root / ("output-" + case["mode"])
            command = runner_command(root, case, password_files)
            with (root / (case["mode"] + "-runner.log")).open("x") as log:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                           env={**os.environ, "HAZIM_ATTRIBUTION_CONFIG": str(root / "config.json")}, start_new_session=True)
                try:
                    expect(process.wait(timeout=80) == 0, "Integrated runner failed; inspect saved log")
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=15)
            directories = list(output.iterdir())
            expect(len(directories) == 1, "Unexpected integrated run directory")
            report["results"].append(audit_run(directories[0], manifest, case))
            print("PASS integrated", case["mode"], flush=True)
        report["status"] = "accepted_four_integrated_benign_captures_not_collection_release"
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        for name in (".pcap-auth", ".ebpf-auth", ".sudo-password"):
            (root / name).unlink(missing_ok=True)
        integration.save(root / "guest_result.json", report)
        with tarfile.open(root / "evidence.tgz", "x:gz") as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file() and (path.name == "guest_result.json" or path.name.endswith("-runner.log") or path.relative_to(root).parts[0].startswith("output-")):
                    expect(not path.is_symlink(), "Unexpected evidence symlink")
                    archive.add(path, arcname=str(path.relative_to(root)), recursive=False)
    return report["status"].startswith("accepted_")


def freeze():
    from export_original_sources import helper_module
    import check_live_attribution as live
    helper = helper_module()
    helper.verify_production()
    integration.self_test(STUDY / "src/malware_runner.py")
    expect(integration.digest(live.ABI_BUILD / "result.json") == "25b0ea84623f27e76e173483fe7d405e76924ce7c3636cf25f59bcffab0d819b", "Frozen v6 build differs")
    build = json.loads((live.ABI_BUILD / "result.json").read_text())
    for name, expected in build["outputs"].items():
        expect(integration.digest(live.ABI_BUILD / name) == expected, "Frozen v6 output differs")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "integrated-collector-readiness" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    candidate = attempt / "integrated_runner.py"
    candidate.write_text(integration.generate(STUDY / "src/malware_runner.py"))
    prior = ROOT / "additional-benign-guest-readiness/20261023T065653342361Z/manifest.json"
    expect(integration.digest(prior.parent / "readiness.json") == "bc0bd754c44ee8a25077a6d2ca16eb6caa2f41df645eaa2d3bf263ef21a8d71c", "Accepted benign guest gate differs")
    binary = next(row for row in json.loads(prior.read_text())["cases"] if row["project"] == "xxhash" and row["mode"] == "native_i386_static")
    expect(integration.digest(binary["path"]) == binary["sha256"], "Accepted i386 target differs")
    control = ROOT / "attribution-pilot/20261022T101347764368Z/attribution-control"
    expect(integration.digest(control) == "da37ee8d8e49c7e864fea73593293932c5400761512bc2491db40354080c5038", "Accepted diagnostic binary differs")
    payload = {Path(__file__).name: Path(__file__), "integrated_attribution.py": Path(integration.__file__),
               candidate.name: candidate, "attribution-v6": live.ABI_BUILD / "attribution-v6",
               "lifecycle.bpf.o": live.ABI_BUILD / "lifecycle.bpf.o", "attribution-control": control, "xxhsum": Path(binary["path"])}
    manifest = {"stamp": stamp, "snapshot": "clean-integrated-" + stamp, "guest_root": "/home/csci/Downloads/integrated-" + stamp,
                "files": {name: integration.digest(path) for name, path in payload.items()}, "guest_btf_sha256": live.GUEST_BTF_SHA256,
                "cases": [{"mode": mode, "marker": "integrated_" + mode, "binary": "attribution-control"} for mode in ("null", "file", "net")]
                         + [{"mode": "i386-hash", "binary": "xxhsum"}]}
    integration.save(attempt / "manifest.json", manifest)
    with tarfile.open(attempt / "payload.tgz", "x:gz") as archive:
        for name, path in payload.items():
            archive.add(path, arcname=name, recursive=False)
        archive.add(attempt / "manifest.json", arcname="manifest.json", recursive=False)
    guest_root = manifest["guest_root"]
    setup_python = f'''import base64,hashlib,io,os,tarfile
from pathlib import Path
root=Path({guest_root!r})
assert not root.exists()
root.mkdir(mode=0o700)
data=base64.b64decode({base64.b64encode((attempt / "payload.tgz").read_bytes()).decode()!r})
assert hashlib.sha256(data).hexdigest()=={integration.digest(attempt / "payload.tgz")!r}
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    members=archive.getmembers()
    assert len(members)=={len(payload) + 1} and len({{item.name for item in members}})==len(members)
    for item in members:
        assert item.isfile() and Path(item.name).name==item.name and item.size<16*1024*1024
        path=root/item.name
        with path.open("xb") as output:output.write(archive.extractfile(item).read())
        path.chmod(0o700 if item.name in ("attribution-control","xxhsum","attribution-v6") else 0o600)
'''
    compile(setup_python, "integrated-setup", "exec")
    (attempt / "setup_guest.sh").write_text("#!/bin/bash\nset -euo pipefail\n/usr/bin/python3 - <<'PY'\n" + setup_python + "PY\n")
    subprocess.run(["bash", "-n", str(attempt / "setup_guest.sh")], check=True)
    integration.save(attempt / "protocol.json", {"schema": integration.SCHEMA, "base_runner_sha256": integration.BASE_SHA256,
        "files": {name: integration.digest(attempt / name) for name in ("manifest.json", "payload.tgz", "setup_guest.sh", "integrated_runner.py")},
        "source_hashes": {str(path): integration.digest(path) for path in payload.values()}, "collection_ready": False,
        "scope": "Four benign integrated captures only; no malware/full collection, role allocation or fitting",
        "limitations": "No general executable-inode/hash, bypass, namespace, allocator/rate/performance acceptance or study release; no compatibility merge with .18"})
    print(attempt, flush=True)
    return attempt, manifest


def execute(attempt, manifest):
    from export_original_sources import check_competitors, helper_module, wait_guest
    helper = helper_module()
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        helper.verify_production()
        check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        expect(before["guest"]["VMState"] == '"poweroff"' and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"' and before["sink"]["VMState"] == '"running"', "Need original TLS/off and isolated Sink/running")
        integration.save(attempt / "initial_vm_state.json", before)
        protocol = json.loads((attempt / "protocol.json").read_text())
        for name, expected in protocol["files"].items():
            expect(integration.digest(attempt / name) == expected, "Frozen transport differs")
        for path, expected in protocol["source_hashes"].items():
            expect(integration.digest(path) == expected, "Frozen source differs")
        try:
            with (attempt / "staging.log").open("x") as log:
                process = subprocess.Popen(["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", helper.VM,
                    "--guest-user", helper.GUEST_USER, "--baseline-snapshot", helper.BASELINE, "--new-snapshot", manifest["snapshot"],
                    "--schema-version", helper.SCHEMA, "--guest-setup", str(attempt / "setup_guest.sh")], cwd=STUDY,
                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    expect(process.wait(timeout=600) == 0, "Integration staging failed")
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=15)
            integration.save(attempt / "staged_snapshot.json", helper.isolated(helper.VM))
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-integrated-auth-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                wait_guest(helper, auth, attempt / "guest-login.log")
                protected = manifest["guest_root"] + "/.sudo-password"
                helper.vbox("guestcontrol", helper.VM, "copyto", *auth, password.name, protected)
                helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/bin/chmod", "--wait-stdout", "--wait-stderr", "--timeout", "30000", "--", "600", protected)
                response = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3", "--wait-stdout", "--wait-stderr", "--timeout", "360000", "--", manifest["guest_root"] + "/" + Path(__file__).name, "--guest", manifest["guest_root"], check=False)
                (attempt / "guest-probe.log").write_text(response.stdout + response.stderr)
                for name in ("guest_result.json", "evidence.tgz"):
                    helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, manifest["guest_root"] + "/" + name, str(attempt / name), check=False)
                expect(response.returncode == 0 and json.loads((attempt / "guest_result.json").read_text())["status"].startswith("accepted_"), "Integrated guest gate failed; preserve evidence")
        except BaseException as error:
            integration.save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error), "collection_ready": False})
            raise
        finally:
            if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                helper.vbox("controlvm", helper.VM, "poweroff")
            helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
            final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
            integration.save(attempt / "final_vm_state.json", final)
            expect(final["guest"]["VMState"] == '"poweroff"' and final["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"' and final["sink"]["VMState"] == '"running"', "Cleanup differs")
            helper.verify_production()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--guest", type=Path)
    options = parser.parse_args()
    if options.guest:
        raise SystemExit(0 if guest(options.guest.resolve()) else 2)
    elif options.self_test:
        integration.self_test(STUDY / "src/malware_runner.py")
        import sys
        from unittest.mock import patch
        sys.path.insert(0, str(STUDY))
        from tests.test_malware_runner_hostmon import malware_runner
        command = runner_command(Path("/owned"), {"mode": "null", "binary": "attribution-control"}, [Path("/owned/pcap-auth"), Path("/owned/ebpf-auth")])
        with patch.object(sys, "argv", command[1:]):
            parsed = malware_runner.parse_args()
        expect(parsed.sample == "/owned/attribution-control" and parsed.common_launch_wrapper and parsed.fixed_observation, "Real runner parser differs")
        compile(Path(__file__).read_text(), __file__, "exec")
        print("PASS real runner command parser and integrated guest driver syntax; no VM operation")
    else:
        attempt, manifest = freeze()
        if options.execute_benign_checks:
            signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
            execute(attempt, manifest)