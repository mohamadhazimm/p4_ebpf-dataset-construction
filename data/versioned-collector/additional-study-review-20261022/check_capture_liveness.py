#!/usr/bin/env python3
"""Freeze and run only the explicitly approved six V2 benign diagnostics."""

import argparse
import ast
import base64
import fcntl
import hashlib
import io
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import capture_liveness as checks
import integrated_liveness as integration
from audit_capture_liveness import audit_case


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
PREPARATION = ROOT / "remediation-preparation/20261022T122641888212Z"
V6 = PREPARATION / "attribution-exec-abi-builds/20261022T172217791905Z"
expect = checks.require


def pinned(path, expected):
    expect(checks.digest(path) == expected, "Frozen input changed: " + str(path))
    return path


def historical_fixture():
    path = pinned(ROOT / "attribution-live-capability/20261022T163150993977Z/evidence.tgz",
                  "824931d89d0b0ccb8776aec1fee778724620886a8d6e56ac40c945fa0b37b63c")
    with tarfile.open(path, "r:gz") as archive:
        receipt = json.load(archive.extractfile("workload.json"))
        packets = checks.pcap_records(archive.extractfile("interface.pcap").read())
    bodies = []
    for transaction in receipt["transactions"]:
        segments = []
        for _timestamp, frame in packets:
            if len(frame) < 54 or frame[12:14] != b"\x08\x00":
                continue
            packet = frame[14:]
            header = (packet[0] & 15) * 4
            if packet[9] != 6 or socket.inet_ntoa(packet[12:16]) != "10.0.0.1":
                continue
            source, target, sequence = struct.unpack_from("!HHI", packet, header)
            if source != 80 or target != transaction["local_endpoint"][1]:
                continue
            end = struct.unpack_from("!H", packet, 2)[0]
            offset = header + (packet[header + 12] >> 4) * 4
            segments.append((sequence, packet[header + 13], packet[offset:end]))
        origins = {sequence + 1 for sequence, flags, _data in segments if flags & 2}
        expect(len(origins) == 1, "Historical response handshake differs")
        origin = origins.pop()
        octets = {}
        for sequence, flags, data in segments:
            for index, value in enumerate(data, sequence + bool(flags & 2) - origin):
                expect(index >= 0 and (index not in octets or octets[index] == value), "Historical overlap differs")
                octets[index] = value
        expect(set(octets) == set(range(len(octets))), "Historical response gap")
        response = bytes(octets[index] for index in range(len(octets)))
        checks.reassemble(segments, response, 16384)
        body = checks.parse_response(response)
        expect(len(body) == transaction["response_size"] == 258 and
               hashlib.sha256(body).hexdigest() == transaction["response_sha256"] ==
               "f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0", "Historical fixture differs")
        bodies.append(body)
    expect(len(bodies) == 4 and len(set(bodies)) == 1, "Historical fixture is not uniquely defined")
    return bodies[0], {"source": str(path), "source_sha256": checks.digest(path),
                       "body_sha256": hashlib.sha256(bodies[0]).hexdigest(), "body_bytes": len(bodies[0]),
                       "basis": "Four accepted historical application receipts and independently reassembled Ethernet TCP responses; frozen before this guest operation"}


def build_recorder(attempt):
    report = pinned(V6 / "result.json", "25b0ea84623f27e76e173483fe7d405e76924ce7c3636cf25f59bcffab0d819b")
    original = json.loads(report.read_text())
    for path, expected in original["input_hashes"].items():
        pinned(path, expected)
    for name, expected in original["outputs"].items():
        pinned(V6 / name, expected)
    source = (V6 / "recorder.c").read_text()
    old = '    unsigned long long deadline = nanoseconds(CLOCK_MONOTONIC) + duration * 1000000000ULL;\n    fputs("{\\"record\\":\\"attached\\",\\"target_workload_launched\\":false}\\n", output);'
    new = ('    unsigned long long attached = nanoseconds(CLOCK_MONOTONIC);\n'
           '    unsigned long long deadline = attached + duration * 1000000000ULL;\n'
           '    fprintf(output, "{\\"record\\":\\"attached\\",\\"target_workload_launched\\":false,\\"monotonic_ns\\":%llu,\\"deadline_ns\\":%llu}\\n", attached, deadline);')
    expect(source.count(old) == 1 and source.count("cleanup:\n") == 1, "Frozen recorder lifecycle anchors differ")
    source = source.replace(old, new).replace("cleanup:\n", 'cleanup:\n    fprintf(output, "{\\"record\\":\\"detaching\\",\\"monotonic_ns\\":%llu}\\n", nanoseconds(CLOCK_MONOTONIC));\n    fflush(output);\n')
    (attempt / "recorder.c").write_text(source)
    headers = PREPARATION / "attribution-builds/20261022T124141961818Z/headers"
    dependencies = PREPARATION / "dependencies/root"
    libraries = dependencies / "usr/lib/x86_64-linux-gnu"
    command = ["gcc", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-I" + str(ROOT / "attribution-v1"),
               "-I" + str(headers / "include"), "-I" + str(dependencies / "usr/include"),
               str(attempt / "recorder.c"), str(headers / "lib/libbpf.a"), "-L" + str(libraries),
               "-Wl,-rpath," + str(libraries), "-lelf", "-lz", "-o", str(attempt / "attribution-diagnostic")]
    environment = {**os.environ, "LD_LIBRARY_PATH": str(libraries)}
    response = subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (attempt / "build.log").write_text(response.stdout)
    expect(response.returncode == 0, "Diagnostic recorder compilation failed")
    tested = subprocess.run([str(attempt / "attribution-diagnostic"), "--self-test"], env=environment,
                            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (attempt / "recorder-self-test.json").write_text(tested.stdout)
    inspected = subprocess.run([str(attempt / "attribution-diagnostic"), "--inspect", str(V6 / "lifecycle.bpf.o")],
                               env=environment, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (attempt / "recorder-inspection.log").write_text(inspected.stdout)
    expect(len(inspected.stdout.splitlines()) == 23, "Actual frozen BPF program inventory differs")
    return original["guest_btf_sha256"], {str(report): checks.digest(report),
                                         str(V6 / "recorder.c"): checks.digest(V6 / "recorder.c"),
                                         str(V6 / "lifecycle.bpf.o"): checks.digest(V6 / "lifecycle.bpf.o")}


def runner_command(root, case, passwords):
    return ["/usr/bin/python3", str(root / "integrated_runner.py"), str(root / "attribution-control"), "--allow-execution",
            "--output-dir", str(root / ("output-" + case["case"])), "--sample-args-file", str(root / (case["case"] + "-args.json")),
            "--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--fixed-observation", "--common-launch-wrapper",
            "--packet-capture-password-file", str(passwords[0]), "--ebpf-password-file", str(passwords[1])]


def guest(root):
    manifest = json.loads((root / "manifest.json").read_text())
    report = {"status": "failed_preserved", "schema": checks.SCHEMA, "cases": [], "collection_ready": False,
              "performance_accepted": False, "malware_executions": 0}
    process = None
    password_paths = [root / "pcap-auth", root / "ebpf-auth"]
    try:
        for name, expected in manifest["files"].items():
            pinned(root / name, expected)
        expect(checks.digest(root / "attribution-control") == checks.TARGET_SHA256, "Null target differs")
        for case in manifest["cases"]:
            checks.validate_arguments(case["target_arguments"])
            config = {"condition": case["condition"], "helper_transactions": case["helper_transactions"],
                      "target_arguments": checks.ARGUMENTS, "sensor": str(root / "attribution-diagnostic"),
                      "sensor_sha256": manifest["files"]["attribution-diagnostic"], "object": str(root / "lifecycle.bpf.o"),
                      "object_sha256": manifest["files"]["lifecycle.bpf.o"], "guest_btf_sha256": manifest["guest_btf_sha256"]}
            if case["helper_transactions"]:
                config["transaction"] = case["transaction"]
            config_path = root / (case["case"] + "-config.json")
            integration.save(config_path, config)
            integration.save(root / (case["case"] + "-args.json"), checks.ARGUMENTS)
            for path in password_paths:
                path.write_bytes((root / ".sudo-password").read_bytes())
                path.chmod(0o600)
            with (root / ("runner-" + case["case"] + ".log")).open("xb") as log:
                process = subprocess.Popen(runner_command(root, case, password_paths), stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                           env={**os.environ, "HAZIM_ATTRIBUTION_CONFIG": str(config_path)})
                expect(process.wait(timeout=80) == 0, "Diagnostic runner failed: " + case["case"])
            directories = list((root / ("output-" + case["case"])).glob("run_*"))
            expect(len(directories) == 1, "Expected exactly one diagnostic run directory")
            prefix = str(directories[0].relative_to(root))
            facts = audit_case(lambda name: (root / name).read_bytes(), prefix, manifest, case)
            report["cases"].append(facts)
            print("PASS", case["case"], facts["quality_status"], facts["pcap_records"], flush=True)
        expect(len({case["boot_id"] for case in report["cases"]}) == 1, "Diagnostic cases crossed boots")
        report["status"] = "accepted_bounded_liveness_diagnostic_not_collection_ready"
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        if process is not None and process.poll() is None:
            integration.stop_process(process, 30)
        for path in [root / ".sudo-password", *password_paths]:
            path.unlink(missing_ok=True)
        integration.save(root / "guest_result.json", report)
        with tarfile.open(root / "evidence.tgz", "x:gz") as archive:
            paths = [root / "guest_result.json", *root.glob("runner-*.log")]
            for directory in root.glob("output-*"):
                paths.extend(path for path in directory.rglob("*") if path.is_file())
            for path in paths:
                expect(not path.is_symlink() and path.stat().st_size <= 64 * 1024 * 1024, "Unsafe evidence file")
                archive.add(path, arcname=str(path.relative_to(root)), recursive=False)
    return report["status"].startswith("accepted_")


def freeze():
    from export_original_sources import helper_module
    helper = helper_module()
    helper.verify_production()
    self_test()
    specification = checks.contract()
    source_hashes = {str((ROOT / path).resolve()): expected for path, expected in specification["source_pins"].items()}
    for path, expected in source_hashes.items():
        pinned(path, expected)
    body, fixture = historical_fixture()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "capture-liveness-readiness" / stamp
    attempt.mkdir(parents=True)
    try:
        btf, build_inputs = build_recorder(attempt)
        source_hashes.update(build_inputs)
        files = {"integrated_runner.py": integration.generate(STUDY / "src/malware_runner.py").encode(),
                 "expected-body.bin": body, "expected-fixture.json": json.dumps(fixture, sort_keys=True).encode(),
                 "attribution-diagnostic": (attempt / "attribution-diagnostic").read_bytes(),
                 "lifecycle.bpf.o": (V6 / "lifecycle.bpf.o").read_bytes()}
        for name in (Path(__file__).name, "capture_liveness.py", "integrated_liveness.py", "audit_capture_liveness.py",
                     "integrated_exec_identity.py", "integrated_attribution.py", "exec_identity.py", "CAPTURE_LIVENESS_PROTOCOL_V2.md"):
            files[name] = (ROOT / name).read_bytes()
            source_hashes[str(ROOT / name)] = checks.digest(ROOT / name)
        target = pinned(ROOT / "attribution-pilot/20261022T101347764368Z/attribution-control", checks.TARGET_SHA256)
        files["attribution-control"] = target.read_bytes()
        source_hashes[str(target)] = checks.TARGET_SHA256
        cases = []
        for case in specification["cases"]:
            current = {**case, "case": case["id"]}
            if case["helper_transactions"]:
                nonce = uuid.uuid4().hex
                request = ("GET /hazim-liveness/" + stamp + "/" + case["id"] + "/" + nonce +
                           " HTTP/1.0\r\nHost: 10.0.0.1\r\nConnection: close\r\n\r\n").encode("ascii")
                current["transaction"] = {"request_hex": request.hex(), "expected_body_sha256": fixture["body_sha256"],
                                          "expected_body_bytes": fixture["body_bytes"], "source_ipv4": "10.0.0.10",
                                          "destination": ["10.0.0.1", 80]}
            cases.append(current)
        manifest = {"schema": checks.SCHEMA, "stamp": stamp, "snapshot": "clean-liveness-" + stamp,
                    "guest_root": "/home/csci/Downloads/liveness-" + stamp, "guest_btf_sha256": btf,
                    "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
                    "runner_sha256": hashlib.sha256(files["integrated_runner.py"]).hexdigest(), "cases": cases,
                    "expected_fixture": fixture, "collection_ready": False, "performance_accepted": False,
                    "authorization": "User selected Approve V2 Implementation And Benign Checks: exact 28-second diagnostic-only lifetime and six controls; no benchmark retry, malware, fitting, traffic padding or policy change"}
        files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
        integration.save(attempt / "manifest.json", manifest)
        (attempt / "integrated_runner.py").write_bytes(files["integrated_runner.py"])
        with tarfile.open(attempt / "payload.tgz", "x:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o700 if name in ("attribution-control", "attribution-diagnostic") else 0o600
                archive.addfile(member, io.BytesIO(data))
        payload = (attempt / "payload.tgz").read_bytes()
        setup = ("import base64,hashlib,io,tarfile\nfrom pathlib import Path\n"
                 "payload=base64.b64decode(" + repr(base64.b64encode(payload).decode()) + ")\n"
                 "assert hashlib.sha256(payload).hexdigest()==" + repr(hashlib.sha256(payload).hexdigest()) + "\n"
                 "root=Path(" + repr(manifest["guest_root"]) + ")\nroot.mkdir(mode=0o700)\n"
                 "with tarfile.open(fileobj=io.BytesIO(payload),mode='r:gz') as archive:\n"
                 " members=archive.getmembers()\n assert len({item.name for item in members})==len(members)\n"
                 " for item in members:\n  assert item.isfile() and Path(item.name).name==item.name and item.size<16777216\n"
                 "  with (root/item.name).open('xb') as target: target.write(archive.extractfile(item).read())\n"
                 "  (root/item.name).chmod(item.mode)\n")
        compile(setup, "liveness-setup", "exec")
        (attempt / "setup_guest.sh").write_text("#!/bin/bash\nset -euo pipefail\n/usr/bin/python3 - <<'PY'\n" + setup + "PY\n")
        subprocess.run(["bash", "-n", str(attempt / "setup_guest.sh")], check=True)
        integration.save(attempt / "protocol.json", {"schema": checks.SCHEMA, "v2_sha256": checks.PROTOCOL_SHA256,
            "authorization": manifest["authorization"], "files": {name: checks.digest(attempt / name) for name in
            ("manifest.json", "payload.tgz", "setup_guest.sh", "integrated_runner.py", "recorder.c", "attribution-diagnostic")},
            "source_hashes": source_hashes, "collection_ready": False, "performance_accepted": False,
            "no_automatic_retry": True, "case_count": 6, "helper_transaction_count": 4,
            "limits_and_tasks_unchanged": specification["limits"], "specification": specification})
    except BaseException as error:
        integration.save(attempt / "build-failure.json", {"status": "failed_preserved", "error": repr(error), "collection_ready": False})
        raise
    print("FROZEN", attempt, "runner", manifest["runner_sha256"], flush=True)
    return attempt, manifest


def execute(attempt, manifest):
    path = ROOT / "check_integrated_attribution.py"
    pinned(path, "55f556320f6ac4121338b57d8a28e6bc39ed9a811916a0e3c0624d24342017af")
    tree = ast.parse(path.read_text())
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "execute")
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and child.value == "360000":
            child.value = "720000"
    namespace = dict(globals())
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), "exec"), namespace)
    namespace["execute"](attempt, manifest)


def local_guards():
    from unittest.mock import MagicMock, patch
    from types import SimpleNamespace
    request = b"GET /hazim-liveness/test/original-pre/0123456789abcdef0123456789abcdef HTTP/1.0\r\nHost: 10.0.0.1\r\nConnection: close\r\n\r\n"
    response = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    config = {"request_hex": request.hex(), "expected_body_sha256": hashlib.sha256(b"body").hexdigest(),
              "expected_body_bytes": 4, "source_ipv4": "10.0.0.10", "destination": ["10.0.0.1", 80]}

    class Clock:
        current = checks.SECOND

        def __call__(self):
            return self.current

    class Connection:
        def __init__(self, clock, slow):
            self.clock = clock
            self.slow = slow
            self.receives = iter([response[:-2], response[-2:], b""])
            self.timeouts = []
            self.sent = bytearray()

        def __enter__(self):
            return self

        def __exit__(self, *_arguments):
            return False

        def bind(self, address):
            expect(address == ("10.0.0.10", 0), "Source binding changed")

        def settimeout(self, value):
            self.timeouts.append(value)

        def connect(self, address):
            expect(address == ("10.0.0.1", 80), "Helper endpoint changed")

        def getsockname(self):
            return "10.0.0.10", 32123

        def getpeername(self):
            return "10.0.0.1", 80

        def getsockopt(self, *_arguments):
            return (7).to_bytes(8, sys.byteorder)

        def send(self, data):
            count = min(len(data), 33)
            self.sent.extend(data[:count])
            return count

        def recv(self, _maximum):
            if self.slow:
                self.clock.current += 700000000
            return next(self.receives)

    with tempfile.TemporaryDirectory(prefix="hazim-liveness-unit-") as temporary:
        root = Path(temporary)
        for slow in (False, True):
            directory = root / str(slow)
            directory.mkdir()
            clock = Clock()
            connection = Connection(clock, slow)
            factory = MagicMock(return_value=connection)
            try:
                receipt = checks.transaction(directory, config, Path("/sys/fs/cgroup/hazim-never-current"), factory, clock)
                expect(not slow and receipt["status"] == "accepted", "Slow partial response accepted")
            except TimeoutError:
                expect(slow, "Fast bounded helper rejected")
                receipt = json.loads((directory / "helper-receipt.json").read_text())
                expect(receipt["status"] == "failed_preserved" and (directory / "helper-response.bin").is_file(),
                       "Timed-out helper evidence not preserved")
            expect(factory.call_count == 1 and bytes(connection.sent) == request, "Helper retry or request change")
            expect(all(0 < value <= 2 for value in connection.timeouts) and connection.timeouts == sorted(connection.timeouts, reverse=True),
                   "Partial progress reset the deadline")
        for field, value in (("destination", ["example.com", 80]), ("destination", ["1.1.1.1", 80]),
                             ("source_ipv4", "127.0.0.1"), ("request_hex", b"GET /bad HTTP/1.0\r\n\r\n".hex())):
            changed = {**config, field: value}
            try:
                checks.transaction(root, changed, Path("/sys/fs/cgroup/hazim-never-current"), MagicMock())
            except ValueError:
                pass
            else:
                raise AssertionError("Unapproved endpoint/request accepted")

    def packet(sequence, flags, payload, reverse=False):
        source, target = ("10.0.0.1", "10.0.0.10") if reverse else ("10.0.0.10", "10.0.0.1")
        ports = (80, 32123) if reverse else (32123, 80)
        tcp = struct.pack("!HHIIBBHHH", *ports, sequence, 0, 5 << 4, flags, 4096, 0, 0) + payload
        ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                           socket.inet_aton(source), socket.inet_aton(target))
        return b"\0" * 12 + b"\x08\x00" + ipv4 + tcp

    frames = [packet(100, 2, b""), packet(200, 18, b"", True), packet(101, 16, request[:7]),
              packet(108, 16, request[7:]), packet(101, 16, request[:7]), packet(201, 16, response, True)]

    def capture(frames):
        data = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        return data + b"".join(struct.pack("<IIII", 1, 100000, len(frame), len(frame)) + frame for frame in frames)

    receipt = {"status": "accepted", "local_endpoint": ["10.0.0.10", 32123], "remote_endpoint": ["10.0.0.1", 80],
               "request_sha256": hashlib.sha256(request).hexdigest(), "response_sha256": hashlib.sha256(response).hexdigest(),
               "realtime_start_ns": checks.SECOND, "realtime_end_ns": 2 * checks.SECOND}
    checks.audit_transaction(capture(frames), receipt, request, response, config)
    for changed in (frames[1:], frames[:-1], frames + [packet(101, 16, b"wrong")], frames + [packet(300, 2, b"")]):
        try:
            checks.audit_transaction(capture(changed), receipt, request, response, config)
        except ValueError:
            pass
        else:
            raise AssertionError("Gapped, marker-only, conflicting or ambiguous PCAP accepted")
    for condition in ("original", "full"):
        for failure in (KeyboardInterrupt(), TimeoutError("synthetic")):
            session = integration.Session(SimpleNamespace(ebpf_password_file=None))
            session.config = {"condition": condition}
            session.receipts = {}
            session.process = MagicMock()
            session.process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 8)]
            session.log = MagicMock()
            with tempfile.TemporaryDirectory(prefix="hazim-liveness-cleanup-") as temporary:
                session.run_dir = Path(temporary)
                for name in ("exec-ready", "attribution-gate"):
                    os.mkfifo(session.run_dir / name, 0o600)
                with patch.object(integration.identity, "read_message", side_effect=failure), patch.object(integration, "stop_process") as stopped:
                    session.stop()
                    expect(stopped.call_count == 1 and session.result["status"] == "rejected", "Interrupted/timeout cleanup skipped")
                expect(not any(session.run_dir.iterdir()) and session.log.close.called, "Private gate cleanup skipped")
    for condition in ("original", "full"):
        result = {"status": "accepted", "temporary_cgroup_removed": False}
        group = MagicMock()
        events = group.__truediv__.return_value.open.return_value.__enter__.return_value
        events.read.return_value = "populated 0\n"
        log = MagicMock()
        with patch.object(integration, "stop_process", side_effect=TimeoutError("injected recorder stop")), \
                patch.object(integration.identity, "stop_trace", side_effect=ValueError("injected observer stop")), \
                patch.object(integration.select, "poll"):
            integration.cleanup_resources(None if condition == "original" else MagicMock(), None, log, -1, group, result)
        expect(result["status"] == "rejected" and result["temporary_cgroup_removed"] and group.rmdir.called and log.close.called,
               "Cleanup failure skipped other resources")
    print("PASS actual helper byte/send/partial-response fake-clock checks, endpoint guards, independent synthetic PCAP recovery/corruptions, original/full interruption/timeout cleanup including injected root cleanup errors")


def auditor_guards():
    import copy
    from unittest.mock import patch
    import audit_capture_liveness as auditor
    with tarfile.open(ROOT / "exec-identity-readiness/20261023T075642576210Z/evidence.tgz", "r:gz") as archive:
        files = {member.name: archive.extractfile(member).read() for member in archive.getmembers() if member.isfile()}
    prefix = next(name.rsplit("/", 1)[0] for name in files if name.startswith("output-null/") and name.endswith("/run.json"))
    metadata = json.loads(files[prefix + "/run.json"])
    metadata.update(telemetry_schema_version=checks.SCHEMA, malware_runner_sha256="synthetic-test-only",
                    sample_arguments=checks.ARGUMENTS, collection_quality_status="rejected",
                    collection_quality_reasons=["packet_capture_interface_no_traffic"],
                    sample_started_monotonic_ns=3 * checks.SECOND, observation_ended_monotonic_ns=23 * checks.SECOND)
    metadata["packet_capture_statistics"].update(packets_received_by_filter=0, packets_captured=0, dropped_by_kernel=0)
    metadata["packet_capture_interface_counter_deltas"] = {name: 0 for name in metadata["packet_capture_interface_counters_before_sample"]}
    metadata["packet_capture_interface_counters_after_capture"] = copy.deepcopy(metadata["packet_capture_interface_counters_before_sample"])
    files[prefix + "/packet_capture.pcap"] = files[prefix + "/packet_capture.pcap"][:24]
    receipts = {"attached_ns": checks.SECOND, "ready_ns": 2 * checks.SECOND, "observation_start_ns": 3 * checks.SECOND,
                "observation_end_ns": 23100000000, "original_observation_end_ns": 23 * checks.SECOND,
                "target_request_ns": 3100000000, "release_ack_ns": 3200000000, "finish_request_ns": 24 * checks.SECOND,
                "finish_ack_ns": 30 * checks.SECOND, "detach_ns": 29 * checks.SECOND, "recorder_exit_ns": 29100000000,
                "attached_lifetime_seconds": 28}
    files[prefix + "/liveness-lifecycle.json"] = json.dumps(receipts).encode()
    files[prefix + "/sample.stdout.log"] = ("event,pid,value\nstart,%d,liveness_null\n" % metadata["sample_root_pid"]).encode()
    broker = json.loads(files[prefix + "/attribution-result.json"])
    broker["boot_id"] = "synthetic-test-only"
    broker["link_state_after"] = {"carrier": 1, "operstate": "up", "monotonic_ns": 30 * checks.SECOND}
    metadata["attribution"] = broker
    files[prefix + "/attribution-result.json"] = json.dumps(broker).encode()
    files[prefix + "/run.json"] = json.dumps(metadata).encode()
    with patch.object(auditor.identity.exec_identity, "validate_receipts", side_effect=ValueError("injected invalid identity")) as guard:
        try:
            audit_case(files.__getitem__, prefix, {"runner_sha256": "synthetic-test-only"},
                       {"case": "full-quiet", "condition": "full", "helper_transactions": 0})
        except ValueError as error:
            expect(str(error) == "injected invalid identity" and guard.call_count == 1, "Quiet identity path not exercised: " + str(error))
        else:
            raise AssertionError("Quiet rejected quality skipped full identity validation")
    for corrupt in ("promotion", "nic_loss", "counter_join"):
        changed = copy.deepcopy(metadata)
        if corrupt == "nic_loss":
            changed["packet_capture_interface_counter_deltas"]["rx_dropped"] = 1
            changed["packet_capture_interface_counters_after_capture"]["rx_dropped"] += 1
        elif corrupt == "counter_join":
            changed["packet_capture_interface_counter_deltas"]["rx_packets"] = 1
        try:
            auditor.audit_interface(changed, corrupt != "promotion")
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupted interface/quiet promotion accepted")
    print("PASS rejected quiet original quality still rejects invalid full identity; NIC loss/counter drift/quiet promotion guards")


def http_guards():
    import http.client
    for response in (b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nbody",
                     b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbodyextra",
                     b"HTTP/1.0 200 OK\r\nContent-Length: -1\r\n\r\nbody",
                     b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\nbody",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
                     b"HTTP/1.0 404 No\r\nContent-Length: 4\r\n\r\nbody", b"x" * 16385):
        try:
            checks.parse_response(response)
        except (ValueError, http.client.HTTPException):
            pass
        else:
            raise AssertionError("Invalid/incomplete/ambiguous HTTP response accepted")
    expect(checks.parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n") == b"body",
           "Complete standard chunked response rejected")
    print("PASS seven incomplete/trailing/ambiguous/status/size HTTP guards and complete chunked response")


def self_test():
    integration.self_test(STUDY / "src/malware_runner.py")
    local_guards()
    auditor_guards()
    http_guards()
    body, fixture = historical_fixture()
    expect(len(body) == 258 and fixture["body_bytes"] == 258, "Frozen historical fixture changed")
    sys.path.insert(0, str(STUDY))
    from tests.test_malware_runner_hostmon import malware_runner
    from unittest.mock import patch
    command = runner_command(Path("/owned"), {"case": "full-quiet"}, [Path("/owned/pcap-auth"), Path("/owned/ebpf-auth")])
    with patch.object(sys, "argv", command[1:]):
        parsed = malware_runner.parse_args()
    expect(parsed.sample == "/owned/attribution-control" and parsed.timeout == 20 and parsed.fixed_observation and
           parsed.common_launch_wrapper, "Real original runner parser differs")
    print("PASS historical fixture independently pinned/reassembled and exact original runner command parsed; no VM operation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--guest", type=Path)
    options = parser.parse_args()
    if options.guest:
        signal.signal(signal.SIGTERM, integration.interrupted)
        raise SystemExit(0 if guest(options.guest.resolve()) else 2)
    elif options.self_test:
        self_test()
    else:
        attempt, manifest = freeze()
        if options.execute_benign_checks:
            signal.signal(signal.SIGTERM, integration.interrupted)
            execute(attempt, manifest)