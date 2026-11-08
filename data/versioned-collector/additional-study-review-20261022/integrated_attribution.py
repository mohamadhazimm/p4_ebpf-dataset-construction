#!/usr/bin/env python3
"""Separately versioned target-only attribution integration for benign readiness."""

import argparse
import ast
import hashlib
import json
import math
import os
import select
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections import Counter
from pathlib import Path


SCHEMA = "2026-10-23.19-attribution-candidate"
BASE_SHA256 = "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49"


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            result.update(block)
    return result.hexdigest()


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def audit_records(rows):
    sessions = [row for row in rows if row.get("record") == "session"]
    attached = [row for row in rows if row.get("record") == "attached"]
    finals = [row for row in rows if row.get("record") == "final"]
    events = [row for row in rows if row.get("record") == "observation"]
    if len(sessions) != 1 or sessions[0]["schema"] != "attribution-sensor-v6" or len(attached) != 1 or len(finals) != 1 or not events:
        raise ValueError("Incomplete v6 sensor lifecycle")
    final = finals[0]
    if (final["returncode"] or not final["counters_available"] or final["invalid_records"] or len(final["counters"]) != 8
            or any(final["counters"][1:]) or final["events_emitted"] != len(events) or final["counters"][0] != len(events)):
        raise ValueError("Missing or positive sensor error/loss counter")
    if sorted(row["sequence"] for row in events) != list(range(1, len(events) + 1)):
        raise ValueError("Sensor sequence gap or duplicate")
    if any(row["schema"] != sessions[0]["schema"] or row["ownership_verified"] or row["frame_link_verified"] for row in events):
        raise ValueError("Sensor record schema differs")
    return {"observations": len(events), "error_loss_counters": dict(enumerate(final["counters"][1:], 1)),
            "schema": sessions[0]["schema"], "kinds": dict(Counter(row["kind"] for row in events))}


def read_message(process, seconds):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(seconds):
            raise TimeoutError("Attribution broker response deadline")
        line = process.stdout.readline(65537)
    if not line or len(line) > 65536:
        raise ValueError("Attribution broker response missing or oversized")
    message = json.loads(line)
    if message.get("status") != "accepted":
        raise ValueError("Attribution broker rejected request: " + str(message.get("error", "unknown")))
    return message


class Session:
    def __init__(self, args):
        self.args = args
        self.process = None
        self.log = None
        self.result = None
        self.run_dir = None
        self.cgroup = None
        self.password = Path(args.ebpf_password_file).read_bytes().rstrip(b"\r\n") if args.ebpf_password_file else b""

    def prepare(self, run_dir, sample):
        if not self.args.common_launch_wrapper or not self.args.fixed_observation or not self.args.ebpf_password_file or not self.args.iface:
            raise ValueError("Integrated capture requires common wrapper, fixed observation, eBPF and PCAP")
        if self.args.bpf or self.args.iface != "enp0s3" or self.args.timeout != 20 or self.args.window_sec != 0.5:
            raise ValueError("Unreviewed integrated capture settings")
        config_path = Path(os.environ["HAZIM_ATTRIBUTION_CONFIG"]).resolve(strict=True)
        config = json.loads(config_path.read_text())
        for field in ("sensor", "object"):
            if digest(config[field]) != config[field + "_sha256"]:
                raise ValueError("Integrated sensor input changed: " + field)
        self.run_dir = Path(run_dir).resolve()
        os.mkfifo(self.run_dir / "attribution-gate", 0o600)
        self.log = (self.run_dir / "attribution-broker.log").open("xb")
        request = {**config, "run_dir": str(self.run_dir), "seconds": math.ceil(self.args.timeout) + 2,
               "sample": str(Path(sample).resolve()), "sample_sha256": digest(sample),
                   "owner_uid": os.getuid(), "owner_gid": os.getgid()}
        request_path = self.run_dir / "attribution-request.json"
        save(request_path, request)
        request_path.chmod(0o600)
        self.process = subprocess.Popen(["/usr/bin/sudo", "-S", "-p", "", "/usr/bin/python3", str(Path(__file__).resolve()),
                                        "--broker", str(request_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=self.log, start_new_session=True)
        self.process.stdin.write(self.password + b"\n")
        self.password = b""
        self.process.stdin.flush()
        ready = read_message(self.process, 20)
        cgroup = Path(ready["cgroup"])
        if cgroup.parent != Path("/sys/fs/cgroup") or not cgroup.name.startswith("hazim-integrated-"):
            raise ValueError("Unexpected target cgroup")
        self.cgroup = cgroup

    def wrap(self, command):
        if self.cgroup is None or self.process.poll() is not None:
            raise ValueError("Target launch before live sensor readiness")
        if command[:4] != ["/bin/bash", "-c", 'exec "$@"', "sample-launch"]:
            raise ValueError("Common launch wrapper differs")
        return ["/bin/bash", "-c", 'IFS= read -r ready < "$1" || exit 125; test "$ready" = GO || exit 125; shift; exec "$@"',
                "sample-launch", str(self.run_dir / "attribution-gate"), *command[4:]]

    def release(self, target):
        lifetime = Path("/proc/%d/stat" % target.pid).read_text().rsplit(")", 1)[1].split()[19]
        self.process.stdin.write(("TARGET %d %s\n" % (target.pid, lifetime)).encode())
        self.process.stdin.flush()
        response = read_message(self.process, 8)
        if response["pid"] != target.pid:
            raise ValueError("Broker released a different target")

    def stop(self):
        if self.process is None or self.result is not None:
            self.password = b""
            if self.log is not None:
                self.log.close()
            return
        try:
            self.process.stdin.write(b"FINISH\n")
            self.process.stdin.flush()
            self.result = read_message(self.process, 12)
            if self.process.wait(timeout=5) != 0:
                raise ValueError("Attribution broker exited unsuccessfully")
        except Exception as error:
            self.result = {"status": "rejected", "error": type(error).__name__ + ": " + str(error)}
            self.process.stdin.close()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=8)
        finally:
            self.log.close()
            (self.run_dir / "attribution-gate").unlink(missing_ok=True)

    def quality(self, metadata, status, reasons):
        self.stop()
        result = self.result or {"status": "rejected", "error": "Sensor was not started"}
        metadata["attribution"] = {**result, "module_sha256": digest(__file__), "base_runner_sha256": BASE_SHA256,
                                   "ownership_verified": False, "frame_mapping_verified": False}
        if result["status"] != "accepted":
            return "rejected", [*reasons, "attribution_failed:" + result.get("error", "unknown")]
        rows = [json.loads(line) for line in (self.run_dir / "attribution.jsonl").read_text().splitlines()]
        root_pid = metadata["sample_root_pid"]
        if not any(row.get("record") == "observation" and row.get("pid") == root_pid and row.get("kind") == 9 for row in rows):
            return "rejected", [*reasons, "attribution_root_exec_missing"]
        if digest(metadata["sample"]) != result["sample_sha256"]:
            return "rejected", [*reasons, "attribution_target_file_changed"]
        clocks = {row["phase"]: row["monotonic_ns"] for row in rows if row.get("record") == "clock"}
        if not clocks.get("before", math.inf) <= metadata["sample_started_monotonic_ns"] < metadata["observation_ended_monotonic_ns"] <= clocks.get("after", -math.inf):
            return "rejected", [*reasons, "attribution_observation_boundary_missing"]
        return status, reasons


def generate(base):
    if digest(base) != BASE_SHA256:
        raise ValueError("Base runner is not the frozen .18 input")
    tree = ast.parse(Path(base).read_text())
    matches = Counter()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "TELEMETRY_SCHEMA_VERSION" for target in node.targets):
            node.value = ast.Constant(SCHEMA)
            matches["schema"] += 1
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            for parent in ast.walk(node):
                for field, value in ast.iter_fields(parent):
                    if not isinstance(value, list):
                        continue
                    replacement = []
                    for statement in value:
                        text = ast.unparse(statement) if isinstance(statement, ast.stmt) else ""
                        if text == "sample_started_ns = time.monotonic_ns()":
                            replacement.extend(ast.parse("attribution.prepare(run_dir, sample)").body)
                            matches["prepare"] += 1
                        if text.startswith("sample_process = subprocess.Popen("):
                            replacement.extend(ast.parse("command = attribution.wrap(command)").body)
                            matches["launch"] += 1
                        replacement.append(statement)
                        if text.startswith("sample_process = subprocess.Popen("):
                            replacement.extend(ast.parse("attribution.release(sample_process)").body)
                            matches["release"] += 1
                        if text == "args = parse_args()":
                            replacement.extend(ast.parse("attribution = integrated_attribution.Session(args)").body)
                            matches["session"] += 1
                        if text == "observer.join()":
                            replacement.extend(ast.parse("attribution.stop()").body)
                            matches["stop"] += 1
                        if (isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call)
                            and isinstance(statement.value.func, ast.Name) and statement.value.func.id == "assess_collection_quality"):
                            replacement.extend(ast.parse("quality_status, quality_reasons = attribution.quality(metadata, quality_status, quality_reasons)").body)
                            matches["quality"] += 1
                    setattr(parent, field, replacement)
            original = node.body
            node.body = original[:2] + [ast.Try(body=original[2:], handlers=[], orelse=[], finalbody=ast.parse("attribution.stop()").body)]
    if matches != Counter(dict.fromkeys(("schema", "prepare", "launch", "release", "session", "stop", "quality"), 1)):
        raise ValueError("Base runner integration sites differ: " + repr(matches))
    tree.body.insert(0, ast.Import(names=[ast.alias(name="integrated_attribution")]))
    result = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    compile(result, "integrated-malware-runner", "exec")
    return result


def broker(request_path):
    if os.geteuid() != 0:
        raise ValueError("Broker requires explicitly authenticated root access")
    request = json.loads(request_path.read_text())
    owner = request["owner_uid"], request["owner_gid"]
    if owner[0] <= 0 or int(os.environ["SUDO_UID"]) != owner[0] or not 1 <= request["seconds"] <= 30:
        raise ValueError("Broker owner or capture bounds differ")
    run_dir = Path(request["run_dir"]).resolve(strict=True)
    if run_dir.stat().st_uid != owner[0] or request_path.resolve().parent != run_dir:
        raise ValueError("Broker output ownership differs")
    for field in ("sensor", "object"):
        if digest(request[field]) != request[field + "_sha256"]:
            raise ValueError("Broker payload changed")
    if digest("/sys/kernel/btf/vmlinux") != request["guest_btf_sha256"]:
        raise ValueError("Guest kernel BTF differs")
    cgroup = Path("/sys/fs/cgroup") / ("hazim-integrated-" + uuid.uuid4().hex)
    process = None
    result = {"status": "rejected", "collection_ready": False, "temporary_cgroup_removed": False}
    log = None
    watcher = -1
    cgroup.mkdir()
    try:
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        if not (cgroup / "cgroup.kill").is_file():
            raise ValueError("Atomic owned-cgroup cleanup unsupported")
        import ctypes
        library = ctypes.CDLL(None, use_errno=True)
        watcher = library.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if watcher < 0 or library.inotify_add_watch(watcher, os.fsencode(run_dir), 2 | 8 | 256) < 0:
            raise OSError(ctypes.get_errno(), "Attribution readiness watch")
        log = (run_dir / "attribution-sensor.log").open("xb")
        observations = run_dir / "attribution.jsonl"
        process = subprocess.Popen([request["sensor"], "--capture", request["object"], str(cgroup), str(request["seconds"]),
                                    cgroup.name, str(observations)], stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 15
        while True:
            lines = observations.read_text().splitlines() if observations.exists() else []
            if any(json.loads(line).get("record") == "attached" for line in lines):
                break
            if process.poll() is not None or time.monotonic() >= deadline:
                raise ValueError("Sensor failed before attachment readiness")
            readable, _, _ = select.select([watcher], [], [], max(0, deadline - time.monotonic()))
            if readable:
                os.read(watcher, 65536)
        print(json.dumps({"status": "accepted", "cgroup": str(cgroup)}), flush=True)
        with selectors.DefaultSelector() as selector:
            selector.register(sys.stdin, selectors.EVENT_READ)
            if not selector.select(8):
                raise TimeoutError("Target membership request deadline")
            action, raw_pid, lifetime = sys.stdin.readline().split()
        target_pid = int(raw_pid)
        proc = Path("/proc/%d" % target_pid)
        if action != "TARGET" or proc.stat().st_uid != owner[0] or proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19] != lifetime:
            raise ValueError("Target membership owner/lifetime differs")
        (cgroup / "cgroup.procs").write_text(str(target_pid))
        if str(target_pid) not in (cgroup / "cgroup.procs").read_text().splitlines():
            raise ValueError("Target cgroup membership not observed")
        signal.signal(signal.SIGALRM, lambda *_arguments: (_ for _ in ()).throw(TimeoutError("Target gate deadline")))
        signal.alarm(5)
        try:
            with (run_dir / "attribution-gate").open("w") as gate:
                gate.write("GO\n")
        finally:
            signal.alarm(0)
        print(json.dumps({"status": "accepted", "pid": target_pid}), flush=True)
        with selectors.DefaultSelector() as selector:
            selector.register(sys.stdin, selectors.EVENT_READ)
            if not selector.select(request["seconds"] + 5) or sys.stdin.readline() != "FINISH\n":
                raise ValueError("Runner failed or broker finish deadline expired")
        (cgroup / "cgroup.kill").write_text("1")
        if process.wait(timeout=10) != 0:
            raise ValueError("Sensor capture failed")
        facts = audit_records([json.loads(line) for line in observations.read_text().splitlines()])
        if digest(request["sample"]) != request["sample_sha256"]:
            raise ValueError("Target file changed during capture")
        result.update(facts, status="accepted", sample_sha256=request["sample_sha256"],
                      observations_sha256=digest(observations), sensor_sha256=request["sensor_sha256"],
                      object_sha256=request["object_sha256"], pre_post_file_hash_only_not_exec_inode_proof=True)
    except BaseException as error:
        result.update(status="rejected", error=type(error).__name__ + ": " + str(error))
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        if log is not None:
            log.close()
        if watcher >= 0:
            os.close(watcher)
        try:
            with (cgroup / "cgroup.events").open() as events:
                poller = select.poll()
                poller.register(events, select.POLLPRI | select.POLLERR)
                (cgroup / "cgroup.kill").write_text("1")
                if "populated 1" in events.read():
                    poller.poll(5000)
                    events.seek(0)
                    if "populated 1" in events.read():
                        raise ValueError("Owned target cgroup remains populated")
            cgroup.rmdir()
            result["temporary_cgroup_removed"] = True
        except BaseException as error:
            result.update(status="rejected", cleanup_error=type(error).__name__ + ": " + str(error))
        save(run_dir / "attribution-result.json", result)
        for name in ("attribution-result.json", "attribution.jsonl", "attribution-sensor.log"):
            if (run_dir / name).is_file():
                os.chown(run_dir / name, *owner)
        print(json.dumps(result), flush=True)


def self_test(base):
    import copy
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    generated = generate(base)
    tree = ast.parse(generated)
    assert sum(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "prepare" and isinstance(node.func.value, ast.Name) and node.func.value.id == "attribution" for node in ast.walk(tree)) == 1
    assert generated.index("attribution.prepare(run_dir, sample)") < generated.index("sample_started_ns = time.monotonic_ns()")
    assert generated.index("command = attribution.wrap(command)") < generated.index("sample_process = subprocess.Popen(")
    assert "attribution.quality(metadata, quality_status, quality_reasons)" in generated
    assert 'SCHEMA' not in generated.split('TELEMETRY_SCHEMA_VERSION = ', 1)[1].splitlines()[0]
    original = ast.parse(Path(base).read_text())
    before = {node.name: ast.dump(node, include_attributes=False) for node in original.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    after = {node.name: ast.dump(node, include_attributes=False) for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    assert before == after
    records = [{"record": "session", "schema": "attribution-sensor-v6"}, {"record": "attached"},
               {"record": "observation", "schema": "attribution-sensor-v6", "kind": 9, "sequence": 1,
                "ownership_verified": False, "frame_link_verified": False},
               {"record": "final", "returncode": 0, "counters_available": True, "invalid_records": 0,
                "counters": [1, 0, 0, 0, 0, 0, 0, 0], "events_emitted": 1}]
    assert audit_records(records)["observations"] == 1
    for kind in ("missing", "loss", "sequence", "count", "ownership"):
        changed = copy.deepcopy(records)
        if kind == "missing":
            changed.pop()
        elif kind == "loss":
            changed[-1]["counters"][4] = 1
        elif kind == "sequence":
            changed[2]["sequence"] = 2
        elif kind == "count":
            changed[-1]["events_emitted"] = 2
        else:
            changed[2]["ownership_verified"] = True
        try:
            audit_records(changed)
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupted integration evidence accepted: " + kind)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "changed.py"
        path.write_text("pass\n")
        try:
            generate(path)
        except ValueError:
            pass
        else:
            raise AssertionError("Changed frozen base accepted")
        credential = Path(directory) / "test-auth"
        credential.write_bytes(b"synthetic-test-only\n")
        session = Session(SimpleNamespace(ebpf_password_file=str(credential)))
        credential.unlink()
        assert session.password == b"synthetic-test-only"
        command = ["/bin/bash", "-c", 'exec "$@"', "sample-launch", "/owned/benign", "argument with spaces"]
        try:
            session.wrap(command)
        except ValueError:
            pass
        else:
            raise AssertionError("Target launch before sensor readiness")
        session.process = MagicMock()
        session.process.poll.return_value = None
        session.cgroup = Path("/sys/fs/cgroup/hazim-integrated-test")
        session.run_dir = Path(directory)
        wrapped = session.wrap(command)
        assert wrapped[4:] == [str(session.run_dir / "attribution-gate"), *command[4:]] and wrapped.count("/bin/bash") == 1
        os.mkfifo(session.run_dir / "attribution-gate", 0o600)
        child_command = session.wrap(["/bin/bash", "-c", 'exec "$@"', "sample-launch", "/usr/bin/printf", "%s", "owned gate check"])
        with subprocess.Popen(child_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            assert child.poll() is None
            with (session.run_dir / "attribution-gate").open("w") as gate:
                gate.write("GO\n")
            stdout, stderr = child.communicate(timeout=5)
            assert child.returncode == 0 and stdout == b"owned gate check" and not stderr
        session.process.poll.return_value = 1
        try:
            session.wrap(command)
        except ValueError:
            pass
        else:
            raise AssertionError("Dead recorder allowed target launch")
    print("PASS exact AST integration sites, identical feature/helper ASTs, new schema and six negative guards")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", type=Path)
    action.add_argument("--broker", type=Path)
    action.add_argument("--build", type=Path)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test(options.self_test)
    elif options.broker:
        broker(options.broker)
    else:
        if options.output is None:
            parser.error("--build requires a new --output path")
        source = generate(options.build)
        with options.output.open("x") as stream:
            stream.write(source)