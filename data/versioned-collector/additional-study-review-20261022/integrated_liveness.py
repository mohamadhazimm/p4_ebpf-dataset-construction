#!/usr/bin/env python3
"""V2 diagnostic-only broker; frozen collectors and benchmark stay unchanged."""

import argparse
import ast
import json
import os
import select
import selectors
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import capture_liveness as checks
import integrated_exec_identity as identity


SCHEMA = checks.SCHEMA
BASE_SHA256 = identity.BASE_SHA256
digest = identity.digest
save = identity.save
require = checks.require


def interrupted(*_arguments):
    raise KeyboardInterrupt("Diagnostic interrupted; cleanup required")


def stop_process(process, grace=3):
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


def input_before(deadline):
    remaining = deadline - time.monotonic_ns()
    if remaining <= 0 or not select.select([sys.stdin], [], [], remaining / checks.SECOND)[0]:
        raise TimeoutError("Diagnostic broker input deadline")
    line = sys.stdin.readline(4097)
    require(0 < len(line) <= 4096, "Missing or oversized broker command")
    return line


def capture_context(request):
    wrapper = Path("/proc/%d" % request["capture_wrapper_pid"])
    fields = wrapper.joinpath("stat").read_text().rsplit(")", 1)[1].split()
    require(fields[19] == request["capture_wrapper_start_ticks"] and int(fields[1]) == request["runner_pid"],
            "Capture wrapper lifetime/parent changed")
    descendants = {request["capture_wrapper_pid"]}
    processes = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            stat = path.read_text().rsplit(")", 1)[1].split()
            processes[int(path.parent.name)] = int(stat[1])
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    for _generation in range(8):
        descendants.update(pid for pid, parent in processes.items() if parent in descendants)
    captures = []
    for pid in descendants:
        path = Path("/proc/%d" % pid)
        try:
            if os.readlink(path / "exe") == "/usr/bin/tcpdump":
                captures.append(path)
        except (FileNotFoundError, ProcessLookupError):
            continue
    require(len(captures) == 1, "Actual tcpdump process missing or ambiguous")
    path = captures[0]
    return {"pid": int(path.name), "start_ticks": path.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19],
            "network_namespace": os.readlink(path / "ns/net"), "process_namespace": os.readlink(path / "ns/pid"),
            "executable_sha256": digest(path / "exe"), "interface": "enp0s3"}


def current_link_state():
    interface = Path("/sys/class/net/enp0s3")
    return {"carrier": int((interface / "carrier").read_text()),
            "operstate": (interface / "operstate").read_text().strip(), "monotonic_ns": time.monotonic_ns()}


def cleanup_resources(process, observer, log, watcher, group, result):
    def remove_group():
        with (group / "cgroup.events").open() as events:
            poller = select.poll()
            poller.register(events, select.POLLPRI | select.POLLERR)
            (group / "cgroup.kill").write_text("1")
            if "populated 1" in events.read():
                poller.poll(5000)
                events.seek(0)
                require("populated 1" not in events.read(), "Owned cgroup remains populated")
        group.rmdir()
        result["temporary_cgroup_removed"] = True

    failures = []
    operations = [("recorder", lambda: stop_process(process)), ("observer", lambda: identity.stop_trace(observer)),
                  ("log", lambda: log.close() if log is not None else None),
                  ("watcher", lambda: os.close(watcher) if watcher >= 0 else None), ("cgroup", remove_group),
                  ("interface", lambda: result.update(link_state_after=current_link_state()))]
    for name, operation in operations:
        try:
            operation()
        except BaseException as error:
            failures.append(name + ": " + type(error).__name__ + ": " + str(error))
    if failures:
        result.update(status="rejected", cleanup_error=failures)


def broker(request_path):
    require(os.geteuid() == 0, "Authenticated root broker required")
    request = json.loads(request_path.read_text())
    owner = request["owner_uid"], request["owner_gid"]
    require(owner[0] > 0 and int(os.environ["SUDO_UID"]) == owner[0], "Diagnostic owner differs")
    require(request["condition"] in ("original", "full") and request["seconds"] == 28,
            "Unapproved diagnostic condition/lifetime")
    require(request["sample_sha256"] == checks.TARGET_SHA256 and digest(request["sample"]) == checks.TARGET_SHA256,
            "Only the accepted null-control image is permitted")
    directory = Path(request["run_dir"]).resolve(strict=True)
    require(directory.stat().st_uid == owner[0] and request_path.resolve().parent == directory,
            "Diagnostic output ownership differs")
    for field in ("sensor", "object"):
        require(digest(request[field]) == request[field + "_sha256"], "Diagnostic sensor input changed")
    require(digest("/sys/kernel/btf/vmlinux") == request["guest_btf_sha256"], "Guest BTF changed")
    group = Path("/sys/fs/cgroup") / ("hazim-integrated-" + uuid.uuid4().hex)
    result = {"status": "rejected", "temporary_cgroup_removed": False, "collection_ready": False,
              "condition": request["condition"], "sample_sha256": request["sample_sha256"],
              "broker_pid": os.getpid(), "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              "cgroup": str(group), "lifecycle": {}}
    process = None
    observer = None
    log = None
    watcher = -1
    group.mkdir()
    try:
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        require((group / "cgroup.kill").is_file(), "Atomic target cleanup unavailable")
        result["capture_context"] = capture_context(request)
        if request["condition"] == "full":
            import ctypes
            library = ctypes.CDLL(None, use_errno=True)
            watcher = library.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
            require(watcher >= 0 and library.inotify_add_watch(watcher, os.fsencode(directory), 2 | 8 | 256) >= 0,
                    "Diagnostic readiness watch unavailable")
            log = (directory / "attribution-sensor.log").open("xb")
            observations = directory / "attribution.jsonl"
            process = subprocess.Popen([request["sensor"], "--capture", request["object"], str(group), "28",
                                        group.name, str(observations)], stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            result["recorder_pid"] = process.pid
            result["recorder_start_ticks"] = Path("/proc/%d/stat" % process.pid).read_text().rsplit(")", 1)[1].split()[19]
            deadline = time.monotonic_ns() + 15 * checks.SECOND
            while True:
                lines = observations.read_text().splitlines() if observations.exists() else []
                attached = [json.loads(line) for line in lines if line.endswith("}") and '"record":"attached"' in line]
                if attached:
                    require(len(attached) == 1, "Ambiguous attachment readiness")
                    result["lifecycle"].update(attached_ns=attached[0]["monotonic_ns"], attached_lifetime_seconds=28)
                    break
                require(process.poll() is None and time.monotonic_ns() < deadline, "Recorder failed before readiness")
                if select.select([watcher], [], [], max(0, deadline - time.monotonic_ns()) / checks.SECOND)[0]:
                    os.read(watcher, 65536)
        ready = time.monotonic_ns()
        result["broker_ready_ns"] = ready
        print(json.dumps({"status": "accepted", "cgroup": str(group), "broker_ready_ns": ready,
                          **result["lifecycle"]}), flush=True)
        action, raw_pid, lifetime = input_before(ready + 5 * checks.SECOND).split()
        result["target_arrival_ns"] = time.monotonic_ns()
        target_pid = int(raw_pid)
        target = Path("/proc/%d" % target_pid)
        require(action == "TARGET" and target.stat().st_uid == owner[0] and
                target.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19] == lifetime,
                "Target owner/lifetime differs")
        (group / "cgroup.procs").write_text(raw_pid)
        require(raw_pid in (group / "cgroup.procs").read_text().splitlines(), "Target migration not observed")
        if request["condition"] == "full":
            observer = identity.start_trace(directory, target_pid, request)
        else:
            readiness = os.open(directory / "exec-ready", os.O_RDONLY | os.O_NONBLOCK)
            try:
                require(select.select([readiness], [], [], 5)[0] and os.read(readiness, 64) == b"READY\n",
                        "Original Bash readiness missing")
            finally:
                os.close(readiness)
        signal.signal(signal.SIGALRM, lambda *_arguments: (_ for _ in ()).throw(TimeoutError("Diagnostic release deadline")))
        signal.alarm(5)
        try:
            with (directory / "attribution-gate").open("w") as stream:
                stream.write("GO\n")
        finally:
            signal.alarm(0)
        print(json.dumps({"status": "accepted", "pid": target_pid}), flush=True)
        require(input_before(ready + 30 * checks.SECOND) == "FINISH\n", "Missing diagnostic finish")
        result["finish_arrival_ns"] = time.monotonic_ns()
        (group / "cgroup.kill").write_text("1")
        if process is not None:
            require(process.wait(timeout=10) == 0, "Diagnostic recorder did not exit naturally")
            result["lifecycle"]["recorder_exit_ns"] = time.monotonic_ns()
            rows = [json.loads(line) for line in observations.read_text().splitlines()]
            result.update(identity.audit_records(rows))
            detaches = [row for row in rows if row.get("record") == "detaching"]
            require(len(detaches) == 1, "Actual detach receipt missing")
            result["lifecycle"]["detach_ns"] = detaches[0]["monotonic_ns"]
            identity.finish_trace(observer, directory, result, request, target_pid)
        require(digest(request["sample"]) == request["sample_sha256"], "Null target file changed")
        result["status"] = "accepted"
    except BaseException as error:
        result.update(status="rejected", error=type(error).__name__ + ": " + str(error))
    finally:
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, signal.SIG_IGN)
        cleanup_resources(process, observer, log, watcher, group, result)
        save(directory / "attribution-result.json", result)
        for name in ("attribution-result.json", "attribution.jsonl", "attribution-sensor.log",
                     "exec-identity.json", "exec-identity.log"):
            if (directory / name).is_file():
                os.chown(directory / name, *owner)
        print(json.dumps(result), flush=True)


class Session(identity.Session):
    def __init__(self, args):
        super().__init__(args)
        signal.signal(signal.SIGTERM, interrupted)

    def observation_end(self, monotonic_ns):
        self.receipts["observation_end_ns"] = monotonic_ns

    def capture_context(self, collector):
        require(collector is not None and collector.process is not None and collector.process.poll() is None,
                "Original packet collector is not running")
        self.capture_wrapper_pid = collector.process.pid
        self.capture_wrapper_start_ticks = Path("/proc/%d/stat" % collector.process.pid).read_text().rsplit(")", 1)[1].split()[19]

    def prepare(self, run_dir, sample):
        require(self.args.common_launch_wrapper and self.args.fixed_observation and self.password and
                self.args.iface == "enp0s3" and self.args.timeout == 20 and self.args.window_sec == 0.5 and not self.args.bpf,
                "Unapproved original capture configuration")
        require(digest(sample) == checks.TARGET_SHA256, "Diagnostic target substitution")
        config = json.loads(Path(os.environ["HAZIM_ATTRIBUTION_CONFIG"]).read_text())
        require(config["condition"] in ("original", "full"), "Unapproved diagnostic condition")
        checks.validate_arguments(config["target_arguments"])
        self.config = config
        self.run_dir = Path(run_dir).resolve()
        self.receipts = {}
        for name in ("attribution-gate", "exec-ready"):
            os.mkfifo(self.run_dir / name, 0o600)
        self.log = (self.run_dir / "attribution-broker.log").open("xb")
        request = {**config, "run_dir": str(self.run_dir), "seconds": 28, "sample": str(Path(sample).resolve()),
                   "sample_sha256": checks.TARGET_SHA256, "owner_uid": os.getuid(), "owner_gid": os.getgid(),
                   "capture_wrapper_pid": self.capture_wrapper_pid, "capture_wrapper_start_ticks": self.capture_wrapper_start_ticks,
                   "runner_pid": os.getpid()}
        path = self.run_dir / "attribution-request.json"
        save(path, request)
        path.chmod(0o600)
        self.process = subprocess.Popen(["/usr/bin/sudo", "-S", "-p", "", "/usr/bin/python3", __file__,
                                         "--broker", str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.log, start_new_session=True)
        self.process.stdin.write(self.password + b"\n")
        self.password = b""
        self.process.stdin.flush()
        ready = identity.read_message(self.process, 20)
        self.receipts["ready_ns"] = time.monotonic_ns()
        self.cgroup = Path(ready["cgroup"])
        require(self.cgroup.parent == Path("/sys/fs/cgroup") and self.cgroup.name.startswith("hazim-integrated-"),
                "Unexpected diagnostic cgroup")
        if config["condition"] == "full":
            require(0 <= self.receipts["ready_ns"] - ready["attached_ns"] <= checks.SECOND, "Stale full readiness")
        if config["helper_transactions"] == 1:
            receipt = checks.transaction(self.run_dir, config["transaction"], self.cgroup)
            self.receipts.update({name: receipt[name] for name in ("helper_start_ns", "helper_end_ns")})
        else:
            require(config["helper_transactions"] == 0 and "transaction" not in config, "Quiet helper configuration")

    def release(self, target):
        lifetime = Path("/proc/%d/stat" % target.pid).read_text().rsplit(")", 1)[1].split()[19]
        self.receipts["target_request_ns"] = time.monotonic_ns()
        require(self.receipts["target_request_ns"] - self.receipts["ready_ns"] <= 4 * checks.SECOND,
                "Diagnostic target request deadline")
        self.process.stdin.write(("TARGET %d %s\n" % (target.pid, lifetime)).encode())
        self.process.stdin.flush()
        response = identity.read_message(self.process, 8)
        self.receipts["release_ack_ns"] = time.monotonic_ns()
        require(response["pid"] == target.pid, "Different target released")

    def stop(self):
        if self.process is None or self.result is not None:
            self.password = b""
            if self.log is not None:
                self.log.close()
            return
        try:
            self.receipts["finish_request_ns"] = time.monotonic_ns()
            self.process.stdin.write(b"FINISH\n")
            self.process.stdin.flush()
            self.result = identity.read_message(self.process, 15)
            self.receipts["finish_ack_ns"] = time.monotonic_ns()
            require(self.process.wait(timeout=3) == 0, "Diagnostic broker exit failed")
        except BaseException as error:
            self.result = {"status": "rejected", "error": type(error).__name__ + ": " + str(error)}
            self.process.stdin.close()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                stop_process(self.process)
        finally:
            self.log.close()
            for name in ("attribution-gate", "exec-ready"):
                (self.run_dir / name).unlink(missing_ok=True)

    def quality(self, metadata, status, reasons):
        self.stop()
        metadata["attribution"] = self.result
        try:
            require(self.result["status"] == "accepted" and self.result["temporary_cgroup_removed"],
                    "Diagnostic broker or cleanup failed")
            receipts = {**self.receipts, **self.result["lifecycle"],
                        "observation_start_ns": metadata["sample_started_monotonic_ns"],
                        "original_observation_end_ns": metadata["observation_ended_monotonic_ns"]}
            require(receipts["observation_end_ns"] >= receipts["original_observation_end_ns"],
                    "Actual observation receipt precedes modeled end")
            checks.validate_lifecycle(receipts, self.config["condition"] == "full", self.config["helper_transactions"] == 1)
            require(self.result["target_arrival_ns"] <= receipts["ready_ns"] + 4 * checks.SECOND,
                    "Actual target arrival deadline")
            require(self.result["finish_arrival_ns"] <= receipts["ready_ns"] + 30 * checks.SECOND,
                    "Actual finish arrival deadline")
            if self.config["condition"] == "full":
                rows = [json.loads(line) for line in (self.run_dir / "attribution.jsonl").read_text().splitlines()]
                identity.audit_records(rows)
                facts = identity.exec_identity.validate_receipts(json.loads((self.run_dir / "exec-identity.json").read_text()),
                                                                 metadata["sample_root_pid"], checks.TARGET_SHA256, rows)
                require(facts == self.result["executable_identity"], "Independent exec-inode receipt differs")
                metadata["executable_identity"] = facts
            save(self.run_dir / "liveness-lifecycle.json", receipts)
            metadata["capture_liveness"] = {"status": "diagnostic_only", "module_sha256": digest(__file__),
                                            "target_arguments": checks.ARGUMENTS, "condition": self.config["condition"],
                                            "helper_transactions": self.config["helper_transactions"],
                                            "collection_ready": False, "performance_accepted": False}
        except (KeyError, ValueError, OSError, TypeError) as error:
            return "rejected", [*reasons, "capture_liveness_failed:" + str(error)]
        return status, reasons


def generate(base):
    tree = ast.parse(identity.generate(base))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "integrated_exec_identity":
                    alias.name = "integrated_liveness"
        elif isinstance(node, ast.Name) and node.id == "integrated_exec_identity":
            node.id = "integrated_liveness"
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "TELEMETRY_SCHEMA_VERSION"
                                                 for target in node.targets):
            node.value = ast.Constant(SCHEMA)
    sites = 0
    end_sites = 0
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if not isinstance(value, list):
                continue
            replacement = []
            for statement in value:
                if isinstance(statement, ast.Expr) and ast.unparse(statement) == "attribution.prepare(run_dir, sample)":
                    replacement.extend(ast.parse("attribution.capture_context(packet_collector)").body)
                    sites += 1
                replacement.append(statement)
                if isinstance(statement, ast.Assign) and ast.unparse(statement) == "observation_ended_ns = time.monotonic_ns()":
                    replacement.extend(ast.parse("attribution.observation_end(observation_ended_ns)").body)
                    end_sites += 1
            setattr(parent, field, replacement)
    require(sites == 1, "Original capture readiness insertion site differs")
    require(end_sites == 1, "Actual observation-end receipt insertion site differs")
    original = {node.name: ast.dump(node) for node in ast.parse(Path(base).read_text()).body
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    generated = {node.name: ast.dump(node) for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    require(original == generated, "Diagnostic changed original feature/helper ASTs")
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


def self_test(base):
    from unittest.mock import MagicMock, patch
    checks.self_test()
    source = generate(base)
    compile(source, "liveness-generated-runner", "exec")
    require(source.index("attribution.prepare(run_dir, sample)") < source.index("sample_started_ns = time.monotonic_ns()"),
            "Helper moved the target timing boundary")
    for failure in (subprocess.TimeoutExpired("synthetic", 3), KeyboardInterrupt()):
        process = MagicMock()
        process.pid = 987654321
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 3), 0]
        with patch.object(os, "killpg") as kill:
            stop_process(process)
            require([call.args[1] for call in kill.call_args_list] == [signal.SIGTERM, signal.SIGKILL],
                    "Bounded process cleanup did not escalate")
        try:
            interrupted()
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("Signal did not take cleanup path")
    require("if status != 'accepted'" not in ast.unparse(ast.parse(textwrap.dedent(__import__("inspect").getsource(Session.quality)))),
            "Quiet rejection bypasses full identity validation")
    print("PASS unchanged original helper ASTs, diagnostic schema, original timing boundary, bounded TERM/KILL and quiet identity path")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--broker", type=Path)
    action.add_argument("--self-test", type=Path)
    options = parser.parse_args()
    broker(options.broker) if options.broker else self_test(options.self_test)