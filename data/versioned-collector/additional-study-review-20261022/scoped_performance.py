#!/usr/bin/env python3
"""Separate benchmark harness; preserve frozen collector feature implementations."""

import argparse
import ast
import copy
import json
import math
import os
import select
import signal
import statistics
import subprocess
import threading
import time
import types
import uuid
from pathlib import Path

import integrated_exec_identity as identity


SCHEMA = "2026-10-23.21-performance-harness"
digest, save = identity.digest, identity.save
CHILDREN = []


class MeasuredPopen(subprocess.Popen):
    def __init__(self, *arguments, **keywords):
        self.begin_ns = time.monotonic_ns()
        self.finished = threading.Event()
        self.usage = None
        self.measurement_error = None
        super().__init__(*arguments, **keywords)
        self.pidfd = os.pidfd_open(self.pid)
        threading.Thread(target=self.reap, daemon=True).start()

    def reap(self):
        try:
            select.select([self.pidfd], [], [])
            ended = time.monotonic_ns()
            observed, status, usage = os.wait4(self.pid, 0)
            if observed != self.pid:
                raise ValueError("Reaped another child")
            self.usage = {"pid": self.pid, "begin_ns": self.begin_ns, "exit_observed_ns": ended,
                          "wall_ns": ended - self.begin_ns, "user_seconds": usage.ru_utime,
                          "system_seconds": usage.ru_stime, "peak_rss_kib": usage.ru_maxrss}
            self._handle_exitstatus(status)
        except BaseException as error:
            self.measurement_error = repr(error)
        finally:
            os.close(self.pidfd)
            self.finished.set()

    def poll(self):
        if self.measurement_error:
            raise RuntimeError(self.measurement_error)
        return self.returncode

    def wait(self, timeout=None):
        if not self.finished.wait(timeout):
            raise subprocess.TimeoutExpired(self.args, timeout)
        if self.measurement_error:
            raise RuntimeError(self.measurement_error)
        return self.returncode


def launch(command, **keywords):
    process = MeasuredPopen(command, **keywords)
    CHILDREN.append(process)
    return process


def write_task_usage(directory, process):
    if process.wait(timeout=1) != 0 or process.usage is None:
        raise ValueError("Measured target failed or wait4 usage unavailable")
    save(Path(directory) / "task-usage.json", {**process.usage, "returncode": process.returncode,
         "boundary": "Before original Bash Popen through pidfd exit readiness; includes FIFO/root migration and full-only attestor setup, not coarse telemetry polling",
         "rss_limitations": "Target RSS includes fork/exec accounting; not steady-state target memory"})


def original_sensors_enabled():
    return os.environ["HAZIM_PERFORMANCE_CONDITION"] != "baseline"


def summarize(rows, limits):
    scored = [row for row in rows if not row["warmup"]]
    if len(scored) != 60 or len(rows) != 84:
        raise ValueError("Incomplete frozen two-warmup/five-repetition three-condition design")
    groups = []
    failures = []
    for abi in ("amd64", "i386"):
        for task in ("file", "network"):
            subset = [row for row in scored if row["abi"] == abi and row["task"] == task]
            by_condition = {condition: sorted((row for row in subset if row["condition"] == condition), key=lambda row: row["repeat"])
                            for condition in ("baseline", "original", "full")}
            for condition, values in by_condition.items():
                if [row["repeat"] for row in values] != list(range(5)):
                    raise ValueError("Missing or repeated prospective repetition: " + condition)
                for row in values:
                    usage = row["usage"]
                    if usage["returncode"] != 0 or not usage["wall_ns"] or any(not math.isfinite(usage[key]) or usage[key] < 0 for key in ("wall_ns", "user_seconds", "system_seconds", "peak_rss_kib")):
                        raise ValueError("Invalid actual task measurement")
            original, full = by_condition["original"], by_condition["full"]
            ratio = statistics.median(row["usage"]["wall_ns"] for row in full) / statistics.median(row["usage"]["wall_ns"] for row in original)
            paired = [observed["usage"]["wall_ns"] / base["usage"]["wall_ns"] for base, observed in zip(original, full)]
            cpu = lambda row: row["usage"]["user_seconds"] + row["usage"]["system_seconds"]
            denominator = statistics.median(cpu(row) for row in original)
            if denominator <= 0:
                raise ValueError("Original task CPU unavailable")
            cpu_ratio = statistics.median(cpu(row) for row in full) / denominator
            recorder_peak = max(row["recorder_usage"]["peak_rss_kib"] for row in full)
            checks = {"median_wall": ratio <= limits["full_vs_original_task_wall_median_ratio_max"],
                      "any_pair_wall": max(paired) <= limits["full_vs_original_task_wall_any_pair_ratio_max"],
                      "median_task_cpu": cpu_ratio <= limits["full_vs_original_task_cpu_median_ratio_max"],
                      "recorder_rss": recorder_peak <= limits["recorder_rss_mib_max"] * 1024}
            if not all(checks.values()):
                failures.append({"abi": abi, "task": task, "checks": checks})
            groups.append({"abi": abi, "task": task, "wall_median_ratio": ratio, "paired_wall_ratios": paired,
                           "task_cpu_median_ratio": cpu_ratio, "recorder_peak_rss_kib": recorder_peak, "checks": checks})
    return {"status": "accepted_bounded_performance" if not failures else "performance_budget_failed_preserved",
            "groups": groups, "failures": failures, "collection_ready": False,
            "limits": "Only frozen owned-file/loopback tasks and observed rates; no arbitrary malware, global hook CPU or kernel map memory inference"}


def group_only_broker(request_path):
    request = json.loads(request_path.read_text())
    owner = request["owner_uid"], request["owner_gid"]
    directory = Path(request["run_dir"]).resolve(strict=True)
    if os.geteuid() != 0 or int(os.environ["SUDO_UID"]) != owner[0] or owner[0] <= 0 or directory.stat().st_uid != owner[0] or request_path.resolve().parent != directory:
        raise ValueError("Unauthenticated cgroup benchmark request")
    group = Path("/sys/fs/cgroup") / ("hazim-integrated-" + uuid.uuid4().hex)
    result = {"status": "rejected", "temporary_cgroup_removed": False, "collection_ready": False}
    group.mkdir()
    try:
        print(json.dumps({"status": "accepted", "cgroup": str(group)}), flush=True)
        if not select.select([0], [], [], 8)[0]:
            raise TimeoutError("Benchmark target request deadline")
        action, raw_pid, lifetime = input().split()
        target = Path("/proc") / raw_pid
        if action != "TARGET" or target.stat().st_uid != owner[0] or target.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19] != lifetime:
            raise ValueError("Benchmark target owner/lifetime differs")
        readiness = os.open(directory / "exec-ready", os.O_RDONLY | os.O_NONBLOCK)
        try:
            if not select.select([readiness], [], [], 5)[0] or os.read(readiness, 64) != b"READY\n":
                raise ValueError("Original Bash readiness missing")
        finally:
            os.close(readiness)
        (group / "cgroup.procs").write_text(raw_pid)
        if raw_pid not in (group / "cgroup.procs").read_text().splitlines():
            raise ValueError("Benchmark cgroup migration not observed")
        signal.signal(signal.SIGALRM, lambda *_values: (_ for _ in ()).throw(TimeoutError("Benchmark FIFO deadline")))
        signal.alarm(5)
        try:
            with (directory / "attribution-gate").open("w") as stream:
                stream.write("GO\n")
        finally:
            signal.alarm(0)
        print(json.dumps({"status": "accepted", "pid": int(raw_pid)}), flush=True)
        if not select.select([0], [], [], 30)[0] or input() != "FINISH":
            raise TimeoutError("Benchmark finish deadline")
        result.update(status="accepted", sample_sha256=request["sample_sha256"])
    except BaseException as error:
        result["error"] = repr(error)
    finally:
        (group / "cgroup.kill").write_text("1")
        with (group / "cgroup.events").open() as events:
            poller = select.poll()
            poller.register(events, select.POLLPRI | select.POLLERR)
            if "populated 1" in events.read():
                poller.poll(5000)
                events.seek(0)
                if "populated 1" in events.read():
                    raise ValueError("Benchmark cgroup remains populated")
        group.rmdir()
        result["temporary_cgroup_removed"] = True
        save(directory / "attribution-result.json", result)
        os.chown(directory / "attribution-result.json", *owner)
        print(json.dumps(result), flush=True)


def broker(request_path):
    condition = json.loads(request_path.read_text())["performance_condition"]
    if condition not in ("baseline", "original", "full"):
        raise ValueError("Unsupported performance condition")
    if condition != "full":
        return group_only_broker(request_path)
    children = []

    def measured(*arguments, **keywords):
        process = MeasuredPopen(*arguments, **keywords)
        children.append(process)
        return process

    namespace = dict(identity.FROZEN)
    namespace["subprocess"] = types.SimpleNamespace(**{**vars(subprocess), "Popen": measured})
    try:
        types.FunctionType(identity.broker.__code__, namespace)(request_path)
    finally:
        request = json.loads(request_path.read_text())
        if len(children) == 1 and children[0].usage is not None:
            path = Path(request["run_dir"]) / "recorder-usage.json"
            save(path, {**children[0].usage, "returncode": children[0].returncode})
            os.chown(path, request["owner_uid"], request["owner_gid"])


class Session(identity.Session):
    def prepare(self, run_dir, sample):
        previous = self.args.iface
        self.args.iface = "enp0s3"
        old_file = identity.FROZEN["__file__"]
        identity.FROZEN["__file__"] = __file__
        try:
            return super().prepare(run_dir, sample)
        finally:
            self.args.iface = previous
            identity.FROZEN["__file__"] = old_file

    def quality(self, metadata, status, reasons):
        if os.environ["HAZIM_PERFORMANCE_CONDITION"] == "full":
            return super().quality(metadata, status, reasons)
        self.stop()
        metadata["benchmark_cgroup"] = self.result
        if not self.result or self.result["status"] != "accepted" or not self.result["temporary_cgroup_removed"]:
            return "rejected", [*reasons, "benchmark_cgroup_failed"]
        return status, reasons


def generate(base):
    tree = ast.parse(identity.generate(base))
    matches = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "integrated_exec_identity":
                    alias.name = "scoped_performance"
        elif isinstance(node, ast.Name) and node.id == "integrated_exec_identity":
            node.id = "scoped_performance"
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "TELEMETRY_SCHEMA_VERSION" for target in node.targets):
            node.value = ast.Constant(SCHEMA)
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "sample_process" for target in node.targets) and isinstance(node.value, ast.Call):
            if ast.unparse(node.value.func) != "subprocess.Popen":
                raise ValueError("Frozen target launch site differs")
            node.value.func = ast.parse("scoped_performance.launch", mode="eval").body
            matches.append("launch")
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    baseline_sites = 0
    for node in ast.walk(main):
        if (isinstance(node, ast.If) and ast.unparse(node.test) == "args.ebpf_password_file"
                and isinstance(node.body[0], ast.Assign) and ast.unparse(node.body[0]) == "ebpf_status = 'unavailable'"):
            node.test = ast.parse("args.ebpf_password_file and scoped_performance.original_sensors_enabled()", mode="eval").body
            baseline_sites += 1
    if baseline_sites != 1:
        raise ValueError("Original eBPF startup site differs")
    for parent in ast.walk(main):
        for field, value in ast.iter_fields(parent):
            if not isinstance(value, list):
                continue
            replacement = []
            for statement in value:
                replacement.append(statement)
                if isinstance(statement, ast.Assign) and ast.unparse(statement).startswith("metadata['return_code'] = sample_process.returncode"):
                    replacement.extend(ast.parse("scoped_performance.write_task_usage(run_dir, sample_process)").body)
                    matches.append("usage")
            setattr(parent, field, replacement)
    if matches != ["launch", "usage"]:
        raise ValueError("Benchmark target measurement sites differ: " + repr(matches))
    generated = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    compile(generated, "scoped-performance-runner", "exec")
    before = {node.name: ast.dump(node) for node in ast.parse(Path(base).read_text()).body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    after = {node.name: ast.dump(node) for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    if before != after:
        raise ValueError("Benchmark changed a feature/helper implementation")
    return generated


def self_test(base):
    generate(base)
    for command, expected in ((["/bin/true"], 0), (["/bin/false"], 1)):
        with MeasuredPopen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as process:
            if process.wait(timeout=3) != expected or not process.usage["wall_ns"] or process.poll() != expected:
                raise AssertionError("Actual wait4/pidfd child accounting differs")
    rows = [{"abi": abi, "task": task, "condition": condition, "repeat": repeat, "warmup": repeat < 0,
             "usage": {"returncode": 0, "wall_ns": 100, "user_seconds": 0.1, "system_seconds": 0.01, "peak_rss_kib": 100},
             "recorder_usage": {"peak_rss_kib": 100}} for abi in ("amd64", "i386") for task in ("file", "network") for repeat in range(-2, 5) for condition in ("baseline", "original", "full")]
    limits = {"full_vs_original_task_wall_median_ratio_max": 1.10, "full_vs_original_task_wall_any_pair_ratio_max": 1.25,
              "full_vs_original_task_cpu_median_ratio_max": 1.15, "recorder_rss_mib_max": 256}
    if summarize(rows, limits)["failures"]:
        raise AssertionError("Synthetic in-budget design rejected")
    changed = copy.deepcopy(rows)
    next(row for row in changed if not row["warmup"] and row["condition"] == "full")["usage"]["wall_ns"] = 126
    if not summarize(changed, limits)["failures"]:
        raise AssertionError("Over-budget pair accepted")
    try:
        summarize(rows[:-1], limits)
    except ValueError:
        pass
    else:
        raise AssertionError("Incomplete performance design accepted")
    print("PASS actual pidfd/wait4 exit accounting, unchanged-helper ASTs, prospective budget and completeness guards")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--broker", type=Path)
    group.add_argument("--self-test", type=Path)
    options = parser.parse_args()
    broker(options.broker) if options.broker else self_test(options.self_test)