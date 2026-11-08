#!/usr/bin/env python3
"""Measure a frozen benign workload with and without the v6 sidecar."""

import argparse
import copy
import ctypes
import hashlib
import json
import math
import os
import pwd
import select
import signal
import statistics
import subprocess
import tarfile
import time
from pathlib import Path

import check_live_attribution as probe


ORDER = (False, True, True, False, False, True)


def summarize(measurements):
    if len(measurements) != len(ORDER):
        raise ValueError("Incomplete paired measurement order")
    for index, row in enumerate(measurements):
        if row["position"] != index or row["instrumented"] is not ORDER[index] or row["returncode"] != 0:
            raise ValueError("Measurement order or workload result differs")
        for field in ("wall_ns", "user_seconds", "system_seconds", "peak_rss_kib"):
            value = row[field]
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError("Invalid workload measurement")
        if not row["wall_ns"] or not row["peak_rss_kib"]:
            raise ValueError("Unavailable workload duration or peak RSS")
        if row["instrumented"] and (not row["sensor_usage"]["peak_rss_kib"] or row["sensor_usage"]["user_seconds"] < 0 or row["sensor_usage"]["system_seconds"] < 0):
            raise ValueError("Unavailable recorder resource measurement")
    baseline = [row for row in measurements if not row["instrumented"]]
    observed = [row for row in measurements if row["instrumented"]]
    median = lambda rows, key: statistics.median(row[key] for row in rows)
    wall_ratio = median(observed, "wall_ns") / median(baseline, "wall_ns")
    return {"status": "bounded_paired_overhead_measured_not_collection_ready", "collection_ready": False,
            "baseline_repeats": 3, "instrumented_repeats": 3, "exact_udp_echoes_per_run": 32,
            "baseline_median_wall_ns": median(baseline, "wall_ns"), "instrumented_median_wall_ns": median(observed, "wall_ns"),
            "median_wall_ratio": wall_ratio, "median_wall_change_percent": (wall_ratio - 1) * 100,
            "paired_wall_ratios": [measurements[offset + int(not ORDER[offset])]["wall_ns"] / measurements[offset + int(ORDER[offset])]["wall_ns"] for offset in (0, 2, 4)],
            "baseline_median_cpu_seconds": statistics.median(row["user_seconds"] + row["system_seconds"] for row in baseline),
            "instrumented_median_cpu_seconds": statistics.median(row["user_seconds"] + row["system_seconds"] for row in observed),
            "recorder_usage": [row["sensor_usage"] for row in observed],
            "global_kernel_hook_overhead_covered": False, "kernel_map_memory_measured": False,
            "acceptance_budget_defined": False, "general_overhead_accepted": False,
            "limits": "Three paired short Python-plus-32-echo tasks; startup/cache/order noise, fork/exec RSS and no kernel-map/global-hook accounting; no invented performance budget or general overhead acceptance"}


def wait_measured(process, timeout):
    def expired(_number, _frame):
        raise TimeoutError("Bounded measurement child exceeded deadline")

    original = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        _pid, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
        return {"user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime, "peak_rss_kib": usage.ru_maxrss}
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, original)


def prepare_work(work, identity):
    work.mkdir()
    os.chown(work, identity.pw_uid, identity.pw_gid)
    probe.save(work / "manifest.json", {"task_mode": "udp"})
    os.chown(work / "manifest.json", identity.pw_uid, identity.pw_gid)


def run(root, manifest):
    identity = pwd.getpwnam("csci")
    report = {"status": "failed_preserved", "collection_ready": False, "malware_executions": 0,
              "ownership_verified": False, "frame_mapping_verified": False, "measurements": []}
    try:
        for index, instrumented in enumerate(ORDER):
            work = root / ("run-%02d" % index)
            prepare_work(work, identity)
            cgroup = Path("/sys/fs/cgroup") / ("hazim-overhead-" + manifest["stamp"] + "-" + str(index))
            cgroup.mkdir()
            sensor = None
            child = None
            watcher = -1
            try:
                with (work / "sensor.log").open("xb") as sensor_log:
                    if instrumented:
                        library = ctypes.CDLL(None, use_errno=True)
                        watcher = library.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
                        if watcher < 0 or library.inotify_add_watch(watcher, os.fsencode(work), 2 | 8 | 256) < 0:
                            raise OSError(ctypes.get_errno(), "Overhead readiness watcher")
                        sensor = subprocess.Popen([str(root / manifest["sensor_name"]), "--capture", str(root / "lifecycle.bpf.o"),
                            str(cgroup), "20", "overhead-" + str(index), str(work / "observations.jsonl")],
                            stdin=subprocess.DEVNULL, stdout=sensor_log, stderr=subprocess.STDOUT, start_new_session=True)
                        deadline = time.monotonic() + 10
                        while True:
                            path = work / "observations.jsonl"
                            if path.exists() and any('"record":"attached"' in line for line in path.read_text().splitlines()):
                                break
                            if sensor.poll() is not None or time.monotonic() >= deadline:
                                raise ValueError("Overhead recorder failed before attachment")
                            if select.select([watcher], [], [], max(0, deadline - time.monotonic()))[0]:
                                os.read(watcher, 65536)

                    def membership():
                        (cgroup / "cgroup.procs").write_text(str(os.getpid()))
                        os.setgroups([])
                        os.setgid(identity.pw_gid)
                        os.setuid(identity.pw_uid)

                    before = time.monotonic_ns()
                    with (work / "workload.log").open("xb") as output:
                        child = subprocess.Popen(["/usr/bin/python3", str(root / "check_live_attribution.py"), "--workload", str(work)],
                            stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, preexec_fn=membership, start_new_session=True)
                        usage = wait_measured(child, 6)
                    measurement = {"position": index, "instrumented": instrumented, "wall_ns": time.monotonic_ns() - before,
                                   "returncode": child.returncode, "pid": child.pid, **usage}
                    if child.returncode:
                        raise ValueError("Measured workload failed with exit " + str(child.returncode) + "; see preserved workload.log")
                    receipt = json.loads((work / "workload.json").read_text())
                    markers = [prefix + "%03d" % item for prefix in ("HAZIM_LIVE_", "HAZIM_CONN_") for item in range(16)]
                    if child.returncode or receipt["pid"] != child.pid or receipt["status"] != "accepted" or receipt["messages_received_and_echoed"] != markers:
                        raise ValueError("Measured actual benign echo receipts differ")
                    if sensor is not None:
                        measurement["sensor_usage"] = wait_measured(sensor, 25)
                        rows = [json.loads(line) for line in (work / "observations.jsonl").read_text().splitlines()]
                        if sensor.returncode or next(row["schema"] for row in rows if row.get("record") == "session") != manifest["sensor_schema"]:
                            raise ValueError("Measured sensor exit/schema differs")
                        measurement["capability"] = {**probe.audit_records(rows), **probe.audit_task(rows, receipt)}
                    probe.save(work / "measurement.json", measurement)
                    report["measurements"].append(measurement)
            finally:
                probe.stop_process(child, signal.SIGTERM)
                probe.stop_process(sensor, signal.SIGTERM)
                if watcher >= 0:
                    os.close(watcher)
                cgroup.rmdir()
        report.update(summarize(report["measurements"]), temporary_cgroup_removed=True,
                      status="load_attach_and_overhead_capability_passed_not_collection_ready")
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        probe.save(root / "guest_result.json", report)
        with tarfile.open(root / "evidence.tgz", "x:gz") as archive:
            for path in sorted(root.glob("run-*/*")):
                if path.is_file() and not path.is_symlink():
                    archive.add(path, arcname=str(path.relative_to(root)), recursive=False)
            archive.add(root / "guest_result.json", arcname="guest_result.json", recursive=False)
        for name in ("guest_result.json", "evidence.tgz"):
            os.chown(root / name, identity.pw_uid, identity.pw_gid)


def audit_saved(root, publish=True):
    report = json.loads((root / "guest_result.json").read_text())
    state = json.loads((root / "final_vm_state.json").read_text())
    if report["status"] != "load_attach_and_overhead_capability_passed_not_collection_ready" or report.get("temporary_cgroup_removed") is not True:
        raise ValueError("Overhead execution or cgroup cleanup failed")
    if state["guest"]["VMState"] != '"poweroff"' or state["guest"]["CurrentSnapshotName"] != '"clean-tls-paired-2026-10-19"' or state["sink"]["VMState"] != '"running"':
        raise ValueError("Saved overhead guest cleanup differs")
    for vm in state.values():
        if vm["nic1"] != '"intnet"' or vm["intnet1"] != '"malnet"' or any(vm["nic" + str(index)] != '"none"' for index in range(2, 9)):
            raise ValueError("Saved overhead isolation differs")
    manifest = json.loads((root / "manifest.json").read_text())
    expected = {"guest_result.json"}
    for index, instrumented in enumerate(ORDER):
        expected.update("run-%02d/" % index + name for name in ("manifest.json", "workload.json", "workload.log", "sensor.log", "measurement.json"))
        if instrumented:
            expected.add("run-%02d/observations.jsonl" % index)
    measurements = []
    with tarfile.open(root / "evidence.tgz") as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or {member.name for member in members} != expected or any(not member.isfile() or member.size > 64 * 1024 * 1024 for member in members):
            raise ValueError("Unsafe or incomplete overhead evidence archive")
        if archive.extractfile("guest_result.json").read() != (root / "guest_result.json").read_bytes():
            raise ValueError("Archived overhead guest report differs")
        for index, instrumented in enumerate(ORDER):
            prefix = "run-%02d/" % index
            measurement = json.load(archive.extractfile(prefix + "measurement.json"))
            receipt = json.load(archive.extractfile(prefix + "workload.json"))
            if receipt["status"] != "accepted" or receipt["pid"] != measurement["pid"] or len(receipt["messages_received_and_echoed"]) != 32:
                raise ValueError("Saved measured receipt differs")
            if instrumented:
                rows = [json.loads(line) for line in archive.extractfile(prefix + "observations.jsonl")]
                if next(row["schema"] for row in rows if row.get("record") == "session") != manifest["sensor_schema"]:
                    raise ValueError("Measured frozen schema differs")
                facts = {**probe.audit_records(rows), **probe.audit_task(rows, receipt)}
                if facts != measurement["capability"]:
                    raise ValueError("Measured capability facts differ")
            measurements.append(measurement)
    if report["measurements"] != measurements:
        raise ValueError("Measured guest facts differ from archived measurements")
    derived = {**summarize(measurements), "measurements": measurements, "negative_measurement_guards": self_test(),
               "validator_sha256": probe.digest(Path(__file__)),
               "inputs": {name: probe.digest(root / name) for name in ("protocol.json", "manifest.json", "payload.tgz", "evidence.tgz", "guest_result.json", "final_vm_state.json")}}
    if publish:
        destination = root / ("validation-derived-" + probe.datetime.now(probe.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        probe.save(destination, derived)
        print(destination, flush=True)
    return derived


def self_test():
    rows = [{"position": index, "instrumented": value, "returncode": 0, "wall_ns": 120 if value else 100,
             "user_seconds": 0.1, "system_seconds": 0.01, "peak_rss_kib": 100,
             "sensor_usage": {"user_seconds": 0.01, "system_seconds": 0.01, "peak_rss_kib": 200}} for index, value in enumerate(ORDER)]
    result = summarize(rows)
    assert result["median_wall_ratio"] == 1.2 and result["paired_wall_ratios"] == [1.2] * 3
    variants = [rows[:-1]]
    for field, value in (("instrumented", True), ("wall_ns", float("nan")), ("returncode", 1), ("peak_rss_kib", 0)):
        changed = copy.deepcopy(rows)
        changed[0][field] = value
        variants.append(changed)
    for changed in variants:
        try:
            summarize(changed)
        except ValueError:
            continue
        raise AssertionError("Invalid overhead measurement accepted")
    return len(variants)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.parse_args()
    print("PASS paired overhead metric guards:", self_test(), "; no guest/BPF operation")