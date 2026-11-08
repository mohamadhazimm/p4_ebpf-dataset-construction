#!/usr/bin/env python3
"""Bounded Linux exec-stop attestation for explicitly allowlisted benign tasks."""

import argparse
import ctypes
import hashlib
import json
import os
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path


SEIZE = 0x4206
CONT = 7
GETEVENTMSG = 0x4201
OPTIONS = 2 | 4 | 8 | 16 | 0x100000
WALL = 0x40000000
SCHEMA = "exec-inode-attestation-v1"
LIBRARY = ctypes.CDLL(None, use_errno=True)
LIBRARY.ptrace.restype = ctypes.c_long


def ptrace(operation, pid, data=0):
    ctypes.set_errno(0)
    result = LIBRARY.ptrace(ctypes.c_uint(operation), ctypes.c_int(pid), ctypes.c_void_p(0), ctypes.c_void_p(data))
    if result == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), "ptrace operation %d for task %d" % (operation, pid))
    return result


def event_message(pid):
    value = ctypes.c_ulong()
    ptrace(GETEVENTMSG, pid, ctypes.addressof(value))
    return value.value


def task_facts(pid):
    proc = Path("/proc/%d" % pid)
    status = proc.joinpath("status").read_text().splitlines()
    identifiers = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status if ":" in line}
    return {"pid": pid, "tgid": int(identifiers["Tgid"]),
            "uid": [int(value) for value in identifiers["Uid"].split()],
            "start_ticks": int(proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19]),
            "namespaces": {name: os.stat(proc / "ns" / name).st_ino for name in ("mnt", "pid", "net", "user")}}


def executable_facts(pid):
    descriptor = os.open("/proc/%d/exe" % pid, os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= 64 * 1024 * 1024:
            raise ValueError("Executed image is not a bounded regular file")
        digest = hashlib.sha256()
        header = os.pread(descriptor, 64, 0)
        while True:
            block = os.read(descriptor, 1048576)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Executed inode changed during hashing")
        if len(header) < 20 or header[:4] != b"\x7fELF" or header[4] not in (1, 2) or header[5] != 1:
            raise ValueError("Executed image is not a supported little-endian ELF")
        machine = int.from_bytes(header[18:20], "little")
        if (header[4], machine) not in ((1, 3), (2, 62)):
            raise ValueError("Executed image ABI outside native x86 scope")
        return {"sha256": digest.hexdigest(), "device": before.st_dev, "inode": before.st_ino,
                "size": before.st_size, "elf_class": header[4], "elf_machine": machine,
                "elf_type": int.from_bytes(header[16:18], "little"),
                "proc_exe_link": os.readlink("/proc/%d/exe" % pid)}
    finally:
        os.close(descriptor)


def validate_receipts(report, root_pid, expected_hash, sensor_events=None):
    if report.get("schema") != SCHEMA or report.get("status") != "accepted" or report.get("root_pid") != root_pid:
        raise ValueError("Exec attestation lifecycle rejected or missing")
    receipts = report["exec_receipts"]
    roots = [row for row in receipts if row["pid"] == root_pid]
    if not roots or roots[0]["image"]["sha256"] != expected_hash or report["live_tasks"]:
        raise ValueError("Exact root image or completed trace missing")
    baseline = report["initial_task"]
    identities = set()
    for row in receipts:
        identity = row["pid"], row["start_ticks"], row["monotonic_ns"]
        if identity in identities or row["stop_event"] != 4 or row["namespaces"] != baseline["namespaces"]:
            raise ValueError("Duplicate exec or namespace substitution")
        identities.add(identity)
        if row["uid"] != baseline["uid"] or row["image"]["sha256"] not in report["allowed_sha256"]:
            raise ValueError("Executed identity is not allowlisted")
        if not row["image"]["inode"] or row["image"]["elf_machine"] not in (3, 62):
            raise ValueError("Executed inode/ABI evidence missing")
    if sensor_events is not None:
        observed = [row for row in sensor_events if row.get("record") == "observation" and row.get("kind") == 9]
        if len(observed) != len(receipts):
            raise ValueError("Kernel exec/attestation counts differ")
        for receipt in receipts:
            matches = [row for row in observed if row["pid"] == receipt["tgid"] and row["tid"] == receipt["pid"]
                       and row["thread_start_ns"] * report["clock_ticks_per_second"] // 1000000000 == receipt["start_ticks"]
                       and 0 <= receipt["stop_observed_ns"] - row["monotonic_ns"] < 1000000000]
            if len(matches) != 1:
                raise ValueError("Exec attestation does not uniquely match kernel task/clock")
    return {"status": "accepted", "exec_count": len(receipts), "root_sha256": expected_hash,
            "executed_inode_verified": True, "namespace_transition_supported": False,
            "library_or_interpreter_attestation": False}


def trace(target_pid, expected_hash, allowed_hashes, seconds=28, ready=None):
    initial = task_facts(target_pid)
    if not 1 <= seconds <= 30 or len(expected_hash) != 64 or expected_hash not in allowed_hashes:
        raise ValueError("Unbounded or unallowlisted exec request")
    report = {"schema": SCHEMA, "status": "rejected", "root_pid": target_pid, "initial_task": initial,
              "allowed_sha256": sorted(allowed_hashes), "exec_receipts": [], "fork_receipts": [],
              "exit_receipts": [], "live_tasks": [target_pid], "clock_ticks_per_second": os.sysconf("SC_CLK_TCK")}
    live = {target_pid}
    previous = signal.signal(signal.SIGALRM, lambda *_arguments: (_ for _ in ()).throw(TimeoutError("Exec trace deadline")))
    signal.alarm(seconds)
    try:
        ptrace(SEIZE, target_pid, OPTIONS)
        if ready is not None:
            ready()
        while live:
            pid, status = os.waitpid(-1, WALL)
            if pid not in live:
                raise ValueError("Unexplained trace task")
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                report["exit_receipts"].append({"pid": pid, "wait_status": status})
                live.remove(pid)
                continue
            if not os.WIFSTOPPED(status):
                raise ValueError("Unrecognized exec wait status")
            event = status >> 16
            delivered_signal = os.WSTOPSIG(status)
            if event in (1, 2, 3):
                child = event_message(pid)
                if child in live:
                    raise ValueError("Duplicate child identity")
                live.add(child)
                report["fork_receipts"].append({"parent_tid": pid, "child_tid": child, "event": event})
            elif event == 4:
                stopped = time.monotonic_ns()
                former_tid = event_message(pid)
                if former_tid != pid:
                    raise ValueError("Non-leader exec requires a separate accepted gate")
                facts = task_facts(pid)
                image = executable_facts(pid)
                receipt = {**facts, "stop_observed_ns": stopped, "monotonic_ns": time.monotonic_ns(), "stop_event": event, "image": image}
                report["exec_receipts"].append(receipt)
                if facts["uid"] != initial["uid"] or facts["namespaces"] != initial["namespaces"]:
                    raise ValueError("Exec credential or namespace transition outside scope")
                if image["sha256"] not in allowed_hashes:
                    raise ValueError("Actual executed inode hash is not allowlisted")
                roots = [row for row in report["exec_receipts"] if row["pid"] == target_pid]
                if pid == target_pid and len(roots) == 1 and image["sha256"] != expected_hash:
                    raise ValueError("First root exec is not the selected executable")
            elif event != 128 and event:
                raise ValueError("Unsupported ptrace event")
            ptrace(CONT, pid, 0 if event else delivered_signal)
        report.update(status="accepted", live_tasks=[])
        validate_receipts(report, target_pid, expected_hash)
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        for pid in live:
            try:
                os.kill(pid, signal.SIGKILL)
                ptrace(CONT, pid)
            except (OSError, ProcessLookupError):
                pass
        while live:
            try:
                pid, status = os.waitpid(-1, WALL)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    report["exit_receipts"].append({"pid": pid, "wait_status": status})
                    live.discard(pid)
                elif os.WIFSTOPPED(status):
                    ptrace(CONT, pid, signal.SIGKILL)
            except ChildProcessError:
                break
        report["live_tasks"] = sorted(live)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    return report


def self_test():
    import copy
    import shutil
    with tempfile.TemporaryDirectory(prefix="hazim-exec-identity-") as temporary:
        root = Path(temporary)
        target = root / "selected"
        shutil.copyfile("/bin/true", target)
        target.chmod(0o700)
        expected = hashlib.sha256(target.read_bytes()).hexdigest()
        reports = []
        for substitute in (False, True):
            gate = root / ("gate-" + str(substitute))
            readiness = root / ("ready-" + str(substitute))
            os.mkfifo(gate, 0o600)
            os.mkfifo(readiness, 0o600)
            process = subprocess.Popen(["/bin/bash", "-c", 'printf "READY\\n" > "$1"; read -r value < "$2"; exec "$3"', "owned-test", str(readiness), str(gate), str(target)], stdin=subprocess.DEVNULL)
            with readiness.open() as stream:
                assert stream.read() == "READY\n"
            def release():
                if substitute:
                    replacement = root / "replacement"
                    shutil.copyfile("/bin/false", replacement)
                    replacement.chmod(0o700)
                    os.replace(replacement, target)
                with gate.open("w") as stream:
                    stream.write("GO\n")
            report = trace(process.pid, expected, {expected}, seconds=5, ready=release)
            process.returncode = os.waitstatus_to_exitcode(report["exit_receipts"][-1]["wait_status"])
            assert report["live_tasks"] == []
            if substitute:
                assert report["status"] == "rejected" and process.returncode == -signal.SIGKILL
                assert "inode hash" in report["error"], report
            else:
                assert report["status"] == "accepted" and process.returncode == 0
                reports.append(report)
        original = reports[0]
        for corruption in ("hash", "inode", "namespace", "duplicate", "live", "stop"):
            changed = copy.deepcopy(original)
            receipt = changed["exec_receipts"][0]
            if corruption == "hash":
                receipt["image"]["sha256"] = "0" * 64
            elif corruption == "inode":
                receipt["image"]["inode"] = 0
            elif corruption == "namespace":
                receipt["namespaces"]["net"] += 1
            elif corruption == "duplicate":
                changed["exec_receipts"].append(copy.deepcopy(receipt))
            elif corruption == "live":
                changed["live_tasks"] = [receipt["pid"]]
            else:
                receipt["stop_event"] = 0
            try:
                validate_receipts(changed, original["root_pid"], expected)
            except ValueError:
                pass
            else:
                raise AssertionError("Corrupted exec evidence accepted: " + corruption)
    print("PASS actual exec-stop inode/hash, actual pre-exec pathname substitution killed before resume, six receipt corruption guards")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--watch", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    else:
        request = json.loads(options.watch.read_text())
        report = trace(request["pid"], request["sha256"], set(request["allowed_sha256"]),
                       request["seconds"], ready=lambda: print(json.dumps({"status": "accepted", "pid": request["pid"]}), flush=True))
        with Path(request["output"]).open("x") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        raise SystemExit(0 if report["status"] == "accepted" else 2)