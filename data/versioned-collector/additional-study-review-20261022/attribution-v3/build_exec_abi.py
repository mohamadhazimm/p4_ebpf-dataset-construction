#!/usr/bin/env python3
"""Build a separate exec-ABI boundary candidate without loading BPF."""

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


REVIEW = Path(__file__).resolve().parent.parent
PREPARATION = REVIEW / "remediation-preparation/20261022T122641888212Z"
BASE = PREPARATION / "attribution-allocator-builds/20261022T140636919722Z"
HEADERS = PREPARATION / "attribution-builds/20261022T124141961818Z/headers"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Pinned source anchor changed: " + old[:100])
    return text.replace(old, new)


def sources():
    header = replace_once((BASE / "sensor-private.h").read_text(),
                          "    unsigned int origin_tid;", "    unsigned int origin_tid;\n    unsigned long long exec_success_ns;\n    unsigned char exec_abi;")
    core = (BASE / "core.bpf.c").read_text()
    anchor = """    } else {
        count(4);
    }
    bpf_map_delete_elem(&pending, &identity);"""
    boundary = """    } else if (operation && operation->thread_start_ns == event->thread_start_ns &&
               operation->syscall_id == 59 && operation->abi == 0 &&
               event->syscall_id == 11 && event->abi == 1 && event->result == 0 &&
               operation->exec_abi == 1 && operation->begin_ns < operation->exec_success_ns &&
               operation->exec_success_ns < event->monotonic_ns) {
        event->kind = 22;
        event->operation_begin_ns = operation->begin_ns;
        event->arguments[0] = operation->syscall_id;
        event->arguments[1] = operation->abi;
        event->arguments[2] = operation->exec_success_ns;
    } else {
        count(4);
    }
    bpf_map_delete_elem(&pending, &identity);"""
    core = replace_once(core, anchor, boundary)
    anchor = """    event->related_pid = context->old_pid;
    __u32 offset = context->__data_loc_filename & 0xffff;"""
    success = """    event->related_pid = context->old_pid;
    __u64 identity = bpf_get_current_pid_tgid();
    struct attr_pending *operation = bpf_map_lookup_elem(&pending, &identity);
    if (operation && operation->thread_start_ns == event->thread_start_ns &&
        ((operation->abi == 0 && (operation->syscall_id == 59 || operation->syscall_id == 322)) ||
         (operation->abi == 1 && (operation->syscall_id == 11 || operation->syscall_id == 358)))) {
        operation->exec_success_ns = event->monotonic_ns;
        operation->exec_abi = event->abi;
        event->operation_begin_ns = operation->begin_ns;
        event->arguments[0] = operation->syscall_id;
        event->arguments[1] = operation->abi;
    }
    __u32 offset = context->__data_loc_filename & 0xffff;"""
    core = replace_once(core, anchor, success)
    lifecycle = replace_once((BASE / "lifecycle.bpf.c").read_text(), "#define ATTR_VERSION 5", "#define ATTR_VERSION 6")
    recorder = (BASE / "recorder.c").read_text().replace("attribution-sensor-v5", "attribution-sensor-v6")
    recorder = replace_once(recorder, "#define ATTR_VERSION 5", "#define ATTR_VERSION 6")
    recorder = replace_once(recorder, "event->kind > 21", "event->kind > 22")
    recorder = replace_once(recorder,
        "    return event->pid && event->tid && event->process_start_ns && event->thread_start_ns;",
        """    if (event->kind == 22 && (event->abi != 1 || event->syscall_id != 11 || event->result ||
            event->related_pid || event->arguments[0] != 59 || event->arguments[1] != 0 ||
            !event->operation_begin_ns || event->operation_begin_ns >= event->arguments[2] ||
            event->arguments[2] >= event->monotonic_ns))
        return false;
    return event->pid && event->tid && event->process_start_ns && event->thread_start_ns;""")
    recorder = replace_once(recorder,
        """    event.kind = 22;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.kind = ATTR_EGRESS;""",
        """    event.kind = 22;
    event.abi = 1;
    event.syscall_id = 11;
    event.operation_begin_ns = 10;
    event.arguments[0] = 59;
    event.arguments[2] = 20;
    event.monotonic_ns = 30;
    if (!valid_event(&event, sizeof(event)))
        return 1;
    event.arguments[2] = 0;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.arguments[2] = 20;
    event.abi = 0;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.abi = 1;
    event.arguments[0] = 11;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.arguments[0] = 59;
    event.kind = 23;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.kind = ATTR_EGRESS;""")
    return {"sensor-private.h": header, "core.bpf.c": core, "lifecycle.bpf.c": lifecycle, "recorder.c": recorder}


def run():
    if digest(BASE / "result.json") != "c3e9c2fc68f61d0dc2a1b0e3366999a18c91295a044cc169e833bc8298dfc0d7":
        raise ValueError("Accepted v5 build report changed")
    previous = json.loads((BASE / "result.json").read_text())
    pins = {Path(name): expected for name, expected in previous["input_hashes"].items()}
    pins.update({BASE / name: expected for name, expected in previous["outputs"].items()})
    for path, expected in pins.items():
        if digest(path) != expected:
            raise ValueError("Frozen v5 source/dependency changed: " + str(path))
    base_inspected = subprocess.run([str(BASE / "attribution-v5"), "--inspect", str(BASE / "lifecycle.bpf.o")],
                                    check=True, capture_output=True, text=True).stdout
    programs = sorted(line.split()[0] for line in base_inspected.splitlines())
    if len(programs) != 23 or len(set(programs)) != 23:
        raise ValueError("Actual accepted v5 program inventory differs")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = PREPARATION / "attribution-exec-abi-builds" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    print(attempt, flush=True)
    report = {"status": "building", "schema": "attribution-exec-abi-build-v6", "collection_ready": False,
              "bpf_loaded": False, "hooks_attached": False, "live_validation_passed": False,
              "build_driver_sha256": digest(Path(__file__)), "base_report_sha256": digest(BASE / "result.json"),
              "base_inventory_metadata_warning": "Frozen v5 report programs field contains a sorted digest due to variable shadowing; actual accepted object is independently inspected and unchanged",
              "input_hashes": {str(path): expected for path, expected in pins.items()},
              "boundary_contract": "Kind22 retains actual exit syscall11/ABI1 plus originating entry59/ABI0 and observed same-task exec-success timestamp; unmatched paths still error; only bounded amd64 execve to i386 supported"}
    try:
        for name, text in sources().items():
            (attempt / name).write_text(text)
        (attempt / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
        command = previous["command"][:]
        command[-3], command[-1] = str(attempt / "lifecycle.bpf.c"), str(attempt / "lifecycle.bpf.o")
        dependencies = PREPARATION / "dependencies/root"
        environment = dict(os.environ, LD_LIBRARY_PATH=str(dependencies / "usr/lib/x86_64-linux-gnu"))
        report["command"] = command
        with (attempt / "compile.log").open("xb") as output:
            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=environment, check=True)
        skeleton = subprocess.run(["bpftool", "gen", "skeleton", str(attempt / "lifecycle.bpf.o")], check=True, capture_output=True, text=True).stdout
        if skeleton.count("struct bpf_program *") != len(programs) or any("*" + name + ";" not in skeleton for name in programs):
            raise ValueError("Compiled v6 program inventory changed")
        (attempt / "skeleton.h").write_text(skeleton)
        if digest(BASE / "guest.btf") != previous["guest_btf_sha256"]:
            raise ValueError("Actual saved guest BTF changed")
        subprocess.run(["bpftool", "gen", "min_core_btf", str(BASE / "guest.btf"), str(attempt / "minimum-guest.btf"), str(attempt / "lifecycle.bpf.o")], check=True, capture_output=True)
        binary = attempt / "attribution-v6"
        subprocess.run(["gcc", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-I" + str(REVIEW / "attribution-v1"),
                        "-I" + str(HEADERS / "include"), "-I" + str(dependencies / "usr/include"), str(attempt / "recorder.c"),
                        str(HEADERS / "lib/libbpf.a"), "-L" + str(dependencies / "usr/lib/x86_64-linux-gnu"),
                        "-Wl,-rpath," + str(dependencies / "usr/lib/x86_64-linux-gnu"), "-lelf", "-lz", "-o", str(binary)],
                       check=True, env=environment)
        observed = json.loads(subprocess.run([str(binary), "--self-test"], check=True, capture_output=True, text=True).stdout)
        if observed["schema"] != "attribution-sensor-v6" or observed["ownership_verified"] or observed["frame_link_verified"]:
            raise ValueError("V6 recorder schema/claim guards differ")
        inspected = subprocess.run([str(binary), "--inspect", str(attempt / "lifecycle.bpf.o")], check=True, capture_output=True, text=True).stdout
        if len(inspected.splitlines()) != 23:
            raise ValueError("Wrong inspected v6 program count")
        for index, (cgroup, duration, run_id) in enumerate((("/", "1", "guard"), ("/sys/fs/cgroup", "1", "guard"),
                ("/sys/fs/cgroup", "0", "guard"), ("/sys/fs/cgroup", "31", "guard"), ("/sys/fs/cgroup", "1", "../unsafe"))):
            output = attempt / ("must-not-exist-" + str(index))
            invalid = subprocess.run([str(binary), "--capture", str(attempt / "lifecycle.bpf.o"), cgroup, duration, run_id, str(output)], capture_output=True)
            if invalid.returncode != 2 or output.exists():
                raise ValueError("Invalid v6 capture request passed")
        for path, expected in pins.items():
            if digest(path) != expected:
                raise ValueError("Frozen source changed during v6 build")
        outputs = [*sources(), "lifecycle.bpf.o", "attribution-v6", "skeleton.h", "minimum-guest.btf"]
        report.update(status="programs_and_recorder_compiled_not_live_validated", programs=programs,
                      guest_btf_sha256=previous["guest_btf_sha256"], negative_capture_guards_passed=5,
                      outputs={name: digest(attempt / name) for name in outputs})
    except BaseException as error:
        report.update(status="failed_preserved", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        with (attempt / "result.json").open("x") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    run()