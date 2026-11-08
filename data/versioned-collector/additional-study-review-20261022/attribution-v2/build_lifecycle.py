#!/usr/bin/env python3
"""Compile lifecycle-v2 BPF and independently inspect all program sections; no load."""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REVIEW = ROOT.parent
PREPARATION = REVIEW / "remediation-preparation/20261022T122641888212Z"
BASE = PREPARATION / "attribution-builds/20261022T124141961818Z"
WORKSPACE = ROOT.parents[5]
EXPECTED = {"syscall_enter", "syscall_return", "send_enter", "send_return", "recv_enter", "recv_return",
            "packet_egress", "packet_ingress", "process_exec", "process_fork", "process_exit",
            "descriptor_install", "file_close", "file_final", "descriptor_receive_check",
            "socket_create_check", "socket_accept_check", "socket_release", "socket_connect_check", "fork_files", "files_final"}


def recorder_source():
    source = (REVIEW / "attribution-v1/attribution.c").read_text()
    replacements = {
        '#include "attribution.h"': '#include "attribution.h"\n#undef ATTR_VERSION\n#define ATTR_VERSION 2',
        'event->kind > ATTR_EXIT': 'event->kind > 21',
        'attribution-sensor-v1': 'attribution-sensor-v2',
        'return count == 11 ? 0 : 1;': 'return count == 21 ? 0 : 1;',
        'links[11]': 'links[21]',
        'link_count >= 11': 'link_count >= 21',
        'link_count == 11': 'link_count == 21',
    }
    for old, new in replacements.items():
        expected = 2 if old == 'attribution-sensor-v1' else 1
        if source.count(old) != expected:
            raise ValueError("Frozen recorder adaptation no longer matches: " + old)
        source = source.replace(old, new)
    probe = '    event.kind = ATTR_EGRESS;\n'
    if source.count(probe) != 1:
        raise ValueError("Frozen recorder self-test changed")
    source = source.replace(probe, '''    for (unsigned int kind = 12; kind <= 21; kind++) {
        event.kind = kind;
        if (!valid_event(&event, sizeof(event)))
            return 1;
    }
    event.kind = 22;
    if (valid_event(&event, sizeof(event)))
        return 1;
''' + probe)
    return source


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run():
    for name, expected in json.loads((BASE / "source_hashes.json").read_text()).items():
        if digest(Path(name)) != expected:
            raise ValueError("Frozen base sensor source changed: " + name)
    dependencies = PREPARATION / "dependencies"
    for name, expected in json.loads((dependencies / "authentication.json").read_text())["extracted_files"].items():
        if digest(dependencies / "root" / name) != expected:
            raise ValueError("Compiler dependency changed")
    attempt = PREPARATION / "attribution-lifecycle-builds" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, LD_LIBRARY_PATH=str(dependencies / "root/usr/lib/x86_64-linux-gnu"))
    command = [str(dependencies / "root/usr/bin/clang-14"), "-target", "bpf", "-D__TARGET_ARCH_x86", "-O2", "-g", "-Wall", "-Werror",
               "-I" + str(WORKSPACE / "p4_ebpf/libbpf-bootstrap/vmlinux.h/include/x86"), "-I" + str(BASE / "headers/include"),
               "-c", str(ROOT / "lifecycle.bpf.c"), "-o", str(attempt / "lifecycle.bpf.o")]
    report = {"schema": "attribution-lifecycle-build-v2", "command": command, "collection_ready": False, "bpf_loaded": False,
              "hooks_attached": False, "live_validation_passed": False, "recorder_integrated": False,
              "source_hashes": {str(path): digest(path) for path in [ROOT / "lifecycle.bpf.c", Path(__file__), REVIEW / "attribution-v1/attribution.h", REVIEW / "attribution-v1/attribution.bpf.c", REVIEW / "attribution-v1/attribution.c"]}}
    try:
        with (attempt / "compile.log").open("x") as output:
            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=environment, check=True)
        result = subprocess.run(["bpftool", "gen", "skeleton", str(attempt / "lifecycle.bpf.o")], capture_output=True, text=True, check=True)
        (attempt / "skeleton.h").write_text(result.stdout)
        for name in EXPECTED:
            if "*" + name + ";" not in result.stdout:
                raise ValueError("Compiled program missing: " + name)
        if result.stdout.count("struct bpf_program *") != len(EXPECTED):
            raise ValueError("Unexpected program count")
        generated = attempt / "recorder.c"
        generated.write_text(recorder_source())
        recorder = attempt / "attribution-v2"
        subprocess.run(["gcc", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(REVIEW / "attribution-v1"), "-I" + str(BASE / "headers/include"),
                        "-I" + str(dependencies / "root/usr/include"), str(generated),
                        str(BASE / "headers/lib/libbpf.a"), "-L" + str(dependencies / "root/usr/lib/x86_64-linux-gnu"),
                        "-Wl,-rpath," + str(dependencies / "root/usr/lib/x86_64-linux-gnu"),
                        "-lelf", "-lz", "-o", str(recorder)], env=environment, check=True)
        self_test = subprocess.run([str(recorder), "--self-test"], capture_output=True, text=True, check=True)
        observation = json.loads(self_test.stdout)
        if observation["schema"] != "attribution-sensor-v2" or observation["ownership_verified"] or observation["frame_link_verified"]:
            raise ValueError("Version-2 recorder schema or conservative evidence flags differ")
        inspect = subprocess.run([str(recorder), "--inspect", str(attempt / "lifecycle.bpf.o")], capture_output=True, text=True, check=True)
        if len(inspect.stdout.splitlines()) != 21:
            raise ValueError("Recorder did not inspect 21 programs")
        for index, request in enumerate([
            [str(attempt / "lifecycle.bpf.o"), "/", "1", "guard"],
            [str(attempt / "lifecycle.bpf.o"), "/sys/fs/cgroup", "1", "guard"],
            [str(attempt / "lifecycle.bpf.o"), "/sys/fs/cgroup", "0", "guard"],
            [str(attempt / "lifecycle.bpf.o"), "/sys/fs/cgroup", "31", "guard"],
            [str(attempt / "lifecycle.bpf.o"), "/sys/fs/cgroup", "1", "../unsafe"],
        ]):
            output = attempt / ("must-not-exist-" + str(index))
            guard = subprocess.run([str(recorder), "--capture", *request, str(output)], capture_output=True, text=True)
            if guard.returncode != 2 or output.exists():
                raise ValueError("Invalid capture request passed the pre-load guard")
        for name, expected in report["source_hashes"].items():
            if digest(Path(name)) != expected:
                raise ValueError("Source changed during compilation")
        report.update({"status": "twenty_one_programs_and_recorder_compiled_not_live_validated", "programs": sorted(EXPECTED),
                   "recorder_integrated": True, "recorder_self_test_passed": True, "negative_capture_guards_passed": 5,
                   "recorder_sha256": digest(recorder), "generated_recorder_source_sha256": digest(generated),
                   "object_sha256": digest(attempt / "lifecycle.bpf.o"), "skeleton_sha256": digest(attempt / "skeleton.h")})
    except Exception as error:
        report.update({"status": "failed_preserved", "error": str(error)})
        raise
    finally:
        with (attempt / "result.json").open("x") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
        print(attempt, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true", required=True)
    parser.parse_args()
    run()