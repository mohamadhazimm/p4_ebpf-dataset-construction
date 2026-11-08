#!/usr/bin/env python3
"""Build and inspect an attribution candidate; never load or attach BPF."""

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parents[5]
LIBBPF = WORKSPACE / "p4_ebpf/libbpf-bootstrap/libbpf"
VMLINUX = WORKSPACE / "p4_ebpf/libbpf-bootstrap/vmlinux.h/include/x86"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(preparation):
    dependencies = preparation / "dependencies"
    authentication = json.loads((dependencies / "authentication.json").read_text())
    for name, expected in authentication["extracted_files"].items():
        if sha256(dependencies / "root" / name) != expected:
            raise ValueError("Compiler dependency changed: " + name)
    inputs = [*ROOT.glob("*.c"), *ROOT.glob("*.h"), Path(__file__), VMLINUX / "vmlinux.h", dependencies / "authentication.json", *list((LIBBPF / "src").glob("*.[ch]")), *list((LIBBPF / "include").rglob("*.h")), LIBBPF / "src/Makefile"]
    source_hashes = {str(path): sha256(path) for path in sorted(inputs)}
    attempt = preparation / "attribution-builds" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    (attempt / "source_hashes.json").write_text(json.dumps(source_hashes, indent=2, sort_keys=True) + "\n")
    environment = os.environ.copy()
    local = dependencies / "root/usr"
    environment["LD_LIBRARY_PATH"] = str(local / "lib/x86_64-linux-gnu")
    environment["C_INCLUDE_PATH"] = str(local / "include")
    environment["LIBRARY_PATH"] = str(local / "lib/x86_64-linux-gnu")
    clang = local / "bin/clang-14"
    headers = attempt / "headers"
    (attempt / "libbpf").mkdir()
    commands = [
        ["make", "-C", str(LIBBPF / "src"), "-j2", "BUILD_STATIC_ONLY=1", "OBJDIR=" + str(attempt / "libbpf") + "/", "DESTDIR=" + str(headers), "INCLUDEDIR=/include", "LIBDIR=/lib", "UAPIDIR=/include", "install"],
        [str(clang), "-target", "bpf", "-D__TARGET_ARCH_x86", "-O2", "-g", "-Wall", "-Werror", "-I" + str(VMLINUX), "-I" + str(headers / "include"), "-c", str(ROOT / "attribution.bpf.c"), "-o", str(attempt / "attribution.bpf.o")],
        ["cc", "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-I" + str(headers / "include"), str(ROOT / "attribution.c"), str(headers / "lib/libbpf.a"), "-L" + str(local / "lib/x86_64-linux-gnu"), "-lelf", "-lz", "-o", str(attempt / "attribution")],
        [str(attempt / "attribution"), "--self-test"],
        [str(attempt / "attribution"), "--inspect", str(attempt / "attribution.bpf.o")],
    ]
    report = {"schema": "attribution-build-v1", "commands": commands, "bpf_loaded": False, "hooks_attached": False, "vm_operations": 0, "target_workload_executions": 0, "collection_ready": False, "live_validation_passed": False}
    try:
        for index, command in enumerate(commands):
            print("CHECK", index, command[0], flush=True)
            with (attempt / f"check-{index}.log").open("x") as output:
                subprocess.run(command, env=environment, stdout=output, stderr=subprocess.STDOUT, check=True)
        snapshot = json.loads((attempt / "check-3.log").read_text())
        if snapshot["frame_link_verified"] or snapshot["ownership_verified"] or snapshot["pid"] or snapshot["abi"] != 255:
            raise ValueError("Synthetic packet incorrectly assigned process identity or ABI")
        inspected = (attempt / "check-4.log").read_text().splitlines()
        if len([line for line in inspected if "\t" in line]) != 11:
            raise ValueError("Missing compiled program")
        forbidden_output = attempt / "must-not-be-created.jsonl"
        for duration, run_id in [("0", "test"), ("31", "test"), ("bad", "test"), ("1", 'invalid"id')]:
            invalid = subprocess.run([str(attempt / "attribution"), "--capture", str(attempt / "attribution.bpf.o"), str(attempt), duration, run_id, str(forbidden_output)], env=environment, capture_output=True, text=True)
            if invalid.returncode != 2 or forbidden_output.exists():
                raise ValueError("Invalid capture arguments were not rejected before side effects")
        invalid = subprocess.run([str(attempt / "attribution"), "--capture", str(attempt / "attribution.bpf.o"), str(attempt), "1", "test", str(forbidden_output)], env=environment, capture_output=True, text=True)
        if invalid.returncode != 2 or forbidden_output.exists():
            raise ValueError("Ordinary directory accepted as a capture cgroup")
        for name, expected in source_hashes.items():
            if sha256(Path(name)) != expected:
                raise ValueError("Source changed during build")
        report.update({"status": "compiled_and_inspected_not_live_validated", "compiled_programs": 11, "invalid_capture_cases_rejected": 5, "output_hashes": {name: sha256(attempt / name) for name in ("attribution.bpf.o", "attribution", "source_hashes.json")}})
    except Exception as error:
        report.update({"status": "build_failed", "error": str(error)})
        raise
    finally:
        with (attempt / "result.json").open("x") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
        print(attempt, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-and-test", required=True, type=Path)
    run(parser.parse_args().build_and_test.resolve())