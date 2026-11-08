#!/usr/bin/env python3
"""Build new static variants in fresh trees and check four benign host tasks."""

import argparse
import datetime
import json
import os
import shlex
import struct
import subprocess
from pathlib import Path

import validate_remediation_workloads as tasks


ROOT = Path(__file__).resolve().parent
PREPARATION = tasks.PREPARATION
BINARIES = {"libarchive": "bsdtar", "perl": "perl", "imagemagick": "utilities/convert", "netcat-openbsd": "nc"}


def static_elf(path):
    data = path.read_bytes()
    tasks.expect(data[:6] == b"\x7fELF\x02\x01", "Not ELF64 little endian")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    tasks.expect((elf_type, machine) == (2, 62), "Not native amd64 static ET_EXEC")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    tasks.expect(size >= 56 and count < 65535 and offset + size * count <= len(data), "Invalid ELF program table")
    kinds = {struct.unpack_from("<I", data, offset + size * index)[0] for index in range(count)}
    tasks.expect(1 in kinds and not kinds.intersection({2, 3}), "PT_DYNAMIC or PT_INTERP present")
    return "native_amd64_static"


def run(previous=None, musl=False, musl_dependencies=None):
    source_authentication = PREPARATION / "source-authentication.json"
    tasks.expect(tasks.digest(source_authentication) == "e23f74397e1145850a4dc3475b0ab1559bcadc2ed8797aeb06da4d227b23f2a1", "Source authentication changed")
    for name, expected in json.loads(source_authentication.read_text())["files"].items():
        tasks.expect(tasks.digest(PREPARATION / name) == expected, "Authenticated source changed")
    dependencies = PREPARATION / "dependencies/authentication.json"
    tasks.expect(tasks.digest(dependencies) == "d0d5deaa592ac5cc691b1779e839ae180a5bef2169d664ebc18995767a6499b9", "Dependency manifest changed")
    for name, expected in json.loads(dependencies.read_text())["extracted_files"].items():
        tasks.expect(tasks.digest(PREPARATION / "dependencies/root" / name) == expected, "Build dependency changed")
    original = ROOT / "build_remediation_sources.sh"
    tasks.expect(tasks.digest(original) == "819460e0af3d2f1906fbff8c7f1a1be368eacca9f28699398c018fdb7832bd77", "Frozen build recipe changed")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = PREPARATION / "static-workload-builds" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    report = {"status": "building", "source_authentication_sha256": tasks.digest(source_authentication),
              "build_driver_sha256": tasks.digest(Path(__file__)), "original_recipe_sha256": tasks.digest(original),
              "executables": [], "results": [], "collection_ready": False, "guest_validated": False,
              "malware_executions": 0, "model_fits": 0, "new_role_or_quota_assigned": False}
    try:
        if previous:
            previous_report = json.loads((previous / "result.json").read_text())
            tasks.expect(previous_report["status"] in ("failed_preserved", "four_static_builds_and_host_workloads_accepted_guest_pending") and
                         [row["project"] for row in previous_report["executables"][:3]] == list(BINARIES)[:3] and
                         len(previous_report["results"]) in (3, 4), "Repair requires the three accepted static builds")
            for row in previous_report["executables"][:3]:
                tasks.expect(tasks.digest(Path(row["path"])) == row["sha256"] and static_elf(Path(row["path"])) == row["mode"], "Prior static identity changed")
            report["executables"] = previous_report["executables"][:3]
            report["results"] = previous_report["results"][:3]
            report["reused_three_accepted_builds_and_host_tasks"] = {"path": str(previous), "result_sha256": tasks.digest(previous / "result.json")}
        source = original.read_text()
        replacements = {
            'root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)': "root=" + shlex.quote(str(ROOT)),
            'cd "$build"\n': 'cd "$build"\nexport LDFLAGS=-static\n',
            'make -j2 bsdtar': 'make -j2 bsdtar LDFLAGS=-all-static',
            '-Doptimize=-O2': '-Doptimize=-O2 -Dldflags=-static',
            'make -j2 utilities/convert': 'make -j2 utilities/convert LDFLAGS=-all-static',
            'CFLAGS=-g -O2': 'CFLAGS=-static -g -O2',
        }
        if musl:
            tasks.expect(previous is not None, "Musl repair must reuse three accepted static builds")
            tasks.expect(musl_dependencies is not None, "Musl repair needs accepted musl-only dependencies")
            dependency_report = json.loads((musl_dependencies / "result.json").read_text())
            tasks.expect(dependency_report["status"] == "musl_dependencies_and_base64_reference_accepted" and
                         dependency_report["base64_reference_cases"] == 257, "Musl dependencies not accepted")
            prefix = musl_dependencies / "install"
            for name, expected in dependency_report["installed_hashes"].items():
                tasks.expect(tasks.digest(prefix / name) == expected, "Musl dependency changed")
            base64_object = Path(dependency_report["base64_object"]["path"])
            tasks.expect(tasks.digest(base64_object) == dependency_report["base64_object"]["sha256"], "Base64 object changed")
            report["musl_dependencies"] = {"path": str(musl_dependencies), "result_sha256": tasks.digest(musl_dependencies / "result.json")}
            native = ROOT.parent / "cohort-100x100-v18-20261021/redesign-native-x64"
            subprocess.run(["sha256sum", "-c", str(native / "compatible-static/musl-package-sha256.txt")],
                           cwd=native / "compatible-static/musl-debs", check=True)
            uapi = attempt / "uapi"
            uapi.mkdir()
            for name, directory in {"linux": "/usr/include/linux", "asm-generic": "/usr/include/asm-generic",
                                    "asm": "/usr/include/x86_64-linux-gnu/asm"}.items():
                tasks.expect(Path(directory).is_dir(), "Missing host UAPI directory: " + directory)
                (uapi / name).symlink_to(directory, target_is_directory=True)
            replacements['make -j2 CC=cc'] = 'make -j2 "CC=bash $native/prepare_compatible_static.sh --cc -idirafter ' + shlex.quote(str(uapi)) + '"'
            replacements['CFLAGS=-g -O2'] = 'CFLAGS=-static -g -O2 -include ' + str(base64_object.with_suffix(".h")) + ' -I' + str(prefix / "include")
            replacements['"LIBS=$dependencies/usr/lib/x86_64-linux-gnu/libbsd.a $dependencies/usr/lib/x86_64-linux-gnu/libmd.a -lresolv"'] = shlex.quote(
                "LIBS=" + str(base64_object) + " " + str(prefix / "lib/libbsd.a") + " " + str(prefix / "lib/libmd.a"))
            report["netcat_libc"] = "previously authenticated workspace musl; guest policy unchanged"
            report["compatible_compiler_driver_sha256"] = tasks.digest(native / "prepare_compatible_static.sh")
            report["musl_package_manifest_sha256"] = tasks.digest(native / "compatible-static/musl-package-sha256.txt")
            report["host_uapi_header_hashes"] = {name: tasks.digest(Path(name)) for name in
                                                  ("/usr/include/linux/in6.h", "/usr/include/linux/types.h", "/usr/include/linux/libc-compat.h")}
        for old, new in replacements.items():
            tasks.expect(source.count(old) == 1, "Pinned recipe adaptation differs: " + old)
            source = source.replace(old, new)
        script = attempt / "build_static.sh"
        script.write_text(source)
        subprocess.run(["bash", "-n", str(script)], check=True)
        report["generated_recipe_sha256"] = tasks.digest(script)
        tasks.save(attempt / "protocol.json", report)
        members, pixels = tasks.fixtures(attempt / "inputs")
        environment = dict(os.environ, LC_ALL="C", HOME=str(attempt), OMP_NUM_THREADS="1")
        for name in ("PERL5OPT", "PERL5LIB", "PERLLIB", "MAGICK_CONFIGURE_PATH", "MAGICK_HOME", "LD_PRELOAD"):
            environment.pop(name, None)
        for project, binary in BINARIES.items():
            if any(row["project"] == project for row in report["executables"]):
                continue
            print("BUILD STATIC", project, flush=True)
            with (attempt / (project + "-build.log")).open("x") as output:
                subprocess.run(["bash", str(script), str(PREPARATION), project, "static-" + stamp],
                               env=environment, stdout=output, stderr=subprocess.STDOUT, timeout=1200, check=True)
            path = PREPARATION / "builds" / (project + "-static-" + stamp) / binary
            row = {"project": project, "path": str(path), "sha256": tasks.digest(path), "mode": static_elf(path)}
            report["executables"].append(row)
            report["results"].append(tasks.run_task(row, attempt / project, attempt / "inputs", members, pixels, environment))
        for row in report["executables"]:
            tasks.expect(tasks.digest(Path(row["path"])) == row["sha256"], "Static executable changed during checks")
        report["status"] = "four_static_builds_and_host_workloads_accepted_guest_pending"
    except Exception as error:
        report.update({"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error)})
        raise
    finally:
        tasks.save(attempt / "result.json", report)
        print(attempt, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-and-check", action="store_true", required=True)
    parser.add_argument("--repair-netcat", type=Path)
    parser.add_argument("--musl-netcat", action="store_true")
    parser.add_argument("--musl-dependencies", type=Path)
    options = parser.parse_args()
    run(options.repair_netcat.resolve() if options.repair_netcat else None, options.musl_netcat,
        options.musl_dependencies.resolve() if options.musl_dependencies else None)