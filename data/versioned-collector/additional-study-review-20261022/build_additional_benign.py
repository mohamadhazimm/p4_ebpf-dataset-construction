#!/usr/bin/env python3
"""Build additional benign native static variants without altering earlier trees."""

import argparse
import importlib.metadata
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import build_matched45_controls as shared
import prepare_remediation_sources as sources
from audit_original_cohorts import elf_header


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "additional-benign-preparation/20261023T061710877601Z"
SOURCE_SHA256 = "8dcaa302465f48e4699f5d2396a6b6031ff54c018af2b3cf86bee7f3a80fbc1b"
RECIPES = {"xxhash": {"program": "xxhsum", "target": "xxhsum"},
           "lz4": {"program": "lz4", "target": "lz4"},
           "byacc": {"program": "yacc", "target": "yacc", "configure": []},
           "diffstat": {"program": "diffstat", "target": "diffstat", "configure": []},
           "dos2unix": {"program": "dos2unix", "target": "dos2unix", "make_args": ["ENABLE_NLS="]},
           "ncompress": {"program": "compress", "target": "compress"},
           "brotli": {"program": "brotli", "target": "brotli", "cmake": ["-DBROTLI_DISABLE_TESTS=ON"]},
           "expat": {"program": "xmlwf", "target": "xmlwf", "source_subdir": "expat",
                     "cmake": ["-DEXPAT_SHARED_LIBS=OFF", "-DEXPAT_BUILD_TESTS=OFF", "-DEXPAT_BUILD_EXAMPLES=OFF", "-DEXPAT_BUILD_DOCS=OFF"]},
           "indent": {"program": "indent", "target": "indent", "configure": [], "make_dir": "src"},
           "bison": {"program": "bison", "target": "src/bison", "configure": ["--disable-nls"], "m4": True, "debian_bison_autoreconf": True, "binary_prerequisites": True},
           "flex": {"program": "flex", "target": "all", "configure": ["--disable-shared", "--enable-static", "--disable-nls"],
                    "make_args": ["MAKEINFO=true", "HELP2MAN=true"], "m4": True, "libtool_static": True},
           "bmake": {"program": "bmake", "target": "bmake", "configure": ["--without-filemon", "--without-meta", "--with-default-sys-path=/nonexistent"], "bootstrap": True}}


def artifact(source, program, mode):
    matches = []
    for path in source.rglob(program):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            content = stream.read(1048576)
        if content.startswith(b"\x7fELF"):
            facts = elf_header(content)
            if facts["mode"] != mode or facts["elf_type"] != 2:
                raise ValueError("Actual ELF mode differs from static ET_EXEC request: " + str(path))
            matches.append({"path": str(path), "sha256": sources.digest(path), "mode": mode, "elf_header": facts})
    if len({row["sha256"] for row in matches}) != 1:
        raise ValueError("Expected one unique executable identity, not aliases or differing outputs: " + program)
    return min(matches, key=lambda row: (len(Path(row["path"]).parts), row["path"]))


def build(projects, reuse=None):
    authentication = SOURCE / "source-authentication.json"
    if sources.digest(authentication) != SOURCE_SHA256:
        raise ValueError("Additional source authentication changed")
    source_report = json.loads(authentication.read_text())
    for name, expected in source_report["files"].items():
        if sources.digest(SOURCE / name) != expected:
            raise ValueError("Authenticated additional source bytes changed")
    for name, expected in json.loads((SOURCE / "protocol.json").read_text())["input_hashes"].items():
        if sources.digest(Path(name)) != expected:
            raise ValueError("Additional source policy or signed input changed")
    packages = shared.audit_toolchain_packages.authenticate_packages()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "additional-benign-builds" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    report = {"status": "building", "source_attempt": str(SOURCE), "source_authentication_sha256": SOURCE_SHA256,
              "build_driver_sha256": sources.digest(Path(__file__)), "authenticated_toolchain": packages,
              "commands": [], "executables": [], "build_environments": {}, "collection_ready": False,
              "target_workload_executions": 0, "vm_operations": 0, "model_fits": 0,
              "roles_or_quotas_assigned": False,
              "build_variants_are_not_additional_program_units": True}

    def run(command, cwd, environment, label):
        report["commands"].append({"argv": command, "cwd": str(cwd), "log": label})
        with (attempt / label).open("x") as output:
            subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                           stdout=output, stderr=subprocess.STDOUT, check=True, timeout=1200)

    try:
        if reuse is not None:
            previous_path = reuse / "result.json"
            previous = json.loads(previous_path.read_text())
            if previous["source_authentication_sha256"] != SOURCE_SHA256:
                raise ValueError("Reused build source authentication differs")
            seen = set()
            for row in previous["executables"]:
                identity = (row["project"], row["mode"])
                if identity in seen or row["project"] not in RECIPES or row["program"] != RECIPES[row["project"]]["program"]:
                    raise ValueError("Duplicate or unknown reused program build")
                seen.add(identity)
                path = Path(row["path"])
                if sources.digest(path) != row["sha256"] or artifact(path.parent, row["program"], row["mode"])["sha256"] != row["sha256"]:
                    raise ValueError("Reused build identity or ELF mode changed")
                if row["project"] in projects:
                    report["executables"].append(row)
            report["reused_builds"] = {"path": str(previous_path), "sha256": sources.digest(previous_path), "count": len(report["executables"])}
        sysroot = attempt / "sysroot"
        sysroot.mkdir()
        for row in packages["packages"]:
            path = shared.STUDY / row["path"]
            if sources.digest(path) != row["sha256"]:
                raise ValueError("Authenticated toolchain package changed")
            run(["dpkg-deb", "-x", str(path), str(sysroot)], attempt, os.environ.copy(), "extract-" + row["package"] + ".log")
        compiler = Path(shutil.which("gcc")).resolve()
        report["host_compiler"] = {"path": str(compiler), "sha256": sources.digest(compiler),
                                   "version": subprocess.check_output([str(compiler), "--version"], text=True).splitlines()[0],
                                   "provenance": "existing system compiler recorded, not newly authenticated"}
        sources.save(attempt / "protocol.json", report)
        for project in projects:
            recipe = RECIPES[project]
            descriptor = list((SOURCE / "sources" / project).glob("*.dsc"))
            if len(descriptor) != 1:
                raise ValueError("Missing unique authenticated descriptor")
            for mode in ("native_amd64_static", "native_i386_static"):
                if any(row["project"] == project and row["mode"] == mode for row in report["executables"]):
                    continue
                label = project + "-" + mode
                work = attempt / label
                work.mkdir()
                source = work / "source"
                environment = dict(os.environ, LC_ALL="C", HOME=str(work), CC="gcc", CFLAGS="-O2", CPPFLAGS="", LDFLAGS="-static")
                for name in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "PKG_CONFIG_PATH", "LD_PRELOAD"):
                    environment.pop(name, None)
                if mode == "native_i386_static":
                    environment.update(shared.build_i386_controls.toolchain_environment(sysroot))
                    for name in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "PKG_CONFIG_PATH", "LD_PRELOAD"):
                        environment.pop(name, None)
                if recipe.get("m4"):
                    tool_root = shared.NATIVE / "build-tools/root"
                    macro_processor = tool_root / "usr/bin/m4"
                    environment["M4"] = str(macro_processor)
                    environment["LD_LIBRARY_PATH"] = str(tool_root / "usr/lib/x86_64-linux-gnu")
                    environment["PATH"] = str(tool_root / "usr/bin") + os.pathsep + environment["PATH"]
                    for name, filename in {"AUTOM4TE": "autom4te", "AUTOCONF": "autoconf", "AUTOHEADER": "autoheader", "ACLOCAL": "aclocal-1.16", "AUTOMAKE": "automake-1.16"}.items():
                        environment[name] = str(tool_root / "usr/bin" / filename)
                    environment["AC_MACRODIR"] = str(tool_root / "usr/share/autoconf")
                    environment["autom4te_perllibdir"] = environment["AC_MACRODIR"]
                    environment["PERL5LIB"] = str(tool_root / "usr/share/automake-1.16") + os.pathsep + environment["AC_MACRODIR"]
                    environment["ACLOCAL_PATH"] = str(tool_root / "usr/share/aclocal")
                    environment["BISON_PKGDATADIR"] = str(tool_root / "usr/share/bison")
                    environment["gettext_datadir"] = str(tool_root / "usr/share/gettext")
                    report["macro_processor"] = {"path": str(macro_processor), "sha256": sources.digest(macro_processor),
                                                 "runtime_files": {str(path): sources.digest(path) for path in (tool_root / "usr/lib/x86_64-linux-gnu").glob("libsigsegv.so*") if path.is_file()},
                                                 "provenance": "recorded existing scoped build helper, not a new independent program"}
                run(["dpkg-source", "--no-check", "-x", str(descriptor[0]), str(source)], work, environment, label + "-unpack.log")
                print("BUILD", label, flush=True)
                report["build_environments"][label] = {name: environment.get(name) for name in ("CC", "CFLAGS", "CPPFLAGS", "LDFLAGS", "PKG_CONFIG_LIBDIR", "M4", "LD_LIBRARY_PATH")}
                if "source_subdir" in recipe:
                    source = source / recipe["source_subdir"]
                if recipe.get("debian_bison_autoreconf"):
                    rules = source / "debian/rules"
                    stub = "@setfilename bison.info\n"
                    if "echo '@setfilename bison.info'" not in rules.read_text():
                        raise ValueError("Authenticated Debian Bison regeneration recipe differs")
                    (source / "doc/bison.texi").write_text(stub)
                    report.setdefault("distribution_build_steps", []).append({"project": project, "mode": mode,
                        "rules_sha256": sources.digest(rules), "documentation_stub_sha256": sources.digest(source / "doc/bison.texi"),
                        "purpose": "exact Debian DFSG autoreconf prerequisite; documentation is not credited as a built artifact"})
                    run([str(tool_root / "usr/bin/autoreconf"), "-fi"], source, environment, label + "-autoreconf.log")
                    (source / "doc/figs").mkdir(exist_ok=True)
                    documentation_inputs = [source / name for name in ("doc/bison.info", "doc/bison.help", "doc/figs/example.txt", "doc/figs/example-reduce.txt", "doc/figs/example-shift.txt", "build-aux/cross-options.pl", "src/getargs.c")]
                    documentation_inputs.extend((source / "doc").glob("*.texi"))
                    for path in documentation_inputs:
                        path.touch(exist_ok=True)
                        os.utime(path, (946684800, 946684800))
                    report["distribution_build_steps"][-1]["documentation_prerequisite_hashes"] = {str(path.relative_to(source)): sources.digest(path) for path in documentation_inputs}
                if "cmake" in recipe:
                    cmake = Path(shutil.which("cmake")).resolve()
                    with cmake.open("rb") as stream:
                        if stream.read(2) == b"#!":
                            cmake = Path(importlib.metadata.distribution("cmake").locate_file("cmake/data/bin/cmake")).resolve()
                    report["cmake"] = {"path": str(cmake), "sha256": sources.digest(cmake),
                                       "version": subprocess.check_output([str(cmake), "--version"], text=True).splitlines()[0],
                                       "provenance": "existing host tool recorded, not newly authenticated"}
                    build_dir = source / "_native_build"
                    run([str(cmake), "-S", str(source), "-B", str(build_dir), "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
                         "-DCMAKE_C_FLAGS=" + environment["CFLAGS"] + " " + environment["CPPFLAGS"],
                         "-DCMAKE_EXE_LINKER_FLAGS=" + environment["LDFLAGS"], *recipe["cmake"]],
                        source, environment, label + "-configure.log")
                    run([str(cmake), "--build", str(build_dir), "--target", recipe["target"], "-j2"],
                        source, environment, label + "-make.log")
                if "configure" in recipe:
                    configure = ["./configure", *recipe["configure"]]
                    if mode == "native_i386_static":
                        configure.append("--host=i686-linux-gnu")
                    run(configure, source, environment, label + "-configure.log")
                if recipe.get("binary_prerequisites"):
                    run(["make", "--no-print-directory", "-s", "--eval=__hazim_built_sources:;@printf '%s\\n' '$(BUILT_SOURCES)'", "__hazim_built_sources"],
                        source, environment, label + "-prerequisites.log")
                    prerequisites = (attempt / (label + "-prerequisites.log")).read_text().split()
                    if not prerequisites or any(name.startswith(("-", "/")) or ".." in Path(name).parts for name in prerequisites):
                        raise ValueError("Unsafe or missing upstream generated prerequisite list")
                    run(["make", "-j2", *prerequisites, "CC=" + environment["CC"], "LDFLAGS=" + environment["LDFLAGS"]],
                        source, environment, label + "-generated-headers.log")
                command = ["make", "-j2", recipe["target"], "CC=" + environment["CC"],
                           "LDFLAGS=" + environment["LDFLAGS"] + (" -all-static" if recipe.get("libtool_static") else ""),
                           "BUILD_SHARED=no", "BUILD_STATIC=yes", *recipe.get("make_args", [])]
                if recipe.get("bootstrap"):
                    run(["sh", "./make-bootstrap.sh"], source, environment, label + "-make.log")
                elif "cmake" not in recipe:
                    run(command, source / recipe.get("make_dir", ""), environment, label + "-make.log")
                report["executables"].append({"project": project, "program": recipe["program"],
                    "unit": project + "::" + recipe["program"], **artifact(source, recipe["program"], mode),
                    "source_descriptor_sha256": sources.digest(descriptor[0]),
                    "source_variant": "signed-index-authenticated source with distribution patches",
                    "workload_status": "pending_substantive_host_and_guest_checks"})
        report["status"] = "accepted_build_only_host_and_guest_workloads_pending"
    except Exception as error:
        report.update({"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error)})
        raise
    finally:
        report["logs"] = {path.name: sources.digest(path) for path in attempt.glob("*.log")}
        sources.save(attempt / "result.json", report)
        print(attempt, flush=True)


def self_test():
    assert len(RECIPES) == len({row["program"] for row in RECIPES.values()})
    assert set(RECIPES) <= {row["project"] for row in json.loads((SOURCE / "source-authentication.json").read_text())["projects"]}
    try:
        artifact(Path("/nonexistent-additional-source"), "xxhsum", "native_i386_static")
    except ValueError:
        pass
    else:
        raise AssertionError("Missing executable accepted")
    print("PASS authenticated recipe membership, independent program names and missing executable rejection; no build")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--build", action="store_true")
    parser.add_argument("--project", choices=sorted(RECIPES), action="append")
    parser.add_argument("--reuse", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    elif not options.project or len(options.project) != len(set(options.project)):
        parser.error("Choose each requested project once")
    else:
        build(options.project, options.reuse.resolve() if options.reuse else None)