#!/usr/bin/env python3
"""Build musl-only BSD libraries and verified portable base64 for netcat."""

import argparse
import base64
import datetime
import json
import os
import shlex
import subprocess
from pathlib import Path

import prepare_remediation_sources as sources


def build(source_attempt):
    authentication = source_attempt / "authentication.json"
    authenticated = json.loads(authentication.read_text())
    if authenticated["status"] != "authenticated":
        raise ValueError("Dependency sources not authenticated")
    protocol = json.loads((source_attempt / "protocol.json").read_text())
    for name, expected in protocol["input_hashes"].items():
        if sources.digest(Path(name)) != expected:
            raise ValueError("Dependency authentication input changed: " + name)
    for name, expected in authenticated["files"].items():
        if sources.digest(source_attempt / name) != expected:
            raise ValueError("Dependency archive changed")
    for name in protocol["input_hashes"]:
        if name.endswith("InRelease"):
            subprocess.run(["gpgv", "--keyring", sources.auditor().KEYRING, name], check=True, capture_output=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = source_attempt / "builds" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    compiler = sources.NATIVE / "prepare_compatible_static.sh"
    uapi = attempt / "uapi"
    uapi.mkdir()
    for name, directory in {"linux": "/usr/include/linux", "asm-generic": "/usr/include/asm-generic",
                            "asm": "/usr/include/x86_64-linux-gnu/asm"}.items():
        (uapi / name).symlink_to(directory, target_is_directory=True)
    compiler_command = ["bash", str(compiler), "--cc", "-idirafter", str(uapi)]
    environment = dict(os.environ)
    for name in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PKG_CONFIG_PATH"):
        environment.pop(name, None)
    prefix = attempt / "install"
    environment.update(CC=shlex.join(compiler_command), CFLAGS="-O2", CPPFLAGS="-I" + str(prefix / "include"),
                       LDFLAGS="-static -L" + str(prefix / "lib"), PKG_CONFIG_LIBDIR=str(prefix / "lib/pkgconfig"))
    report = {"status": "building", "authentication_path": str(authentication),
              "authentication_sha256": sources.digest(authentication), "compiler_driver_sha256": sources.digest(compiler),
              "build_driver_sha256": sources.digest(Path(__file__)), "collection_ready": False, "vm_operations": 0,
              "sysctl_header_sha256": sources.digest(Path("/usr/include/linux/sysctl.h")),
              "system_installation": False, "libraries": {}}
    (attempt / "build_driver.py").write_bytes(Path(__file__).read_bytes())
    sources.save(attempt / "protocol.json", report)

    def command(arguments, directory, label):
        with (attempt / (label + ".log")).open("xb") as output:
            subprocess.run(arguments, cwd=directory, env=environment, stdout=output,
                           stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=300, check=True)

    try:
        subprocess.run(["sha256sum", "-c", str(sources.NATIVE / "compatible-static/musl-package-sha256.txt")],
                       cwd=sources.NATIVE / "compatible-static/musl-debs", check=True)
        for project in ("libmd", "libbsd", "openssh"):
            descriptors = list((source_attempt / "sources" / project).glob("*.dsc"))
            if len(descriptors) != 1:
                raise ValueError("Expected one dependency descriptor")
            tree = attempt / project
            command(["dpkg-source", "-x", str(descriptors[0]), str(tree)], attempt, project + "-unpack")
            if project == "openssh":
                continue
            command([str(tree / "configure"), "--prefix=" + str(prefix), "--disable-shared", "--enable-static",
                     "--disable-dependency-tracking"], tree, project + "-configure")
            command(["make", "-j2"], tree, project + "-make")
            command(["make", "install"], tree, project + "-install")
            library = prefix / "lib" / (project + ".a")
            report["libraries"][project] = {"path": str(library), "sha256": sources.digest(library)}
        portable = attempt / "base64"
        portable.mkdir()
        originals = attempt / "openssh/openbsd-compat"
        report["base64_source_hashes"] = {}
        for name in ("base64.c", "base64.h"):
            original = originals / name
            text = original.read_text()
            if text.count('#include "includes.h"') != 1:
                raise ValueError("Portable base64 umbrella include changed")
            (portable / name).write_text(text.replace('#include "includes.h"', '#include <sys/types.h>'))
            report["base64_source_hashes"][name] = {"original": sources.digest(original), "adapted": sources.digest(portable / name)}
        command([*compiler_command, "-D_GNU_SOURCE", "-O2", "-Wall", "-Wextra", "-c", str(portable / "base64.c"),
                 "-o", str(portable / "base64.o")], portable, "base64-compile")
        (portable / "check.c").write_text('''#include <stdio.h>
#include "base64.h"
int main(void) {
    unsigned char input[256];
    char output[345];
    for (unsigned int index = 0; index < sizeof(input); index++) input[index] = index;
    for (unsigned int length = 0; length <= sizeof(input); length++) {
        if (b64_ntop(input, length, output, sizeof(output)) < 0) return 1;
        puts(output);
    }
    return 0;
}
''')
        command([*compiler_command, "-static", "-O2", str(portable / "check.c"), str(portable / "base64.o"),
                 "-o", str(portable / "check")], portable, "base64-check-compile")
        observed = subprocess.run([str(portable / "check")], capture_output=True, check=True,
                                  stdin=subprocess.DEVNULL, timeout=5).stdout
        expected = b"".join(base64.b64encode(bytes(range(length))) + b"\n" for length in range(257))
        if observed != expected:
            raise ValueError("Portable base64 differs from independent reference")
        for name, expected_hash in authenticated["files"].items():
            if sources.digest(source_attempt / name) != expected_hash:
                raise ValueError("Dependency source changed during build")
        report.update(status="musl_dependencies_and_base64_reference_accepted", base64_reference_cases=257,
                      base64_object={"path": str(portable / "base64.o"), "sha256": sources.digest(portable / "base64.o")},
                      installed_hashes={str(path.relative_to(prefix)): sources.digest(path)
                                        for path in sorted(prefix.rglob("*")) if path.is_file() and not path.is_symlink()})
    except Exception as error:
        report.update(status="failed_preserved", error=str(error))
        raise
    finally:
        sources.save(attempt / "result.json", report)
        print(attempt, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    options = parser.parse_args()
    build(options.sources.resolve())