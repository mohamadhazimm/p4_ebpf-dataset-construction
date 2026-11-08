#!/usr/bin/env python3
"""Validate substantive additional benign tasks without collection or allocation."""

import argparse
import csv
import ctypes
import hashlib
import io
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import build_additional_benign as builds
from validate_remediation_workloads import digest, expect, save


ROOT = Path(__file__).resolve().parent
BUILD_ATTEMPTS = ("20261023T062028058290Z", "20261023T062102907928Z", "20261023T062326517790Z",
                  "20261023T062538301805Z", "20261023T064527447317Z")
M4_I386 = builds.shared.STUDY / "data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z/project-builds/m4/20261021T201608995369Z/source/src/m4"
M4_AMD64 = builds.shared.NATIVE / "build-tools/root/usr/bin/m4"
HASH_REFERENCE = Path("/usr/lib/x86_64-linux-gnu/libxxhash.so.0").resolve()
GRAMMAR = r'''%{
#include <stdio.h>
int yylex(void);
void yyerror(const char *message);
%}
%token NUMBER
%left '+'
%left '*'
%%
input: expr { printf("%d\n", $1); };
expr: NUMBER | expr '+' expr { $$ = $1 + $3; } | expr '*' expr { $$ = $1 * $3; };
%%
static const char *cursor = "3+4*5";
int yylex(void) { int token = *cursor++; if (token >= '0' && token <= '9') { yylval = token - '0'; return NUMBER; } return token; }
void yyerror(const char *message) { fprintf(stderr, "%s\n", message); }
int main(void) { return yyparse(); }
'''
LEXER = r'''%option noyywrap
%{
#include <stdio.h>
#include <stdlib.h>
static int numbers, words, total;
%}
%%
[0-9]+ { numbers++; total += atoi(yytext); }
[a-zA-Z]+ { words++; }
[ \t\r\n]+ ;
. { return 2; }
%%
int main(void) { int status = yylex(); if (status) return status; printf("%d %d %d\n", numbers, words, total); return 0; }
'''


def hash_reference(content, bits):
    library = ctypes.CDLL(str(HASH_REFERENCE))
    function = getattr(library, "XXH" + str(bits))
    function.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64 if bits == 64 else ctypes.c_uint32)
    function.restype = ctypes.c_uint64 if bits == 64 else ctypes.c_uint32
    buffer = ctypes.create_string_buffer(content)
    return format(function(buffer, len(content), 0), "0" + str(bits // 4) + "x")


def tokens(content):
    return re.findall(r"[A-Za-z_]\w*|\d+|!=|==|\+=|[^\s]", content)


def fixtures(work):
    payload = bytes(range(256)) * 128 + b"owned compression fixture\n" * 1024
    (work / "data.bin").write_bytes(payload)
    (work / "empty.bin").write_bytes(b"")
    (work / "abc.bin").write_bytes(b"abc")
    (work / "dos.txt").write_bytes(b"".join(("record-%04d\r\n" % index).encode() for index in range(4096)))
    (work / "valid.xml").write_text("<records>" + "".join('<item value="%d">owned</item>' % index for index in range(4096)) + "</records>\n")
    (work / "invalid.xml").write_text("<records><item></records>\n")
    (work / "change.diff").write_text("--- old.txt\n+++ new.txt\n@@ -1,3 +1,4 @@\n alpha\n-beta\n+beta2\n+gamma\n omega\n")
    (work / "source.c").write_text("int main(void){int value=7;if(value>2){value+=5;}return value!=12;}\n")
    (work / "grammar.y").write_text(GRAMMAR)
    (work / "scanner.l").write_text(LEXER)
    targets = ["result-%02d.txt" % index for index in range(8)]
    (work / "Buildfile").write_text("all: " + " ".join(targets) + "\n" + "".join(
        "%s:\n\tprintf '%%s\\n' 'owned-result-%02d' > %s\n" % (name, index, name) for index, name in enumerate(targets)))
    return payload


def task(row, work, compile_generated=True):
    work.mkdir()
    payload = fixtures(work)
    input_hashes = {path.name: digest(path) for path in work.iterdir()}
    environment = dict(os.environ, LC_ALL="C", HOME=str(work))
    for name in ("LD_PRELOAD", "PERL5OPT", "BISON_PKGDATADIR", "M4", "LD_LIBRARY_PATH"):
        environment.pop(name, None)
    if row["project"] in {"bison", "flex"}:
        environment["M4"] = str(M4_I386 if row["mode"] == "native_i386_static" else M4_AMD64)
        if row["mode"] == "native_amd64_static":
            environment["LD_LIBRARY_PATH"] = str(builds.shared.NATIVE / "build-tools/root/usr/lib/x86_64-linux-gnu")
        if row["project"] == "bison":
            environment["BISON_PKGDATADIR"] = str(Path(row["path"]).parent.parent / "data")
    receipts = []

    def command(arguments, expected_return=0, executable=None, input_bytes=None):
        selected = str(executable or row["path"])
        arguments = [str(argument) for argument in arguments]
        result = subprocess.run([selected, *arguments], cwd=work, env=environment,
                                stdin=subprocess.DEVNULL if input_bytes is None else None,
                                input=input_bytes, capture_output=True, timeout=20, check=False)
        number = len(receipts)
        (work / ("stdout-%02d.bin" % number)).write_bytes(result.stdout)
        (work / ("stderr-%02d.bin" % number)).write_bytes(result.stderr)
        receipts.append({"executable": selected, "arguments": arguments, "returncode": result.returncode,
                         "expected_returncode": expected_return, "role": "target" if executable is None else "generated-output verification helper",
                         "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()})
        expect(result.returncode == expected_return, "Unexpected task return: " + str(receipts[-1]))
        return result

    project = row["project"]
    if project == "xxhash":
        for name, content in (("empty.bin", b""), ("abc.bin", b"abc"), ("data.bin", payload)):
            for bits in (32, 64):
                result = command(["-H" + str(bits), name])
                expect(result.stdout.decode().split()[0] == hash_reference(content, bits), "xxHash independent reference mismatch")
    elif project in {"lz4", "brotli", "ncompress"}:
        if project == "lz4":
            command(["-q", "-f", "data.bin", "compressed.lz4"])
            command(["-q", "-d", "-f", "compressed.lz4", "restored.bin"])
        elif project == "brotli":
            command(["-f", "-q", "5", "-o", "compressed.br", "data.bin"])
            command(["-d", "-f", "-o", "restored.bin", "compressed.br"])
        else:
            (work / "compressed.Z").write_bytes(command(["-c", "data.bin"]).stdout)
            (work / "restored.bin").write_bytes(command(["-d", "-c", "compressed.Z"]).stdout)
        expect((work / "restored.bin").read_bytes() == payload, "Compression round-trip differs")
    elif project == "dos2unix":
        command(["-n", "dos.txt", "unix.txt"])
        expect((work / "unix.txt").read_bytes() == (work / "dos.txt").read_bytes().replace(b"\r\n", b"\n"), "Line conversion differs")
    elif project == "expat":
        command(["valid.xml"])
        expect(bool(command(["invalid.xml"], 2).stderr), "Malformed XML diagnostic absent")
    elif project == "diffstat":
        result = command(["-t", "change.diff"])
        rows = list(csv.DictReader(io.StringIO(result.stdout.decode())))
        expect(len(rows) == 1 and int(rows[0]["INSERTED"]) == 2 and int(rows[0]["DELETED"]) == 1, "Diff totals differ")
    elif project == "indent":
        command(["-npro", "-i4", "-nut", "source.c", "-o", "formatted.c"])
        expect(tokens((work / "formatted.c").read_text()) == tokens((work / "source.c").read_text()), "Formatting changed C tokens")
        if compile_generated:
            command(["formatted.c", "-o", "verified"], executable="/usr/bin/gcc")
            command([], executable=work / "verified")
    elif project in {"byacc", "bison", "flex"}:
        if project == "flex":
            command(["-o", "generated.c", "scanner.l"])
        else:
            command(["-o", "generated.c", "grammar.y"])
        expect((work / "generated.c").stat().st_size > 1000, "Generated C output missing")
        if compile_generated:
            command(["generated.c", "-o", "verified"], executable="/usr/bin/gcc")
            result = command([], executable=work / "verified", input_bytes=b"alpha 12 beta 30 gamma 7\n" if project == "flex" else None)
            expect(result.stdout == (b"3 3 49\n" if project == "flex" else b"23\n"), "Generated program semantics differ")
    elif project == "bmake":
        command(["-r", "-f", "Buildfile", "all"])
        for index in range(8):
            expect((work / ("result-%02d.txt" % index)).read_text() == "owned-result-%02d\n" % index, "Build result differs")
    else:
        raise ValueError("Unknown additional task")
    expect(input_hashes == {name: digest(work / name) for name in input_hashes}, "Task modified its frozen inputs")
    return {"status": "accepted", "unit": row["unit"], "mode": row["mode"], "executable_sha256": row["sha256"],
            "receipts": receipts, "inputs": input_hashes, "outputs": {path.name: digest(path) for path in work.iterdir() if path.is_file() and path.name not in input_hashes},
            "generated_programs_compiled_and_checked": compile_generated and project in {"indent", "byacc", "bison", "flex"}}


def run():
    reports = [ROOT / "additional-benign-builds" / stamp / "result.json" for stamp in BUILD_ATTEMPTS]
    rows = []
    for path in reports:
        report = json.loads(path.read_text())
        expect(report["status"] == "accepted_build_only_host_and_guest_workloads_pending", "Unaccepted build report")
        rows.extend(report["executables"])
    expect(len(rows) == 24 and len({row["unit"] for row in rows}) == 12 and len({row["sha256"] for row in rows}) == 24, "Unexpected program/build counts")
    for row in rows:
        expect(digest(Path(row["path"])) == row["sha256"], "Executable changed")
        expect(builds.artifact(Path(row["path"]).parent, row["program"], row["mode"])["sha256"] == row["sha256"], "Actual executable mode differs")
    attempt = ROOT / "additional-benign-workloads" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    inputs = {str(path): digest(path) for path in [*reports, Path(__file__), Path(builds.__file__), HASH_REFERENCE, M4_I386, M4_AMD64]}
    for row in rows:
        if row["project"] == "bison":
            inputs.update({str(path): digest(path) for path in (Path(row["path"]).parent.parent / "data").rglob("*") if path.is_file()})
    save(attempt / "protocol.json", {"schema": "additional-benign-host-tasks-v1", "input_hashes": inputs, "executables": rows,
         "task_scope": "substantive data-only tasks in private workspaces; parser/lexer C outputs compiled and exercised",
         "compiler": {"path": "/usr/bin/gcc", "sha256": digest(Path("/usr/bin/gcc"))}, "stdin": "target DEVNULL", "timeout_per_command_seconds": 20,
         "helper_scope": "previous m4 dependencies and compiled generated-output checks are not additional independent units",
         "collection_ready": False, "vm_operations": 0, "model_fits": 0, "roles_or_quotas_assigned": False})
    report = {"status": "running", "results": [], "collection_ready": False, "guest_validated": False}
    for row in rows:
        work = attempt / (row["project"] + "-" + row["mode"])
        try:
            result = task(row, work)
        except Exception as error:
            result = {"status": "failed_preserved", "unit": row["unit"], "mode": row["mode"], "error": type(error).__name__ + ": " + str(error)}
        report["results"].append(result)
        print(result["status"], row["project"], row["mode"], result.get("error", ""), flush=True)
    expect(all(digest(Path(name)) == expected for name, expected in inputs.items()), "Frozen host task input changed")
    report["status"] = "accepted_host_tasks_guest_pending" if all(row["status"] == "accepted" for row in report["results"]) else "failed_preserved"
    save(attempt / "result.json", report)
    print(attempt, flush=True)
    return report["status"] == "accepted_host_tasks_guest_pending"


def self_test():
    expect(hash_reference(b"", 32) == "02cc5d05" and hash_reference(b"abc", 32) == "32d153ff", "XXH32 known-vector mismatch")
    expect(hash_reference(b"", 64) == "ef46db3751d8e999" and hash_reference(b"abc", 64) == "44bc2cf5ad770999", "XXH64 known-vector mismatch")
    expect(tokens("int value=2;\n") == tokens("int  value = 2 ;"), "Formatting invariant differs")
    expect(tokens("int value=2;") != tokens("int value=3;"), "Changed C value accepted")
    print("PASS independent XXH32/64 known vectors and C-format invariance/change guards; no target workload")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--run", action="store_true")
    options = parser.parse_args()
    if options.self_test:
        self_test()
    else:
        raise SystemExit(0 if run() else 2)