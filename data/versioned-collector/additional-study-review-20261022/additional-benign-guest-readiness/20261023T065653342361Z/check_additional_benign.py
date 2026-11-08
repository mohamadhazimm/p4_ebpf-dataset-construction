import argparse,csv,hashlib,io,json,os,re,subprocess,tarfile
from pathlib import Path
from types import SimpleNamespace
GRAMMAR='%{\n#include <stdio.h>\nint yylex(void);\nvoid yyerror(const char *message);\n%}\n%token NUMBER\n%left \'+\'\n%left \'*\'\n%%\ninput: expr { printf("%d\\n", $1); };\nexpr: NUMBER | expr \'+\' expr { $$ = $1 + $3; } | expr \'*\' expr { $$ = $1 * $3; };\n%%\nstatic const char *cursor = "3+4*5";\nint yylex(void) { int token = *cursor++; if (token >= \'0\' && token <= \'9\') { yylval = token - \'0\'; return NUMBER; } return token; }\nvoid yyerror(const char *message) { fprintf(stderr, "%s\\n", message); }\nint main(void) { return yyparse(); }\n'
LEXER='%option noyywrap\n%{\n#include <stdio.h>\n#include <stdlib.h>\nstatic int numbers, words, total;\n%}\n%%\n[0-9]+ { numbers++; total += atoi(yytext); }\n[a-zA-Z]+ { words++; }\n[ \\t\\r\\n]+ ;\n. { return 2; }\n%%\nint main(void) { int status = yylex(); if (status) return status; printf("%d %d %d\\n", numbers, words, total); return 0; }\n'
def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1048576), b""):
            checksum.update(block)
    return checksum.hexdigest()


def expect(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")


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


def xml_error(stdout, stderr):
    diagnostic = stdout + stderr
    return b"invalid.xml:" in diagnostic and b"mismatched tag" in diagnostic


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
        save(work / ("command-%02d.json" % number), receipts[-1])
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
        malformed = command(["invalid.xml"], 2)
        expect(xml_error(malformed.stdout, malformed.stderr), "Malformed XML diagnostic differs")
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

def hash_reference(content,bits):
    return manifest["xxhash_references"][str(bits)][hashlib.sha256(content).hexdigest()]

def main(root):
    global manifest,M4_I386,M4_AMD64,builds
    manifest=json.loads((root/"manifest.json").read_text())
    M4_I386=root/"dependencies/m4-i386"
    M4_AMD64=root/"dependencies/m4-amd64"
    builds=SimpleNamespace(shared=SimpleNamespace(NATIVE=root/"support"))
    report={"status":"running","results":[],"collection_ready":False,"bpf_loaded":False,"malware_executions":0,"model_fits":0,"generated_outputs_compiled_in_guest":False}
    try:
        for name,expected in manifest["payload_hashes"].items():
            expect(digest(root/name)==expected,"Guest payload differs: "+name)
        for case in manifest["cases"]:
            row=dict(case,path=str(root/case["payload_path"]))
            try:
                result=task(row,root/(row["project"]+"-"+row["mode"]),compile_generated=False)
            except Exception as error:
                result={"status":"failed_preserved","unit":row["unit"],"mode":row["mode"],"error":type(error).__name__+": "+str(error)}
            report["results"].append(result)
            print(result["status"],row["unit"],row["mode"],flush=True)
        expect(all(digest(root/name)==expected for name,expected in manifest["payload_hashes"].items()),"Guest input changed")
        report["status"]="accepted_guest_tasks_host_generated_output_checks_pending" if all(row["status"]=="accepted" for row in report["results"]) else "failed_preserved"
    except Exception as error:
        report.update(status="failed_preserved",error=type(error).__name__+": "+str(error))
        raise
    finally:
        save(root/"guest_validation.json",report)
        with tarfile.open(root/"evidence.tgz","x:gz") as archive:
            archive.add(root/"guest_validation.json",arcname="guest_validation.json",recursive=False)
            for case in manifest["cases"]:
                work=root/(case["project"]+"-"+case["mode"])
                if work.is_dir():
                    for path in sorted(work.rglob("*")):
                        expect(not path.is_symlink(),"Unexpected task symlink")
                        if path.is_file():archive.add(path,arcname=str(path.relative_to(root)),recursive=False)
    return report["status"]!="failed_preserved"

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("root",type=Path)
    raise SystemExit(0 if main(parser.parse_args().root.resolve()) else 2)
