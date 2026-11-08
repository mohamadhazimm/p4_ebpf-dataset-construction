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
