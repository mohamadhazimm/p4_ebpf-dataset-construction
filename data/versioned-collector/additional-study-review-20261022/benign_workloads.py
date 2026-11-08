"""Shared, guest-safe benign workload registry for the matched cohort (revision5-matched).

ONE source of truth for what each benign program does, consumed by BOTH the host preflight (preflight_benign.py)
and the guest payload builder (build_revision5_payload.py) so the two cannot drift. Every workload is designed for
the production runner's constraints: stdin is DEVNULL (no interactive/piped input), the target is a single argv with
no shell, inputs are read from staged fixtures referenced by ABSOLUTE paths, and outputs are written with RELATIVE
names into the runner's writable per-sample CWD. Compressors use `-c`/`-o` (never in-place next to a shared input),
cpio EXTRACTS from a prebuilt archive via `-F` (no stdin file-list), and sqlite3 runs a script via `.read` (no stdin).

A workload() returns {fixtures, argv, rc_ok}: `fixtures` are (role, kind, size) to stage; `argv` tokens are plain
strings (literals), {"fix": role} (-> absolute fixture path), or {"out": name} (-> relative output in CWD). The host
and guest consumers resolve the tokens against their own roots. activity_bin picks the fixture size (the host
preflight measures the resulting syscall volume; the sizes were tuned so benign overlaps the malware per-mode bands).
No sample is executed here; the builders only create benign data/fixtures.
"""

import os
import random
import subprocess
from pathlib import Path

MB = {"light": 1, "medium": 16, "heavy": 64}          # streaming bytes
FILES = {"light": 50, "medium": 500, "heavy": 2000}    # tree file count
ROWS = {"light": 2000, "medium": 50000, "heavy": 300000}  # sqlite rows
_rng = random.Random(42)
WORDS = ["".join(_rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(_rng.randint(3, 9))) for _ in range(4000)]

HASHERS = {"b2sum", "cksum", "md5sum", "xxhsum", "sha1sum", "sha256sum", "sha512sum", "sum"}
ENCODERS = {"base32", "base64", "basenc"}
STDOUT_COMPRESSORS = {"gzip", "bzip2", "xz", "brotli", "compress"}  # emit to stdout via -c (no output file, no in-place)


# ---------------------------------------------------------------------------------------------- fixture builders

def _fill_stream(path, mb):
    rng = random.Random(1)
    with open(path, "wb") as handle:
        line = (" ".join(rng.choice(WORDS) for _ in range(1500)) + "\n").encode()
        while handle.tell() < mb * 1048576:
            handle.write(line + os.urandom(96) + b"\n")


def _fill_json(path, mb):
    rng = random.Random(2)
    with open(path, "w") as handle:
        handle.write("[")
        first = True
        while handle.tell() < mb * 1048576:
            handle.write(("" if first else ",") + '{"k":"%s","n":%d,"v":"%s"}' % (
                rng.choice(WORDS), rng.randint(0, 10 ** 6), rng.choice(WORDS)))
            first = False
        handle.write("]")


def _fill_xml(path, mb):
    rng = random.Random(3)
    with open(path, "w") as handle:
        handle.write("<root>")
        while handle.tell() < mb * 1048576:
            handle.write("<item id='%d'>%s</item>" % (rng.randint(0, 10 ** 6), rng.choice(WORDS)))
        handle.write("</root>")


def _fill_m4(path, mb):
    rng = random.Random(4)
    with open(path, "w") as handle:
        handle.write("define(`W', `%s')dnl\n" % rng.choice(WORDS))
        while handle.tell() < mb * 1048576:
            handle.write(" ".join(rng.choice(WORDS) for _ in range(40)) + " W\n")


def _make_tree(path, n):
    rng = random.Random(5)
    path.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (path / ("f%05d.txt" % i)).write_text(" ".join(rng.choice(WORDS) for _ in range(150)))


def _make_sql(path, rows):
    rng = random.Random(6)
    with open(path, "w") as handle:
        handle.write("CREATE TABLE t(a INTEGER, b TEXT, c TEXT);\nBEGIN;\n")
        for _ in range(rows):
            handle.write("INSERT INTO t VALUES(%d,'%s','%s');\n" % (rng.randint(0, 10 ** 9),
                                                                    rng.choice(WORDS), rng.choice(WORDS)))
        handle.write("COMMIT;\nSELECT count(*),sum(a) FROM t;\n")


def materialize(kind, size, dest_dir, cache):
    """Build (once, cached by kind+size) a fixture under dest_dir and return its absolute Path."""
    key = (kind, size)
    if key in cache:
        return cache[key]
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    if kind == "stream":
        p = dest_dir / ("stream%d.bin" % size); _fill_stream(p, size)
    elif kind == "stream_copy":
        src = materialize("stream", size, dest_dir, cache); p = dest_dir / ("streamcopy%d.bin" % size)
        p.write_bytes(src.read_bytes())
    elif kind == "json":
        p = dest_dir / ("data%d.json" % size); _fill_json(p, size)
    elif kind == "xml":
        p = dest_dir / ("data%d.xml" % size); _fill_xml(p, size)
    elif kind == "m4":
        p = dest_dir / ("data%d.m4" % size); _fill_m4(p, size)
    elif kind == "xz":
        src = materialize("stream", size, dest_dir, cache); p = dest_dir / ("stream%d.bin.xz" % size)
        subprocess.run(["xz", "-kfT1", str(src)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # xz -k writes src.xz next to src; move into deterministic name
        Path(str(src) + ".xz").replace(p)
    elif kind == "tree":
        p = dest_dir / ("tree%d" % size); _make_tree(p, size)
    elif kind == "treezip":
        tree = materialize("tree", size, dest_dir, cache); p = dest_dir / ("tree%d.zip" % size)
        p.unlink(missing_ok=True)
        subprocess.run(["zip", "-rq", str(p), tree.name], cwd=str(dest_dir), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif kind == "treecpio":
        tree = materialize("tree", size, dest_dir, cache); p = dest_dir / ("tree%d.cpio" % size)
        listing = subprocess.run(["find", ".", "-type", "f"], cwd=str(tree), capture_output=True, text=True, check=True).stdout
        with open(p, "wb") as out:
            subprocess.run(["cpio", "-o", "--quiet"], cwd=str(tree), input=listing, text=True,
                           stdout=out, stderr=subprocess.DEVNULL, check=True)
    elif kind == "gitrepo":
        p = dest_dir / ("gitrepo%d" % size); _make_tree(p, size)
        env = {**os.environ, "GIT_AUTHOR_NAME": "b", "GIT_AUTHOR_EMAIL": "b@b", "GIT_COMMITTER_NAME": "b",
               "GIT_COMMITTER_EMAIL": "b@b", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
        q = dict(cwd=str(p), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(["git", "init", "-q"], **q)
        subprocess.run(["git", "add", "-A"], **q)
        subprocess.run(["git", "commit", "-q", "-m", "seed"], **q)
    elif kind == "sql":
        p = dest_dir / ("insert%d.sql" % size); _make_sql(p, size)
    else:
        raise ValueError("unknown fixture kind: " + kind)
    cache[key] = p
    return p


# ---------------------------------------------------------------------------------------------- per-program workloads

def workload(program, activity_bin):
    """Return {fixtures:[(role,kind,size)], argv:[token...], rc_ok:[int...]} for a compute benign case.

    argv tokens: plain str = literal; {"fix": role} = absolute staged-fixture path; {"out": name} = relative CWD output.
    """
    mb, k, rows = MB[activity_bin], FILES[activity_bin], ROWS[activity_bin]
    f = lambda role: {"fix": role}
    o = lambda name: {"out": name}
    if program in HASHERS:
        return {"fixtures": [("in", "stream", mb)], "argv": [f("in")], "rc_ok": [0]}
    if program in ENCODERS:
        argv = (["--base64", f("in")] if program == "basenc" else [f("in")])
        return {"fixtures": [("in", "stream", mb)], "argv": argv, "rc_ok": [0]}
    if program in STDOUT_COMPRESSORS:
        argv = (["-c", "-T1", f("in")] if program == "xz" else ["-c", f("in")])
        return {"fixtures": [("in", "stream", mb)], "argv": argv, "rc_ok": [0]}
    if program == "zstd":
        return {"fixtures": [("in", "stream", mb)], "argv": ["-q", f("in"), "-o", o("o.zst")], "rc_ok": [0]}
    if program == "lz4":
        return {"fixtures": [("in", "stream", mb)], "argv": ["-qf", f("in"), o("o.lz4")], "rc_ok": [0]}
    if program == "xzdec":
        return {"fixtures": [("in", "xz", mb)], "argv": [f("in")], "rc_ok": [0]}
    if program in ("sort", "uniq"):
        return {"fixtures": [("in", "stream", mb)], "argv": [f("in")], "rc_ok": [0]}
    if program in ("wc", "od"):
        return {"fixtures": [("in", "stream", mb)], "argv": [f("in")], "rc_ok": [0]}
    if program == "jq":
        return {"fixtures": [("in", "json", mb)], "argv": ["-c", ".", f("in")], "rc_ok": [0]}
    if program == "m4":
        return {"fixtures": [("in", "m4", mb)], "argv": [f("in")], "rc_ok": [0]}
    if program == "xmlwf":
        return {"fixtures": [("in", "xml", mb)], "argv": [f("in")], "rc_ok": [0]}
    if program in ("cmp", "diff"):  # two byte-identical files -> reads both fully, rc 0
        return {"fixtures": [("a", "stream", mb), ("b", "stream_copy", mb)], "argv": [f("a"), f("b")], "rc_ok": [0]}
    if program == "tar":
        return {"fixtures": [("tree", "tree", k)], "argv": ["-cf", o("o.tar"), "-C", f("tree"), "."], "rc_ok": [0]}
    if program == "zip":
        return {"fixtures": [("tree", "tree", k)], "argv": ["-rq", o("o.zip"), f("tree")], "rc_ok": [0]}
    if program == "unzip":
        return {"fixtures": [("z", "treezip", k)], "argv": ["-oq", f("z"), "-d", o("unz")], "rc_ok": [0]}
    if program == "cpio":  # extract a prebuilt archive via -F into the writable CWD; no stdin file-list, no pre-made -D dir
        return {"fixtures": [("a", "treecpio", k)], "argv": ["-i", "-F", f("a"),
                "--no-absolute-filenames", "--quiet"], "rc_ok": [0]}
    if program == "rsync":
        return {"fixtures": [("tree", "tree", k)], "argv": ["-a", {"fix": "tree", "slash": True}, o("copy")], "rc_ok": [0]}
    if program == "git":  # read-only status over a prebuilt repo; stats every file, no stdin
        return {"fixtures": [("repo", "gitrepo", k)], "argv": ["-C", f("repo"), "status", "--porcelain"], "rc_ok": [0]}
    if program == "sqlite3":  # run the script via .read; db in CWD; no stdin
        return {"fixtures": [("s", "sql", rows)], "argv": [o("t.db"), {"read": "s"}], "rc_ok": [0]}
    raise KeyError("no benign workload spec for program: " + program)


def resolve_argv(spec, fixture_paths, out_root):
    """Resolve argv tokens to concrete strings. fixture_paths maps role->absolute path; out_root prefixes outputs."""
    out = []
    for token in spec["argv"]:
        if isinstance(token, str):
            out.append(token)
        elif "fix" in token:
            path = str(fixture_paths[token["fix"]])
            out.append(path + "/" if token.get("slash") else path)
        elif "out" in token:
            out.append(str(Path(out_root) / token["out"]) if out_root != "." else token["out"])
        elif "read" in token:
            out.append(".read " + str(fixture_paths[token["read"]]))
        else:
            raise ValueError("bad argv token: " + repr(token))
    return out


if __name__ == "__main__":  # quick self-check: every program's fixtures build and argv resolves
    import tempfile
    from collections import OrderedDict
    programs = sorted(HASHERS | ENCODERS | STDOUT_COMPRESSORS | {
        "zstd", "lz4", "xzdec", "sort", "uniq", "wc", "od", "jq", "m4", "xmlwf", "cmp", "diff",
        "tar", "zip", "unzip", "cpio", "rsync", "git", "sqlite3"})
    with tempfile.TemporaryDirectory() as d:
        cache = {}
        for prog in programs:
            spec = workload(prog, "light")
            paths = OrderedDict((role, materialize(kind, size, Path(d) / "fix", cache))
                                for role, kind, size in spec["fixtures"])
            argv = resolve_argv(spec, paths, ".")
            assert all(isinstance(a, str) for a in argv), (prog, argv)
        print("PASS benign_workloads: %d programs, fixtures build + argv resolve" % len(programs))
