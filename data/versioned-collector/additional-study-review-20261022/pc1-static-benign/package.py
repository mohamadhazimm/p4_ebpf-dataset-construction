"""Package the dataset's own static benign programs for a live run on PC1 (p4_ebpf PC1.md Part 6).

Why: PC1's live benign programs (Ubuntu 20.04 builds and busybox) are flagged by the host and hybrid detectors in
19 of 47 executions. A test with the dataset's own binaries and tasks separates the two explanations: if the
dataset's static programs (which carry their own C library) run on PC1 and give the rows the dataset has, the
live pipeline is faithful and the gap comes from PC1's programs; if they do not, the live collection differs.

What it writes (pc1-static-benign/static-benign/, then static-benign.tar.gz):
- bin/<execution_id>/<program>: the 66 static benign programs without a network task (45 amd64, 21 i386), each
  the exact binary of the dataset run, under its original name;
- fixtures/: the 15 input files their tasks read, byte for byte;
- cases.tsv: execution_id, program, project, mode, split, expected exit codes, binary path, the task's arguments
  as JSON with @ROOT@ in place of the folder (PC1 substitutes its own);
- manifest.json: SHA-256 of every file, the dataset row of each case, the sources;
- README.md.
The execution_id of each case is its row in the release's dataset/features.csv (row i of features.csv is
entry i of paper-check-20261028/independent_pool.json). Nothing is executed here.

    /usr/bin/python3 pc1-static-benign/package.py
"""
import csv
import hashlib
import io
import json
import re
import shutil
import tarfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent
REV5 = STUDY / "revision5-collection/20261025T100025568989Z"
PAYLOAD = REV5 / "payload"
POOL = STUDY / "paper-check-20261028/independent_pool.json"
FEATURES = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
OUT = HERE / "static-benign"
TARBALL = HERE / "static-benign.tar.gz"
MODES = {"native_amd64_static": "amd64_static", "native_i386_static": "i386_static"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    (OUT / "bin").mkdir(parents=True)
    (OUT / "fixtures").mkdir()
    guest_root = json.load(open(REV5 / "protocol.json"))["guest_root"].rstrip("/")
    fix_re = re.compile(re.escape(guest_root) + r"/fixtures/rev5/([^/\s]+)")
    cases = json.load(open(PAYLOAD / "cases.json"))
    pool = json.load(open(POOL))
    rows = list(csv.DictReader(open(FEATURES, newline="")))
    assert len(pool) == len(rows) == 240
    row_of = {p["sample"]: i for i, p in enumerate(pool)}
    picked = [c for c in cases if c["label"] == "benign" and c["mode"] in MODES and not c["network"]]
    assert len(picked) == 66, len(picked)
    manifest = {"sources": {"revision5_cases.json": sha(PAYLOAD / "cases.json"), "features.csv": sha(FEATURES),
                            "independent_pool.json": sha(POOL), "package.py": sha(__file__)},
                "guest_root_replaced": guest_root, "cases": [], "files": {}}
    fixtures = set()
    lines = []
    for c in picked:
        i = row_of[c["sample"]]
        r = rows[i]
        assert r["category"] == "benign" and r["program"] == c["program"] and r["mode"] == MODES[c["mode"]], c
        eid = r["execution_id"]
        with zipfile.ZipFile(PAYLOAD / "samples" / c["sample"]) as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            assert len(members) == 1, c["sample"]
            member = members[0]
            data = z.read(member)
        assert data[:4] == b"\x7fELF", c["sample"]
        name = Path(member.filename).name
        dest = OUT / "bin" / eid / name
        dest.parent.mkdir(parents=True)
        dest.write_bytes(data)
        dest.chmod(0o755)
        args = json.load(open(PAYLOAD / "arguments" / (c["sample"] + ".json")))
        out_args = []
        for a in args:
            for n in fix_re.findall(a):
                fixtures.add(n)
            assert guest_root not in fix_re.sub("", a), "a guest path that is not a fixture: %s" % a
            out_args.append(a.replace(guest_root + "/fixtures/rev5", "@ROOT@/fixtures"))
        exp = c.get("expected_returncodes") or [0]
        rec = {"execution_id": eid, "row": i, "program": c["program"], "project": c["project"], "mode": r["mode"],
               "split": r["split"], "expected_returncodes": exp, "binary": "bin/%s/%s" % (eid, name),
               "binary_sha256": hashlib.sha256(data).hexdigest(), "args": out_args, "sample": c["sample"],
               "dataset_syscall_count": int(r["syscall_count"]), "dataset_return_code": r["return_code"]}
        manifest["cases"].append(rec)
        lines.append("\t".join([eid, c["program"], c["project"], r["mode"], r["split"],
                                ",".join(str(x) for x in exp), rec["binary"], json.dumps(out_args)]))
    for n in sorted(fixtures):
        src = PAYLOAD / "fixtures/rev5" / n
        assert src.is_file(), n
        shutil.copy2(src, OUT / "fixtures" / n)
    (OUT / "cases.tsv").write_text("execution_id\tprogram\tproject\tmode\tsplit\texpected_returncodes\tbinary\targs\n"
                                   + "\n".join(lines) + "\n")
    (OUT / "README.md").write_text(README)
    for p in sorted(OUT.rglob("*")):
        if p.is_file():
            manifest["files"][str(p.relative_to(OUT))] = sha(p)
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    with tarfile.open(TARBALL, "w:gz") as tar:
        for p in sorted(OUT.rglob("*")):
            info = tar.gettarinfo(str(p), arcname=str(Path("static-benign") / p.relative_to(OUT)))
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 1794700800  # 2026-11-15 00:00 UTC, so the tarball is reproducible
            if p.is_file():
                with open(p, "rb") as f:
                    tar.addfile(info, f)
            else:
                tar.addfile(info)
    by_mode = {}
    for c in manifest["cases"]:
        by_mode[c["mode"]] = by_mode.get(c["mode"], 0) + 1
    print(json.dumps({"cases": len(manifest["cases"]), "by_mode": by_mode, "fixtures": len(fixtures),
                      "tarball": str(TARBALL), "tarball_mb": round(TARBALL.stat().st_size / 1e6, 1),
                      "tarball_sha256": sha(TARBALL)}, indent=1))


README = """# The dataset's static benign programs, for a live run on PC1

66 static benign programs of the release dataset (rows of `dataset/features.csv` with category `benign`, mode
`amd64_static` or `i386_static`, no network task), each the exact binary of the dataset run, with the input
files their tasks read. Run and compare them with `live_test/static_benign/` in p4_ebpf (PC1.md Part 6).

- `bin/<execution_id>/<program>`: the binary, under its original name (some programs read their name).
- `fixtures/`: the input files, byte for byte as in the dataset run.
- `cases.tsv`: one line per case. `args` is the task's argument list as JSON, with `@ROOT@` standing for the
  folder this README is in.
- `manifest.json`: the SHA-256 of every file and each case's dataset row (`row`: its index in features.csv).

The programs are command-line tools (GNU coreutils, diffutils, gzip, m4, cpio, bzip2, brotli, lz4, ncompress,
xxHash, expat's xmlwf, sqlite3), built from Ubuntu 22.04 source packages for the study. They read their input
files and write their outputs to the working directory; none uses the network.
"""


if __name__ == "__main__":
    main()
