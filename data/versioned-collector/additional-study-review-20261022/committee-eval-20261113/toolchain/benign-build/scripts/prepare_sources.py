"""Unpack the dataset's own authenticated benign source packages (Ubuntu jammy, distribution patches applied) into
benign-build/sources/<project>/ for the toolchain rebuilds. No source is downloaded again: every .dsc is the one the
study authenticated earlier through the signed Ubuntu Sources index; its SHA-256 must equal the earlier record, and
`dpkg-source -x` then checks the orig/debian tarballs against the .dsc checksums. Run with /usr/bin/python3 -I.

    /usr/bin/python3 -I scripts/prepare_sources.py <benign-build dir>
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

VC = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector")
RED = VC / "cohort-100x100-v18-20261021/redesign-native-x64/benign-sources"
ADD = VC / "additional-study-review-20261022/additional-benign-preparation/20261023T061710877601Z"
HOLD = VC / "cohort-100x100-v18-20261021/redesign-native-x64/benign-sources-i386-holdout/20261021T201119747468Z"
HOLD_AUTH = VC / "cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z/source-authentication.json"

PROJECTS = {
    "bzip2": ("red", "bzip2"), "gzip": ("red", "gzip"), "coreutils": ("red", "coreutils"),
    "diffutils": ("red", "diffutils"), "xz-utils": ("red", "xz-utils"), "libzstd": ("red", "libzstd"),
    "lz4": ("add", "lz4"), "xxhash": ("add", "xxhash"), "ncompress": ("add", "ncompress"),
    "brotli": ("add", "brotli"), "expat": ("add", "expat"),
    "sqlite3": ("hold", "sqlite3"), "m4": ("hold", "m4"), "cpio": ("hold", "cpio"),
}


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def expected_dsc_hash(kind, name, dsc):
    if kind == "red":
        rec = RED / name / "authentication.sha256"
        for line in rec.read_text().splitlines():
            h, path = line.split(None, 1)
            if path.endswith(dsc.name):
                return h, str(rec)
    if kind == "add":
        rec = ADD / "source-authentication.json"
        files = json.loads(rec.read_text())["files"]
        return files["sources/%s/%s" % (name, dsc.name)], str(rec)
    if kind == "hold":
        for s in json.loads(HOLD_AUTH.read_text())["authenticated_sources"]:
            if s["descriptor"].endswith(dsc.name):
                return s["descriptor_sha256"], str(HOLD_AUTH)
    raise KeyError(name)


def main():
    bb = Path(sys.argv[1]).resolve()
    out = bb / "sources"
    out.mkdir(exist_ok=True)
    record = []
    for project, (kind, name) in PROJECTS.items():
        base = {"red": RED, "add": ADD / "sources", "hold": HOLD}[kind] / name
        dscs = sorted(base.glob("*.dsc"))
        assert len(dscs) == 1, (project, dscs)
        dsc = dscs[0]
        want, recfile = expected_dsc_hash(kind, name, dsc)
        got = sha256(dsc)
        if got != want:
            sys.exit("dsc hash differs from the earlier authentication record: " + project)
        tree = out / project
        if tree.exists():
            shutil.rmtree(tree)
        r = subprocess.run(["dpkg-source", "-x", str(dsc), str(tree)], capture_output=True, text=True)
        (bb / "logs" / ("unpack-" + project + ".log")).write_text(r.stdout + r.stderr)
        if r.returncode != 0:
            sys.exit("dpkg-source failed for " + project)
        version = re.search(r"^Version: (.+)$", dsc.read_text(), re.M).group(1)
        record.append({"project": project, "dsc": str(dsc), "dsc_sha256": got, "version": version,
                       "earlier_authentication_record": recfile, "tree": str(tree.relative_to(bb)),
                       "dpkg_source_checksums": "verified by dpkg-source -x",
                       "signature_note": "dsc signature not checked here (uploader keys absent); authenticity comes "
                                         "from the signed jammy Sources index recorded earlier"})
        print(project, version, "OK")
    (out / "sources.json").write_text(json.dumps(record, indent=1))


if __name__ == "__main__":
    main()
