"""Download the official Go releases (linux-amd64) used for the benign Go builds and verify each archive against the
SHA-256 published in the go.dev release index (https://go.dev/dl/?mode=json&include=all, fetched over HTTPS).
Nothing downloaded is executed before its hash matches. Run with /usr/bin/python3 -I.

    /usr/bin/python3 -I scripts/fetch_go.py <benign-build dir>
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

WANT = [(1, 13), (1, 16), (1, 18), (1, 20), (1, 21), (1, 22), (1, 24)]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    bb = Path(sys.argv[1]).resolve()
    index = bb / "downloads/go-index/go-dl-all.json"
    rel = json.loads(index.read_text())
    best = {}
    for r in rel:
        m = re.match(r"go(\d+)\.(\d+)(?:\.(\d+))?$", r["version"])
        if not m or (int(m.group(1)), int(m.group(2))) not in WANT:
            continue
        key = (int(m.group(1)), int(m.group(2)))
        patch = int(m.group(3) or 0)
        for f in r["files"]:
            if f["os"] == "linux" and f["arch"] == "amd64" and f["kind"] == "archive":
                if key not in best or patch > best[key][0]:
                    best[key] = (patch, r["version"], f)
    out = bb / "downloads/go"
    out.mkdir(parents=True, exist_ok=True)
    record = []
    for key in WANT:
        _, version, f = best[key]
        dst = out / f["filename"]
        url = "https://go.dev/dl/" + f["filename"]
        if not dst.exists() or sha256(dst) != f["sha256"]:
            subprocess.run(["curl", "-sSfL", "--retry", "3", "-o", str(dst), url], check=True)
        got = sha256(dst)
        ok = got == f["sha256"] and dst.stat().st_size == f["size"]
        record.append({"version": version, "url": url, "file": str(dst.relative_to(bb)), "size": dst.stat().st_size,
                       "sha256": got, "published_sha256": f["sha256"], "published_size": f["size"],
                       "verified": ok, "verification": "sha256 and size equal to the go.dev release index"})
        print(version, "OK" if ok else "MISMATCH", got)
        if not ok:
            dst.rename(dst.with_suffix(dst.suffix + ".BAD"))
    (out / "verification.json").write_text(json.dumps({
        "index_url": "https://go.dev/dl/?mode=json&include=all",
        "index_file": str(index.relative_to(bb)), "index_sha256": sha256(index), "archives": record}, indent=1))
    if not all(r["verified"] for r in record):
        sys.exit(1)


if __name__ == "__main__":
    main()
