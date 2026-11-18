"""Download the uClibc 0.9.30.1 / GCC 4.1.2 cross-compilers (cross-compiler-x86_64, cross-compiler-i686) that
uclibc.org published in 2009 under downloads/binaries/0.9.30.1/.

uclibc.org now answers 403 for these two files and never published checksums, so they are taken from the Internet
Archive's Wayback Machine. Verification: every successful (HTTP 200) capture of the official URL that the Wayback
CDX index lists (2010 ... 2024) carries the same SHA-1 content digest; the copy downloaded here must reproduce that
digest, and an early (2010) and a late (2024) capture are downloaded separately and must be byte-identical.
Nothing is executed before both checks pass. Run with /usr/bin/python3 -I.

    /usr/bin/python3 -I scripts/fetch_uclibc_cross.py <benign-build dir>
"""
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

FILES = ["cross-compiler-x86_64.tar.bz2", "cross-compiler-i686.tar.bz2"]
BASE = "uclibc.org/downloads/binaries/0.9.30.1/"


def digests(path):
    s1, s2 = hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            s1.update(chunk); s2.update(chunk)
    return base64.b32encode(s1.digest()).decode(), s2.hexdigest()


def curl(url, dst=None):
    cmd = ["curl", "-sSfL", "--retry", "4", "--retry-delay", "5", url]
    if dst:
        cmd[1:1] = ["-o", str(dst)]
        subprocess.run(cmd, check=True)
        return None
    return subprocess.run(cmd, check=True, capture_output=True).stdout


def main():
    bb = Path(sys.argv[1]).resolve()
    out = bb / "downloads/uclibc-0.9.30.1-cross"
    out.mkdir(parents=True, exist_ok=True)
    record = []
    for name in FILES:
        cdx = json.loads(curl("https://web.archive.org/cdx/search/cdx?url=" + BASE + name +
                              "&output=json&fl=timestamp,original,statuscode,digest"))
        caps = [dict(zip(cdx[0], row)) for row in cdx[1:] if row[2] == "200"]
        digest_set = sorted(set(c["digest"] for c in caps))
        early, late = caps[0], caps[-1]
        files = {}
        for tag, cap in (("early", early), ("late", late)):
            dst = out / (tag + "-" + name)
            if not dst.exists():
                curl("https://web.archive.org/web/%sid_/%s" % (cap["timestamp"], cap["original"]), dst)
            b32, s256 = digests(dst)
            files[tag] = {"capture": cap, "file": str(dst.relative_to(bb)), "size": dst.stat().st_size,
                          "sha1_base32": b32, "sha256": s256}
        ok = (len(digest_set) == 1 and files["early"]["sha1_base32"] == digest_set[0]
              and files["late"]["sha1_base32"] == digest_set[0] and files["early"]["sha256"] == files["late"]["sha256"])
        if ok:
            final = out / name
            if not final.exists():
                (out / ("early-" + name)).rename(final)
                (out / ("late-" + name)).unlink()
            files["final"] = str(final.relative_to(bb))
        record.append({"name": name, "official_url": "https://www.uclibc.org/downloads/binaries/0.9.30.1/" + name,
                       "official_status_2026-11-13": "403 Forbidden (no checksum ever published)",
                       "n_200_captures": len(caps), "capture_years": sorted(set(c["timestamp"][:4] for c in caps)),
                       "cdx_digests": digest_set, "downloads": files, "verified": ok,
                       "verification": "SHA-1 equals the Wayback CDX content digest of all %d HTTP-200 captures of the "
                                       "official URL; early and late capture byte-identical" % len(caps)})
        print(name, "OK" if ok else "FAIL", files["early"]["sha256"], digest_set)
    (out / "verification.json").write_text(json.dumps(record, indent=1))
    if not all(r["verified"] for r in record):
        sys.exit(1)


if __name__ == "__main__":
    main()
