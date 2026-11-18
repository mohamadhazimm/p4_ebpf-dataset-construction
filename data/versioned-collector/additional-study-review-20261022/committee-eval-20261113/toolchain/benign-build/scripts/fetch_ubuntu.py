"""Download Ubuntu binary packages through the signed archive chain and extract them into a private sysroot.

Chain: dists/<suite>/InRelease (or Release + Release.gpg) verified with gpgv against the Ubuntu archive keyrings
shipped on the host (/usr/share/keyrings/ubuntu-archive-keyring.gpg and ubuntu-archive-removed-keys.gpg, which
holds the 2004 key that signed the old releases) -> SHA256 of the binary Packages index -> SHA256 and size of every
.deb. Packages are only unpacked with `dpkg-deb -x` (no maintainer scripts, nothing installed on the host).
Run with /usr/bin/python3 -I.

    /usr/bin/python3 -I scripts/fetch_ubuntu.py <benign-build dir> <tag> <mirror> <suite> <arch> <pkg> [<pkg> ...]
    mirror: archive | old-releases
"""
import bz2
import gzip
import hashlib
import json
import lzma
import subprocess
import sys
from pathlib import Path

import os
MIRRORS = {"archive": "https://archive.ubuntu.com/ubuntu/", "old-releases": "http://old-releases.ubuntu.com/ubuntu/",
           "debian": "https://deb.debian.org/debian/"}
KEYRINGS = ["/usr/share/keyrings/ubuntu-archive-keyring.gpg", "/usr/share/keyrings/ubuntu-archive-removed-keys.gpg"]
if os.environ.get("EXTRA_KEYRING"):  # e.g. Debian's keyring, itself taken from the Ubuntu-signed debian-archive-keyring
    KEYRINGS = [os.environ["EXTRA_KEYRING"]]


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def get(url):
    return subprocess.run(["curl", "-sSfL", "--retry", "4", url], check=True, capture_output=True).stdout


def gpgv(args):
    cmd = ["gpgv", "--status-fd", "1"]
    for k in KEYRINGS:
        cmd += ["--keyring", k]
    r = subprocess.run(cmd + args, capture_output=True, text=True)
    lines = r.stdout.splitlines()
    good = [l for l in lines if l.startswith("[GNUPG:] VALIDSIG")]
    bad = [l for l in lines if l.startswith("[GNUPG:] BADSIG")]
    # several archive keys sign each Release; a key absent from our keyring gives NO_PUBKEY (gpgv exit 2), which is
    # not a failure as long as at least one signature is VALID and none is BAD
    return bool(good) and not bad, r.stdout + r.stderr


def parse_release(text):
    out, section = {}, None
    for line in text.splitlines():
        if not line.startswith(" "):
            section = line.split(":")[0]
            continue
        if section == "SHA256":
            h, size, name = line.split()
            out[name] = (h, int(size))
    return out


def parse_packages(text):
    pkgs, cur = {}, {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if "Package" in cur:
                pkgs.setdefault(cur["Package"], []).append(cur)
            cur = {}
            continue
        if line[0] in " \t":
            continue
        k, _, v = line.partition(":")
        cur[k] = v.strip()
    return pkgs


def main():
    bb, tag, mirror, suite, arch, names = (Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3], sys.argv[4],
                                           sys.argv[5], sys.argv[6:])
    base = MIRRORS[mirror]
    dl = bb / "downloads" / tag
    dl.mkdir(parents=True, exist_ok=True)
    try:
        inrel = get(base + "dists/%s/InRelease" % suite)
        (dl / "InRelease").write_bytes(inrel)
        ok, log = gpgv([str(dl / "InRelease")])
        release = inrel.decode("utf-8", "replace")
        sigfile = "InRelease"
    except subprocess.CalledProcessError:
        rel = get(base + "dists/%s/Release" % suite)
        sig = get(base + "dists/%s/Release.gpg" % suite)
        (dl / "Release").write_bytes(rel); (dl / "Release.gpg").write_bytes(sig)
        ok, log = gpgv([str(dl / "Release.gpg"), str(dl / "Release")])
        release = rel.decode("utf-8", "replace")
        sigfile = "Release+Release.gpg"
    (dl / "gpgv.log").write_text(log)
    if not ok:
        sys.exit("signature check failed for %s %s" % (suite, sigfile))
    sums = parse_release(release)
    index = None
    for comp in ("main", "universe"):
        for ext, dec in ((".xz", lzma.decompress), (".gz", gzip.decompress), (".bz2", bz2.decompress)):
            name = "%s/binary-%s/Packages%s" % (comp, arch, ext)
            if name in sums:
                raw = get(base + "dists/%s/%s" % (suite, name))
                if sha256(raw) != sums[name][0] or len(raw) != sums[name][1]:
                    sys.exit("index hash mismatch " + name)
                index = (index or {})
                for k, v in parse_packages(dec(raw).decode("utf-8", "replace")).items():
                    index.setdefault(k, []).extend(v)
                (dl / name.replace("/", "_")).write_bytes(raw)
                break
    sysroot = bb / "toolchains" / tag / "sysroot"
    sysroot.mkdir(parents=True, exist_ok=True)
    rec = {"tag": tag, "mirror": base, "suite": suite, "arch": arch, "signature_file": sigfile, "gpgv_ok": ok,
           "release_sha256": sha256(release.encode()), "keyrings": KEYRINGS,
           "gpgv_status": [l for l in log.splitlines() if "SIG" in l], "packages": []}
    for name in names:
        cands = index.get(name)
        if not cands:
            sys.exit("package not found: " + name)
        p = cands[-1]
        raw = get(base + p["Filename"])
        if sha256(raw) != p["SHA256"] or len(raw) != int(p["Size"]):
            sys.exit("deb hash mismatch " + name)
        deb = dl / Path(p["Filename"]).name
        deb.write_bytes(raw)
        subprocess.run(["dpkg-deb", "-x", str(deb), str(sysroot)], check=True)
        rec["packages"].append({"package": name, "version": p["Version"], "filename": p["Filename"],
                                "sha256": p["SHA256"], "size": int(p["Size"]), "verified": True})
        print(tag, name, p["Version"], "OK")
    (dl / "verification.json").write_text(json.dumps(rec, indent=1))


if __name__ == "__main__":
    main()
