#!/usr/bin/env python3
"""Download benign Debian bookworm busybox builds through a verified signature chain.

Chain: host ubuntu-archive-keyring -> Ubuntu resolute InRelease -> universe Packages
-> debian-archive-keyring .deb -> Debian bookworm InRelease -> main Packages -> .deb.
Nothing downloaded here is executed on the host.
"""
import hashlib
import json
import lzma
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "artifacts"
UBUNTU = "http://archive.ubuntu.com/ubuntu"
DEBIAN = "https://deb.debian.org/debian"
HOST_KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
WANTED = [
    ("busybox", "amd64"), ("busybox-static", "amd64"), ("busybox-static", "i386"),
    ("busybox-static", "armel"), ("busybox", "armel"), ("busybox-static", "mipsel"),
    ("busybox-static", "arm64"),
]


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verified_release(url, keyring, workdir):
    signed = workdir / "InRelease"
    signed.write_bytes(fetch(url))
    plain = workdir / "Release"
    subprocess.run(["gpgv", "--keyring", str(keyring), "--output", str(plain), str(signed)],
                   check=True, capture_output=True)
    hashes, in_sha = {}, False
    for line in plain.read_text().splitlines():
        if line.startswith("SHA256:"):
            in_sha = True
            continue
        if in_sha and line.startswith(" "):
            digest, size, name = line.split()
            hashes[name] = (digest, int(size))
        elif in_sha:
            in_sha = False
    return sha256(signed.read_bytes()), hashes


def packages(base, suite, component, arch, hashes):
    name = f"{component}/binary-{arch}/Packages.xz"
    data = fetch(f"{base}/dists/{suite}/{name}")
    if sha256(data) != hashes[name][0]:
        raise SystemExit(f"Packages hash mismatch: {name}")
    stanzas = {}
    for block in lzma.decompress(data).decode().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(" "))
        if "Package" in fields:
            stanzas.setdefault(fields["Package"], fields)
    return stanzas


def download_deb(base, stanza):
    data = fetch(f"{base}/{stanza['Filename']}")
    if sha256(data) != stanza["SHA256"] or len(data) != int(stanza["Size"]):
        raise SystemExit(f"deb hash mismatch: {stanza['Filename']}")
    return data


def main():
    OUT.mkdir(exist_ok=True)
    record = {"ubuntu_suite": "resolute", "debian_suite": "bookworm", "artifacts": []}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "u").mkdir()
        record["ubuntu_inrelease_sha256"], u_hashes = verified_release(
            f"{UBUNTU}/dists/resolute/InRelease", HOST_KEYRING, tmp / "u")
        keyring_stanza = packages(UBUNTU, "resolute", "universe", "amd64", u_hashes)["debian-archive-keyring"]
        keyring_deb = tmp / "keyring.deb"
        keyring_deb.write_bytes(download_deb(UBUNTU, keyring_stanza))
        subprocess.run(["dpkg-deb", "-x", str(keyring_deb), str(tmp / "kr")], check=True)
        debian_keyring = tmp / "kr/usr/share/keyrings/debian-archive-keyring.gpg"
        record["debian_archive_keyring"] = {"version": keyring_stanza["Version"],
                                            "deb_sha256": keyring_stanza["SHA256"],
                                            "keyring_sha256": sha256(debian_keyring.read_bytes())}
        (tmp / "d").mkdir()
        record["debian_inrelease_sha256"], d_hashes = verified_release(
            f"{DEBIAN}/dists/bookworm/InRelease", debian_keyring, tmp / "d")
        for package, arch in WANTED:
            stanza = packages(DEBIAN, "bookworm", "main", arch, d_hashes)[package]
            deb = tmp / f"{package}_{arch}.deb"
            deb.write_bytes(download_deb(DEBIAN, stanza))
            extract = tmp / f"x_{package}_{arch}"
            subprocess.run(["dpkg-deb", "-x", str(deb), str(extract)], check=True)
            binary = next(p for p in (extract / "bin/busybox", extract / "usr/bin/busybox") if p.is_file())
            linkage = "static" if package == "busybox-static" else "dynamic"
            target = OUT / f"busybox-{arch}-{linkage}"
            target.write_bytes(binary.read_bytes())
            record["artifacts"].append({
                "file": target.name, "package": package, "arch": arch, "version": stanza["Version"],
                "deb_filename": stanza["Filename"], "deb_sha256": stanza["SHA256"],
                "binary_sha256": sha256(target.read_bytes()), "binary_bytes": target.stat().st_size,
                "file_description": subprocess.run(["file", "-b", str(target)], capture_output=True,
                                                   text=True, check=True).stdout.strip(),
            })
    (ROOT / "artifact_provenance.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    sys.exit(main())
