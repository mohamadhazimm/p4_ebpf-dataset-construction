"""Download CentOS glibc development RPMs from vault.centos.org, verify each RPM's embedded OpenPGP signature with
the CentOS release key, and unpack the payload into a private sysroot (cpio only; no rpm database, no scriptlets).

Key: https://www.centos.org/keys/RPM-GPG-KEY-CentOS-<N>; its fingerprint must equal the one printed on
https://www.centos.org/keys/ (hard-coded below as read from that page on 2026-11-13). Signature: the RPM signature
header's header+payload signature (tag 1002 RSA / 1005 DSA) and header-only signature (268 RSA / 267 DSA) are
checked with gpgv; the MD5 (tag 1004) and SHA1 (tag 269) digests are recomputed. A private GNUPGHOME inside the
download folder is used (no change to the user's keyrings). Run with /usr/bin/python3 -I.

    /usr/bin/python3 -I scripts/fetch_centos.py <benign-build dir> <tag> <release> <repo-path> <rpm> [<rpm> ...]
"""
import bz2
import gzip
import hashlib
import json
import lzma
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

FPR = {"5": "473D66D5212271FD51CC17B1A8A447DCE8562897",
       "6": "C1DAC52D1664E8A4386DBA430946FCA2C105B9DE",
       "7": "6341AB2753D78A78A7C27BB124C6A8A7F4A80EB5"}


def get(url):
    return subprocess.run(["curl", "-sSfL", "--retry", "4", url], check=True, capture_output=True).stdout


def header(buf, off):
    assert buf[off:off + 3] == b"\x8e\xad\xe8", "bad header magic"
    n, size = struct.unpack(">II", buf[off + 8:off + 16])
    idx = off + 16
    store = idx + 16 * n
    tags = {}
    for i in range(n):
        tag, typ, o, cnt = struct.unpack(">IIII", buf[idx + 16 * i: idx + 16 * i + 16])
        tags[tag] = (typ, store + o, cnt)
    return tags, store + size


def tag_value(buf, tags, tag):
    if tag not in tags:
        return None
    typ, o, cnt = tags[tag]
    if typ == 7:
        return buf[o:o + cnt]
    if typ in (6, 8, 9):
        return buf[o:buf.index(b"\0", o)].decode()
    if typ == 4:
        return struct.unpack(">I", buf[o:o + 4])[0]
    return None


def gpgv(home, sig, data):
    with tempfile.TemporaryDirectory(dir=home) as d:
        s, f = Path(d) / "s", Path(d) / "f"
        s.write_bytes(sig); f.write_bytes(data)
        r = subprocess.run(["gpgv", "--homedir", str(home), "--keyring", str(home / "centos.gpg"), "--status-fd", "1",
                            str(s), str(f)], capture_output=True, text=True)
    valid = [l.split()[2] for l in r.stdout.splitlines() if l.startswith("[GNUPG:] VALIDSIG")]
    return r.returncode == 0 and bool(valid), valid, r.stdout + r.stderr


def main():
    bb, tag, release, repo, rpms = Path(sys.argv[1]).resolve(), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
    dl = bb / "downloads" / tag
    home = dl / "gnupg"
    home.mkdir(parents=True, exist_ok=True)
    home.chmod(0o700)
    keyfile = dl / ("RPM-GPG-KEY-CentOS-" + release)
    keyfile.write_bytes(get("https://www.centos.org/keys/RPM-GPG-KEY-CentOS-" + release))
    subprocess.run(["gpg", "--homedir", str(home), "--batch", "--quiet", "--import", str(keyfile)], check=True,
                   capture_output=True)
    out = subprocess.run(["gpg", "--homedir", str(home), "--batch", "--with-colons", "--fingerprint"],
                         check=True, capture_output=True, text=True).stdout
    fprs = [l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:")]
    if FPR[release] not in fprs:
        sys.exit("CentOS-%s key fingerprint mismatch: %s" % (release, fprs))
    exp = subprocess.run(["gpg", "--homedir", str(home), "--batch", "--export", FPR[release]], check=True,
                         capture_output=True).stdout
    (home / "centos.gpg").write_bytes(exp)
    sysroot = bb / "toolchains" / tag / "sysroot"
    sysroot.mkdir(parents=True, exist_ok=True)
    rec = {"tag": tag, "release": release, "repo": "https://vault.centos.org/" + repo + "/",
           "key_url": "https://www.centos.org/keys/RPM-GPG-KEY-CentOS-" + release, "key_fingerprint": FPR[release],
           "fingerprint_source": "https://www.centos.org/keys/ (read 2026-11-13)", "rpms": []}
    for name in rpms:
        raw = get("https://vault.centos.org/" + repo + "/" + name)
        (dl / name).write_bytes(raw)
        assert raw[:4] == b"\xed\xab\xee\xdb", "not an rpm"
        stags, send = header(raw, 96)
        hstart = send + ((8 - send % 8) % 8)
        htags, hend = header(raw, hstart)
        hdr, hdr_payload = raw[hstart:hend], raw[hstart:]
        checks = {}
        md5 = tag_value(raw, stags, 1004)
        if md5 is not None:
            checks["md5_header_payload"] = hashlib.md5(hdr_payload).digest() == md5
        sha1 = tag_value(raw, stags, 269)
        if sha1 is not None:
            checks["sha1_header"] = hashlib.sha1(hdr).hexdigest() == sha1
        sigs = {}
        for t, label, data in ((1002, "rsa_header_payload", hdr_payload), (1005, "dsa_header_payload", hdr_payload),
                               (268, "rsa_header", hdr), (267, "dsa_header", hdr)):
            s = tag_value(raw, stags, t)
            if s is not None:
                ok, valid, _ = gpgv(home, s, data)
                sigs[label] = {"ok": ok, "validsig": valid}
        sig_ok = any(v["ok"] for k, v in sigs.items() if k.endswith("header_payload"))
        ok = sig_ok and all(checks.values())
        if not ok:
            sys.exit("verification failed for %s: %s %s" % (name, checks, sigs))
        comp = tag_value(raw, htags, 1125) or "gzip"
        payload = raw[hend:]
        cpio = {"gzip": gzip.decompress, "xz": lzma.decompress, "lzma": lzma.decompress,
                "bzip2": bz2.decompress}[comp](payload)
        subprocess.run(["cpio", "-idm", "--quiet", "--no-absolute-filenames", "-D", str(sysroot)], input=cpio,
                       check=True)
        rec["rpms"].append({"rpm": name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                            "name": tag_value(raw, htags, 1000), "version": tag_value(raw, htags, 1001),
                            "release": tag_value(raw, htags, 1002), "arch": tag_value(raw, htags, 1022),
                            "payload_compressor": comp, "digest_checks": checks, "signatures": sigs, "verified": ok})
        print(tag, name, "OK", sigs)
    (dl / "verification.json").write_text(json.dumps(rec, indent=1))


if __name__ == "__main__":
    main()
