#!/usr/bin/env python3
"""Run as root inside the guest (by guest_prep.sh) before the guest gets real internet:
    guest_scrub.py <known hashes file> <report.json> [--roots DIR ...] [--user-roots DIR ...] [--downloads DIR]

Deletes, and records:
  downloads     everything inside the guest user's Downloads folder (the lab staged its sample sets and inputs
                there; the folder itself is kept, empty);
  known_hash    any regular file under the roots whose SHA-256 is in the known-hashes file (every sample and
                sample archive hash the host side knows);
  sample_name   any regular file under the roots named like a sample (64 hex digits, optional extension);
  user_binary   any ELF file or archive (zip, 7z, gzip, xz, bzip2, rar) under the user roots.
Then scans again with the same rules; the report says what is left (should be nothing). Nothing outside the roots
is touched; /opt/VBoxGuestAdditions* is never touched.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time

ROOTS = ["/home", "/root", "/tmp", "/var/tmp", "/opt", "/srv", "/mnt", "/media", "/usr/local", "/var/lib/work"]
USER_ROOTS = ["/home", "/root", "/tmp", "/var/tmp", "/srv", "/mnt", "/media"]
DOWNLOADS = "/home/csci/Downloads"
SKIP_PREFIXES = ("/opt/VBoxGuestAdditions",)
NAME = re.compile(r"^[0-9a-f]{64}(\.[A-Za-z0-9]+)?$")
ELF = b"\x7fELF"
ARCHIVES = (b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b", b"\xfd7zXZ\x00", b"BZh", b"Rar!")
MAX_HASH = 1 << 30


def under(path, prefixes):
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)


def file_facts(path):
    with open(path, "rb") as stream:
        head = stream.read(8)
        size = os.fstat(stream.fileno()).st_size
        digest = None
        if size <= MAX_HASH:
            h = hashlib.sha256(head)
            for block in iter(lambda: stream.read(1 << 20), b""):
                h.update(block)
            digest = h.hexdigest()
    return head, size, digest


def reasons(path, head, digest, known, user_roots):
    out = []
    if digest and digest in known:
        out.append("known_hash")
    if NAME.match(os.path.basename(path)):
        out.append("sample_name")
    if under(path, user_roots) and (head.startswith(ELF) or any(head.startswith(m) for m in ARCHIVES)):
        out.append("user_binary")
    return out


def scan(roots, user_roots, known, delete, log):
    found, errors, scanned = [], [], 0
    for root in roots:
        if not os.path.isdir(root) or os.path.islink(root) or under(root, SKIP_PREFIXES):
            continue
        for top, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not under(os.path.join(top, d), SKIP_PREFIXES)
                       and not os.path.islink(os.path.join(top, d))]
            for name in files:
                path = os.path.join(top, name)
                try:
                    st = os.lstat(path)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    head, size, digest = file_facts(path)
                except OSError as error:
                    errors.append({"path": path, "error": str(error)})
                    continue
                scanned += 1
                why = reasons(path, head, digest, known, user_roots)
                if not why:
                    continue
                entry = {"path": path, "reasons": why, "bytes": size, "sha256": digest,
                         "elf": head.startswith(ELF)}
                if delete:
                    try:
                        os.unlink(path)
                        entry["deleted"] = True
                    except OSError as error:
                        entry["deleted"] = False
                        entry["error"] = str(error)
                found.append(entry)
                log.write("%s %s %s\n" % ("deleted" if delete else "left", ",".join(why), path))
    return found, errors, scanned


def clear_downloads(folder, log):
    entries = []
    if not os.path.isdir(folder):
        return entries
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        files, size = 0, 0
        if os.path.isdir(path) and not os.path.islink(path):
            for top, _, names in os.walk(path, followlinks=False):
                for n in names:
                    p = os.path.join(top, n)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    files += 1
                    size += st.st_size if stat.S_ISREG(st.st_mode) else 0
            shutil.rmtree(path)
        else:
            try:
                st = os.lstat(path)
                files, size = 1, (st.st_size if stat.S_ISREG(st.st_mode) else 0)
            except OSError:
                pass
            os.unlink(path)
        entries.append({"name": name, "files": files, "bytes": size})
        log.write("deleted downloads %s (%d files, %d bytes)\n" % (name, files, size))
    return entries


def main():
    p = argparse.ArgumentParser()
    p.add_argument("known")
    p.add_argument("report")
    p.add_argument("--roots", nargs="+", default=ROOTS)
    p.add_argument("--user-roots", nargs="+", default=USER_ROOTS)
    p.add_argument("--downloads", default=DOWNLOADS)
    a = p.parse_args()
    known = set(open(a.known).read().split())
    started = time.time()
    with open(a.report + ".log", "w") as log:
        downloads = clear_downloads(a.downloads, log)
        deleted, errors, scanned = scan(a.roots, a.user_roots, known, True, log)
        left, errors2, scanned2 = scan(a.roots, a.user_roots, known, False, log)
    report = {"known_hashes": len(known), "roots": a.roots, "user_roots": a.user_roots, "downloads_folder": a.downloads,
              "downloads_deleted": downloads, "deleted": deleted, "scan_errors": errors,
              "files_scanned_first_pass": scanned, "left_after": left, "scan_errors_after": errors2,
              "files_scanned_after": scanned2, "seconds": round(time.time() - started, 1),
              "counts": {"downloads_entries": len(downloads),
                         "downloads_files": sum(e["files"] for e in downloads),
                         "deleted_files": sum(1 for e in deleted if e.get("deleted")),
                         "delete_failed": sum(1 for e in deleted if not e.get("deleted")),
                         "known_hash_deleted": sum(1 for e in deleted if "known_hash" in e["reasons"]),
                         "left_after": len(left)}}
    with open(a.report, "w") as stream:
        json.dump(report, stream, indent=1, sort_keys=True)
    print(json.dumps(report["counts"]))
    return 0 if not left and not report["counts"]["delete_failed"] else 3


if __name__ == "__main__":
    sys.exit(main())
