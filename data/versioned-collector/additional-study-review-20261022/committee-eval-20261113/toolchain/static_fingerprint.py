"""Static toolchain fingerprint of every executable in the dataset (offline). Malware members are read into memory
from their AES transports (7z -so) and never written to disk or executed; benign programs likewise from the frozen
payload. Only headers and printable strings are inspected.

    /usr/bin/python3 toolchain/static_fingerprint.py
"""
import collections
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import common as C  # noqa: E402

PAYLOAD = Path(__file__).resolve().parents[2] / "revision5-collection/20261025T100025568989Z/payload"


def member_bytes(zip_path, password):
    names = subprocess.run(["7z", "l", "-slt", "-p" + password, str(zip_path)], capture_output=True, text=True).stdout
    files = [l.split(" = ", 1)[1] for l in names.splitlines() if l.startswith("Path = ")][1:]
    out = subprocess.run(["7z", "x", "-so", "-p" + password, str(zip_path), files[0]], capture_output=True)
    return files[0], out.stdout


def sections(b):
    """Names -> (offset, size) of ELF sections, if a section header table is present."""
    try:
        cls = b[4]
        end = "<" if b[5] == 1 else ">"
        if cls == 2:
            shoff, = struct.unpack_from(end + "Q", b, 0x28); shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", b, 0x3A)
        else:
            shoff, = struct.unpack_from(end + "I", b, 0x20); shentsize, shnum, shstrndx = struct.unpack_from(end + "HHH", b, 0x2E)
        if not shoff or not shnum or shstrndx >= shnum:
            return {}
        def sh(i):
            o = shoff + i * shentsize
            if cls == 2:
                name, typ, flags, addr, off, size = struct.unpack_from(end + "IIQQQQ", b, o)
            else:
                name, typ, flags, addr, off, size = struct.unpack_from(end + "IIIIII", b, o)
            return name, off, size
        _, stroff, strsize = sh(shstrndx)
        res = {}
        for i in range(shnum):
            n, off, size = sh(i)
            nm = b[stroff + n: b.index(b"\0", stroff + n)].decode("latin1")
            res[nm] = (off, size)
        return res
    except Exception:
        return {}


def fingerprint(b):
    f = {"size": len(b), "elf": b[:4] == b"\x7fELF"}
    if not f["elf"]:
        return f
    f["elfclass"] = 64 if b[4] == 2 else 32
    f["interp"] = None
    m = re.search(rb"/lib[^\0]{0,40}ld-[^\0]{1,40}\.so[^\0]{0,8}", b[:4096])
    f["interp"] = m.group(0).decode("latin1") if m else None
    sec = sections(b)
    f["n_sections"] = len(sec)
    if ".comment" in sec:
        off, size = sec[".comment"]
        f["comment"] = sorted(set(x.decode("latin1") for x in b[off:off + size].split(b"\0") if x))[:6]
    else:
        f["comment"] = sorted(set(m.decode("latin1") for m in re.findall(rb"GCC: \([^)\0]{0,60}\) [0-9][0-9.]{0,12}", b)))[:6]
    f["upx"] = b"UPX!" in b
    gov = re.findall(rb"go1\.\d{1,2}(?:\.\d{1,2})?", b)
    f["go"] = bool(b"\xff Go buildinf:" in b or b"Go build ID" in b or b".gopclntab" in b or (len(gov) > 3 and b"runtime." in b))
    f["go_version"] = collections.Counter(x.decode() for x in gov).most_common(1)[0][0] if gov and f["go"] else None
    f["rust"] = b"/rustc/" in b or b"rust_panic" in b
    f["glibc_versions"] = sorted(set(x.decode() for x in re.findall(rb"GLIBC_2\.\d{1,2}(?:\.\d)?", b)))[-3:]
    f["glibc_markers"] = [k for k in ("GLIBC_TUNABLES", "FATAL: kernel too old", "glibc.malloc", "__libc_start_main",
                                     "Fatal glibc error", "libc_early_init", "/etc/ld.so.cache")
                          if k.encode() in b]
    f["musl_markers"] = [k for k in ("No error information", "ld-musl", "musl") if k.encode() in b]
    f["uclibc_markers"] = [k for k in ("uClibc", "ld-uClibc", "__uClibc_main") if k.encode() in b]
    f["diet_markers"] = [k for k in ("dietlibc", "diet libc") if k.encode() in b]
    return f


def classify(f):
    if not f.get("elf"):
        return "not-elf"
    if f["upx"]:
        return "upx"
    if f["go"]:
        return "go"
    if f["rust"]:
        return "rust"
    if f["interp"]:
        return "dynamic:" + ("musl" if "musl" in f["interp"] else "uclibc" if "uClibc" in f["interp"] else "glibc")
    if f["uclibc_markers"]:
        return "uclibc"
    if f["musl_markers"]:
        return "musl"
    if f["diet_markers"]:
        return "dietlibc"
    if f["glibc_markers"]:
        return "glibc-static"
    return "unknown-static"


def main():
    rows, _, _ = C.load()
    seqs = {o["row"]: o["first40"] for o in json.loads((HERE / "startup_sequences.json").read_text())}
    dirs = C.run_dirs(rows)
    out = []
    for i, r in enumerate(rows):
        if r["category"] not in ("malware", "benign"):
            continue
        z = PAYLOAD / "samples" / dirs[i].name
        pw = "infected" if r["category"] == "malware" else ""
        if z is None or not z.exists():
            out.append({"row": i, "category": r["category"], "family": r["family"], "project": r["project"],
                        "mode": r["mode"], "error": "transport not found"})
            continue
        name, b = member_bytes(z, pw)
        f = fingerprint(b)
        out.append({"row": i, "category": r["category"], "family": r["family"], "project": r["project"],
                    "program": r["program"], "mode": r["mode"], "member": name, "class": classify(f),
                    "startup8": " ".join(seqs.get(i, [])[:8]), **f})
    (HERE / "static_fingerprint.json").write_text(json.dumps(out, indent=1))
    t = collections.Counter((o["category"], o["mode"], o.get("class")) for o in out)
    for k in sorted(t):
        print(k, t[k])
    print("errors", sum(1 for o in out if "error" in o))


if __name__ == "__main__":
    main()
