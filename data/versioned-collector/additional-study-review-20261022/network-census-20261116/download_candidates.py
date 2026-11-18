#!/usr/bin/env python3
"""Download the census's network-active x86 candidates of the 14 new families into quarantine (user approval
"yes please", 2026-11-16). Host-side only: nothing is executed, extracted or opened except to read the ELF header.

For every candidate of census.json / census2.json with network activity on Triage and a family in NEW: the sample
is fetched from Triage, its SHA-256 must equal the census's, and its ELF header is classified with the dataset's
strict rule (x86-64 or i386; static, or dynamic with an interpreter; a PT_DYNAMIC without an interpreter, i.e.
static-PIE, is not supported). Accepted files are written as <sha256>.elf with mode 0600 into a 0700 quarantine
folder and appended to known_metadata.jsonl; unsupported ones are only listed. The key is read from
/home/ali/Desktop/Hazim/.env and never printed; one request per second.

    /usr/bin/python3 -I download_candidates.py
"""
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
QUAR = STUDY / "data/malware/revision5-diverse/network-census-20261116"
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
API = "https://tria.ge/api/v0/"
NEW = {"flylegitbot", "rekoobe", "sliver", "mettle", "gobrat", "zergeca", "moobot", "perfctl", "vshell", "fritzfrog",
       "xmrig_linux", "echobot", "adaptixc2", "ladvix"}
CAP = 10


def key():
    for line in open("/home/ali/Desktop/Hazim/.env"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            if k.strip() == "TRIAGE_API_KEY":
                return v.strip().strip(chr(34)).strip(chr(39))
    raise SystemExit("TRIAGE_API_KEY missing")


def elf_mode(raw):
    """(mode, reason): mode is amd64_static, amd64_dynamic, i386_static, i386_dynamic, or None."""
    if raw[:4] != b"\x7fELF":
        return None, "not ELF"
    cls, data = raw[4], raw[5]
    if data != 1:
        return None, "not little-endian"
    try:
        e_type, e_machine = struct.unpack_from("<HH", raw, 16)
        if cls == 2:
            phoff = struct.unpack_from("<Q", raw, 32)[0]
            phentsize, phnum = struct.unpack_from("<HH", raw, 54)
        elif cls == 1:
            phoff = struct.unpack_from("<I", raw, 28)[0]
            phentsize, phnum = struct.unpack_from("<HH", raw, 42)
        else:
            return None, "bad class"
    except struct.error:
        return None, "truncated header"
    arch = "amd64" if (cls == 2 and e_machine == 62) else "i386" if (cls == 1 and e_machine == 3) else None
    if not arch:
        return None, "machine %d class %d" % (e_machine, cls)
    interp = dynamic = False
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + 4 > len(raw):
            return None, "program headers beyond file"
        p_type = struct.unpack_from("<I", raw, off)[0]
        interp |= p_type == 3
        dynamic |= p_type == 2
    if interp:
        return arch + "_dynamic", "e_type %d" % e_type
    if dynamic:
        return None, "PT_DYNAMIC without interpreter (static-PIE)"
    return arch + "_static", "e_type %d" % e_type


def fetch(sid, k):
    time.sleep(1.0)
    req = urllib.request.Request(API + "samples/%s/sample" % sid, headers={"Authorization": "Bearer " + k, "User-Agent": UA})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(10 * (attempt + 1))
                continue
            return e.code, b""
        except Exception:      # noqa: BLE001
            if attempt < 2:
                time.sleep(10)
                continue
            return 0, b""
    return 0, b""


def main():
    k = key()
    cands = []
    for name in ("census.json", "census2.json"):
        cands += [c for c in json.load(open(HERE / name))["candidates"] if c["network_active"] and c["family"] in NEW]
    QUAR.mkdir(parents=True, exist_ok=True)
    os.chmod(QUAR, 0o700)
    manifest_path = QUAR / "manifest.json"
    manifest = json.load(open(manifest_path)) if manifest_path.exists() else {"accepted": [], "rejected": []}
    done = {r["sha256"] for r in manifest["accepted"] + manifest["rejected"]}
    per_family = {}
    for r in manifest["accepted"]:
        per_family[r["family"]] = per_family.get(r["family"], 0) + 1
    for c in cands:
        h = c["sha256"]
        if h in done or per_family.get(c["family"], 0) >= CAP:
            continue
        st, raw = fetch(c["triage_id"], k)
        rec = {"sha256": h, "family": c["family"], "category": c["category"], "triage_id": c["triage_id"],
               "triage_class": c["class"], "triage_flows": c["flows"], "triage_ports": c["top_ports"],
               "triage_scanner": c["scanner"], "download_status": st, "size": len(raw)}
        if st != 200 or not raw:
            rec["reason"] = "download failed"
            manifest["rejected"].append(rec)
        elif hashlib.sha256(raw).hexdigest() != h:
            rec["reason"] = "SHA-256 differs (%s)" % hashlib.sha256(raw).hexdigest()[:16]
            manifest["rejected"].append(rec)
        else:
            mode, why = elf_mode(raw)
            rec["mode"], rec["elf"] = mode, why
            if not mode:
                rec["reason"] = why
                manifest["rejected"].append(rec)
            else:
                path = QUAR / (h + ".elf")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(raw)
                rec["path"] = str(path.relative_to(STUDY))
                manifest["accepted"].append(rec)
                per_family[c["family"]] = per_family.get(c["family"], 0) + 1
                with open(KNOWN, "a") as kf:
                    kf.write(json.dumps({"sha256": h, "signature": c["family"], "source": "triage_census_20261116"}) + "\n")
        manifest_path.write_text(json.dumps(manifest, indent=1))
        print("%-12s %s %-10s %s" % (c["family"], h[:12], rec.get("mode") or "-", rec.get("reason", "")), flush=True)
    acc = manifest["accepted"]
    print("\naccepted %d, rejected %d" % (len(acc), len(manifest["rejected"])))
    fam = {}
    for r in acc:
        fam.setdefault(r["family"], {}).setdefault(r["mode"], 0)
        fam[r["family"]][r["mode"]] += 1
    for f, v in sorted(fam.items()):
        print("  %-12s %s" % (f, v))


if __name__ == "__main__":
    sys.exit(main())
