#!/usr/bin/env python3
"""Which Linux malware families circulate now? The most recent ELF files on MalwareBazaar, by signature.

Read-only and host-side: one MalwareBazaar query (get_file_type elf, the newest 1000 entries); no sample is
downloaded. The abuse.ch key is read from /home/ali/Desktop/Hazim/.env and never printed. The listing is untrusted
data: it is saved under raw/ and only parsed as JSON.

Per signature: entries, how many we do not hold yet, first-seen range, the most common tags, and how many entries
carry an x86 hint (a tag or a file name with x86, x86_64, x86-64, amd64, x64, i386, i486, i586, i686). The hint is a
lead, not a classification: architectures are only certain from a static report or the file itself.

    /usr/bin/python3 -I enumerate_mb.py
"""
import collections
import csv
import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
SELECTION = STUDY / "data/malware/revision5-diverse/matched-selection/malware_selection.json"
FEATURES = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
X86 = re.compile(r"(^|[^a-z0-9])(x86|x86[_-]64|amd64|x64|i[3456]86)([^a-z0-9]|$)", re.I)
NON_X86 = re.compile(r"(^|[^a-z0-9])(arm|arm5|arm6|arm7|armv\d\w*|aarch64|arm64|mips|mipsel|mpsl|mips64|ppc|powerpc|"
                     r"sh4|m68k|sparc|spc|arc|riscv)([^a-z0-9]|$)", re.I)


def env():
    d = {}
    for line in open("/home/ali/Desktop/Hazim/.env"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip().strip(chr(34)).strip(chr(39))
    return d


def known_hashes():
    s = set()
    for line in KNOWN.read_text().splitlines():
        try:
            h = (json.loads(line).get("sha256") or "").lower()
        except ValueError:
            continue
        if h:
            s.add(h)
    for c in json.load(open(SELECTION))["cases"]:
        s.add(c["sha256"].lower())
    for r in csv.DictReader(open(FEATURES)):
        if r.get("sha256"):
            s.add(r["sha256"].lower())
    return s


def main():
    RAW.mkdir(exist_ok=True)
    key = env().get("ABUSE_CH_API_KEY", "")
    data = urllib.parse.urlencode({"query": "get_file_type", "file_type": "elf", "limit": 1000}).encode()
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=data,
                                 headers={"Auth-Key": key, "User-Agent": UA,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=120) as r:
        body = r.read()
    (RAW / ("mb_recent_elf_%s.json" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))).write_bytes(body)
    d = json.loads(body)
    rows = d.get("data") if isinstance(d.get("data"), list) else []
    known = known_hashes()
    sig = collections.defaultdict(lambda: {"entries": 0, "new": 0, "x86_hint": 0, "non_x86_hint": 0, "tags": collections.Counter(),
                                           "first_seen": [], "new_x86_hint_sha256": []})
    for e in rows:
        s = e.get("signature") or "(none)"
        rec = sig[s]
        rec["entries"] += 1
        h = (e.get("sha256_hash") or "").lower()
        new = h not in known
        rec["new"] += int(new)
        tags = [t for t in (e.get("tags") or []) if t]
        rec["tags"].update(t.lower() for t in tags)
        text = " ".join(tags + [e.get("file_name") or ""])
        x86 = bool(X86.search(text))
        rec["x86_hint"] += int(x86)
        rec["non_x86_hint"] += int(bool(NON_X86.search(text)) and not x86)
        if e.get("first_seen"):
            rec["first_seen"].append(e["first_seen"])
        if new and x86 and len(rec["new_x86_hint_sha256"]) < 40:
            rec["new_x86_hint_sha256"].append(h)
    out = {"query_status": d.get("query_status"), "entries": len(rows), "signatures": {}}
    for s, rec in sorted(sig.items(), key=lambda kv: -kv[1]["entries"]):
        fs = sorted(rec["first_seen"])
        out["signatures"][s] = {"entries": rec["entries"], "new": rec["new"], "x86_hint": rec["x86_hint"],
                                "non_x86_hint": rec["non_x86_hint"], "first_seen": [fs[0], fs[-1]] if fs else None,
                                "top_tags": [t for t, _ in rec["tags"].most_common(8)],
                                "new_x86_hint_sha256": rec["new_x86_hint_sha256"]}
    (HERE / "mb_recent_elf.json").write_text(json.dumps(out, indent=1))
    print("MalwareBazaar newest ELF entries: %d (%s)" % (len(rows), d.get("query_status")))
    print("%-22s %7s %5s %8s %10s  %s" % ("signature", "entries", "new", "x86 hint", "non-x86", "first seen range"))
    for s, v in out["signatures"].items():
        print("%-22s %7d %5d %8d %10d  %s" % (s[:22], v["entries"], v["new"], v["x86_hint"], v["non_x86_hint"],
                                             " to ".join(x[:10] for x in v["first_seen"]) if v["first_seen"] else ""))


if __name__ == "__main__":
    main()
