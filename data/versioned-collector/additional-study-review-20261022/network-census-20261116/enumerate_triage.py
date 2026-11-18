#!/usr/bin/env python3
"""Which Linux malware families does Triage see now, by behaviour category, and which of them run on x86?

Read-only and host-side: Triage searches "tag:linux tag:<category>" (newest first) and the overview of each new hash
(its family tags and the platforms of its behavioral runs). No sample is downloaded and nothing is executed. The key
is read from /home/ali/Desktop/Hazim/.env and never printed; one request per second. Overviews are untrusted data:
they are only parsed as JSON (saved under raw/enum/).

A hash counts as x86 when Triage ran it on an amd64 Ubuntu machine (Triage picks the machine from the file's
architecture; ARM and MIPS files run on Debian armhf/mips machines). Families are Triage's own family tags; a hash
with several family tags counts for each (Triage often stacks rule names).

    /usr/bin/python3 -I enumerate_triage.py
"""
import collections
import csv
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw" / "enum"
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
QUARANTINE = STUDY / "data/malware/revision5-diverse"
SELECTION = QUARANTINE / "matched-selection/malware_selection.json"
FEATURES = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
API = "https://tria.ge/api/v0/"
CATEGORIES = ["botnet", "backdoor", "rat", "miner", "trojan", "worm", "ddos", "proxy", "downloader", "dropper",
              "spyware", "stealer"]
PER_CATEGORY = 60          # new hashes looked at per category (newest first)


def env():
    d = {}
    for line in open("/home/ali/Desktop/Hazim/.env"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip().strip(chr(34)).strip(chr(39))
    return d


H = {"Authorization": "Bearer " + env()["TRIAGE_API_KEY"], "User-Agent": UA}


def get(path):
    time.sleep(1.0)
    req = urllib.request.Request(API + path, headers=H)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(10 * (attempt + 1))
                continue
            return e.code, None
        except Exception:      # noqa: BLE001
            if attempt < 2:
                time.sleep(10)
                continue
            return 0, None
    return 0, None


def held_hashes():
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
    for p in QUARANTINE.rglob("*"):         # quarantined files are named by their SHA-256
        stem = p.name.split(".")[0].lower()
        if len(stem) == 64 and all(ch in "0123456789abcdef" for ch in stem):
            s.add(stem)
    return s


def main():
    RAW.mkdir(parents=True, exist_ok=True)
    held = held_hashes()
    seen = {}
    fam = collections.defaultdict(lambda: {"hashes": 0, "x86": 0, "arm_mips": 0, "categories": collections.Counter(),
                                           "x86_examples": []})
    for cat in CATEGORIES:
        cursor, looked = None, 0
        while looked < PER_CATEGORY:
            q = "search?query=" + urllib.parse.quote("tag:linux tag:" + cat) + "&limit=50"
            if cursor:
                q += "&offset=" + urllib.parse.quote(cursor)
            st, res = get(q)
            if st != 200 or not res or not res.get("data"):
                break
            for row in res["data"]:
                h = (row.get("sha256") or "").lower()
                if not h or h in held or looked >= PER_CATEGORY:
                    continue
                if h in seen:
                    for f in seen[h]["families"]:
                        fam[f]["categories"][cat] += 1
                    continue
                looked += 1
                st, ov = get("samples/%s/overview.json" % row["id"])
                if st != 200 or not ov:
                    continue
                (RAW / ("%s.json" % h)).write_text(json.dumps(ov))
                fams = sorted(set((ov.get("analysis") or {}).get("family") or []))
                oses = [((t.get("os") or "") + " " + (t.get("resource") or "")) for t in (ov.get("tasks") or {}).values()
                        if t.get("kind") == "behavioral"]
                x86 = any("amd64" in o for o in oses)
                armmips = any(("armhf" in o or "mips" in o or "arm64" in o) for o in oses)
                seen[h] = {"families": fams or ["(none)"], "x86": x86, "id": row["id"], "filename": row.get("filename"),
                           "submitted": row.get("submitted"), "category": cat}
                for f in seen[h]["families"]:
                    r = fam[f]
                    r["hashes"] += 1
                    r["x86"] += int(x86)
                    r["arm_mips"] += int(armmips and not x86)
                    r["categories"][cat] += 1
                    if x86 and len(r["x86_examples"]) < 15:
                        r["x86_examples"].append({"sha256": h, "triage_id": row["id"]})
            cursor = res.get("next")
            if not cursor:
                break
        print("category %-10s looked at %3d new hashes; families so far %d" % (cat, looked, len(fam)), flush=True)
        (HERE / "triage_families.json").write_text(json.dumps(
            {"families": {f: dict(v, categories=dict(v["categories"])) for f, v in fam.items()}, "hashes": seen},
            indent=1))
    print("\n%-22s %6s %5s %8s  %s" % ("family (Triage tag)", "hashes", "x86", "ARM/MIPS", "categories"))
    for f, v in sorted(fam.items(), key=lambda kv: (-kv[1]["x86"], -kv[1]["hashes"])):
        print("%-22s %6d %5d %8d  %s" % (f[:22], v["hashes"], v["x86"], v["arm_mips"],
                                         ", ".join("%s %d" % kv for kv in v["categories"].most_common(4))))


if __name__ == "__main__":
    main()
