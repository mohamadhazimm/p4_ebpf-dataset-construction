#!/usr/bin/env python3
"""Fetch Triage's behavioral reports (network section included) for the 99 malware of the paper's dataset.

Read-only: only hashes we hold are queried, only JSON reports are downloaded (no sample, no pcap). Keys are read
from /home/ali/Desktop/Hazim/.env and never printed. Triage needs a browser User-Agent past Cloudflare. Reports are
untrusted data: they go into their own directory (triage-reports-20261115/<sha256>/), are only parsed as JSON,
and are never executed or imported. One request per second.

    python3 -I triage_network_fetch.py
"""
import csv
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "triage-reports-20261115"
FEATURES = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
INTEL = HERE / "intel99-paper-dataset-20261113.json"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
API = "https://tria.ge/api/v0/"

ENV = {}
for line in open("/home/ali/Desktop/Hazim/.env"):
    line = line.strip()
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        ENV[k.strip()] = v.strip().strip(chr(34)).strip(chr(39))
HDR = {"Authorization": "Bearer " + ENV["TRIAGE_API_KEY"], "User-Agent": UA}


def get(path):
    time.sleep(1.0)
    req = urllib.request.Request(API + path, headers=HDR)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(10 * (attempt + 1))
                continue
            return e.code, e.read()
        except Exception as e:  # noqa: BLE001
            if attempt < 2:
                time.sleep(10)
                continue
            return 0, str(e).encode()
    return 0, b"retries exhausted"


def main():
    rows = [r for r in csv.DictReader(open(FEATURES)) if r["category"] == "malware"]
    assert len(rows) == 99
    intel = json.load(open(INTEL))
    RAW.mkdir(exist_ok=True)
    log = []
    for n, r in enumerate(rows, 1):
        sha = r["sha256"]
        d = RAW / sha
        if (d / "done.json").exists():
            continue
        d.mkdir(exist_ok=True)
        t = intel.get(sha, {}).get("triage", {})
        ids = [t["id"]] if t.get("id") else []
        st, body = get("search?query=" + sha)          # every analysis of this hash, newest first
        if st == 200:
            for s in json.loads(body).get("data", []):
                if s.get("id") and s["id"] not in ids:
                    ids.append(s["id"])
        entry = {"sha256": sha, "family": r["family"], "search_status": st, "samples": []}
        for sid in ids[:3]:
            st, body = get("samples/%s/overview.json" % sid)
            rec = {"id": sid, "overview_status": st, "tasks": []}
            if st == 200:
                (d / ("%s_overview.json" % sid)).write_bytes(body)
                ov = json.loads(body)
                for tid, task in (ov.get("tasks") or {}).items():
                    if task.get("kind") != "behavioral" or task.get("status") != "reported":
                        continue
                    short = tid[len(sid) + 1:] if tid.startswith(sid + "-") else tid
                    st2, body2 = get("samples/%s/%s/report_triage.json" % (sid, short))
                    rec["tasks"].append({"task": short, "os": task.get("os"), "status": st2})
                    if st2 == 200:
                        (d / ("%s_%s.json" % (sid, short))).write_bytes(body2)
            entry["samples"].append(rec)
        (d / "done.json").write_text(json.dumps(entry, indent=1))
        log.append(entry)
        print("%2d/99 %s %-10s samples %d, reports %d" % (n, sha[:12], r["family"], len(entry["samples"]),
              sum(1 for s in entry["samples"] for t in s["tasks"] if t["status"] == 200)), flush=True)
    print("done", file=sys.stderr)


if __name__ == "__main__":
    main()
