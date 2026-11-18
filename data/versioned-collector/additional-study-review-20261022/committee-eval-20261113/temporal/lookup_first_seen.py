"""Look up first-seen dates of the 99 dataset malware samples (metadata only; nothing is downloaded).

MalwareBazaar `get_info` per SHA-256, through the project's existing client (key read from .env, never printed).
Samples MalwareBazaar does not know are listed for a Triage lookup. Writes first_seen.json next to this script.

    /usr/bin/python3 lookup_first_seen.py
"""
import csv
import json
import sys
import time
from pathlib import Path

STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
sys.path.insert(0, str(STUDY / "src"))
from acquire_malwarebazaar_samples import api_auth_key, post_api  # noqa: E402

FEATURES = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
OUT = Path(__file__).resolve().parent / "first_seen.json"


def main():
    rows = [r for r in csv.DictReader(open(FEATURES)) if r["category"] == "malware"]
    key = api_auth_key()
    if not key:
        sys.exit("MalwareBazaar key not found")
    out = json.loads(OUT.read_text()) if OUT.exists() else {}
    for r in rows:
        s = r["sha256"]
        if s in out and out[s].get("query_status") == "ok":
            continue
        body = json.loads(post_api({"query": "get_info", "hash": s}, key, retries=3, max_bytes=2_000_000))
        rec = {"query_status": body.get("query_status"), "dataset_family": r["family"], "dataset_source": r["source"]}
        if body.get("query_status") == "ok":
            d = body["data"][0]
            rec.update({k: d.get(k) for k in ("first_seen", "last_seen", "signature", "file_type", "reporter")})
            assert d.get("sha256_hash") == s
        out[s] = rec
        time.sleep(0.4)
    OUT.write_text(json.dumps(out, indent=1, sort_keys=True))
    ok = sum(v["query_status"] == "ok" for v in out.values())
    print("looked up %d, found on MalwareBazaar %d, not found %d" % (len(out), ok, len(out) - ok))


if __name__ == "__main__":
    main()
