#!/usr/bin/env python3
"""Threat-intel lookup for our sinkhole-run samples: Triage (config extraction) + MalwareBazaar (tags/intel).
Read-only OSINT on hashes we hold. Keys read from .env, never printed. Writes a JSON summary."""
import json, sys, time, urllib.request, urllib.error, urllib.parse
from pathlib import Path

ENV = {}
for line in open("/home/ali/Desktop/Hazim/.env"):
    line = line.strip()
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1); ENV[k.strip()] = v.strip().strip(chr(34)).strip(chr(39))

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
HASHES = json.load(open(sys.argv[1]))  # {family: [sha256,...]}


def get(url, headers=None, timeout=25):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def post(url, data, headers=None, timeout=25):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def triage(h):
    hdr = {"Authorization": "Bearer " + ENV["TRIAGE_API_KEY"], "User-Agent": UA}
    st, body = get("https://tria.ge/api/v0/search?query=" + h, hdr)
    if st != 200:
        return {"status": st, "note": body[:120].decode("utf-8", "replace")}
    data = json.loads(body).get("data", [])
    if not data:
        return {"found": False}
    sid = data[0]["id"]
    st, body = get("https://tria.ge/api/v0/samples/%s/overview.json" % sid, hdr)
    if st != 200:
        return {"found": True, "id": sid, "overview_status": st}
    ov = json.loads(body)
    out = {"found": True, "id": sid}
    an = ov.get("analysis", {})
    out["score"] = an.get("score")
    out["family"] = sorted({f for f in (ov.get("analysis", {}).get("family") or [])})
    sigs = [s.get("name") for s in ov.get("signatures", []) if s.get("name")]
    out["signatures"] = sigs[:12]
    configs = []
    for ex in ov.get("extracted", []):
        c = ex.get("config") or {}
        if c:
            configs.append({"family": c.get("family"), "c2": c.get("c2"), "keys": list(c.get("keys", []))[:2]
                            if isinstance(c.get("keys"), list) else c.get("keys"),
                            "attr": {k: c[k] for k in ("botnet", "version", "type") if k in c}})
    out["configs"] = configs
    return out


def mb(h):
    hdr = {"Auth-Key": ENV.get("ABUSE_CH_API_KEY") or ENV["MALWARE_BAZAAR_API_KEY"], "User-Agent": UA}
    st, body = post("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": h}, hdr)
    try:
        d = json.loads(body)
    except ValueError:
        return {"status": st}
    if d.get("query_status") != "ok":
        return {"query_status": d.get("query_status")}
    item = (d.get("data") or [{}])[0]
    vi = item.get("vendor_intel") or {}
    return {"signature": item.get("signature"), "tags": item.get("tags"),
            "file_type": item.get("file_type_mime"), "first_seen": item.get("first_seen"),
            "delivery": item.get("delivery_method"),
            "vendors": {k: (v[0].get("detection") if isinstance(v, list) and v else
                            (v.get("verdict") if isinstance(v, dict) else None)) for k, v in list(vi.items())[:6]}}


out = {}
for fam, hs in HASHES.items():
    for h in hs:
        rec = {"family_ours": fam, "triage": triage(h), "mb": mb(h)}
        out[h] = rec
        t = rec["triage"]; m = rec["mb"]
        cfg = t.get("configs") if isinstance(t, dict) else None
        print("%-12s %s T:%s MB:%s %s" % (
            fam, h[:12],
            ("%s score=%s" % (t.get("family"), t.get("score"))) if t.get("found") else t.get("found", t),
            m.get("signature") or m.get("query_status"),
            ("CONFIG:" + json.dumps(cfg)[:200]) if cfg else ""))
        time.sleep(0.6)
json.dump(out, open(sys.argv[2], "w"), indent=1)
print("saved", sys.argv[2])
