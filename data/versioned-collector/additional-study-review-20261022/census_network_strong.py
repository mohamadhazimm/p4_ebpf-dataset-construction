"""Plan-only sourcing census for network-STRONG Linux malware (DDoS/flood/scan botnets), from NON-Triage sources.

Reads MALWARE_BAZAAR_API_KEY and MALSHARE_API_KEY from /home/ali/Desktop/Hazim/.env (never printed). NO sample is
downloaded or executed here -- this only counts what is obtainable, by family and ELF mode, deduped against what we
already hold (known_metadata.jsonl). It reports, so the user can decide the cohort before any download/collection.
"""
import json, sys, time, urllib.request, urllib.parse, urllib.error
from pathlib import Path

STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
ENV = Path("/home/ali/Desktop/Hazim/.env")
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
MB_API = "https://mb-api.abuse.ch/api/v1/"
MS_API = "https://malshare.com/api.php"

# network-strong families: volumetric DDoS / flood / telnet-scanner botnets where the NETWORK signal is the discriminator
NET_STRONG = ["Mirai", "Gafgyt", "Tsunami", "Mozi", "Dofloo", "Kaiji", "RapperBot", "Hajime", "Pnscan", "MooBot",
              "Enemybot", "Condi", "Fodcha", "Zerobot", "Ngioweb", "Muhstik", "Sysrv", "Katana", "Chaos", "XorDDoS"]


UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")


def env(name):
    for ln in ENV.read_text().splitlines():
        if "=" not in ln:
            continue
        k, _, v = ln.partition("=")          # .env uses `NAME = "value"` (spaces + quotes)
        if k.strip() == name:
            return v.strip().strip('"').strip("'")
    return ""


def known_hashes():
    s = set()
    if KNOWN.is_file():
        for ln in KNOWN.read_text().splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
                for k in ("sha256", "sha256_hash", "hash"):
                    if d.get(k):
                        s.add(d[k].lower())
            except Exception:
                pass
    return s


def mb_siginfo(sig, key, limit=100):
    body = urllib.parse.urlencode({"query": "get_siginfo", "signature": sig, "limit": str(limit)}).encode()
    req = urllib.request.Request(MB_API, data=body, headers={"Auth-Key": key, "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            d = json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}
    if d.get("query_status") != "ok":
        return {"status": d.get("query_status")}
    return {"data": d.get("data", [])}


def ms_get(params, key):
    params = dict(params); params["api_key"] = key
    url = MS_API + "?" + urllib.parse.urlencode(params)
    try:
        rq = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(rq, timeout=60) as r:
            raw = r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return {"error": "HTTP %s %s" % (e.code, e.read().decode(errors="replace")[:120])}
    except Exception as e:
        return {"error": str(e)}
    try:
        return {"json": json.loads(raw)}
    except Exception:
        return {"text": raw[:200]}


def main():
    mb = env("MALWARE_BAZAAR_API_KEY"); ms = env("MALSHARE_API_KEY")
    known = known_hashes()
    print("keys present: MB=%s MalShare=%s ; known-hash dedup base=%d" % (bool(mb), bool(ms), len(known)))

    print("\n================ MalwareBazaar (abuse.ch) — network-strong family census (ELF only, deduped) ================")
    mb_rows = {}
    for sig in NET_STRONG:
        res = mb_siginfo(sig, mb, limit=100)
        if "data" not in res:
            print("  %-12s -> %s" % (sig, res)); continue
        elf = [x for x in res["data"] if "elf" in (x.get("file_type_mime", "") + x.get("file_type", "")).lower()]
        new = [x for x in elf if (x.get("sha256_hash", "").lower() not in known)]
        archs = {}
        for x in new:
            a = (x.get("architecture") or "?")
            archs[a] = archs.get(a, 0) + 1
        mb_rows[sig] = {"elf_returned": len(elf), "new_vs_known": len(new), "arch": archs}
        print("  %-12s returned ELF=%-3d  NEW(not held)=%-3d  arch=%s" % (sig, len(elf), len(new), archs))
        time.sleep(0.3)

    print("\n================ MalShare (malshare.com) — reachability + ELF availability (24h) ================")
    t = ms_get({"action": "gettypes"}, ms)
    if "json" in t and isinstance(t["json"], dict):
        elfish = {k: v for k, v in t["json"].items() if "ELF" in k.upper()}
        print("  gettypes OK; ELF-ish buckets (24h):", elfish, "; total buckets:", len(t["json"]))
    else:
        print("  gettypes ->", t)
    le = ms_get({"action": "getlistbytype", "type": "ELF"}, ms)
    if "json" in le and isinstance(le["json"], list):
        rows = le["json"]
        newms = [r for r in rows if (r.get("sha256", "").lower() not in known)]
        print("  getlistbytype ELF (24h): %d rows, %d not-held; sample keys=%s" %
              (len(rows), len(newms), list(rows[0].keys()) if rows else []))
    else:
        print("  getlistbytype ELF ->", le)
    # MalShare search for a couple of network-strong families (metadata search)
    for q in ("mirai", "gafgyt", "tsunami"):
        s = ms_get({"action": "search", "query": q}, ms)
        if "json" in s and isinstance(s["json"], list):
            print("  search %-8s -> %d hits" % (q, len(s["json"])))
        else:
            print("  search %-8s -> %s" % (q, s))
        time.sleep(0.3)

    print("\n================ SUMMARY ================")
    total_new = sum(v["new_vs_known"] for v in mb_rows.values() if isinstance(v, dict) and "new_vs_known" in v)
    print("MB new network-strong ELF candidates (not already held), summed over families:", total_new)
    print("Top MB families by NEW candidates:",
          sorted(((v.get("new_vs_known", 0), k) for k, v in mb_rows.items()), reverse=True)[:8])


if __name__ == "__main__":
    main()
