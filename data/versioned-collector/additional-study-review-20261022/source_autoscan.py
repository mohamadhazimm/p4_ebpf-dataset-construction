"""Source autonomous-scanner DDoS/flood ELF candidates (host-side only; NO execution, NO VM).

Target families that tend to SYN-scan/flood on launch (the "host can't tell" class we need to
grow): Mirai, Gafgyt, Mozi, Tsunami, Kaiten, Hajime. Three sources, all abuse.ch calls use the
UNIFIED ABUSE_CH_API_KEY (old MB-only key is deprecated -> 403):
  - MalwareBazaar get_siginfo(<family>)              -> family samples by signature
  - ThreatFox get_iocs(days) -> sha256_hash IOCs     -> fetched from MB get_file (fresh variants)
  - Triage search family:<f> tag:linux -> download   -> native ELF
Each candidate: fetch bytes, classify strict ELF mode in-memory (7z -so for MB AES zips; raw for
Triage), keep native x86 (amd64/i386 static or interp-linked dynamic; exclude static-PIE/ET_DYN-
no-interp and non-x86), dedup vs known_metadata.jsonl, quarantine 0600 (never extracted to disk,
never executed). Appends new hashes to known_metadata.jsonl; writes a manifest. Keys from .env only.
"""
import json, os, re, struct, subprocess, sys, time, urllib.request, urllib.parse

STUDY = "/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010"
ENV = "/home/ali/Desktop/Hazim/.env"
KNOWN = os.path.join(STUDY, "data/malware/revision5-diverse/known_metadata.jsonl")
QUAR_MB = os.path.join(STUDY, "data/malware/revision5-diverse/autoscan-incoming")      # MB/ThreatFox AES zips
QUAR_TR = os.path.join(STUDY, "data/malware/revision5-diverse/autoscan-triage")        # Triage raw ELF
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
FAMILIES = ["Mirai", "Gafgyt", "Mozi", "Tsunami", "Kaiten", "Hajime"]
FAM_LC = {f.lower() for f in FAMILIES}
MB_PER_FAMILY = 400       # get_siginfo rows considered per family
TRIAGE_PER_FAMILY = 60    # Triage search rows considered per family
CAP_KEEP_PER_FAMILY = 60  # native-usable kept per family (across all sources)
MAX_DOWNLOADS = 900       # hard cap on get_file/sample downloads attempted


def env(name):
    for ln in open(ENV):
        if "=" in ln:
            k, _, v = ln.partition("=")
            if k.strip() == name:
                return v.strip().strip('"').strip("'")
    return ""


def known_hashes():
    s = set()
    if os.path.isfile(KNOWN):
        for ln in open(KNOWN):
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


def classify(raw):
    """strict native ELF mode -> amd64-static/amd64-dynamic/i386-static/i386-dynamic or None."""
    if raw[:4] != b"\x7fELF":
        return None
    cls = raw[4]
    try:
        emach = struct.unpack_from("<H", raw, 18)[0]
        phoff = struct.unpack_from("<Q" if cls == 2 else "<I", raw, 32 if cls == 2 else 28)[0]
        phes = struct.unpack_from("<H", raw, 54 if cls == 2 else 42)[0]
        phn = struct.unpack_from("<H", raw, 56 if cls == 2 else 44)[0]
    except Exception:
        return None
    if cls == 2 and emach == 62:
        arch = "amd64"
    elif cls == 1 and emach == 3:
        arch = "i386"
    else:
        return None
    interp = dyn = False
    for i in range(phn):
        o = phoff + i * phes
        try:
            pt = struct.unpack_from("<I", raw, o)[0]
        except Exception:
            break
        if pt == 3:
            interp = True
        if pt == 2:
            dyn = True
    if interp:
        return arch + "-dynamic"
    if dyn:
        return None            # static-PIE / ET_DYN-no-interp -> unsupported
    return arch + "-static"


def mb_get_file(sha, key):
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/",
                                 data=urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha}).encode(),
                                 headers={"Auth-Key": key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read()


def mb_siginfo(sig, key, limit):
    req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/",
                                 data=urllib.parse.urlencode({"query": "get_siginfo", "signature": sig, "limit": str(limit)}).encode(),
                                 headers={"Auth-Key": key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        d = json.loads(r.read())
    return d.get("data", []) if d.get("query_status") == "ok" else []


def threatfox_hashes(key, days=7):   # ThreatFox caps days at 7; >7 returns a string error, not rows
    req = urllib.request.Request("https://threatfox-api.abuse.ch/api/v1/",
                                 data=json.dumps({"query": "get_iocs", "days": days}).encode(),
                                 headers={"Auth-Key": key, "User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        d = json.loads(r.read())
    out = {}  # sha -> family
    data = d.get("data")
    if d.get("query_status") != "ok" or not isinstance(data, list):
        return out
    for row in data:
        if not isinstance(row, dict) or row.get("ioc_type") != "sha256_hash":
            continue
        fam = (row.get("malware_printable") or "") + " " + (row.get("malware") or "") + " " + (row.get("malware_alias") or "")
        hit = next((f for f in FAM_LC if f in fam.lower()), None)
        if hit:
            out[(row.get("ioc") or "").lower()] = hit
    return out


def urlhaus_hashes(key):   # URLhaus recent ELF payloads (GET) -> {sha256: family}
    req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/payloads/recent/",
                                 headers={"Auth-Key": key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        d = json.loads(r.read())
    out = {}
    if d.get("query_status") != "ok":
        return out
    for row in (d.get("payloads") or []):
        if not isinstance(row, dict) or "elf" not in (row.get("file_type", "") or "").lower():
            continue
        hit = next((f for f in FAM_LC if f in (row.get("signature") or "").lower()), None)
        sha = (row.get("sha256_hash") or "").lower()
        if hit and sha:
            out[sha] = hit
    return out


def triage_ids(fam, key, limit):
    req = urllib.request.Request("https://api.tria.ge/v0/search?" + urllib.parse.urlencode({"query": "family:%s" % fam}),
                                 headers={"Authorization": "Bearer " + key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read())
    return [row.get("id") for row in (d.get("data", []) or [])[:limit] if row.get("id")]


def triage_sample(sid, key):
    req = urllib.request.Request("https://api.tria.ge/v0/samples/%s/sample" % sid,
                                 headers={"Authorization": "Bearer " + key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read()


def extract_member(zpath):
    try:
        return subprocess.run(["7z", "x", "-so", "-pinfected", zpath], capture_output=True, timeout=180).stdout
    except Exception:
        return b""


def main():
    ab = env("ABUSE_CH_API_KEY")
    tr = env("TRIAGE_API_KEY")
    if not ab:
        print("ABUSE_CH_API_KEY missing; abort"); sys.exit(2)
    for d in (QUAR_MB, QUAR_TR):
        os.makedirs(d, exist_ok=True)
        try: os.chmod(d, 0o700)
        except Exception: pass
    known = known_hashes()
    print("known-hash dedup base:", len(known))
    kept = []
    keep_count = {f.lower(): 0 for f in FAMILIES}
    seen = set()
    downloads = 0

    def consider_mb(sha, fam, source):
        nonlocal downloads
        sha = sha.lower()
        if sha in known or sha in seen:
            return
        if keep_count.get(fam, 0) >= CAP_KEEP_PER_FAMILY or downloads >= MAX_DOWNLOADS:
            return
        seen.add(sha); known.add(sha); downloads += 1
        try:
            z = mb_get_file(sha, ab)
        except Exception:
            return
        if z[:2] != b"PK":
            return
        zp = os.path.join(QUAR_MB, sha + ".zip")
        open(zp, "wb").write(z)
        try: os.chmod(zp, 0o600)
        except Exception: pass
        raw = extract_member(zp)
        mode = classify(raw)
        if mode is None:
            os.unlink(zp)  # non-native: drop
            return
        kept.append({"sha256": sha, "family": fam, "mode": mode, "zip": zp, "size": len(raw), "source": source})
        keep_count[fam] = keep_count.get(fam, 0) + 1
        print("  KEEP MB   %s %-14s %-8s via %s" % (sha[:12], mode, fam, source))
        time.sleep(0.15)

    # 1) MalwareBazaar get_siginfo per family
    for sig in FAMILIES:
        try:
            rows = mb_siginfo(sig, ab, MB_PER_FAMILY)
        except Exception as e:
            print("[MB %s] err %s" % (sig, e)); rows = []
        print("[MB %s] rows=%d" % (sig, len(rows)))
        for x in rows:
            ft = (x.get("file_type", "") + x.get("file_type_mime", "")).lower()
            if "elf" not in ft:
                continue
            consider_mb(x.get("sha256_hash", ""), sig.lower(), "mb_siginfo")

    # 2) ThreatFox recent sha256 IOCs -> MB get_file
    try:
        tf = threatfox_hashes(ab, days=7)
        print("[ThreatFox] flood-family sha256 IOCs:", len(tf))
    except Exception as e:
        print("[ThreatFox] err", e); tf = {}
    for sha, fam in tf.items():
        consider_mb(sha, fam, "threatfox")

    # 2b) URLhaus recent ELF payloads -> MB get_file
    try:
        uh = urlhaus_hashes(ab)
        print("[URLhaus] flood-family ELF sha256:", len(uh))
    except Exception as e:
        print("[URLhaus] err", e); uh = {}
    for sha, fam in uh.items():
        consider_mb(sha, fam, "urlhaus")

    # 3) Triage native ELF
    for sig in FAMILIES:
        if not tr:
            break
        try:
            ids = triage_ids(sig.lower(), tr, TRIAGE_PER_FAMILY)
        except Exception as e:
            print("[Triage %s] err %s" % (sig, e)); ids = []
        print("[Triage %s] ids=%d" % (sig, len(ids)))
        for sid in ids:
            if keep_count.get(sig.lower(), 0) >= CAP_KEEP_PER_FAMILY or downloads >= MAX_DOWNLOADS:
                break
            downloads += 1
            try:
                raw = triage_sample(sid, tr)
            except Exception:
                continue
            mode = classify(raw)
            if mode is None:
                continue
            import hashlib
            sha = hashlib.sha256(raw).hexdigest()
            if sha in known or sha in seen:
                continue
            seen.add(sha); known.add(sha)
            p = os.path.join(QUAR_TR, sha + ".elf")
            open(p, "wb").write(raw)
            try: os.chmod(p, 0o600)
            except Exception: pass
            kept.append({"sha256": sha, "family": sig.lower(), "mode": mode, "elf": p, "size": len(raw),
                         "source": "triage", "triage_id": sid})
            keep_count[sig.lower()] = keep_count.get(sig.lower(), 0) + 1
            print("  KEEP TR   %s %-14s %-8s" % (sha[:12], mode, sig))
            time.sleep(0.15)

    # append to known base
    with open(KNOWN, "a") as f:
        for r in kept:
            f.write(json.dumps({"sha256": r["sha256"], "signature": r["family"], "source": "autoscan_" + r["source"]}) + "\n")

    by_family = {f.lower(): sum(1 for r in kept if r["family"] == f.lower()) for f in FAMILIES}
    by_mode = {m: sum(1 for r in kept if r["mode"] == m) for m in sorted({r["mode"] for r in kept})}
    by_source = {s: sum(1 for r in kept if r["source"] == s) for s in sorted({r["source"] for r in kept})}
    out = os.path.join(QUAR_MB, "autoscan_candidates.json")
    json.dump({"kept": kept, "downloads_attempted": downloads, "by_family": by_family,
               "by_mode": by_mode, "by_source": by_source}, open(out, "w"), indent=1)
    print("\nTOTAL native-usable kept:", len(kept))
    print("by family:", by_family)
    print("by mode:  ", by_mode)
    print("by source:", by_source)
    print("manifest:", out)


if __name__ == "__main__":
    main()
