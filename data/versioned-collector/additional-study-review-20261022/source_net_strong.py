"""Stage 1 sourcing for the network-strong DDoS cohort (host-side only; NO execution, NO VM).

Downloads native x86-64/i386 candidates from MalwareBazaar (non-Triage) for the IRC-flood / scanner families
(Tsunami/Kaiten lineage, Gafgyt, Mirai), classifies ELF mode in-memory (never extracts a malware member to disk),
dedups against known_metadata.jsonl, and offline-extracts each sample's likely IRC C2 endpoint (ASCII strings only)
so the later viability probe can alias it to lo and trigger the flood. Quarantine: AES-zip, 0600, never executed.
"""
import json, re, struct, subprocess, sys, time, urllib.request, urllib.parse
from pathlib import Path

STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
ENV = Path("/home/ali/Desktop/Hazim/.env")
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
QUAR = STUDY / "data/malware/revision5-diverse/net-strong-incoming"
MB_API = "https://mb-api.abuse.ch/api/v1/"
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

# IRC-controllable flood families (Tsunami == Kaiten lineage) + Mirai autonomous scanners
FAMILIES = {"Tsunami": 28, "Gafgyt": 28, "Mirai": 28}   # cap native-usable kept per family
PER_FAMILY_SCAN = 150                                   # how many recent MB rows to consider per family

IPRE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IRC_TOKENS = (b"PRIVMSG", b"NICK", b"USER ", b"JOIN", b"PING", b"PONG", b"#", b"MODE")


def env(name):
    for ln in ENV.read_text().splitlines():
        if "=" not in ln:
            continue
        k, _, v = ln.partition("=")
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


def mb(query, key, extra=None):
    body = {"query": query}
    if extra:
        body.update(extra)
    req = urllib.request.Request(MB_API, data=urllib.parse.urlencode(body).encode(),
                                 headers={"Auth-Key": key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def mb_json(query, key, extra=None):
    try:
        return json.loads(mb(query, key, extra).decode())
    except Exception as e:
        return {"query_status": "exc", "err": str(e)}


def classify(raw):
    """strict native ELF mode; returns 'amd64-static'/'amd64-dynamic'/'i386-static'/'i386-dynamic' or None."""
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


def c2_hints(raw, family):
    """offline-only: candidate IRC C2 endpoints + channels from ASCII strings (no execution)."""
    # printable runs
    runs = re.findall(rb"[\x20-\x7e]{4,}", raw)
    text = b"\n".join(runs)
    irc_like = any(t in text for t in IRC_TOKENS)
    ips = sorted({m.decode() for m in IPRE.findall(text)
                  if not m.startswith((b"0.", b"127.", b"255.", b"10.0.0", b"239."))})
    chans = sorted({m.decode(errors="replace") for m in re.findall(rb"#[A-Za-z0-9_.\-]{1,20}", text)})[:8]
    return {"irc_like": irc_like, "candidate_ips": ips[:12], "candidate_channels": chans}


def main():
    key = env("MALWARE_BAZAAR_API_KEY")
    known = known_hashes()
    QUAR.mkdir(parents=True, exist_ok=True)
    try:
        QUAR.chmod(0o700)
    except Exception:
        pass
    kept = []
    for fam, cap in FAMILIES.items():
        info = mb_json("get_siginfo", key, {"signature": fam, "limit": str(PER_FAMILY_SCAN)})
        rows = info.get("data", []) if info.get("query_status") == "ok" else []
        print("[%s] MB rows=%d (status=%s)" % (fam, len(rows), info.get("query_status")))
        got = 0
        for x in rows:
            if got >= cap:
                break
            sha = (x.get("sha256_hash") or "").lower()
            if not sha or sha in known:
                continue
            ft = (x.get("file_type", "") + x.get("file_type_mime", "")).lower()
            if "elf" not in ft:
                continue
            try:
                zbytes = mb("get_file", key, {"sha256_hash": sha})
            except Exception as e:
                print("   dl fail %s: %s" % (sha[:12], e)); continue
            if zbytes[:2] not in (b"PK",):          # MB returns a zip; a short error text otherwise
                continue
            zpath = QUAR / (sha + ".zip")
            zpath.write_bytes(zbytes)
            try:
                zpath.chmod(0o600)
            except Exception:
                pass
            # extract member in-memory for classification (never to disk)
            try:
                raw = subprocess.run(["7z", "x", "-so", "-pinfected", str(zpath)],
                                     capture_output=True, timeout=120).stdout
            except Exception as e:
                print("   7z fail %s: %s" % (sha[:12], e)); continue
            mode = classify(raw)
            known.add(sha)
            if mode is None:
                zpath.unlink(missing_ok=True)       # non-native: drop the quarantined zip
                continue
            rec = {"sha256": sha, "family": fam, "mode": mode, "zip": str(zpath),
                   "size": len(raw), "c2": c2_hints(raw, fam)}
            kept.append(rec); got += 1
            print("   KEEP %s %-13s %s irc=%s ips=%s" %
                  (sha[:12], mode, fam, rec["c2"]["irc_like"], rec["c2"]["candidate_ips"][:3]))
            time.sleep(0.25)
        print("[%s] native-usable kept=%d" % (fam, got))

    # append new hashes to known base
    with KNOWN.open("a") as f:
        for r in kept:
            f.write(json.dumps({"sha256": r["sha256"], "signature": r["family"], "source": "mb_net_strong"}) + "\n")
    out = QUAR / "net_strong_candidates.json"
    out.write_text(json.dumps({"kept": kept, "by_family": {f: sum(1 for r in kept if r["family"] == f) for f in FAMILIES},
                               "by_mode": {m: sum(1 for r in kept if r["mode"] == m)
                                           for m in sorted({r["mode"] for r in kept})}}, indent=2))
    print("\nTOTAL native-usable kept:", len(kept))
    print("by family:", {f: sum(1 for r in kept if r["family"] == f) for f in FAMILIES})
    print("by mode:", {m: sum(1 for r in kept if r["mode"] == m) for m in sorted({r["mode"] for r in kept})})
    print("irc-like (candidate flood-triggerable):", sum(1 for r in kept if r["c2"]["irc_like"]))
    print("manifest:", out)


if __name__ == "__main__":
    main()
