"""Source fresh Tsunami/Kaiten ELF payloads from abuse.ch (URLhaus feed + MalwareBazaar fallback),
dedup against what we already hold, and fingerprint each IN MEMORY for the auto-scanning
ZiggyStarTux / "Qbot Redo by Milenko" / Ziggy-Redo-by-Freak lineage -- the only behaviour that
floods under our reg-only controller. Quarantine ALL downloaded ELFs 0600 (never executed); the
auto-scan CLONES are the sourcing goal. Keys read from /home/ali/Desktop/Hazim/.env, never printed.
"""
import json, os, re, subprocess, sys, time, urllib.request, urllib.parse, zipfile, io, hashlib
from pathlib import Path

STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
ENV = "/home/ali/Desktop/Hazim/.env"
QUAR = STUDY / "data/malware/revision5-diverse/ziggy-incoming"
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
HERE = Path(__file__).resolve().parent

MARKERS = [b"Ziggy StarTux", b"ZIGGY StarTux", b"Kaiten Reborn", b"Ziggy Redo", b"Qbot Redo",
           b"by Milenko", b"by Freak", b"ziggy.c", b"Shellz", b"Enabled and awaiting orders",
           b"GETBB", b"SCANNER STARTED!", b"[TELNET] CRACKED", b"doScanner", b"advance_state",
           b"KEKSTD", b"busyboxterrorist", b"RNDNICK"]
IRC = [b"NICK ", b"USER ", b"JOIN ", b"PRIVMSG", b"PONG", b"NOTICE "]
STR = re.compile(rb"[\x20-\x7e]{4,}")
MAXNEW = int(os.environ.get("ZIGGY_MAXNEW", "245"))


def key(name):
    for ln in open(ENV):
        ln = ln.strip()
        if ln.startswith("export "):
            ln = ln[7:]
        if "=" in ln and ln.split("=", 1)[0].strip() == name:
            return ln.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def urlhaus_list(sig, k):
    req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/signature/",
        data=urllib.parse.urlencode({"signature": sig}).encode(),
        headers={"Auth-Key": k, "User-Agent": "Mozilla/5.0 research"})
    r = json.load(urllib.request.urlopen(req, timeout=60))
    out = {}
    for u in (r.get("urls") or []):
        if u.get("file_type") == "elf" and u.get("sha256_hash"):
            out[u["sha256_hash"].lower()] = u
    return out


def dl_urlhaus(url, k):
    try:
        req = urllib.request.Request(url, headers={"Auth-Key": k, "User-Agent": "Mozilla/5.0 research"})
        b = urllib.request.urlopen(req, timeout=60).read()
        # urlhaus sometimes returns a zip (pw infected); unwrap
        if b[:2] == b"PK":
            z = zipfile.ZipFile(io.BytesIO(b))
            m = z.namelist()[0]
            return z.read(m, pwd=b"infected")
        return b
    except Exception:
        return None


def dl_mb(sha, k):
    try:
        req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/",
            data=urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha}).encode(),
            headers={"Auth-Key": k, "User-Agent": "Mozilla/5.0 research"})
        b = urllib.request.urlopen(req, timeout=60).read()
        if b[:2] == b"PK":
            z = zipfile.ZipFile(io.BytesIO(b))
            return z.read(z.namelist()[0], pwd=b"infected")
        return None
    except Exception:
        return None


def fingerprint(b):
    text = b"\n".join(STR.findall(b))
    hits = [m.decode("latin-1") for m in MARKERS if m in text]
    irc = sum(1 for m in IRC if m in text)
    banner = [l.decode("latin-1") for l in STR.findall(b) if b"Kaiten" in l or b"Ziggy" in l][:1]
    mach = "?"
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b); tmp = f.name
        os.chmod(tmp, 0o600)
        out = subprocess.run(["readelf", "-h", tmp], capture_output=True, text=True, timeout=30).stdout
        os.unlink(tmp)
        m = re.search(r"Machine:\s+(.*)", out); c = re.search(r"Class:\s+(ELF\d+)", out)
        mach = ((c.group(1) if c else "?") + "/" + (m.group(1).strip() if m else "?"))
    except Exception:
        pass
    return len(hits), hits, irc, banner[0] if banner else "", mach


def main():
    k = key("ABUSE_CH_API_KEY"); mbk = key("MALWARE_BAZAAR_API_KEY")
    assert k, "no ABUSE_CH_API_KEY"
    QUAR.mkdir(parents=True, exist_ok=True); os.chmod(QUAR, 0o700)
    known = set()
    if KNOWN.is_file():
        for ln in open(KNOWN):
            try:
                known.add(json.loads(ln).get("sha256", "").lower())
            except Exception:
                pass
    # also skip anything already on disk anywhere in the malware tree
    cand = {}
    for sig in ("Tsunami", "Kaiten"):
        try:
            cand.update(urlhaus_list(sig, k))
        except Exception as e:
            print("list", sig, "error", e)
    new = [(s, u) for s, u in cand.items() if s not in known]
    print("urlhaus elf payloads: %d | already-known: %d | NEW to fetch: %d (cap %d)"
          % (len(cand), len(cand) - len(new), len(new), MAXNEW))
    new.sort(key=lambda su: su[1].get("firstseen", ""), reverse=True)
    results = []; got = 0; clones = 0
    for sha, u in new[:MAXNEW]:
        b = dl_urlhaus(u.get("urlhaus_download", ""), k)
        if not b or hashlib.sha256(b).hexdigest().lower() != sha:
            b = dl_mb(sha, mbk or k)
        if not b or hashlib.sha256(b).hexdigest().lower() != sha:
            results.append({"sha256": sha, "status": "download_failed", "firstseen": u.get("firstseen")})
            continue
        if b[:4] != b"\x7fELF":
            results.append({"sha256": sha, "status": "not_elf"}); continue
        p = QUAR / (sha + ".elf")
        with open(p, "wb") as f:
            f.write(b)
        os.chmod(p, 0o600)
        got += 1
        nmark, hits, irc, banner, mach = fingerprint(b)
        clone = nmark >= 4 and irc >= 3
        clones += clone
        results.append({"sha256": sha, "status": "ok", "firstseen": u.get("firstseen"),
                        "markers": nmark, "marker_list": hits, "irc": irc, "banner": banner,
                        "mach": mach, "clone": clone})
        with open(KNOWN, "a") as kf:
            kf.write(json.dumps({"sha256": sha, "family": "Tsunami", "source": "urlhaus"}) + "\n")
        time.sleep(0.2)
    summ = {"fetched": got, "clones": clones, "results": results}
    (HERE / "ziggy_incoming_candidates.json").write_text(json.dumps(summ, indent=1))
    print("fetched %d ELFs | auto-scan CLONES=%d" % (got, clones))
    print("\n=== auto-scan CLONES found (the goal) ===")
    for r in results:
        if r.get("clone"):
            print("  %s  %-10s %-22s m=%d irc=%d  %s" % (r["sha256"][:12], r.get("firstseen"),
                  r.get("mach"), r["markers"], r["irc"], r.get("banner")))
    print("\n=== distinct banners among fetched ===")
    ban = {}
    for r in results:
        if r.get("status") == "ok":
            ban[r.get("banner", "")] = ban.get(r.get("banner", ""), 0) + 1
    for bnr, c in sorted(ban.items(), key=lambda x: -x[1])[:25]:
        print("  %3d  %s" % (c, bnr[:90]))
    print("\nwrote", HERE / "ziggy_incoming_candidates.json")


if __name__ == "__main__":
    main()
