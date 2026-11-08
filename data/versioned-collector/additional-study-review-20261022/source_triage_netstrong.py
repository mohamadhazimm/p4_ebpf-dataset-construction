"""Triage-sourced network-strong candidates WITH extracted C2 endpoints (host-side; NO execution, NO VM).

Triage's sandbox reports decode each bot's C2 config (exact IP:port, and IRC channel/key when present). We keep only
native x86-64/i386 ELF DDoS-family samples that have an extracted C2 endpoint -- those are the ones we can actually
TRIGGER to flood (alias the exact C2 IP to lo + bind a responder on the EXACT port). Downloads the raw sample from
Triage (download works again), quarantines it 0600 (never executed), classifies ELF mode in-memory, dedups, records
the full extracted config + behavioral tags for the trigger step. Key from .env (never printed).
"""
import hashlib, json, re, struct, sys, time, urllib.request, urllib.parse
from pathlib import Path

STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
ENV = Path("/home/ali/Desktop/Hazim/.env")
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
QUAR = STUDY / "data/malware/revision5-diverse/triage-netstrong"
BASE = "https://api.tria.ge/v0"
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
FAMILIES = {"mirai": 80, "gafgyt": 80, "tsunami": 60, "kaiten": 40, "dofloo": 30}  # Triage search budget per family
CAP_PER_FAMILY = 16                                                                 # native-with-C2 kept per family


def env(name):
    for ln in ENV.read_text().splitlines():
        if "=" in ln:
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


def api(path, key, raw=False):
    req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + key, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=45) as r:
        b = r.read()
    return b if raw else json.loads(b)


def classify(raw):
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
        return None
    return arch + "-static"


def c2_and_cfg(ov):
    c2 = []; cfg_all = []; tags = set(ov.get("analysis", {}).get("tags", []))
    for t in ov.get("targets", []):
        for tg in t.get("tags", []):
            tags.add(tg)
    for e in ov.get("extracted", []):
        cfg = e.get("config") or {}
        if cfg:
            cfg_all.append(cfg)
        for c in (cfg.get("c2") or []):
            c2.append(c)
    return c2, cfg_all, sorted(tags)


def main():
    key = env("TRIAGE_API_KEY")
    known = known_hashes()
    QUAR.mkdir(parents=True, exist_ok=True)
    try:
        QUAR.chmod(0o700)
    except Exception:
        pass
    kept = []
    seen_ids = set()
    for fam, budget in FAMILIES.items():
        got = 0; scanned = 0; cursor = None
        while scanned < budget and got < CAP_PER_FAMILY:
            q = "/search?query=" + urllib.parse.quote("family:%s" % fam) + "&limit=20"
            if cursor:
                q += "&offset=" + urllib.parse.quote(cursor)
            try:
                s = api(q, key)
            except Exception as e:
                print("[%s] search err %s" % (fam, e)); break
            rows = s.get("data", [])
            if not rows:
                break
            cursor = s.get("next")
            for row in rows:
                if got >= CAP_PER_FAMILY:
                    break
                sid = row.get("id")
                if not sid or sid in seen_ids:
                    continue
                seen_ids.add(sid); scanned += 1
                try:
                    ov = api("/samples/%s/overview.json" % sid, key)
                except Exception:
                    continue
                c2, cfg_all, tags = c2_and_cfg(ov)
                if not c2:
                    continue                       # need an extracted C2 endpoint to trigger
                try:
                    raw = api("/samples/%s/sample" % sid, key, raw=True)
                except Exception:
                    continue
                mode = classify(raw)
                if mode is None:
                    continue                       # non-native / unsupported
                sha = hashlib.sha256(raw).hexdigest()
                if sha in known:
                    continue
                path = QUAR / (sha + ".elf")
                path.write_bytes(raw)
                try:
                    path.chmod(0o600)
                except Exception:
                    pass
                irc = any("irc" in str(c).lower() for c in cfg_all) or \
                      any(isinstance(c, dict) and c.get("channel") for c in cfg_all)
                rec = {"sha256": sha, "triage_id": sid, "family": fam, "mode": mode, "elf_path": str(path),
                       "size": len(raw), "c2": c2[:8], "config": cfg_all[:3], "tags": tags[:15], "irc_hint": irc}
                kept.append(rec); known.add(sha); got += 1
                print("  KEEP %s %-13s %-8s c2=%s irc=%s" % (sha[:12], mode, fam, c2[:3], irc))
                time.sleep(0.2)
            if not cursor:
                break
        print("[%s] native-with-C2 kept=%d (scanned %d)" % (fam, got, scanned))

    with KNOWN.open("a") as f:
        for r in kept:
            f.write(json.dumps({"sha256": r["sha256"], "signature": r["family"], "source": "triage_netstrong"}) + "\n")
    out = QUAR / "triage_netstrong_candidates.json"
    out.write_text(json.dumps({"kept": kept,
                               "by_family": {f: sum(1 for r in kept if r["family"] == f) for f in FAMILIES},
                               "by_mode": {m: sum(1 for r in kept if r["mode"] == m) for m in sorted({r["mode"] for r in kept})}},
                              indent=2))
    print("\nTOTAL native-with-C2 kept:", len(kept))
    print("by family:", {f: sum(1 for r in kept if r["family"] == f) for f in FAMILIES})
    print("by mode:", {m: sum(1 for r in kept if r["mode"] == m) for m in sorted({r["mode"] for r in kept})})
    print("with C2 port known:", sum(1 for r in kept if any(":" in c for c in r["c2"])))
    print("irc-hint:", sum(1 for r in kept if r["irc_hint"]))
    print("manifest:", out)


if __name__ == "__main__":
    main()
