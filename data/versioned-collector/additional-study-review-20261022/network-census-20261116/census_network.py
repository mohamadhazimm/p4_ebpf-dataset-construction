#!/usr/bin/env python3
"""Census: which Linux malware families on Triage and MalwareBazaar have native x86 samples that use the network?

Read-only and host-side. Only metadata and analysis reports are fetched (Triage search results, static and
behavioral reports; MalwareBazaar signature listings). No sample is downloaded, and nothing is executed. Keys are
read from /home/ali/Desktop/Hazim/.env and never printed. Triage needs a browser User-Agent; one request per second.
Reports are untrusted data: they are saved under raw/ and only parsed as JSON.

Per family (Triage family tag; the MalwareBazaar signature in FAMILIES):
- MalwareBazaar: how many ELF files the signature lists, and how many of them we do not hold yet.
- Triage: search the family tag, newest first; skip hashes we hold; for each new hash, the static report says
  whether it is an ELF for Linux on x86 (tags "x64" or "x86"); for those, the behavioral report of a Linux amd64 run
  gives the sample's own flows. The sample's flows are separated from the sandbox OS's traffic with the background
  of the 2026-11-15 check of the 99 dataset malware (triage_network_analyze.py: shared endpoints, vendor names and
  their DNS aliases, Canonical's network; DNS judged by the names asked). Classes as there: silent, all answered,
  some unanswered, none answered, uncertain (at most 3 flows to ports 80/443 and no name outside the vendor list).
- Budget: at most SCAN static reports and KEEP network-active x86 samples per family; a family is abandoned after
  MISS_RUN consecutive hashes that are not x86 Linux ELF files.

Category per family is from public threat reporting, not verified here.

    /usr/bin/python3 -I census_network.py
"""
import collections
import csv
import json
import site
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
sys.path.append(site.getusersitepackages())     # numpy for the imported module; -I keeps cwd and env out of sys.path
sys.path.insert(0, str(ASR / "sample-intel-20261113"))
import triage_network_analyze as T      # noqa: E402  background rules of the 2026-11-15 check

STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
KNOWN = STUDY / "data/malware/revision5-diverse/known_metadata.jsonl"
SELECTION = STUDY / "data/malware/revision5-diverse/matched-selection/malware_selection.json"
FEATURES = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
RAW = HERE / "raw"
OUT_JSON, OUT_CSV = HERE / "census.json", HERE / "census_candidates.csv"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
TRIAGE = "https://tria.ge/api/v0/"
MB = "https://mb-api.abuse.ch/api/v1/"
SCAN, KEEP, MISS_RUN, PAGES = 25, 10, 12, 6

# Triage family tag -> (MalwareBazaar signature, category from public reporting, in the 99?)
FAMILIES = {
    "kinsing": ("Kinsing", "miner and worm (Go)", False),
    "sysrv": ("Sysrv", "miner and worm (Go)", False),
    "p2pinfect": ("P2PInfect", "P2P worm (Rust)", False),
    "redtail": ("RedTail", "miner and worm", False),
    "diicot": ("Diicot", "SSH brute-force botnet and miner", False),
    "lucifer": ("Lucifer", "DDoS bot and miner", False),
    "muhstik": ("Muhstik", "IRC DDoS bot and worm", False),
    "ddostf": ("DDoSTF", "DDoS bot", False),
    "zergeca": ("Zergeca", "DDoS bot (Go)", False),
    "moobot": ("Moobot", "DDoS bot (Mirai variant)", False),
    "mozi": ("Mozi", "P2P IoT botnet", False),
    "hajime": ("Hajime", "P2P IoT worm", False),
    "xmrig": ("XMRIG", "cryptominer", False),
    "kimwolf": ("Kimwolf", "DDoS bot", False),
    "jackskid": ("JackSkid", "DDoS bot", False),
    "flylegitbot": ("FlyLegitBot", "DDoS bot", False),
    "mossadproxy": ("MossadProxy", "proxy bot", False),
    "rekoobe": ("Rekoobe", "backdoor (reverse shell)", False),
    "sliver": ("Sliver", "C2 framework implant (Go)", False),
    "cobaltstrike": ("CobaltStrike", "C2 framework beacon", False),
    "meterpreter": ("Meterpreter", "C2 framework stager", False),
    "mettle": ("Mettle", "C2 framework implant", False),
    "winnti": ("Winnti", "backdoor (APT)", False),
    "merlin": ("Merlin", "C2 framework implant (Go)", False),
    "pupy": ("Pupy", "RAT", False),
    "sysjoker": ("SysJoker", "backdoor", False),
    "gobrat": ("GobRAT", "RAT (Go)", False),
    "perfctl": ("perfctl", "miner and proxyjacking", False),
    "kaiji": ("Kaiji", "DDoS bot (Go)", True),
    "ngioweb": ("Ngioweb", "proxy bot", True),
}


def env():
    d = {}
    for line in open("/home/ali/Desktop/Hazim/.env"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            d[k.strip()] = v.strip().strip(chr(34)).strip(chr(39))
    return d


ENV = env()
TH = {"Authorization": "Bearer " + ENV["TRIAGE_API_KEY"], "User-Agent": UA}


def tget(path, raw=False):
    time.sleep(1.0)
    req = urllib.request.Request(TRIAGE + path, headers=TH)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                body = r.read()
                return r.status, (body if raw else json.loads(body))
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


def mb_siginfo(signature):
    data = urllib.parse.urlencode({"query": "get_siginfo", "signature": signature, "limit": 1000}).encode()
    req = urllib.request.Request(MB, data=data, headers={"Auth-Key": ENV.get("ABUSE_CH_API_KEY", ""),
                                                         "User-Agent": UA,
                                                         "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read())
    except Exception as e:     # noqa: BLE001
        return {"status": "error %s" % type(e).__name__, "rows": []}
    return {"status": d.get("query_status"), "rows": d.get("data") or [] if isinstance(d.get("data"), list) else []}


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


def background():
    """The background endpoint sets of triage_network_analyze.main(), computed from the saved reports of the 99."""
    per_hash = T.load_reports()
    rows = [r for r in csv.DictReader(open(FEATURES)) if r["category"] == "malware"]
    fam = {r["sha256"]: r["family"] for r in rows}
    have = [h for h in fam if h in per_hash and per_hash[h]["reports"]]
    ip_h, ip_f, dom_h, dom_f = (collections.defaultdict(set) for _ in range(4))
    for h in have:
        for rp in per_hash[h]["reports"]:
            flows, asked, _ = T.report_parts(rp["report"])
            for f in flows:
                ip, _ = T.split_ep(f.get("dst", ""))
                ip_h[ip].add(h)
                ip_f[ip].add(fam[h])
            for names in asked.values():
                for n in names:
                    dom_h[n].add(h)
                    dom_f[n].add(fam[h])
    n = len(have)
    bg_ip = {ip for ip in ip_h if len(ip_h[ip]) >= T.BG_SHARE * n and len(ip_f[ip]) >= T.BG_FAMILIES}
    bg_dom = {d for d in dom_h if len(dom_h[d]) >= T.BG_SHARE * n and len(dom_f[d]) >= T.BG_FAMILIES}
    bg_dom |= {d for d in dom_h if T.vendor(d)}
    bg_dom -= set(T.NEVER_BACKGROUND)
    for h in have:
        for rp in per_hash[h]["reports"]:
            flows, asked, answers = T.report_parts(rp["report"])
            ips = (rp["report"].get("network") or {}).get("ips") or {}
            names, addrs = T.alias_closure(answers, [d for d in answers if T.vendor(d) or d in bg_dom])
            bg_dom |= names - set(T.NEVER_BACKGROUND)
            bg_ip |= addrs
            for f in flows:
                ip, _ = T.split_ep(f.get("dst", ""))
                if (T.vendor(f.get("domain")) or T.vendor(f.get("tls_sni"))
                        or (f.get("domain") or "").lower().rstrip(".") in bg_dom
                        or (ips.get(ip) or {}).get("asn") in T.VENDOR_ASNS):
                    bg_ip.add(ip)
    google = set()
    for h in have:
        for rp in per_hash[h]["reports"]:
            google |= T.alias_closure(T.report_parts(rp["report"])[2], list(T.NEVER_BACKGROUND))[1]
    return bg_ip - google, bg_dom


def classify(rep, bg_ip, bg_dom):
    """The sample's own flows in one behavioral report, by the rules of triage_network_analyze.main()."""
    starts = [p.get("started") for p in (rep.get("processes") or []) if p.get("started") is not None]
    t0 = min(starts) if starts else 0
    flows, asked, answers = T.report_parts(rep)
    ips_info = (rep.get("network") or {}).get("ips") or {}
    names_vendor, addrs_vendor = T.alias_closure(answers, [d for d in answers if T.vendor(d) or d in bg_dom])
    bgd = (bg_dom | names_vendor) - set(T.NEVER_BACKGROUND)
    bgi = (bg_ip | addrs_vendor) - T.alias_closure(answers, list(T.NEVER_BACKGROUND))[1]   # www.google.com: never
    bg_resolved = {v for d in bgd for v in answers.get(d, ())}
    rec = {"flows": 0, "answered": 0, "dst_ips": set(), "ports": collections.Counter(), "dns": set(),
           "named": set(), "first_contact_s": None, "protocols": collections.Counter()}
    for f in flows:
        ip, port = T.split_ep(f.get("dst", ""))
        names = asked.get(f.get("id"), set())
        if T.special(ip):
            continue
        if port == 53:
            is_bg = not names or names <= bgd
        else:
            is_bg = (ip in bgi or ip in bg_resolved or (f.get("domain") or "").lower().rstrip(".") in bgd
                     or T.vendor(f.get("domain")) or (ips_info.get(ip) or {}).get("asn") in T.VENDOR_ASNS)
        if is_bg:
            continue
        rec["flows"] += 1
        rec["answered"] += int((f.get("rx_packets") or 0) > 0)
        rec["dst_ips"].add(ip)
        rec["ports"][port] += 1
        rec["dns"] |= {x for x in names if x not in bgd}
        rec["named"] |= {x for x in (f.get("domain"), f.get("tls_sni")) if x and not T.vendor(x)}
        rec["protocols"].update(f.get("protocols") or [])
        t = (f.get("first_seen", 0) - t0) / 1000
        rec["first_contact_s"] = t if rec["first_contact_s"] is None else min(rec["first_contact_s"], t)
    fl, ans = rec["flows"], rec["answered"]
    cls = "silent" if fl == 0 else "all_answered" if ans == fl else "none_answered" if ans == 0 else "some_unanswered"
    if 0 < fl <= 3 and set(rec["ports"]) <= {80, 443} and not rec["dns"] and not rec["named"]:
        cls = "uncertain"
    return {"class": cls, "flows": fl, "answered": ans, "dst_ips_n": len(rec["dst_ips"]),
            "scanner": len(rec["dst_ips"]) >= 50, "top_ports": [p for p, _ in rec["ports"].most_common(5)],
            "dns_names": sorted(rec["dns"])[:6], "protocols": dict(rec["protocols"]),
            "first_contact_s": rec["first_contact_s"]}


def x86_elf(static):
    files = [f for f in (static.get("files") or []) if f.get("selected") or f.get("depth") == 0][:1]
    if not files:
        return None
    f = files[0]
    tags = set(f.get("tags") or [])
    if ".elf" not in (f.get("exts") or []) or "linux" not in tags:
        return None
    if "x64" in tags:
        return "x64"
    if "x86" in tags or "x32" in tags or "i386" in tags:
        return "x86"
    return None


def main():
    RAW.mkdir(exist_ok=True)
    known = known_hashes()
    bg_ip, bg_dom = background()
    print("known hashes %d; background %d IPs, %d names" % (len(known), len(bg_ip), len(bg_dom)), flush=True)
    summary, cands = {}, []
    for fam, (sig, cat, in99) in FAMILIES.items():
        mb = mb_siginfo(sig)
        elf = [r for r in mb["rows"] if (r.get("file_type") or "").lower() == "elf"]
        s = {"category": cat, "in_dataset": in99, "mb_signature": sig, "mb_status": mb["status"],
             "mb_elf": len(elf), "mb_elf_new": sum(1 for r in elf if (r.get("sha256_hash") or "").lower() not in known),
             "triage_hits": 0, "triage_new": 0, "x86_elf": 0, "with_linux_run": 0, "classes": collections.Counter(),
             "network_active": 0, "scanners": 0, "stopped": ""}
        seen, misses, cursor, kept = set(), 0, None, 0
        for _ in range(PAGES):
            q = "search?query=" + urllib.parse.quote("family:" + fam) + "&limit=50"
            if cursor:
                q += "&offset=" + urllib.parse.quote(cursor)
            st, res = tget(q)
            if st != 200 or not res:
                s["stopped"] = s["stopped"] or ("search status %s" % st)
                break
            rows = res.get("data") or []
            for row in rows:
                h = (row.get("sha256") or "").lower()
                if not h or h in seen:
                    continue
                seen.add(h)
                s["triage_hits"] += 1
                if h in known:
                    continue
                s["triage_new"] += 1
                if s["x86_elf"] + misses >= SCAN or kept >= KEEP or misses >= MISS_RUN:
                    continue
                st, static = tget("samples/%s/reports/static" % row["id"])
                arch = x86_elf(static) if st == 200 and static else None
                if not arch:
                    misses += 1
                    continue
                misses = 0
                s["x86_elf"] += 1
                st, ov = tget("samples/%s/overview.json" % row["id"])
                if st != 200 or not ov:
                    continue
                task = next((tid for tid, t in (ov.get("tasks") or {}).items() if t.get("kind") == "behavioral"
                             and t.get("status") == "reported" and "amd64" in ((t.get("os") or "") + (t.get("resource") or ""))), None)
                if not task:
                    continue
                short = task[len(row["id"]) + 1:] if task.startswith(row["id"] + "-") else task
                st, rep = tget("samples/%s/%s/report_triage.json" % (row["id"], short))
                if st != 200 or not rep:
                    continue
                s["with_linux_run"] += 1
                d = RAW / h
                d.mkdir(exist_ok=True)
                (d / "overview.json").write_text(json.dumps(ov))
                (d / ("%s.json" % short)).write_text(json.dumps(rep))
                c = classify(rep, bg_ip, bg_dom)
                s["classes"][c["class"]] += 1
                active = c["class"] in ("all_answered", "some_unanswered", "none_answered")
                s["network_active"] += int(active)
                s["scanners"] += int(c["scanner"])
                kept += int(active)
                cands.append(dict({"family": fam, "category": cat, "sha256": h, "triage_id": row["id"],
                                   "filename": row.get("filename"), "submitted": row.get("submitted"), "arch_tag": arch,
                                   "os": (ov["tasks"][task].get("os") or ""), "network_active": active}, **c))
            cursor = res.get("next")
            if not cursor or kept >= KEEP or misses >= MISS_RUN or s["x86_elf"] + misses >= SCAN:
                break
        if misses >= MISS_RUN:
            s["stopped"] = s["stopped"] or "%d hashes in a row not x86 Linux ELF" % misses
        s["classes"] = dict(s["classes"])
        summary[fam] = s
        print("%-12s %-28s MB elf %4d (new %4d) | Triage hits %3d new %3d x86-ELF %2d run %2d net-active %2d "
              "scanners %2d %s" % (fam, cat[:28], s["mb_elf"], s["mb_elf_new"], s["triage_hits"], s["triage_new"],
                                   s["x86_elf"], s["with_linux_run"], s["network_active"], s["scanners"], s["stopped"]),
              flush=True)
        OUT_JSON.write_text(json.dumps({"summary": summary, "candidates": cands}, indent=1, default=str))
    with open(OUT_CSV, "w", newline="") as fh:
        keys = ["family", "category", "sha256", "triage_id", "filename", "submitted", "arch_tag", "os", "network_active",
                "class", "flows", "answered", "dst_ips_n", "scanner", "top_ports", "dns_names", "first_contact_s"]
        w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for c in cands:
            w.writerow(c)
    print("wrote", OUT_JSON, OUT_CSV)


if __name__ == "__main__":
    main()
