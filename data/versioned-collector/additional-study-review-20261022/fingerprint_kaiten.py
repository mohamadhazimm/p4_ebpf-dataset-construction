"""OFFLINE string-fingerprint hunt for the auto-scanning Kaiten/ZiggyStarTux lineage
(the ONE behaviour that floods under our reg-only controller: a telnet SYN scanner that
auto-starts after a generic IRC registration). NO execution: in-memory 7z extract / raw read
-> ASCII strings -> marker + Jaccard match against the known flooding sample 478053...

A candidate is an auto-scan CLONE if it carries the distinctive scanner/IRC markers of that
lineage (not merely the "Tsunami/Kaiten" family tag -- command-driven Kaiten bots lack the
auto-scanner and do NOT flood under a reg-only controller).

Usage: python3 fingerprint_kaiten.py DIR [DIR ...]   (writes kaiten_fingerprint.json next to this script)
"""
import glob, json, os, re, subprocess, sys
from pathlib import Path

REF_SHA = "478053ea93052dd3f1477cf497443c0cb1b0e75361ba3927b929b707c18f35e2"
HERE = Path(__file__).resolve().parent

# distinctive markers of the ZiggyStarTux / "Kaiten Reborn" / Shellz-Freak-Milenko lineage
# (the forks that bundle the auto-starting telnet scanner -- the flooding behaviour we want)
MARKERS = [
    # lineage banners (any version: StarTux 2.x, Ziggy Redo by Freak 4.x, Qbot Redo by Milenko 14.x)
    b"Ziggy StarTux",
    b"ZIGGY StarTux",
    b"Kaiten Reborn",
    b"Ziggy Redo",
    b"Qbot Redo",
    b"by Milenko",
    b"by Freak",
    b"ziggy.c",
    b"Shellz",
    # shared command/scanner skeleton
    b"Enabled and awaiting orders",
    b"GETBB",
    b"SCANNER STARTED!",
    b"[TELNET] CRACKED",
    b"doScanner",
    b"advance_state",
    b"KEKSTD",
    b"busyboxterrorist",
    b"RNDNICK",
]
# generic IRC-bot and telnet-scanner tokens (supporting signal, less specific)
IRC = [b"NICK ", b"USER ", b"JOIN ", b"PRIVMSG", b"PONG", b"NOTICE "]
SCAN = [b":23 ", b"/bin/busybox", b"ogin:", b"assword:", b"incorrect", b"/var/bin", b"telnetd"]
STR = re.compile(rb"[\x20-\x7e]{4,}")


def raw(path):
    if path.endswith(".zip"):
        try:
            return subprocess.run(["7z", "x", "-so", "-pinfected", path],
                                  capture_output=True, timeout=120).stdout
        except Exception:
            return b""
    try:
        return open(path, "rb").read()
    except Exception:
        return b""


def strings_set(b):
    return set(STR.findall(b))


def score(path, ref_markers, ref_set):
    b = raw(path)
    if not b:
        return None
    text = b"\n".join(STR.findall(b))
    ss = set(STR.findall(b))
    hits = [m.decode("latin-1") for m in MARKERS if m in text]
    irc = sum(1 for m in IRC if m in text)
    scan = sum(1 for m in SCAN if m in text)
    inter = len(ss & ref_set); union = len(ss | ref_set) or 1
    jac = inter / union
    return {"markers": len(hits), "marker_list": hits, "irc": irc, "scan": scan,
            "jaccard": round(jac, 3), "strings": len(ss)}


def main():
    dirs = sys.argv[1:]
    assert dirs, "pass candidate dirs"
    # reference
    ref_path = None
    for d in ("vbox-runs/hybrid-rf-study-20261010/data/malware/full-cohort-323/samples",):
        p = Path("/home/ali/Desktop/Hazim") / d / (REF_SHA + ".zip")
        if p.is_file():
            ref_path = str(p); break
    assert ref_path, "reference sample not found"
    rb = raw(ref_path); ref_text = b"\n".join(STR.findall(rb)); ref_set = set(STR.findall(rb))
    ref_markers = [m for m in MARKERS if m in ref_text]
    print("reference markers present: %d/%d" % (len(ref_markers), len(MARKERS)))

    seen = {}
    for d in dirs:
        for p in sorted(glob.glob(d + "/*.zip") + glob.glob(d + "/*.elf")):
            m = re.search(r"[0-9a-f]{64}", os.path.basename(p))
            sha = m.group(0) if m else os.path.basename(p)
            if sha in seen:            # dedup by sha across dirs
                continue
            s = score(p, ref_markers, ref_set)
            if s is None:
                continue
            s["sha"] = sha; s["path"] = p; s["dir"] = os.path.basename(os.path.dirname(p))
            # clone tier: carries the lineage scanner/IRC markers strongly
            s["clone"] = (sha == REF_SHA) or (s["markers"] >= 4 and s["irc"] >= 3)
            s["near"] = (not s["clone"]) and (s["markers"] >= 2 or s["jaccard"] >= 0.30)
            seen[sha] = s
    rows = sorted(seen.values(), key=lambda r: (r["markers"], r["jaccard"]), reverse=True)
    out = HERE / "kaiten_fingerprint.json"
    json.dump({"reference": REF_SHA, "ref_markers_present": len(ref_markers),
               "n": len(rows), "clones": [r for r in rows if r["clone"]],
               "near": [r for r in rows if r["near"]], "all": rows}, open(out, "w"), indent=1)
    clones = [r for r in rows if r["clone"] and r["sha"] != REF_SHA]
    near = [r for r in rows if r["near"]]
    print("scanned %d unique samples | CLONES=%d (excl. ref) | NEAR=%d" % (len(rows), len(clones), len(near)))
    print("\n=== auto-scan CLONES (markers>=4 & irc>=3) ===")
    for r in clones[:40]:
        print("  %s  %-20s markers=%d irc=%d scan=%d jac=%.2f  %s"
              % (r["sha"][:12], r["dir"], r["markers"], r["irc"], r["scan"], r["jaccard"], ",".join(r["marker_list"][:4])))
    print("\n=== NEAR (weaker lineage signal) ===")
    for r in near[:20]:
        print("  %s  %-20s markers=%d irc=%d scan=%d jac=%.2f" % (r["sha"][:12], r["dir"], r["markers"], r["irc"], r["scan"], r["jaccard"]))
    print("\nwrote", out)


if __name__ == "__main__":
    main()
