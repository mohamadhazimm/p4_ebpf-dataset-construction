#!/usr/bin/env python3
"""Read-only inventory: malware on disk that runs natively and is not in the paper's 99.

Run with: /usr/bin/python3 -I inventory.py

Reads only metadata written by our own scripts, plus the ELF headers of the
ziggy-incoming files (static parse; nothing is extracted or executed).
Prints aggregate counts per family; no per-sample records.
"""
import collections
import csv
import hashlib
import json
import pathlib
import statistics
import struct

STUDY = pathlib.Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
R = STUDY / "data/malware/revision5-diverse"
A = STUDY / "data/versioned-collector/additional-study-review-20261022"
FEAT = pathlib.Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
V21 = "4933ff5c9c56bd097ce565d14a7173bd281dd124aca43d1df0dbe76315e64b9c"
PROBES = (("C2 probe", "c2-viability/20261025T142642347649Z", "c2_selection.json"),
          ("backdoor probe", "evasive-viability/20261025T151638248361Z", "evasive_selection.json"))


def fam(x):
    return (x or "?").strip()


def fkey(x):
    return fam(x).casefold()


def sha_of(r):
    return r.get("member_sha256") or r.get("sha256") or r.get("sha")


def items(d):
    if isinstance(d, list):
        return d
    for k in ("cases", "kept", "usable", "selection", "malware"):
        if isinstance(d.get(k), list):
            return d[k]
    return next(v for v in d.values() if isinstance(v, list) and v and isinstance(v[0], dict))


def norm(m):
    m = (m or "").lower().replace("-", "_")
    if any(x in m for x in ("pie", "unsupported", "qemu", "arm", "mips")):
        return "not-native"
    if any(x in m for x in ("amd64", "x86_64", "x64")):
        return "amd64-dynamic" if "dyn" in m else "amd64-static"
    if "i386" in m:
        return "i386-dynamic" if "dyn" in m else "i386-static"
    return "other:" + m


def elf_mode(b):
    """Same rules as the collection: ET_EXEC static or interpreter-linked dynamic, x86-64 or i386."""
    if len(b) < 64 or b[:4] != b"\x7fELF":
        return "not-elf"
    cls, enc = b[4], b[5]
    if cls not in (1, 2) or enc not in (1, 2):
        return "not-native"
    e = "<" if enc == 1 else ">"
    etype, mach = struct.unpack_from(e + "HH", b, 16)
    if cls == 2:
        phoff = struct.unpack_from(e + "Q", b, 32)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", b, 54)
    else:
        phoff = struct.unpack_from(e + "I", b, 28)[0]
        phentsize, phnum = struct.unpack_from(e + "HH", b, 42)
    if phentsize < 4 or phoff + phentsize * phnum > len(b):
        return "bad-phdr"
    pt = [struct.unpack_from(e + "I", b, phoff + i * phentsize)[0] for i in range(phnum)]
    interp, dyn = 3 in pt, 2 in pt
    if (dyn and not interp) or (etype == 3 and not interp):
        return "not-native"  # no-interpreter dynamic / static-PIE: excluded by the collector rules
    if mach == 62 and cls == 2:
        return "amd64-dynamic" if interp else "amd64-static"
    if mach == 3 and cls == 1:
        return "i386-dynamic" if interp else "i386-static"
    return "not-native"


def match(sel, sample):
    return [c for c in sel if sha_of(c) in sample or pathlib.Path(c["source_path"]).stem in sample]


# --- the paper's 99 and the 105 attempted
rows = list(csv.DictReader(open(FEAT)))
mal99 = [r for r in rows if r["category"] == "malware"]
assert len(mal99) == 99, len(mal99)
S99 = {r["sha256"] for r in mal99}
F99 = collections.Counter(fam(r["family"]) for r in mal99)
F99n = {fkey(f): n for f, n in F99.items()}
CANON = {fkey(f): f for f in F99}
S105 = {sha_of(r) for r in items(json.loads((R / "matched-selection/malware_selection.json").read_text()))}
assert S99 <= S105, "99 not inside the matched selection"
print(f"paper dataset: {len(mal99)} malware, {len(F99)} families; matched selection {len(S105)}")


def label(f):
    k = fkey(f)
    return CANON.get(k, fam(f)), (f"in 99: {F99n[k]:2d}" if k in F99n else "NEW      ")


# --- already-collected .21 runs outside the 99
collected = []  # (source, sha, family, mode, passed)
v21sel = items(json.loads((A / "v21-collection-selection/20261024T170741270302Z/malware_selection.json").read_text()))
v21val = json.loads((A / "v21-collection/20261024T194347772138Z/validation-20261024T235509430027Z.json").read_text())
for res in v21val["results"]:
    if res.get("label") != "malware":
        continue
    hit = match(v21sel, res["sample"])
    assert len(hit) == 1, (res["sample"], len(hit))
    c = hit[0]
    collected.append(("v21 collection", sha_of(c), fam(c["family"]), norm(c["mode"]), res["status"] == "accepted"))

probe_stats = collections.defaultdict(lambda: [collections.Counter(), []])
for name, att, selfile in PROBES:
    sel = items(json.loads((A / att / selfile).read_text()))
    for rj in sorted((A / att / "runs").rglob("run.json")):
        m = json.loads(rj.read_text())
        hit = match(sel, m.get("sample_name") or m.get("sample") or "")
        if not hit:
            continue  # null controls
        c = hit[0]
        w = m.get("windows")
        nwin = w if isinstance(w, int) else len(w or [])
        te = m.get("target_exec") or {}
        ok = (m.get("malware_runner_sha256") == V21 and m.get("collection_quality_status") == "accepted"
              and te.get("status") == "observed" and nwin == 40)
        collected.append((name, sha_of(c), fam(c["family"]), norm(c["mode"]), ok))
        post = te.get("post_target_lineage_raw_syscalls")
        probe_stats[(name, fam(c["family"]))][0][m.get("return_code")] += 1
        probe_stats[(name, fam(c["family"]))][1].append(post if isinstance(post, int) else -1)

# --- quarantined, classified, never run through the dataset collector
quar = []
for src, path in (("native_usable", "native_usable.json"),
                  ("net-strong (MB)", "net-strong-incoming/net_strong_candidates.json"),
                  ("net-strong (Triage)", "triage-netstrong/triage_netstrong_candidates.json"),
                  ("autoscan", "autoscan-incoming/autoscan_candidates.json")):
    for c in items(json.loads((R / path).read_text())):
        quar.append((src, sha_of(c), fam(c["family"]), norm(c["mode"])))
zig_modes = collections.Counter()
for p in sorted((R / "ziggy-incoming").iterdir()):
    if p.is_file():
        b = p.read_bytes()
        md = elf_mode(b)
        zig_modes[md] += 1
        quar.append(("ziggy (URLhaus/MB)", hashlib.sha256(b).hexdigest(), "Tsunami/Kaiten (unverified)", md))

# --- report
seen = set(S105)
print("\n== already collected with the same .21 collector, not in the 99 (deduped)")
print("   passed = v21 audit accepted; probes: runner .21 + quality accepted + exec observed + 40 windows")
by = collections.defaultdict(lambda: [0, 0, set(), set()])
for src, sha, f, md, ok in collected:
    if sha in seen:
        continue
    seen.add(sha)
    e = by[fkey(f)]
    e[0] += 1
    e[1] += ok
    e[2].add(md)
    e[3].add(src)
tot = [0, 0]
for k, (n, ok, mds, srcs) in sorted(by.items(), key=lambda kv: (-kv[1][1], kv[0])):
    name, tag = label(k)
    print(f"  {tag} {name:14s} runs {n:3d}  passed {ok:3d}  {','.join(sorted(mds)):30s} {'; '.join(sorted(srcs))}")
    tot[0] += n
    tot[1] += ok
print(f"  total runs {tot[0]}, passed {tot[1]}")

print("\n== probe runs: exit codes and post-target system calls")
for (name, f), (rc, post) in sorted(probe_stats.items()):
    print(f"  {name:14s} {f:13s} rc {dict(rc)}  post-target calls min/median/max "
          f"{min(post)}/{int(statistics.median(post))}/{max(post)}")

print("\n== quarantined, native, never run through the dataset collector (deduped against all above)")
q = collections.defaultdict(lambda: [0, collections.Counter(), set()])
dropped = collections.Counter()
for src, sha, f, md in quar:
    if not md.startswith(("amd64", "i386")):
        dropped[src] += 1
        continue
    if sha in seen:
        continue
    seen.add(sha)
    e = q[fkey(f)]
    e[0] += 1
    e[1][md] += 1
    e[2].add(src)
qt = 0
for k, (n, mds, srcs) in sorted(q.items(), key=lambda kv: (-kv[1][0], kv[0])):
    name, tag = label(k)
    print(f"  {tag} {name:28s} {n:4d}  {dict(mds)}  {'; '.join(sorted(srcs))}")
    qt += n
print(f"  total {qt}; not native (dropped): {dict(dropped)}")
print("  ziggy header modes:", dict(zig_modes))
print("\n99 per family:", dict(sorted(F99.items(), key=lambda kv: -kv[1])))
