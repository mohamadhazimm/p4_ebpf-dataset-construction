"""Matched-cohort MALWARE allocation (offline, no VM, no execution).

Builds a family-capped, mode-balanced, family-held-out malware selection from every NATIVE-usable source we hold
(existing recovered 535 + cohort 323 + new MalwareBazaar 91), classified by strict ELF linkage. Per the user's
decision: cap 10 per family (curbs Mirai dominance 46%->~10%); whole families are reserved for a fresh held-out
validation split (never seen in training), mixing new and established families and covering all three native modes.
This is a source selection + split only -- not a payload, not a guest preflight, not a collection. Exit-status /
activity matching is a benign-design + analysis-protocol concern applied later; this step fixes family/mode identity.
"""

import csv, json, subprocess, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
sys.path.insert(0, str(STUDY / "data/versioned-collector/cohort-100x100-v18-20261021"))
import prepare_selection as ps

SR = ROOT / "source-recovery/20261022T055952526099Z"
COHORT = STUDY / "data/malware/full-cohort-323/samples"
MB = STUDY / "data/malware/revision5-diverse/incoming"
LABELS = STUDY / "data/malware/revision4/training521_holdout461_20261017/malware_hash_labels.csv"
OUT = STUDY / "data/malware/revision5-diverse/matched-selection"
CAP = 10
NATIVE = {"native_x86_64_static": "amd64_static", "native_x86_64_dynamic": "amd64_dynamic",
          "native_i386_static": "i386_static"}
MODE_ORDER = ["amd64_static", "amd64_dynamic", "i386_static"]
# Whole families reserved for the fresh held-out validation split (disjoint from training). Chosen to span all
# three native modes and include new families (novelty test) plus established ones; leaves the bulk in training.
HELD_OUT = {"Tsunami", "Dofloo", "RapperBot",           # new families (never trained) -> true novelty test
            "DeskRAT", "Prometei", "Bert", "XorDDoS",   # established, mode-diverse
            "ChinaZ", "BillGates", "INC", "CatStorm"}    # established singletons


def member_bytes(path: Path):
    if path.suffix == ".zip":
        for pw in (["-pinfected"], []):
            r = subprocess.run(["7z", "x", "-so", *pw, str(path)], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=60)
            if r.returncode == 0 and r.stdout[:4] == b"\x7fELF":
                return r.stdout[:4096]
        return None
    try:
        b = path.read_bytes()[:4096]
        return b if b[:4] == b"\x7fELF" else None
    except Exception:
        return None


def mode_of(path):
    b = member_bytes(path)
    if b is None:
        return None
    try:
        return NATIVE.get(ps.inspect_elf(b, strict_linkage=True)[0])
    except Exception:
        return None


def main():
    label = {}
    for r in csv.DictReader(open(LABELS)):
        f = (r.get("family_label") or "").strip()
        if r.get("sha256") and f:
            label[r["sha256"].lower()] = f
    mb_fam = {}
    for ln in open(MB / "download_manifest.jsonl"):
        r = json.loads(ln)
        if r.get("query_status") == "downloaded":
            mb_fam[r["sha256"].lower()] = r.get("signature", "?")

    # Collect native-usable samples (dedup by sha; prefer first physical occurrence).
    seen = {}
    def add(path, fam_map, src):
        sha = path.stem.lower()
        if sha in seen:
            return
        m = mode_of(path)
        if m is None:
            return
        fam = fam_map.get(sha, "unlabeled")
        if fam == "unknown/unassigned":
            return
        seen[sha] = {"sha256": sha, "family": fam, "mode": m,
                     "source_path": str(path.resolve().relative_to(STUDY)), "source_set": src}
    for p in sorted(SR.glob("*.triage")) + sorted(SR.glob("*.zip")):
        add(p, label, "recovered")
    for p in sorted(COHORT.glob("*.zip")):
        add(p, label, "cohort323")
    for p in sorted(MB.glob("*.zip")):
        add(p, mb_fam, "malwarebazaar")

    by_family = defaultdict(lambda: defaultdict(list))
    for rec in seen.values():
        by_family[rec["family"]][rec["mode"]].append(rec)

    selected = []
    for fam in sorted(by_family):
        queues = {m: sorted(by_family[fam][m], key=lambda r: r["sha256"]) for m in MODE_ORDER}
        picks, i = [], 0
        while len(picks) < CAP and any(queues[m] for m in MODE_ORDER):
            m = MODE_ORDER[i % len(MODE_ORDER)]; i += 1
            if queues[m]:
                picks.append(queues[m].pop(0))
        split = "validation" if fam in HELD_OUT else "training"
        for rec in picks:
            rec = dict(rec, split=split)
            selected.append(rec)

    OUT.mkdir(parents=True, exist_ok=True)
    summary = {"cap_per_family": CAP, "held_out_families": sorted(HELD_OUT),
               "total": len(selected), "families": len(by_family)}
    for split in ("training", "validation"):
        s = [r for r in selected if r["split"] == split]
        summary[split] = {"total": len(s),
                          "families": sorted({r["family"] for r in s}),
                          "by_mode": {m: sum(r["mode"] == m for r in s) for m in MODE_ORDER}}
    (OUT / "malware_selection.json").write_text(json.dumps(
        {"summary": summary, "cases": selected}, indent=1, sort_keys=True))
    # print a compact family x mode x split table
    print(f"MATCHED-COHORT MALWARE ALLOCATION  cap={CAP}/family  total={len(selected)}")
    print(f"{'family':12s} {'a64s':>4} {'a64d':>4} {'i386':>4}  split")
    for fam in sorted(by_family, key=lambda f: -sum(r["family"] == f for r in selected)):
        fs = [r for r in selected if r["family"] == fam]
        if not fs:
            continue
        c = {m: sum(r["mode"] == m for r in fs) for m in MODE_ORDER}
        print(f"{fam:12s} {c['amd64_static']:4d} {c['amd64_dynamic']:4d} {c['i386_static']:4d}  "
              f"{fs[0]['split']}{' NEW' if fs[0]['source_set']=='malwarebazaar' else ''}")
    for split in ("training", "validation"):
        b = summary[split]
        print(f"\n{split}: {b['total']} malware, {len(b['families'])} families, by_mode={b['by_mode']}")
    print("held-out validation families:", summary["validation"]["families"])
    print("WROTE", OUT / "malware_selection.json")


if __name__ == "__main__":
    main()
