"""Deterministic malware selection for the .21 150+150 quiet collection (step 3, local only).

Builds a 150-malware selection across the three strict native modes with the user-chosen mix
(amd64-dynamic 12 training-only, amd64-static 69, i386-static 69), at most 10 per family per mode,
round-robin across families, outcome-independent, DDoSAgent globally excluded, matched45's 45 identities
not reused, and a family-held-out (~70/30) split with validation drawn only from the two static modes.

Candidate sources: the 323-sample cohort (AES zips, already a usable transport) and the recovered 535
originals (archive or raw-ELF; raw-ELF needs wrapping at packaging time). Dedup is by ELF member sha256,
preferring an already-usable AES-zip source. The script writes a selection manifest to disk and prints
ONLY aggregate counts per (mode, family, split) -- never per-sample malware records.

No VM operation, no sample execution, no model fit. Run with /usr/bin/python3 -I from any directory.
"""

import argparse
import csv
import hashlib
import json
import random
import struct
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
COHORT = STUDY / "data/malware/full-cohort-323"
LABELS = STUDY / "data/malware/revision4/training521_holdout461_20261017/malware_hash_labels.csv"
RECOVERED = ROOT / "source-recovery/20261022T055952526099Z/source_verification.json"
MATCHED = ROOT / "matched45-readiness/20261022T072823231146Z/manifest.json"
OUT_DIR = ROOT / "v21-collection-selection"

STRICT = ("native_amd64_dynamic", "native_amd64_static", "native_i386_static")
TARGET = {"native_amd64_dynamic": 12, "native_amd64_static": 69, "native_i386_static": 69}
TRAINING_ONLY = {"native_amd64_dynamic"}
FAMILY_CAP = 10
SEED = 42
VALIDATION_FRACTION = 0.30
EXCLUDE_FAMILIES = {"DDoSAgent", "unassigned", "UNLABELED", ""}


def norm_family(fam):
    return {"flylegitbot": "FlyLegitBot"}.get((fam or "").lower(), (fam or "").strip())


def elf_mode(data):
    """Return (mode, little_endian) using ELF + program-header inspection; mode is '' if not strict native."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return "", None
    ei_class, ei_data = data[4], data[5]
    end = "<" if ei_data == 1 else ">"
    e_machine = struct.unpack(end + "H", data[18:20])[0]
    is64 = ei_class == 2
    if is64:
        e_phoff = struct.unpack(end + "Q", data[32:40])[0]
        e_phentsize = struct.unpack(end + "H", data[54:56])[0]
        e_phnum = struct.unpack(end + "H", data[56:58])[0]
    else:
        e_phoff = struct.unpack(end + "I", data[28:32])[0]
        e_phentsize = struct.unpack(end + "H", data[42:44])[0]
        e_phnum = struct.unpack(end + "H", data[44:46])[0]
    interp = False
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 4 > len(data):
            break
        if struct.unpack(end + "I", data[off:off + 4])[0] == 3:  # PT_INTERP
            interp = True
    linkage = "dynamic" if interp else "static"
    if e_machine == 62 and ei_class == 2:
        return "native_amd64_%s" % linkage, ei_data == 1
    if e_machine == 3 and ei_class == 1:
        return "native_i386_%s" % linkage, ei_data == 1
    return "", ei_data == 1


def load_labels():
    labels = {}
    with LABELS.open() as handle:
        for row in csv.DictReader(handle):
            labels[row["sha256"].lower()] = norm_family(row["family_label"])
    return labels


def cohort_families():
    families = {}
    with (COHORT / "cohort_manifest.csv").open() as handle:
        for row in csv.DictReader(handle):
            families[row["sample_artifact"]] = norm_family(
                (row.get("group_id") or "").replace("malware_signature::", ""))
    return families


def extract_member(path):
    done = subprocess.run(["7z", "x", "-so", "-pinfected", str(path)],
                          capture_output=True, timeout=120)
    return done.stdout if done.returncode == 0 else None


def build_candidates(labels):
    """member_sha256 -> candidate dict, preferring an already-usable AES-zip transport."""
    candidates = {}
    # 323-sample cohort: AES zips, already a usable transport; member hash == stem.
    families = cohort_families()
    for archive in sorted((COHORT / "samples").glob("*.zip")):
        data = extract_member(archive)
        if data is None:
            continue
        member = hashlib.sha256(data).hexdigest()
        if member != archive.stem:
            continue
        mode, _le = elf_mode(data)
        if mode not in STRICT:
            continue
        fam = families.get(archive.name) or labels.get(member) or ""
        candidates[member] = {
            "member_sha256": member, "mode": mode, "family": norm_family(fam),
            "source_path": str(archive.resolve().relative_to(STUDY)),
            "source_format": "aes_zip", "transport_ready": True}
    # recovered 535 originals: archive or raw_elf; do not overwrite a usable 323 zip.
    recovered = json.loads(RECOVERED.read_text())["sources"]
    for src in recovered:
        if src["mode"] not in STRICT or not src.get("source_member_verified"):
            continue
        member = src["member_sha256"].lower()
        fam = norm_family(labels.get(member) or "")
        entry = {
            "member_sha256": member, "mode": src["mode"], "family": fam,
            "source_path": src["source_archive_path"],
            "source_format": src["source_format"],
            "transport_ready": src["source_format"] == "archive"}
        if member not in candidates:
            candidates[member] = entry
        elif not candidates[member]["family"] and fam:
            candidates[member]["family"] = fam
    return candidates


def round_robin_select(records, count):
    by_family = defaultdict(list)
    for record in sorted(records, key=lambda item: item["member_sha256"]):
        by_family[record["family"]].append(record)
    capped = {fam: items[:FAMILY_CAP] for fam, items in by_family.items()}
    families = sorted(capped)
    selected, exhausted = [], False
    while len(selected) < count and not exhausted:
        exhausted = True
        for fam in families:
            if capped[fam] and len(selected) < count:
                selected.append(capped[fam].pop(0))
                exhausted = False
    return selected


def holdout_split(selected):
    """Whole families to validation (static modes only) until ~VALIDATION_FRACTION per static mode."""
    generator = random.Random(SEED)
    for case in selected:
        case["split"] = "training"
    for mode in STRICT:
        if mode in TRAINING_ONLY:
            continue
        mode_cases = [c for c in selected if c["mode"] == mode]
        counts = Counter(c["family"] for c in mode_cases)
        target = round(len(mode_cases) * VALIDATION_FRACTION)
        families = sorted(counts)
        generator.shuffle(families)
        chosen, total = [], 0
        for fam in families:
            if total >= target:
                break
            if total + counts[fam] <= target + FAMILY_CAP // 2 and len(chosen) < len(families) - 1:
                chosen.append(fam)
                total += counts[fam]
        validation = set(chosen)
        for case in mode_cases:
            if case["family"] in validation:
                case["split"] = "validation"
    return selected


def select():
    labels = load_labels()
    excluded = {case["sha256"].lower() for case in json.loads(MATCHED.read_text())["cases"]
                if case["label"] == "malware"}
    candidates = build_candidates(labels)
    pool = [c for c in candidates.values()
            if c["family"] not in EXCLUDE_FAMILIES and c["member_sha256"] not in excluded]
    selected = []
    shortfalls = {}
    for mode in STRICT:
        mode_pool = [c for c in pool if c["mode"] == mode]
        picked = round_robin_select(mode_pool, TARGET[mode])
        if len(picked) < TARGET[mode]:
            shortfalls[mode] = {"wanted": TARGET[mode], "available": len(picked)}
        selected.extend(picked)
    selected = holdout_split(selected)
    for position, case in enumerate(sorted(selected, key=lambda c: (c["mode"], c["family"], c["member_sha256"])), 1):
        case["position"] = position
    return selected, shortfalls


def summarize(selected):
    by_mode_split = Counter((c["mode"], c["split"]) for c in selected)
    by_mode_family_split = Counter((c["mode"], c["family"], c["split"]) for c in selected)
    ready = Counter((c["mode"], c["transport_ready"]) for c in selected)
    return {"total": len(selected),
            "by_mode_split": {f"{m}/{s}": n for (m, s), n in sorted(by_mode_split.items())},
            "by_mode_family_split": {f"{m}/{f}/{s}": n for (m, f, s), n in sorted(by_mode_family_split.items())},
            "transport_ready_by_mode": {f"{m}/{'ready' if r else 'needs_wrap'}": n for (m, r), n in sorted(ready.items())},
            "families_per_mode": {m: len({c["family"] for c in selected if c["mode"] == m}) for m in STRICT},
            "validation_families_per_mode": {
                m: sorted({c["family"] for c in selected if c["mode"] == m and c["split"] == "validation"})
                for m in STRICT}}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="Write the selection manifest to disk")
    args = parser.parse_args()
    selected, shortfalls = select()
    summary = summarize(selected)
    summary["shortfalls"] = shortfalls
    summary["seed"] = SEED
    summary["generated_utc"] = datetime.now(timezone.utc).isoformat()
    if args.write:
        OUT_DIR.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        attempt = OUT_DIR / stamp
        attempt.mkdir()
        manifest = {"format": "v21-malware-selection-v1", "seed": SEED, "targets": TARGET,
                    "training_only_modes": sorted(TRAINING_ONLY), "family_cap": FAMILY_CAP,
                    "validation_fraction": VALIDATION_FRACTION, "excluded_families": sorted(EXCLUDE_FAMILIES),
                    "matched45_identities_excluded": True, "cases": selected, "summary": summary}
        (attempt / "malware_selection.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        summary["written"] = str(attempt / "malware_selection.json")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
