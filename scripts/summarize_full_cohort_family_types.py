#!/usr/bin/env python3
"""Summarize family-type labels for the 323-sample malware cohort."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
KNOWN_COHORT = "known_224"
TRIAGE_COHORT = "triage_unknown_x86_64_99"
FIELDS = ("family_type", "sample_count", "percent_of_total")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def sample_hash(value: str) -> str:
    candidate = Path(value).name.removesuffix(".zip").lower()
    return candidate if HASH_PATTERN.fullmatch(candidate) else ""


def rows_by_hash(rows: list[dict[str, str]], source_name: str) -> dict[str, dict[str, str]]:
    result = {}
    for row in rows:
        digest = sample_hash(row.get("sha256", ""))
        if not digest:
            continue
        if digest in result:
            raise ValueError(f"Duplicate SHA-256 in {source_name}: {digest}")
        result[digest] = row
    return result


def malwarebazaar_family_type(category: str, tags: str) -> str:
    explicit = category.strip().casefold()
    if explicit:
        return explicit

    normalized_tags = {tag.strip().casefold() for tag in tags.split(";") if tag.strip()}
    for family_type in ("ransomware", "ddos", "backdoor"):
        if family_type in normalized_tags:
            return family_type
    if normalized_tags.intersection({"botnet", "mirai", "gafgyt"}):
        return "botnet"
    return "other_or_unclassified"


def write_summary(path: Path, counts: Counter[str], total: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(path.name + ".tmp")
    try:
        with temporary_path.open("w", newline="", encoding="utf-8") as destination:
            writer = csv.DictWriter(destination, fieldnames=FIELDS)
            writer.writeheader()
            for family_type, count in sorted(counts.items()):
                writer.writerow(
                    {
                        "family_type": family_type,
                        "sample_count": count,
                        "percent_of_total": f"{count / total * 100:.2f}",
                    }
                )
            writer.writerow(
                {
                    "family_type": "TOTAL",
                    "sample_count": total,
                    "percent_of_total": "100.00",
                }
            )
        temporary_path.replace(path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "data/malware/full-cohort-323/cohort_manifest.csv",
    )
    parser.add_argument(
        "--known-inventory",
        type=Path,
        default=ROOT / "data/malware/malware_sample_source_catalog.csv",
    )
    parser.add_argument(
        "--triage-inventory",
        type=Path,
        default=ROOT / "data/malware/revision4/triage-incoming/triage_sample_inventory_20261016.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "data/malware/full-cohort-323/family_type_counts_323.csv",
    )
    args = parser.parse_args()

    try:
        manifest = read_csv(args.manifest)
        known_by_hash = rows_by_hash(read_csv(args.known_inventory), str(args.known_inventory))
        triage_by_hash = rows_by_hash(read_csv(args.triage_inventory), str(args.triage_inventory))

        cohort_by_hash: dict[str, str] = {}
        for row in manifest:
            digest = sample_hash(row.get("sample_artifact", ""))
            cohort = row.get("source_cohort", "")
            if not digest:
                raise ValueError(f"Invalid sample artifact in manifest: {row.get('sample_artifact', '')}")
            if digest in cohort_by_hash:
                raise ValueError(f"Duplicate sample hash in manifest: {digest}")
            cohort_by_hash[digest] = cohort

        known_hashes = {digest for digest, cohort in cohort_by_hash.items() if cohort == KNOWN_COHORT}
        triage_hashes = {digest for digest, cohort in cohort_by_hash.items() if cohort == TRIAGE_COHORT}
        if len(cohort_by_hash) != 323 or len(known_hashes) != 224 or len(triage_hashes) != 99:
            raise ValueError(
                f"Expected 323 unique samples (224 known, 99 Triage); found "
                f"{len(cohort_by_hash)} ({len(known_hashes)} known, {len(triage_hashes)} Triage)."
            )

        missing_known = sorted(known_hashes - set(known_by_hash))
        missing_triage = sorted(triage_hashes - set(triage_by_hash))
        if missing_known or missing_triage:
            raise ValueError(
                f"Missing classification metadata: {len(missing_known)} known, "
                f"{len(missing_triage)} Triage samples."
            )

        counts: Counter[str] = Counter()
        for digest in known_hashes:
            metadata = known_by_hash[digest]
            family_type = malwarebazaar_family_type(
                metadata.get("malwarebazaar_category", ""),
                metadata.get("malwarebazaar_tags", ""),
            )
            counts[family_type] += 1
        for digest in triage_hashes:
            metadata = triage_by_hash[digest]
            family_type = (metadata.get("category") or "").strip().casefold()
            counts[family_type or "other_or_unclassified"] += 1

        if sum(counts.values()) != len(cohort_by_hash):
            raise ValueError("Family-type counts do not sum to the cohort size.")

        output = args.output.expanduser().resolve()
        write_summary(output, counts, len(cohort_by_hash))
    except (OSError, csv.Error, ValueError) as error:
        parser.error(str(error))

    print(
        json.dumps(
            {
                "output": str(output),
                "samples": len(cohort_by_hash),
                "family_types": dict(sorted(counts.items())),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())