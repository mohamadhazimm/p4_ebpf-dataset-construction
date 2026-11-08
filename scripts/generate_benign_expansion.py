#!/usr/bin/env python3
"""Generate deterministic, package-group-disjoint benign workload cohorts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path


STUDY_DIR = Path(__file__).resolve().parents[1]
TRAINING_COUNT = 500
VALIDATION_COUNT = 138
VALIDATION_PACKAGES = ("bzip2", "coreutils", "curl", "git", "iproute2", "procps")
RUN_ID_PATTERN = re.compile(r"(?m)^RUN_ID=\d+$")
FIXTURE_PATTERN = re.compile(r"(?m)^FIXTURE_DATA='([^']+)'$")


def read_source(source_dir: Path) -> tuple[list[str], dict[str, list[dict[str, str]]]]:
    manifest_path = source_dir / "workload_manifest.csv"
    scripts_dir = source_dir / "workload_scripts"
    with manifest_path.open(newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        fieldnames = reader.fieldnames
        rows = list(reader)
    if not fieldnames or not rows:
        raise ValueError(f"Benign source manifest is empty: {manifest_path}")

    templates: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        artifact = row.get("sample_artifact", "")
        script_path = scripts_dir / artifact
        if not artifact or not script_path.is_file():
            raise ValueError(f"Manifest script is missing: {artifact}")
        script = script_path.read_text(encoding="utf-8")
        if len(RUN_ID_PATTERN.findall(script)) != 1 or len(FIXTURE_PATTERN.findall(script)) != 1:
            raise ValueError(f"Script must have one RUN_ID and fixture path: {artifact}")
        if hashlib.sha256(script.encode("utf-8")).hexdigest() != row.get("sha256", ""):
            raise ValueError(f"Script hash differs from manifest: {artifact}")
        templates[row["package"]].append(row)

    for package_rows in templates.values():
        package_rows.sort(key=lambda row: (int(row["run_index"]), row["sample_artifact"]))
    return fieldnames, templates


def distribute(total: int, packages: list[str]) -> dict[str, int]:
    quotient, remainder = divmod(total, len(packages))
    return {
        package: quotient + (index < remainder)
        for index, package in enumerate(packages)
    }


def make_split(
    split: str,
    packages: list[str],
    counts: dict[str, int],
    templates: dict[str, list[dict[str, str]]],
    source_scripts_dir: Path,
    destination_scripts_dir: Path,
    first_run_id: int,
) -> list[dict[str, str]]:
    entries = []
    run_index = 0
    destination_scripts_dir.mkdir(parents=True, mode=0o700)
    for package in packages:
        package_templates = templates[package]
        for package_index in range(counts[package]):
            template_row = package_templates[package_index % len(package_templates)]
            template_path = source_scripts_dir / template_row["sample_artifact"]
            script = template_path.read_text(encoding="utf-8")
            script, replacements = RUN_ID_PATTERN.subn(
                f"RUN_ID={first_run_id + run_index}", script
            )
            if replacements != 1:
                raise ValueError(f"Could not uniquely update RUN_ID: {template_path.name}")

            artifact = f"benign_{split}_{package}_{package_index + 1:03d}.sh"
            destination = destination_scripts_dir / artifact
            destination.write_text(script, encoding="utf-8")
            destination.chmod(0o700)
            entry = dict(template_row)
            entry.update(
                {
                    "sample_artifact": artifact,
                    "run_index": str(run_index + 1),
                    "sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
                    "split": split,
                    "template_artifact": template_row["sample_artifact"],
                    "variant": f"{template_row['variant']}_run_{package_index + 1:03d}",
                }
            )
            entries.append(entry)
            run_index += 1
    return entries


def write_split(root: Path, split: str, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    split_dir = root / split
    scripts_dir = split_dir / "workload_scripts"
    scripts_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    split_dir.chmod(0o700)
    scripts_dir.chmod(0o700)
    columns = [*fieldnames, "split", "template_artifact"]
    manifest_path = split_dir / "workload_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    manifest_path.chmod(0o600)

    sample_list = split_dir / "sample_list.txt"
    sample_list.write_text(
        "".join(f"{row['sample_artifact']}\n" for row in rows), encoding="utf-8"
    )
    sample_list.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=STUDY_DIR / "data/benign/revision3",
        help="Existing benign workload set containing workload_manifest.csv and workload_scripts/",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=STUDY_DIR / "data/benign/revision4/expanded",
    )
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()

    try:
        fieldnames, templates = read_source(args.source_dir)
        packages = sorted(templates)
        validation_packages = sorted(VALIDATION_PACKAGES)
        missing = set(validation_packages) - set(packages)
        if missing:
            raise ValueError(f"Validation packages are absent from source: {sorted(missing)}")
        training_packages = [package for package in packages if package not in validation_packages]
        training_counts = distribute(TRAINING_COUNT, training_packages)
        validation_counts = distribute(VALIDATION_COUNT, validation_packages)
        if sum(training_counts.values()) != TRAINING_COUNT:
            raise ValueError("Training allocation does not match the requested total")
        if sum(validation_counts.values()) != VALIDATION_COUNT:
            raise ValueError("Validation allocation does not match the requested total")

        print(
            f"training={TRAINING_COUNT} samples across {len(training_packages)} package groups; "
            f"validation={VALIDATION_COUNT} samples across {len(validation_packages)} groups"
        )
        print("validation packages: " + ", ".join(validation_packages))
        if args.plan_only:
            print("package_group_overlap=0; no files written")
            return 0
        if args.output_dir.exists():
            raise ValueError(f"Refusing to overwrite existing output directory: {args.output_dir}")

        args.output_dir.mkdir(parents=True, mode=0o700)
        training_rows = make_split(
            "training",
            training_packages,
            training_counts,
            templates,
            args.source_dir / "workload_scripts",
            args.output_dir / "training" / "workload_scripts",
            first_run_id=10001,
        )
        validation_rows = make_split(
            "validation",
            validation_packages,
            validation_counts,
            templates,
            args.source_dir / "workload_scripts",
            args.output_dir / "validation" / "workload_scripts",
            first_run_id=20001,
        )
        write_split(args.output_dir, "training", training_rows, fieldnames)
        write_split(args.output_dir, "validation", validation_rows, fieldnames)
        print(f"generated_training={len(training_rows)}")
        print(f"generated_validation={len(validation_rows)}")
        print(f"output_dir={args.output_dir}")
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())