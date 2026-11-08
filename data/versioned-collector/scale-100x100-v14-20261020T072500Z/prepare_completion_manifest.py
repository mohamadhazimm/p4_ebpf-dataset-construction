#!/usr/bin/env python3
import csv
import hashlib
import json
from pathlib import Path

EXPERIMENT = Path(__file__).resolve().parent
STUDY = EXPERIMENT.parents[2]
DATA = STUDY / "data"
CURRENT_MANIFEST = EXPERIMENT / "manifests/malware-100-continuation.txt"
OUTPUT_ROOT = EXPERIMENT / "runs/malware"
FAILED_SAMPLE = "4dc06ecee904b9165fa699b026045c1b6408cc7061df3d2a7bc2b7b4f0879f4d.zip"
REPLACEMENT_SAMPLE = "8c9ff5d82f986b9c86ff8d1a26f83a9c41e50a5f0671e2b79e13c663afb1ba20.zip"
SCHEMA = "2026-10-19.14"
RUNNER_HASH = "b366c337481e82e3118038ac966f3b35d5a5195123213a763a5ba2a8b1bf09d9"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    selection_path = EXPERIMENT / "completion_selection.json"
    if selection_path.exists():
        raise SystemExit("Completion selection already exists; refusing to overwrite")
    current = CURRENT_MANIFEST.read_text(encoding="utf-8").splitlines()
    if len(current) != 100 or len(set(current)) != 100 or current.count(FAILED_SAMPLE) != 1:
        raise SystemExit("Current continuation manifest is not the expected 100-item list")
    if REPLACEMENT_SAMPLE in current:
        raise SystemExit("Replacement sample is already in the current manifest")

    cohort_path = DATA / "malware/full-cohort-323/cohort_manifest.csv"
    with cohort_path.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    by_name = {row["sample_artifact"]: row for row in rows}
    failed = by_name.get(FAILED_SAMPLE)
    replacement = by_name.get(REPLACEMENT_SAMPLE)
    if not failed or not replacement:
        raise SystemExit("Failed or replacement artifact is absent from the frozen cohort")
    if failed["group_id"] != "malware_signature::LockBit":
        raise SystemExit("Expected failed artifact is not the recorded LockBit sample")
    if replacement["group_id"] != "malware_signature::Katana":
        raise SystemExit("Replacement family is not the selected Katana group")

    source_path = DATA / "malware/full-cohort-323/samples" / REPLACEMENT_SAMPLE
    if not source_path.is_file():
        raise SystemExit("Replacement artifact is missing")

    completed = [name for name in current if name != FAILED_SAMPLE]
    for name in completed:
        sample_dir = OUTPUT_ROOT / name
        host_log = sample_dir / "host_run.txt"
        archive = sample_dir / "output.tgz"
        run_jsons = list((sample_dir / "output").rglob("run.json"))
        if not host_log.is_file() or "status=completed" not in host_log.read_text(errors="replace").splitlines():
            raise SystemExit(f"Existing item is not completed: {name}")
        if not archive.is_file() or archive.stat().st_size == 0 or len(run_jsons) != 1:
            raise SystemExit(f"Existing item lacks a unique archived run: {name}")
        metadata = json.loads(run_jsons[0].read_text(encoding="utf-8"))
        features = [field for group in metadata.get("telemetry_feature_groups", {}).values() for field in group]
        if (
            metadata.get("telemetry_schema_version") != SCHEMA
            or metadata.get("malware_runner_sha256") != RUNNER_HASH
            or len(features) != 169
        ):
            raise SystemExit(f"Existing item has a provenance/schema mismatch: {name}")

    if (OUTPUT_ROOT / REPLACEMENT_SAMPLE).exists():
        raise SystemExit("Replacement already has an output directory; refusing to repeat it")

    completed_manifest = [REPLACEMENT_SAMPLE if name == FAILED_SAMPLE else name for name in current]
    if len(set(completed_manifest)) != 100:
        raise SystemExit("Completion manifest contains duplicate artifacts")
    manifest_path = EXPERIMENT / "manifests/malware-100-completion.txt"
    manifest_path.write_text("".join(f"{name}\n" for name in completed_manifest), encoding="utf-8")
    record = {
        "reason": "The LockBit artifact failed to produce run.json on two attempts; its partial outputs remain preserved. The source cohort has no unselected LockBit alternative, so an unselected artifact from a family tied for the minimum selected count is used to complete the 100-item cohort.",
        "prior_manifest": "manifests/malware-100-continuation.txt",
        "replaced_sample": {
            "sample": FAILED_SAMPLE,
            "family": failed["group_id"],
            "status": "runner_failed",
            "attempts": 2,
            "usable_run_json": False,
            "backup": "failed-attempts/lockbit-before-resume",
        },
        "replacement_sample": {
            "sample": REPLACEMENT_SAMPLE,
            "family": replacement["group_id"],
            "sha256": sha256(source_path),
            "previously_completed_in_this_run": False,
        },
        "completion_manifest": "manifests/malware-100-completion.txt",
        "completion_manifest_sha256": sha256(manifest_path),
        "sample_count": 100,
        "unique_sample_count": len(set(completed_manifest)),
        "verified_completed_outputs_to_skip": len(completed),
        "new_samples_to_run": 1,
        "selection_note": "The replacement raises Katana from six to seven selected artifacts, matching the current maximum family count of seven.",
    }
    selection_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print("Prepared the 100-item completion manifest.")
    print("Verified completed outputs to skip:", len(completed))
    print("Replacement:", REPLACEMENT_SAMPLE, replacement["group_id"])
    print("Manifest SHA-256:", sha256(manifest_path))


if __name__ == "__main__":
    main()
