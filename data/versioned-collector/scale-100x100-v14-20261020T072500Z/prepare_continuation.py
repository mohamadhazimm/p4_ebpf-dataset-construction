#!/usr/bin/env python3
import csv
import hashlib
import json
from pathlib import Path

EXPERIMENT = Path(__file__).resolve().parent
STUDY = EXPERIMENT.parents[2]
DATA = STUDY / "data"
ORIGINAL_MANIFEST = EXPERIMENT / "manifests/malware-100.txt"
ORIGINAL_HASH = "bf0c7b1b892cd28f9a8b7b2c4d5eee784b1b34c65d2cb1daa670ccfcb9832a6a"
FAILED_SAMPLE = "3fafbee7a3b7259db3cb16b1ea7ebf7c12a61ced08e8f71c5e85258090d8b6cf.zip"
REPLACEMENT_SAMPLE = "400522dc52473e2a9d38098c49643a833ac5da6f54a39e0c5336c2a301147daf.zip"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sha256(ORIGINAL_MANIFEST) != ORIGINAL_HASH:
        raise SystemExit("Original malware manifest hash mismatch")
    if (EXPERIMENT / "continuation_selection.json").exists():
        raise SystemExit("Continuation selection already exists; refusing to overwrite")

    original = ORIGINAL_MANIFEST.read_text(encoding="utf-8").splitlines()
    if len(original) != 100 or len(set(original)) != 100 or original.count(FAILED_SAMPLE) != 1:
        raise SystemExit("Original manifest does not have the expected unique 100 samples")
    if REPLACEMENT_SAMPLE in original:
        raise SystemExit("Replacement artifact is already in the original manifest")

    cohort_path = DATA / "malware/full-cohort-323/cohort_manifest.csv"
    with cohort_path.open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    by_name = {row["sample_artifact"]: row for row in rows}
    failed = by_name.get(FAILED_SAMPLE)
    replacement = by_name.get(REPLACEMENT_SAMPLE)
    if not failed or not replacement or failed["group_id"] != replacement["group_id"]:
        raise SystemExit("Replacement is not a verified same-family cohort artifact")

    source = DATA / "malware/full-cohort-323/samples"
    replacement_path = source / REPLACEMENT_SAMPLE
    if not replacement_path.is_file():
        raise SystemExit("Replacement artifact is missing from the staged source")

    continuation = [REPLACEMENT_SAMPLE if name == FAILED_SAMPLE else name for name in original]
    if len(continuation) != 100 or len(set(continuation)) != 100:
        raise SystemExit("Continuation manifest is not 100 unique artifacts")
    continuation_path = EXPERIMENT / "manifests/malware-100-continuation.txt"
    continuation_path.write_text("".join(f"{name}\n" for name in continuation), encoding="utf-8")

    record = {
        "reason": "The selected JackSkid artifact failed archive creation after six guest tar retries in this run and has repeated archive failures in prior documented attempts. Preserve its failed output and replace it in the continuation list.",
        "original_manifest": "manifests/malware-100.txt",
        "original_manifest_sha256": ORIGINAL_HASH,
        "replaced_sample": {
            "sample": FAILED_SAMPLE,
            "family": failed["group_id"],
            "attempt_status": "output_archive_failed",
            "attempt_run_id": "run_20261020T085415Z",
            "partial_telemetry_counted": False,
        },
        "replacement_sample": {
            "sample": REPLACEMENT_SAMPLE,
            "family": replacement["group_id"],
            "sha256": sha256(replacement_path),
            "previously_in_original_manifest": False,
        },
        "continuation_manifest": "manifests/malware-100-continuation.txt",
        "continuation_manifest_sha256": sha256(continuation_path),
        "sample_count": len(continuation),
        "unique_sample_count": len(set(continuation)),
        "policy": "All other original entries remain in order. The original 100-entry manifest is unchanged. Use --resume with the same output directory so valid completed records are skipped.",
    }
    (EXPERIMENT / "continuation_selection.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print("Prepared a 100-unique continuation manifest.")
    print("Removed persistent archive failure:", FAILED_SAMPLE)
    print("Same-family replacement:", REPLACEMENT_SAMPLE)
    print("Manifest SHA-256:", sha256(continuation_path))


if __name__ == "__main__":
    main()
