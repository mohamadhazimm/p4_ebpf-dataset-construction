#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STUDY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BATCH_SCRIPT="$SCRIPT_DIR/vbox_malware_batch.sh"
STAGE_SCRIPT="$SCRIPT_DIR/stage_versioned_runner_snapshot.sh"
MALWARE_STAGE_SCRIPT="$SCRIPT_DIR/stage_malware_revision4.sh"
VM_NAME="${VM_NAME:-Ubuntu-Clean-24.04}"
GUEST_USER="${GUEST_USER:-csci}"
GUEST_RUNNER="/home/$GUEST_USER/Downloads/malware_runner.py"
SCHEMA_VERSION="${SCHEMA_VERSION:-2026-10-17.2}"
FEATURE_COUNT=169
MALWARE_BASELINE="clean-malware-training-staged-20261017"
BENIGN_BASELINE="clean-benign-expanded-20261017"
MALWARE_SNAPSHOT="${MALWARE_SNAPSHOT:-clean-versioned-telemetry-20261017.2-malware-full}"
BENIGN_SNAPSHOT="${BENIGN_SNAPSHOT:-clean-versioned-telemetry-20261017.2-benign}"
COMMON_LAUNCH_WRAPPER="${COMMON_LAUNCH_WRAPPER:-0}"
FIXED_OBSERVATION="${FIXED_OBSERVATION:-0}"
RESUME_RUN="${RESUME_RUN:-0}"
MALWARE_TRAIN_GUEST="/home/$GUEST_USER/Downloads/model training"
MALWARE_TEST_GUEST="/home/$GUEST_USER/Downloads/malware_full_cohort_323"
BENIGN_TRAIN_GUEST="/home/$GUEST_USER/Downloads/benign-expanded/training/workload_scripts"
BENIGN_TEST_GUEST="/home/$GUEST_USER/Downloads/benign-expanded/validation/workload_scripts"
MALWARE_TRAIN_SOURCE="/tmp/malware-training-535-sample-list-20261017.txt"
MALWARE_TEST_SOURCE="$STUDY_DIR/data/malware/full-cohort-323/cohort_manifest.csv"
MALWARE_ARCHIVE_SOURCE="$STUDY_DIR/data/malware/full-cohort-323/samples"
BENIGN_TRAIN_SOURCE="$STUDY_DIR/data/benign/revision4/expanded/training/sample_list.txt"
BENIGN_TEST_SOURCE="$STUDY_DIR/data/benign/revision4/expanded/validation/sample_list.txt"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_ROOT="$STUDY_DIR/data/versioned-collector/telemetry-$SCHEMA_VERSION-$RUN_ID"
RUNNER_SOURCE="$STUDY_DIR/src/malware_runner.py"
RUNNER_SHA256="$(sha256sum "$RUNNER_SOURCE" | awk '{print $1}')"
OVERALL_FAILURE=0
FATAL_FAILURE=0

die() {
    echo "ERROR: $*" >&2
    exit 1
}

[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || die "RUN_ID contains unsupported characters"
[[ -s "$MALWARE_TRAIN_SOURCE" ]] || die "Missing 535-sample source list: $MALWARE_TRAIN_SOURCE"
[[ -s "$MALWARE_TEST_SOURCE" ]] || die "Missing 323-sample cohort manifest: $MALWARE_TEST_SOURCE"
[[ -s "$BENIGN_TRAIN_SOURCE" && -s "$BENIGN_TEST_SOURCE" ]] || die "Benign cohort sample lists are missing"
[[ "$COMMON_LAUNCH_WRAPPER" =~ ^[01]$ ]] || die "COMMON_LAUNCH_WRAPPER must be 0 or 1"
[[ "$FIXED_OBSERVATION" =~ ^[01]$ ]] || die "FIXED_OBSERVATION must be 0 or 1"
[[ "$RESUME_RUN" =~ ^[01]$ ]] || die "RESUME_RUN must be 0 or 1"
if [[ -e "$RUN_ROOT" ]]; then
    [[ "$RESUME_RUN" -eq 1 ]] || die "Refusing to mix with an existing run: $RUN_ROOT"
    [[ -s "$RUN_ROOT/collection_manifest.json" ]] || die "Cannot resume without the frozen collection manifest"
else
    [[ "$RESUME_RUN" -eq 0 ]] || die "Cannot resume a run root that does not exist: $RUN_ROOT"
fi
command -v sha256sum >/dev/null 2>&1 || die "sha256sum was not found"
mkdir -p "$RUN_ROOT/manifests" "$RUN_ROOT/logs" "$RUN_ROOT/runs" "$RUN_ROOT/summaries"

python3 - "$RUN_ROOT" "$MALWARE_TRAIN_SOURCE" "$MALWARE_TEST_SOURCE" \
    "$MALWARE_ARCHIVE_SOURCE" "$BENIGN_TRAIN_SOURCE" "$BENIGN_TEST_SOURCE" "$RUNNER_SHA256" \
    "$MALWARE_SNAPSHOT" "$BENIGN_SNAPSHOT" "$SCHEMA_VERSION" \
    "$COMMON_LAUNCH_WRAPPER" "$FIXED_OBSERVATION" <<'PY'
import csv
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
train_source, test_source, archive_source, benign_train_source, benign_test_source = map(Path, sys.argv[2:7])
runner_hash, malware_snapshot, benign_snapshot, schema_version, common_wrapper, fixed_observation = sys.argv[7:]

def read_lines(path):
    return [line.strip().replace("\r", "") for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

malware_train = read_lines(train_source)
with test_source.open(newline="", encoding="utf-8-sig") as source:
    malware_test = [row["sample_artifact"].strip() for row in csv.DictReader(source)]
benign_train = read_lines(benign_train_source)
benign_test = read_lines(benign_test_source)

cohorts = {
    "malware-training-535": (malware_train, 535, train_source),
    "malware-holdout-323": (malware_test, 323, test_source),
    "benign-training-500": (benign_train, 500, benign_train_source),
    "benign-validation-138": (benign_test, 138, benign_test_source),
}
for name, (samples, expected, source) in cohorts.items():
    if len(samples) != expected or len(set(samples)) != expected:
        raise SystemExit(f"{name} expected {expected} unique samples; found {len(samples)}")
    if any(Path(sample).name != sample or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in sample) for sample in samples):
        raise SystemExit(f"{name} contains an invalid guest sample basename")
    target = root / "manifests" / f"{name}.txt"
    manifest_text = "".join(sample + "\n" for sample in samples)
    if target.exists():
        if target.read_text(encoding="ascii") != manifest_text:
            raise SystemExit(f"Frozen manifest changed while resuming: {target}")
    else:
        target.write_text(manifest_text, encoding="ascii")

if set(malware_train) & set(malware_test):
    raise SystemExit("Malware training and holdout lists overlap")

def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

archive_stage_dir = root / "staging" / "malware-holdout-323"
archive_stage_dir.mkdir(parents=True, exist_ok=True)
archive_manifest = []
for archive_name in malware_test:
    source_archive = archive_source / archive_name
    if not source_archive.is_file():
        raise SystemExit(f"Missing holdout archive: {source_archive}")
    sample_hash = Path(archive_name).stem
    if len(sample_hash) != 64 or Path(archive_name).suffix != ".zip":
        raise SystemExit(f"Invalid holdout archive name: {archive_name}")
    staged_archive = archive_stage_dir / archive_name
    shutil.copy2(source_archive, staged_archive)
    archive_manifest.append({
        "query_status": "downloaded",
        "sha256": sample_hash,
        "archive": archive_name,
        "archive_sha256": sha256(staged_archive),
    })
archive_manifest_path = archive_stage_dir / "manifest.jsonl"
archive_manifest_text = "".join(json.dumps(row) + "\n" for row in archive_manifest)
if archive_manifest_path.exists():
    if archive_manifest_path.read_text(encoding="utf-8") != archive_manifest_text:
        raise SystemExit("Frozen malware archive manifest changed while resuming")
else:
    archive_manifest_path.write_text(archive_manifest_text, encoding="utf-8")

manifest = {
    "run_id": root.name,
    "created_at_utc": datetime.now(timezone.utc).isoformat(),
    "telemetry_schema_version": schema_version,
    "feature_count": 169,
    "malware_runner_sha256": runner_hash,
    "collection_controls": {
        "common_launch_wrapper": common_wrapper == "1",
        "fixed_observation": fixed_observation == "1",
    },
    "snapshots": {
        "malware": {"baseline": "clean-malware-training-staged-20261017", "versioned": malware_snapshot},
        "benign": {"baseline": "clean-benign-expanded-20261017", "versioned": benign_snapshot},
    },
    "malware_holdout_archive_stage": {
        "archive_count": len(archive_manifest),
        "source_directory": str(archive_source),
        "staged_manifest": "staging/malware-holdout-323/manifest.jsonl",
        "staged_manifest_sha256": sha256(archive_stage_dir / "manifest.jsonl"),
    },
    "cohorts": {
        name: {
            "expected_samples": len(samples),
            "manifest": f"manifests/{name}.txt",
            "manifest_sha256": sha256(root / "manifests" / f"{name}.txt"),
            "source": str(source),
            "source_sha256": sha256(source),
        }
        for name, (samples, _, source) in cohorts.items()
    },
}
collection_manifest_path = root / "collection_manifest.json"
if collection_manifest_path.exists():
    existing_manifest = json.loads(collection_manifest_path.read_text(encoding="utf-8"))
    for key, value in manifest.items():
        if key != "created_at_utc" and existing_manifest.get(key) != value:
            raise SystemExit(f"Collection provenance changed while resuming: {key}")
else:
    collection_manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print("Frozen cohort manifests: malware 535 + 323, benign 500 + 138")
print("Malware training/holdout overlap: 0")
PY

echo "Isolated output root: $RUN_ROOT"
echo "Runner SHA-256: $RUNNER_SHA256"

stage_snapshot() {
    local cohort="$1" baseline="$2" snapshot="$3"
    if VBoxManage snapshot "$VM_NAME" list --machinereadable 2>/dev/null | grep -Fq "=\"$snapshot\""; then
        echo "Reusing existing versioned snapshot: $snapshot"
        return 0
    fi
    if [[ "$cohort" == "malware" ]]; then
        bash "$MALWARE_STAGE_SCRIPT" --vm "$VM_NAME" --guest-user "$GUEST_USER" \
            --baseline-snapshot "$baseline" --new-snapshot "$snapshot" \
            --manifest "$RUN_ROOT/staging/malware-holdout-323/manifest.jsonl" \
            --host-runner "$RUNNER_SOURCE" --guest-runner "$GUEST_RUNNER" \
            --schema-version "$SCHEMA_VERSION" \
            --guest-sample-dir "$MALWARE_TEST_GUEST" \
            --guest-stage-dir "/tmp/versioned-malware-stage-$RUN_ID" \
            2>&1 | tee "$RUN_ROOT/logs/stage-$cohort.log"
    else
        bash "$STAGE_SCRIPT" --vm "$VM_NAME" --guest-user "$GUEST_USER" \
            --baseline-snapshot "$baseline" --new-snapshot "$snapshot" \
            --guest-runner "$GUEST_RUNNER" 2>&1 | tee "$RUN_ROOT/logs/stage-$cohort.log"
    fi
}

stage_snapshot malware "$MALWARE_BASELINE" "$MALWARE_SNAPSHOT"
stage_snapshot benign "$BENIGN_BASELINE" "$BENIGN_SNAPSHOT"

dry_run_cohort() {
    local name="$1" snapshot="$2" guest_dir="$3" sample_list="$4" expected="$5"
    local log="$RUN_ROOT/logs/dry-run-$name.log" validated
    local -a args=(
        --vm "$VM_NAME" --guest-user "$GUEST_USER"
        --guest-malware-dir "$guest_dir" --guest-runner "$GUEST_RUNNER"
        --snapshot "$snapshot" --output-dir "$RUN_ROOT/runs/$name"
        --sample-list "$sample_list" --dry-run
    )
    if ! bash "$BATCH_SCRIPT" "${args[@]}" >"$log" 2>&1; then
        tail -n 80 "$log" >&2
        return 1
    fi
    validated="$(grep -c '^Validated sample:' "$log" || true)"
    [[ "$validated" -eq "$expected" ]] || {
        echo "$name dry-run validated $validated samples; expected $expected" >&2
        return 1
    }
    echo "Dry-run verified $name: $validated samples, schema $SCHEMA_VERSION, runner $RUNNER_SHA256"
}

dry_run_cohort malware-training-535 "$MALWARE_SNAPSHOT" "$MALWARE_TRAIN_GUEST" \
    "$RUN_ROOT/manifests/malware-training-535.txt" 535 || die "Malware training dry-run failed; no cohort was executed"
dry_run_cohort malware-holdout-323 "$MALWARE_SNAPSHOT" "$MALWARE_TEST_GUEST" \
    "$RUN_ROOT/manifests/malware-holdout-323.txt" 323 || die "Malware holdout dry-run failed; no cohort was executed"
dry_run_cohort benign-training-500 "$BENIGN_SNAPSHOT" "$BENIGN_TRAIN_GUEST" \
    "$RUN_ROOT/manifests/benign-training-500.txt" 500 || die "Benign training dry-run failed; no cohort was executed"
dry_run_cohort benign-validation-138 "$BENIGN_SNAPSHOT" "$BENIGN_TEST_GUEST" \
    "$RUN_ROOT/manifests/benign-validation-138.txt" 138 || die "Benign validation dry-run failed; no cohort was executed"

audit_cohort() {
    local name="$1" expected="$2"
    python3 - "$RUN_ROOT" "$name" "$expected" "$SCHEMA_VERSION" "$RUNNER_SHA256" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

root, name, expected_count, version, runner_hash = sys.argv[1:]
root = Path(root)
expected_count = int(expected_count)
samples = [line.strip() for line in (root / "manifests" / f"{name}.txt").read_text(encoding="ascii").splitlines() if line.strip()]
output_root = root / "runs" / name
counts = Counter()
failures = []
unsupported = []
for sample in samples:
    run_dir = output_root / sample
    status_path = run_dir / "host_run.txt"
    if not status_path.is_file():
        counts["missing"] += 1
        failures.append(sample)
        continue
    status = next((line.split("=", 1)[1] for line in status_path.read_text(errors="replace").splitlines() if line.startswith("status=")), "missing_status")
    counts[status] += 1
    if status == "unsupported_architecture":
        unsupported.append(sample)
        continue
    if status != "completed":
        failures.append(sample)
        continue
    metadata_paths = list((run_dir / "output").rglob("run.json"))
    if not metadata_paths or not (run_dir / "output.tgz").is_file():
        counts["provenance_missing"] += 1
        failures.append(sample)
        continue
    try:
        metadata = json.loads(metadata_paths[0].read_text(encoding="utf-8"))
        groups = metadata["telemetry_feature_groups"]
        features = [field for group in groups.values() for field in group]
        fields = set(metadata["telemetry_fields"])
        valid = (
            metadata.get("telemetry_schema_version") == version
            and metadata.get("malware_runner_sha256") == runner_hash
            and len(features) == 169
            and len(features) == len(set(features))
            and set(features).issubset(fields)
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        valid = False
    if not valid:
        counts["provenance_mismatch"] += 1
        failures.append(sample)

report = {
    "cohort": name,
    "expected": expected_count,
    "sample_list_count": len(samples),
    "runner_schema_version": version,
    "runner_sha256": runner_hash,
    "status_counts": dict(counts),
    "unsupported_architecture_samples": unsupported,
    "failed_or_missing_samples": failures,
}
summary_path = root / "summaries" / f"{name}.json"
summary_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f"Audit {name}: {dict(counts)}")
if len(samples) != expected_count or failures or unsupported:
    raise SystemExit(1)
PY
}

run_cohort() {
    local name="$1" snapshot="$2" guest_dir="$3" expected="$4"
    local sample_list="$RUN_ROOT/manifests/$name.txt"
    local log="$RUN_ROOT/logs/$name.log"
    local attempt
    local -a base_args=(
        --vm "$VM_NAME" --guest-user "$GUEST_USER"
        --guest-malware-dir "$guest_dir" --guest-runner "$GUEST_RUNNER"
        --snapshot "$snapshot" --output-dir "$RUN_ROOT/runs/$name"
        --sample-list "$sample_list" --timeout 20 --window-sec 0.5
        --iface enp0s3 --ebpf
    )
    if [[ "$COMMON_LAUNCH_WRAPPER" -eq 1 ]]; then
        base_args+=(--common-launch-wrapper)
    fi
    if [[ "$FIXED_OBSERVATION" -eq 1 ]]; then
        base_args+=(--fixed-observation)
    fi
    for attempt in 1 2 3; do
        local -a args=("${base_args[@]}")
        if [[ "$RESUME_RUN" -eq 1 || "$attempt" -gt 1 ]]; then
            args+=(--resume)
        fi
        echo "Starting $name, pass $attempt/3; expected $expected samples"
        if ! bash "$BATCH_SCRIPT" "${args[@]}" 2>&1 | tee -a "$log"; then
            if grep -Fq 'Runner provenance mismatch' "$log"; then
                return 3
            fi
            echo "Batch harness failed for $name on pass $attempt" >&2
            continue
        fi
        if audit_cohort "$name" "$expected"; then
            return 0
        fi
        if grep -Fq '"provenance_mismatch":' "$RUN_ROOT/summaries/$name.json"; then
            return 3
        fi
    done
    audit_cohort "$name" "$expected" || true
    return 1
}

run_one() {
    local name="$1" snapshot="$2" guest_dir="$3" expected="$4"
    local status
    if run_cohort "$name" "$snapshot" "$guest_dir" "$expected"; then
        echo "Cohort complete: $name"
    else
        status=$?
        OVERALL_FAILURE=1
        echo "Cohort needs attention: $name (status $status); continuing with the next isolated cohort" >&2
        if [[ "$status" -eq 3 ]]; then
            FATAL_FAILURE=1
        fi
    fi
}

run_one malware-training-535 "$MALWARE_SNAPSHOT" "$MALWARE_TRAIN_GUEST" 535
if [[ "$FATAL_FAILURE" -eq 0 ]]; then
    run_one malware-holdout-323 "$MALWARE_SNAPSHOT" "$MALWARE_TEST_GUEST" 323
fi
if [[ "$FATAL_FAILURE" -eq 0 ]]; then
    run_one benign-training-500 "$BENIGN_SNAPSHOT" "$BENIGN_TRAIN_GUEST" 500
fi
if [[ "$FATAL_FAILURE" -eq 0 ]]; then
    run_one benign-validation-138 "$BENIGN_SNAPSHOT" "$BENIGN_TEST_GUEST" 138
fi

python3 - "$RUN_ROOT" "$OVERALL_FAILURE" "$SCHEMA_VERSION" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
failed = bool(int(sys.argv[2]))
schema_version = sys.argv[3]
reports = {}
for path in sorted((root / "summaries").glob("*.json")):
    reports[path.stem] = json.loads(path.read_text(encoding="utf-8"))
summary = {
    "run_id": root.name,
    "finished_at_utc": datetime.now(timezone.utc).isoformat(),
    "telemetry_schema_version": schema_version,
    "status": "needs_attention" if failed or len(reports) != 4 else "complete",
    "cohorts": reports,
}
(root / "collection_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print("Collection summary:", root / "collection_summary.json")
PY

echo "Versioned outputs and logs: $RUN_ROOT"
[[ "$OVERALL_FAILURE" -eq 0 ]] || exit 1