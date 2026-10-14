#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STUDY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BENIGN_DATA_DIR="${BENIGN_DATA_DIR:-$STUDY_DIR/data/benign}"
MALWARE_CSV="${MALWARE_CSV:-$STUDY_DIR/data/malware/combined_collector.csv}"
BENIGN_CSV="${BENIGN_CSV:-$BENIGN_DATA_DIR/combined_collector.csv}"
BENIGN_MANIFEST="${BENIGN_MANIFEST:-$BENIGN_DATA_DIR/workload_manifest.csv}"
DATASET="${DATASET:-$STUDY_DIR/data/labeled_sample_dataset.csv}"
REPORTS_DIR="${REPORTS_DIR:-$STUDY_DIR/reports}"
MODELS_DIR="${MODELS_DIR:-$STUDY_DIR/models}"

python3 "$STUDY_DIR/src/build_dataset.py" \
    --malware-csv "$MALWARE_CSV" \
    --benign-csv "$BENIGN_CSV" \
    --benign-manifest "$BENIGN_MANIFEST" \
    --output "$DATASET"

python3 "$STUDY_DIR/src/train_compare.py" \
    --dataset "$DATASET" \
    --reports-dir "$REPORTS_DIR" \
    --models-dir "$MODELS_DIR" \
    --folds 5 \
    --seed 42