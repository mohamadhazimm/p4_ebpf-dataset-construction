#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STUDY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
BATCH_SCRIPT="$SCRIPT_DIR/vbox_malware_batch.sh"
MERGER="$SCRIPT_DIR/merge_collector_csvs.py"
VM_NAME="${VM_NAME:-Ubuntu-Clean-24.04}"
GUEST_USER="${GUEST_USER:-csci}"
BENIGN_SNAPSHOT="${BENIGN_SNAPSHOT:-clean-emulated-hybrid-rf-v2-20261011}"
BENIGN_DATA_DIR="${BENIGN_DATA_DIR:-$STUDY_DIR/data/benign/revision2}"
GUEST_WORKLOAD_DIR="${GUEST_WORKLOAD_DIR:-/home/$GUEST_USER/Downloads/hybrid-rf-study/workloads}"
RUN_TAG="${RUN_TAG:-benign-v2-$(date +%Y%m%d-%H%M%S)}"
RUN_DIR="$BENIGN_DATA_DIR/runs/$RUN_TAG"
RESUME="${RESUME:-0}"

[[ -n "${VBOX_GUEST_PASSWORD:-}" ]] || {
    echo "Set VBOX_GUEST_PASSWORD in the environment." >&2
    exit 1
}

batch_args=(
    --vm "$VM_NAME"
    --guest-user "$GUEST_USER"
    --guest-malware-dir "$GUEST_WORKLOAD_DIR"
    --guest-runner "/home/$GUEST_USER/Downloads/malware_runner.py"
    --snapshot "$BENIGN_SNAPSHOT"
    --output-dir "$RUN_DIR"
    --timeout 20
    --window-sec 0.5
    --iface enp0s3
    --ebpf
)
if [[ "$RESUME" == "1" ]]; then
    batch_args+=(--resume)
fi

"$BATCH_SCRIPT" "${batch_args[@]}"

python3 "$MERGER" "$RUN_DIR" \
    --output "$BENIGN_DATA_DIR/combined_collector.csv"
printf 'Benign run output: %s\n' "$RUN_DIR"