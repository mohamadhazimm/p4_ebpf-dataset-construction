#!/usr/bin/env bash
# Benign-only execution-mode pilot. Phase a: .15 defect check; b: .16 pilot; c: .17 replication; d: .18 interface-gate smoke.
set -Eeuo pipefail

PHASE="${1:?usage: run_pilot.sh a|b}"
STUDY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN_ROOT="$STUDY_ROOT/data/versioned-collector/exec-mode-pilot-v16-20261020T204233Z"
VM_NAME="Ubuntu-Clean-24.04"
GUEST_USER="csci"
RUNNER="/home/csci/Downloads/malware_runner.py"
SAMPLE_DIR="/home/csci/Downloads/exec-mode-pilot-v16/samples"
ARGUMENTS_DIR="/home/csci/Downloads/exec-mode-pilot-v16/arguments"
BASELINE="clean-current-runner-2026-10-18.1-malware"
ORIGINAL_SNAPSHOT="clean-tls-paired-2026-10-19"
BATCH_SHA="4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f"
STAGING_SHA="5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103"
case "$PHASE" in
    a) SCHEMA="2026-10-20.15"; RUNNER_SHA="3303be05f57fb993cd1923c3a958a61706567e637b34a87e1c0c21146c4f0c56"
       NEW_SNAPSHOT="clean-exec-mode-pilot-v15-20261020T204233Z"; LIST="$RUN_ROOT/manifests/phase-a-v15.txt"
       OUTPUT="$RUN_ROOT/runs/phase-a-v15"; TIMEOUT=8 ;;
    b) SCHEMA="${PHASE_B_SCHEMA:?}"; RUNNER_SHA="${PHASE_B_RUNNER_SHA:?}"
       NEW_SNAPSHOT="clean-exec-mode-pilot-v16-20261020T204233Z"; LIST="$RUN_ROOT/manifests/pilot-v16.txt"
       OUTPUT="$RUN_ROOT/runs/pilot-v16"; TIMEOUT=20 ;;
    c) SCHEMA="${PHASE_C_SCHEMA:?}"; RUNNER_SHA="${PHASE_C_RUNNER_SHA:?}"
       NEW_SNAPSHOT="clean-exec-mode-pilot-v17-20261020T204233Z"; LIST="$RUN_ROOT/manifests/pilot-v16.txt"
       OUTPUT="$RUN_ROOT/runs/pilot-v17"; TIMEOUT=20 ;;
    d) SCHEMA="${PHASE_D_SCHEMA:?}"; RUNNER_SHA="${PHASE_D_RUNNER_SHA:?}"
       NEW_SNAPSHOT="clean-exec-mode-pilot-v18-20261020T204233Z"; LIST="$RUN_ROOT/manifests/phase-d-v18.txt"
       OUTPUT="$RUN_ROOT/runs/smoke-v18"; TIMEOUT=20 ;;
    *) echo "unknown phase" >&2; exit 2 ;;
esac
LOG_PREFIX="$RUN_ROOT/phase-$PHASE"

cd "$STUDY_ROOT"
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG_PREFIX-coordinator.log"; }

restore_original() {
    local state
    set +e
    state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable 2>/dev/null |
        awk -F= '$1 == "VMState" { gsub(/"/, "", $2); print $2; exit }')"
    [[ "$state" != "running" ]] || VBoxManage controlvm "$VM_NAME" poweroff >/dev/null 2>&1
    sleep 3
    VBoxManage snapshot "$VM_NAME" restore "$ORIGINAL_SNAPSHOT" >/dev/null 2>&1
}
cleanup() { local c=$?; trap - EXIT INT TERM; restore_original; log "exit $c; restored $ORIGINAL_SNAPSHOT"; exit "$c"; }

state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | awk -F= '$1=="VMState"{gsub(/"/,"",$2);print $2;exit}')"
[[ "$state" != "running" ]] || { echo "VM already running" >&2; exit 2; }
if pgrep -af '[v]box_malware_batch|[r]un_versioned_cohorts|[s]tage_versioned_runner|[r]un_campaign|[r]un_elf_100|[r]un_known_answer' >/dev/null; then
    echo "another collection/staging process active" >&2; exit 2
fi
nonisolated="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E '^nic[2-8]=' | grep -vc '"none"' || true)"
[[ "$nonisolated" == "0" ]] || { echo "guest has non-isolated NICs" >&2; exit 2; }
VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -qx 'nic1="intnet"' || { echo "nic1 not intnet" >&2; exit 2; }
VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -qx 'intnet1="malnet"' || { echo "nic1 not on malnet" >&2; exit 2; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$(sha256sum src/malware_runner.py | awk '{print $1}')" == "$RUNNER_SHA" ]] || { echo "runner hash changed" >&2; exit 2; }
[[ "$(sha256sum scripts/vbox_malware_batch.sh | awk '{print $1}')" == "$BATCH_SHA" ]] || { echo "batch hash changed" >&2; exit 2; }
[[ "$(sha256sum scripts/stage_versioned_runner_snapshot.sh | awk '{print $1}')" == "$STAGING_SHA" ]] || { echo "staging hash changed" >&2; exit 2; }

log "Phase $PHASE: staging $NEW_SNAPSHOT from $BASELINE (schema $SCHEMA)"
bash scripts/stage_versioned_runner_snapshot.sh --vm "$VM_NAME" --guest-user "$GUEST_USER" \
    --baseline-snapshot "$BASELINE" --new-snapshot "$NEW_SNAPSHOT" \
    --guest-runner "$RUNNER" --schema-version "$SCHEMA" \
    --guest-setup "$RUN_ROOT/setup_pilot.sh" >"$LOG_PREFIX-stage.log" 2>&1

run_batch() {
    local output_dir="$1"
    shift
    bash scripts/vbox_malware_batch.sh \
        --vm "$VM_NAME" --guest-user "$GUEST_USER" \
        --guest-malware-dir "$SAMPLE_DIR" --guest-runner "$RUNNER" \
        --snapshot "$NEW_SNAPSHOT" --output-dir "$output_dir" \
        --sample-list "$LIST" \
        --guest-arguments-dir "$ARGUMENTS_DIR" --schema-version "$SCHEMA" \
        --timeout "$TIMEOUT" --window-sec 0.5 --iface enp0s3 --ebpf \
        --fixed-observation --common-launch-wrapper "$@"
}

log "Dry-run with guest architecture diagnostics"
run_batch "$OUTPUT-dry-run" --guest-arch-diagnostics >"$LOG_PREFIX-dry-run.log" 2>&1
log "Collecting"
run_batch "$OUTPUT" >"$LOG_PREFIX-collection.log" 2>&1 || log "batch returned nonzero"
log "Collection finished"
