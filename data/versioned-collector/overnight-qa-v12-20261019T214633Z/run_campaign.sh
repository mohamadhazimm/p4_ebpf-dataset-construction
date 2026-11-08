#!/usr/bin/env bash
set -Eeuo pipefail

STUDY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
CAMPAIGN_DIR="$STUDY_ROOT/data/versioned-collector/overnight-qa-v12-20261019T214633Z"
VM_NAME="Ubuntu-Clean-24.04"
GUEST_USER="csci"
RUNNER="/home/csci/Downloads/malware_runner.py"
MALWARE_DIR="/home/csci/Downloads/malware_full_cohort_323"
BENIGN_DIR="/home/csci/Downloads/paired-elf-watchpath-pilot-20261018/benign"
WATCH_DIR="/home/csci/Downloads/paired-elf-watchpath-pilot-20261018/watch"
ARGUMENTS_ROOT="/home/csci/Downloads/overnight-qa-benign-arguments"
MALWARE_SNAPSHOT="clean-overnight-qa-v12-20261019T214633Z-malware"
BENIGN_SNAPSHOT="clean-overnight-qa-v12-20261019T214633Z-benign"
ORIGINAL_SNAPSHOT="clean-tls-paired-2026-10-19"
SCHEMA="2026-10-19.12"
FILTERED_RUNNER_SHA="e35403e32b2cb410b17843135fa6a12e2fe5c52eb81204d2097f7a42dca9007b"
BATCH_SHA="2b055ccdb8528b498457a5c621dc228d9569229d0284928982964df1ddccc359"
STAGING_SHA="5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103"

cd "$STUDY_ROOT"

restore_original() {
    local state
    set +e
    state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable 2>/dev/null |
        awk -F= '$1 == "VMState" { gsub(/"/, "", $2); print $2; exit }')"
    if [[ "$state" == "running" ]]; then
        VBoxManage controlvm "$VM_NAME" poweroff >/dev/null 2>&1
    fi
    VBoxManage snapshot "$VM_NAME" restore "$ORIGINAL_SNAPSHOT" >/dev/null 2>&1
}
cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    restore_original
    exit "$exit_code"
}
vm_state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable |
    awk -F= '$1 == "VMState" { gsub(/"/, "", $2); print $2; exit }')"
[[ "$vm_state" != "running" ]] || { echo "Refusing to start: VM is already running" >&2; exit 2; }
if pgrep -af '[v]box_malware_batch|[r]un_versioned_cohorts|[s]tage_versioned_runner' >/dev/null; then
    echo "Refusing to start: another collection or staging process is active" >&2
    exit 2
fi
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[[ "$(sha256sum src/malware_runner.py | awk '{print $1}')" == "$FILTERED_RUNNER_SHA" ]] || {
    echo "Runner hash changed after manifest freeze" >&2; exit 2;
}
[[ "$(sha256sum scripts/vbox_malware_batch.sh | awk '{print $1}')" == "$BATCH_SHA" ]] || {
    echo "Batch script hash changed after manifest freeze" >&2; exit 2;
}
[[ "$(sha256sum scripts/stage_versioned_runner_snapshot.sh | awk '{print $1}')" == "$STAGING_SHA" ]] || {
    echo "Staging script hash changed after manifest freeze" >&2; exit 2;
}

stage_snapshot() {
    local baseline="$1" child="$2" setup="${3:-}"
    local args=(--vm "$VM_NAME" --guest-user "$GUEST_USER" --baseline-snapshot "$baseline"
        --new-snapshot "$child" --guest-runner "$RUNNER" --schema-version "$SCHEMA")
    [[ -z "$setup" ]] || args+=(--guest-setup "$setup")
    bash scripts/stage_versioned_runner_snapshot.sh "${args[@]}"
}

run_malware_batch() {
    local sample_list="$1" output_dir="$2"
    shift 2
    bash scripts/vbox_malware_batch.sh \
        --vm "$VM_NAME" --guest-user "$GUEST_USER" \
        --guest-malware-dir "$MALWARE_DIR" --guest-runner "$RUNNER" \
        --snapshot "$MALWARE_SNAPSHOT" --output-dir "$output_dir" \
        --sample-list "$sample_list" --schema-version "$SCHEMA" \
        --timeout 20 --window-sec 0.5 --iface enp0s3 --ebpf \
        --fixed-observation --common-launch-wrapper \
        --packet-capture-buffer-kb 16384 --packet-capture-drain-ms 1000 \
        --bpftrace-perf-rb-pages 16384 "$@"
}

run_benign_batch() {
    local profile="$1" output_dir="$2"
    shift 2
    bash scripts/vbox_malware_batch.sh \
        --vm "$VM_NAME" --guest-user "$GUEST_USER" \
        --guest-malware-dir "$BENIGN_DIR" --guest-runner "$RUNNER" \
        --snapshot "$BENIGN_SNAPSHOT" --output-dir "$output_dir" \
        --sample-list "$CAMPAIGN_DIR/manifests/benign-10.txt" \
        --guest-arguments-dir "$ARGUMENTS_ROOT/$profile" \
        --watch-path "$WATCH_DIR" --schema-version "$SCHEMA" \
        --timeout 20 --window-sec 0.5 --iface enp0s3 --ebpf \
        --fixed-observation --common-launch-wrapper \
        --packet-capture-buffer-kb 16384 --packet-capture-drain-ms 1000 \
        --bpftrace-perf-rb-pages 16384 "$@"
}

log() {
    printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$CAMPAIGN_DIR/coordinator.log"
}

log "Staging fresh malware snapshot"
stage_snapshot "clean-current-runner-2026-10-18.1-malware" "$MALWARE_SNAPSHOT" \
    >"$CAMPAIGN_DIR/stage-malware.log" 2>&1
log "Preflighting both malware waves without execution"
run_malware_batch "$CAMPAIGN_DIR/manifests/malware-wave-1-all.txt" \
    "$CAMPAIGN_DIR/runs/preflight-malware" --dry-run >"$CAMPAIGN_DIR/preflight-malware-wave-1.log" 2>&1
run_malware_batch "$CAMPAIGN_DIR/manifests/malware-wave-2-all.txt" \
    "$CAMPAIGN_DIR/runs/preflight-malware" --dry-run >"$CAMPAIGN_DIR/preflight-malware-wave-2.log" 2>&1

log "Staging fresh benign snapshot and 100 argument profiles"
stage_snapshot "clean-paired-elf-watchpath-pilot-v4-20261018" "$BENIGN_SNAPSHOT" \
    "$CAMPAIGN_DIR/setup_benign_profiles.sh" >"$CAMPAIGN_DIR/stage-benign.log" 2>&1
run_benign_batch profile-01 "$CAMPAIGN_DIR/runs/preflight-benign" \
    --dry-run >"$CAMPAIGN_DIR/preflight-benign.log" 2>&1

for round in 01 02 03 04 05; do
    log "Wave 1 malware round $round"
    run_malware_batch "$CAMPAIGN_DIR/manifests/malware-wave-1-round-$round.txt" \
        "$CAMPAIGN_DIR/runs/wave-1/malware/round-$round" \
        >"$CAMPAIGN_DIR/collect-wave-1-malware-round-$round.log" 2>&1
    log "Wave 1 benign profile $round"
    run_benign_batch "profile-$round" "$CAMPAIGN_DIR/runs/wave-1/benign/profile-$round" \
        >"$CAMPAIGN_DIR/collect-wave-1-benign-profile-$round.log" 2>&1
done

log "Validating wave 1; wave 2 is gated on every invariant"
if ! /usr/bin/python3 "$CAMPAIGN_DIR/validate_campaign_wave.py" --wave 1 \
        >"$CAMPAIGN_DIR/wave-1-validation.log" 2>&1; then
    log "Wave 1 failed quality/retrieval/archive validation; wave 2 withheld"
    exit 20
fi
log "Wave 1 passed all gates; starting conditional wave 2"

for round in 01 02 03 04 05; do
    log "Wave 2 malware round $round"
    run_malware_batch "$CAMPAIGN_DIR/manifests/malware-wave-2-round-$round.txt" \
        "$CAMPAIGN_DIR/runs/wave-2/malware/round-$round" \
        >"$CAMPAIGN_DIR/collect-wave-2-malware-round-$round.log" 2>&1
    printf -v profile 'profile-%02d' "$((10#$round + 5))"
    log "Wave 2 benign profile $profile"
    run_benign_batch "$profile" "$CAMPAIGN_DIR/runs/wave-2/benign/$profile" \
        >"$CAMPAIGN_DIR/collect-wave-2-benign-$profile.log" 2>&1
done

log "Validating wave 2"
/usr/bin/python3 "$CAMPAIGN_DIR/validate_campaign_wave.py" --wave 2 \
    >"$CAMPAIGN_DIR/wave-2-validation.log" 2>&1
log "Both waves completed and validated"