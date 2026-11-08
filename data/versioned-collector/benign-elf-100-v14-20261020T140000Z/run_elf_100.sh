#!/usr/bin/env bash
# Collect 100 benign ELF runs (10 tools x 10 argument profiles) with runner schema .14.
# Reuses setup_benign_profiles.sh from the partial .12 campaign (not its outputs).
set -Eeuo pipefail

STUDY_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
CAMPAIGN_DIR="$STUDY_ROOT/data/versioned-collector/benign-elf-100-v14-20261020T140000Z"
OLD_CAMPAIGN="$STUDY_ROOT/data/versioned-collector/overnight-qa-v12-20261019T214633Z"
VM_NAME="Ubuntu-Clean-24.04"
GUEST_USER="csci"
RUNNER="/home/csci/Downloads/malware_runner.py"
BENIGN_DIR="/home/csci/Downloads/paired-elf-watchpath-pilot-20261018/benign"
WATCH_DIR="/home/csci/Downloads/paired-elf-watchpath-pilot-20261018/watch"
ARGUMENTS_ROOT="/home/csci/Downloads/overnight-qa-benign-arguments"
BENIGN_SNAPSHOT="clean-benign-elf-100-v14-20261020T140000Z"
BASELINE="clean-paired-elf-watchpath-pilot-v4-20261018"
ORIGINAL_SNAPSHOT="clean-tls-paired-2026-10-19"
SCHEMA="2026-10-19.14"
RUNNER_SHA="b366c337481e82e3118038ac966f3b35d5a5195123213a763a5ba2a8b1bf09d9"
BATCH_SHA="4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f"
STAGING_SHA="5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103"

cd "$STUDY_ROOT"
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$CAMPAIGN_DIR/coordinator.log"; }

restore_original() {
    local state
    set +e
    state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable 2>/dev/null |
        awk -F= '$1 == "VMState" { gsub(/"/, "", $2); print $2; exit }')"
    [[ "$state" != "running" ]] || VBoxManage controlvm "$VM_NAME" poweroff >/dev/null 2>&1
    VBoxManage snapshot "$VM_NAME" restore "$ORIGINAL_SNAPSHOT" >/dev/null 2>&1
}
cleanup() { local c=$?; trap - EXIT INT TERM; restore_original; exit "$c"; }

state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | awk -F= '$1=="VMState"{gsub(/"/,"",$2);print $2;exit}')"
[[ "$state" != "running" ]] || { echo "VM already running" >&2; exit 2; }
if pgrep -af '[v]box_malware_batch|[r]un_versioned_cohorts|[s]tage_versioned_runner|[r]un_campaign' >/dev/null; then
    echo "another collection/staging process active" >&2; exit 2
fi
nic_ok="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | grep -E '^nic[2-8]=' | grep -vc '"none"' || true)"
[[ "$nic_ok" == "0" ]] || { echo "guest has non-isolated NICs" >&2; exit 2; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ "$(sha256sum src/malware_runner.py | awk '{print $1}')" == "$RUNNER_SHA" ]] || { echo "runner hash changed" >&2; exit 2; }
[[ "$(sha256sum scripts/vbox_malware_batch.sh | awk '{print $1}')" == "$BATCH_SHA" ]] || { echo "batch hash changed" >&2; exit 2; }
[[ "$(sha256sum scripts/stage_versioned_runner_snapshot.sh | awk '{print $1}')" == "$STAGING_SHA" ]] || { echo "staging hash changed" >&2; exit 2; }

log "Staging $BENIGN_SNAPSHOT from $BASELINE"
bash scripts/stage_versioned_runner_snapshot.sh --vm "$VM_NAME" --guest-user "$GUEST_USER" \
    --baseline-snapshot "$BASELINE" --new-snapshot "$BENIGN_SNAPSHOT" \
    --guest-runner "$RUNNER" --schema-version "$SCHEMA" \
    --guest-setup "$OLD_CAMPAIGN/setup_benign_profiles.sh" >"$CAMPAIGN_DIR/stage.log" 2>&1

run_batch() {
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
        --fixed-observation --common-launch-wrapper "$@"
}

log "Preflight dry-run (profile-01)"
run_batch profile-01 "$CAMPAIGN_DIR/runs/preflight" --dry-run >"$CAMPAIGN_DIR/preflight.log" 2>&1

for n in 01 02 03 04 05 06 07 08 09 10; do
    log "Collecting profile-$n"
    run_batch "profile-$n" "$CAMPAIGN_DIR/runs/benign-elf/profile-$n" --resume \
        >"$CAMPAIGN_DIR/collect-profile-$n.log" 2>&1 || log "profile-$n batch exited nonzero"
done
log "Collection finished"
