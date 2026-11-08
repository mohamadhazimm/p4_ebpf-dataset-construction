#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER_SOURCE="$SCRIPT_DIR/../src/malware_runner.py"
SCHEMA_VERSION="2026-10-18.1"
FEATURE_COUNT=169
VM_NAME=""
GUEST_USER=""
BASELINE_SNAPSHOT=""
NEW_SNAPSHOT=""
GUEST_RUNNER=""
GUEST_SETUP=""
PASSWORD_FILE=""
STAGING_COMMITTED=0

usage() {
    cat <<'EOF'
Usage: stage_versioned_runner_snapshot.sh --vm NAME --guest-user USER \
    --baseline-snapshot NAME --new-snapshot NAME [--guest-runner PATH] \
    [--schema-version VERSION]

Restores an existing clean snapshot, installs the workspace runner, verifies
its schema and SHA-256 inside the guest, and creates a new child snapshot.
No sample is selected or executed; the baseline snapshot remains unchanged.
EOF
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --vm) VM_NAME="${2:?Missing value for --vm}"; shift 2 ;;
        --guest-user) GUEST_USER="${2:?Missing value for --guest-user}"; shift 2 ;;
        --baseline-snapshot) BASELINE_SNAPSHOT="${2:?Missing value for --baseline-snapshot}"; shift 2 ;;
        --new-snapshot) NEW_SNAPSHOT="${2:?Missing value for --new-snapshot}"; shift 2 ;;
        --guest-runner) GUEST_RUNNER="${2:?Missing value for --guest-runner}"; shift 2 ;;
        --schema-version) SCHEMA_VERSION="${2:?Missing value for --schema-version}"; shift 2 ;;
        --guest-setup) GUEST_SETUP="${2:?Missing setup script}"; shift 2 ;;
        --help) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

[[ -n "$VM_NAME" && -n "$GUEST_USER" && -n "$BASELINE_SNAPSHOT" && -n "$NEW_SNAPSHOT" ]] || {
    usage >&2
    die "VM, guest user, baseline snapshot, and new snapshot are required"
}
[[ "$BASELINE_SNAPSHOT" != "$NEW_SNAPSHOT" ]] || die "New snapshot must differ from baseline"
[[ -s "$RUNNER_SOURCE" ]] || die "Runner source is missing: $RUNNER_SOURCE"
command -v VBoxManage >/dev/null 2>&1 || die "VBoxManage was not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum was not found"
GUEST_RUNNER="${GUEST_RUNNER:-/home/$GUEST_USER/Downloads/malware_runner.py}"
EXPECTED_RUNNER_SHA256="$(sha256sum "$RUNNER_SOURCE" | awk '{print $1}')"

if [[ -z "${VBOX_GUEST_PASSWORD:-}" ]]; then
    ENV_FILE="${ENV_FILE:-$(cd "$SCRIPT_DIR/../../.." && pwd)/.env}"
    if [[ -r "$ENV_FILE" ]]; then
        VBOX_GUEST_PASSWORD="$(python3 - "$ENV_FILE" <<'PY'
import shlex
import sys
from pathlib import Path

for raw_line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("export "):
        line = line[7:].lstrip()
    name, separator, value = line.partition("=")
    if not separator or name.strip() not in {"VBOX_GUEST_PASSWORD", "GUEST_PASSWORD", "guest_password"}:
        continue
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        parts = shlex.split(value, comments=False, posix=True)
        if len(parts) != 1:
            raise SystemExit("Invalid guest password value in .env")
        value = parts[0]
    else:
        value = value.split(" #", 1)[0].strip()
    print(value)
    break
PY
        )"
    fi
fi
[[ -n "${VBOX_GUEST_PASSWORD:-}" ]] || die "Set guest_password in the workspace .env"

PASSWORD_FILE="$(mktemp)"
chmod 600 "$PASSWORD_FILE"
printf '%s' "$VBOX_GUEST_PASSWORD" >"$PASSWORD_FILE"
unset VBOX_GUEST_PASSWORD
VBOX_AUTH=(--username "$GUEST_USER" --passwordfile "$PASSWORD_FILE")

vm_state() {
    VBoxManage showvminfo "$VM_NAME" --machinereadable 2>/dev/null |
        awk -F= '$1 == "VMState" { gsub(/"/, "", $2); print $2; exit }'
}

snapshot_exists() {
    VBoxManage snapshot "$VM_NAME" list --machinereadable 2>/dev/null |
        grep -Fq "=\"$1\""
}

network_is_isolated() {
    local info value
    info="$(VBoxManage showvminfo "$VM_NAME" --machinereadable)"
    while IFS= read -r line; do
        value="${line#*=}"
        value="${value//\"/}"
        case "$value" in
            none|null|intnet) ;;
            *) return 1 ;;
        esac
    done < <(grep -E '^nic[0-9]+=' <<<"$info")
}

poweroff_vm() {
    if [[ "$(vm_state)" == "running" ]]; then
        VBoxManage controlvm "$VM_NAME" poweroff >/dev/null 2>&1 || true
        for _ in {1..30}; do
            [[ "$(vm_state)" != "running" ]] && return
            sleep 1
        done
        die "VM did not power off: $VM_NAME"
    fi
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    set +e
    poweroff_vm
    if [[ "$STAGING_COMMITTED" -ne 1 && -n "$BASELINE_SNAPSHOT" ]] && snapshot_exists "$BASELINE_SNAPSHOT"; then
        VBoxManage snapshot "$VM_NAME" restore "$BASELINE_SNAPSHOT" >/dev/null 2>&1
    fi
    [[ -n "$PASSWORD_FILE" ]] && rm -f "$PASSWORD_FILE"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

VBoxManage showvminfo "$VM_NAME" >/dev/null 2>&1 || die "VirtualBox VM was not found: $VM_NAME"
snapshot_exists "$BASELINE_SNAPSHOT" || die "Baseline snapshot not found: $BASELINE_SNAPSHOT"
! snapshot_exists "$NEW_SNAPSHOT" || die "Refusing to overwrite snapshot: $NEW_SNAPSHOT"
[[ "$(vm_state)" != "running" ]] || die "Power off the VM before staging a runner snapshot"

echo "Runner SHA-256: $EXPECTED_RUNNER_SHA256"
echo "Restoring clean baseline: $BASELINE_SNAPSHOT"
VBoxManage snapshot "$VM_NAME" restore "$BASELINE_SNAPSHOT" >/dev/null
network_is_isolated || die "Restored VM has a host-connected NIC; refusing to stage"
VBoxManage modifyvm "$VM_NAME" --clipboard-mode disabled --drag-and-drop disabled
VBoxManage startvm "$VM_NAME" --type headless

GUEST_ERROR_FILE="$(mktemp)"
chmod 600 "$GUEST_ERROR_FILE"
guest_ready=0
for attempt in {1..90}; do
    if VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
        --exe /bin/true --wait-stdout --wait-stderr --timeout 5000 -- \
        >/dev/null 2>"$GUEST_ERROR_FILE"; then
        guest_ready=1
        break
    fi
    sleep 2
done
[[ "$guest_ready" -eq 1 ]] || die "Guest Control did not become ready: $(<"$GUEST_ERROR_FILE")"
rm -f "$GUEST_ERROR_FILE"

if [[ -n "$GUEST_SETUP" ]]; then
    [[ -s "$GUEST_SETUP" ]] || die "Guest setup script is missing"
    guest_setup_path="/home/$GUEST_USER/.corrected-pilot-setup.sh"
    VBoxManage guestcontrol "$VM_NAME" copyto "${VBOX_AUTH[@]}" "$GUEST_SETUP" "$guest_setup_path" >/dev/null
    VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
        --exe /bin/bash --wait-stdout --wait-stderr --timeout 120000 -- "$guest_setup_path"
    VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
        --exe /bin/rm --wait-stdout --wait-stderr --timeout 30000 -- -f "$guest_setup_path"
fi

guest_temp="${GUEST_RUNNER}.versioned"
VBoxManage guestcontrol "$VM_NAME" copyto "${VBOX_AUTH[@]}" "$RUNNER_SOURCE" "$guest_temp" >/dev/null
VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
    --exe /bin/cp --wait-stdout --wait-stderr --timeout 30000 -- \
    -f -- "$guest_temp" "$GUEST_RUNNER"
VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
    --exe /bin/chmod --wait-stdout --wait-stderr --timeout 30000 -- \
    755 "$GUEST_RUNNER"
VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
    --exe /bin/rm --wait-stdout --wait-stderr --timeout 30000 -- \
    -f -- "$guest_temp"

schema_json="$(VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
    --exe /usr/bin/python3 --wait-stdout --wait-stderr --timeout 30000 -- \
    "$GUEST_RUNNER" --print-feature-schema | tr -d '\r')"
python3 - "$SCHEMA_VERSION" "$FEATURE_COUNT" "$EXPECTED_RUNNER_SHA256" "$schema_json" <<'PY'
import json
import sys

version, count, expected_hash, payload = sys.argv[1:]
try:
    schema = json.loads(payload)
except json.JSONDecodeError as error:
    raise SystemExit("Guest runner returned invalid JSON: " + str(error))
features = [field for group in schema.get("feature_groups", {}).values() for field in group]
if schema.get("schema_version") != version:
    raise SystemExit("Guest telemetry schema version mismatch")
if schema.get("feature_count") != int(count) or len(features) != int(count):
    raise SystemExit("Guest telemetry feature count mismatch")
if len(features) != len(set(features)):
    raise SystemExit("Guest telemetry schema has duplicate fields")
if schema.get("runner_sha256") != expected_hash:
    raise SystemExit("Guest runner SHA-256 does not match host source")
PY

VBoxManage guestcontrol "$VM_NAME" run "${VBOX_AUTH[@]}" \
    --exe /bin/sync --wait-stdout --wait-stderr --timeout 30000 --
poweroff_vm
VBoxManage snapshot "$VM_NAME" take "$NEW_SNAPSHOT" \
    --description "Verified telemetry schema $SCHEMA_VERSION; runner SHA-256 $EXPECTED_RUNNER_SHA256; no sample executed" \
    >/dev/null
STAGING_COMMITTED=1
echo "Created verified runner snapshot: $NEW_SNAPSHOT"