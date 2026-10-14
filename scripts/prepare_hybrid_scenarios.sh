#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STUDY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SCENARIO_DIR="${SCENARIO_DIR:-$STUDY_DIR/data/hybrid_scenarios}"
WORKLOAD_DIR="$SCENARIO_DIR/workloads"
MANIFEST="$SCENARIO_DIR/scenario_manifest.csv"
ENV_FILE="${ENV_FILE:-$STUDY_DIR/../../.env}"
VM_NAME="${VM_NAME:-Ubuntu-Clean-24.04}"
GUEST_USER="${GUEST_USER:-csci}"
BASELINE_SNAPSHOT="${BASELINE_SNAPSHOT:-clean-emulated-hybrid-rf-v3h-20261011}"
SCENARIO_SNAPSHOT="${SCENARIO_SNAPSHOT:-clean-emulated-hybrid-scenarios-v1-20261013}"
GUEST_ROOT="${GUEST_ROOT:-/home/$GUEST_USER/Downloads/hybrid-scenarios-v1}"
GUEST_ARCHIVE="/tmp/hybrid-scenarios-v1.tar.gz"
RUNNER_SOURCE="$STUDY_DIR/src/malware_runner.py"
GUEST_RUNNER="/home/$GUEST_USER/Downloads/malware_runner.py"
PASSWORD_FILE=""
GUEST_ERROR_FILE=""
STAGING_STARTED=0

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

[[ -r "$ENV_FILE" ]] || fail "Workspace .env file is missing or unreadable: $ENV_FILE"
[[ -s "$RUNNER_SOURCE" ]] || fail "Telemetry runner source is missing: $RUNNER_SOURCE"
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
[[ -n "$VBOX_GUEST_PASSWORD" ]] || fail "Set guest_password in the workspace .env; no terminal prompt was made"
[[ -d "$WORKLOAD_DIR" && -s "$MANIFEST" ]] || fail "Generate the hybrid scenario cohort first"
command -v VBoxManage >/dev/null 2>&1 || fail "VBoxManage was not found"

VM_INFO="$(VBoxManage showvminfo "$VM_NAME" --machinereadable)"
[[ "$(awk -F= '$1 == "nic1" {gsub(/"/, "", $2); print $2}' <<<"$VM_INFO")" == "intnet" ]] ||
    fail "NIC1 must remain on the isolated malnet internal network"
grep -Fxq 'intnet1="malnet"' <<<"$VM_INFO" || fail "NIC1 must remain on malnet"
while IFS= read -r line; do
    adapter="${line#*=}"
    adapter="${adapter//\"/}"
    case "$adapter" in
        intnet|none|null) ;;
        *) fail "Host-connected adapter is not allowed: $adapter" ;;
    esac
done < <(grep -E '^nic[0-9]+=' <<<"$VM_INFO")

vm_state() {
    VBoxManage showvminfo "$VM_NAME" --machinereadable 2>/dev/null |
        awk -F= '$1 == "VMState" {gsub(/"/, "", $2); print $2; exit}'
}

snapshot_exists() {
    VBoxManage snapshot "$VM_NAME" list --machinereadable 2>/dev/null |
        grep -Fq "=\"$1\""
}

poweroff_vm() {
    if [[ "$(vm_state)" == "running" ]]; then
        VBoxManage controlvm "$VM_NAME" poweroff >/dev/null 2>&1 || true
        for _ in {1..30}; do
            [[ "$(vm_state)" != "running" ]] && return
            sleep 1
        done
        fail "VM did not power off: $VM_NAME"
    fi
}

restore_snapshot() {
    poweroff_vm
    VBoxManage snapshot "$VM_NAME" restore "$1" >/dev/null
}

guest_run() {
    local executable="$1"
    shift
    VBoxManage guestcontrol "$VM_NAME" run --username "$GUEST_USER" \
        --passwordfile "$PASSWORD_FILE" --exe "$executable" \
        --wait-stdout --wait-stderr --timeout "${GUEST_RUN_TIMEOUT_MS:-120000}" -- "$@"
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    set +e
    if [[ "$STAGING_STARTED" -eq 1 ]]; then
        restore_snapshot "$BASELINE_SNAPSHOT"
    fi
    [[ -n "$PASSWORD_FILE" ]] && rm -f "$PASSWORD_FILE"
    [[ -n "$GUEST_ERROR_FILE" ]] && rm -f "$GUEST_ERROR_FILE"
    [[ -n "${ARCHIVE_FILE:-}" ]] && rm -f "$ARCHIVE_FILE"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

[[ "$(vm_state)" != "running" ]] || fail "Shut down the VM before preparing scenarios"
snapshot_exists "$BASELINE_SNAPSHOT" || fail "Baseline snapshot not found: $BASELINE_SNAPSHOT"
! snapshot_exists "$SCENARIO_SNAPSHOT" || fail "Scenario snapshot already exists: $SCENARIO_SNAPSHOT"
EXPECTED_SAMPLES="$(python3 - "$MANIFEST" <<'PY'
import csv
import sys
from pathlib import Path
with Path(sys.argv[1]).open(newline="", encoding="utf-8-sig") as source:
    print(sum(1 for _ in csv.DictReader(source)))
PY
)"
[[ "$EXPECTED_SAMPLES" -gt 0 ]] || fail "Scenario manifest is empty"
ARCHIVE_FILE="$(mktemp --suffix=.tar.gz)"
tar -C "$SCENARIO_DIR" -czf "$ARCHIVE_FILE" workloads scenario_manifest.csv
ARCHIVE_SHA256="$(sha256sum "$ARCHIVE_FILE" | awk '{print $1}')"
PASSWORD_FILE="$(mktemp)"
chmod 600 "$PASSWORD_FILE"
printf '%s' "$VBOX_GUEST_PASSWORD" >"$PASSWORD_FILE"
unset VBOX_GUEST_PASSWORD
GUEST_ERROR_FILE="$(mktemp)"
chmod 600 "$GUEST_ERROR_FILE"

STAGING_STARTED=1
restore_snapshot "$BASELINE_SNAPSHOT"
VBoxManage startvm "$VM_NAME" --type headless >/dev/null
printf 'Waiting for Guest Control (headless startup; credential loaded from .env).\n'
guest_ready=0
guest_started_at=$SECONDS
guest_deadline=$((guest_started_at + 60))
guest_attempt=0
while (( SECONDS < guest_deadline )); do
    guest_attempt=$((guest_attempt + 1))
    if GUEST_RUN_TIMEOUT_MS=5000 guest_run /bin/true >/dev/null 2>"$GUEST_ERROR_FILE"; then
        guest_ready=1
        break
    fi
    if (( guest_attempt % 5 == 0 )); then
        printf 'Guest Control is not ready yet (%d checks; %d seconds elapsed).\n' \
            "$guest_attempt" "$((SECONDS - guest_started_at))"
    fi
    sleep 2
done
if [[ "$guest_ready" -ne 1 ]]; then
    guest_error="$(<"$GUEST_ERROR_FILE")"
    fail "Guest Control did not become available within 60 seconds: ${guest_error:-no VBox diagnostic}"
fi
guest_run /bin/mkdir -p "$GUEST_ROOT" >/dev/null
VBoxManage guestcontrol "$VM_NAME" copyto --username "$GUEST_USER" \
    --passwordfile "$PASSWORD_FILE" "$ARCHIVE_FILE" "$GUEST_ARCHIVE" >/dev/null
verify_archive_code='import hashlib, sys
path, expected = sys.argv[1:]
digest = hashlib.sha256()
with open(path, "rb") as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
if digest.hexdigest() != expected:
    raise SystemExit("scenario archive SHA-256 mismatch")'
guest_run /usr/bin/python3 -c "$verify_archive_code" "$GUEST_ARCHIVE" "$ARCHIVE_SHA256"
guest_run /bin/tar -xzf "$GUEST_ARCHIVE" -C "$GUEST_ROOT"
VBoxManage guestcontrol "$VM_NAME" copyto --username "$GUEST_USER" \
    --passwordfile "$PASSWORD_FILE" "$RUNNER_SOURCE" "$GUEST_RUNNER" >/dev/null
guest_run /bin/chmod 755 "$GUEST_RUNNER"
guest_run /usr/bin/python3 -m py_compile "$GUEST_RUNNER"
validate_code='import pathlib, py_compile, sys
root = pathlib.Path(sys.argv[1])
files = sorted((root / "workloads").glob("*.py"))
expected = int(sys.argv[2])
if len(files) != expected:
    raise SystemExit(f"expected {expected} scripts, found {len(files)}")
for path in files:
    py_compile.compile(str(path), doraise=True)
    path.chmod(0o755)
print(len(files))'
STAGED_COUNT="$(guest_run /usr/bin/python3 -c "$validate_code" "$GUEST_ROOT" "$EXPECTED_SAMPLES" | tr -d '\r')"
[[ "$STAGED_COUNT" == "$EXPECTED_SAMPLES" ]] || fail "Guest scenario count mismatch"
guest_run /bin/rm -f "$GUEST_ARCHIVE" >/dev/null
guest_run /bin/sync -f "$GUEST_RUNNER"
guest_run /bin/sync >/dev/null
poweroff_vm
VBoxManage snapshot "$VM_NAME" take "$SCENARIO_SNAPSHOT" \
    --description "Isolated matched hybrid simulations; internal malnet destinations only" >/dev/null
STAGING_STARTED=0
rm -f "$PASSWORD_FILE" "$GUEST_ERROR_FILE" "$ARCHIVE_FILE"
PASSWORD_FILE=""
GUEST_ERROR_FILE=""
ARCHIVE_FILE=""
printf 'Created scenario snapshot: %s\nStaged scripts: %s\nGuest workload directory: %s\nGuest telemetry runner: %s\n' \
    "$SCENARIO_SNAPSHOT" "$STAGED_COUNT" "$GUEST_ROOT" "$GUEST_RUNNER"
