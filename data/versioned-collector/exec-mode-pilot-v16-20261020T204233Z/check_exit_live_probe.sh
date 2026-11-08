#!/usr/bin/env bash
# Host wrapper for guest_exit_live_probe.sh: benign probe-compatibility check on the
# isolated Phase A snapshot; restores the original snapshot afterwards.
set -Eeuo pipefail
RUN_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VM="Ubuntu-Clean-24.04"
SNAPSHOT="clean-exec-mode-pilot-v15-20261020T204233Z"
ORIGINAL="clean-tls-paired-2026-10-19"
ENV_FILE="$(cd "$RUN_ROOT/../../../../.." && pwd)/.env"

info() { VBoxManage showvminfo "$VM" --machinereadable; }
[[ "$(info | awk -F= '$1=="VMState"{gsub(/"/,"",$2);print $2}')" != "running" ]] || { echo "VM running" >&2; exit 2; }
! pgrep -af '[v]box_malware_batch|[r]un_pilot|[s]tage_versioned_runner' >/dev/null || { echo "collector active" >&2; exit 2; }
info | grep -qx 'nic1="intnet"' && info | grep -qx 'intnet1="malnet"' || { echo "nic1 not malnet" >&2; exit 2; }
[[ "$(info | grep -E '^nic[2-8]=' | grep -vc '"none"' || true)" == "0" ]] || { echo "extra NICs" >&2; exit 2; }

PW="$(mktemp)"; chmod 600 "$PW"
/usr/bin/python3 - "$ENV_FILE" >"$PW" <<'PY'
import shlex, sys
from pathlib import Path
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if line.startswith("export "):
        line = line[7:].lstrip()
    name, sep, value = line.partition("=")
    if sep and name.strip() in {"VBOX_GUEST_PASSWORD", "GUEST_PASSWORD", "guest_password"}:
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = shlex.split(value)[0]
        else:
            value = value.split(" #", 1)[0].strip()
        sys.stdout.write(value)
        break
PY
[[ -s "$PW" ]] || { rm -f "$PW"; echo "no guest password" >&2; exit 2; }
AUTH=(--username csci --passwordfile "$PW")
cleanup() {
    set +e
    VBoxManage controlvm "$VM" poweroff >/dev/null 2>&1; sleep 3
    VBoxManage snapshot "$VM" restore "$ORIGINAL" >/dev/null 2>&1
    rm -f "$PW"
    echo "restored $ORIGINAL"
}
trap cleanup EXIT
VBoxManage snapshot "$VM" restore "$SNAPSHOT"
VBoxManage startvm "$VM" --type headless
for _ in $(seq 1 60); do
    VBoxManage guestcontrol "$VM" run "${AUTH[@]}" --exe /bin/true >/dev/null 2>&1 && break; sleep 3
done
VBoxManage guestcontrol "$VM" copyto "${AUTH[@]}" --target-directory /tmp/ "$RUN_ROOT/${GUEST_SCRIPT:-guest_exit_live_probe.sh}"
VBoxManage guestcontrol "$VM" copyto "${AUTH[@]}" --target-directory /tmp/ "$PW"
VBoxManage guestcontrol "$VM" run "${AUTH[@]}" --exe /bin/chmod -- 600 "/tmp/$(basename "$PW")"
VBoxManage guestcontrol "$VM" run "${AUTH[@]}" --wait-stdout --wait-stderr --timeout 120000 --exe /bin/bash -- \
    /tmp/${GUEST_SCRIPT:-guest_exit_live_probe.sh} "/tmp/$(basename "$PW")"
