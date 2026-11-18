#!/usr/bin/env bash
# Copy the Sink half of the sinkhole kit into the running Sink VM with VBoxManage Guest Control.
# Run it yourself in a host terminal: it asks for the Sink account's password, keeps it only in a
# private temporary file for the copy, and deletes that file afterwards. Nothing is installed or
# switched on; that is done on the Sink console (see README.md).
# Usage: bash push_to_sink.sh SINK_USER
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
vm=${SINK_VM:-Sink}
user=${1:?usage: push_to_sink.sh SINK_USER}
files=("sinkhole.sh:/tmp/hazim-sinkhole.sh" "sinkhole_catchall.py:/tmp/hazim-sinkhole_catchall.py")

info=$(VBoxManage showvminfo "$vm" --machinereadable)
grep -qx 'VMState="running"' <<<"$info" || { echo "$vm is not running" >&2; exit 1; }
grep -qx 'nic1="intnet"' <<<"$info" && grep -qx 'intnet1="malnet"' <<<"$info" \
    || { echo "$vm NIC 1 is not on the internal network malnet" >&2; exit 1; }
for n in 2 3 4 5 6 7 8; do
    grep -qx "nic$n=\"none\"" <<<"$info" || { echo "$vm has another NIC enabled (nic$n)" >&2; exit 1; }
done

umask 077
pw=$(mktemp)
trap 'shred -u "$pw" 2>/dev/null || rm -f "$pw"' EXIT
read -rsp "Password for $user on $vm (not echoed): " secret
echo
printf '%s' "$secret" >"$pw"
unset secret
auth=(--username "$user" --passwordfile "$pw")

for pair in "${files[@]}"; do
    VBoxManage guestcontrol "$vm" copyto "${auth[@]}" "$here/${pair%%:*}" "${pair#*:}"
done
remote=$(VBoxManage guestcontrol "$vm" run "${auth[@]}" --exe /usr/bin/sha256sum --wait-stdout --wait-stderr \
    --timeout 20000 -- /tmp/hazim-sinkhole.sh /tmp/hazim-sinkhole_catchall.py)
for pair in "${files[@]}"; do
    want=$(sha256sum "$here/${pair%%:*}" | cut -d' ' -f1)
    grep -q "^$want  ${pair#*:}\$" <<<"$remote" || { echo "hash mismatch for ${pair#*:}" >&2; exit 1; }
done
echo "Copied and hash-checked: /tmp/hazim-sinkhole.sh, /tmp/hazim-sinkhole_catchall.py on $vm."
echo "Next, on the Sink console:  sudo bash /tmp/hazim-sinkhole.sh install"
