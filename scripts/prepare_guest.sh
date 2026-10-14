#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STUDY_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
VM_NAME="${VM_NAME:-Ubuntu-Clean-24.04}"
SOURCE_SNAPSHOT="${SOURCE_SNAPSHOT:-clean-emulated-ebpf-pcap-runner3-20261010}"
BENIGN_SNAPSHOT="${BENIGN_SNAPSHOT:-clean-emulated-hybrid-rf-v2-20261011}"
GUEST_USER="${GUEST_USER:-csci}"

[[ -n "${VBOX_GUEST_PASSWORD:-}" ]] || {
    echo "Set VBOX_GUEST_PASSWORD in the environment." >&2
    exit 1
}
command -v VBoxManage >/dev/null 2>&1 || {
    echo "VBoxManage was not found." >&2
    exit 1
}

package_dir="$STUDY_DIR/data/packages"
workload_dir="${WORKLOAD_SET_DIR:-$STUDY_DIR/data/benign/revision2}"
(
    cd "$package_dir/debs"
    sha256sum -c ../SHA256SUMS >/dev/null
)
[[ "$(find "$workload_dir/workload_scripts" -maxdepth 1 -type f -name '*.sh' | wc -l)" -eq 138 ]] || {
    echo "Expected 138 generated workload scripts." >&2
    exit 1
}
[[ "$(find "$workload_dir/workload_fixtures" -mindepth 2 -maxdepth 2 -type d -name data | wc -l)" -eq 138 ]] || {
    echo "Expected 138 prebuilt workload fixture directories." >&2
    exit 1
}

tar -C "$workload_dir" -czf "$workload_dir/workloads.tar.gz" \
    workload_scripts workload_manifest.csv workload_fixtures

vm_info="$(VBoxManage showvminfo "$VM_NAME" --machinereadable)"
grep -Fxq 'nic1="intnet"' <<<"$vm_info" || {
    echo "NIC1 must remain attached to an isolated internal network." >&2
    exit 1
}
grep -Fxq 'intnet1="malnet"' <<<"$vm_info" || {
    echo "NIC1 must remain on the malnet internal network." >&2
    exit 1
}

auth_file="$(mktemp)"
chmod 600 "$auth_file"
trap 'rm -f "$auth_file"' EXIT
printf '%s' "$VBOX_GUEST_PASSWORD" >"$auth_file"
unset VBOX_GUEST_PASSWORD

vm_state="$(VBoxManage showvminfo "$VM_NAME" --machinereadable | awk -F= '$1 == "VMState" { gsub(/"/, "", $2); print $2; exit }')"
if [[ "$vm_state" == "running" ]]; then
    VBoxManage controlvm "$VM_NAME" poweroff
fi
VBoxManage snapshot "$VM_NAME" restore "$SOURCE_SNAPSHOT" >/dev/null
VBoxManage startvm "$VM_NAME" --type headless >/dev/null
VBoxManage guestproperty wait "$VM_NAME" \
    /VirtualBox/GuestInfo/OS/LoggedInUsersList --timeout 180000 --fail-on-timeout >/dev/null
VBoxManage guestproperty wait "$VM_NAME" \
    /VirtualBox/GuestInfo/OS/LoggedInUsersList --timeout 180000 --fail-on-timeout >/dev/null

VBoxManage guestcontrol "$VM_NAME" copyto --username "$GUEST_USER" \
    --passwordfile "$auth_file" "$package_dir/packages.tar.gz" \
    "/home/$GUEST_USER/Downloads/hybrid-packages.tar.gz"
VBoxManage guestcontrol "$VM_NAME" copyto --username "$GUEST_USER" \
    --passwordfile "$auth_file" "$workload_dir/workloads.tar.gz" \
    "/home/$GUEST_USER/Downloads/hybrid-workloads.tar.gz"
VBoxManage guestcontrol "$VM_NAME" copyto --username "$GUEST_USER" \
    --passwordfile "$auth_file" "$STUDY_DIR/src/malware_runner.py" \
    "/home/$GUEST_USER/Downloads/malware_runner.py"
VBoxManage guestcontrol "$VM_NAME" copyto --username "$GUEST_USER" \
    --passwordfile "$auth_file" "$STUDY_DIR/tests/ebpf_write_smoke.sh" \
    "/home/$GUEST_USER/Downloads/ebpf_write_smoke.sh"

VBoxManage guestcontrol "$VM_NAME" run --username "$GUEST_USER" \
    --passwordfile "$auth_file" --exe /bin/bash --wait-stdout --wait-stderr \
    --timeout 120000 -- -lc '
set -euo pipefail
root="$HOME/Downloads/hybrid-rf-study"
if [[ -e "$root" ]]; then
    echo "Refusing to overwrite existing guest project directory: $root" >&2
    exit 2
fi
mkdir -p "$root/source-packages" "$root/package-root"
tar -xzf "$HOME/Downloads/hybrid-packages.tar.gz" -C "$root/source-packages"
for package in "$root"/source-packages/debs/*.deb; do
    dpkg-deb -x "$package" "$root/package-root"
done
tar -xzf "$HOME/Downloads/hybrid-workloads.tar.gz" -C "$root"
mv "$root/workload_scripts" "$root/workloads"
mkdir -p "$root/workload_smoke"
first_workload="$root/workloads/benign_curl_01.sh"
test -f "$first_workload"
cp "$first_workload" "$root/workload_smoke/"
cp "$HOME/Downloads/ebpf_write_smoke.sh" "$root/workload_smoke/"
chmod 755 "$root"/workloads/*.sh "$root"/workload_smoke/*.sh "$HOME/Downloads/malware_runner.py"
test -f "$root/workload_smoke/ebpf_write_smoke.sh"
test "$(find "$root/workload_fixtures" -mindepth 2 -maxdepth 2 -type d -name data | wc -l)" -eq 138
test -f "$root/workload_fixtures/benign_curl_01/data/text.txt"
python3 -m py_compile "$HOME/Downloads/malware_runner.py"
LD_LIBRARY_PATH="$root/package-root/usr/lib/x86_64-linux-gnu:$root/package-root/lib/x86_64-linux-gnu" \
    "$root/package-root/usr/bin/gawk" --version >/dev/null
"$root/package-root/usr/bin/curl" --noproxy "*" -fsSI --max-time 5 http://example.com/ >/dev/null
test "$(find "$root/workloads" -maxdepth 1 -type f -name "*.sh" | wc -l)" -eq 138
rm -f "$HOME/Downloads/hybrid-packages.tar.gz" "$HOME/Downloads/hybrid-workloads.tar.gz"
rm -f "$HOME/Downloads/ebpf_write_smoke.sh"
sudo -K
sync -f "$HOME/Downloads/malware_runner.py"
sync -f "$root"
echo "benign guest prepared: 138 workloads and prebuilt fixtures; Ubuntu packages extracted without installation"
'

VBoxManage controlvm "$VM_NAME" poweroff
VBoxManage snapshot "$VM_NAME" take "$BENIGN_SNAPSHOT" \
    --description "Isolated benign workload cohort for hybrid random forest study"
echo "Prepared snapshot: $BENIGN_SNAPSHOT"