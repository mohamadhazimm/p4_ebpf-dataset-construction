#!/bin/bash
# Run as root inside the guest, only while building a NEW child snapshot of the clean baseline.
# Disables label-independent background network sources measured in every matched45 capture:
# NetworkManager connectivity checks, chrony NTP lookups, avahi mDNS and cups-browsed printer discovery.
# Prints a JSON receipt of the resulting state. Never touches the baseline snapshot itself.
set -euo pipefail

conf=/etc/NetworkManager/conf.d/99-hazim-quiet-ambient.conf
install -d -m 0755 /etc/NetworkManager/conf.d
printf '[connectivity]\nenabled=false\n' > "$conf"
chmod 0644 "$conf"

systemctl disable --now chrony.service
systemctl mask --now avahi-daemon.socket avahi-daemon.service cups-browsed.service
if systemctl list-unit-files --no-legend geoclue.service | grep -q '^geoclue.service'; then
    systemctl mask --now geoclue.service
fi
sync

python3 - "$conf" <<'PY'
import hashlib, json, subprocess, sys
units = ["chrony.service", "avahi-daemon.socket", "avahi-daemon.service", "cups-browsed.service",
         "geoclue.service", "NetworkManager.service"]
def state(verb, unit):
    return subprocess.run(["systemctl", verb, unit], capture_output=True, text=True).stdout.strip()
print(json.dumps({
    "networkmanager_conf": sys.argv[1],
    "networkmanager_conf_sha256": hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest(),
    "units": {unit: {"enabled": state("is-enabled", unit), "active": state("is-active", unit)} for unit in units},
}, sort_keys=True))
PY
