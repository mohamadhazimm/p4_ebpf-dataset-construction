#!/bin/bash
# Prepares the guest for the real-internet snapshot; run by make_internet_snapshot.py as the guest user, while the
# guest is still on the isolated network:
#   guest_prep.sh <staging dir>
# Becomes root with one sudo from the protected credential file and removes that file first (as enter.sh does).
#  1. guest_scrub.py: deletes the staged lab inputs and every sample-like file, scans again (report);
#  2. switches the NetworkManager profile of enp0s3 from the lab's static address to DHCP (the host then attaches
#     the adapter to VirtualBox NAT);
#  3. packs the report into /home/<user>/prep-report.tgz for the host, removes the staging folder, syncs.
# Refuses to run anywhere but a VirtualBox guest.
set -u
dir="$1"
if [ "$(id -u)" != 0 ]; then
  shopt -s execfail
  exec sudo -S -p '' /bin/bash "$0" "$dir" "$(id -un)" < "$dir/.auth"
  rm -f "$dir/.auth"
  exit 4
fi
user="$2"
rm -f "$dir/.auth"
rm -rf "/run/sudo/ts/$user"
exec 0</dev/null
[ "$(cat /sys/class/dmi/id/product_name 2>/dev/null)" = VirtualBox ] || { echo "not a VirtualBox guest"; exit 9; }
out="/home/$user/prep-report"
rm -rf "$out" "$out.tgz"
install -d -m 0755 -o "$user" "$out" || exit 5
status=0

# 1. scrub
python3 -I "$dir/guest_scrub.py" "$dir/known_hashes.txt" "$out/scrub.json" > "$out/scrub.out" 2>&1
echo "$?" > "$out/scrub.rc"
[ "$(cat "$out/scrub.rc")" = 0 ] || status=6

# 2. network: the profile of enp0s3, static -> DHCP (applied at the next boot, on the NAT adapter)
{
  echo "=== devices"; nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device 2>&1
  echo "=== connections"; nmcli -t -f NAME,UUID,TYPE,DEVICE connection show 2>&1
  echo "=== files naming 10.0.0.10 or 10.0.0.1"
  grep -rIlE '10\.0\.0\.(1|10)\b' /etc/NetworkManager /etc/netplan /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d \
    /etc/hosts /etc/network 2>/dev/null
} > "$out/net-before.txt"
conn=$(nmcli -g GENERAL.CONNECTION device show enp0s3 2>/dev/null)
if [ -z "$conn" ]; then
  conn=$(nmcli -t -f NAME,DEVICE connection show 2>/dev/null | awk -F: '$2 == "enp0s3" {print $1; exit}')
fi
echo "$conn" > "$out/net-connection.txt"
if [ -z "$conn" ]; then
  echo "no NetworkManager connection on enp0s3" > "$out/net-error.txt"
  status=7
else
  nmcli connection show "$conn" > "$out/net-profile-before.txt" 2>&1
  if nmcli connection modify "$conn" ipv4.method auto ipv4.addresses "" ipv4.gateway "" ipv4.dns "" \
       ipv4.routes "" ipv4.ignore-auto-dns no ipv4.never-default no connection.autoconnect yes \
       > "$out/net-modify.txt" 2>&1; then
    nmcli connection show "$conn" > "$out/net-profile-after.txt" 2>&1
    grep -E '^ipv4\.(method|addresses|gateway|dns):' "$out/net-profile-after.txt" > "$out/net-ipv4-after.txt"
    grep -q '^ipv4.method: *auto' "$out/net-ipv4-after.txt" || status=8
  else
    status=8
  fi
fi
grep -rIlE '10\.0\.0\.(1|10)\b' /etc/NetworkManager /etc/netplan /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d \
  /etc/hosts /etc/network > "$out/net-files-after.txt" 2>/dev/null

# 3. report for the host
echo "$status" > "$out/status.txt"
chown -R "$user" "$out"
tar czf "$out.tgz" -C "$out" . && chown "$user" "$out.tgz"
rm -rf "$dir"
sync
echo "prep done status $status"
exit "$status"
