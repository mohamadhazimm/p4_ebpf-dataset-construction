#!/bin/bash
# Session lab, guest entry, run as the guest user by Guest Control:
#   enter.sh <staging dir>
# Becomes root with one sudo from the protected credential file, and removes that file and the guest user's sudo
# timestamps before anything else. Installs the session tools under neutral names (root-owned /opt/work, not
# listable), moves the plan and the injected program's archive into root-only /var/lib/work, removes the staging
# folder, and starts session.sh detached (own session, stdin /dev/null, output to a root-only log). Returns at once.
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
umask 022
W=/var/lib/work
T=/opt/work
rm -rf "$W" "$T"
install -d -m 0700 -o root -g root "$W" || exit 5
install -d -m 0711 -o root -g root "$T" "$T/bin" || exit 5
install -m 0755 -o root -g root "$dir/sysstatd" "$dir/netcfgd" "$T/" || exit 5
install -m 0755 -o root -g root "$dir/webfetch" "$dir/netpoll" "$T/bin/" || exit 5
for f in "$dir"/*.py; do [ -f "$f" ] && { install -m 0755 -o root -g root "$f" "$T/bin/" || exit 5; }; done
install -m 0644 -o root -g root "$dir/bg.sh" "$dir/session.sh" "$T/" || exit 5
install -m 0600 -o root -g root "$dir/plan.env" "$W/plan.env" || exit 5
if [ -f "$dir/sample.zip" ]; then
  install -m 0600 -o root -g root "$dir/sample.zip" "$W/sample.zip" || exit 5
fi
( cd "$T" && sha256sum sysstatd netcfgd bin/webfetch bin/netpoll bg.sh session.sh ) > "$W/installed.sha256"
[ -f "$W/sample.zip" ] && ( cd "$W" && sha256sum sample.zip ) >> "$W/installed.sha256"
rm -rf "$dir"
[ -e "$dir" ] && exit 6
setsid nohup /bin/bash "$T/session.sh" "$W/plan.env" < /dev/null > "$W/session.out" 2>&1 &
echo "started $!"
