#!/bin/bash
# Socket-ownership live check, guest side (benign only). Run as the guest user from Guest Control:
#   guest_attr_run.sh <dir> <sink ip> <guest ip> <seconds>
# Starts sockowner on the root cgroup and a capture on enp0s3 (both via sudo -S from the protected
# credential file, removed on exit), runs benign clients with known local ports, each group in its
# own cgroup, then stops everything and leaves the outputs in <dir>.
set -u
root="$1"; sink="$2"; gip="$3"; secs="$4"
auth="$root/.auth"
trap 'rm -f "$auth"' EXIT
cd "$root" || exit 2
S() { sudo -S -p '' "$@" < "$auth"; }
cg=/sys/fs/cgroup/hz-attr
log() { echo "$(date -u +%H:%M:%S.%N) $*" >> run.log; }

uname -r > kernel.txt
S mkdir -p "$cg"
for c in c1 c2 c3 c4 c5 c6; do S mkdir -p "$cg/$c"; done
# sudo creates the cgroup directories under its umask 077, so read their ids as root
S python3 -I -c 'import json, os, sys; b = sys.argv[1]; print(json.dumps({c: os.stat(os.path.join(b, c)).st_ino for c in sorted(os.listdir(b)) if os.path.isdir(os.path.join(b, c))}))' "$cg" > cgroups.json
log "cgroups $(cat cgroups.json)"
bench() { for _ in 1 2 3; do "$root/udp_send_bench" "$sink" 65005 200000 "$1" >> bench.jsonl; done; }
bench off-before

S "$root/sockowner" /sys/fs/cgroup > sockowner.log 2> sockowner.err &
for _ in $(seq 1 100); do grep -q SOCKOWNER_READY sockowner.log 2>/dev/null && break; sleep 0.2; done
grep -q SOCKOWNER_READY sockowner.log || { log "sockowner not ready"; cat sockowner.err >> run.log; }
log "sockowner $(head -1 sockowner.log)"
bench on
S tcpdump -i enp0s3 -n -U --immediate-mode -s 128 -w "$root/capture.pcap" 2> tcpdump.log &
sleep 1.5
python3 -I -c 'import json, time; print(json.dumps([[time.time_ns(), time.monotonic_ns()] for _ in range(5)]))' > clocks.json

client() {  # cgroup user client-id mode ports [extra args]
  local c="$1" who="$2" id="$3" mode="$4" ports="$5"; shift 5
  local cmd=(python3 -I "$root/attr_clients.py" --client "$id" --mode "$mode" --ports "$ports" --sink "$sink"
             --laddr "$gip" --duration "$secs" --out "$root/receipts-$id.jsonl" "$@")
  if [ "$who" = root ]; then
    S sh -c 'echo $$ > "$0/cgroup.procs" && exec "$@"' "$cg/$c" "${cmd[@]}" &
  else
    S sh -c 'echo $$ > "$0/cgroup.procs" && exec runuser -u '"$(id -un)"' -- "$@"' "$cg/$c" "${cmd[@]}" &
  fi
}
log "clients start"
client c1 user c1a mixed 31000-31199
client c1 user c1b mixed 31500-31699
client c2 user c2 mixed 32000-32199
client c3 user c3 thread 33000-33399
client c4 user c4 inherit 34000-34199
client c5 user c5 burst 35000-35000 --count 2000
client c6 root c6 raw 36000-36199 --count 100
wait_clients() { while pgrep -f "$root/attr_clients.py" > /dev/null; do sleep 0.5; done; }
wait_clients
log "clients done"
sleep 2
S pkill -INT -x tcpdump
sleep 1
S pkill -INT -x sockowner
for _ in $(seq 1 50); do grep -q SOCKOWNER_HEALTH sockowner.log 2>/dev/null && break; sleep 0.2; done
log "sockowner $(tail -1 sockowner.log)"
sleep 0.5
bench off-after
# files written by root (capture, the raw client's receipts) under sudo's umask 077: hand them back
S chown -R "$(id -un):$(id -gn)" "$root"
S chmod 0644 capture.pcap
for c in c1 c2 c3 c4 c5 c6; do S rmdir "$cg/$c" 2>> run.log; done
S rmdir "$cg" 2>> run.log
log "done"
