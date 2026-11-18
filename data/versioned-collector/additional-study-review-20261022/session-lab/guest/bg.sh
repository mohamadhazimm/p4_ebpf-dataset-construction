#!/bin/bash
# Session lab background activity, as the guest user in cgroup app-a, from the session start to its end:
#   bg.sh <seed> <duration s> <tools dir> <work dir> [time scale per mille, default 1000]
# A seeded schedule of ordinary activity, from tools already used in the dataset (webfetch = flood_gen's benign
# modes, netpoll = lowrate_gen) and the guest's own programs:
#   check-in      webfetch beacon to the Sink's web server every 10 s for the whole session;
#   browsing      webfetch session (10-40 pages) every 30-60 s, to the Sink or a public address;
#   downloads     webfetch bulk (5-20 files) every 45-90 s, to the Sink or a public address;
#   DNS lookups   webfetch dns (5-50 queries) every 20-40 s;
#   commands      a hashing, compressing, archiving, search, listing or grep job every 15-40 s;
#   once each     an NTP poll that nobody answers (30 s) and a TLS poll (30 s), at random times.
# The public addresses are documentation addresses (RFC 5737); in the lab the Sink answers them. Each job's start
# and end go to <work dir>/bg.log. The session kills this script's cgroup at its end.
set -u
LC_ALL=C
seed="$1"; dur="$2"; B="$3"; work="$4"; pm="${5:-1000}"
RANDOM=$seed
cd "$work" || exit 2

log() { echo "$EPOCHREALTIME $*" >> "$work/bg.log"; }
uni() { R=$(( $1 + RANDOM % ($2 - $1 + 1) )); }     # integer in [a, b], into R
sec() { S=$(( $1 * 1000 * pm )); }                   # seconds, scaled, into S (microseconds)
job() {                                              # name argv...: run in the background, log start and end
  local name="$1"
  shift
  ( log "start $name $*"; "$@" > /dev/null 2>&1; log "end $name rc=$?" ) &
}
command_job() {
  case $(( RANDOM % 6 )) in
    0) job hash sha256sum /usr/bin/bash /usr/bin/ls /usr/bin/tar /usr/bin/gzip ;;
    1) job compress gzip -c /usr/bin/bash ;;
    2) job archive tar czf "$work/doc-$1.tgz" /usr/share/doc ;;
    3) job search find /usr/share -name '*.png' ;;
    4) job listing ls -lR /usr/share/man ;;
    5) job grep grep -rl Copyright /usr/share/doc ;;
  esac
}

DST=(10.0.0.1 198.51.100.23 203.0.113.77 192.0.2.80)
start=${EPOCHREALTIME/./}
end=$(( start + dur * 1000 * pm ))
log "background seed $seed duration_s $dur scale_pm $pm"
job checkin "$B/webfetch" beacon 1000 10.0.0.1 80 $(( 10 * pm ))
late=$(( dur > 60 ? dur - 40 : dur / 2 ))
uni 5 30; sec $R; next_browse=$(( start + S ))
uni 10 45; sec $R; next_dl=$(( start + S ))
uni 3 20; sec $R; next_dns=$(( start + S ))
uni 2 15; sec $R; next_cmd=$(( start + S ))
uni 10 $late; sec $R; at_ntp=$(( start + S ))
uni 10 $late; sec $R; at_tls=$(( start + S ))
n=0
while :; do
  now=${EPOCHREALTIME/./}
  (( now >= end )) && break
  if (( now >= next_browse )); then
    uni 10 40; pages=$R
    job browse "$B/webfetch" session "$pages" "${DST[RANDOM % 4]}" 80
    uni 30 60; sec $R; next_browse=$(( now + S ))
  fi
  if (( now >= next_dl )); then
    uni 5 20; files=$R
    job download "$B/webfetch" bulk "$files" "${DST[RANDOM % 4]}" 80
    uni 45 90; sec $R; next_dl=$(( now + S ))
  fi
  if (( now >= next_dns )); then
    uni 5 50
    job dns "$B/webfetch" dns "$R" 10.0.0.1
    uni 20 40; sec $R; next_dns=$(( now + S ))
  fi
  if (( now >= next_cmd )); then
    n=$(( n + 1 ))
    command_job "$n"
    uni 15 40; sec $R; next_cmd=$(( now + S ))
  fi
  if (( at_ntp > 0 && now >= at_ntp )); then
    job ntp "$B/netpoll" ntp 8000 30000 10.0.0.1
    at_ntp=0
  fi
  if (( at_tls > 0 && now >= at_tls )); then
    job tls "$B/netpoll" tlspoll 5000 30000 10.0.0.1 443
    at_tls=0
  fi
  wake=$end
  for t in "$next_browse" "$next_dl" "$next_dns" "$next_cmd" "$at_ntp" "$at_tls"; do
    (( t > 0 && t < wake )) && wake=$t
  done
  d=$(( wake - ${EPOCHREALTIME/./} ))
  (( d < 10000 )) && d=10000
  printf -v frac '%06d' $(( d % 1000000 ))
  sleep "$(( d / 1000000 )).$frac"
done
log "schedule done"
wait
