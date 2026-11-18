#!/bin/bash
# Session lab, guest side, as root; started detached by enter.sh:
#   session.sh <plan.env>
# One session: ordinary background activity from the start, one program injected at T_INJECT (or nothing), the
# host recorded in the kernel by two sysstatd (hostmon_agg, 0.5-s windows, one per cgroup) and one netcfgd
# (sockowner, every socket's flows with its cgroup and process). The network is recorded outside the guest (Sink).
#  1. the injected program is unpacked as the guest user into WORK/x and its SHA-256 checked;
#  2. two cgroups: app-a (background) and app-b (injected program);
#  3. netcfgd on the root cgroup, the two sysstatd waiting for the shared start;
#  4. the background and the injected program start as the guest user, each blocked on a FIFO; this script moves
#     each into its cgroup and releases it at its time, so everything it does is counted and nothing before;
#  5. shared start t0 = now + 2.5 s (monotonic); clock probes (UDP to PROBE_DST:PROBE_PORT) carry the guest's
#     clocks, three before t0 and three after the end;
#  6. at t0 + DUR both cgroups are killed, the monitors stopped (their health lines), and the outputs packed into OUT.
# All settings come from plan.env (written by the host driver; the local test writes its own).
set -u
LC_ALL=C
. "$1" || exit 2
exec 0</dev/null
umask 022
cd "$W" || exit 2
GUID=${GUID:-$(id -u "$GUSER")}
GGROUP=${GGROUP:-$(id -gn "$GUSER")}
if [ "${DROP_AUTO:-0}" = 1 ]; then      # as root in the guest: drop to the guest user, its own groups, no fork
  DROP=(setpriv --reuid="$GUID" --regid="$(id -g "$GUSER")" --init-groups --)
fi

BLOCKED=()
MONITORS=()
T0=""
R0=0
FINISHED=0

log() { echo "$EPOCHREALTIME $*" >> "$W/session.log"; }

sleep_until() {   # realtime target in microseconds
  local now=${EPOCHREALTIME/./} d frac
  d=$(( $1 - now ))
  (( d > 0 )) || return 0
  printf -v frac '%06d' $(( d % 1000000 ))
  sleep "$(( d / 1000000 )).$frac"
}

wait_line() {     # file pattern tries (0.2 s each)
  local i
  for (( i = 0; i < $3; i++ )); do
    grep -q "$2" "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

probes() {        # phase (start|end) output file: three marked datagrams with the guest's clocks
  "$PY" -I - "$SID" "$1" "$PROBE_DST" "$PROBE_PORT" "$2" "${3:-}" <<'EOF'
import json, socket, sys, time
sid, phase, dst, port, out, margin = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5], sys.argv[6]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sent = []
for n in range(3):
    m, r = time.monotonic_ns(), time.time_ns()
    try:
        s.sendto(("HZSYNC %s %s %d %d %d" % (sid, phase, n, m, r)).encode(), (dst, port))
        ok = True
    except OSError as error:
        ok = str(error)
    sent.append({"n": n, "mono_ns": m, "real_ns": r, "sent": ok})
    time.sleep(0.1)
record = {"phase": phase, "probes": sent}
if margin:   # the shared start: 2.5 s ahead, on both clocks
    m, r = time.monotonic_ns(), time.time_ns()
    record.update(t0_mono_ns=m + int(float(margin) * 1e9), t0_real_ns=r + int(float(margin) * 1e9), pair=[m, r])
    print("%d.%09d %d" % (record["t0_mono_ns"] // 10**9, record["t0_mono_ns"] % 10**9, record["t0_real_ns"] // 1000))
json.dump(record, open(out, "w"), indent=1)
EOF
}

start_blocked() { # name cgroup cwd stdout stderr argv...: start as the guest user, blocked; move into the cgroup
  local name="$1" cg="$2" cwd="$3" out="$4" err="$5" i pid=""
  shift 5
  local fifo="$WORK/.go-$name" pidf="$WORK/.pid-$name"
  rm -f "$fifo" "$pidf"
  mkfifo -m 0600 "$fifo" && chown "$GUSER:$GGROUP" "$fifo" || return 1
  setsid "${DROP[@]}" /usr/bin/env -i "${UENV[@]}" /bin/bash -c \
    'cd "$1" || exit 97; echo $$ > "$2"; read -r _ <> "$3"; shift 3; exec "$@"' \
    hzwait "$cwd" "$pidf" "$fifo" "$@" < /dev/null > "$out" 2> "$err" &
  for (( i = 0; i < 50; i++ )); do
    [ -s "$pidf" ] && pid=$(<"$pidf") && [[ "$pid" =~ ^[0-9]+$ ]] && break
    pid=""
    sleep 0.1
  done
  [ -n "$pid" ] || return 1
  BLOCKED+=("$pid")
  [ "$(stat -c %u "/proc/$pid")" = "$GUID" ] || return 1
  echo "$pid" > "$CGROOT/$cg/cgroup.procs" || return 1
  grep -qx "$pid" "$CGROOT/$cg/cgroup.procs" || return 1
  sleep 0.2
  kill -0 "$pid" 2>/dev/null || return 1
  log "blocked $name pid $pid in $cg"
  printf -v "PID_$name" '%s' "$pid"
}

release() {       # name: let the blocked program go
  local pid
  pid="PID_$1"
  pid="${!pid}"
  kill -0 "$pid" 2>/dev/null || { log "release $1: pid $pid gone"; return 1; }
  timeout 10 /bin/bash -c 'printf "go\n" > "$0"' "$WORK/.go-$1" || { log "release $1 timed out"; return 1; }
  rm -f "$WORK/.go-$1" "$WORK/.pid-$1"
}

finish() {        # status: stop what runs, pack the outputs for the host, exit
  local status="$1" c i p
  (( FINISHED )) && exit "$status"
  FINISHED=1
  trap - TERM INT HUP
  for c in app-b app-a; do
    [ -d "$CGROOT/$c" ] && echo 1 > "$CGROOT/$c/cgroup.kill" 2>/dev/null
  done
  for p in "${BLOCKED[@]}"; do kill -KILL "$p" 2>/dev/null; done
  for c in app-b app-a; do
    for (( i = 0; i < 50; i++ )); do
      { [ -d "$CGROOT/$c" ] && [ -s "$CGROOT/$c/cgroup.procs" ]; } || break
      sleep 0.2
    done
    [ -d "$CGROOT/$c" ] && log "cgroup $c left: $(tr '\n' ' ' < "$CGROOT/$c/cgroup.procs")"
  done
  log "cgroups killed"
  [ -n "$T0" ] && probes end "$W/clock-end.json"
  for p in "${MONITORS[@]}"; do kill -INT "$p" 2>/dev/null; done
  wait_line "$W/host-a.log" HOSTMON_HEALTH 75
  wait_line "$W/host-b.log" HOSTMON_HEALTH 25
  wait_line "$W/sock.log" SOCKOWNER_HEALTH 25
  for p in "${MONITORS[@]}"; do kill -KILL "$p" 2>/dev/null; done
  log "monitors stopped"
  for c in app-b app-a; do [ -d "$CGROOT/$c" ] && rmdir "$CGROOT/$c" 2>> "$W/session.log"; done
  [ -f "$BGWORK/bg.log" ] && cp "$BGWORK/bg.log" "$W/bg.log"
  rm -rf "$WORK" "$BGWORK"
  rm -f "$W/.start-a" "$W/.start-b" "$W/sample.zip"
  echo "$status" > "$W/status.txt"
  log "finish status $status"
  tar czf "$W/out.tgz.part" -C "$W" --exclude=out.tgz.part --exclude=plan.env . 2>> "$W/session.log"
  install -m 0644 -o "$GUSER" -g "$GGROUP" "$W/out.tgz.part" "$OUT.part" && mv -f "$OUT.part" "$OUT"
  exit "$status"
}

fail() { log "FAIL $*"; echo "$*" >> "$W/failed.txt"; finish 1; }

trap 'fail "signal"' TERM INT HUP
log "session $SID kind $KIND marker $MARKER t_inject_us $T_INJECT_US dur_us $DUR_US"
uname -r > "$W/kernel.txt"

# 1. the injected program
install -d -m 0755 -o "$GUSER" -g "$GGROUP" "$WORK" "$WORK/x" "$WORK/w" "$BGWORK" || fail "work folders"
exe=""
case "$INJ_SOURCE" in
  archive)
    install -m 0644 -o "$GUSER" -g "$GGROUP" "$W/sample.zip" "$WORK/.s.zip" || fail "archive copy"
    "${DROP[@]}" /usr/bin/7z x -pinfected -o"$WORK/x" -y "$WORK/.s.zip" > "$W/extract.log" 2>&1 || fail "extract"
    rm -f "$WORK/.s.zip"
    mapfile -t found < <(find "$WORK/x" -type f)
    (( ${#found[@]} == 1 )) || fail "archive members: ${#found[@]}"
    exe="${found[0]}"
    chmod 0755 "$exe"
    got=$(sha256sum "$exe" | cut -d' ' -f1)
    echo "$got" > "$W/injected.sha256"
    [ "$got" = "$INJ_SHA256" ] || fail "injected SHA-256 $got"
    ;;
  tool)
    exe="$WORK/x/$INJ_TOOL"
    install -m 0755 -o "$GUSER" -g "$GGROUP" "$T/bin/$INJ_TOOL" "$exe" || fail "tool copy"
    sha256sum "$exe" | cut -d' ' -f1 > "$W/injected.sha256"
    ;;
  system)
    exe="$INJ_EXE"
    [ -x "$exe" ] || fail "no $exe"
    sha256sum "$exe" | cut -d' ' -f1 > "$W/injected.sha256"
    ;;
  none) ;;
  *) fail "unknown source $INJ_SOURCE" ;;
esac
log "injected program: ${exe:-none}"

# 2. cgroups
for c in app-a app-b; do mkdir "$CGROOT/$c" || fail "cgroup $c"; done
printf '{"app-a": %s, "app-b": %s}\n' "$(stat -c %i "$CGROOT/app-a")" "$(stat -c %i "$CGROOT/app-b")" > "$W/cgroups.json"
log "cgroups $(cat "$W/cgroups.json")"

# 3. monitors
"$T/netcfgd" "$CGROOT" > "$W/sock.log" 2> "$W/sock.err" &
MONITORS+=("$!")
wait_line "$W/sock.log" SOCKOWNER_READY 100 || fail "netcfgd not ready"
mkfifo -m 0600 "$W/.start-a" "$W/.start-b" || fail "start fifos"
exec 7<>"$W/.start-a" 8<>"$W/.start-b"
"$T/sysstatd" 0.5 "$CGROOT/app-a" < "$W/.start-a" > "$W/host-a.log" 2> "$W/host-a.err" &
MONITORS+=("$!")
"$T/sysstatd" 0.5 "$CGROOT/app-b" < "$W/.start-b" > "$W/host-b.log" 2> "$W/host-b.err" &
MONITORS+=("$!")
wait_line "$W/host-a.log" HOSTMON_READY 150 || fail "sysstatd app-a not ready"
wait_line "$W/host-b.log" HOSTMON_READY 150 || fail "sysstatd app-b not ready"
log "monitors ready: ${MONITORS[*]}"

# 4. the background and the injected program, blocked in their cgroups
start_blocked bg app-a "$BGWORK" "$W/bg.stdout" "$W/bg.stderr" \
  /bin/bash "$T/bg.sh" "$BG_SEED" "$BG_DUR_S" "$T/bin" "$BGWORK" "$SCALE_PM" || fail "background blocker"
if [ -n "$exe" ]; then
  start_blocked inj app-b "$WORK/w" "$W/injected.stdout" "$W/injected.stderr" \
    /bin/bash -c 'exec "$@"' sample-launch "$exe" "${INJ_ARGS[@]}" || fail "injected blocker"
fi

# 5. shared start
read -r T0 R0 < <(probes start "$W/clock-start.json" 2.5)
[[ "$T0" =~ ^[0-9]+\.[0-9]{9}$ ]] && [[ "$R0" =~ ^[0-9]+$ ]] || fail "no shared start"
printf '%s\n' "$T0" >&7
printf '%s\n' "$T0" >&8
exec 7>&- 8>&-
log "t0 $T0 r0_us $R0"

sleep_until "$R0"
release bg || fail "background release"
log "background released"
if [ -n "$exe" ]; then
  sleep_until $(( R0 + T_INJECT_US - 2000000 ))
  ps -eo pid,ppid,user,stat,comm,args > "$W/ps-before-inject.txt" 2>&1
  sleep_until $(( R0 + T_INJECT_US ))
  log "inject release begin"
  release inj || fail "injected release"
  log "inject release end"
else
  sleep_until $(( R0 + T_INJECT_US ))
  log "pseudo injection (nothing injected)"
fi

# 6. end
sleep_until $(( R0 + DUR_US ))
log "end of session"
for p in $(cat "$CGROOT/app-b/cgroup.procs"); do
  printf '%s %s %s\n' "$p" "$(stat -c %u "/proc/$p" 2>/dev/null)" "$(cat "/proc/$p/comm" 2>/dev/null)"
done > "$W/b-procs.txt"
wc -l < "$CGROOT/app-a/cgroup.procs" > "$W/a-procs-count.txt"
finish 0
