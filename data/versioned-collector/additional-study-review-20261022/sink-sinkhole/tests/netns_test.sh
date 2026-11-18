#!/usr/bin/env bash
# Local functional test of the sinkhole kit in private network namespaces. No VM, no real network:
# an unprivileged user+network namespace plays the Sink (10.0.0.1), a child network namespace plays
# the guest (10.0.0.10, default route via the Sink), joined only by a veth pair. A stand-in INetSim
# answers DNS/HTTP/HTTPS. Runs the real sinkhole.sh (nft and iptables backends), the real
# catch-all and the real guest check, then the refusal cases and a loopback test of the catch-all.
# Usage: bash tests/netns_test.sh OUTDIR   (OUTDIR must not exist); then tests/evaluate.py OUTDIR
set -euo pipefail
KIT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [ "${1:-}" != --inside ]; then
    OUT=${1:?usage: netns_test.sh OUTDIR}
    [ ! -e "$OUT" ] || { echo "refusing: $OUT exists" >&2; exit 1; }
    mkdir -p "$OUT"
    OUT=$(cd "$OUT" && pwd)
    exec unshare -rn bash "${BASH_SOURCE[0]}" --inside "$OUT"
fi
OUT=$2
PIDS=()
cleanup() {
    local p
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    if [ -f "$OUT/state/catchall.pid" ]; then kill "$(cat "$OUT/state/catchall.pid")" 2>/dev/null || true; fi
}
trap cleanup EXIT

wait_port() {  # wait_port tcp|udp ADDR:PORT [present|absent]
    local flag=u want=${3:-present} i
    [ "$1" = tcp ] && flag=t
    for i in $(seq 1 100); do
        if ss -H -ln"$flag" | awk '{print $4}' | grep -qx "$2"; then
            [ "$want" = present ] && return 0
        else
            [ "$want" = absent ] && return 0
        fi
        sleep 0.05
    done
    echo "timeout waiting for $1 $2 $want" >&2
    return 1
}

# --- two namespaces joined by a veth pair -------------------------------------------------------
ip link set lo up
ip link add sinkif type veth peer name guestif
unshare -n sleep 3600 &
GPID=$!
PIDS+=("$GPID")
mine=$(readlink /proc/self/ns/net)
for _ in $(seq 1 100); do
    [ "$(readlink "/proc/$GPID/ns/net" 2>/dev/null || true)" != "$mine" ] && break
    sleep 0.02
done
ip link set guestif netns "$GPID"
ip addr add 10.0.0.1/24 brd + dev sinkif
ip link set sinkif up
G() { nsenter -t "$GPID" -n "$@"; }
G ip link set lo up
G ip addr add 10.0.0.10/24 brd + dev guestif
G ip link set guestif up
G ip route add default via 10.0.0.1
{ ip -br addr; echo; G ip -br addr; G ip route; } >"$OUT/topology.txt"

# --- stand-in INetSim -----------------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=sink.test \
    -keyout "$OUT/key.pem" -out "$OUT/cert.pem" >/dev/null 2>&1
python3 -I "$KIT/tests/fake_inetsim.py" --bind 10.0.0.1 --answer 10.0.0.1 \
    --cert "$OUT/cert.pem" --key "$OUT/key.pem" >"$OUT/fake_inetsim.log" 2>&1 &
FPID=$!
PIDS+=("$FPID")
wait_port udp 10.0.0.1:53 && wait_port tcp 10.0.0.1:53 && wait_port tcp 10.0.0.1:80 && wait_port tcp 10.0.0.1:443

export NO_SYSTEMD=1 SKIP_UFW_CHECK=1 STATE_DIR="$OUT/state" LOG_DIR="$OUT/log" LIB_DIR="$KIT"
SK() { bash "$KIT/sinkhole.sh" "$@"; }
SK render-nft sinkif udp/53 tcp/53 tcp/80 tcp/443 >"$OUT/render-nft.txt"
SK render-unit >"$OUT/hazim-sinkhole-catchall.service"

# --- both backends: on, check, burst, find, off, check again ---------------------------------------
for backend in nft iptables; do
    marker="hz${backend}$(date +%H%M%S)"
    echo "$marker" >"$OUT/$backend-marker.txt"
    BACKEND=$backend SK on >"$OUT/$backend-on.txt" 2>&1
    SK status >"$OUT/$backend-status-on.txt" 2>&1 || true
    G python3 -I "$KIT/sinkhole_guest_check.py" --sink 10.0.0.1 --marker "$marker" --skip-system-dns \
        --json-out "$OUT/$backend-check-on.json" >/dev/null || true
    G python3 -I "$KIT/tests/burst_client.py" --count 60 --marker "$marker" >"$OUT/$backend-burst.json"
    sleep 1.5
    SK status --find "$marker" >"$OUT/$backend-find.txt" 2>&1 || true
    SK off >"$OUT/$backend-off.txt" 2>&1
    SK status >"$OUT/$backend-status-off.txt" 2>&1 || true
    G python3 -I "$KIT/sinkhole_guest_check.py" --sink 10.0.0.1 --marker "${marker}off" --skip-system-dns \
        --json-out "$OUT/$backend-check-off.json" >/dev/null || true
    { nft list ruleset; iptables -t nat -S; } >"$OUT/$backend-rules-after-off.txt" 2>&1 || true
done

# --- refusals ---------------------------------------------------------------------------------------
refuse() {  # refuse NAME: "on" must fail
    if SK on >"$OUT/refuse-$1.txt" 2>&1; then echo "FAIL $1" >>"$OUT/refusals.txt"; SK off >/dev/null 2>&1 || true
    else echo "ok $1" >>"$OUT/refusals.txt"; fi
}
sysctl -qw net.ipv4.ip_forward=1
refuse forwarding-on
sysctl -qw net.ipv4.ip_forward=0
python3 -I -c 'import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.0.1", 64999)); s.listen(1); time.sleep(60)' &
BPID=$!
PIDS+=("$BPID")
wait_port tcp 10.0.0.1:64999
refuse port-in-use
kill "$BPID"
wait_port tcp 10.0.0.1:64999 absent
kill "$FPID"
wait_port tcp 10.0.0.1:80 absent
refuse inetsim-down
{ nft list ruleset; iptables -t nat -S; } >"$OUT/rules-after-refusals.txt" 2>&1 || true

# --- the catch-all on its own, on loopback: record budget, idle close, clean stop ------------------
python3 -I "$KIT/sinkhole_catchall.py" --bind 127.0.0.1 --port 65001 --log "$OUT/unit.jsonl" \
    --log-rate 5 --summary-every 1 --idle 1 --max-hold 5 >"$OUT/unit.out" 2>&1 &
UPID=$!
PIDS+=("$UPID")
wait_port tcp 127.0.0.1:65001 && wait_port udp 127.0.0.1:65001
python3 -I - >"$OUT/unit-client.json" <<'EOF'
import json, socket, time
quick = 0
for i in range(30):
    with socket.create_connection(("127.0.0.1", 65001), timeout=3) as s:
        s.sendall(b"0123456789")
    quick += 1
s = socket.create_connection(("127.0.0.1", 65001), timeout=5)
start = time.monotonic()
s.settimeout(5)
data = s.recv(16)
closed_after = round(time.monotonic() - start, 3)
s.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.sendto(b"udp-unit", ("127.0.0.1", 65001))
print(json.dumps({"quick": quick, "idle_data": data.hex(), "idle_closed_after_s": closed_after}))
EOF
sleep 2.5
kill -TERM "$UPID"
wait "$UPID" || true
echo done >"$OUT/finished.txt"
