#!/usr/bin/env bash
# hazim-sinkhole: passive sinkhole for the isolated lab Sink. Run as root ON THE SINK.
#
# When on, traffic that the guest sends to any address other than the Sink itself is redirected
# on the Sink: DNS (udp/tcp 53), HTTP (tcp 80) and HTTPS (tcp 443) go to the INetSim services
# already running there, and every other TCP/UDP port goes to a silent catch-all listener that
# logs the connection and its first bytes and never sends anything back. IRC and every other
# port fall into the silent listener on purpose. Traffic addressed to the Sink's own address is
# not touched, so today's lab behaviour stays exactly as it is.
# Nothing is persistent: "off", or a Sink reboot, removes the rules and stops the listener.
#
# Usage: hazim-sinkhole install | on | off | status [--find MARKER] | uninstall
set -euo pipefail

SINK_IP=${SINK_IP:-10.0.0.1}
GUEST_IP=${GUEST_IP:-10.0.0.10}
CATCH_PORT=${CATCH_PORT:-64999}
STATE_DIR=${STATE_DIR:-/var/lib/hazim-sinkhole}
LOG_DIR=${LOG_DIR:-/var/log/hazim-sinkhole}
LIB_DIR=${LIB_DIR:-/usr/local/lib/hazim-sinkhole}
BIN_PATH=${BIN_PATH:-/usr/local/sbin/hazim-sinkhole}
NO_SYSTEMD=${NO_SYSTEMD:-0}        # 1 = run the listener as a plain background process (tests)
BACKEND=${BACKEND:-auto}           # auto | nft | iptables
SKIP_UFW_CHECK=${SKIP_UFW_CHECK:-0}
FORCE=${FORCE:-0}                  # 1 = switch on even if INetSim DNS/HTTP are not listening
UNIT=hazim-sinkhole-catchall.service
UNIT_PATH=/etc/systemd/system/$UNIT
TABLE=hazim_sinkhole
CHAIN=HAZIM_SINKHOLE
CANDIDATES="udp/53 tcp/53 tcp/80 tcp/443"
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_FILE=$LOG_DIR/catchall.jsonl

die() { echo "hazim-sinkhole: $*" >&2; exit 1; }
say() { echo "hazim-sinkhole: $*"; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }
have() { command -v "$1" >/dev/null 2>&1; }

iface_for_ip() {
    ip -o -4 addr show | awk -v ip="$SINK_IP" '{split($4, a, "/"); if (a[1] == ip) {print $2; exit}}'
}

broadcast_of() {
    ip -o -4 addr show dev "$1" | awk -v ip="$SINK_IP" \
        '{split($4, a, "/"); if (a[1] == ip) for (i = 1; i < NF; i++) if ($i == "brd") {print $(i + 1); exit}}'
}

listening() {  # listening tcp|udp PORT: something is bound on SINK_IP or a wildcard address
    local flag=u
    [ "$1" = tcp ] && flag=t
    ss -H -ln"$flag" 2>/dev/null | awk '{print $4}' \
        | grep -qE "^(${SINK_IP//./\\.}|0\\.0\\.0\\.0|\\*|\\[::\\]):$2\$"
}

mapped_ports() {  # INetSim ports among the candidates that are listening now
    local c
    for c in $CANDIDATES; do
        if listening "${c%/*}" "${c#*/}"; then echo "$c"; fi
    done
    return 0
}

pick_backend() {
    case "$BACKEND" in
        nft) have nft || die "nft not found"; echo nft ;;
        iptables) have iptables || die "iptables not found"; echo iptables ;;
        auto) if have nft; then echo nft; elif have iptables; then echo iptables
              else die "need nft or iptables"; fi ;;
        *) die "unknown BACKEND=$BACKEND" ;;
    esac
}

check_ufw() {
    [ "$SKIP_UFW_CHECK" = 1 ] && return 0
    have ufw || return 0
    if ufw status 2>/dev/null | head -1 | grep -q 'Status: active'; then
        die "ufw is active and may block the listener port. Allow it first, then rerun:
  ufw allow in proto tcp to $SINK_IP port $CATCH_PORT
  ufw allow in proto udp to $SINK_IP port $CATCH_PORT"
    fi
}

render_nft() {  # render_nft IFACE [proto/port ...]
    local iface=$1 bcast m elements
    shift
    bcast=$(broadcast_of "$iface")
    elements="$SINK_IP, 224.0.0.0/4, 255.255.255.255${bcast:+, $bcast}"
    cat <<EOF
add table ip $TABLE
delete table ip $TABLE
table ip $TABLE {
    set exclude_dst {
        type ipv4_addr
        flags interval
        elements = { $elements }
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "$iface" meta pkttype host ip saddr $GUEST_IP ip daddr != @exclude_dst jump to_sinkhole
    }
    chain to_sinkhole {
EOF
    for m in "$@"; do echo "        ${m%/*} dport ${m#*/} counter redirect"; done
    cat <<EOF
        tcp dport 1-65535 counter redirect to :$CATCH_PORT
        udp dport 1-65535 counter redirect to :$CATCH_PORT
    }
}
EOF
}

load_nft() {
    render_nft "$@" | nft -f -
}

load_iptables() {  # load_iptables IFACE [proto/port ...]
    local iface=$1 bcast d m
    shift
    bcast=$(broadcast_of "$iface")
    iptables -t nat -N "$CHAIN" || return 1
    for d in "$SINK_IP" 224.0.0.0/4 255.255.255.255 $bcast; do
        iptables -t nat -A "$CHAIN" -d "$d" -j RETURN || return 1
    done
    for m in "$@"; do
        iptables -t nat -A "$CHAIN" -p "${m%/*}" --dport "${m#*/}" -j REDIRECT || return 1
    done
    iptables -t nat -A "$CHAIN" -p tcp -j REDIRECT --to-ports "$CATCH_PORT" || return 1
    iptables -t nat -A "$CHAIN" -p udp -j REDIRECT --to-ports "$CATCH_PORT" || return 1
    iptables -t nat -I PREROUTING 1 -i "$iface" -s "$GUEST_IP" -j "$CHAIN" || return 1
}

unload_all() {
    if have nft; then nft delete table ip "$TABLE" 2>/dev/null || true; fi
    if have iptables; then
        local rule
        while rule=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -e "-j $CHAIN\$" | head -1) \
              && [ -n "$rule" ]; do
            # shellcheck disable=SC2086  # the saved rule is split back into its words on purpose
            iptables -t nat ${rule/-A /-D } || break
        done
        iptables -t nat -F "$CHAIN" 2>/dev/null || true
        iptables -t nat -X "$CHAIN" 2>/dev/null || true
    fi
}

rules_present() {
    if have nft && nft list table ip "$TABLE" >/dev/null 2>&1; then return 0; fi
    if have iptables && iptables -t nat -S "$CHAIN" >/dev/null 2>&1; then return 0; fi
    return 1
}

stop_catchall() {
    if [ "$NO_SYSTEMD" = 1 ]; then
        if [ -f "$STATE_DIR/catchall.pid" ]; then
            kill "$(cat "$STATE_DIR/catchall.pid")" 2>/dev/null || true
            rm -f "$STATE_DIR/catchall.pid"
        fi
    elif have systemctl; then
        systemctl stop "$UNIT" 2>/dev/null || true
    fi
    local i
    for i in $(seq 1 60); do
        listening tcp "$CATCH_PORT" || listening udp "$CATCH_PORT" || return 0
        sleep 0.1
    done
    return 0
}

start_catchall() {
    stop_catchall
    if listening tcp "$CATCH_PORT" || listening udp "$CATCH_PORT"; then
        die "port $CATCH_PORT is already in use on $SINK_IP; set CATCH_PORT to a free port"
    fi
    if [ "$NO_SYSTEMD" = 1 ]; then
        mkdir -p "$LOG_DIR" "$STATE_DIR"
        nohup python3 -I "$LIB_DIR/sinkhole_catchall.py" --bind "$SINK_IP" --port "$CATCH_PORT" \
            --log "$LOG_FILE" >>"$STATE_DIR/catchall.out" 2>&1 &
        echo $! >"$STATE_DIR/catchall.pid"
    else
        [ -f "$UNIT_PATH" ] || die "not installed; run: hazim-sinkhole install"
        systemctl start "$UNIT"
    fi
    local i
    for i in $(seq 1 60); do
        if listening tcp "$CATCH_PORT" && listening udp "$CATCH_PORT"; then return 0; fi
        sleep 0.1
    done
    die "the catch-all listener did not start on $SINK_IP:$CATCH_PORT"
}

write_state() {  # write_state STATUS BACKEND IFACE "MAPPED"
    local m list=""
    for m in $4; do list="$list${list:+, }\"$m\""; done
    mkdir -p "$STATE_DIR"
    cat >"$STATE_DIR/state.json" <<EOF
{"status": "$1", "backend": "$2", "iface": "$3", "sink_ip": "$SINK_IP", "guest_ip": "$GUEST_IP", "catch_port": $CATCH_PORT, "inetsim_ports": [$list], "changed_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
EOF
}

state_is_on() { [ -f "$STATE_DIR/state.json" ] && grep -q '"status": "on"' "$STATE_DIR/state.json"; }

record_before() {  # what the Sink looked like before install
    local dir
    dir=$STATE_DIR/before-$(date -u +%Y%m%dT%H%M%SZ)
    mkdir -p "$dir"
    { ip -4 addr; echo; ip route; } >"$dir/network.txt" 2>&1 || true
    ss -lntup >"$dir/listening.txt" 2>&1 || true
    cat /proc/sys/net/ipv4/ip_forward >"$dir/ip_forward.txt" 2>&1 || true
    if have nft; then nft list ruleset >"$dir/nft-ruleset.txt" 2>&1 || true; fi
    if have iptables-save; then iptables-save >"$dir/iptables-save.txt" 2>&1 || true; fi
    if have systemctl; then systemctl is-active inetsim >"$dir/inetsim-active.txt" 2>&1 || true; fi
    if [ -f /etc/inetsim/inetsim.conf ]; then sha256sum /etc/inetsim/inetsim.conf >"$dir/inetsim-conf.sha256"; fi
    echo "$dir"
}

write_unit() { render_unit >"$UNIT_PATH"; }

render_unit() {
    cat <<EOF
[Unit]
Description=Hazim lab sinkhole: silent catch-all listener (logs only, never sends data)

[Service]
Type=simple
ExecStart=/usr/bin/python3 -I $LIB_DIR/sinkhole_catchall.py --bind $SINK_IP --port $CATCH_PORT --log $LOG_FILE
DynamicUser=yes
LogsDirectory=$(basename "$LOG_DIR")
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
MemoryMax=256M
TasksMax=640
Restart=no
EOF
}

cmd_install() {
    need_root
    local src="" f before
    for f in "$HERE/sinkhole_catchall.py" "$HERE/hazim-sinkhole_catchall.py"; do
        if [ -f "$f" ]; then src=$f; break; fi
    done
    [ -n "$src" ] || die "sinkhole_catchall.py not found next to this script"
    have python3 || die "python3 not found"
    have nft || have iptables || die "need nft or iptables"
    have systemctl || die "systemctl not found (use NO_SYSTEMD=1 only for tests)"
    before=$(record_before)
    install -D -m 0644 "$src" "$LIB_DIR/sinkhole_catchall.py"
    if [ "$(readlink -f "${BASH_SOURCE[0]}")" != "$(readlink -f "$BIN_PATH" 2>/dev/null || true)" ]; then
        install -D -m 0755 "${BASH_SOURCE[0]}" "$BIN_PATH"
    fi
    write_unit
    systemctl daemon-reload
    sha256sum "$BIN_PATH" "$LIB_DIR/sinkhole_catchall.py" "$UNIT_PATH" >"$STATE_DIR/installed.sha256"
    say "installed $BIN_PATH, $LIB_DIR/sinkhole_catchall.py and $UNIT_PATH"
    say "saved the Sink's current network state in $before"
    say "nothing is switched on yet; next: sudo hazim-sinkhole on"
}

cmd_on() {
    need_root
    local iface fwd mapped backend
    iface=$(iface_for_ip)
    [ -n "$iface" ] || die "no interface has $SINK_IP"
    fwd=$(cat /proc/sys/net/ipv4/ip_forward)
    [ "$fwd" = 0 ] || die "net.ipv4.ip_forward=$fwd; the sinkhole answers locally and needs forwarding off"
    check_ufw
    mapped=$(mapped_ports)
    if ! grep -qx 'udp/53' <<<"$mapped" || ! grep -qx 'tcp/80' <<<"$mapped"; then
        [ "$FORCE" = 1 ] || die "INetSim is not listening on udp/53 and tcp/80 at $SINK_IP; restart INetSim first (FORCE=1 overrides)"
    fi
    backend=$(pick_backend)
    start_catchall
    unload_all
    # shellcheck disable=SC2086  # one word per mapped port
    if [ "$backend" = nft ]; then
        load_nft "$iface" $mapped || { stop_catchall; die "loading the nft rules failed"; }
    else
        load_iptables "$iface" $mapped || { unload_all; stop_catchall; die "loading the iptables rules failed"; }
    fi
    write_state on "$backend" "$iface" "$mapped"
    say "ON: guest $GUEST_IP -> any address but $SINK_IP is redirected on $iface ($backend)"
    say "    to INetSim: $(echo $mapped)"
    say "    all other TCP/UDP ports -> silent listener $SINK_IP:$CATCH_PORT (log $LOG_FILE)"
}

cmd_off() {
    need_root
    unload_all
    stop_catchall
    write_state off none "" ""
    if rules_present; then die "rules are still present after off"; fi
    if listening tcp "$CATCH_PORT" || listening udp "$CATCH_PORT"; then die "the listener is still running"; fi
    say "OFF: rules removed and listener stopped (logs kept in $LOG_DIR)"
}

cmd_status() {
    need_root
    local find="" iface fwd mapped problems="" m state=off backend=none
    if [ "${1:-}" = --find ]; then find=${2:?usage: status --find MARKER}; fi
    iface=$(iface_for_ip)
    fwd=$(cat /proc/sys/net/ipv4/ip_forward)
    mapped=$(mapped_ports)
    if state_is_on; then
        state=on
        backend=$(sed -n 's/.*"backend": "\([a-z]*\)".*/\1/p' "$STATE_DIR/state.json")
    fi
    echo "state:              $state (backend $backend)"
    echo "sink address:       $SINK_IP on ${iface:-<none>}"
    echo "ip_forward:         $fwd"
    echo "INetSim listening:  $(echo $mapped)"
    if listening tcp "$CATCH_PORT" && listening udp "$CATCH_PORT"; then
        echo "catch-all:          listening on $SINK_IP:$CATCH_PORT (tcp+udp)"
    else
        echo "catch-all:          not listening"
    fi
    if [ -f "$LOG_FILE" ]; then
        echo "log:                $LOG_FILE ($(grep -c '"type": "tcp"' "$LOG_FILE" || true) tcp, $(grep -c '"type": "udp"' "$LOG_FILE" || true) udp records)"
    else
        echo "log:                $LOG_FILE (none yet)"
    fi
    if [ "$state" = on ]; then
        if have nft && nft list table ip "$TABLE" >/dev/null 2>&1; then
            echo "--- nft table ip $TABLE (counters = new connections/flows)"
            nft list table ip "$TABLE"
        elif have iptables && iptables -t nat -S "$CHAIN" >/dev/null 2>&1; then
            echo "--- iptables nat $CHAIN"
            iptables -t nat -L "$CHAIN" -n -v
        else
            problems="$problems rules-missing"
        fi
        [ "$fwd" = 0 ] || problems="$problems ip_forward-on"
        listening tcp "$CATCH_PORT" && listening udp "$CATCH_PORT" || problems="$problems listener-down"
        for m in $(sed -n 's/.*"inetsim_ports": \[\([^]]*\)\].*/\1/p' "$STATE_DIR/state.json" | tr -d '",'); do
            listening "${m%/*}" "${m#*/}" || problems="$problems inetsim-$m-down"
        done
        if [ -n "$problems" ]; then echo "overall:            NOT OK:$problems"; else echo "overall:            OK"; fi
    else
        rules_present && problems="$problems rules-present-while-off"
        if [ -n "$problems" ]; then echo "overall:            NOT OK:$problems"; else echo "overall:            off"; fi
    fi
    if [ -n "$find" ]; then
        echo "--- records containing $find"
        if [ -f "$LOG_FILE" ]; then grep -F -- "$find" "$LOG_FILE" || echo "(none)"; else echo "(no log)"; fi
    fi
    if [ "$state" = on ] && [ -n "$problems" ]; then return 1; fi
    return 0
}

cmd_uninstall() {
    need_root
    cmd_off
    rm -f "$UNIT_PATH" "$LIB_DIR/sinkhole_catchall.py"
    rmdir "$LIB_DIR" 2>/dev/null || true
    if have systemctl; then systemctl daemon-reload; fi
    say "uninstalled the unit and the listener (kept $STATE_DIR and $LOG_DIR; $BIN_PATH removed last)"
    rm -f "$BIN_PATH"
}

case "${1:-}" in
    install) cmd_install ;;
    on) cmd_on ;;
    off) cmd_off ;;
    status) shift; cmd_status "$@" ;;
    uninstall) cmd_uninstall ;;
    render-nft) shift; render_nft "$@" ;;   # print the nft rules for an interface (review/tests)
    render-unit) render_unit ;;             # print the systemd unit (review/tests)
    *) echo "usage: hazim-sinkhole install | on | off | status [--find MARKER] | uninstall" >&2; exit 2 ;;
esac
