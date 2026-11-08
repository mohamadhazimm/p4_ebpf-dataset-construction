#!/usr/bin/env bash
# Guest-side check (benign): which busybox network applet reaches the internal Sink
# (10.0.0.1) for each pilot mode, and does the TS_COMPAT-gated raw connect read work?
set -u
pw="$1"
work="$(mktemp -d)"
cd "$work"
src=/home/csci/Downloads/exec-mode-pilot-v16/samples
modes="amd64-static amd64-dynamic i386-static armel-static mipsel-static arm64-static"
for m in $modes; do
    mkdir -p "$m"
    /usr/bin/7z x -pinfected -so "$src/${m}_file_r1.zip" >"$m/busybox" 2>/dev/null
    chmod 755 "$m/busybox"
done
echo "applets(amd64-static): $(./amd64-static/busybox --list | grep -Ex 'nc|wget|telnet|ping|ftpget|httpd|nslookup' | tr '\n' ' ')"
sudo -S -p '' /usr/bin/bpftrace -e '
tracepoint:raw_syscalls:sys_enter /comm == "busybox"/ {
  $compat = (curtask->thread_info.status & 2) ? 1 : 0;
  if (($compat == 0 && args->id == 42) || ($compat == 1 && args->id == 362)) {
    $sa = (uint64)args->args[1]; $fam = *uptr((uint16 *)$sa);
    $port = (*uptr((uint8 *)($sa + 2)) << 8) | *uptr((uint8 *)($sa + 3));
    printf("RAWCONNECT pid=%d compat=%d fam=%d port=%d\n", pid, $compat, $fam, $port); }
  if ($compat == 1 && args->id == 102) { printf("SOCKETCALL pid=%d call=%d\n", pid, args->args[0]); } }
tracepoint:syscalls:sys_enter_connect /comm == "busybox"/ { printf("NAMEDCONNECT pid=%d\n", pid); }' \
    <"$pw" >"$work/bt.out" 2>&1 &
for _ in $(seq 1 60); do grep -q 'Attached' "$work/bt.out" && break; sleep 0.5; done
req='GET / HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n'
for m in $modes; do
    rm -f out.html
    (cd "$m" && timeout 15 ./busybox wget -q -T 5 -O ../out.html http://10.0.0.1/); rc=$?
    echo "$m wget rc=$rc bytes=$(stat -c %s out.html 2>/dev/null || echo 0)"
    out="$(cd "$m" && printf "$req" | timeout 15 ./busybox nc -w 3 10.0.0.1 80 2>&1 | head -c 200 | tr '\r\n' '  ')"; rc=$?
    echo "$m nc rc=$rc head=${out:0:60}"
done
sleep 1
sudo -S -p '' /usr/bin/pkill -INT -x bpftrace <"$pw"
for _ in $(seq 1 40); do pgrep -x bpftrace >/dev/null || break; sleep 0.5; done
echo "== bpftrace output"; cat "$work/bt.out"
rm -f "$pw"
rm -rf "$work"
