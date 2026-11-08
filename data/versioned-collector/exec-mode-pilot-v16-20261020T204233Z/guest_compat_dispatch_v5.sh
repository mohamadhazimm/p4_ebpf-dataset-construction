#!/usr/bin/env bash
# Guest-side check (benign): can one raw_syscalls:sys_enter probe, gated by the x86
# TS_COMPAT bit, recover openat/connect/execve paths for amd64 and i386 busybox, and
# how do the named sys_enter_* tracepoints compare on the same workloads?
set -u
pw="$1"
work="$(mktemp -d)"
cd "$work"
src=/home/csci/Downloads/exec-mode-pilot-v16/samples
for m in amd64 i386; do mkdir -p "$m"
    /usr/bin/7z x -pinfected -so "$src/${m}-static_file_r1.zip" >"$m/busybox" 2>/dev/null
    chmod 755 "$m/busybox"
    echo "$m busybox: $(od -An -tx1 -j4 -N1 "$m/busybox") class byte, $(stat -c %s "$m/busybox") bytes"
done
sudo -S -p '' /usr/bin/bpftrace -e '
tracepoint:raw_syscalls:sys_enter /comm == "busybox"/ {
  $compat = (curtask->thread_info.status & 2) ? 1 : 0;
  @compat_by_comm[$compat, $compat] = count();
  if (($compat == 0 && args->id == 257) || ($compat == 1 && args->id == 295)) {
    @raw_openat[$compat] = count();
    if (str(uptr(args->args[1])) == "bb_file_workload.txt") { @raw_openat_path_ok[$compat] = count(); } }
  if (($compat == 0 && args->id == 42) || ($compat == 1 && args->id == 362)) {
    $sa = (uint64)args->args[1]; $fam = *uptr((uint16 *)$sa);
    $port = (*uptr((uint8 *)($sa + 2)) << 8) | *uptr((uint8 *)($sa + 3));
    @raw_connect[$compat, $fam, $port] = count(); }
  if ($compat == 1 && args->id == 102) { @i386_socketcall[$compat, args->args[0]] = count(); }
  if (($compat == 0 && args->id == 59) || ($compat == 1 && args->id == 11)) {
    @raw_execve[$compat, str(uptr(args->args[0]))] = count(); } }
tracepoint:raw_syscalls:sys_enter /comm == "ka-launch"/ {
  $compat = (curtask->thread_info.status & 2) ? 1 : 0;
  if ($compat == 0 && args->id == 59) { @raw_execve_launcher[str(uptr(args->args[0]))] = count(); } }
tracepoint:syscalls:sys_enter_execve /comm == "ka-launch"/ { @named_execve_launcher[str(uptr(args->filename))] = count(); }
tracepoint:syscalls:sys_enter_openat /comm == "busybox"/ { @named_enter_openat[(curtask->thread_info.status & 2) ? 1 : 0] = count(); }
tracepoint:syscalls:sys_exit_openat /comm == "busybox"/ { @named_exit_openat[(curtask->thread_info.status & 2) ? 1 : 0] = count(); }
tracepoint:syscalls:sys_enter_connect /comm == "busybox"/ { @named_enter_connect[(curtask->thread_info.status & 2) ? 1 : 0] = count(); }
END { printf("== END\n"); }' \
    <"$pw" >"$work/bt.out" 2>&1 &
for _ in $(seq 1 60); do grep -q 'Attached' "$work/bt.out" && break; sleep 0.5; done
loop='i=0; while [ $i -lt 300 ]; do echo $i > bb_file_workload.txt; read v < bb_file_workload.txt; i=$((i+1)); done'
for m in amd64 i386; do mkdir -p "$m"
    for r in 1 2; do
        "./$m/busybox" sh -c "$loop"; echo "$m file r$r rc=$? last=$(cat bb_file_workload.txt)"
        "./$m/busybox" wget -q -T 5 -O "net-$m.html" http://10.0.0.1/; echo "$m net r$r rc=$? bytes=$(stat -c %s "net-$m.html" 2>/dev/null || echo 0)"
        # exec through a launcher whose comm is ka-launch (bash copy), mimicking the runner wrapper.
        cp /bin/bash ./ka-launch 2>/dev/null
        ./ka-launch -c "exec ./$m/busybox true"; echo "$m exec r$r rc=$?"
        sleep 1
    done
done
sudo -S -p '' /usr/bin/pkill -INT -x bpftrace <"$pw"
for _ in $(seq 1 40); do pgrep -x bpftrace >/dev/null || break; sleep 0.5; done
echo "bpftrace still running: $(pgrep -x bpftrace || echo no)"
echo "== bpftrace output"; cat "$work/bt.out"
rm -f "$pw"
rm -rf "$work"
