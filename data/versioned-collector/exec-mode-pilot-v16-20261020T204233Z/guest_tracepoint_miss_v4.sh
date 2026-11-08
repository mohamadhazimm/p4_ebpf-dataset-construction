#!/usr/bin/env bash
# Guest-side check (benign): which syscall tracepoints miss events for a known workload
# (200 openat + 200 write + 200 close per leader-exit run)?
set -u
pw="$1"
work="$(mktemp -d)"
cd "$work"
/usr/bin/7z x -pinfected -o"$work" -y /home/csci/Downloads/exec-mode-pilot-v16/samples/amd64-static-threads_leader-exit_r1.zip >/dev/null
sudo -S -p '' /usr/bin/bpftrace -e '
tracepoint:syscalls:sys_enter_openat /comm == "thread-exec-ka"/ { @enter_openat[pid] = count(); }
tracepoint:syscalls:sys_exit_openat /comm == "thread-exec-ka"/ { @exit_openat[pid] = count(); }
tracepoint:syscalls:sys_enter_write /comm == "thread-exec-ka"/ { @enter_write[pid] = count(); }
tracepoint:syscalls:sys_exit_write /comm == "thread-exec-ka"/ { @exit_write[pid] = count(); }
tracepoint:syscalls:sys_enter_close /comm == "thread-exec-ka"/ { @enter_close[pid] = count(); }
tracepoint:raw_syscalls:sys_enter /comm == "thread-exec-ka" && args->id == 257/ {
  @raw_openat[pid] = count();
  if (str(uptr(args->args[1])) == "ka_leader_exit.txt") { @raw_openat_path_ok[pid] = count(); } }
tracepoint:raw_syscalls:sys_enter /comm == "thread-exec-ka" && args->id == 1/ { @raw_write[pid] = count(); }
tracepoint:raw_syscalls:sys_enter /comm == "thread-exec-ka" && args->id == 3/ { @raw_close[pid] = count(); }' \
    <"$pw" >"$work/bt.out" 2>&1 &
for _ in $(seq 1 60); do grep -q 'Attached' "$work/bt.out" && break; sleep 0.5; done
for i in 1 2 3; do
    ./thread-exec-ka leader-exit & p=$!; echo "run $i pid $p"; wait "$p"; sleep 2
done
tail -n 1 ka_leader_exit.txt
sudo -S -p '' /usr/bin/pkill -INT -x bpftrace <"$pw"
for _ in $(seq 1 40); do pgrep -x bpftrace >/dev/null || break; sleep 0.5; done; echo "bpftrace still running: $(pgrep -x bpftrace || echo no)"
echo "== bpftrace output"; cat "$work/bt.out"
rm -f "$pw"
rm -rf "$work"
