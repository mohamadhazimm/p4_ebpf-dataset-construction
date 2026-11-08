#!/usr/bin/env bash
# Guest-side check (benign): do syscall tracepoints keep firing for a known workload
# at different delays after bpftrace attaches?
set -u
pw="$1"
work="$(mktemp -d)"
cd "$work"
/usr/bin/7z x -pinfected -o"$work" -y /home/csci/Downloads/exec-mode-pilot-v16/samples/amd64-static-threads_leader-exit_r1.zip >/dev/null
sudo -S -p '' /usr/bin/bpftrace -e '
tracepoint:syscalls:sys_enter_openat /comm == "thread-exec-ka" || comm == "sh" || comm == "cat"/ {
  @openat[pid, comm] = count(); }
tracepoint:raw_syscalls:sys_enter /comm == "thread-exec-ka" || comm == "cat"/ {
  @raw[pid, comm] = count(); }
tracepoint:syscalls:sys_exit_write /comm == "thread-exec-ka" || comm == "cat"/ {
  @write_exit[pid, comm] = count(); }
tracepoint:sched:sched_process_exit /comm == "thread-exec-ka" || comm == "cat"/ {
  printf("exit pid=%d tid=%d comm=%s\n", pid, tid, comm); }' <"$pw" >"$work/bt.out" 2>&1 &
for _ in $(seq 1 60); do grep -q 'Attached' "$work/bt.out" && break; sleep 0.5; done
echo "== attached"; date +%T.%N
echo "== t+0 cat"; cat /etc/hostname >/dev/null
echo "== t+0 leader-exit"; ./thread-exec-ka leader-exit & p=$!; echo "pid $p"; wait "$p"
sleep 5
echo "== t+5 cat"; cat /etc/hostname >/dev/null
echo "== t+5 exec"; ./thread-exec-ka exec & p=$!; echo "pid $p"; wait "$p"
sleep 10
echo "== t+15 leader-exit"; ./thread-exec-ka leader-exit & p=$!; echo "pid $p"; wait "$p"
echo "== t+15 cat"; cat /etc/hostname >/dev/null
tail -n 1 ka_leader_exit.txt; tail -n 1 ka_thread_exec.txt
sudo -S -p '' /usr/bin/pkill -INT -x bpftrace <"$pw"
sleep 2
echo "== bpftrace output"; cat "$work/bt.out"
rm -f "$pw"
rm -rf "$work"
