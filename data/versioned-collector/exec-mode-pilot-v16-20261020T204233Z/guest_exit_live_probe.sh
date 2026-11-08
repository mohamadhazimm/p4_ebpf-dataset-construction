#!/usr/bin/env bash
# Guest-side check (benign): does bpftrace accept curtask->signal->live.counter in
# sched_process_exit, and what values does it report for leader-exit / thread-exec?
set -u
pw="$1"
work="$(mktemp -d)"
cd "$work"
echo "== uname"; uname -r
echo "== bpftrace"; /usr/bin/bpftrace --version
echo "== sched_process_exit format"
sudo -S -p '' cat /sys/kernel/tracing/events/sched/sched_process_exit/format <"$pw" 2>&1 | grep -E 'field:|print fmt' || true
/usr/bin/7z x -pinfected -o"$work" -y /home/csci/Downloads/exec-mode-pilot-v16/samples/amd64-static-threads_leader-exit_r1.zip >/dev/null
sha256sum "$work/thread-exec-ka"
sudo -S -p '' /usr/bin/bpftrace -e '
tracepoint:sched:sched_process_exit /comm == "thread-exec-ka" || comm == "sh"/ {
  printf("exit pid=%d tid=%d comm=%s live=%d\n", pid, tid, comm, curtask->signal->live.counter); }
tracepoint:sched:sched_process_exec /comm == "sh"/ {
  printf("exec pid=%d tid=%d old_pid=%d\n", pid, tid, args->old_pid); }
tracepoint:syscalls:sys_enter_openat /comm == "thread-exec-ka" || comm == "sh"/ {
  @opens[pid, tid, comm] = count(); }' <"$pw" >"$work/bt.out" 2>&1 &
for _ in $(seq 1 60); do grep -q Attaching "$work/bt.out" && break; sleep 0.5; done
echo "== bpftrace startup"; head -3 "$work/bt.out"
echo "== run leader-exit"; ./thread-exec-ka leader-exit; echo "rc=$?"; sleep 0.3
echo "== run exec"; ./thread-exec-ka exec; echo "rc=$?"; sleep 0.3
tail -2 ka_leader_exit.txt ka_thread_exec.txt 2>&1
sudo -S -p '' /usr/bin/pkill -INT -x bpftrace <"$pw"
sleep 2
echo "== bpftrace output"; cat "$work/bt.out"
rm -f "$pw"
rm -rf "$work"
