#!/usr/bin/env bash
# Guest-side check (benign): does bpftrace accept curtask->signal->live.counter in
# sched_process_exit, and does the proposed liveness-aware @tracked deletion keep
# leader-exit and non-leader-thread exec workloads visible?
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
tracepoint:sched:sched_process_exec /str(args->filename) == "./thread-exec-ka"/ { @tracked[pid] = 1;
  printf("track pid=%d\n", pid); }
tracepoint:sched:sched_process_fork /@tracked[args->parent_pid]/ { @tracked[args->child_pid] = 1; }
tracepoint:sched:sched_process_exit /@tracked[pid]/ {
  $live = curtask->signal->live.counter;
  printf("exit pid=%d tid=%d comm=%s live=%d group_dead=%d\n", pid, tid, comm, $live, args->group_dead);
  if (tid != pid) { delete(@tracked[tid]); }
  if ($live == 0) { delete(@tracked[pid]); } }
tracepoint:sched:sched_process_exec /@tracked[pid]/ {
  printf("exec pid=%d tid=%d old_pid=%d filename=%s\n", pid, tid, args->old_pid, str(args->filename)); }
tracepoint:syscalls:sys_enter_openat /@tracked[pid]/ {
  printf("openat pid=%d tid=%d comm=%s path=%s\n", pid, tid, comm, str(uptr(args->filename))); }' <"$pw" >"$work/bt.out" 2>&1 &
for _ in $(seq 1 60); do grep -q Attaching "$work/bt.out" && break; sleep 0.5; done
echo "== bpftrace startup"; head -3 "$work/bt.out"
echo "== run leader-exit"; ./thread-exec-ka leader-exit; echo "rc=$?"; sleep 0.3
echo "== run exec"; ./thread-exec-ka exec; echo "rc=$?"; sleep 0.3
tail -n 1 ka_leader_exit.txt; tail -n 1 ka_thread_exec.txt
sudo -S -p '' /usr/bin/pkill -INT -x bpftrace <"$pw"
sleep 2
echo "== bpftrace non-openat output"; grep -v '^openat' "$work/bt.out"
echo "== openat counts (pid tid comm path)"
grep '^openat' "$work/bt.out" | awk '{print $2, $3, $4, $5}' | sort | uniq -c
rm -f "$pw"
rm -rf "$work"
