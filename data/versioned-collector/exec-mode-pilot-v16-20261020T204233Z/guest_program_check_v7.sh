#!/usr/bin/env bash
# Guest-side v7 check (benign): exact schema .16 bpftrace program, runner SHA
# f235d011606e9b885e3339fbf234692ee463a3fd2638195f97de4d0df228d8ca. Workloads are benign busybox/thread known-answer cases only.
set -u
pw="$1"
work="$(mktemp -d)"; cd "$work"
src=/home/csci/Downloads/exec-mode-pilot-v16/samples
for m in amd64-static i386-static armel-static; do mkdir -p "$m"
    /usr/bin/7z x -pinfected -so "$src/${m}_file_r1.zip" >"$m/busybox" 2>/dev/null; chmod 755 "$m/busybox"
done
/usr/bin/7z x -pinfected -o"$work" -y "$src/amd64-static-threads_leader-exit_r1.zip" >/dev/null
cat >program.bt <<'PROGRAM_EOF'
tracepoint:raw_syscalls:sys_enter /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tsyscall\tid=%d\n", nsecs, pid, tid, comm, args->id); $compat = (curtask->thread_info.status & 2) ? 1 : 0; $id = args->id; if (($compat == 0 && $id == 59) || ($compat == 1 && $id == 11)) { printf("EBPF\t%llu\t%d\t%d\t%s\texecve\tpath=%s\n", nsecs, pid, tid, comm, str(uptr(args->args[0]))); } else if (($compat == 0 && $id == 322) || ($compat == 1 && $id == 358)) { printf("EBPF\t%llu\t%d\t%d\t%s\texecveat\tpath=%s\n", nsecs, pid, tid, comm, str(uptr(args->args[1]))); } else if (($compat == 0 && $id == 257) || ($compat == 1 && $id == 295)) { printf("EBPF\t%llu\t%d\t%d\t%s\topenat\tpath=%s flags=%lu\n", nsecs, pid, tid, comm, str(uptr(args->args[1])), args->args[2]); } else if (($compat == 0 && $id == 437) || ($compat == 1 && $id == 437)) { printf("EBPF\t%llu\t%d\t%d\t%s\topenat2\tpath=%s\n", nsecs, pid, tid, comm, str(uptr(args->args[1]))); } else if (($compat == 0 && $id == 264) || ($compat == 1 && $id == 302)) { printf("EBPF\t%llu\t%d\t%d\t%s\trenameat\tpath=%s dest=%s\n", nsecs, pid, tid, comm, str(uptr(args->args[1])), str(uptr(args->args[3]))); } else if (($compat == 0 && $id == 316) || ($compat == 1 && $id == 353)) { printf("EBPF\t%llu\t%d\t%d\t%s\trenameat2\tpath=%s dest=%s\n", nsecs, pid, tid, comm, str(uptr(args->args[1])), str(uptr(args->args[3]))); } else if (($compat == 0 && $id == 263) || ($compat == 1 && $id == 301)) { printf("EBPF\t%llu\t%d\t%d\t%s\tunlinkat\tpath=%s\n", nsecs, pid, tid, comm, str(uptr(args->args[1]))); } else if (($compat == 0 && $id == 42) || ($compat == 1 && $id == 362)) { $sa = (uint64)(args->args[1]); $salen = (uint64)(args->args[2]); $family = 0; if ($sa != 0 && $salen >= 2) { $family = *uptr((uint16 *)$sa); } if ($sa != 0 && $salen >= 16 && $family == 2) { $port = (*uptr((uint8 *)($sa + 2)) << 8) | *uptr((uint8 *)($sa + 3)); $address = (*uptr((uint8 *)($sa + 4)) << 24) | (*uptr((uint8 *)($sa + 5)) << 16) | (*uptr((uint8 *)($sa + 6)) << 8) | *uptr((uint8 *)($sa + 7)); printf("EBPF\t%llu\t%d\t%d\t%s\tconnect\taddr=%u port=%u family=%u\n", nsecs, pid, tid, comm, $address, $port, $family); } else { printf("EBPF\t%llu\t%d\t%d\t%s\tconnect\taddr=0 port=0 family=%u\n", nsecs, pid, tid, comm, $family); } } else if ($compat == 1 && $id == 102) { $call = args->args[0]; $a = (uint64)args->args[1]; if ($call == 3) { $sa = (uint64)(*uptr((uint32 *)($a + 4))); $salen = (uint64)(*uptr((uint32 *)($a + 8))); $family = 0; if ($sa != 0 && $salen >= 2) { $family = *uptr((uint16 *)$sa); } if ($sa != 0 && $salen >= 16 && $family == 2) { $port = (*uptr((uint8 *)($sa + 2)) << 8) | *uptr((uint8 *)($sa + 3)); $address = (*uptr((uint8 *)($sa + 4)) << 24) | (*uptr((uint8 *)($sa + 5)) << 16) | (*uptr((uint8 *)($sa + 6)) << 8) | *uptr((uint8 *)($sa + 7)); printf("EBPF\t%llu\t%d\t%d\t%s\tconnect\taddr=%u port=%u family=%u\n", nsecs, pid, tid, comm, $address, $port, $family); } else { printf("EBPF\t%llu\t%d\t%d\t%s\tconnect\taddr=0 port=0 family=%u\n", nsecs, pid, tid, comm, $family); } } else if ($call == 1) { printf("EBPF\t%llu\t%d\t%d\t%s\tsocket\t-\n", nsecs, pid, tid, comm); } else if ($call == 2) { printf("EBPF\t%llu\t%d\t%d\t%s\tbind\t-\n", nsecs, pid, tid, comm); } else if ($call == 4) { printf("EBPF\t%llu\t%d\t%d\t%s\tlisten\t-\n", nsecs, pid, tid, comm); } else if ($call == 5) { printf("EBPF\t%llu\t%d\t%d\t%s\taccept\t-\n", nsecs, pid, tid, comm); } else if ($call == 11) { printf("EBPF\t%llu\t%d\t%d\t%s\tsendto\t-\n", nsecs, pid, tid, comm); } else if ($call == 12) { printf("EBPF\t%llu\t%d\t%d\t%s\trecvfrom\t-\n", nsecs, pid, tid, comm); } else if ($call == 18) { printf("EBPF\t%llu\t%d\t%d\t%s\taccept4\t-\n", nsecs, pid, tid, comm); } } }
tracepoint:raw_syscalls:sys_exit /@tracked[pid] && (curtask->thread_info.status & 2)/ { $id = args->id; $ret = args->ret; if ($id == 295 && $ret >= 0) { printf("EBPF\t%llu\t%d\t%d\t%s\topenat_success\tfd=%ld\n", nsecs, pid, tid, comm, $ret); } else if ($id == 437 && $ret >= 0) { printf("EBPF\t%llu\t%d\t%d\t%s\topenat2_success\tfd=%ld\n", nsecs, pid, tid, comm, $ret); } else if ($id == 4 && $ret > 0) { printf("EBPF\t%llu\t%d\t%d\t%s\tfile_write_success\tbytes=%ld\n", nsecs, pid, tid, comm, $ret); } else if ($id == 181 && $ret > 0) { printf("EBPF\t%llu\t%d\t%d\t%s\tfile_pwrite64_success\tbytes=%ld\n", nsecs, pid, tid, comm, $ret); } else if ($id == 146 && $ret > 0) { printf("EBPF\t%llu\t%d\t%d\t%s\tfile_writev_success\tbytes=%ld\n", nsecs, pid, tid, comm, $ret); } else if ($id == 11) { printf("EBPF\t%llu\t%d\t%d\t%s\texec_return\tsyscall=execve ret=%ld\n", nsecs, pid, tid, comm, $ret); } else if ($id == 358) { printf("EBPF\t%llu\t%d\t%d\t%s\texec_return\tsyscall=execveat ret=%ld\n", nsecs, pid, tid, comm, $ret); } }
tracepoint:syscalls:sys_enter_sendto /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tsendto\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_recvfrom /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\trecvfrom\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_write /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\twrite\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_pwrite64 /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tpwrite64\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_writev /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\twritev\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_close /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tclose\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_dup2 /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tdup2\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_dup3 /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tdup3\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_socket /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tsocket\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_bind /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tbind\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_listen /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tlisten\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_accept /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\taccept\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_accept4 /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\taccept4\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_mmap /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tmmap\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_mprotect /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tmprotect\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_ptrace /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tptrace\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_enter_kill /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\tkill\t-\n", nsecs, pid, tid, comm); }
tracepoint:syscalls:sys_exit_openat /@tracked[pid]/ { if (args->ret >= 0) { printf("EBPF\t%llu\t%d\t%d\t%s\topenat_success\tfd=%ld\n", nsecs, pid, tid, comm, args->ret); } }
tracepoint:syscalls:sys_exit_openat2 /@tracked[pid]/ { if (args->ret >= 0) { printf("EBPF\t%llu\t%d\t%d\t%s\topenat2_success\tfd=%ld\n", nsecs, pid, tid, comm, args->ret); } }
tracepoint:syscalls:sys_exit_write /@tracked[pid]/ { if (args->ret > 0) { printf("EBPF\t%llu\t%d\t%d\t%s\tfile_write_success\tbytes=%ld\n", nsecs, pid, tid, comm, args->ret); } }
tracepoint:syscalls:sys_exit_pwrite64 /@tracked[pid]/ { if (args->ret > 0) { printf("EBPF\t%llu\t%d\t%d\t%s\tfile_pwrite64_success\tbytes=%ld\n", nsecs, pid, tid, comm, args->ret); } }
tracepoint:syscalls:sys_exit_writev /@tracked[pid]/ { if (args->ret > 0) { printf("EBPF\t%llu\t%d\t%d\t%s\tfile_writev_success\tbytes=%ld\n", nsecs, pid, tid, comm, args->ret); } }
tracepoint:sched:sched_process_fork /args->parent_pid == 987654321 || @tracked[args->parent_pid]/ { @tracked[args->child_pid] = 1; if (args->parent_pid != 987654321) { printf("EBPF\t%llu\t%d\t%d\t%s\tfork\t-\n", nsecs, args->parent_pid, args->child_pid, comm); } }
tracepoint:sched:sched_process_exit /@tracked[pid]/ { $live = curtask->signal->live.counter; printf("EBPF\t%llu\t%d\t%d\t%s\texit\tlive=%d\n", nsecs, pid, tid, comm, $live); if (tid != pid) { delete(@tracked[tid]); } if ($live == 0) { delete(@tracked[pid]); } }
tracepoint:sched:sched_process_exec /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\texec_success\told_pid=%d filename=%s\n", nsecs, pid, tid, comm, args->old_pid, str(args->filename)); if (args->old_pid != pid) { delete(@tracked[args->old_pid]); } }
tracepoint:syscalls:sys_exit_execve /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\texec_return\tsyscall=execve ret=%ld\n", nsecs, pid, tid, comm, args->ret); }
tracepoint:syscalls:sys_exit_execveat /@tracked[pid]/ { printf("EBPF\t%llu\t%d\t%d\t%s\texec_return\tsyscall=execveat ret=%ld\n", nsecs, pid, tid, comm, args->ret); }
PROGRAM_EOF
cat >file_loop.txt <<'LOOP_EOF'
i=0; while [ $i -lt 300 ]; do echo $i > bb_file_workload.txt; read v < bb_file_workload.txt; i=$((i+1)); done
LOOP_EOF
cat >net_script.txt <<'NET_EOF'
printf "GET / HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n" | nc -w 3 10.0.0.1 80 > bb_net_workload.html
NET_EOF
: >roots.txt
(
    while [ ! -e go ]; do sleep 0.2; done
    run() { local name="$1"; shift; "$@" & local p=$!; echo "$name pid $p" >>roots.txt; wait "$p"; echo "$name rc=$?"; }
    run amd64_file ./amd64-static/busybox sh -c "$(cat file_loop.txt)"
    run amd64_net ./amd64-static/busybox sh -c "$(cat net_script.txt)"; head -c 15 bb_net_workload.html; echo; rm -f bb_net_workload.html
    run i386_file ./i386-static/busybox sh -c "$(cat file_loop.txt)"
    run i386_net ./i386-static/busybox sh -c "$(cat net_script.txt)"; head -c 15 bb_net_workload.html; echo; rm -f bb_net_workload.html
    run armel_net ./armel-static/busybox sh -c "$(cat net_script.txt)"; head -c 15 bb_net_workload.html; echo; rm -f bb_net_workload.html
    run thread_leader_exit ./thread-exec-ka leader-exit
    sleep 1.5
    run thread_exec ./thread-exec-ka exec
    echo "ka files: $(tail -n1 ka_leader_exit.txt 2>/dev/null) $(tail -n1 ka_thread_exec.txt 2>/dev/null)"
    touch done
) &
launcher=$!
sed -i "s/987654321/$launcher/g" program.bt
sudo -S -p '' /usr/bin/env BPFTRACE_PERF_RB_PAGES=16384 /usr/bin/bpftrace program.bt <"$pw" >bt.out 2>bt.err &
for _ in $(seq 1 120); do grep -q 'Attached' bt.out bt.err 2>/dev/null && break; sleep 0.5; done
echo "== attach: $(grep -h 'Attached' bt.out bt.err)"
touch go
for _ in $(seq 1 240); do [ -e done ] && break; sleep 0.5; done
sleep 1
sudo -S -p '' /usr/bin/pkill -INT -x bpftrace <"$pw"
for _ in $(seq 1 40); do pgrep -x bpftrace >/dev/null || break; sleep 0.5; done
echo "== bpftrace stderr"; head -c 3000 bt.err
echo "== lost: $(grep -hi 'lost' bt.out bt.err | head -3)"
echo "== roots"; cat roots.txt
awk '{print $1, $2, $3}' roots.txt >roots3.txt
python3 - bt.out roots3.txt <<'PY_EOF'

import collections, re, sys
roots = {}
for line in open(sys.argv[2]):
    name, _, pid = line.split()
    roots[int(pid)] = name
owner = dict((pid, name) for pid, name in roots.items())
stats = collections.defaultdict(collections.Counter)
details = collections.defaultdict(list)
other = collections.Counter()
for line in open(sys.argv[1], errors="replace"):
    parts = line.rstrip("\n").split("\t")
    if len(parts) != 7 or parts[0] != "EBPF":
        if line.strip() and not line.startswith("EBPF"):
            other[line.strip()[:160]] += 1
        continue
    _, ts, pid, tid, comm, event, detail = parts
    pid, tid = int(pid), int(tid)
    if event == "fork":
        if pid in owner:
            owner[tid] = owner[pid]
        continue
    name = owner.get(pid) or owner.get(tid)
    if name is None:
        stats["(untracked-by-script)"][event] += 1
        continue
    stats[name][event] += 1
    if event == "syscall":
        continue
    if event in ("connect", "exec_success", "exec_return", "exit", "socket"):
        details[name].append(f"{comm}:{pid}/{tid}:{event}:{detail}")
    elif event in ("openat", "openat_success", "file_write_success") and \
            ("workload" in detail or event != "openat"):
        key = f"{event}:{'bb_file' if 'bb_file' in detail else 'bb_net' if 'bb_net' in detail else 'ka' if 'ka_' in detail else '-'}"
        stats[name]["detail:" + key] += 1
for name in list(dict.fromkeys(roots.values())) + ["(untracked-by-script)"]:
    print(f"== {name}")
    print("  counts:", dict(sorted((k, v) for k, v in stats[name].items())))
    seen = collections.Counter(details[name])
    for item, count in list(seen.items())[:40]:
        print(f"  {count}x {item}")
print("== non-event output lines")
for item, count in other.most_common(20):
    print(f"  {count}x {item}")

PY_EOF
rm -f "$pw"; cd /; rm -rf "$work"
