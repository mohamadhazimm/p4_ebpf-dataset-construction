#!/usr/bin/env python3
"""Write guest_program_check_v7.sh: run the exact schema .16 bpftrace program in the
guest against benign busybox/thread known-answer workloads (no malware, internal Sink)."""
import hashlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
for name in ("watchdog", "watchdog.events", "watchdog.observers"):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules["watchdog.events"].FileSystemEventHandler = object
sys.modules["watchdog.observers"].Observer = object
sys.modules.setdefault("psutil", types.ModuleType("psutil"))
sys.path.insert(0, str(STUDY))
from src import malware_runner  # noqa: E402

sys.path.insert(0, str(ROOT))
from build_pilot_payload import FILE_LOOP, NET_SCRIPT  # noqa: E402

PLACEHOLDER = 987654321
program = malware_runner._ebpf_program_x86_64(PLACEHOLDER)
assert "'" not in program and "PROGRAM_EOF" not in program
runner_sha = hashlib.sha256((STUDY / "src/malware_runner.py").read_bytes()).hexdigest()

ANALYSIS = r'''
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
'''

script = f"""#!/usr/bin/env bash
# Guest-side v7 check (benign): exact schema .16 bpftrace program, runner SHA
# {runner_sha}. Workloads are benign busybox/thread known-answer cases only.
set -u
pw="$1"
work="$(mktemp -d)"; cd "$work"
src=/home/csci/Downloads/exec-mode-pilot-v16/samples
for m in amd64-static i386-static armel-static; do mkdir -p "$m"
    /usr/bin/7z x -pinfected -so "$src/${{m}}_file_r1.zip" >"$m/busybox" 2>/dev/null; chmod 755 "$m/busybox"
done
/usr/bin/7z x -pinfected -o"$work" -y "$src/amd64-static-threads_leader-exit_r1.zip" >/dev/null
cat >program.bt <<'PROGRAM_EOF'
{program}
PROGRAM_EOF
cat >file_loop.txt <<'LOOP_EOF'
{FILE_LOOP}
LOOP_EOF
cat >net_script.txt <<'NET_EOF'
{NET_SCRIPT}
NET_EOF
: >roots.txt
(
    while [ ! -e go ]; do sleep 0.2; done
    run() {{ local name="$1"; shift; "$@" & local p=$!; echo "$name pid $p" >>roots.txt; wait "$p"; echo "$name rc=$?"; }}
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
sed -i "s/{PLACEHOLDER}/$launcher/g" program.bt
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
awk '{{print $1, $2, $3}}' roots.txt >roots3.txt
python3 - bt.out roots3.txt <<'PY_EOF'
{ANALYSIS}
PY_EOF
rm -f "$pw"; cd /; rm -rf "$work"
"""
(ROOT / "guest_program_check_v7.sh").write_text(script)
print(runner_sha, len(program))
