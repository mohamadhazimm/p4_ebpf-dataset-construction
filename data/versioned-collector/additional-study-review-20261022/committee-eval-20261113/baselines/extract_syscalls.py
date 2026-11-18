"""Per-thread system-call token sequences for every run (cache for STIDE and the n-gram HIDS).

For each of the 240 runs this reads syscall_events.csv (raw system-call entries of the sample's process tree,
`detail` = `id=<number>`), exec_events.csv and the fork records of ebpf_events.csv, and writes
cache/syscalls/<row>.npz with one token sequence per thread (tid), ordered by timestamp.

Token = (abi << 10) | syscall number, abi 0 = x86-64, 1 = i386, so the two numbering schemes never collide.
The ABI is not in the trace line, so it is reconstructed per process (tgid):
  * the root process runs the collector's python3 and /bin/bash launcher (both x86-64) until its 2nd
    exec_success, which loads the target program; from then on it uses the run's mode (i386 for i386_static);
  * later execs: guest system binaries (/usr/bin, /usr/sbin, /bin, /sbin, /lib*, /usr/lib*) are x86-64, any
    other image (the sample's own path or a copy of it, e.g. /tmp/..., /var/tmp/...) uses the run's mode;
  * a forked process inherits its parent's ABI at fork time (fork records in ebpf_events.csv); a process with
    no fork record uses the run's mode.
This refines the plain "row mode" rule: in i386 runs the 178-call launcher prologue and the guest tools that
malware starts (systemctl, sed, sh, ...) are x86-64 programs.

The prologue = root-process events before its 2nd exec_success (the fixed launcher, 178 calls in every run).

Gates (checked for every run): 2nd root exec_success is the expected target path; events in windows 0..39
equal host_total_syscalls_total__sum of features.csv; prologue length is 178; syscall numbers < 1024.

    /usr/bin/python3 extract_syscalls.py
"""
import bisect
import csv
import json
import re
import sys
from multiprocessing import Pool

import numpy as np

import bl_common as B

OUT = B.CACHE / "syscalls"
SYSTEM_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/lib32/", "/usr/lib/",
                   "/usr/lib64/", "/usr/lib32/", "/usr/libexec/")
X64, I386 = 0, 1


def image_abi(filename, run_abi):
    return X64 if filename.startswith(SYSTEM_PREFIXES) else run_abi


def _work(args):
    i, od, mode, expected_total = args
    run_abi = I386 if mode == "i386_static" else X64
    rj = json.loads((od / "run.json").read_text())
    root = int(rj["sample_root_pid"])
    target = rj["target_exec"]["expected_path"]

    execs = {}  # tgid -> list of (ts, filename)
    with open(od / "exec_events.csv", newline="") as f:
        for e in csv.DictReader(f):
            if e["event"] == "exec_success":
                fn = re.search(r"filename=(\S+)", e["detail"]).group(1)
                execs.setdefault(int(e["pid"]), []).append((int(e["timestamp_ns"]), fn))
    for v in execs.values():
        v.sort()
    root_execs = execs.get(root, [])
    assert len(root_execs) >= 2, (i, "root exec_success count", len(root_execs))
    assert root_execs[0][1] == "/bin/bash", (i, root_execs[0])
    assert root_execs[1][1] == target, (i, root_execs[1], target)
    t_target = root_execs[1][0]

    parent = {}  # child id -> (fork ts, parent tgid)
    with open(od / "ebpf_events.csv", newline="") as f:
        for e in csv.DictReader(f):
            if e["event"] == "fork":
                c = int(e["tid"])
                if c not in parent:
                    parent[c] = (int(e["timestamp_ns"]), int(e["pid"]))

    timelines = {}  # tgid -> (sorted change times, abi values)

    def timeline(tgid, depth=0):
        if tgid in timelines:
            return timelines[tgid]
        if tgid == root:
            seq = [(-1, X64), (t_target, run_abi)]
            seq += [(ts, image_abi(fn, run_abi)) for ts, fn in root_execs[2:]]
        else:
            if tgid in parent and depth < 64 and parent[tgid][1] != tgid:
                fts, ptg = parent[tgid]
                start = abi_at(ptg, fts, depth + 1)
            else:
                start = run_abi
            seq = [(-1, start)] + [(ts, image_abi(fn, run_abi)) for ts, fn in execs.get(tgid, [])]
        timelines[tgid] = ([s[0] for s in seq], [s[1] for s in seq])
        return timelines[tgid]

    def abi_at(tgid, ts, depth=0):
        times, abis = timeline(tgid, depth)
        return abis[bisect.bisect_right(times, ts) - 1]

    threads = {}   # tid -> list of (ts, order, token)
    order = []
    n_file = n_out = n_prologue = n_i386 = 0
    max_id = 0
    with open(od / "syscall_events.csv", newline="") as f:
        rd = csv.reader(f)
        head = next(rd)
        assert head == ["timestamp_ns", "window_id", "pid", "tid", "comm", "event", "detail"], head
        for k, e in enumerate(rd):
            n_file += 1
            assert e[5] == "syscall" and e[6].startswith("id="), (i, e)
            w = int(e[1])
            if not 0 <= w < 40:
                n_out += 1
                continue
            ts, pid, tid, sid = int(e[0]), int(e[2]), int(e[3]), int(e[6][3:])
            max_id = max(max_id, sid)
            abi = abi_at(pid, ts)
            n_i386 += abi
            if pid == root and ts < t_target:
                n_prologue += 1
                assert tid == root, (i, "prologue event from another thread")
            lst = threads.get(tid)
            if lst is None:
                lst = threads[tid] = []
                order.append(tid)
            lst.append((ts, k, (abi << 10) | sid))
    assert max_id < 1024, (i, max_id)
    toks, off, tids = [], [0], []
    root_thread, prologue_len = -1, 0
    for tid in order:
        lst = sorted(threads[tid])
        if tid == root:
            root_thread = len(tids)
            # prologue events are root-thread events before the target exec; after sorting they are a prefix
            prologue_len = sum(1 for ts, _, _ in lst if ts < t_target)
            assert all(ts < t_target for ts, _, _ in lst[:prologue_len])
        toks.extend(t for _, _, t in lst)
        off.append(len(toks))
        tids.append(tid)
    n_win = len(toks)
    assert n_win == expected_total, (i, "events in windows", n_win, "features.csv total", expected_total)
    assert prologue_len == n_prologue == 178, (i, prologue_len, n_prologue)
    OUT.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUT / ("%03d.npz" % i), tok=np.asarray(toks, dtype=np.int32),
                        off=np.asarray(off, dtype=np.int64), tid=np.asarray(tids, dtype=np.int64),
                        root_thread=root_thread, prologue_len=prologue_len)
    n_proc = len(timelines)
    return {"row": i, "events_in_file": n_file, "events_outside_windows": n_out, "events": n_win,
            "threads": len(tids), "processes": n_proc, "prologue": prologue_len, "i386_tokens": n_i386,
            "run_abi": run_abi, "root_execs": len(root_execs), "forks": len(parent)}


def main():
    rows, y, g, cat, split, mode = B.dataset()
    dirs = B.C.run_dirs(rows)
    tot = [int(round(float(r["host_total_syscalls_total__sum"]))) for r in rows]
    jobs = [(i, B.C.output_dir(dirs[i]), mode[i], tot[i]) for i in range(len(rows))]
    sizes = [(od / "syscall_events.csv").stat().st_size for _, od, _, _ in jobs]
    jobs = [jobs[i] for i in np.argsort(sizes)[::-1]]  # largest first
    with Pool(B.MAX_JOBS) as p:
        res = p.map(_work, jobs, chunksize=1)
    res.sort(key=lambda d: d["row"])
    summary = {
        "runs": len(res),
        "events_total": int(sum(d["events"] for d in res)),
        "events_outside_windows_total": int(sum(d["events_outside_windows"] for d in res)),
        "runs_with_i386_tokens": int(sum(1 for d in res if d["i386_tokens"])),
        "i386_runs": int(sum(1 for d in res if d["run_abi"] == I386)),
        "x64_tokens_in_i386_runs": int(sum(d["events"] - d["i386_tokens"] for d in res if d["run_abi"] == I386)),
        "gates": "2nd root exec = target path; events in windows 0..39 = host_total_syscalls_total__sum; "
                 "prologue = 178; syscall numbers < 1024 (all 240 runs passed)",
        "per_run": res,
    }
    B.write_json(B.CACHE / "syscalls_summary.json", summary)
    print({k: v for k, v in summary.items() if k != "per_run"})


if __name__ == "__main__":
    sys.exit(main())
