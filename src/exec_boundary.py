"""Re-derive per-window eBPF host counters for the target program only.

Every collected run starts the sample through the same machinery: a Python Popen child
(close/dup2 stdio setup), an execve into the wrapper shell, and `exec "$@"` into the target.
Those events are identical for all samples, so they are launch artifacts rather than behavior.
This module cuts the archived root-PID event stream at the target execve (the second root
execve) and recomputes the counters exactly as ``malware_runner.EbpfCollector.collect`` does.
With ``exec_index=0`` it reproduces the stored telemetry, which is the parity check.
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

X86_64_SYSCALLS = {
    1: "write", 3: "close", 9: "mmap", 10: "mprotect", 18: "pwrite64",
    20: "writev", 33: "dup2", 41: "socket", 42: "connect", 43: "accept",
    44: "sendto", 45: "recvfrom", 49: "bind", 50: "listen", 59: "execve",
    62: "kill", 101: "ptrace", 257: "openat", 263: "unlinkat",
    264: "renameat", 288: "accept4", 292: "dup3", 316: "renameat2",
    322: "execveat", 437: "openat2",
}
I386_SYSCALLS = {
    4: "write", 6: "close", 11: "execve", 26: "ptrace", 37: "kill", 63: "dup2",
    125: "mprotect", 146: "writev", 181: "pwrite64", 192: "mmap", 295: "openat",
    301: "unlinkat", 302: "renameat", 330: "dup3", 353: "renameat2",
    358: "execveat", 437: "openat2",
}
SYSCALLS_BY_ABI = {"x86_64": X86_64_SYSCALLS, "i386": I386_SYSCALLS}
EXEC_IDS = (59, 322)
TARGET_EXEC_INDEX = 2
WRITE_EVENTS = ("file_write_success", "file_pwrite64_success", "file_writev_success")
FAMILIES = (
    "ebpf_accept4_count", "ebpf_accept_count", "ebpf_bind_count", "ebpf_close_count",
    "ebpf_connect_count", "ebpf_dup2_count", "ebpf_dup3_count", "ebpf_event_count",
    "ebpf_execve_count", "ebpf_execveat_count", "ebpf_exit_count",
    "ebpf_file_pwrite64_success_count", "ebpf_file_write_bytes",
    "ebpf_file_write_success_count", "ebpf_file_writev_success_count", "ebpf_fork_count",
    "ebpf_kill_count", "ebpf_listen_count", "ebpf_mmap_count", "ebpf_mprotect_count",
    "ebpf_openat2_count", "ebpf_openat2_success_count", "ebpf_openat_count",
    "ebpf_openat_success_count", "ebpf_ptrace_count", "ebpf_pwrite64_count",
    "ebpf_recvfrom_count", "ebpf_renameat2_count", "ebpf_renameat_count",
    "ebpf_sendto_count", "ebpf_socket_count", "ebpf_unique_threads",
    "ebpf_unlinkat_count", "ebpf_write_count", "ebpf_writev_count",
)
NAMED_EXEC_PAIR_NS = 1_000_000


class BoundaryError(ValueError):
    """The run lacks the events needed to place the target exec boundary."""


def _read_csv(path: Path, required: tuple[str, ...]) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None or not set(required) <= set(reader.fieldnames):
            raise BoundaryError(f"{path}: missing columns {set(required) - set(reader.fieldnames or [])}")
        rows = []
        for row in reader:
            try:
                row["timestamp_ns"] = int(row["timestamp_ns"])
                row["window_id"] = int(row["window_id"])
                row["pid"] = int(row["pid"])
                row["tid"] = int(row["tid"])
            except (TypeError, ValueError) as error:
                raise BoundaryError(f"{path}: malformed row {row!r}") from error
            rows.append(row)
    return rows


def _syscall_id(detail: str) -> int | None:
    _, _, value = detail.partition("id=")
    try:
        return int(value)
    except ValueError:
        return None


def find_exec_boundary(raw_rows: list[dict], root_pid: int, exec_index: int) -> int | None:
    """Return the timestamp of the root PID's ``exec_index``-th execve, or None when 0."""
    if exec_index == 0:
        return None
    execs = sorted(
        row["timestamp_ns"]
        for row in raw_rows
        if row["pid"] == root_pid and row["event"] == "syscall" and _syscall_id(row["detail"]) in EXEC_IDS
    )
    if len(execs) < exec_index:
        raise BoundaryError(f"root PID {root_pid} has {len(execs)} execve calls; need {exec_index}")
    return execs[exec_index - 1]


def _cut(named_rows, raw_rows, root_pid, boundary):
    """Cut root-PID rows at the boundary and drop the target-exec record that trails it."""
    if boundary is None:
        return list(named_rows), list(raw_rows)
    kept_named = []
    paired_exec_dropped = False
    for row in sorted(named_rows, key=lambda item: item["timestamp_ns"]):
        if row["pid"] != root_pid:
            kept_named.append(row)
            continue
        if row["timestamp_ns"] <= boundary:
            continue
        if (
            not paired_exec_dropped
            and row["event"] in ("execve", "execveat")
            and row["timestamp_ns"] - boundary <= NAMED_EXEC_PAIR_NS
        ):
            paired_exec_dropped = True
            continue
        kept_named.append(row)
    return kept_named, [
        row for row in raw_rows if row["pid"] != root_pid or row["timestamp_ns"] > boundary
    ]


def _count(named_rows, raw_rows, window_count, abi_boundary=None, target_abi="x86_64"):
    counts: dict[int, Counter] = defaultdict(Counter)
    threads: dict[int, set] = defaultdict(set)
    named_syscalls: Counter = Counter()
    for row in named_rows:
        window, event = row["window_id"], row["event"]
        counts[window][f"ebpf_{event}_count"] += 1
        counts[window]["ebpf_event_count"] += 1
        named_syscalls[(window, row["pid"], event)] += 1
        threads[window].add(row["tid"])
        if event in WRITE_EVENTS:
            try:
                counts[window]["ebpf_file_write_bytes"] += int(row["detail"].rsplit("bytes=", 1)[1])
            except (IndexError, ValueError):
                pass
    raw_by_key: Counter = Counter()
    for row in raw_rows:
        pre_target = abi_boundary is not None and row["timestamp_ns"] <= abi_boundary
        table = SYSCALLS_BY_ABI["x86_64" if pre_target else target_abi]
        name = table.get(_syscall_id(row["detail"]))
        if name is not None:
            raw_by_key[(row["window_id"], row["pid"], name)] += 1
    for (window, pid, name), raw_count in raw_by_key.items():
        missing = max(raw_count - named_syscalls[(window, pid, name)], 0)
        if missing:
            counts[window][f"ebpf_{name}_count"] += missing
    out = {}
    for window in range(window_count):
        row = {family: float(counts[window][family]) for family in FAMILIES}
        row["ebpf_unique_threads"] = float(len(threads[window]))
        out[window] = row
    return out


def _try_boundary(raw_rows, root_pid, exec_index):
    try:
        return find_exec_boundary(raw_rows, root_pid, exec_index)
    except BoundaryError:
        return None


def infer_target_abi(named_rows, raw_rows, root_pid, window_count, stored_rows):
    """Pick the target ABI whose root-PID model exceeds stored counts least, then falls shortest."""
    abi_boundary = _try_boundary(raw_rows, root_pid, TARGET_EXEC_INDEX)
    root_named = [row for row in named_rows if row["pid"] == root_pid]
    root_raw = [row for row in raw_rows if row["pid"] == root_pid]
    best = None
    for abi in SYSCALLS_BY_ABI:
        model = _count(root_named, root_raw, window_count, abi_boundary, abi)
        deltas = [
            model[w][f] - float(stored_rows[w][f])
            for w in range(window_count)
            for f in FAMILIES
            if f != "ebpf_unique_threads"
        ]
        score = (sum(d for d in deltas if d > 0), sum(-d for d in deltas if d < 0))
        if best is None or score < best[1]:
            best = (abi, score)
    return best[0]


def derive_counters(named_rows, raw_rows, root_pid, exec_index, window_count, stored_rows):
    """Return stored telemetry minus the root PID's pre-target-exec contribution.

    Subtracting from stored values keeps events the collector could not map to a syscall
    name (for example exited descendants) exactly as recorded. The cut only touches the
    root PID. Before the target exec it is always the 64-bit launcher (x86-64 ABI); after
    it the target's ABI applies, inferred so the root model never exceeds stored counts.
    """
    boundary = find_exec_boundary(raw_rows, root_pid, exec_index)
    target_abi = infer_target_abi(named_rows, raw_rows, root_pid, window_count, stored_rows)
    abi_boundary = _try_boundary(raw_rows, root_pid, TARGET_EXEC_INDEX)
    kept_named, kept_raw = _cut(named_rows, raw_rows, root_pid, boundary)
    root_named = [row for row in named_rows if row["pid"] == root_pid]
    root_raw = [row for row in raw_rows if row["pid"] == root_pid]
    kept_root_named = [row for row in kept_named if row["pid"] == root_pid]
    kept_root_raw = [row for row in kept_raw if row["pid"] == root_pid]
    full_root = _count(root_named, root_raw, window_count, abi_boundary, target_abi)
    kept_root = _count(kept_root_named, kept_root_raw, window_count, abi_boundary, target_abi)
    kept_threads = _count(kept_named, [], window_count)
    out = {}
    for window in range(window_count):
        row = {}
        for family in FAMILIES:
            if family == "ebpf_unique_threads":
                row[family] = kept_threads[window][family] if boundary is not None else float(stored_rows[window][family])
                continue
            removed = full_root[window][family] - kept_root[window][family]
            value = float(stored_rows[window][family]) - removed
            if value < -1e-9:
                raise BoundaryError(f"window {window} {family}: removal {removed} exceeds stored {stored_rows[window][family]}")
            row[family] = max(value, 0.0)
        out[window] = row
    return out


def load_run(run_dir: Path):
    metadata = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    root_pid = metadata.get("sample_root_pid")
    if not isinstance(root_pid, int):
        raise BoundaryError(f"{run_dir}: run.json has no integer sample_root_pid")
    columns = ("timestamp_ns", "window_id", "pid", "tid", "comm", "event", "detail")
    named = _read_csv(run_dir / "ebpf_events.csv", columns)
    raw = _read_csv(run_dir / "syscall_events.csv", columns)
    with (run_dir / "telemetry.csv").open(newline="", encoding="utf-8") as source:
        stored = list(csv.DictReader(source))
    return metadata, named, raw, stored


def derive_run(run_dir: Path, exec_index: int = 2):
    metadata, named, raw, stored = load_run(Path(run_dir))
    return derive_counters(named, raw, metadata["sample_root_pid"], exec_index, len(stored), stored)
