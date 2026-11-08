from __future__ import annotations

import csv
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

try:
    import watchdog.events  # noqa: F401
    import watchdog.observers  # noqa: F401
except ModuleNotFoundError:
    events_module = types.ModuleType("watchdog.events")
    events_module.FileSystemEventHandler = object
    observers_module = types.ModuleType("watchdog.observers")
    observers_module.Observer = object
    sys.modules["watchdog"] = types.ModuleType("watchdog")
    sys.modules["watchdog.events"] = events_module
    sys.modules["watchdog.observers"] = observers_module

from src import exec_boundary as eb

ROOT = 100
COLUMNS = ["timestamp_ns", "window_id", "pid", "tid", "comm", "event", "detail"]


def raw(ts, syscall_id, pid=ROOT, window=0, comm="x", tid=None):
    return dict(timestamp_ns=ts, window_id=window, pid=pid, tid=tid or pid, comm=comm,
                event="syscall", detail=f"id={syscall_id}")


def named(ts, event, pid=ROOT, window=0, comm="x", tid=None, detail="-"):
    return dict(timestamp_ns=ts, window_id=window, pid=pid, tid=tid or pid, comm=comm,
                event=event, detail=detail)


def launcher(base=1_000, exec2_at=5_000):
    """Python stdio setup, wrapper exec, bash startup, target exec (each exec has a trailing named record)."""
    rows_raw = [raw(base, 3), raw(base + 1, 33), raw(base + 2, 33), raw(base + 3, 33),
                raw(base + 100, 59), raw(base + 200, 9), raw(base + 201, 9), raw(exec2_at, 59)]
    rows_named = [named(base, "close"), named(base + 1, "dup2"), named(base + 2, "dup2"),
                  named(base + 3, "dup2"), named(base + 102, "execve"), named(base + 200, "mmap"),
                  named(base + 201, "mmap"), named(exec2_at + 2, "execve")]
    return rows_raw, rows_named


def write_run(directory: Path, named_rows, raw_rows, window_count=3, root_pid=ROOT, abi_boundary=None,
              target_abi="x86_64", corrupt=None):
    directory.mkdir(parents=True, exist_ok=True)
    metadata = {} if root_pid is None else {"sample_root_pid": root_pid}
    (directory / "run.json").write_text(json.dumps(metadata))
    for name, rows in (("ebpf_events.csv", named_rows), ("syscall_events.csv", raw_rows)):
        with (directory / name).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
    if abi_boundary is None:
        abi_boundary = eb._try_boundary(raw_rows, ROOT, 2)
    model = eb._count(named_rows, raw_rows, window_count, abi_boundary, target_abi)
    with (directory / "telemetry.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(eb.FAMILIES))
        writer.writeheader()
        for window in range(window_count):
            row = dict(model[window])
            if corrupt:
                row.update(corrupt)
            writer.writerow(row)


class ExecBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "run"
        self.addCleanup(self.tmp.cleanup)

    def derive(self, exec_index=2):
        return eb.derive_run(self.dir, exec_index)

    def test_launcher_removed_and_target_kept(self):
        rr, nn = launcher()
        rr += [raw(6_000, 1), raw(6_001, 9)]
        nn += [named(6_000, "write"), named(6_001, "mmap")]
        write_run(self.dir, nn, rr)
        post = self.derive()[0]
        self.assertEqual(post["ebpf_dup2_count"], 0)
        self.assertEqual(post["ebpf_close_count"], 0)
        self.assertEqual(post["ebpf_execve_count"], 0)
        self.assertEqual(post["ebpf_mmap_count"], 1)
        self.assertEqual(post["ebpf_write_count"], 1)
        self.assertEqual(post["ebpf_event_count"], 2)

    def test_identical_launcher_gives_identical_zero_features(self):
        rr, nn = launcher()
        write_run(self.dir, nn, rr)
        post = self.derive()
        self.assertTrue(all(value == 0 for window in post.values() for value in window.values()))

    def test_no_cut_reproduces_stored_telemetry(self):
        rr, nn = launcher()
        rr += [raw(6_000, 1)]
        nn += [named(6_000, "write")]
        write_run(self.dir, nn, rr)
        stored = list(csv.DictReader((self.dir / "telemetry.csv").open()))
        derived = self.derive(0)
        for window, row in enumerate(stored):
            for family in eb.FAMILIES:
                self.assertEqual(float(row[family]), derived[window][family])

    def test_single_exec_is_unresolved(self):
        rr, nn = launcher()
        write_run(self.dir, nn[:5], rr[:5])
        with self.assertRaises(eb.BoundaryError):
            self.derive()

    def test_zero_events_is_unresolved(self):
        write_run(self.dir, [], [])
        with self.assertRaises(eb.BoundaryError):
            self.derive()

    def test_later_target_exec_is_behavior(self):
        rr, nn = launcher()
        rr += [raw(7_000, 59), raw(7_500, 322)]
        write_run(self.dir, nn, rr)
        post = self.derive()[0]
        self.assertEqual(post["ebpf_execve_count"], 1)
        self.assertEqual(post["ebpf_execveat_count"], 1)

    def test_third_named_exec_is_not_dropped_by_pairing(self):
        rr, nn = launcher()
        rr += [raw(9_000, 59)]
        nn += [named(9_002, "execve")]
        write_run(self.dir, nn, rr)
        self.assertEqual(self.derive()[0]["ebpf_execve_count"], 1)

    def test_named_exec_outside_pairing_window_is_kept(self):
        rr, nn = launcher()
        nn += [named(5_000 + eb.NAMED_EXEC_PAIR_NS + 1, "execve")]
        write_run(self.dir, nn, rr)
        self.assertEqual(self.derive()[0]["ebpf_execve_count"], 1)

    def test_child_pid_execs_do_not_move_the_boundary(self):
        rr, nn = launcher()
        rr.insert(0, raw(10, 59, pid=200))
        rr.insert(0, raw(11, 59, pid=200))
        write_run(self.dir, nn, rr)
        self.assertEqual(eb.find_exec_boundary(rr, ROOT, 2), 5_000)

    def test_event_at_boundary_timestamp_is_removed(self):
        rr, nn = launcher(exec2_at=5_000)
        rr += [raw(5_000, 1)]
        write_run(self.dir, nn, rr)
        self.assertEqual(self.derive()[0]["ebpf_write_count"], 0)

    def test_descendant_events_are_never_cut(self):
        rr, nn = launcher()
        rr += [raw(300, 1, pid=201)]
        nn += [named(300, "write", pid=201, tid=201), named(301, "fork", pid=201, tid=201)]
        write_run(self.dir, nn, rr)
        post = self.derive()[0]
        self.assertEqual(post["ebpf_write_count"], 1)
        self.assertEqual(post["ebpf_fork_count"], 1)
        self.assertEqual(post["ebpf_unique_threads"], 1)

    def test_unique_threads_exclude_launcher(self):
        rr, nn = launcher()
        nn += [named(6_000, "mmap", tid=ROOT + 1), named(6_001, "mmap", tid=ROOT + 2)]
        write_run(self.dir, nn, rr)
        self.assertEqual(self.derive()[0]["ebpf_unique_threads"], 2)

    def test_windows_are_preserved(self):
        rr, nn = launcher()
        rr += [raw(1_000_000, 1, window=1), raw(2_000_000, 1, window=2)]
        nn += [named(1_000_000, "write", window=1)]
        write_run(self.dir, nn, rr, window_count=4)
        post = self.derive()
        self.assertEqual(sorted(post), [0, 1, 2, 3])
        self.assertEqual([post[w]["ebpf_write_count"] for w in range(4)], [0, 1, 1, 0])

    def test_file_write_bytes_parsed_after_cut(self):
        rr, nn = launcher()
        nn += [named(6_000, "file_write_success", detail="fd=1 bytes=42")]
        write_run(self.dir, nn, rr)
        self.assertEqual(self.derive()[0]["ebpf_file_write_bytes"], 42)

    def test_i386_target_after_x86_launcher(self):
        rr, nn = launcher()
        rr += [raw(6_000, 4), raw(6_001, 192)]
        write_run(self.dir, nn, rr, target_abi="i386")
        self.assertEqual(eb.infer_target_abi(nn, rr, ROOT, 3, list(csv.DictReader((self.dir / "telemetry.csv").open()))), "i386")
        post = self.derive()[0]
        self.assertEqual(post["ebpf_write_count"], 1)
        self.assertEqual(post["ebpf_mmap_count"], 1)

    def test_missing_root_pid_and_bad_input_fail_loudly(self):
        rr, nn = launcher()
        write_run(self.dir, nn, rr, root_pid=None)
        with self.assertRaises(eb.BoundaryError):
            self.derive()
        write_run(self.dir, nn, rr)
        (self.dir / "syscall_events.csv").write_text("timestamp_ns,window_id,pid\n1,0,1\n")
        with self.assertRaises(eb.BoundaryError):
            self.derive()
        write_run(self.dir, nn, rr)
        text = (self.dir / "ebpf_events.csv").read_text().replace(",close,", ",close,", 1)
        (self.dir / "ebpf_events.csv").write_text(text + "abc,0,1,1,x,close,-\n")
        with self.assertRaises(eb.BoundaryError):
            self.derive()

    def test_stored_smaller_than_removal_is_rejected(self):
        rr, nn = launcher()
        write_run(self.dir, nn, rr, corrupt={"ebpf_dup2_count": 0})
        with self.assertRaises(eb.BoundaryError):
            self.derive()

    def test_unsorted_input_rows_are_handled(self):
        rr, nn = launcher()
        rr += [raw(6_000, 1)]
        nn += [named(6_000, "write")]
        write_run(self.dir, list(reversed(nn)), list(reversed(rr)))
        self.assertEqual(self.derive()[0]["ebpf_write_count"], 1)

    def test_syscall_tables_match_runner(self):
        try:
            from src import malware_runner
        except Exception as error:  # dependency stubs unavailable
            self.skipTest(str(error))
        self.assertEqual(eb.X86_64_SYSCALLS, malware_runner.SYSCALL_NAMES_BY_ABI["x86_64"])
        # exec_boundary reproduces schema .14 counters; schema .16 added i386 socket ids
        # that .14 never mapped, so they are excluded here on purpose.
        added_in_16 = {359, 361, 362, 363, 364, 369, 371}
        runner_i386 = {key: value for key, value in malware_runner.SYSCALL_NAMES_BY_ABI["i386"].items()
                       if key not in added_in_16}
        self.assertEqual(eb.I386_SYSCALLS, runner_i386)
        self.assertEqual(set(eb.EXEC_IDS), malware_runner.EXEC_SYSCALL_IDS_BY_ABI["x86_64"])


if __name__ == "__main__":
    unittest.main()
