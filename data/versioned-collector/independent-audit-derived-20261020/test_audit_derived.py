#!/usr/bin/env python3
"""DERIVED audit tests (2026-10-20). Synthetic fixtures only; no frozen artifact is read or written.

Run from this directory: /usr/bin/python3 -m unittest test_audit_derived -v
"""
from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from unittest import mock

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "src"))
import audit_runs  # noqa: E402
import diagnostics as d  # noqa: E402
import exclusions_and_duplicates as xd  # noqa: E402
import exec_boundary as eb  # noqa: E402
import linkage_stratified as ls  # noqa: E402

FIELDS = ["timestamp_ns", "window_id", "pid", "tid", "comm", "event", "detail"]
ROOT, START = 100, 1_000_000_000


def raw(ts, pid, comm, sid):
    return {"timestamp_ns": ts, "window_id": 0, "pid": pid, "tid": pid, "comm": comm, "event": "syscall",
            "detail": f"id={sid}"}


def named(ts, pid, comm, event, detail="", tid=None):
    return {"timestamp_ns": ts, "window_id": 0, "pid": pid, "tid": pid if tid is None else tid, "comm": comm,
            "event": event, "detail": detail}


class RunFixture:
    """Write a minimal archived run directory inside this derived folder."""

    def __init__(self, raw_rows, named_rows):
        self._tmp = tempfile.TemporaryDirectory(dir=HERE, prefix="_test_run_")
        self.path = Path(self._tmp.name)
        (self.path / "run.json").write_text(json.dumps({
            "sample_root_pid": ROOT, "sample_started_monotonic_ns": START,
            "observation_ended_monotonic_ns": START + 20_000_000_000}))
        for name, rows in (("syscall_events.csv", raw_rows), ("ebpf_events.csv", named_rows)):
            with (self.path / name).open("w", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(rows)

    def cleanup(self):
        self._tmp.cleanup()


LAUNCH = [raw(START + 10, ROOT, "python3", 33), raw(START + 20, ROOT, "python3", 59),
          raw(START + 30, ROOT, "bash", 59)]


class ExecOutcomeTests(unittest.TestCase):
    def audit(self, raw_rows, named_rows=()):
        fixture = RunFixture(raw_rows, list(named_rows))
        self.addCleanup(fixture.cleanup)
        return audit_runs.audit_run(fixture.path)

    def test_zero_post_exec_syscalls_flagged(self):
        result = self.audit(LAUNCH)
        self.assertEqual(result["exec_outcome"], "no_post_exec_root_syscalls")
        self.assertEqual(result["post_exec_raw_syscalls"], 0)

    def test_launcher_comm_after_second_exec_flagged(self):
        result = self.audit(LAUNCH + [raw(START + 40, ROOT, "bash", 1), raw(START + 50, ROOT, "bash", 231)])
        self.assertEqual(result["exec_outcome"], "launcher_comm_persisted")
        self.assertFalse(result["exec_success_inferred"])

    def test_target_comm_observed(self):
        result = self.audit(LAUNCH + [raw(START + 40, ROOT, "target", 12)])
        self.assertEqual(result["exec_outcome"], "target_comm_observed")
        self.assertEqual(result["post_exec_raw_syscalls"], 1)

    def test_exec_boundary_does_not_verify_exec_success(self):
        # Documents the derived-layer limitation: a failed target exec still yields a boundary.
        rows = [dict(r) for r in LAUNCH] + [raw(START + 40, ROOT, "bash", 231)]
        self.assertEqual(eb.find_exec_boundary(rows, ROOT, 2), START + 30)

    def test_missing_root_rows_raise(self):
        with self.assertRaises(eb.BoundaryError):
            eb.find_exec_boundary([raw(START, 999, "other", 59)], ROOT, 2)

    def test_pid_reuse_suspect_detected(self):
        named_rows = [named(START + 100, 200, "child", "exit"),
                      named(START + 100 + 5_000_000, 200, "reused", "openat", "path=/x")]
        self.assertEqual(self.audit(LAUNCH, named_rows)["pid_reuse_suspects"], 1)

    def test_no_pid_reuse_for_clean_exit(self):
        named_rows = [named(START + 50, 200, "child", "openat", "path=/x"), named(START + 100, 200, "child", "exit")]
        self.assertEqual(self.audit(LAUNCH, named_rows)["pid_reuse_suspects"], 0)


class LinkageProxyTests(unittest.TestCase):
    def link(self, named_rows):
        fixture = RunFixture(LAUNCH, named_rows)
        self.addCleanup(fixture.cleanup)
        return ls.linkage(fixture.path)

    def test_libc_before_boundary_is_ignored(self):
        rows = [named(START + 15, ROOT, "python3", "openat", "path=/lib/x86_64-linux-gnu/libc.so.6")]
        self.assertEqual(self.link(rows)["libc_opened_after_exec"], 0)

    def test_libc_after_boundary_counts_for_any_lineage_pid(self):
        rows = [named(START + 40, 300, "child", "openat", "path=/lib/x86_64-linux-gnu/libc.so.6"),
                named(START + 41, ROOT, "target", "openat", "path=/etc/ld.so.cache")]
        self.assertEqual(self.link(rows), {"libc_opened_after_exec": 1, "ld_so_cache_after_exec": 1})


class SplitAndSelectionTests(unittest.TestCase):
    def setUp(self):
        self.y = np.repeat([0, 1], 30)
        self.g = np.asarray([f"b{i // 3}" for i in range(30)] + [f"m{i // 3}" for i in range(30)])

    def test_splits_are_group_disjoint(self):
        splits = d.splits_for(self.y, self.g)
        d.check_splits(self.y, self.g, splits)
        covered = np.concatenate([test for _, test in splits])
        self.assertEqual(sorted(covered.tolist()), list(range(60)))

    def test_check_splits_rejects_group_leakage(self):
        # Rows 57-59 form group m9; putting row 57 in train and 58-59 in test leaks it.
        with self.assertRaisesRegex(AssertionError, "group leakage"):
            d.check_splits(self.y, self.g, [(np.arange(0, 58), np.arange(58, 60))])

    def test_check_splits_rejects_single_class_training(self):
        with self.assertRaisesRegex(AssertionError, "missing a class"):
            d.check_splits(self.y, self.g, [(np.arange(0, 30), np.arange(30, 60))])

    def test_selection_sees_training_rows_only(self):
        rng = np.random.default_rng(0)
        x = rng.normal(size=(60, 10))
        cols = [f"host__fam{i // 5}__{s}" for i, s in zip(range(10), ["mean", "max", "sum", "std", "active_windows"] * 2)]
        splits = d.splits_for(self.y, self.g)
        seen = []
        real = d.mi_select

        def spy(train_x, train_y, select_cols, seed, k=29):
            seen.append(len(train_y))
            return real(train_x, train_y, select_cols, seed, k=1)

        with mock.patch.object(d, "mi_select", spy):
            d.oof(x, self.y, splits, trees=10, select_cols=cols)
        self.assertEqual(seen, [len(train) for train, _ in splits])

    def test_group_permutation_keeps_labels_constant_within_group(self):
        rng = np.random.default_rng(1)
        x = rng.normal(size=(60, 4))
        captured = []
        real = d.splits_for

        def spy(labels, groups, **kwargs):
            by_group = defaultdict(set)
            for label, group in zip(labels, groups):
                by_group[group].add(int(label))
            captured.append(all(len(v) == 1 for v in by_group.values()))
            return real(labels, groups, **kwargs)

        with mock.patch.object(d, "splits_for", spy):
            d.group_permutation(x, self.y, self.g, observed=0.5, n=3, trees=5)
        self.assertTrue(captured and all(captured))

    def test_cluster_bootstrap_perfect_prediction(self):
        self.assertEqual(d.cluster_bootstrap(self.y, self.y.copy(), self.g, 50), [1.0, 1.0])


class DuplicateClusterTests(unittest.TestCase):
    def test_duplicates_across_groups_labels_and_folds(self):
        x = np.asarray([[1.0, 2.0], [1.0, 2.0], [1.0, 2.0], [3.0, 4.0], [5.0, 6.0]])
        labels = np.asarray([0, 1, 0, 1, 0])
        groups = np.asarray(["a", "b", "a", "c", "d"])
        splits = [(np.asarray([1, 3, 4]), np.asarray([0, 2])), (np.asarray([0, 2, 4]), np.asarray([1, 3])),
                  (np.asarray([0, 1, 2, 3]), np.asarray([4]))]
        result = xd.duplicate_clusters(x, labels, groups, splits)
        self.assertEqual(result["unique_vectors"], 3)
        self.assertEqual(result["duplicate_clusters"], 1)
        self.assertEqual(result["rows_in_duplicate_clusters"], 3)
        self.assertEqual(result["clusters_spanning_groups"], 1)
        self.assertEqual(result["clusters_spanning_labels"], 1)
        self.assertEqual(result["clusters_spanning_folds"], 1)

    def test_nan_rows_compare_equal(self):
        x = np.asarray([[np.nan, 1.0], [np.nan, 1.0]])
        result = xd.duplicate_clusters(x, np.asarray([0, 0]), np.asarray(["a", "a"]),
                                       [(np.asarray([1]), np.asarray([0])), (np.asarray([0]), np.asarray([1]))])
        self.assertEqual(result["duplicate_clusters"], 1)


if __name__ == "__main__":
    unittest.main()
