"""Focused tests for the .22 memory fail-closed guard. Run from a shadow repo whose src/malware_runner.py is the
.22 candidate (see build_runner_v22.py). The rest of the runner's behaviour is covered by the inherited .21 suite.
"""
import unittest

from tests import test_malware_runner_hostmon  # noqa: F401  installs watchdog/psutil stubs
from src import malware_runner
from src.malware_runner import EbpfCollector, assess_collection_quality


def _up():
    return {"operstate": "up", "carrier": 1}


class V22SchemaTests(unittest.TestCase):
    def test_schema_is_22(self):
        self.assertEqual(malware_runner.TELEMETRY_SCHEMA_VERSION, "2026-11-05.22")


class V22QualityOverflowTests(unittest.TestCase):
    # eBPF enabled, packet capture disabled, so only the eBPF path is exercised.
    def test_overflow_zero_still_accepts_a_clean_run(self):
        status, reasons = assess_collection_quality(
            False, "disabled", None, True, "active", 0, ebpf_events_overflow=0,
        )
        self.assertEqual(status, "accepted")
        self.assertEqual(reasons, [])

    def test_positive_overflow_rejects_fail_closed(self):
        status, reasons = assess_collection_quality(
            False, "disabled", None, True, "active", 0, ebpf_events_overflow=1234,
        )
        self.assertEqual(status, "rejected")
        self.assertIn("ebpf_events_overflow:1234", reasons)

    def test_default_overflow_param_is_backward_compatible(self):
        # Callers that do not pass the new keyword behave exactly as before.
        status, _ = assess_collection_quality(False, "disabled", None, True, "active", 0)
        self.assertEqual(status, "accepted")


class V22ReadEventsCapTests(unittest.TestCase):
    class _FakeProc:
        def __init__(self, lines):
            self.stdout = iter(lines)

    def _collector_over(self, cap, n_events):
        malware_runner.MAX_RETAINED_EBPF_EVENTS = cap
        c = EbpfCollector(password_file="/dev/null")
        lines = [f"EBPF\t{1000 + i}\t100\t100\tsample\tsyscall\tid=1 abi=0\n" for i in range(n_events)]
        c.process = self._FakeProc(lines)
        c._read_events()
        return c

    def test_buffer_is_capped_and_overflow_counted(self):
        try:
            c = self._collector_over(cap=10, n_events=25)
            self.assertEqual(len(c.events), 10)
            self.assertEqual(c.events_overflow, 15)
        finally:
            malware_runner.MAX_RETAINED_EBPF_EVENTS = 4_000_000

    def test_under_cap_keeps_all_events_no_overflow(self):
        try:
            c = self._collector_over(cap=1000, n_events=25)
            self.assertEqual(len(c.events), 25)
            self.assertEqual(c.events_overflow, 0)
        finally:
            malware_runner.MAX_RETAINED_EBPF_EVENTS = 4_000_000

    def test_default_cap_is_four_million(self):
        self.assertEqual(malware_runner.MAX_RETAINED_EBPF_EVENTS, 4_000_000)


if __name__ == "__main__":
    unittest.main()
