"""Tests for the .20 runner: fail-closed post-processing, publish failure, watchdog and IPv4 readiness."""
import io, json, subprocess, sys, tempfile, textwrap, unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests import test_malware_runner_hostmon as base  # noqa: F401  installs the watchdog/psutil stubs
from src import malware_runner
from src.malware_runner import EbpfCollector


def harness(directory, collector, extra=(), patches=()):
    clock = [10.0]
    process = MagicMock(pid=100, returncode=0)
    process.poll.return_value = 0
    waiter = MagicMock()
    waiter.wait.side_effect = lambda duration: clock.__setitem__(0, clock[0] + duration)
    snapshot = {"cpu_percent": 0, "memory_percent": 0, "pids": set(), "net_bytes_sent": 0, "net_bytes_recv": 0,
                "net_packets_sent": 0, "net_packets_recv": 0, "disk_read_bytes": 0, "disk_write_bytes": 0}
    argv = ["malware_runner.py", "/bin/true", "--allow-execution", "--output-dir", directory, "--timeout", "1",
            "--window-sec", "0.5", "--fixed-observation", "--common-launch-wrapper", "--ebpf-password-file", "/unused", *extra]
    stack = [patch.object(sys, "argv", argv), patch.object(malware_runner, "Observer"),
             patch.object(malware_runner, "EbpfCollector", return_value=collector),
             patch.object(malware_runner, "system_snapshot", return_value=snapshot),
             patch.object(malware_runner, "stop_process_group"),
             patch.object(malware_runner.subprocess, "Popen", return_value=process),
             patch.object(malware_runner.threading, "Event", return_value=waiter),
             patch.object(malware_runner.time, "monotonic", side_effect=lambda: clock[0]),
             patch.object(malware_runner.time, "monotonic_ns", side_effect=lambda: int(clock[0] * 1e9)), *patches]
    return stack


def ebpf_collector():
    collector = EbpfCollector("/unused", 0.5)
    collector.events = []
    collector.start = MagicMock()
    collector.stop = MagicMock()
    collector.write_log = MagicMock()
    return collector


def run_main(stack):
    from contextlib import ExitStack
    with ExitStack() as context:
        for item in stack:
            context.enter_context(item)
        context.enter_context(redirect_stdout(io.StringIO()))
        malware_runner.main()


class FailClosed(unittest.TestCase):
    def test_postprocessing_exception_writes_rejected_run_json(self):
        collector = ebpf_collector()
        collector.collect = MagicMock(side_effect=RuntimeError("injected collect failure"))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                run_main(harness(directory, collector))
            metadata = json.loads(next(Path(directory).glob("*/run.json")).read_text())
            self.assertEqual(metadata["collection_quality_status"], "rejected")
            self.assertIn("postprocessing_failed:RuntimeError", metadata["collection_quality_reasons"])
            self.assertIn("injected collect failure", metadata["postprocessing_error"])
            self.assertEqual(metadata["telemetry_schema_version"], malware_runner.TELEMETRY_SCHEMA_VERSION)

    def test_normal_run_still_writes_accepted_shape_twice_in_one_process(self):
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                run_main(harness(directory, ebpf_collector()))
                metadata = json.loads(next(Path(directory).glob("*/run.json")).read_text())
                self.assertEqual(metadata["windows"], 2)
                self.assertNotIn("postprocessing_error", metadata)

    def test_publish_failure_skips_windowing_and_rejects(self):
        packets = MagicMock(uses_pcap=True, buffer_restore_error=None, process=None, interface="enp0s3",
                            buffer_size_kb=65536, drain_ms=1000, lifecycle_events=[], stderr_events=[],
                            original_rmem_max=4194304, rmem_max_during_capture=134217728, effective_rmem_max=4194304,
                            interface_counters_before_sample={}, interface_counters_after_drain={},
                            interface_counters_after_capture={},
                            interface_counter_deltas={"rx_packets": 5, "tx_packets": 5, "rx_bytes": 1, "tx_bytes": 1,
                                                      "rx_dropped": 0, "tx_dropped": 0},
                            interface_link_state_before_sample={"operstate": "up", "carrier": 1})
        packets.snapshot_and_reset.side_effect = lambda window_id=None: {
            "net_packets_captured": 0, "net_bytes_captured": 0, "net_flow_count": 0,
            **malware_runner.P4_NETWORK_ZERO, **malware_runner.NETWORK_EXTRA_ZERO}
        packets.capture_stats.return_value = {"packets_captured": 10, "packets_received_by_filter": 10, "dropped_by_kernel": 0}
        packets.publish_pcap.side_effect = OSError("injected publish failure")
        with tempfile.TemporaryDirectory() as directory:
            stack = harness(directory, ebpf_collector(), extra=("--iface", "enp0s3", "--packet-capture-password-file", "/unused"),
                            patches=(patch.object(malware_runner, "PacketCollector", return_value=packets),
                                     patch.object(malware_runner, "wait_for_interface_ipv4",
                                                  return_value={"ready": True, "addresses": ["10.0.0.10"]}),
                                     patch.object(malware_runner, "capture_path_probe"),
                                     patch.object(malware_runner, "capture_path_probe_quality",
                                                  side_effect=lambda *a: (a[-2], a[-1]))))
            run_main(stack)
            metadata = json.loads(next(Path(directory).glob("*/run.json")).read_text())
            packets.collect_by_window.assert_not_called()
            self.assertEqual(metadata["collection_quality_status"], "rejected")
            self.assertIn("packet_capture_publish_failed", metadata["collection_quality_reasons"])
            self.assertIn("injected publish failure", metadata["packet_capture_publish_error"])

    def test_ipv4_wait_skips_absent_and_tentative_then_settles(self):
        shown = iter([[], [{"addr_info": [{"local": "10.0.0.10", "tentative": True}]}],
                      [{"addr_info": [{"local": "10.0.0.10", "prefixlen": 24}]}]])
        clock, sleeps = [0.0], []
        fake_run = lambda *a, **k: subprocess.CompletedProcess(a, 0, json.dumps(next(shown)), "")
        with patch.object(malware_runner.subprocess, "run", side_effect=fake_run), \
             patch.object(malware_runner, "_REAL_MONOTONIC", side_effect=lambda: clock[0]), \
             patch.object(malware_runner.time, "sleep", side_effect=lambda s: (sleeps.append(s), clock.__setitem__(0, clock[0] + s))):
            result = malware_runner.wait_for_interface_ipv4("enp0s3")
        self.assertEqual(result["ready"], True)
        self.assertEqual(result["addresses"], ["10.0.0.10"])
        self.assertEqual(result["settle_seconds"], 4)
        self.assertEqual(sleeps[-1], 4)

    def test_ipv4_wait_ready_immediately_has_no_settle(self):
        fake_run = lambda *a, **k: subprocess.CompletedProcess(a, 0, json.dumps([{"addr_info": [{"local": "10.0.0.10"}]}]), "")
        with patch.object(malware_runner.subprocess, "run", side_effect=fake_run), \
             patch.object(malware_runner.time, "sleep") as sleep:
            result = malware_runner.wait_for_interface_ipv4("enp0s3")
        self.assertEqual((result["ready"], result["settle_seconds"]), (True, 0))
        sleep.assert_not_called()

    def test_ipv4_wait_times_out_not_ready(self):
        clock = [0.0]
        fake_run = lambda *a, **k: subprocess.CompletedProcess(a, 0, "[]", "")
        with patch.object(malware_runner.subprocess, "run", side_effect=fake_run), \
             patch.object(malware_runner, "_REAL_MONOTONIC", side_effect=lambda: clock[0]), \
             patch.object(malware_runner.time, "sleep", side_effect=lambda s: clock.__setitem__(0, clock[0] + s)):
            result = malware_runner.wait_for_interface_ipv4("enp0s3", timeout_seconds=15)
        self.assertEqual(result["ready"], False)
        self.assertGreaterEqual(result["waited_seconds"], 15)

    def test_ipv4_not_ready_rejects_the_run(self):
        packets = MagicMock(uses_pcap=True, buffer_restore_error=None, process=None, interface="enp0s3",
                            buffer_size_kb=65536, drain_ms=1000, lifecycle_events=[], stderr_events=[],
                            original_rmem_max=4194304, rmem_max_during_capture=134217728, effective_rmem_max=4194304,
                            interface_counters_before_sample={}, interface_counters_after_drain={},
                            interface_counters_after_capture={},
                            interface_counter_deltas={"rx_packets": 5, "tx_packets": 5, "rx_bytes": 1, "tx_bytes": 1,
                                                      "rx_dropped": 0, "tx_dropped": 0},
                            interface_link_state_before_sample={"operstate": "up", "carrier": 1})
        packets.snapshot_and_reset.side_effect = lambda window_id=None: {
            "net_packets_captured": 0, "net_bytes_captured": 0, "net_flow_count": 0,
            **malware_runner.P4_NETWORK_ZERO, **malware_runner.NETWORK_EXTRA_ZERO}
        packets.capture_stats.return_value = {"packets_captured": 10, "packets_received_by_filter": 10, "dropped_by_kernel": 0}
        packets.collect_by_window.return_value = {}
        with tempfile.TemporaryDirectory() as directory:
            stack = harness(directory, ebpf_collector(), extra=("--iface", "enp0s3", "--packet-capture-password-file", "/unused"),
                            patches=(patch.object(malware_runner, "PacketCollector", return_value=packets),
                                     patch.object(malware_runner, "wait_for_interface_ipv4",
                                                  return_value={"ready": False, "addresses": [], "waited_seconds": 15.0}),
                                     patch.object(malware_runner, "capture_path_probe"),
                                     patch.object(malware_runner, "capture_path_probe_quality",
                                                  side_effect=lambda *a: (a[-2], a[-1]))))
            run_main(stack)
            metadata = json.loads(next(Path(directory).glob("*/run.json")).read_text())
            self.assertEqual(metadata["collection_quality_status"], "rejected")
            self.assertIn("packet_capture_interface_ipv4_not_ready", metadata["collection_quality_reasons"])

    def test_watchdog_writes_rejected_record_and_exits_3(self):
        with tempfile.TemporaryDirectory() as directory:
            script = textwrap.dedent('''
                import sys, time, json
                sys.path.insert(0, %r)
                from tests import test_malware_runner_hostmon  # stubs
                from src import malware_runner as m
                m.start_postprocess_watchdog({"run_id": "x", "collection_quality_reasons": []}, %r, -55.8)
                time.sleep(5)
                print("NOT REACHED")
            ''') % (str(Path(__file__).resolve().parents[1]), str(Path(directory) / "run.json"))
            done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30,
                                  cwd=str(Path(__file__).resolve().parents[1]))
            self.assertEqual(done.returncode, 3, done.stderr)
            self.assertNotIn("NOT REACHED", done.stdout)
            metadata = json.loads((Path(directory) / "run.json").read_text())
            self.assertEqual(metadata["collection_quality_reasons"], ["postprocessing_deadline_exceeded"])
            self.assertEqual(metadata["collection_quality_status"], "rejected")

    def test_watchdog_is_noop_after_final_write(self):
        with tempfile.TemporaryDirectory() as directory:
            script = textwrap.dedent('''
                import sys, time
                sys.path.insert(0, %r)
                from tests import test_malware_runner_hostmon  # stubs
                from src import malware_runner as m
                m.start_postprocess_watchdog({"run_id": "x"}, %r, -55.8)
                m.FINALIZED["written"] = True
                time.sleep(0.6)
                print("survived")
            ''') % (str(Path(__file__).resolve().parents[1]), str(Path(directory) / "run.json"))
            done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30,
                                  cwd=str(Path(__file__).resolve().parents[1]))
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("survived", done.stdout)
            self.assertFalse((Path(directory) / "run.json").exists())


if __name__ == "__main__":
    unittest.main()
