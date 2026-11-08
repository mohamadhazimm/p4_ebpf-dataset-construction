"""Tests for the .21 runner: whole-microsecond anchor, integer-microsecond packet bins, exact grid strings."""
import csv
import json
import struct
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from tests import test_malware_runner_hostmon  # noqa: F401  installs the watchdog/psutil stubs
from tests.test_runner_v20_failclosed import ebpf_collector, harness, run_main
from src import malware_runner
from scripts import rebuild_versioned_p4_csvs  # noqa: F401  puts p4_ebpf on sys.path
import analyze_p4_pcap_ablation as p4

ANCHOR_US = 1792848528669581
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def utc(us):
    return (EPOCH + timedelta(microseconds=us)).isoformat()


def udp_frame(sport):
    payload = b"tie-test"
    udp = struct.pack("!HHHH", sport, 65003, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([10, 0, 0, 10]), bytes([239, 255, 42, 198]))
    return bytes.fromhex("01005e7f2ac6001b210aee09") + b"\x08\x00" + ip + udp


def write_pcap(path, offsets_us):
    with open(path, "wb") as stream:
        stream.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, offset in enumerate(offsets_us):
            moment = ANCHOR_US + offset
            frame = udp_frame(40000 + index)
            stream.write(struct.pack("<IIII", moment // 1_000_000, moment % 1_000_000, len(frame), len(frame)) + frame)


class MicrosecondBins(unittest.TestCase):
    OFFSETS = [0, 499_999, 500_000, 500_001, 1_000_000, 19_999_999, 20_000_000]
    EXPECTED = [0, 0, 1, 1, 2, 39, None]

    def test_packet_time_us_is_exact(self):
        self.assertEqual(malware_runner.packet_time_us(Decimal("1792848528.669581")), ANCHOR_US)
        self.assertEqual(malware_runner.packet_time_us(1792848528.669581), ANCHOR_US)
        from scapy.utils import EDecimal
        self.assertEqual(malware_runner.packet_time_us(EDecimal(1792848528) + EDecimal("0.000001") * 669581), ANCHOR_US)

    def test_boundary_ties_agree_between_runner_paths_and_reconstructor(self):
        with tempfile.TemporaryDirectory() as directory:
            pcap = Path(directory) / "tie.pcap"
            write_pcap(pcap, self.OFFSETS)
            collector = malware_runner.PacketCollector.__new__(malware_runner.PacketCollector)
            collector.pcap_path = pcap
            fast = collector.collect_by_window(ANCHOR_US / 1_000_000, 0.5, 40)
            reference = collector.collect_by_window_scapy(ANCHOR_US / 1_000_000, 0.5, 40)
            self.assertEqual(fast, reference)
            counts = [fast[k]["net_packets_captured"] for k in range(40)]
            expected = [sum(1 for w in self.EXPECTED if w == k) for k in range(40)]
            self.assertEqual(counts, expected)
            rows = [{"window_start_utc": utc(ANCHOR_US + k * 500_000), "window_end_utc": utc(ANCHOR_US + (k + 1) * 500_000),
                     "net_packets_captured": str(counts[k])} for k in range(40)]
            metadata = {"window_seconds": 0.5, "started_at_utc": utc(ANCHOR_US - 3_000_000),
                        "finished_at_utc": utc(ANCHOR_US + 30_000_000)}
            from scapy.utils import PcapReader
            with PcapReader(str(pcap)) as capture:
                times = [float(packet.time) for packet in capture]
            import numpy as np
            assignment, diagnostics = p4.recover_frame_windows(np.asarray(times), rows, metadata)
            self.assertEqual(diagnostics["alignment_status"], "unique")
            self.assertEqual(assignment, self.EXPECTED)

    def test_run_json_records_anchor_and_exact_grid(self):
        with tempfile.TemporaryDirectory() as directory:
            run_main(harness(directory, ebpf_collector()))
            run = next(Path(directory).glob("*/run.json"))
            metadata = json.loads(run.read_text())
            anchor = metadata["sample_started_wall_us"]
            self.assertIsInstance(anchor, int)
            self.assertEqual(metadata["sample_started_at_utc"], utc(anchor))
            rows = list(csv.DictReader((run.parent / "telemetry.csv").open()))
            self.assertEqual([row["window_start_utc"] for row in rows], [utc(anchor + k * 500_000) for k in range(len(rows))])
            self.assertEqual([row["window_end_utc"] for row in rows], [utc(anchor + (k + 1) * 500_000) for k in range(len(rows))])


if __name__ == "__main__":
    unittest.main()
