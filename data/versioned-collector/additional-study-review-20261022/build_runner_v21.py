"""Build the .21 runner candidate from the installed .20 runner by exact, single-occurrence text patches.

Change (evidence: integrity-v20/20261024T154623789619Z, int02-udp-r1): one frame lay exactly on the window 0/1 boundary
at microsecond resolution. .20 binned packets with the full-precision float sample start while sample_started_at_utc
and the grid strings are microsecond-rounded, so the offline recorded-window reconstruction put that tie in the other
window (1 of 15 cases; totals exact). .21:
  * anchors the sample start at a whole microsecond (time.time_ns() // 1000) and records it as sample_started_wall_us;
  * writes window_start_utc/window_end_utc from (anchor + k * window_us) exactly;
  * bins PCAP packets with integer microseconds, (packet_us - anchor_us) // window_us, in both the byte-level path and
    the scapy reference path (packet_us is exact for scapy's EDecimal timestamps).
The offline reconstructor compares correctly-rounded floats of the same exact microsecond values with a half-open rule,
so it now resolves boundary ties exactly like the runner. Feature names and counts are unchanged (169); per-window
values differ from .20 only for a frame exactly on a boundary.
"""

import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
SOURCE = STUDY / "src/malware_runner.py"
SOURCE_SHA256 = "80211b3d75f6c541eb3be5d8586dad7227d99b394a59f12c3080902bd060a5ab"
OUTPUT = ROOT / "collector-v21/malware_runner.py"
PATCHES = [
    ("schema", 'TELEMETRY_SCHEMA_VERSION = "2026-10-24.20"', 'TELEMETRY_SCHEMA_VERSION = "2026-10-24.21"'),
    ("decimal import", "from datetime import datetime, timezone\n",
     "from datetime import datetime, timezone\nfrom decimal import ROUND_FLOOR, Decimal\n"),
    ("helper", "\nPCAP_FAST_FALLBACK = object()\n", '''
PCAP_FAST_FALLBACK = object()


def packet_time_us(value):
    """Whole microseconds of a PCAP timestamp: exact for scapy's EDecimal, rounded for a float (older scapy)."""
    if isinstance(value, Decimal):
        return int(value.scaleb(6).to_integral_value(rounding=ROUND_FLOOR))
    return int(round(float(value) * 1_000_000))
'''),
    ("fast path anchor", '''        self.window_decoder_counts = Counter()
        if self.pcap_path is None or not self.pcap_path.exists():
            return {}
''', '''        self.window_decoder_counts = Counter()
        if self.pcap_path is None or not self.pcap_path.exists():
            return {}
        start_us, window_us = int(round(sample_started_wall * 1_000_000)), int(round(window_seconds * 1_000_000))
'''),
    ("fast path binning", '''                timestamp = float(raw_packet.time)
                offset = timestamp - sample_started_wall
                if offset < 0:
                    continue
                window_id = int(offset / window_seconds)
''', '''                timestamp = float(raw_packet.time)
                offset_us = packet_time_us(raw_packet.time) - start_us
                if offset_us < 0:
                    continue
                window_id = offset_us // window_us
'''),
    ("scapy path anchor", '''        if self.pcap_path is None or not self.pcap_path.exists():
            return {}

        results = {}
        next_window = 0
''', '''        if self.pcap_path is None or not self.pcap_path.exists():
            return {}
        start_us, window_us = int(round(sample_started_wall * 1_000_000)), int(round(window_seconds * 1_000_000))

        results = {}
        next_window = 0
'''),
    ("scapy path binning", '''                offset = float(packet.time) - sample_started_wall
                if offset < 0:
                    continue
                window_id = int(offset / window_seconds)
''', '''                offset_us = packet_time_us(packet.time) - start_us
                if offset_us < 0:
                    continue
                window_id = offset_us // window_us
'''),
    ("sample anchor", '''            sample_started_ns = time.monotonic_ns()
            sample_started_wall = time.time()
''', '''            sample_started_ns = time.monotonic_ns()
            sample_started_wall_us = time.time_ns() // 1000  # .21: whole-microsecond anchor for bins and strings
            sample_started_wall = sample_started_wall_us / 1_000_000
            window_us = int(round(args.window_sec * 1_000_000))
'''),
    ("anchor metadata", '''            metadata["sample_started_at_utc"] = datetime.fromtimestamp(
                sample_started_wall, timezone.utc
            ).isoformat()
''', '''            metadata["sample_started_at_utc"] = datetime.fromtimestamp(
                sample_started_wall, timezone.utc
            ).isoformat()
            metadata["sample_started_wall_us"] = sample_started_wall_us
'''),
    ("grid bounds", '''                        bin_start_ts=sample_started_wall + window_id * args.window_sec,
                        bin_end_ts=sample_started_wall + (window_id + 1) * args.window_sec,
''', '''                        bin_start_ts=(sample_started_wall_us + window_id * window_us) / 1_000_000,
                        bin_end_ts=(sample_started_wall_us + (window_id + 1) * window_us) / 1_000_000,
'''),
]


def build():
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise SystemExit("Installed runner is not the expected .20 source")
    text = source.decode()
    for label, old, new in PATCHES:
        count = text.count(old)
        if count != 1:
            raise SystemExit("Patch anchor %r occurs %d times" % (label, count))
        text = text.replace(old, new)
    names = {node.name for node in ast.walk(ast.parse(text)) if isinstance(node, ast.FunctionDef)}
    if "packet_time_us" not in names or "offset = float(packet.time) - sample_started_wall" in text:
        raise SystemExit("Integer-microsecond binning not applied")
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(text)
    report = {"built_utc": datetime.now(timezone.utc).isoformat(), "source": str(SOURCE), "source_sha256": SOURCE_SHA256,
              "output": str(OUTPUT), "output_sha256": hashlib.sha256(text.encode()).hexdigest(), "schema": "2026-10-24.21",
              "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "installed": False,
              "patches": [label for label, _old, _new in PATCHES]}
    (OUTPUT.parent / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("output", "output_sha256", "schema", "installed")}, indent=2))


if __name__ == "__main__":
    build()
