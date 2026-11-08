"""Build the .22 runner candidate from the installed .21 runner by exact, single-occurrence text patches.

Purpose: enable a multi-minute (e.g. 300 s / 600 window) fixed observation for the observation-length pilot,
WITHOUT risking the 6 GiB guest. The .21 EbpfCollector buffers the entire raw bpftrace event stream in one
in-RAM list (self.events) and processes it once at the end in collect(). At 20 s this is fine; over 5 minutes a
heavy sample (e.g. ~190k syscalls/s) would buffer tens of millions of events and exhaust guest memory before the
run ends. The time margins (POSTPROCESS_GUARD_SECONDS added to --timeout; batch Guest Control envelope timeout+60)
already scale with --timeout, so no time change is needed; only memory must be made fail-closed.

.22 == .21 plus:
  * a hard cap MAX_RETAINED_EBPF_EVENTS on the live event buffer; past it, events are dropped and counted in
    EbpfCollector.events_overflow instead of appended (bounds guest RAM; the single-pass collect() structures then
    also stay bounded);
  * metadata["ebpf_events_overflow"] records the dropped count;
  * assess_collection_quality rejects a run with ebpf_events_overflow > 0 (fail-closed: an overflowed capture is
    never silently accepted, mirroring the existing ebpf_events_lost rejection);
  * schema bumped to 2026-11-05.22 so .22 captures are never merged with .21/.20/.19 without a compatibility check.

Feature names, counts (169), windowing, and the microsecond anchor are unchanged. For a run that stays under the
cap (all selected pilot samples project well under it), .22 produces byte-identical features to .21 at the same
observation length; the cap only changes behaviour for a run that would otherwise have exhausted memory.
"""

import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
SOURCE = STUDY / "src/malware_runner.py"
SOURCE_SHA256 = "4933ff5c9c56bd097ce565d14a7173bd281dd124aca43d1df0dbe76315e64b9c"
OUTPUT = ROOT / "collector-v22/malware_runner.py"

# 4,000,000 events is ~6x the heaviest selected pilot sample (Gafgyt ~1.1M projected) and under the ~6M kernel
# perf-buffer capacity on a 6-CPU guest, so collect()'s transient structures stay within a few GB in the 6 GiB VM.
MAX_EVENTS = 4_000_000

PATCHES = [
    (
        "schema",
        'TELEMETRY_SCHEMA_VERSION = "2026-10-24.21"',
        'TELEMETRY_SCHEMA_VERSION = "2026-11-05.22"',
    ),
    (
        "max-events constant",
        "DEFAULT_BPFTRACE_PERF_RB_PAGES = 16 * 1024\n",
        "DEFAULT_BPFTRACE_PERF_RB_PAGES = 16 * 1024\n"
        f"MAX_RETAINED_EBPF_EVENTS = {MAX_EVENTS}\n",
    ),
    (
        "overflow counter init",
        "        self.process = None\n        self.events = []\n",
        "        self.process = None\n        self.events = []\n        self.events_overflow = 0\n",
    ),
    (
        "read-events cap",
        "            with self.lock:\n                self.events.append(event)\n",
        "            with self.lock:\n"
        "                if len(self.events) >= MAX_RETAINED_EBPF_EVENTS:\n"
        "                    self.events_overflow += 1\n"
        "                    continue\n"
        "                self.events.append(event)\n",
    ),
    (
        "quality signature",
        "                              interface_counter_deltas=None,\n"
        "                              interface_link_state=None):\n",
        "                              interface_counter_deltas=None,\n"
        "                              interface_link_state=None,\n"
        "                              ebpf_events_overflow=0):\n",
    ),
    (
        "quality reason",
        '        elif ebpf_lost_event_count > 0:\n'
        '            reasons.append(f"ebpf_events_lost:{ebpf_lost_event_count}")\n'
        "    return (\"rejected\" if reasons else \"accepted\", reasons)\n",
        '        elif ebpf_lost_event_count > 0:\n'
        '            reasons.append(f"ebpf_events_lost:{ebpf_lost_event_count}")\n'
        "    if ebpf_events_overflow:\n"
        '        reasons.append(f"ebpf_events_overflow:{ebpf_events_overflow}")\n'
        "    return (\"rejected\" if reasons else \"accepted\", reasons)\n",
    ),
    (
        "overflow metadata",
        '            metadata["ebpf_lost_event_count"] = ebpf_collector.lost_event_count()\n',
        '            metadata["ebpf_lost_event_count"] = ebpf_collector.lost_event_count()\n'
        '            metadata["ebpf_events_overflow"] = ebpf_collector.events_overflow\n',
    ),
    (
        "quality call",
        '            metadata.get("packet_capture_interface_link_state_before_sample"),\n'
        "        )\n"
        "        quality_status, quality_reasons = capture_path_probe_quality(\n",
        '            metadata.get("packet_capture_interface_link_state_before_sample"),\n'
        '            ebpf_events_overflow=metadata.get("ebpf_events_overflow", 0),\n'
        "        )\n"
        "        quality_status, quality_reasons = capture_path_probe_quality(\n",
    ),
]


def main():
    text = SOURCE.read_text(encoding="utf-8")
    actual = hashlib.sha256(text.encode()).hexdigest()
    if actual != SOURCE_SHA256:
        raise SystemExit(f"installed runner SHA mismatch: {actual} != {SOURCE_SHA256}")

    patched = text
    for name, old, new in PATCHES:
        count = patched.count(old)
        if count != 1:
            raise SystemExit(f"patch {name!r}: expected exactly 1 occurrence, found {count}")
        patched = patched.replace(old, new)

    # Guard: the patched module must still parse, and nothing beyond the intended edits changed. Compare the
    # two sources with the known old/new fragments normalised away.
    ast.parse(patched)
    probe = patched
    for _, old, new in PATCHES:
        probe = probe.replace(new, old)
    if probe != text:
        raise SystemExit("unexpected differences beyond the declared patches")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(patched, encoding="utf-8")
    out_sha = hashlib.sha256(patched.encode()).hexdigest()
    print(f"wrote {OUTPUT}")
    print(f"schema  2026-11-05.22")
    print(f"sha256  {out_sha}")
    print(f"cap     MAX_RETAINED_EBPF_EVENTS = {MAX_EVENTS}")


if __name__ == "__main__":
    main()
