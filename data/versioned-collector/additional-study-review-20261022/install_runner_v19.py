"""Install schema .19 into src/malware_runner.py as a formatting-preserving text patch of the frozen .18 source.

The patched file must be AST-identical to the piloted draft collector-v19/malware_runner.py (ignoring only the
draft's prepended provenance docstring). A verbatim .18 copy must already exist in collector-v18-frozen/.
"""

import argparse
import ast
import hashlib
import re
from pathlib import Path

import build_runner_v19 as build
import performance_v4


ROOT = Path(__file__).resolve().parent
TARGET = build.SOURCE
FROZEN_V18 = ROOT / "collector-v18-frozen/malware_runner.py"
DRAFT = build.OUTPUT
DRAFT_SHA256 = "bef85019b580dbb3f135756aa9e9b7eb67447a0edb1cd92be7d630fed06f1ad2"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def probe_source():
    """The V4 probe constants/functions with their original formatting, renamed into the runner namespace."""
    text = Path(performance_v4.__file__).read_text()
    tree = ast.parse(text)
    names = {"TARGET", "CONNECT_TIMEOUT_SECONDS", "SETTLE_SECONDS", "MATCH_SLACK_NS", "PROBE_FILE", "PROBES",
             "capture_path_probe", "pcap_frames", "tcp_frames", "recover", "probe_quality"}
    segments = [ast.get_source_segment(text, node) for node in tree.body
                if (isinstance(node, ast.Assign) and node.targets[0].id in names if isinstance(node, ast.Assign)
                    and isinstance(node.targets[0], ast.Name) else isinstance(node, ast.FunctionDef) and node.name in names)]
    block = "\n".join(segment + ("\n\n" if segment.startswith("def ") else "") for segment in segments)
    for old, new in sorted(build.RENAME.items(), key=lambda item: -len(item[0])):
        if old != new:
            block = re.sub(r"\b%s\b" % re.escape(old), new, block)
    return ("# Per-sample capture-path probes (schema .19): bounded TCP probes to the internal Sink before and\n"
            "# after the feature windows, required in the published PCAP instead of relying on ambient traffic.\n"
            "import socket\n" + block.rstrip() + "\n\n\n")


def patched():
    source = FROZEN_V18.read_text()
    replacements = [
        ('TELEMETRY_SCHEMA_VERSION = "2026-10-20.18"\n', 'TELEMETRY_SCHEMA_VERSION = "%s"\n' % build.SCHEMA),
        ("            if packet_collector is not None:\n                packet_collector.start()\n",
         "            if packet_collector is not None:\n                packet_collector.start()\n"
         "                capture_path_probe('pre', packet_collector)\n"),
        ("                    try:\n                        if packet_collector is not None:\n"
         "                            packet_collector.stop()\n",
         "                    try:\n                        capture_path_probe('post', packet_collector)\n"
         "                        if packet_collector is not None:\n                            packet_collector.stop()\n"),
        ('        metadata.get("packet_capture_interface_link_state_before_sample"),\n    )\n'
         '    metadata["collection_quality_status"] = quality_status\n',
         '        metadata.get("packet_capture_interface_link_state_before_sample"),\n    )\n'
         "    quality_status, quality_reasons = capture_path_probe_quality(\n"
         "        run_dir, metadata, args.iface is not None, sample_started_wall, args.window_sec, rows,\n"
         "        quality_status, quality_reasons)\n"
         '    metadata["collection_quality_status"] = quality_status\n'),
        ("\n\ndef main():\n", "\n\n" + probe_source() + "def main():\n"),
    ]
    for old, new in replacements:
        if source.count(old) != 1:
            raise ValueError("Patch anchor is not unique: " + old[:60])
        source = source.replace(old, new)
    return source


def verify(text):
    draft = ast.parse(DRAFT.read_text())
    draft.body = draft.body[1:]  # drop only the draft's prepended provenance docstring
    if ast.dump(ast.parse(text)) != ast.dump(draft):
        raise ValueError("Patched source is not AST-identical to the piloted .19 draft")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true", help="write src/malware_runner.py (otherwise verify only)")
    options = parser.parse_args()
    if digest(FROZEN_V18) != build.SOURCE_SHA256 or digest(DRAFT) != DRAFT_SHA256:
        raise ValueError("Frozen .18 copy or piloted .19 draft changed")
    text = patched()
    verify(text)
    compile(text, str(TARGET), "exec")
    print("PASS formatting-preserving .19 patch is AST-identical to the piloted draft", DRAFT_SHA256)
    if options.install:
        if digest(TARGET) != build.SOURCE_SHA256:
            raise ValueError("src/malware_runner.py is not the expected .18; refusing to overwrite")
        TARGET.write_text(text)
        print("INSTALLED", TARGET, digest(TARGET))


if __name__ == "__main__":
    main()
