"""Deterministic bracketing capture-path probes over the immutable performance V3 harness.

Root cause addressed: the unchanged .18 quality gate rejects a capture with zero
packets and zero NIC deltas (``packet_capture_interface_no_traffic``).  In the
isolated lab the only enp0s3 traffic is incidental NetworkManager connectivity
checks whose retry interval doubles against the INetSim Sink, so long single-boot
benchmarks eventually contain fully quiet 20-second windows although the capture
path is alive.  The gate therefore measured ambient traffic, not capture liveness.

V4 keeps every original gate and adds positive evidence instead of waiving it:
one bounded TCP probe from the runner process to the internal Sink immediately
after tcpdump readiness (before eBPF start, sample start and Popen) and one
immediately after observation end/eBPF shutdown (before the PCAP drain/SIGINT).
Both must be independently recovered from the published PCAP, outside the
feature windows, or the case is rejected.  Probe frames lie outside the task
wall, wait4 CPU, the telemetry windows/P4 features and the target cgroup.
"""

import argparse
import ast
import hashlib
import json
import signal
import socket
import struct
import time
from pathlib import Path

import performance_v3 as frozen


ROOT = Path(__file__).resolve().parent
SCHEMA = "2026-10-23.27-performance-capture-probe-harness"
FROZEN_SHA256 = "73acfd00f9f8e28132dcfe8ba92c03fc9e359d5bcaff9e9654001182031634ef"
if hashlib.sha256(Path(frozen.__file__).read_bytes()).hexdigest() != FROZEN_SHA256:
    raise ValueError("Measured performance V3 source changed")

identity = frozen.identity
launch = frozen.launch
write_task_usage = frozen.write_task_usage
original_sensors_enabled = frozen.original_sensors_enabled
broker = frozen.broker
summarize = frozen.summarize
Session = frozen.Session

TARGET = ("10.0.0.1", 80)
CONNECT_TIMEOUT_SECONDS = 1.0
SETTLE_SECONDS = 0.2
MATCH_SLACK_NS = 1_000_000_000
PROBE_FILE = "capture-path-probe.json"
PROBES = {}


def capture_path_probe(phase, packet_collector):
    """One bounded TCP handshake to the internal Sink; aborted with RST. Never raises."""
    if packet_collector is None:
        return
    record = {"phase": phase, "target": "%s:%d" % TARGET, "connected": False, "error": None,
              "local_port": None, "close": "so_linger_0_rst", "settle_seconds": SETTLE_SECONDS}
    try:
        record["started_wall_ns"] = time.time_ns()
        record["started_monotonic_ns"] = time.monotonic_ns()
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            stream.settimeout(CONNECT_TIMEOUT_SECONDS)
            stream.bind(("", 0))
            record["local_port"] = stream.getsockname()[1]
            stream.connect(TARGET)
            record["connected"] = True
            record["local_address"] = stream.getsockname()[0]
        except OSError as error:
            record["error"] = type(error).__name__ + ": " + str(error)
        finally:
            stream.close()
            record["ended_wall_ns"] = time.time_ns()
            record["ended_monotonic_ns"] = time.monotonic_ns()
        time.sleep(SETTLE_SECONDS)
        record["settled_wall_ns"] = time.time_ns()
    except Exception as error:  # the probe must never disturb the original lifecycle
        record["error"] = type(error).__name__ + ": " + str(error)
    PROBES[phase] = record


def pcap_frames(path):
    data = Path(path).read_bytes()
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    if data[:4] not in formats or len(data) < 24:
        raise ValueError("Not a classic PCAP")
    endian, scale = formats[data[:4]]
    if struct.unpack(endian + "I", data[20:24])[0] & 0xFFFF != 1:
        raise ValueError("PCAP link type is not Ethernet")
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("Truncated PCAP record header")
        seconds, fraction, included, _original = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if offset + included > len(data):
            raise ValueError("Truncated PCAP record")
        yield seconds * 1_000_000_000 + fraction * scale, data[offset:offset + included]
        offset += included


def tcp_frames(path):
    for timestamp, frame in pcap_frames(path):
        position, ethertype = 14, frame[12:14]
        while ethertype in (b"\x81\x00", b"\x88\xa8") and len(frame) >= position + 4:
            ethertype, position = frame[position + 2:position + 4], position + 4
        if ethertype != b"\x08\x00" or len(frame) < position + 20:
            continue
        header = frame[position:]
        length = (header[0] & 0x0F) * 4
        if header[0] >> 4 != 4 or header[9] != 6 or len(header) < length + 14:
            continue
        sport, dport = struct.unpack("!HH", header[length:length + 4])
        yield {"ns": timestamp, "src": socket.inet_ntoa(header[12:16]), "dst": socket.inet_ntoa(header[16:20]),
               "sport": sport, "dport": dport, "flags": header[length + 13]}


def recover(frames, record, window_start_ns, window_end_ns):
    port = record.get("local_port")
    tuple_frames = [frame for frame in frames if port and (
        (frame["sport"] == port and frame["dst"] == TARGET[0] and frame["dport"] == TARGET[1])
        or (frame["src"] == TARGET[0] and frame["sport"] == TARGET[1] and frame["dport"] == port))]
    low = record.get("started_wall_ns", 0) - MATCH_SLACK_NS
    high = record.get("ended_wall_ns", 0) + MATCH_SLACK_NS
    syn = [frame for frame in tuple_frames if frame["sport"] == port and frame["flags"] & 0x02
           and not frame["flags"] & 0x10 and low <= frame["ns"] <= high]
    reply = [frame for frame in tuple_frames if frame["sport"] == TARGET[1] and low <= frame["ns"] <= high
             and (frame["flags"] & 0x12 == 0x12 or frame["flags"] & 0x04)]
    inside = [frame for frame in tuple_frames if window_start_ns <= frame["ns"] < window_end_ns]
    return {"local_port": port, "tuple_frames": len(tuple_frames), "outbound_syn": len(syn), "sink_reply": len(reply),
            "frames_inside_feature_windows": len(inside), "connected": record.get("connected"),
            "recovered": bool(port and syn and reply and not inside)}


def probe_quality(run_dir, metadata, capture_enabled, sample_started_wall, window_sec, rows, status, reasons):
    """Require both bracketing probes in the published PCAP; never relaxes earlier findings."""
    if not capture_enabled:
        return status, reasons
    reasons = list(reasons)
    summary = {"schema": SCHEMA, "target": "%s:%d" % TARGET, "probes": dict(PROBES), "recovery": {},
               "in_window_packets_captured": sum(int(row.get("net_packets_captured", 0)) for row in rows),
               "limitation": "Bracketing probes show the single tcpdump process captured traffic before and after the "
                             "feature windows; they do not prove continuous in-window completeness."}
    findings = []
    try:
        if sample_started_wall is None:
            raise ValueError("sample start unavailable")
        window_start_ns = int(round(sample_started_wall * 1_000_000_000))
        window_end_ns = window_start_ns + int(round(len(rows) * window_sec * 1_000_000_000))
        summary.update(window_start_wall_ns=window_start_ns, window_end_wall_ns=window_end_ns)
        frames = list(tcp_frames(Path(run_dir) / "packet_capture.pcap"))
        for phase in ("pre", "post"):
            record = PROBES.get(phase)
            if record is None:
                findings.append("capture_path_probe_" + phase + "_missing")
                continue
            result = recover(frames, record, window_start_ns, window_end_ns)
            outside = (record.get("ended_wall_ns", 0) < window_start_ns if phase == "pre"
                       else record.get("started_wall_ns", 0) >= window_end_ns)
            result["probe_interval_outside_feature_windows"] = outside
            summary["recovery"][phase] = result
            if result["frames_inside_feature_windows"] or not outside:
                findings.append("capture_path_probe_" + phase + "_inside_feature_windows")
            elif not result["recovered"]:
                findings.append("capture_path_probe_" + phase + "_not_recovered")
    except Exception as error:
        summary["error"] = type(error).__name__ + ": " + str(error)
        findings.append("capture_path_probe_unverifiable")
    summary["findings"] = findings
    summary["status"] = "recovered" if not findings else "rejected"
    metadata["capture_path_probe"] = summary
    try:
        (Path(run_dir) / PROBE_FILE).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        findings.append("capture_path_probe_record_unwritable")
        summary["write_error"] = str(error)
    if findings:
        return "rejected", reasons + findings
    return status, reasons


def _expression(source):
    return ast.parse(source).body[0]


def _locate(tree, predicate, label):
    matches = []
    for parent in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(parent, field, None)
            if isinstance(block, list):
                matches.extend((block, index) for index, node in enumerate(block) if predicate(node))
    if len(matches) != 1:
        raise ValueError("Probe anchor not unique: " + label)
    return matches[0]


def _is_call(node, text):
    return isinstance(node, ast.Expr) and ast.unparse(node.value) == text


def generate(base):
    tree = ast.parse(frozen.generate(base))
    imports = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "performance_v3":
                    alias.name = "performance_v4"
                    imports += 1
        elif isinstance(node, ast.Name) and node.id == "performance_v3":
            node.id = "performance_v4"
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "TELEMETRY_SCHEMA_VERSION" for target in node.targets
        ):
            node.value = ast.Constant(SCHEMA)
    if imports != 1:
        raise ValueError("Frozen performance import anchor differs")
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    block, index = _locate(main, lambda node: _is_call(node, "packet_collector.start()"), "start")
    block.insert(index + 1, _expression("performance_v4.capture_path_probe('pre', packet_collector)"))
    block, index = _locate(main, lambda node: isinstance(node, ast.If)
                           and ast.unparse(node.test) == "packet_collector is not None"
                           and len(node.body) == 1 and _is_call(node.body[0], "packet_collector.stop()"), "stop")
    block.insert(index, _expression("performance_v4.capture_path_probe('post', packet_collector)"))
    block, index = _locate(main, lambda node: isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                           and ast.unparse(node.value.func) == "assess_collection_quality", "quality")
    block.insert(index + 1, _expression(
        "(quality_status, quality_reasons) = performance_v4.probe_quality(run_dir, metadata, args.iface is not None, "
        "sample_started_wall, args.window_sec, rows, quality_status, quality_reasons)"))
    generated = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    compile(generated, "performance-v4-runner", "exec")
    return generated


def write_pcap(path, frames, nanosecond=False):
    output = bytearray(struct.pack("<IHHiIII", 0xA1B23C4D if nanosecond else 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for timestamp, frame in frames:
        fraction = timestamp % 1_000_000_000 if nanosecond else (timestamp % 1_000_000_000) // 1000
        output += struct.pack("<IIII", timestamp // 1_000_000_000, fraction, len(frame), len(frame)) + frame
    Path(path).write_bytes(bytes(output))


def tcp_frame(source, destination, sport, dport, flags, vlan=False):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, socket.inet_aton(source), socket.inet_aton(destination))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0)
    tag = b"\x81\x00\x00\x01" if vlan else b""
    return b"\x02" * 6 + b"\x04" * 6 + tag + b"\x08\x00" + ip + tcp


def self_test(base=None):
    import tempfile

    base = Path(base) if base is not None else ROOT.parents[2] / "src/malware_runner.py"
    generated = generate(base)
    assert "performance_v4.launch" in generated and "performance_v3." not in generated
    order = ["packet_collector.start()", "performance_v4.capture_path_probe('pre', packet_collector)",
             "ebpf_collector.start()", "attribution.prepare(run_dir, sample)", "sample_started_wall = time.time()",
             "performance_v4.launch(", "attribution.observation_end(", "observation_ended_ns = min(",
             "ebpf_collector.stop()", "performance_v4.capture_path_probe('post', packet_collector)",
             "packet_collector.stop()", "packet_collector.publish_pcap(", "= assess_collection_quality(",
             "performance_v4.probe_quality(", "attribution.quality("]
    positions = [generated.index(text) for text in order]
    assert positions == sorted(positions), "Probe insertion ordering differs"
    assert generated.count("capture_path_probe(") == 2 and generated.count("probe_quality(") == 1
    before = {node.name: ast.dump(node) for node in ast.parse(base.read_text()).body
              if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    after = {node.name: ast.dump(node) for node in ast.parse(generated).body
             if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    assert before == after, "Original feature/helper code changed"
    frozen_body = ast.parse(frozen.generate(base))
    frozen_main = next(node for node in frozen_body.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    new_main = next(node for node in ast.parse(generated).body if isinstance(node, ast.FunctionDef) and node.name == "main")
    removed = {ast.unparse(node).replace("performance_v3", "performance_v4") for node in ast.walk(frozen_main) if isinstance(node, ast.stmt)}
    kept = {ast.unparse(node) for node in ast.walk(new_main) if isinstance(node, ast.stmt)}
    added = [text for text in kept if text not in removed]
    assert all("capture_path_probe" in text or "probe_quality" in text or "\n" in text for text in added), added

    start = 1_800_000_000_000_000_000
    window_end = start + 20_000_000_000
    pre = {"local_port": 40001, "connected": True, "started_wall_ns": start - 400_000_000, "ended_wall_ns": start - 390_000_000}
    post = {"local_port": 40002, "connected": True, "started_wall_ns": window_end + 10_000_000, "ended_wall_ns": window_end + 20_000_000}

    def frames(port, at, reply_flags=0x12, vlan=False):
        return [(at, tcp_frame("10.0.0.10", "10.0.0.1", port, 80, 0x02, vlan)),
                (at + 300_000, tcp_frame("10.0.0.1", "10.0.0.10", 80, port, reply_flags, vlan)),
                (at + 400_000, tcp_frame("10.0.0.10", "10.0.0.1", port, 80, 0x04, vlan))]

    rows = [{"net_packets_captured": 0} for _ in range(40)]
    cases = {
        "pass_us": (frames(40001, pre["started_wall_ns"] + 1000) + frames(40002, post["started_wall_ns"] + 1000), False, []),
        "pass_ns_vlan_rst": (frames(40001, pre["started_wall_ns"] + 1000, 0x14, True)
                             + frames(40002, post["started_wall_ns"] + 1000), True, []),
        "no_post": (frames(40001, pre["started_wall_ns"] + 1000), False, ["capture_path_probe_post_not_recovered"]),
        "no_reply": ([frames(40001, pre["started_wall_ns"] + 1000)[0]] + frames(40002, post["started_wall_ns"] + 1000),
                     False, ["capture_path_probe_pre_not_recovered"]),
        "wrong_port": (frames(40009, pre["started_wall_ns"] + 1000) + frames(40002, post["started_wall_ns"] + 1000),
                       False, ["capture_path_probe_pre_not_recovered"]),
        "stray_inside": (frames(40001, pre["started_wall_ns"] + 1000) + frames(40002, post["started_wall_ns"] + 1000)
                         + [(start + 5_000_000, tcp_frame("10.0.0.1", "10.0.0.10", 80, 40001, 0x11))],
                         False, ["capture_path_probe_pre_inside_feature_windows"]),
        "empty": ([], False, ["capture_path_probe_pre_not_recovered", "capture_path_probe_post_not_recovered"]),
    }
    with tempfile.TemporaryDirectory(prefix="hazim-performance-v4-") as directory:
        run_dir = Path(directory)
        for name, (packets, nanosecond, expected) in cases.items():
            write_pcap(run_dir / "packet_capture.pcap", sorted(packets), nanosecond)
            PROBES.clear()
            PROBES.update(pre=dict(pre), post=dict(post))
            metadata = {}
            status, reasons = probe_quality(run_dir, metadata, True, start / 1e9, 0.5, rows, "accepted", [])
            assert reasons == expected, (name, reasons)
            assert status == ("accepted" if not expected else "rejected"), name
            assert json.loads((run_dir / PROBE_FILE).read_text())["status"] == metadata["capture_path_probe"]["status"]
        PROBES.clear()
        PROBES.update(pre=dict(pre), post=dict(post, started_wall_ns=window_end - 1))
        write_pcap(run_dir / "packet_capture.pcap", sorted(frames(40001, pre["started_wall_ns"] + 1000)
                                                          + frames(40002, window_end + 1000)))
        assert probe_quality(run_dir, {}, True, start / 1e9, 0.5, rows, "accepted", [])[1] == [
            "capture_path_probe_post_inside_feature_windows"]
        PROBES.clear()
        PROBES["pre"] = dict(pre)
        assert "capture_path_probe_post_missing" in probe_quality(run_dir, {}, True, start / 1e9, 0.5, rows, "accepted", [])[1]
        assert probe_quality(run_dir, {}, False, None, 0.5, rows, "rejected", ["x"]) == ("rejected", ["x"])
        assert probe_quality(run_dir, {}, True, start / 1e9, 0.5, rows, "rejected",
                             ["packet_capture_interface_no_traffic"])[0] == "rejected"
        (run_dir / "packet_capture.pcap").write_bytes(b"corrupt")
        assert probe_quality(run_dir, {}, True, start / 1e9, 0.5, rows, "accepted", [])[1] == ["capture_path_probe_unverifiable"]
    PROBES.clear()
    capture_path_probe("pre", None)
    assert not PROBES
    print("PASS V4 probe insertion ordering, unchanged helpers/main remainder, synthetic PCAP recovery and fail-closed probe guards")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--broker", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    else:
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        broker(options.broker)
