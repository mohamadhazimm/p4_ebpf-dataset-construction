"""Build the .20 runner candidate from the installed .19 runner by exact, single-occurrence text patches.

Changes (each traced to measured evidence in AGENTS.md, 2026-10-24):
  1. Fast PCAP windowing: collect_by_window decodes Ethernet/VLAN/IPv4/IPv6 + TCP/UDP/ICMP with struct and hands every
     other packet to scapy; .19's scapy implementation is kept verbatim as collect_by_window_scapy (reference and
     fallback for non-Ethernet captures). Timestamps come from scapy's own PcapReader with the raw link layer, so they
     equal .19's float(packet.time) on any scapy version. Cause: 49.8 s scapy re-parse of a 270k-packet flood exceeded
     the batch's 80 s Guest Control envelope (runner_failed, no run.json).
  2. Recorded window bounds: window_start_utc/window_end_utc are the nominal grid the runner actually bins on
     (sample start + k*W); window_seconds keeps the observed loop duration. Cause: recorded strings were late wake-up
     times, so offline recorded-interval binning slipped frames across boundaries (14/14 + 18/18 reproduced).
  3. Fail-closed post-processing: a PCAP publish failure skips packet windowing and rejects with
     packet_capture_publish_failed (it used to raise PermissionError with no run.json); any post-processing exception
     writes a rejected run.json before propagating; a SIGALRM interval timer armed for post-processing writes a rejected run.json and exits at timeout+56 s
     (the batch envelope is timeout+60 s; the slowest saved successful run finished at 70.4 s); a hard exit after a
     successful finish avoids the post-write linger seen in Mirai 0882 (run.json at 69.2 s, process still alive at 80.4 s).
  4. Interface IPv4 readiness: before capture starts, wait (netlink only, <=15 s) for a configured, non-tentative
     IPv4 address on the capture interface and pause 4 s if the wait was needed; reject with
     packet_capture_interface_ipv4_not_ready otherwise. Cause: quiet-v3.2 boot 10, Guest Control answered during
     NetworkManager's RFC 5227 probing and the first packets left from 0.0.0.0.
Feature names and counts are unchanged (169). In-kernel syscall aggregation (eBPF loss on >~1.06M-event bursts) is NOT
part of this build.
"""

import ast
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
SOURCE = STUDY / "src/malware_runner.py"
SOURCE_SHA256 = "37e5a156774663214ba231825c5174c048d5468747b0a213624153426af60b0a"
OUTPUT = ROOT / "collector-v20/malware_runner.py"
SCHEMA_OLD, SCHEMA_NEW = '"2026-10-24.19"', '"2026-10-24.20"'


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit("Patch anchor %r occurs %d times" % (label, count))
    return text.replace(old, new)


NETWORK_EXTRA_OLD = '''    def record_packet(self, window_id, packet):
        if packet.haslayer("IP"):
            ip_layer = packet.getlayer("IP")
            protocol = int(ip_layer.proto)
            ipv6 = False
        elif packet.haslayer("IPv6"):
            ip_layer = packet.getlayer("IPv6")
            protocol = int(ip_layer.nh)
            ipv6 = True
        else:
            return

        state = self.windows.setdefault(window_id, self._new_window())
        packet_size = len(packet)
        timestamp = float(packet.time)
        source_ip = str(ip_layer.src)
        destination_ip = str(ip_layer.dst)
        transport = packet.getlayer("TCP") or packet.getlayer("UDP")
        source_port = int(transport.sport) if transport is not None else -1
        destination_port = int(transport.dport) if transport is not None else -1
'''
NETWORK_EXTRA_NEW = '''    def record_packet(self, window_id, packet):
        if packet.haslayer("IP"):
            ip_layer = packet.getlayer("IP")
            protocol = int(ip_layer.proto)
            ipv6 = False
        elif packet.haslayer("IPv6"):
            ip_layer = packet.getlayer("IPv6")
            protocol = int(ip_layer.nh)
            ipv6 = True
        else:
            return
        transport = packet.getlayer("TCP") or packet.getlayer("UDP")
        ports = (int(transport.sport), int(transport.dport)) if transport is not None else None
        tcp_flags = int(packet.getlayer("TCP").flags) if packet.haslayer("TCP") else None
        self.record_fields(window_id, float(packet.time), len(packet), ipv6, protocol,
                           str(ip_layer.src), str(ip_layer.dst), ports, tcp_flags)

    def record_fields(self, window_id, timestamp, packet_size, ipv6, protocol, source_ip,
                      destination_ip, ports, tcp_flags):
        """Field-level entry point shared by the scapy path and the .20 byte-level decoder."""
        state = self.windows.setdefault(window_id, self._new_window())
        source_port, destination_port = ports if ports is not None else (-1, -1)
'''
NETWORK_EXTRA_FLAGS_OLD = '''        if protocol == 6:
            state["tcp"] += 1
            if packet.haslayer("TCP"):
                flags = int(packet.getlayer("TCP").flags)
'''
NETWORK_EXTRA_FLAGS_NEW = '''        if protocol == 6:
            state["tcp"] += 1
            if tcp_flags is not None:
                flags = tcp_flags
'''
NETWORK_EXTRA_PORTS_OLD = '''        if transport is not None:
            state["source_ports"].add(source_port)
            state["destination_ports"].add(destination_port)
            ports = {source_port, destination_port}
'''
NETWORK_EXTRA_PORTS_NEW = '''        if ports is not None:
            state["source_ports"].add(source_port)
            state["destination_ports"].add(destination_port)
            ports = {source_port, destination_port}
'''

DECODER = '''
PCAP_FAST_FALLBACK = object()


def decode_ethernet_fields(data):
    """Byte-level decode of one Ethernet frame for .20 packet windowing.

    Returns None for a frame scapy would see without IP/IPv6 (only ARP is decided here), a tuple
    (ip_version, source_ip, destination_ip, protocol, ports_or_None, tcp_flags_or_None) for plain IPv4/IPv6 carrying
    TCP, UDP, ICMP or ICMPv6, and PCAP_FAST_FALLBACK for everything else (other EtherTypes, 802.3 frames, more than two
    VLAN tags, IPv4 options are fine but other IP protocols, IPv6 extension headers, short or truncated headers), which
    the caller hands to scapy unchanged. Non-first IPv4 fragments carry no ports, as in scapy.
    """
    if len(data) < 14:
        return PCAP_FAST_FALLBACK
    offset, ethertype, tags = 12, (data[12] << 8) | data[13], 0
    while ethertype in (0x8100, 0x88A8):
        tags += 1
        if tags > 2 or len(data) < offset + 6:
            return PCAP_FAST_FALLBACK
        offset += 4
        ethertype = (data[offset] << 8) | data[offset + 1]
    offset += 2
    if ethertype == 0x0806:
        return None
    if ethertype == 0x0800:
        if len(data) < offset + 20 or data[offset] >> 4 != 4:
            return PCAP_FAST_FALLBACK
        header = (data[offset] & 0x0F) * 4
        total = (data[offset + 2] << 8) | data[offset + 3]
        if header < 20 or total < header or len(data) < offset + header:
            return PCAP_FAST_FALLBACK
        limit = min(len(data), offset + total)
        protocol = data[offset + 9]
        if protocol not in (1, 6, 17):
            return PCAP_FAST_FALLBACK
        source = socket.inet_ntoa(data[offset + 12:offset + 16])
        destination = socket.inet_ntoa(data[offset + 16:offset + 20])
        if ((data[offset + 6] & 0x1F) << 8 | data[offset + 7]) != 0:
            return (4, source, destination, protocol, None, None)
        transport = offset + header
        version = 4
    elif ethertype == 0x86DD:
        if len(data) < offset + 40 or data[offset] >> 4 != 6:
            return PCAP_FAST_FALLBACK
        protocol = data[offset + 6]
        if protocol not in (6, 17, 58):
            return PCAP_FAST_FALLBACK
        limit = min(len(data), offset + 40 + ((data[offset + 4] << 8) | data[offset + 5]))
        source = socket.inet_ntop(socket.AF_INET6, data[offset + 8:offset + 24])
        destination = socket.inet_ntop(socket.AF_INET6, data[offset + 24:offset + 40])
        transport = offset + 40
        version = 6
    else:
        return PCAP_FAST_FALLBACK
    if protocol in (1, 58):
        return (version, source, destination, protocol, None, None)
    if limit < transport + (20 if protocol == 6 else 8):
        return PCAP_FAST_FALLBACK
    ports = ((data[transport] << 8) | data[transport + 1], (data[transport + 2] << 8) | data[transport + 3])
    flags = ((data[transport + 12] & 0x01) << 8 | data[transport + 13]) if protocol == 6 else None
    return (version, source, destination, protocol, ports, flags)


class P4NetworkAccumulator:'''

COLLECT_OLD_HEAD = '''    def collect_by_window(self, sample_started_wall, window_seconds, window_count):
        from scapy.layers.inet import IP
'''
COLLECT_NEW = '''    def collect_by_window(self, sample_started_wall, window_seconds, window_count):
        """.20 byte-level windowing; per-window results equal collect_by_window_scapy (.19) by construction."""
        from scapy.config import conf
        from scapy.layers.inet import IP  # noqa: F401  registers layers for the per-packet scapy fallback
        from scapy.layers.inet6 import IPv6  # noqa: F401
        from scapy.layers.l2 import Ether
        from scapy.utils import PcapReader

        self.window_decoder_counts = Counter()
        if self.pcap_path is None or not self.pcap_path.exists():
            return {}
        with PcapReader(str(self.pcap_path)) as probe_reader:
            ethernet = probe_reader.linktype == 1
        if not ethernet:
            self.window_decoder_counts["scapy_reference_non_ethernet"] = 1
            return self.collect_by_window_scapy(sample_started_wall, window_seconds, window_count)

        packet_counts = defaultdict(int)
        byte_counts = defaultdict(int)
        flows_by_window = defaultdict(set)
        p4_network = P4NetworkAccumulator(window_seconds)
        network_extra = NetworkPacketFeatureAccumulator()
        results = {}
        next_window = 0

        def finish_window(window_id):
            results[window_id] = {
                "net_packets_captured": packet_counts[window_id],
                "net_bytes_captured": byte_counts[window_id],
                "net_flow_count": len(flows_by_window[window_id]),
                **p4_network.summarize_window(window_id),
                **network_extra.summarize_window(window_id),
            }

        with PcapReader(str(self.pcap_path)) as capture:
            capture.LLcls = conf.raw_layer  # scapy keeps computing packet.time; only dissection is skipped
            for raw_packet in capture:
                timestamp = float(raw_packet.time)
                offset = timestamp - sample_started_wall
                if offset < 0:
                    continue
                window_id = int(offset / window_seconds)
                if window_id < 0 or window_id >= window_count:
                    continue
                if window_id < next_window:
                    raise ValueError("PCAP packets cross windows out of timestamp order")
                while next_window < window_id:
                    finish_window(next_window)
                    next_window += 1
                data = bytes(raw_packet)
                fields = decode_ethernet_fields(data)
                if fields is PCAP_FAST_FALLBACK:
                    self.window_decoder_counts["scapy_fallback"] += 1
                    packet = Ether(data)
                    packet.time = raw_packet.time
                    packet_counts[window_id] += 1
                    byte_counts[window_id] += len(packet)
                    if packet.haslayer(IP):
                        ip_layer = packet.getlayer(IP)
                        protocol = str(ip_layer.proto)
                    elif packet.haslayer(IPv6):
                        ip_layer = packet.getlayer(IPv6)
                        protocol = str(ip_layer.nh)
                    else:
                        continue
                    network_extra.record_packet(window_id, packet)
                    transport = packet.getlayer("TCP") or packet.getlayer("UDP")
                    flow = (ip_layer.src, ip_layer.dst, protocol)
                    if transport is not None:
                        flow += (transport.sport, transport.dport)
                    flows_by_window[window_id].add(flow)
                    self._record_p4_packet(packet, window_id, timestamp, accumulator=p4_network)
                    continue
                self.window_decoder_counts["fast"] += 1
                packet_counts[window_id] += 1
                byte_counts[window_id] += len(data)
                if fields is None:
                    continue
                version, source, destination, protocol, ports, flags = fields
                network_extra.record_fields(window_id, timestamp, len(data), version == 6, protocol,
                                            source, destination, ports, flags)
                flow = (source, destination, str(protocol))
                if ports is not None:
                    flow += ports
                flows_by_window[window_id].add(flow)
                if version == 4 and ports is not None:
                    p4_network.record_packet(window_id, timestamp, source, ports[0], destination, ports[1],
                                             protocol, len(data), flags or 0)

        while next_window < window_count:
            finish_window(next_window)
            next_window += 1
        return results

    def collect_by_window_scapy(self, sample_started_wall, window_seconds, window_count):
        from scapy.layers.inet import IP
'''

BUILD_ROW_OLD = '''    file_events,
    packet_features,
):
    duration = max(end_ts - start_ts, 0.0)
    rate_duration = max(duration, 0.001)
    row = {
        "run_id": run_id,
        "label": label,
        "window_id": window_id,
        "window_start_utc": datetime.fromtimestamp(
            start_ts, timezone.utc
        ).isoformat(),
        "window_end_utc": datetime.fromtimestamp(end_ts, timezone.utc).isoformat(),
'''
BUILD_ROW_NEW = '''    file_events,
    packet_features,
    bin_start_ts=None,
    bin_end_ts=None,
):
    duration = max(end_ts - start_ts, 0.0)
    rate_duration = max(duration, 0.001)
    bin_start_ts = start_ts if bin_start_ts is None else bin_start_ts
    bin_end_ts = end_ts if bin_end_ts is None else bin_end_ts
    row = {
        "run_id": run_id,
        "label": label,
        "window_id": window_id,
        # .20: the grid the packet and eBPF bins use; window_seconds keeps the observed loop duration.
        "window_start_utc": datetime.fromtimestamp(
            bin_start_ts, timezone.utc
        ).isoformat(),
        "window_end_utc": datetime.fromtimestamp(bin_end_ts, timezone.utc).isoformat(),
'''
LOOP_OLD = '''                        previous_wall,
                        ended_wall,
                        current,
                        previous,
                        file_features,
                        packet_features,
                    )
'''
LOOP_NEW = '''                        previous_wall,
                        ended_wall,
                        current,
                        previous,
                        file_features,
                        packet_features,
                        bin_start_ts=sample_started_wall + window_id * args.window_sec,
                        bin_end_ts=sample_started_wall + (window_id + 1) * args.window_sec,
                    )
'''
PUBLISH_OLD = '''            packet_counts = packet_collector.collect_by_window(
                sample_started_wall, args.window_sec, len(rows)
            )
'''
PUBLISH_NEW = '''            # .20: an unpublished PCAP is the protected staging file; never read it (used to raise PermissionError).
            packet_counts = {} if metadata.get("packet_capture_publish_error") else packet_collector.collect_by_window(
                sample_started_wall, args.window_sec, len(rows)
            )
            metadata["packet_window_decoder"] = dict(getattr(packet_collector, "window_decoder_counts", {}))
'''
QUALITY_OLD = '''    metadata["collection_quality_status"] = quality_status
    metadata["collection_quality_reasons"] = quality_reasons
'''
QUALITY_NEW = '''    if metadata.get("packet_capture_publish_error"):
        quality_status = "rejected"
        quality_reasons = [*quality_reasons, "packet_capture_publish_failed"]
    if args.iface is not None and not (metadata.get("packet_capture_interface_ipv4_ready") or {}).get("ready"):
        quality_status = "rejected"
        quality_reasons = [*quality_reasons, "packet_capture_interface_ipv4_not_ready"]
    metadata["collection_quality_status"] = quality_status
    metadata["collection_quality_reasons"] = quality_reasons
'''
IPV4_WAIT_OLD = '''            if packet_collector is not None:
                packet_collector.start()
'''
IPV4_WAIT_NEW = '''            if packet_collector is not None:
                metadata["packet_capture_interface_ipv4_ready"] = wait_for_interface_ipv4(args.iface)
                packet_collector.start()
'''
WATCHDOG_ANCHOR = '''    rows = []
    timed_out = False
'''
WATCHDOG_INSTALL = '''    rows = []
    timed_out = False
    start_postprocess_watchdog(metadata, metadata_path, args.timeout)
'''
FINAL_WRITE_OLD = '''    metadata["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\\n", encoding="utf-8")
'''
FINAL_WRITE_NEW = '''    metadata["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    with FINALIZE_LOCK:
        if FINALIZED["written"]:
            return
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\\n", encoding="utf-8")
        FINALIZED["written"] = True
'''
POSTPROCESS_START = '''    if ebpf_collector is not None:
        ebpf_collector.write_log(ebpf_log_path)
'''
POSTPROCESS_END = FINAL_WRITE_NEW
POSTPROCESS_EXCEPT = '''    except Exception as error:
        write_rejected_metadata(metadata, metadata_path, "postprocessing_failed:" + type(error).__name__,
                                f"{type(error).__name__}: {error}")
        raise
'''
HELPERS = '''

_REAL_MONOTONIC = time.monotonic  # captured at import, so a patched time.monotonic cannot move the deadline
RUNNER_STARTED_MONOTONIC = _REAL_MONOTONIC()
POSTPROCESS_GUARD_SECONDS = 56  # the batch's Guest Control envelope is timeout + 60 s from process start
FINALIZE_LOCK = threading.Lock()
FINALIZED = {"written": False}


def write_rejected_metadata(metadata, metadata_path, reason, detail):
    """Write run.json once with collection_quality_status=rejected; returns False if run.json was already written."""
    with FINALIZE_LOCK:
        if FINALIZED["written"]:
            return False
        try:
            record = json.loads(json.dumps(metadata, default=str))
        except (RuntimeError, ValueError, TypeError):
            record = {key: metadata.get(key) for key in ("run_id", "sample", "sample_name", "sample_root_pid")}
        record.update({
            "collection_quality_status": "rejected",
            "collection_quality_reasons": [*(record.get("collection_quality_reasons") or []), reason],
            "postprocessing_error": str(detail)[:4000],
            "telemetry_schema_version": TELEMETRY_SCHEMA_VERSION,
            "malware_runner_sha256": malware_runner_sha256(),
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        })
        Path(metadata_path).write_text(json.dumps(record, indent=2, default=str) + "\\n", encoding="utf-8")
        FINALIZED["written"] = True
        return True


def start_postprocess_watchdog(metadata, metadata_path, timeout_seconds):
    """Arm a kernel interval timer that leaves a rejected run.json before the batch's envelope ends."""
    FINALIZED["written"] = False  # one run per process in production; reset so repeated main() calls stay correct
    remaining = float(timeout_seconds) + POSTPROCESS_GUARD_SECONDS - (_REAL_MONOTONIC() - RUNNER_STARTED_MONOTONIC)

    def fire(_signum, _frame):
        if not FINALIZE_LOCK.acquire(blocking=False):
            return  # the final run.json is being written right now; let it finish
        FINALIZE_LOCK.release()
        if write_rejected_metadata(metadata, metadata_path, "postprocessing_deadline_exceeded",
                                   "runner exceeded timeout + %d s" % POSTPROCESS_GUARD_SECONDS):
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(3)

    try:
        signal.signal(signal.SIGALRM, fire)
        signal.setitimer(signal.ITIMER_REAL, max(0.001, remaining))
        return True
    except ValueError:  # not running in the main thread
        return False


def wait_for_interface_ipv4(interface, timeout_seconds=15, settle_seconds=4):
    """Wait until the capture interface has a configured, non-tentative IPv4 address (netlink only, sends nothing).

    Guest Control can answer while NetworkManager is still probing its address (RFC 5227); a run started then sends
    its first packets from 0.0.0.0. If the wait was needed, pause settle_seconds so the announcements finish first.
    """
    tool = "/usr/sbin/ip" if Path("/usr/sbin/ip").exists() else "ip"
    started = _REAL_MONOTONIC()
    waited = False
    while True:
        try:
            shown = json.loads(subprocess.run([tool, "-4", "-j", "addr", "show", "dev", interface], capture_output=True,
                                              text=True, timeout=5, check=False).stdout or "[]")
        except (OSError, ValueError, subprocess.SubprocessError):
            shown = []
        addresses = [entry.get("local") for link in shown for entry in link.get("addr_info", [])
                     if entry.get("local") and not entry.get("tentative") and not entry.get("dadfailed")]
        elapsed = _REAL_MONOTONIC() - started
        if addresses:
            if waited:
                time.sleep(settle_seconds)
            return {"ready": True, "addresses": addresses, "waited_seconds": round(elapsed, 3),
                    "settle_seconds": settle_seconds if waited else 0}
        if elapsed >= timeout_seconds:
            return {"ready": False, "addresses": [], "waited_seconds": round(elapsed, 3), "settle_seconds": 0}
        waited = True
        time.sleep(0.2)


def stop_postprocess_watchdog():
    try:
        signal.setitimer(signal.ITIMER_REAL, 0)
    except ValueError:
        pass


def main():'''
MAIN_GUARD_OLD = '''if __name__ == "__main__":
    main()
'''
MAIN_GUARD_NEW = '''if __name__ == "__main__":
    main()
    # .20: outputs are written and closed; skip interpreter teardown of millions of event objects.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)
'''


def build():
    source = SOURCE.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise SystemExit("Installed runner is not the expected .19 source")
    text = source.decode()
    text = replace_once(text, "TELEMETRY_SCHEMA_VERSION = " + SCHEMA_OLD, "TELEMETRY_SCHEMA_VERSION = " + SCHEMA_NEW, "schema")
    text = replace_once(text, NETWORK_EXTRA_OLD, NETWORK_EXTRA_NEW, "network extra head")
    text = replace_once(text, NETWORK_EXTRA_FLAGS_OLD, NETWORK_EXTRA_FLAGS_NEW, "network extra flags")
    text = replace_once(text, NETWORK_EXTRA_PORTS_OLD, NETWORK_EXTRA_PORTS_NEW, "network extra ports")
    text = replace_once(text, "\n\nclass P4NetworkAccumulator:", "\n" + DECODER, "decoder")
    text = replace_once(text, COLLECT_OLD_HEAD, COLLECT_NEW, "collect_by_window")
    text = replace_once(text, BUILD_ROW_OLD, BUILD_ROW_NEW, "build_row")
    text = replace_once(text, LOOP_OLD, LOOP_NEW, "observation loop")
    text = replace_once(text, PUBLISH_OLD, PUBLISH_NEW, "publish")
    text = replace_once(text, IPV4_WAIT_OLD, IPV4_WAIT_NEW, "ipv4 wait")
    text = replace_once(text, QUALITY_OLD, QUALITY_NEW, "quality")
    text = replace_once(text, FINAL_WRITE_OLD, FINAL_WRITE_NEW, "final write")
    text = replace_once(text, "\n\ndef main():", HELPERS, "helpers")
    text = replace_once(text, MAIN_GUARD_OLD, MAIN_GUARD_NEW, "main guard")
    start, end = text.index(POSTPROCESS_START), text.index(POSTPROCESS_END) + len(POSTPROCESS_END)
    block = text[start:end]
    if text.count(POSTPROCESS_START) != 1 or "\n    def " in block:
        raise SystemExit("Post-processing block is ambiguous")
    indented = "".join(("    " + line if line.strip() else line) for line in block.splitlines(True))
    text = (text[:start] + "    start_postprocess_watchdog(metadata, metadata_path, args.timeout)\n    try:\n"
            + indented + POSTPROCESS_EXCEPT + "    finally:\n        stop_postprocess_watchdog()\n" + text[end:])
    tree = ast.parse(text)
    names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    for required in ("decode_ethernet_fields", "collect_by_window_scapy", "record_fields", "write_rejected_metadata",
                     "start_postprocess_watchdog"):
        if required not in names:
            raise SystemExit("Missing " + required)
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(text)
    report = {"built_utc": datetime.now(timezone.utc).isoformat(), "source": str(SOURCE), "source_sha256": SOURCE_SHA256,
              "output": str(OUTPUT), "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
              "schema": SCHEMA_NEW.strip('"'), "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "installed": False, "changes": __doc__.split("Changes", 1)[1].strip()}
    (OUTPUT.parent / "build.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("output", "output_sha256", "schema", "installed")}, indent=2))


if __name__ == "__main__":
    build()
