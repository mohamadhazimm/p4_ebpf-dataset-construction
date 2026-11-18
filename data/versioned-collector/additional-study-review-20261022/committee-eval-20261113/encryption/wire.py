"""Packet-level facts of one run's guest capture (tshark, read-only) and system-call names. Offline.

Shared by dataset_http_https.py and sliver_transports.py. Only frames inside the run's feature windows
[sample start, sample start + k x 0.5 s) are counted, with the runner's own anchor (run.json
sample_started_wall_us) and integer-microsecond binning, so the counts are comparable with the switch features
(which count IPv4 TCP/UDP frames only; ARP and the collector's capture-path probes fall outside).

TLS is recognised from the record layer, not from the port: a TCP segment whose payload starts with a TLS record
header (type 20-23, version byte 0x03) on any port, plus tshark's TLS dissector for the record list
(tls.record.content_type = cleartext records, tls.record.opaque_type = TLS 1.3 encrypted records).
"""
import csv
import re
import subprocess
from collections import Counter
from decimal import Decimal
from pathlib import Path

GUEST = "10.0.0.10"
FIELDS = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto", "tcp.stream", "tcp.srcport",
          "tcp.dstport", "tcp.len", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
          "udp.srcport", "udp.dstport", "tls.record.content_type", "tls.record.opaque_type", "tls.record.length",
          "tls.handshake.type", "tls.handshake.extensions.supported_version", "http.request.method",
          "http.response.code", "tcp.payload"]
TLS_VERSION = {"0x0304": "TLS1.3", "0x0303": "TLS1.2", "0x0302": "TLS1.1", "0x0301": "TLS1.0"}


def _flag(v):
    return v in ("1", "True", "true")


def _ints(v):
    return [int(x) for x in v.split(",") if x != ""] if v else []


def frames(pcap):
    """All frames of a capture as dicts (tshark -T fields, every occurrence of multi-valued fields)."""
    cmd = ["tshark", "-r", str(pcap), "-n", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
           "-E", "aggregator=,"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        v = line.split("\t")
        v += [""] * (len(FIELDS) - len(v))
        d = dict(zip(FIELDS, v))
        d["t_us"] = int(Decimal(d["frame.time_epoch"]).scaleb(6))
        rows.append(d)
    return rows


def summarize(pcap, anchor_us, n_windows, window_us=500_000):
    """Counts over the frames inside the feature windows."""
    lo, hi = anchor_us, anchor_us + n_windows * window_us
    inw = [f for f in frames(pcap) if lo <= f["t_us"] < hi]
    p4 = [f for f in inw if f["ip.proto"] in ("6", "17") and f["ip.src"]]
    out = {"frames_in_window": len(inw), "ipv4_tcp_udp_frames": len(p4),
           "ipv4_tcp_udp_frame_bytes": sum(int(f["frame.len"]) for f in p4),
           "frames_out": sum(1 for f in p4 if f["ip.src"] == GUEST),
           "frames_in": sum(1 for f in p4 if f["ip.dst"] == GUEST),
           "tcp_connections": len({f["tcp.stream"] for f in p4 if f["tcp.stream"]}),
           "server_ports": sorted({int(f["tcp.dstport"]) if f["ip.src"] == GUEST else int(f["tcp.srcport"])
                                   for f in p4 if f["tcp.stream"]}),
           "syn_frames": sum(1 for f in p4 if _flag(f["tcp.flags.syn"])),
           "fin_frames": sum(1 for f in p4 if _flag(f["tcp.flags.fin"])),
           "rst_frames": sum(1 for f in p4 if _flag(f["tcp.flags.reset"])),
           "rst_from_server": sum(1 for f in p4 if _flag(f["tcp.flags.reset"]) and f["ip.dst"] == GUEST),
           "tcp_payload_bytes": sum(int(f["tcp.len"] or 0) for f in p4),
           "tcp_payload_bytes_out": sum(int(f["tcp.len"] or 0) for f in p4 if f["ip.src"] == GUEST),
           "tcp_payload_bytes_in": sum(int(f["tcp.len"] or 0) for f in p4 if f["ip.dst"] == GUEST),
           "udp_frames": sum(1 for f in p4 if f["ip.proto"] == "17"),
           "udp_out_by_dst_port": dict(Counter(f["udp.dstport"] for f in p4
                                               if f["ip.proto"] == "17" and f["ip.src"] == GUEST)),
           "udp_in_by_src_port": dict(Counter(f["udp.srcport"] for f in p4
                                              if f["ip.proto"] == "17" and f["ip.dst"] == GUEST))}
    # TLS record layer. ClientHello/ServerHello are counted from the segment bytes (record type 22, handshake
    # type 1/2), which works on any port; tshark's TLS dissector supplies the record list and the version.
    lengths, plain, opaque, versions = [], Counter(), 0, set()
    start_out = start_in = client_hello = server_hello = 0
    hello_bytes, flight_bytes = [], []  # TCP payload of segments that begin with a ClientHello / ServerHello record
    for f in p4:
        pay = f["tcp.payload"]
        if len(pay) >= 12 and pay[:2] in ("14", "15", "16", "17") and pay[2:4] == "03":
            if f["ip.src"] == GUEST:
                start_out += 1
                if pay[:2] == "16" and pay[10:12] == "01":
                    client_hello += 1
                    hello_bytes.append(int(f["tcp.len"]))
            else:
                start_in += 1
                if pay[:2] == "16" and pay[10:12] == "02":
                    server_hello += 1
                    flight_bytes.append(int(f["tcp.len"]))
        lengths += _ints(f["tls.record.length"])
        for c in _ints(f["tls.record.content_type"]):
            plain[c] += 1
        opaque += len(_ints(f["tls.record.opaque_type"]))
        if 2 in _ints(f["tls.handshake.type"]):  # ServerHello: negotiated version = its supported_versions value
            sv = [x for x in f["tls.handshake.extensions.supported_version"].split(",") if x]
            versions.add(TLS_VERSION.get(sv[-1], sv[-1]) if sv else "TLS<=1.2")
    http_req = Counter(m for f in p4 for m in f["http.request.method"].split(",") if m)
    http_resp = Counter(c for f in p4 for c in f["http.response.code"].split(",") if c)
    out.update({"tls_record_segments_out": start_out, "tls_record_segments_in": start_in,
                "tls_records": len(lengths), "tls_records_cleartext_type": dict(sorted(plain.items())),
                "tls_records_encrypted": opaque, "tls_record_bytes_incl_headers": sum(lengths) + 5 * len(lengths),
                "tls_client_hello": client_hello, "tls_server_hello": server_hello,
                "tls_client_hello_segment_bytes": sorted(set(hello_bytes)),
                "tls_server_hello_segment_bytes": sorted(set(flight_bytes)),
                "tls_versions": sorted(versions), "http_requests_cleartext": dict(http_req),
                "http_responses_cleartext": dict(http_resp)})
    parts = []
    if server_hello:
        parts.append("+".join(sorted(versions)) or "TLS (version not decoded)")
    if http_req:
        parts.append("HTTP cleartext")
    if client_hello > server_hello:
        parts.append("%d TLS ClientHello without ServerHello" % (client_hello - server_hello))
    if not parts:
        if out["tcp_payload_bytes_out"]:
            parts.append("TCP cleartext payload")
        elif out["tcp_connections"]:
            parts.append("TCP connect, no client payload" + (" (server TLS alert)" if start_in else ""))
        elif out["udp_frames"]:
            parts.append("UDP")
        else:
            parts.append("none")
    out["transport_observed"] = "; ".join(parts)
    return out


def _syscall_names(header):
    names = {}
    for line in open(header):
        m = re.match(r"#define __NR_(\w+)\s+(\d+)", line)
        if m:
            names[int(m.group(2))] = m.group(1)
    return names


NAMES_64 = _syscall_names("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")
NAMES_32 = _syscall_names("/usr/include/x86_64-linux-gnu/asm/unistd_32.h")


def target_syscalls(run_out, comm, i386):
    """Raw system calls of the target program (rows of syscall_events.csv whose comm is the program), by name."""
    names = NAMES_32 if i386 else NAMES_64
    c = Counter()
    with open(Path(run_out) / "syscall_events.csv", newline="") as f:
        for r in csv.DictReader(f):
            if r["comm"] == comm and r["event"] == "syscall" and r["detail"].startswith("id="):
                n = int(r["detail"][3:])
                c[names.get(n, "id%d" % n)] += 1
    return c
