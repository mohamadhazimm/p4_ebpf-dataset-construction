#!/usr/bin/env python3
"""Benign check of the Sink's passive sinkhole; run inside the guest as the normal user.

It only contacts documentation addresses (RFC 5737: 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and the Sink itself, so no check can name a real host. It prints one JSON line
and exits 0 when every required check passed.

What "passed" means:
  - connections and DNS queries to addresses other than the Sink are answered (DNS, HTTP, HTTPS
    by INetSim; every other port by the silent catch-all, which accepts and never sends data);
  - traffic to the Sink's own address behaves as before (INetSim HTTP answers; closed TCP and
    UDP ports are refused).
A UDP datagram to the catch-all gets no answer either way, so its arrival can only be confirmed
in the Sink's log: run "hazim-sinkhole status --find MARKER" on the Sink afterwards.
"""

import argparse
import json
import random
import secrets
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone

DNS_REDIRECTED = "192.0.2.53"      # a resolver address that is not the Sink
HTTP_REDIRECTED = "198.51.100.7"
HTTPS_REDIRECTED = "203.0.113.9"
TCP_CATCHALL = ("192.0.2.44", 4444)
TCP_CATCHALL_IRC = ("192.0.2.45", 6667)
UDP_CATCHALL = ("192.0.2.46", 40000)
SINK_CLOSED_TCP = 47011
SINK_CLOSED_UDP = 65003


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def default_gateway():
    with open("/proc/net/route") as stream:
        next(stream)
        for line in stream:
            fields = line.split()
            if fields[1] == "00000000" and int(fields[3], 16) & 2:
                return socket.inet_ntoa(struct.pack("<I", int(fields[2], 16))), fields[0]
    return None, None


def dns_name(label, marker):
    return "%s-%s.example.com" % (label, marker)


def dns_query(server, name, timeout=3.0):
    """One A query over UDP from a socket connected to server:53; returns (rcode, [addresses])."""
    qid = random.getrandbits(16)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    message = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question + b"\x00" + struct.pack(">HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, 53))  # a connected socket only accepts replies from server:53
        sock.send(message)
        data = sock.recv(4096)
    return parse_answer(data, qid)


def skip_name(data, offset):
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def parse_answer(data, qid):
    if len(data) < 12:
        raise ValueError("short DNS reply")
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != qid or not flags & 0x8000:
        raise ValueError("not a reply to this query")
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(data, offset) + 4
    addresses = []
    for _ in range(ancount):
        offset = skip_name(data, offset)
        rtype, rclass, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == 1 and rclass == 1 and rdlength == 4:
            addresses.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += rdlength
    return flags & 0xF, addresses


def http_get(address, port, host, path, tls=False, timeout=5.0):
    """Returns (status line, response bytes, tls note)."""
    note = None
    raw = socket.create_connection((address, port), timeout=timeout)
    stream = raw
    try:
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                stream = context.wrap_socket(raw, server_hostname=host)
            except ssl.SSLError as error:  # an old self-signed test certificate: retry at level 0
                raw.close()
                note = "default TLS settings refused (%s); retried with SECLEVEL=0" % error.reason
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
                raw = socket.create_connection((address, port), timeout=timeout)
                stream = context.wrap_socket(raw, server_hostname=host)
            note = (note + "; " if note else "") + stream.version()
        request = ("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: hazim-sinkhole-check\r\n"
                   "Connection: close\r\n\r\n" % (path, host))
        stream.sendall(request.encode())
        data = b""
        while len(data) < 1 << 20:
            chunk = stream.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        stream.close()
    return data.split(b"\r\n", 1)[0].decode("latin-1"), len(data), note


def tcp_silent(address, port, marker, wait=3.0):
    """Connect, send one marked line, and wait for any data. Returns (connect seconds, outcome)."""
    start = time.monotonic()
    sock = socket.create_connection((address, port), timeout=5.0)
    connected = round(time.monotonic() - start, 4)
    try:
        sock.sendall(("HAZIM-SINKHOLE-CHECK %s tcp %s:%d\n" % (marker, address, port)).encode())
        sock.settimeout(wait)
        try:
            data = sock.recv(1024)
            outcome = "closed_by_server" if not data else "server_sent_%d_bytes" % len(data)
        except socket.timeout:
            outcome = "silent"
    finally:
        sock.close()
    return connected, outcome


def udp_probe(address, port, marker, wait=2.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(wait)
        sock.connect((address, port))
        sock.send(("HAZIM-SINKHOLE-CHECK %s udp %s:%d\n" % (marker, address, port)).encode())
        try:
            data = sock.recv(2048)
            return "server_sent_%d_bytes" % len(data)
        except socket.timeout:
            return "silent"
        except ConnectionRefusedError:
            return "refused"


def tcp_refused(address, port):
    try:
        sock = socket.create_connection((address, port), timeout=3.0)
    except ConnectionRefusedError:
        return "refused"
    except socket.timeout:
        return "timeout"
    sock.close()
    return "connected"


def run_checks(sink, marker, skip_system_dns):
    checks = []

    def check(name, required, func):
        start = time.monotonic()
        try:
            ok, detail = func()
        except Exception as error:  # every failure is reported, none aborts the run
            ok, detail = False, "%s: %s" % (type(error).__name__, error)
        checks.append({"name": name, "required": required, "ok": bool(ok), "detail": detail,
                       "seconds": round(time.monotonic() - start, 3)})

    def gateway():
        address, iface = default_gateway()
        return address == sink, "default via %s dev %s" % (address, iface)

    def dns(server, label):
        def run():
            rcode, addresses = dns_query(server, dns_name(label, marker))
            return rcode == 0 and sink in addresses, "rcode %d, A %s" % (rcode, addresses)
        return run

    def system_dns():
        name = dns_name("sys", marker)
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(name, 80, socket.AF_INET)})
        return sink in addresses, "getaddrinfo %s" % addresses

    def http(address, port, tls):
        def run():
            status, size, note = http_get(address, port, "hz-check.example", "/hz-" + marker, tls)
            parts = status.split()
            ok = len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1] == "200"
            return ok, "%r, %d bytes%s" % (status, size, ", " + note if note else "")
        return run

    def silent(target):
        def run():
            connected, outcome = tcp_silent(target[0], target[1], marker)
            return outcome == "silent", "connected in %ss, then %s" % (connected, outcome)
        return run

    def refused(port, udp):
        def run():
            outcome = udp_probe(sink, port, marker) if udp else tcp_refused(sink, port)
            return outcome == "refused", outcome
        return run

    def udp_catchall():
        outcome = udp_probe(UDP_CATCHALL[0], UDP_CATCHALL[1], marker)
        return outcome == "silent", outcome + " (arrival is confirmed in the Sink log)"

    check("default_route_via_sink", True, gateway)
    check("dns_to_sink_unchanged", True, dns(sink, "direct"))
    check("dns_to_other_resolver_redirected", True, dns(DNS_REDIRECTED, "redir"))
    if not skip_system_dns:
        check("dns_system_resolver", False, system_dns)
    check("http_to_other_address_redirected", True, http(HTTP_REDIRECTED, 80, False))
    check("https_to_other_address_redirected", True, http(HTTPS_REDIRECTED, 443, True))
    check("tcp_other_port_silent_catchall", True, silent(TCP_CATCHALL))
    check("tcp_irc_port_silent_catchall", True, silent(TCP_CATCHALL_IRC))
    check("udp_other_port_no_answer", False, udp_catchall)
    check("http_to_sink_unchanged", True, http(sink, 80, False))
    check("tcp_closed_port_on_sink_refused", True, refused(SINK_CLOSED_TCP, False))
    check("udp_closed_port_on_sink_refused", True, refused(SINK_CLOSED_UDP, True))
    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--sink", default="10.0.0.1")
    parser.add_argument("--marker", default="hz" + secrets.token_hex(6))
    parser.add_argument("--skip-system-dns", action="store_true")
    parser.add_argument("--json-out")
    args = parser.parse_args(argv)
    if not args.marker.replace("-", "").isalnum() or len(args.marker) > 40:
        parser.error("marker must be letters, digits and '-' (at most 40)")
    started = utc()
    checks = run_checks(args.sink, args.marker.lower(), args.skip_system_dns)
    result = {"check": "hazim-sinkhole-guest-check", "marker": args.marker.lower(), "sink": args.sink,
              "started_utc": started, "ended_utc": utc(), "host": socket.gethostname(),
              "passed": all(item["ok"] for item in checks if item["required"]),
              "required_failed": [item["name"] for item in checks if item["required"] and not item["ok"]],
              "checks": checks}
    if args.json_out:
        with open(args.json_out, "w") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
