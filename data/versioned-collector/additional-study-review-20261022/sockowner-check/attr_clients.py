"""Benign clients with known flows, for the socket-ownership check (runs in the analysis VM).

Every flow is opened from a local port the client chose, and written to a receipt with the client's
process and thread ids: that is the ground truth the tracer is checked against. Destinations are the
isolated Sink only (INetSim on TCP 80, dnsmasq on UDP 53, closed UDP/TCP ports for the rest).

  python3 -I attr_clients.py --client c1a --mode mixed --ports 31000-31199 --sink 10.0.0.1 \
      --laddr 10.0.0.10 --duration 15 --out receipts-c1a.jsonl

Modes: mixed (HTTP GET, DNS query, UDP datagram every 0.25 s), thread (4 threads of HTTP GETs in one
process), inherit (the parent connects, a forked child sends the request on the inherited socket),
burst (one UDP socket, datagrams to --count destination ports), raw (root: --count TCP SYNs from a raw
socket to a closed port, the shape of a raw-socket flood at a benign rate).
"""
import argparse
import json
import os
import random
import socket
import struct
import threading
import time

lock = threading.Lock()


class Receipts:
    def __init__(self, path, client, mode):
        self.stream = open(path, "a", buffering=1)
        self.client, self.mode = client, mode

    def write(self, proto, local, remote, ok, detail="", owner_pid=None):
        record = {"client": self.client, "mode": self.mode, "pid": os.getpid(), "tid": threading.get_native_id(),
                  "owner_pid": owner_pid if owner_pid is not None else os.getpid(), "proto": proto,
                  "laddr": local[0], "lport": local[1], "raddr": remote[0], "rport": remote[1],
                  "t_wall_ns": time.time_ns(), "ok": bool(ok), "detail": str(detail)[:120]}
        with lock:
            self.stream.write(json.dumps(record, sort_keys=True) + "\n")


class Ports:
    def __init__(self, low, high):
        self.ports, self.i = list(range(low, high + 1)), 0

    def next(self):
        with lock:
            port = self.ports[self.i % len(self.ports)]
            self.i += 1
            return port


def bound(kind, laddr, ports, tries=50):
    for _ in range(tries):
        s = socket.socket(socket.AF_INET, kind)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((laddr, ports.next()))
            return s
        except OSError:
            s.close()
    raise OSError("no free local port in the range")


def http_get(r, args, ports, n):
    s = bound(socket.SOCK_STREAM, args.laddr, ports)
    s.settimeout(2.0)
    local = s.getsockname()
    try:
        s.connect((args.sink, args.http_port))
        s.sendall(("GET /attr/%s/%d HTTP/1.0\r\nHost: %s\r\n\r\n" % (args.client, n, args.sink)).encode())
        got = 0
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            got += len(chunk)
        r.write(6, local, (args.sink, args.http_port), got > 0, "http %d B" % got)
    except OSError as error:
        r.write(6, local, (args.sink, args.http_port), False, error)
    finally:
        s.close()


def dns_query(r, args, ports, n):
    s = bound(socket.SOCK_DGRAM, args.laddr, ports)
    s.settimeout(1.0)
    local = s.getsockname()
    name = b"".join(bytes([len(p)]) + p for p in (("attr-%s-%d" % (args.client, n)).encode(), b"lab")) + b"\0"
    query = struct.pack("!HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    try:
        s.sendto(query, (args.sink, 53))
        answer, _ = s.recvfrom(512)
        r.write(17, local, (args.sink, 53), True, "dns %d B" % len(answer))
    except OSError as error:
        r.write(17, local, (args.sink, 53), False, error)
    finally:
        s.close()


def udp_datagram(r, args, ports, n):
    s = bound(socket.SOCK_DGRAM, args.laddr, ports)
    local = s.getsockname()
    try:
        s.sendto(("attr %s %d" % (args.client, n)).encode(), (args.sink, 65003))
        r.write(17, local, (args.sink, 65003), True, "udp")
    except OSError as error:
        r.write(17, local, (args.sink, 65003), False, error)
    finally:
        s.close()


def mode_mixed(r, args, ports):
    end, n = time.monotonic() + args.duration, 0
    while time.monotonic() < end:
        http_get(r, args, ports, n)
        dns_query(r, args, ports, n)
        udp_datagram(r, args, ports, n)
        n += 1
        time.sleep(0.25)


def mode_thread(r, args, ports):
    def worker(k):
        end, n = time.monotonic() + args.duration, 0
        while time.monotonic() < end:
            http_get(r, args, ports, k * 100000 + n)
            n += 1
            time.sleep(0.3)
    threads = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def mode_inherit(r, args, ports):
    end, n = time.monotonic() + args.duration, 0
    while time.monotonic() < end:
        s = bound(socket.SOCK_STREAM, args.laddr, ports)
        s.settimeout(2.0)
        local = s.getsockname()
        parent = os.getpid()
        try:
            s.connect((args.sink, args.http_port))
        except OSError as error:
            r.write(6, local, (args.sink, args.http_port), False, error)
            s.close()
            time.sleep(0.4)
            continue
        child = os.fork()
        if child == 0:  # the child uses the socket its parent created
            try:
                s.sendall(("GET /attr/%s/inherit/%d HTTP/1.0\r\nHost: %s\r\n\r\n" % (args.client, n, args.sink)).encode())
                got = 0
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    got += len(chunk)
                r.write(6, local, (args.sink, args.http_port), got > 0, "inherited http %d B" % got, owner_pid=parent)
            except OSError as error:
                r.write(6, local, (args.sink, args.http_port), False, error, owner_pid=parent)
            os._exit(0)
        s.close()
        os.waitpid(child, 0)
        n += 1
        time.sleep(0.4)


def mode_burst(r, args, ports):
    s = bound(socket.SOCK_DGRAM, args.laddr, ports)
    local = s.getsockname()
    for i in range(args.count):
        try:
            s.sendto(b"burst", (args.sink, 20000 + i))
            r.write(17, local, (args.sink, 20000 + i), True, "burst")
        except OSError as error:
            r.write(17, local, (args.sink, 20000 + i), False, error)
        time.sleep(0.0005)
    s.close()


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mode_raw(r, args, ports):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    src, dst = socket.inet_aton(args.laddr), socket.inet_aton(args.sink)
    for i in range(args.count):
        sport, seq = ports.next(), random.getrandbits(32)
        header = struct.pack("!HHIIBBHHH", sport, 65004, seq, 0, 5 << 4, 0x02, 1024, 0, 0)
        pseudo = src + dst + struct.pack("!BBH", 0, 6, len(header))
        header = header[:16] + struct.pack("!H", checksum(pseudo + header)) + header[18:]
        try:
            s.sendto(header, (args.sink, 0))
            r.write(6, (args.laddr, sport), (args.sink, 65004), True, "raw syn")
        except OSError as error:
            r.write(6, (args.laddr, sport), (args.sink, 65004), False, error)
        time.sleep(0.1)
    s.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--client", required=True)
    p.add_argument("--mode", choices=["mixed", "thread", "inherit", "burst", "raw"], required=True)
    p.add_argument("--ports", required=True)
    p.add_argument("--sink", default="10.0.0.1")
    p.add_argument("--laddr", default="10.0.0.10")
    p.add_argument("--duration", type=float, default=15.0)
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--http-port", type=int, default=80)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    low, high = (int(x) for x in args.ports.split("-"))
    r = Receipts(args.out, args.client, args.mode)
    {"mixed": mode_mixed, "thread": mode_thread, "inherit": mode_inherit, "burst": mode_burst,
     "raw": mode_raw}[args.mode](r, args, Ports(low, high))


if __name__ == "__main__":
    main()
