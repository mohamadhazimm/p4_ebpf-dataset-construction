#!/usr/bin/env python3
"""Silent catch-all listener for the lab Sink's passive sinkhole.

The sinkhole rules on the Sink (see sinkhole.sh) redirect every TCP connection and UDP datagram
that the guest sends to an address other than the Sink, on a port INetSim does not serve, to this
one listener. For each TCP connection it records the client, the address the client originally
dialed (SO_ORIGINAL_DST), how many bytes arrived, and the first --capture-bytes of them. For each
UDP datagram it records the client, the length and the first bytes. The original destination of a
redirected UDP datagram is not available here; the guest-side packet capture has it.

It never sends data. A TCP connection is held open until the client closes it, it has been idle
for --idle seconds, or --max-hold seconds have passed; then it is closed. At most --max-conns
connections are held at once; further ones wait in the kernel's accept queue. Records beyond
--log-rate per second, or past --max-log-mb, are only counted in the periodic summary records.

Standard library only; meant to run unprivileged (the systemd unit uses DynamicUser).
"""

import argparse
import hashlib
import json
import os
import signal
import socket
import threading
import time
from collections import Counter
from datetime import datetime, timezone

SO_ORIGINAL_DST = 80  # linux/netfilter_ipv4.h


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def preview(data, limit=128):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def original_dst(conn):
    """(ip, port) the client dialed before the redirect, or None if unavailable."""
    try:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    except OSError:
        return None
    return socket.inet_ntoa(raw[4:8]), int.from_bytes(raw[2:4], "big")


class Recorder:
    """JSON-lines log with a per-second record budget and a size cap; counts everything."""

    def __init__(self, path, rate, max_bytes):
        self.lock = threading.Lock()
        self.stream = open(path, "a", buffering=1, encoding="utf-8")
        self.rate = float(rate)
        self.tokens = float(rate)
        self.last = time.monotonic()
        self.max_bytes = max_bytes
        self.counts = Counter()
        self.dst = Counter()

    def _write(self, record):
        self.stream.write(json.dumps(record, sort_keys=True) + "\n")

    def _room(self):
        return os.fstat(self.stream.fileno()).st_size < self.max_bytes

    def event(self, kind, record, dst_key):
        with self.lock:
            self.counts[kind] += 1
            self.dst[dst_key] += 1
            now = time.monotonic()
            self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= 1.0 and self._room():
                self.tokens -= 1.0
                self.counts[kind + "_logged"] += 1
                self._write(record)

    def count(self, key):
        with self.lock:
            self.counts[key] += 1

    def note(self, record):
        with self.lock:
            self._write(record)

    def summary(self, final=False):
        with self.lock:
            if not self.counts and not final:
                return
            self._write({"type": "summary", "t": utc(), "final": final,
                         "counts": dict(self.counts), "top_dst": dict(self.dst.most_common(20))})
            self.counts.clear()
            self.dst.clear()


def head_fields(head):
    return {"head_hex": head.hex(), "head_sha256": hashlib.sha256(head).hexdigest(),
            "preview": preview(head)}


def serve_tcp(conn, peer, args, recorder, slots, active, stop):
    opened, start = utc(), time.monotonic()
    orig = original_dst(conn)
    local = conn.getsockname()
    head, total, first, end = bytearray(), 0, None, "eof"
    try:
        while True:
            left = args.max_hold - (time.monotonic() - start)
            if left <= 0:
                end = "max_hold"
                break
            conn.settimeout(min(args.idle, left))
            try:
                data = conn.recv(65536)
            except socket.timeout:
                end = "idle" if left > args.idle else "max_hold"
                break
            except ConnectionResetError:
                end = "reset"
                break
            except OSError as error:
                end = "error:" + type(error).__name__
                break
            if not data:
                end = "stopped" if stop.is_set() else "eof"
                break
            if first is None:
                first = round(time.monotonic() - start, 6)
            total += len(data)
            if len(head) < args.capture_bytes:
                head += data[: args.capture_bytes - len(head)]
    finally:
        with active["lock"]:
            active["conns"].discard(conn)
        try:
            conn.close()
        except OSError:
            pass
        slots.release()
    record = {"type": "tcp", "t_open": opened, "t_close": utc(),
              "duration_s": round(time.monotonic() - start, 6),
              "src": "%s:%d" % peer, "orig_dst": "%s:%d" % orig if orig else None,
              "redirected": bool(orig) and orig != (local[0], local[1]),
              "bytes_in": total, "first_data_s": first, "end": end}
    record.update(head_fields(bytes(head)))
    recorder.event("tcp", record, "tcp/%d" % orig[1] if orig else "tcp/unknown")


def serve_udp(sock, args, recorder, stop):
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            if stop.is_set():
                break
            time.sleep(0.05)
            continue
        record = {"type": "udp", "t": utc(), "src": "%s:%d" % peer, "orig_dst": None,
                  "bytes_in": len(data)}
        record.update(head_fields(data[: args.capture_bytes]))
        recorder.event("udp", record, "udp")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Silent catch-all listener (never sends data).")
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=64999)
    parser.add_argument("--log", required=True)
    parser.add_argument("--idle", type=float, default=300.0)
    parser.add_argument("--max-hold", type=float, default=900.0)
    parser.add_argument("--capture-bytes", type=int, default=256)
    parser.add_argument("--max-conns", type=int, default=512)
    parser.add_argument("--log-rate", type=float, default=200.0)
    parser.add_argument("--max-log-mb", type=float, default=512.0)
    parser.add_argument("--summary-every", type=float, default=10.0)
    args = parser.parse_args(argv)

    os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
    recorder = Recorder(args.log, args.log_rate, int(args.max_log_mb * 1024 * 1024))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((args.bind, args.port))
    tcp.listen(256)
    tcp.settimeout(1.0)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((args.bind, args.port))

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    slots = threading.BoundedSemaphore(args.max_conns)
    active = {"lock": threading.Lock(), "conns": set()}
    threads = []

    udp_thread = threading.Thread(target=serve_udp, args=(udp, args, recorder, stop), daemon=True)
    udp_thread.start()

    def summarize():
        while not stop.wait(args.summary_every):
            recorder.summary()

    threading.Thread(target=summarize, daemon=True).start()
    settings = {key: getattr(args, key) for key in
                ("idle", "max_hold", "capture_bytes", "max_conns", "log_rate", "max_log_mb")}
    recorder.note({"type": "start", "t": utc(), "pid": os.getpid(), "passive": True,
                   "bind": "%s:%d" % (args.bind, args.port), "settings": settings})
    print("READY %s:%d" % (args.bind, args.port), flush=True)

    while not stop.is_set():
        if not slots.acquire(timeout=1.0):
            continue
        try:
            conn, peer = tcp.accept()
        except (socket.timeout, InterruptedError):
            slots.release()
            continue
        except OSError:
            slots.release()
            if stop.is_set():
                break
            time.sleep(0.05)
            continue
        with active["lock"]:
            active["conns"].add(conn)
        worker = threading.Thread(target=serve_tcp, daemon=True,
                                  args=(conn, peer, args, recorder, slots, active, stop))
        try:
            worker.start()
        except RuntimeError:
            with active["lock"]:
                active["conns"].discard(conn)
            conn.close()
            slots.release()
            recorder.count("tcp_thread_error")
            continue
        threads = [thread for thread in threads if thread.is_alive()]
        threads.append(worker)

    tcp.close()
    with active["lock"]:
        held = list(active["conns"])
    for conn in held:  # wake the readers; SHUT_RD sends nothing to the client
        try:
            conn.shutdown(socket.SHUT_RD)
        except OSError:
            pass
    deadline = time.monotonic() + 3.0
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    udp_thread.join(2.0)
    udp.close()
    recorder.summary(final=True)
    recorder.note({"type": "stop", "t": utc(), "pid": os.getpid()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
