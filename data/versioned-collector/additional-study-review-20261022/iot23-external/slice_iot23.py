#!/usr/bin/env python3
"""Download time slices of a large IoT-23 pcap with HTTP range requests.

For each slice [start, end) the byte offsets of the first records with a timestamp at or after start
and end are found by binary search over range probes: inside a probe, a record boundary is accepted
only where eight consecutive record headers chain consistently (plausible time, captured length within
the snapshot length and not above the original length). The bytes in between are fetched in parallel
segments and written after the original 24-byte pcap header, which gives a valid pcap holding exactly
the records of the slice. Each slice is then read back record by record as a check.

    python3 -I slice_iot23.py URL OUT_DIR START_UTC END_UTC [START_UTC END_UTC ...]
    (times as YYYY-MM-DDTHH:MM:SS)
"""

import calendar
import json
import os
import struct
import sys
import threading
import time
import urllib.request

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) research-download"
PROBE = 1 << 20
SEGMENT = 64 << 20
CHAIN = 8


def fetch(url, start, end):
    for attempt in range(1, 21):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Range": "bytes=%d-%d" % (start, end)})
            with urllib.request.urlopen(req, timeout=60) as r:
                if r.status != 206:
                    raise IOError("HTTP %d" % r.status)
                data = r.read()
            if len(data) != end - start + 1:
                raise IOError("short read %d of %d" % (len(data), end - start + 1))
            return data
        except Exception as error:
            print("retry %d %d-%d: %s" % (attempt, start, end, error), flush=True)
            time.sleep(min(30, 2 * attempt))
    raise IOError("range %d-%d failed" % (start, end))


class Capture:
    def __init__(self, url):
        self.url = url
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as r:
            self.size = int(r.headers["Content-Length"])
        self.header = fetch(url, 0, 23)
        formats = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
                   b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}
        self.order, self.digits = formats[self.header[:4]]
        self.snaplen = struct.unpack(self.order + "I", self.header[16:20])[0]
        self.unpack = struct.Struct(self.order + "IIII").unpack_from
        start = fetch(url, 24, 24 + PROBE - 1)
        seconds, fraction = self.unpack(start, 0)[:2]
        self.first_us = seconds * 1_000_000 + (fraction if self.digits == 6 else fraction // 1000)
        self.tmin, self.tmax = seconds - 1, seconds + 7 * 86400
        assert len(self.records(start, 0, CHAIN)) == CHAIN, "first records do not chain"

    def plausible(self, buf, p):
        if p + 16 > len(buf):
            return None
        seconds, fraction, captured, original = self.unpack(buf, p)
        if not (self.tmin <= seconds <= self.tmax and fraction < 10 ** self.digits
                and 14 <= captured <= self.snaplen and captured <= original <= 262144):
            return None
        return seconds * 1_000_000 + (fraction if self.digits == 6 else fraction // 1000), 16 + captured

    def records(self, buf, p, limit=None):
        """(offset in buf, time us, next offset) of consecutive valid records from p that fit in buf."""
        out = []
        while limit is None or len(out) < limit:
            record = self.plausible(buf, p)
            if record is None or p + record[1] > len(buf):
                break
            out.append((p, record[0], p + record[1]))
            p += record[1]
        return out

    def boundary(self, offset):
        """First record boundary at or after offset, and its time: eight chained headers, or a chain
        that ends exactly at the end of the file."""
        end = min(offset + PROBE, self.size) - 1
        buf = fetch(self.url, offset, end)
        at_eof = end == self.size - 1
        for p in range(len(buf) - 15):
            chain = self.records(buf, p, CHAIN)
            if len(chain) >= CHAIN:
                return offset + p, chain[0][1]
            if at_eof and chain and self.records(buf, p)[-1][2] == len(buf):
                return offset + p, chain[0][1]
        return None, None

    def lower_bound(self, target_us):
        """Offset of the first record with time >= target_us."""
        lo, hi = 24, self.size
        while hi - lo > PROBE:
            mid = (lo + hi) // 2
            offset, t = self.boundary(mid)
            if offset is None or t >= target_us:
                hi = mid
            else:
                lo = offset
        buf = fetch(self.url, lo, min(hi + PROBE, self.size) - 1)
        p = 0
        while True:
            record = self.plausible(buf, p)
            if record is None:
                raise ValueError("lost record alignment near offset %d" % (lo + p))
            if record[0] >= target_us:
                return lo + p
            p += record[1]
            if p + 16 > len(buf):
                if lo + p >= self.size:
                    return self.size
                buf, lo, p = fetch(self.url, lo + p, min(lo + p + PROBE, self.size) - 1), lo + p, 0

    def download(self, start, end, path, workers=8):
        segments = [(s, min(s + SEGMENT, end) - 1) for s in range(start, end, SEGMENT)]
        parts = [None] * len(segments)
        lock = threading.Lock()
        queue = list(enumerate(segments))

        def worker():
            while True:
                with lock:
                    if not queue:
                        return
                    i, (s, e) = queue.pop(0)
                part = "%s.part%04d" % (path, i)
                with open(part, "wb") as f:
                    f.write(fetch(self.url, s, e))
                parts[i] = part

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        with open(path + ".tmp", "wb") as out:
            out.write(self.header)
            for part in parts:
                with open(part, "rb") as f:
                    out.write(f.read())
                os.remove(part)
        os.replace(path + ".tmp", path)


def verify(path, start_us, end_us):
    with open(path, "rb") as f:
        header = f.read(24)
        order = "<" if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = header[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        unpack = struct.Struct(order + "IIII").unpack
        n, first, last, outside = 0, None, None, 0
        while True:
            record = f.read(16)
            if not record:
                break
            if len(record) < 16:
                raise ValueError("truncated record header")
            seconds, fraction, captured, _ = unpack(record)
            if len(f.read(captured)) != captured:
                raise ValueError("truncated record")
            t = seconds * 1_000_000 + (fraction // 1000 if nano else fraction)
            first = t if first is None else first
            last = t
            outside += not (start_us <= t < end_us)
            n += 1
    return {"records": n, "first_us": first, "last_us": last, "records_outside_slice": outside}


def main():
    url, out_dir, times = sys.argv[1], sys.argv[2], sys.argv[3:]
    assert times and len(times) % 2 == 0
    capture = Capture(url)
    os.makedirs(out_dir, exist_ok=True)
    name = url.rsplit("/", 1)[1]
    manifest = {"url": url, "size": capture.size, "first_us": capture.first_us, "slices": []}
    for start_s, end_s in zip(times[::2], times[1::2]):
        start_us = calendar.timegm(time.strptime(start_s, "%Y-%m-%dT%H:%M:%S")) * 1_000_000
        end_us = calendar.timegm(time.strptime(end_s, "%Y-%m-%dT%H:%M:%S")) * 1_000_000
        a, b = capture.lower_bound(start_us), capture.lower_bound(end_us)
        path = os.path.join(out_dir, "%s.slice-%s-%s.pcap" % (name[:-5], start_s.replace(":", ""), end_s.replace(":", "")))
        print("slice %s..%s: bytes %d-%d (%.2f GB)" % (start_s, end_s, a, b, (b - a) / 1e9), flush=True)
        if not (os.path.exists(path) and os.path.getsize(path) == b - a + 24):
            capture.download(a, b, path)
        check = verify(path, start_us, end_us)
        print("  ", check, flush=True)
        if check["records_outside_slice"]:
            print("  note: %d records outside the slice (capture not in strict time order)" % check["records_outside_slice"])
        manifest["slices"].append({"start_utc": start_s, "end_utc": end_s, "start_us": start_us, "end_us": end_us,
                                   "byte_start": a, "byte_end": b, "file": os.path.basename(path), **check})
    with open(os.path.join(out_dir, name[:-5] + ".slices.json"), "w") as f:
        json.dump(manifest, f, indent=1)


if __name__ == "__main__":
    main()
