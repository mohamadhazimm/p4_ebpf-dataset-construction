#!/usr/bin/env python3
"""Download selected IoT-23 files with parallel HTTP range requests.

Only packet captures, labeled Zeek connection logs and READMEs are requested; the malware binaries
are never fetched. Each file is stored under DEST/<scenario>/<path> and counts as complete only when
its size equals the server's Content-Length. Completed files are skipped on a rerun, and interrupted
segments resume where they stopped.

    python3 -I fetch_iot23.py DEST [--workers 8] [--only SCENARIO ...] [--include-large]
"""

import argparse
import os
import queue
import sys
import threading
import time
import urllib.request

BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
SEGMENT = 128 * 1024 * 1024
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) research-download"

# (scenario, path) pairs. Main captures only: the derived subsets the authors also publish
# (port-filtered extracts, "only15000000", test.pcap) are not needed.
FILES = [
    ("CTU-Honeypot-Capture-4-1", "README.md"),
    ("CTU-Honeypot-Capture-4-1", "2018-10-25-14-06-32-192.168.1.132.pcap.xz"),
    ("CTU-Honeypot-Capture-4-1", "2018-10-25-14-06-32-192.168.1.132.capinfos"),
    ("CTU-Honeypot-Capture-4-1", "bro/conn.log.labeled"),
    ("CTU-Honeypot-Capture-5-1", "README.md"),
    ("CTU-Honeypot-Capture-5-1", "2018-09-21-capture.pcap"),
    ("CTU-Honeypot-Capture-5-1", "bro/conn.log.labeled"),
    ("CTU-Honeypot-Capture-7-1", "Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap"),
    ("CTU-Honeypot-Capture-7-1", "Somfy-01/bro/conn.log.labeled"),
    ("CTU-Honeypot-Capture-7-1", "Somfy-02/2019-07-03-16-41-09-192.168.1.158.pcap"),
    ("CTU-Honeypot-Capture-7-1", "Somfy-03/2019-07-04-16-41-10-192.168.1.158.pcap"),
    ("CTU-Honeypot-Capture-7-1", "Somfy-04/2019-07-05-16-41-14-192.168.1.158.pcap"),
    ("CTU-Honeypot-Capture-7-1", "Somfy-05/2019-07-06-16-41-17-192.168.1.158.pcap"),
    ("CTU-Honeypot-Capture-7-1", "Somfy-06/2019-07-07-16-41-19-192.168.1.158.pcap"),
    ("CTU-IoT-Malware-Capture-34-1", "README.md"),
    ("CTU-IoT-Malware-Capture-34-1", "2018-12-21-15-50-14-192.168.1.195.pcap"),
    ("CTU-IoT-Malware-Capture-34-1", "2018-12-21-15-50-14-192.168.1.195.capinfos"),
    ("CTU-IoT-Malware-Capture-34-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-8-1", "README.md"),
    ("CTU-IoT-Malware-Capture-8-1", "2018-07-31-15-15-09-192.168.100.113.pcap"),
    ("CTU-IoT-Malware-Capture-8-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-20-1", "README.md"),
    ("CTU-IoT-Malware-Capture-20-1", "2018-10-02-13-12-30-192.168.100.103.pcap"),
    ("CTU-IoT-Malware-Capture-20-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-21-1", "README.md"),
    ("CTU-IoT-Malware-Capture-21-1", "2018-10-03-15-22-32-192.168.100.113.pcap"),
    ("CTU-IoT-Malware-Capture-21-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-42-1", "README.md"),
    ("CTU-IoT-Malware-Capture-42-1", "2019-01-10-14-34-38-192.168.1.197.pcap"),
    ("CTU-IoT-Malware-Capture-42-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-3-1", "README.md"),
    ("CTU-IoT-Malware-Capture-3-1", "2018-05-21_capture.pcap"),
    ("CTU-IoT-Malware-Capture-3-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-1-1", "README.md"),
    ("CTU-IoT-Malware-Capture-1-1", "2018-05-09-192.168.100.103.pcap"),
    ("CTU-IoT-Malware-Capture-1-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-44-1", "README.md"),
    ("CTU-IoT-Malware-Capture-44-1", "2019-01-10-21-06-26-192.168.1.199.pcap"),
    ("CTU-IoT-Malware-Capture-44-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-7-1", "README.md"),
    ("CTU-IoT-Malware-Capture-7-1", "2018-07-20-17-31-20-192.168.100.108.pcap"),
    ("CTU-IoT-Malware-Capture-7-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-9-1", "README.md"),
    ("CTU-IoT-Malware-Capture-9-1", "2018-07-25-10-53-16-192.168.100.111.pcap"),
    ("CTU-IoT-Malware-Capture-9-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-48-1", "README.md"),
    ("CTU-IoT-Malware-Capture-48-1", "2019-02-28-19-15-13-192.168.1.200.pcap"),
    ("CTU-IoT-Malware-Capture-48-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-49-1", "README.md"),
    ("CTU-IoT-Malware-Capture-49-1", "2019-02-28-20-50-15-192.168.1.193.pcap"),
    ("CTU-IoT-Malware-Capture-49-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-35-1", "README.md"),
    ("CTU-IoT-Malware-Capture-35-1", "2018-12-21-15-33-59-192.168.1.196.pcap"),
    ("CTU-IoT-Malware-Capture-35-1", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-60-1", "README.md"),
    ("CTU-IoT-Malware-Capture-60-1", "bro/conn.log.labeled"),
]
# Fetched only with --include-large (21 GB; may instead be fetched by time range).
LARGE = [("CTU-IoT-Malware-Capture-60-1", "2019-09-20-02-40-32-192.168.1.195.pcap")]

log_lock = threading.Lock()


def log(message, logfile):
    line = "%s %s" % (time.strftime("%Y-%m-%dT%H:%M:%S"), message)
    with log_lock:
        print(line, flush=True)
        with open(logfile, "a") as f:
            f.write(line + "\n")


def request(url, start=None, end=None, method="GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
    if start is not None:
        req.add_header("Range", "bytes=%d-%d" % (start, end))
    return urllib.request.urlopen(req, timeout=60)


def size_or_zero(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def content_length(url):
    with request(url, method="HEAD") as r:
        return int(r.headers["Content-Length"])


class File:
    def __init__(self, scenario, path, dest):
        self.url = BASE + scenario + "/" + path
        self.final = os.path.join(dest, scenario, path)
        self.size = None
        self.parts = []
        self.remaining = 0
        self.lock = threading.Lock()


def download_segment(f, index, start, end, logfile):
    part = "%s.part%04d" % (f.final, index)
    want = end - start + 1
    for attempt in range(1, 31):
        have = os.path.getsize(part) if os.path.exists(part) else 0
        if have == want:
            return part
        if have > want:
            os.remove(part)
            continue
        try:
            with request(f.url, start + have, end) as r, open(part, "ab") as out:
                if r.status != 206:
                    raise IOError("unexpected HTTP status %d" % r.status)
                while True:
                    block = r.read(1 << 20)
                    if not block:
                        break
                    out.write(block)
        except Exception as error:  # network errors: retry with backoff
            log("retry %d %s part %d: %s" % (attempt, os.path.basename(f.final), index, error), logfile)
            time.sleep(min(60, 2 * attempt))
    raise IOError("segment %d of %s did not complete" % (index, f.final))


def assemble(f, logfile):
    tmp = f.final + ".tmp"
    with open(tmp, "wb") as out:
        for part in f.parts:
            with open(part, "rb") as src:
                while True:
                    block = src.read(1 << 24)
                    if not block:
                        break
                    out.write(block)
    if os.path.getsize(tmp) != f.size:
        raise IOError("%s: assembled %d bytes, expected %d" % (f.final, os.path.getsize(tmp), f.size))
    os.replace(tmp, f.final)
    for part in f.parts:
        os.remove(part)
    log("done %s %d bytes" % (f.final, f.size), logfile)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dest")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--only", nargs="*", help="restrict to these scenarios")
    parser.add_argument("--include-large", action="store_true")
    args = parser.parse_args()
    logfile = os.path.join(args.dest, "fetch.log")

    entries = FILES + (LARGE if args.include_large else [])
    if args.only:
        entries = [e for e in entries if e[0] in args.only]
    files = []
    for scenario, path in entries:
        f = File(scenario, path, args.dest)
        f.size = content_length(f.url)
        if os.path.exists(f.final) and os.path.getsize(f.final) == f.size:
            continue
        os.makedirs(os.path.dirname(f.final), exist_ok=True)
        files.append(f)
    files.sort(key=lambda f: f.size)
    total = sum(f.size for f in files)
    log("start: %d files, %.2f GB to fetch" % (len(files), total / 1e9), logfile)

    tasks = queue.Queue()
    for f in files:
        starts = list(range(0, f.size, SEGMENT)) or [0]
        f.remaining = len(starts)
        for index, start in enumerate(starts):
            end = min(start + SEGMENT, f.size) - 1
            f.parts.append("%s.part%04d" % (f.final, index))
            tasks.put((f, index, start, end))

    errors = []

    def worker():
        while True:
            try:
                f, index, start, end = tasks.get_nowait()
            except queue.Empty:
                return
            try:
                if f.size == 0:
                    open(f.parts[index], "wb").close()
                else:
                    download_segment(f, index, start, end, logfile)
                with f.lock:
                    f.remaining -= 1
                    last = f.remaining == 0
                if last:
                    assemble(f, logfile)
            except Exception as error:
                errors.append((f.final, str(error)))
                log("FAILED %s: %s" % (f.final, error), logfile)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.workers)]
    for t in threads:
        t.start()
    started = time.time()
    while any(t.is_alive() for t in threads):
        time.sleep(30)
        done = 0
        for f in files:
            if size_or_zero(f.final) == f.size:
                done += f.size
            else:
                done += sum(size_or_zero(p) for p in f.parts)
        rate = done / max(time.time() - started, 1)
        log("progress %.2f/%.2f GB, %.1f MB/s" % (done / 1e9, total / 1e9, rate / 1e6), logfile)
    if errors:
        log("finished with %d failed files" % len(errors), logfile)
        sys.exit(1)
    log("finished, all files complete", logfile)


if __name__ == "__main__":
    main()
