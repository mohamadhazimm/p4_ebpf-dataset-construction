#!/usr/bin/env python3
"""Test client: open many short TCP connections to documentation addresses (RFC 5737), send one
marked line on each and check that nothing comes back. Used only by netns_test.sh."""

import argparse
import json
import socket
from concurrent.futures import ThreadPoolExecutor


def one(index, marker, wait):
    address, port = "192.0.2.%d" % (100 + index % 50), 20000 + index
    line = "HAZIM-SINKHOLE-CHECK %s burst %d\n" % (marker, index)
    try:
        sock = socket.create_connection((address, port), timeout=5)
    except OSError as error:
        return {"dst": "%s:%d" % (address, port), "outcome": "connect_" + type(error).__name__}
    with sock:
        sock.sendall(line.encode())
        sock.settimeout(wait)
        try:
            data = sock.recv(1024)
            outcome = "closed_by_server" if not data else "server_sent_%d_bytes" % len(data)
        except socket.timeout:
            outcome = "silent"
    return {"dst": "%s:%d" % (address, port), "outcome": outcome, "sent": len(line)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=60)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--wait", type=float, default=0.5)
    args = parser.parse_args()
    with ThreadPoolExecutor(max_workers=args.count) as pool:
        results = list(pool.map(lambda i: one(i, args.marker, args.wait), range(args.count)))
    print(json.dumps({"count": args.count, "silent": sum(r["outcome"] == "silent" for r in results),
                      "results": results}))


if __name__ == "__main__":
    main()
