"""Benign HTTP/HTTPS client for the encrypted-traffic pairs (E5). One shape per run, over HTTP or HTTPS.

    python3 tls_client.py <http|https> <poll|pool|session|upload|download> <host>

HTTPS uses an unverified context (the Sink serves a self-signed certificate). Everything but the scheme is
identical between the two runs of a pair, so any feature difference is due to TLS, not the workload.
"""
import json
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

scheme, shape, host = sys.argv[1], sys.argv[2], sys.argv[3]
assert scheme in ("http", "https") and host == "10.0.0.1"
base = "%s://%s" % (scheme, host)
ctx = ssl._create_unverified_context() if scheme == "https" else None


def get(path, data=None):
    req = urllib.request.Request(base + path, data=data, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
        return len(r.read())


ok = 0
try:
    if shape == "poll":
        for i in range(60):
            ok += get("/status/%d" % i) >= 0
    elif shape == "pool":
        with ThreadPoolExecutor(10) as pool:
            ok = sum(s >= 0 for s in pool.map(lambda i: get("/page/%d" % i), range(200)))
    elif shape == "session":
        for i in range(120):
            ok += get("/api/item/%d" % i) >= 0
    elif shape == "upload":
        import os
        for i in range(20):
            ok += get("/upload/%d" % i, os.urandom(256 * 1024)) >= 0
    elif shape == "download":
        for i in range(40):
            ok += get("/file/%d.bin" % i) >= 0
    else:
        raise SystemExit("unknown shape " + shape)
except OSError as e:
    print(json.dumps({"scheme": scheme, "shape": shape, "ok": ok, "error": type(e).__name__}))
    raise SystemExit(1)
print(json.dumps({"scheme": scheme, "shape": shape, "ok": ok}))
sys.exit(0 if ok else 1)
