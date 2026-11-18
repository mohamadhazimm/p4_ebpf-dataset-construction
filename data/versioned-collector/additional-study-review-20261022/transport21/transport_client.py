"""Benign Python client of the encrypted-traffic test: the same requests as `labtransport client`
over plain HTTP/1.1 or HTTP/1.1 over TLS 1.1, 1.2 or 1.3 (standard library only; no QUIC).

    python3 transport_client.py MODE WORKLOAD SERVER [DURATION_S]
    MODE: http tls11 tls12 tls13; WORKLOAD: poll session bulk (as labtransport)

poll: a new connection every 1 s with one GET of 4 KiB; session: one kept-alive connection, a GET
of 1 KiB every 100 ms; bulk: a new connection per GET of 1 MiB, 0.5 s apart. The lab server's
certificate is self-signed, so it is not validated. Prints one JSON summary.
"""
import http.client
import json
import ssl
import sys
import time
import warnings

PORTS = {"http": 9080, "tls11": 9441, "tls12": 9442, "tls13": 9443}
WORKLOADS = {"poll": (4096, 1.0, False), "session": (1024, 0.1, True), "bulk": (1 << 20, 0.5, False)}


def context(mode):
    if mode == "http":
        return None
    version = {"tls11": ssl.TLSVersion.TLSv1_1, "tls12": ssl.TLSVersion.TLSv1_2, "tls13": ssl.TLSVersion.TLSv1_3}[mode]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if mode == "tls11":
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")   # TLS 1.1 needs SHA-1 signatures
        ctx.minimum_version = version
        ctx.maximum_version = version
    return ctx


def connect(mode, host, ctx):
    if ctx is None:
        return http.client.HTTPConnection(host, PORTS[mode], timeout=5)
    return http.client.HTTPSConnection(host, PORTS[mode], timeout=5, context=ctx)


def main(argv):
    if len(argv) < 3 or argv[0] not in PORTS or argv[1] not in WORKLOADS:
        print(__doc__, file=sys.stderr)
        return 2
    mode, workload, host = argv[:3]
    duration = float(argv[3]) if len(argv) > 3 else 16.0
    size, gap, keep = WORKLOADS[workload]
    ctx = context(mode)
    res = {"Mode": mode, "Workload": workload, "Server": host, "OK": 0, "Failed": 0, "Connections": 0,
           "Bytes": 0, "Versions": {}, "Errors": {}, "Client": "python " + sys.version.split()[0]}
    start = time.monotonic()
    end = start + duration
    conn = None
    k = 0
    while True:
        due = start + k * gap
        k += 1
        if due >= end:
            break
        if due > time.monotonic():
            time.sleep(due - time.monotonic())
        try:
            if conn is None:
                conn = connect(mode, host, ctx)
                res["Connections"] += 1
            conn.request("GET", "/bytes?n=%d" % size)
            resp = conn.getresponse()
            body = resp.read()
            res["Bytes"] += len(body)
            version = conn.sock.version() if ctx is not None and conn.sock is not None else "plain"
            key = "%s/HTTP/1.1" % (version or "?")
            res["Versions"][key] = res["Versions"].get(key, 0) + 1
            if resp.status == 200 and len(body) == size:
                res["OK"] += 1
            else:
                res["Failed"] += 1
                err = "status %d, %d bytes" % (resp.status, len(body))
                res["Errors"][err] = res["Errors"].get(err, 0) + 1
        except (OSError, http.client.HTTPException) as e:
            res["Failed"] += 1
            res["Errors"][type(e).__name__] = res["Errors"].get(type(e).__name__, 0) + 1
            if conn is not None:
                conn.close()
            conn = None
            continue
        if not keep:
            conn.close()
            conn = None
    if conn is not None:
        conn.close()
    res["DurationS"] = round(time.monotonic() - start, 3)
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
