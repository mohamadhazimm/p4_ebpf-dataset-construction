#!/usr/bin/env python3
"""Test stand-in for the Sink's INetSim: DNS (udp+tcp 53) answers every A query with one address,
HTTP (80) and HTTPS (443) answer every request with 200. Used only by netns_test.sh."""

import argparse
import socket
import ssl
import struct
import threading

BODY = b"<html><body>fake inetsim</body></html>\n"


def dns_reply(query, answer):
    if len(query) < 12:
        return None
    qid, _, qdcount = struct.unpack(">HHH", query[:6])
    offset = 12
    while offset < len(query) and query[offset] != 0:
        offset += 1 + query[offset]
    offset += 5
    question = query[12:offset]
    qtype = struct.unpack(">H", question[-4:-2])[0] if len(question) >= 4 else 0
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1 if qtype == 1 else 0, 0, 0)
    record = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(answer) if qtype == 1 else b""
    return header + question + record


def serve_dns_udp(bind, answer):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, 53))
    while True:
        data, peer = sock.recvfrom(4096)
        reply = dns_reply(data, answer)
        if reply:
            sock.sendto(reply, peer)


def serve_dns_tcp(bind, answer):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, 53))
    sock.listen(16)
    while True:
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(3)
            try:
                length = struct.unpack(">H", conn.recv(2))[0]
                reply = dns_reply(conn.recv(length), answer)
                if reply:
                    conn.sendall(struct.pack(">H", len(reply)) + reply)
            except (OSError, struct.error):
                pass


def handle_http(conn):
    with conn:
        conn.settimeout(5)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n"
                         b"Connection: close\r\n\r\n%s" % (len(BODY), BODY))
        except OSError:
            pass


def serve_http(bind, port, context=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.listen(64)
    while True:
        conn, _ = sock.accept()
        if context:
            try:
                conn = context.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                conn.close()
                continue
        threading.Thread(target=handle_http, args=(conn,), daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", required=True)
    parser.add_argument("--answer", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    workers = [threading.Thread(target=serve_dns_udp, args=(args.bind, args.answer), daemon=True),
               threading.Thread(target=serve_dns_tcp, args=(args.bind, args.answer), daemon=True),
               threading.Thread(target=serve_http, args=(args.bind, 80), daemon=True),
               threading.Thread(target=serve_http, args=(args.bind, 443, context), daemon=True)]
    for worker in workers:
        worker.start()
    print("FAKE-INETSIM READY", flush=True)
    for worker in workers:
        worker.join()


if __name__ == "__main__":
    main()
