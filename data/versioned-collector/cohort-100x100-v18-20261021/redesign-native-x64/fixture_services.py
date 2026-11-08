#!/usr/bin/env python3
"""Loopback-only protocol fixtures, available equally to both dataset labels."""

import json
import os
import socketserver
import sys
import threading
from pathlib import Path


def reply(protocol, request):
    if protocol == "whois":
        return b"Domain Name: EXAMPLE.INVALID\r\nStatus: RESERVED\r\n" if request.strip() == b"example.invalid" else b"No match\r\n"
    return b"221 Goodbye\r\n" if request.upper().startswith(b"QUIT") else b"530 Not logged in\r\n"


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        protocol = "whois" if self.server.server_address[1] == 65014 else "ftp"
        if protocol == "ftp":
            self.wfile.write(b"220 Isolated fixture FTP ready\r\n")
            self.wfile.flush()
        try:
            request = self.rfile.readline(1024)
            if request:
                self.wfile.write(reply(protocol, request))
                self.wfile.flush()
        except OSError:
            pass
        finally:
            record = json.dumps({"protocol": protocol, "request_received": bool(locals().get("request"))}) + "\n"
            descriptor = os.open(self.server.events_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, record.encode())
            finally:
                os.close(descriptor)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    root = Path(sys.argv[1]).resolve()
    servers = []
    for port in (65014, 65015):
        server = Server(("127.0.0.1", port), Handler)
        server.events_path = str(root / "fixture-service-events.jsonl")
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    main()