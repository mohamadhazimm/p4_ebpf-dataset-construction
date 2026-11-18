#!/usr/bin/env python3
"""Host preflight of the network-active benign batch (run_session_netbenign.py): every task's exact arguments, run
once inside an unprivileged, loopback-only network namespace against stand-in servers. Nothing leaves the namespace.

Stand-ins (all on the namespace's loopback, which also holds 10.0.0.1, 203.0.113.200 and the three RFC 5737 /24s):
DNS (53, every A query -> 203.0.113.200), HTTP (80), HTTPS (443), FTP (21) and implicit FTPS (990), SMTP (25, with
STARTTLS) and SMTPS (465), POP3 (110) and POP3S (995); and the real transport test server (labtransport server on
10.0.0.1: 9080, 9441-9443, 9444/udp). They stand in for INetSim, dnsmasq and the test server: they show that each
client accepts its arguments and completes its protocol exchange, not how INetSim answers.

  netbenign_preflight.sh <out-dir>      (sets up the namespace and calls this file with --serve and --run)
"""
import argparse
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BODY = b"<html><body>stand-in</body></html>\n"
LOG_LOCK = threading.Lock()
LOG = None


def log(service, event, **kw):
    with LOG_LOCK:
        LOG.write(json.dumps(dict(service=service, event=event, t=time.time(), **kw)) + "\n")
        LOG.flush()


def dns_reply(query, answer="203.0.113.200"):
    if len(query) < 12:
        return None
    qid = struct.unpack(">H", query[:2])[0]
    offset = 12
    while offset < len(query) and query[offset] != 0:
        offset += 1 + query[offset]
    offset += 5
    question = query[12:offset]
    qtype = struct.unpack(">H", question[-4:-2])[0] if len(question) >= 4 else 0
    # as the lab: dnsmasq answers A and refuses AAAA (no upstream); the guest's resolver passes that on as SERVFAIL
    header = struct.pack(">HHHHHH", qid, 0x8180 if qtype == 1 else 0x8182, 1, 1 if qtype == 1 else 0, 0, 0)
    record = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(answer) if qtype == 1 else b""
    return header + question + record


def serve_dns_udp(addr):
    # bound to one address: a reply from 0.0.0.0 would leave from 127.0.0.1, which resolvers reject
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, 53))
    while True:
        data, peer = s.recvfrom(4096)
        r = dns_reply(data)
        if r:
            s.sendto(r, peer)
            log("dns", "query", peer=peer[1])


def serve_dns_tcp():
    def handle(c):
        try:
            n = struct.unpack(">H", c.recv(2))[0]
            q = c.recv(n)
            r = dns_reply(q)
            c.sendall(struct.pack(">H", len(r)) + r)
        finally:
            c.close()
    listen(53, handle)


def listen(port, handler, tls_ctx=None, service=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(256)

    def run(c, peer):
        try:
            if tls_ctx is not None:
                c = tls_ctx.wrap_socket(c, server_side=True)
            log(service or str(port), "connect", peer=peer[1])
            handler(c)
        except Exception as e:      # noqa: BLE001 -- a stand-in: log and drop the connection
            log(service or str(port), "error", error="%s: %s" % (type(e).__name__, e))
        finally:
            try:
                c.close()
            except OSError:
                pass
    while True:
        c, peer = s.accept()
        threading.Thread(target=run, args=(c, peer), daemon=True).start()


def readline(f):
    line = f.readline(65536)
    return line.decode(errors="replace").rstrip("\r\n") if line else None


def http_handler(c):
    f = c.makefile("rb")
    while True:
        line = readline(f)
        if not line:
            return
        method, path, version = (line.split(" ") + ["", "", ""])[:3]
        headers = {}
        while True:
            h = readline(f)
            if h is None:
                return
            if h == "":
                break
            k, _, v = h.partition(":")
            headers[k.strip().lower()] = v.strip()
        n = int(headers.get("content-length", "0") or 0)
        got = 0
        while got < n:
            chunk = f.read(min(65536, n - got))
            if not chunk:
                break
            got += len(chunk)
        keep = version == "HTTP/1.1" and headers.get("connection", "").lower() != "close"
        log("http", "request", method=method, path=path[:80], body=got)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n%s"
                  % (len(BODY), b"keep-alive" if keep else b"close", BODY))
        if not keep:
            return


class Line:
    def __init__(self, c):
        self.c, self.f = c, c.makefile("rb")

    def send(self, text):
        self.c.sendall((text + "\r\n").encode())

    def recv(self):
        return readline(self.f)

    def upgrade(self, ctx):
        self.c = ctx.wrap_socket(self.c, server_side=True)
        self.f = self.c.makefile("rb")


def ftp_handler_factory(ctx, implicit):
    def handler(c):
        s = Line(c)
        s.send("220 stand-in FTP ready")
        prot_p, data = False, None
        while True:
            line = s.recv()
            if line is None:
                return
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            log("ftps" if implicit else "ftp", "cmd", cmd=cmd)
            if cmd == "USER":
                s.send("331 password please")
            elif cmd == "PASS":
                s.send("230 logged in")
            elif cmd == "SYST":
                s.send("215 UNIX Type: L8")
            elif cmd == "PWD":
                s.send('257 "/" is the current directory')
            elif cmd in ("TYPE", "MODE", "STRU", "OPTS", "PBSZ", "NOOP"):
                s.send("200 ok")
            elif cmd == "PROT":
                prot_p = arg.strip().upper() == "P"
                s.send("200 ok")
            elif cmd == "AUTH":
                s.send("234 go")
                s.upgrade(ctx)
            elif cmd == "FEAT":
                s.c.sendall(b"211-Features\r\n EPSV\r\n PASV\r\n PBSZ\r\n PROT\r\n211 End\r\n")
            elif cmd == "CWD":
                s.send("250 ok")
            elif cmd in ("SIZE", "MDTM"):
                s.send("550 not available")
            elif cmd in ("EPSV", "PASV"):
                data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data.bind(("0.0.0.0", 0))
                data.listen(1)
                port = data.getsockname()[1]
                if cmd == "EPSV":
                    s.send("229 Entering Extended Passive Mode (|||%d|)" % port)
                else:
                    s.send("227 Entering Passive Mode (10,0,0,1,%d,%d)" % (port >> 8, port & 255))
            elif cmd in ("LIST", "NLST", "MLSD", "RETR"):
                if data is None:
                    s.send("425 no data connection")
                    continue
                s.send("150 opening data connection")
                d, _ = data.accept()
                if prot_p:
                    d = ctx.wrap_socket(d, server_side=True)
                payload = (b"-rw-r--r-- 1 ftp ftp 4096 Nov 17 00:00 readme.txt\r\n" if cmd != "RETR"
                           else b"stand-in file\n" * 100)
                d.sendall(payload)
                if prot_p:
                    try:
                        d.unwrap()
                    except (OSError, ssl.SSLError):
                        pass
                d.close()
                data.close()
                data = None
                s.send("226 done")
            elif cmd == "QUIT":
                s.send("221 bye")
                return
            else:
                s.send("502 not implemented")
    return handler


def smtp_handler_factory(ctx):
    def handler(c):
        s = Line(c)
        s.send("220 stand-in ESMTP")
        while True:
            line = s.recv()
            if line is None:
                return
            cmd = line.split(" ")[0].upper()
            log("smtp", "cmd", cmd=cmd)
            if cmd == "EHLO":
                s.c.sendall(b"250-stand-in\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 OK\r\n")
            elif cmd == "HELO":
                s.send("250 stand-in")
            elif cmd == "STARTTLS":
                s.send("220 go ahead")
                s.upgrade(ctx)
            elif cmd in ("MAIL", "RCPT", "RSET", "NOOP"):
                s.send("250 ok")
            elif cmd == "DATA":
                s.send("354 end with .")
                while True:
                    m = s.recv()
                    if m is None or m == ".":
                        break
                s.send("250 queued")
            elif cmd == "QUIT":
                s.send("221 bye")
                return
            else:
                s.send("502 not implemented")
    return handler


def pop3_handler_factory(ctx):
    def handler(c):
        s = Line(c)
        s.send("+OK stand-in POP3 ready")
        msg = "From: a@lab.example\r\nSubject: hello\r\n\r\nbody"
        while True:
            line = s.recv()
            if line is None:
                return
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            log("pop3", "cmd", cmd=cmd)
            if cmd == "CAPA":
                s.c.sendall(b"+OK\r\nUSER\r\nUIDL\r\nSTLS\r\n.\r\n")
            elif cmd in ("USER", "PASS", "NOOP", "RSET", "DELE"):
                s.send("+OK")
            elif cmd == "STLS":
                s.send("+OK begin TLS")
                s.upgrade(ctx)
            elif cmd == "STAT":
                s.send("+OK 1 %d" % len(msg))
            elif cmd == "LIST":
                if arg:
                    s.send("+OK 1 %d" % len(msg))
                else:
                    s.c.sendall(b"+OK 1 messages\r\n1 %d\r\n.\r\n" % len(msg))
            elif cmd == "UIDL":
                s.c.sendall(b"+OK\r\n1 msg1\r\n.\r\n")
            elif cmd in ("RETR", "TOP"):
                s.c.sendall(b"+OK\r\n" + msg.encode() + b"\r\n.\r\n")
            elif cmd == "QUIT":
                s.send("+OK bye")
                return
            else:
                s.send("-ERR unknown")
    return handler


def serve(out):
    global LOG
    LOG = open(out / "standin.jsonl", "a")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(out / "cert.pem", out / "key.pem")
    threads = [threading.Thread(target=serve_dns_udp, args=(addr,), daemon=True) for addr in ("127.0.0.53", "10.0.0.1")]
    threads.append(threading.Thread(target=serve_dns_tcp, daemon=True))
    plan = [(80, http_handler, None, "http"), (443, http_handler, ctx, "https"),
            (21, ftp_handler_factory(ctx, False), None, "ftp"), (990, ftp_handler_factory(ctx, True), ctx, "ftps"),
            (25, smtp_handler_factory(ctx), None, "smtp"), (465, smtp_handler_factory(ctx), ctx, "smtps"),
            (110, pop3_handler_factory(ctx), None, "pop3"), (995, pop3_handler_factory(ctx), ctx, "pop3s")]
    for port, handler, tctx, name in plan:
        threads.append(threading.Thread(target=listen, args=(port, handler, tctx, name), daemon=True))
    for t in threads:
        t.start()
    (out / "standin.ready").write_text("ready\n")
    while True:
        time.sleep(3600)


# ------------------------------------------------------------------------------------------------- the clients

def check(spec, rc, out, err, work):
    """Did the client complete its exchange? From its own output files, receipt or stdout."""
    name, prog, args = spec["name"], spec.get("program"), spec["args"]
    text = out + err
    files = {p.name: p.stat().st_size for p in work.rglob("*") if p.is_file()}
    if prog in ("webfetch", "netpoll", "labtransport", "python-client"):
        try:
            receipt = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return False, "no JSON receipt"
        ok = receipt.get("ok", receipt.get("OK", receipt.get("answers", 0)))
        if prog == "netpoll":
            ok = sum(a.get("ok", 0) for a in receipt.get("activities", []))
        return bool(ok) and rc == 0, "receipt %s" % json.dumps(receipt)[:300]
    if prog == "openssl":
        return ("CONNECTION ESTABLISHED" in text or "CONNECTED(" in text), [l for l in text.splitlines()
                                                                             if "Protocol" in l or "CONNECT" in l][:3]
    if prog == "telnet":                      # stdin is /dev/null: telnet connects and closes (as the dataset's tasks)
        return "Connected to" in text, text.strip().splitlines()[:4]
    if prog == "curl":
        if "smtp" in name:
            return rc == 0, "rc %d" % rc
        expect = {"curl-crawl": 40, "curl-cdn-tls": 8, "curl-api-tls": 20}.get(name.rsplit("-", 1)[0], 1)
        written = [k for k, v in files.items() if v > 0]
        if name.startswith("curl-download"):
            big = sorted(v for k, v in files.items() if k.startswith("big"))
            return rc == 0 and big == [8000000] * 4, "big files %s" % big
        return rc == 0 and len(written) >= expect, "rc %d, %d files" % (rc, len(written))
    if prog == "wget":
        written = [k for k, v in files.items() if v > 0]
        if name.startswith("wget-download"):
            return rc == 0 and files.get("dl.bin") == 8000000, "dl.bin %s" % files.get("dl.bin")
        return rc == 0 and bool(written), "rc %d, files %s" % (rc, sorted(written)[:4])
    return rc == 0, "rc %d" % rc


def command(spec, bins, tools):
    if spec.get("source") == "archive":
        folder = bins / spec["archive"][:-4]
        member = [p for p in folder.iterdir() if p.is_file()]
        assert len(member) == 1, folder
        return [str(member[0])] + spec["args"]
    tool = spec["tool"]
    return [str(tools / tool)] + spec["args"]


def run_one(spec, bins, tools, out):
    work = out / "work" / spec["name"]
    work.mkdir(parents=True, exist_ok=True)
    argv = command(spec, bins, tools)
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=work, stdin=subprocess.DEVNULL, capture_output=True, timeout=200)
        rc, so, se = p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired as e:
        rc, so, se = -999, (e.stdout or b"").decode(errors="replace"), (e.stderr or b"").decode(errors="replace")
    ok, why = check(spec, rc, so, se, work)
    return {"name": spec["name"], "program": spec.get("program"), "ok": ok, "rc": rc,
            "seconds": round(time.monotonic() - t0, 1), "why": why, "stdout_tail": so[-400:], "stderr_tail": se[-400:]}


def run(out, protocol, bins, tools):
    specs = [s for s in json.loads(Path(protocol).read_text())["sessions"] if s["kind"] == "benign"]
    with ThreadPoolExecutor(max_workers=len(specs)) as ex:
        results = list(ex.map(lambda s: run_one(s, bins, tools, out), specs))
    (out / "results.json").write_text(json.dumps(results, indent=1))
    bad = [r for r in results if not r["ok"]]
    for r in sorted(results, key=lambda r: r["name"]):
        print("%-4s %-32s rc=%-4s %6.1fs %s" % ("ok" if r["ok"] else "FAIL", r["name"], r["rc"], r["seconds"],
                                                str(r["why"])[:110]))
    print("%d of %d tasks completed their exchange" % (len(results) - len(bad), len(results)))
    return 0 if not bad else 1


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--serve", action="store_true")
    p.add_argument("--run", action="store_true")
    p.add_argument("--out", required=True)
    p.add_argument("--protocol")
    p.add_argument("--bins")
    p.add_argument("--tools")
    a = p.parse_args()
    out = Path(a.out)
    if a.serve:
        serve(out)
    elif a.run:
        sys.exit(run(out, a.protocol, Path(a.bins), Path(a.tools)))


if __name__ == "__main__":
    main()
