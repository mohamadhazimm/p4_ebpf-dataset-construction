
import socket, sys, threading, time, json
port = int(sys.argv[1]); logpath = sys.argv[2]
logf = open(logpath, "a", buffering=1)
def rec(d, s):
    try: logf.write(json.dumps({"t": time.time(), "dir": d, "msg": s}) + "\n")
    except Exception: pass
def send(conn, s):
    conn.sendall((s + "\r\n").encode("latin-1", "replace")); rec("S->C", s)
def keepalive(conn):
    while True:
        time.sleep(1.5)
        try: conn.sendall(b"PING :lab\r\n")
        except Exception: return
def handle(conn):
    conn.settimeout(300); nick=None; ka=[False]; chan=[None]; buf=b""
    while True:
        try: data = conn.recv(4096)
        except socket.timeout: break
        if not data: break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            text = line.decode("latin-1").rstrip("\r")
            if not text: continue
            rec("C->S", text); parts = text.split(); cmd = parts[0].upper() if parts else ""
            if cmd == "NICK" and len(parts) > 1: nick = parts[1].lstrip(":")
            elif cmd == "USER":
                n = nick or "bot"
                for num, msg in (("001","Welcome"),("002","your host is lab"),("003","created"),
                                 ("004","lab lab 1.0 o o"),("375","- MOTD -"),("372","- lab -"),("376","End of MOTD")):
                    send(conn, ":lab %s %s :%s" % (num, n, msg))
                if not ka[0]:
                    ka[0] = True; threading.Thread(target=keepalive, args=(conn,), daemon=True).start()
            elif cmd == "CAP": send(conn, ":lab CAP * LS :")
            elif cmd == "PING":
                arg = text.split(" ", 1)[1] if " " in text else ":lab"
                send(conn, "PONG %s" % arg)
            elif cmd == "JOIN" and len(parts) > 1:
                ch = parts[1].lstrip(":").split(",")[0]; chan[0] = ch
                send(conn, ":%s!%s@lab JOIN :%s" % (nick, nick, ch))
                send(conn, ":lab 353 %s = %s :%s @op" % (nick, ch, nick))
                send(conn, ":lab 366 %s %s :End of names" % (nick, ch))
            elif cmd == "WHO" and len(parts) > 1:
                who = parts[1]; ch = chan[0] or "#bots"
                send(conn, ":lab 352 %s %s %s 10.0.0.10 lab %s H :0 %s" % (nick, ch, who, nick, who))
                send(conn, ":lab 315 %s %s :End of /WHO list." % (nick, who))
    rec("INFO", "client disconnected")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.listen(5); s.settimeout(300)
rec("INFO", "reg-only controller on %d (NO attack commands)" % port)
try:
    while True:
        try: conn, addr = s.accept()
        except socket.timeout: break
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
except KeyboardInterrupt:
    pass
