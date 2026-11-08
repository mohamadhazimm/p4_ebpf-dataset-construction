
import socket, sys, time, json, threading
port = int(sys.argv[1]); logpath = sys.argv[2]; enable_pass = sys.argv[3]; flood_cmd = sys.argv[4]; sink = sys.argv[5]
logf = open(logpath, "a", buffering=1)
state = {"found": False, "channel": None, "flood_sent": False, "blocked": False}
ATTACK = {"UDP","TCP","STD","HTTP","HOLD","JUNK","PAN","PHATWONK","BLACKNURSE","UNKNOWN","GET","SCANNER","KILLALL","KILLATTK","DNS","STOP"}
def rec(d, raw): logf.write(json.dumps({"t": time.time(), "dir": d, "raw": raw}) + "\n")
def send(conn, s):
    body = s.split(" :", 1)[1] if " :" in s else ""
    toks = body.split(); verb = toks[0].upper() if toks else ""
    if verb in ATTACK and not (len(toks) >= 2 and toks[1] == sink):   # only a flood AT THE SINK may be sent
        state["blocked"] = True; rec("BLOCKED", s); return False
    conn.sendall((s + "\r\n").encode("latin-1", "replace")); rec("S->C", s); return True
def commander(conn, channel):
    time.sleep(3)
    send(conn, ":op!op@lab PRIVMSG %s :ENABLE %s" % (channel, enable_pass))
    t0 = time.time()
    while time.time() - t0 < 12 and not state["found"]: time.sleep(0.3)
    if not state["found"]:
        rec("INFO", "ENABLE not confirmed; NOT sending flood"); return
    sent = send(conn, ":op!op@lab PRIVMSG %s :%s" % (channel, flood_cmd))
    state["flood_sent"] = bool(sent)
    rec("INFO", ("flood command issued: " if sent else "flood command BLOCKED: ") + flood_cmd)
def handle(conn):
    conn.settimeout(WINDOW_HINT); nick=None; registered=False; joined=False; buf=b""
    while True:
        try: data = conn.recv(4096)
        except socket.timeout: break
        if not data: break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            text = line.decode("latin-1").rstrip("\r")
            if not text: continue
            rec("C->S", text); low = text.lower()
            if ("password correct" in low) or ("awaiting orders" in low) or ("already enabled" in low):
                state["found"] = True; rec("INFO", "ENABLE accepted")
            parts = text.split(); cmd = parts[0].upper() if parts else ""
            if cmd == "NICK" and len(parts) > 1: nick = parts[1].lstrip(":")
            elif cmd == "USER" and not registered:
                n = nick or "bot"
                for num, msg in (("001","Welcome"),("002","your host is lab"),("003","created"),
                                 ("004","lab lab 1.0 o o"),("375","- MOTD -"),("372","- lab -"),("376","End of MOTD")):
                    send(conn, ":lab %s %s :%s" % (num, n, msg))
                registered = True
            elif cmd == "CAP": send(conn, ":lab CAP * LS :")
            elif cmd == "PING":
                arg = text.split(" ", 1)[1] if " " in text else ":lab"
                send(conn, "PONG %s" % arg)
            elif cmd == "JOIN" and len(parts) > 1:
                ch = parts[1].lstrip(":").split(",")[0]; state["channel"] = ch
                send(conn, ":%s!%s@lab JOIN :%s" % (nick, nick, ch))
                send(conn, ":lab 353 %s = %s :%s @op" % (nick, ch, nick))
                send(conn, ":lab 366 %s %s :End of names" % (nick, ch))
                if not joined:
                    joined = True
                    threading.Thread(target=commander, args=(conn, ch), daemon=True).start()
    rec("INFO", "client disconnected")
WINDOW_HINT = 120
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(5); s.settimeout(WINDOW_HINT)
    rec("INFO", "listening on %d; flood_cmd=%r sink=%s" % (port, flood_cmd, sink))
    try:
        while True:
            try: conn, addr = s.accept()
            except socket.timeout: break
            rec("INFO", "connection from %s" % (addr,))
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    finally:
        json.dump(state, open(logpath + ".summary", "w"))
main()
