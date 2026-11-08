
import socket, sys, time, json, threading
port = int(sys.argv[1]); logpath = sys.argv[2]; enable_pass = sys.argv[3]; flood_cmd = sys.argv[4]; sink = sys.argv[5]
logf = open(logpath, "a", buffering=1)
state = {"found": False, "channel": None, "flood_sent": False, "blocked": False}
MASTER = "Freak"   # a configured master nick (ismaster gate); the bot only obeys a master, addressed with a nick pattern
ATTACK = {"UDP","TCP","STD","HTTP","HOLD","JUNK","PAN","PHATWONK","BLACKNURSE","UNKNOWN","GET","SCANNER","KILLALL","KILLATTK","DNS","STOP"}
def rec(d, raw): logf.write(json.dumps({"t": time.time(), "dir": d, "raw": raw}) + "\n")
def send(conn, s):
    body = s.split(" :", 1)[1] if " :" in s else ""
    toks = body.split()
    for i, t in enumerate(toks):                       # any attack verb (anywhere) must target exactly the Sink
        if t.upper() in ATTACK:
            tgt = toks[i + 1] if i + 1 < len(toks) else ""
            if tgt != sink:
                state["blocked"] = True; rec("BLOCKED", s); return False
    conn.sendall((s + "\r\n").encode("latin-1", "replace")); rec("S->C", s); return True
def keepalive(conn):                                   # keep the bot's recv fed so it does not idle-timeout+reconnect
    while True:
        time.sleep(1.5)
        try: conn.sendall(b"PING :lab\r\n")
        except Exception: return
def commander(conn, channel):
    time.sleep(1.0)                                    # send ENABLE promptly, before the bot's recv-timeout reconnect
    src = ":%s!%s@lab" % (MASTER, MASTER)              # command must come FROM a master and be addressed to the bot (*)
    send(conn, "%s PRIVMSG %s :* ENABLE %s" % (src, channel, enable_pass))
    t0 = time.time()
    while time.time() - t0 < 12 and not state["found"]: time.sleep(0.3)
    if not state["found"]:
        rec("INFO", "ENABLE not confirmed; NOT sending flood"); return
    sent = send(conn, "%s PRIVMSG %s :* %s" % (src, channel, flood_cmd))
    state["flood_sent"] = bool(sent)
    rec("INFO", ("flood command issued: " if sent else "flood command BLOCKED: ") + flood_cmd)
def handle(conn):
    conn.settimeout(WINDOW_HINT); nick=None; registered=False; joined=False; ka=[False]; buf=b""
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
            elif cmd == "USER":                         # (re-)send welcome on every USER so a re-register recovers
                n = nick or "bot"
                for num, msg in (("001","Welcome"),("002","your host is lab"),("003","created"),
                                 ("004","lab lab 1.0 o o"),("375","- MOTD -"),("372","- lab -"),("376","End of MOTD")):
                    send(conn, ":lab %s %s :%s" % (num, n, msg))
                registered = True
                if not ka[0]:
                    ka[0] = True
                    threading.Thread(target=keepalive, args=(conn,), daemon=True).start()
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
            elif cmd == "WHO" and len(parts) > 1:   # the bot blocks waiting for its own WHO reply; answer 352+315
                who = parts[1]; ch = state.get("channel") or "#bots"
                send(conn, ":lab 352 %s %s %s 10.0.0.10 lab %s H :0 %s" % (nick, ch, who, nick, who))
                send(conn, ":lab 315 %s %s :End of /WHO list." % (nick, who))
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
