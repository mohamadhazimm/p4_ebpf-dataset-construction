
import socket, sys, time, json, threading
port = int(sys.argv[1]); logpath = sys.argv[2]; candidates = json.load(open(sys.argv[3]))
logf = open(logpath, "a", buffering=1)
state = {"winner": None, "found": False, "channel": None, "last_guess": None, "sent_attack": False}
lock = threading.Lock()
ATTACK = {"UDP","TCP","STD","HTTP","HOLD","JUNK","PAN","PHATWONK","BLACKNURSE","UNKNOWN","GET","SCANNER","KILLALL","KILLATTK","DNS"}
def rec(direction, raw):
    logf.write(json.dumps({"t": time.time(), "dir": direction, "raw": raw}) + "\n")
def send(conn, s):
    body = s.split(" :", 1)[1] if " :" in s else ""
    tok = body.split()[0].upper() if body else ""
    if tok in ATTACK:                      # hard guardrail: Phase 2 can never issue an attack command
        state["sent_attack"] = True; rec("BLOCKED", s); return
    conn.sendall((s + "\r\n").encode("latin-1", "replace")); rec("S->C", s)
def enable_probes(conn, channel):
    time.sleep(5)
    for g in candidates:
        with lock:
            if state["found"]: break
            state["last_guess"] = g
        send(conn, ":op!op@lab PRIVMSG %s :ENABLE %s" % (channel, g))
        time.sleep(2.5)
    rec("INFO", "enable probes done found=%s winner=%s" % (state["found"], state["winner"]))
def handle(conn):
    conn.settimeout(150); nick=None; registered=False; joined=False; buf=b""
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
                with lock: state["found"]=True; state["winner"]=state["last_guess"]
                rec("INFO", "ENABLE accepted winner=%s" % state["winner"])
            parts = text.split(); cmd = parts[0].upper() if parts else ""
            if cmd=="NICK" and len(parts)>1: nick = parts[1].lstrip(":")
            elif cmd=="USER" and not registered:
                n = nick or "bot"
                for num,msg in (("001","Welcome"),("002","your host is lab"),("003","created"),
                                ("004","lab lab 1.0 o o"),("375","- MOTD -"),("372","- lab -"),("376","End of MOTD")):
                    send(conn, ":lab %s %s :%s" % (num, n, msg))
                registered = True
            elif cmd=="CAP": send(conn, ":lab CAP * LS :")
            elif cmd=="PING":
                arg = text.split(" ",1)[1] if " " in text else ":lab"
                send(conn, "PONG %s" % arg)
            elif cmd=="JOIN" and len(parts)>1:
                ch = parts[1].lstrip(":").split(",")[0]; state["channel"]=ch
                send(conn, ":%s!%s@lab JOIN :%s" % (nick, nick, ch))
                send(conn, ":lab 353 %s = %s :%s @op" % (nick, ch, nick))
                send(conn, ":lab 366 %s %s :End of names" % (nick, ch))
                if not joined:
                    joined = True
                    threading.Thread(target=enable_probes, args=(conn, ch), daemon=True).start()
    rec("INFO", "client disconnected")
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(5); s.settimeout(130)
    rec("INFO", "listening on %d" % port)
    try:
        while True:
            try: conn, addr = s.accept()
            except socket.timeout: break
            rec("INFO", "connection from %s" % (addr,))
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    finally:
        json.dump(state, open(logpath + ".summary", "w"))
main()
