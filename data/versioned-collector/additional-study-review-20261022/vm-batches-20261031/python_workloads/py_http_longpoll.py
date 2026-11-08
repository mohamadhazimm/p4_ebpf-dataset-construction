"""Benign long-polling client: 30 sessions, each sends a complete request every 2 s for 12 s,
reusing its connection while the server keeps it open."""
import http.client, json, sys, time
host = sys.argv[1]; assert host == "10.0.0.1"
sessions = [None] * 30
ok = fail = connects = 0
end = time.monotonic() + 12
while time.monotonic() < end:
    for s in range(len(sessions)):
        try:
            if sessions[s] is None:
                sessions[s] = http.client.HTTPConnection(host, 80, timeout=3); connects += 1
            sessions[s].request("GET", "/events?session=%d" % s, headers={"Connection": "keep-alive"})
            r = sessions[s].getresponse(); r.read(); ok += 1
            if r.getheader("Connection", "").lower() == "close" or r.version == 10:
                sessions[s].close(); sessions[s] = None
        except (OSError, http.client.HTTPException):
            fail += 1
            if sessions[s] is not None:
                sessions[s].close()
            sessions[s] = None
    time.sleep(2)
for c in sessions:
    if c is not None:
        c.close()
print(json.dumps({"workload": "http_longpoll", "ok": ok, "failed": fail, "connections": connects}))
sys.exit(0 if ok else 1)
