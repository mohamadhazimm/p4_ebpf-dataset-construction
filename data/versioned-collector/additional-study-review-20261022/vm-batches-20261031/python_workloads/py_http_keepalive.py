"""Benign API client: 200 requests over a persistent HTTP/1.1 connection (reconnects if the server closes it)."""
import http.client, json, sys
host = sys.argv[1]; assert host == "10.0.0.1"
ok = fail = connects = 0
conn = None
for i in range(200):
    try:
        if conn is None:
            conn = http.client.HTTPConnection(host, 80, timeout=3); connects += 1
        conn.request("GET", "/api/v1/items/%d" % i, headers={"Connection": "keep-alive"})
        resp = conn.getresponse(); resp.read(); ok += 1
        if resp.getheader("Connection", "").lower() == "close" or resp.version == 10:
            conn.close(); conn = None
    except (OSError, http.client.HTTPException):
        fail += 1
        if conn is not None:
            conn.close()
        conn = None
if conn is not None:
    conn.close()
print(json.dumps({"workload": "http_keepalive", "ok": ok, "failed": fail, "connections": connects}))
sys.exit(0 if ok else 1)
