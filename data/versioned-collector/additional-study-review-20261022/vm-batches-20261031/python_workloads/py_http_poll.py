"""Benign polling client: GET a status page every 0.25 s for 12 s."""
import json, sys, time, urllib.request
host = sys.argv[1]; assert host == "10.0.0.1"
ok = fail = 0
end = time.monotonic() + 12
i = 0
while time.monotonic() < end:
    try:
        with urllib.request.urlopen("http://%s/status/%d" % (host, i), timeout=3) as r:
            r.read(); ok += 1
    except OSError:
        fail += 1
    i += 1
    time.sleep(0.25)
print(json.dumps({"workload": "http_poll", "ok": ok, "failed": fail}))
sys.exit(0 if ok else 1)
