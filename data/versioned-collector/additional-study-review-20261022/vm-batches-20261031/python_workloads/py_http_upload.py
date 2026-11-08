"""Benign uploader: POST twenty 256-KiB files."""
import json, os, sys, urllib.request
host = sys.argv[1]; assert host == "10.0.0.1"
ok = fail = 0
for i in range(20):
    body = os.urandom(256 * 1024)
    req = urllib.request.Request("http://%s/upload/file%d.bin" % (host, i), data=body, method="POST",
                                 headers={"Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            r.read(); ok += 1
    except OSError:
        fail += 1
print(json.dumps({"workload": "http_upload", "ok": ok, "failed": fail, "bytes_sent": ok * 256 * 1024}))
sys.exit(0 if ok else 1)
