"""Benign concurrent downloader: 10 worker threads fetch 300 pages."""
import json, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor
host = sys.argv[1]; assert host == "10.0.0.1"
def get(i):
    try:
        with urllib.request.urlopen("http://%s/page/%d.html" % (host, i), timeout=3) as r:
            return len(r.read())
    except OSError:
        return -1
with ThreadPoolExecutor(10) as pool:
    sizes = list(pool.map(get, range(300)))
ok = sum(s >= 0 for s in sizes)
print(json.dumps({"workload": "http_threadpool", "ok": ok, "failed": len(sizes) - ok, "bytes": sum(s for s in sizes if s > 0)}))
sys.exit(0 if ok else 1)
