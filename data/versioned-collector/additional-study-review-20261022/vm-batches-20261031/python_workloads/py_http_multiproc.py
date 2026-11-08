"""Benign parallel fetcher: 4 worker processes fetch 60 pages each."""
import json, sys, urllib.request
from multiprocessing import Pool
host = sys.argv[1]; assert host == "10.0.0.1"
def worker(w):
    ok = 0
    for i in range(60):
        try:
            with urllib.request.urlopen("http://%s/w%d/item%d" % (host, w, i), timeout=3) as r:
                r.read(); ok += 1
        except OSError:
            pass
    return ok
if __name__ == "__main__":
    with Pool(4) as pool:
        counts = pool.map(worker, range(4))
    print(json.dumps({"workload": "http_multiproc", "ok": sum(counts), "failed": 240 - sum(counts)}))
    sys.exit(0 if sum(counts) else 1)
