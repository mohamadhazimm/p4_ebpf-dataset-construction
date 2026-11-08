"""Benign concurrent logging: 8 threads each append 2,000 lines to their own log file, then the logs are merged."""
import json, sys, threading
def worker(t):
    with open("log%d.txt" % t, "a") as f:
        for i in range(2000):
            f.write("thread %d event %d\n" % (t, i)); f.flush()
threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
for t in threads: t.start()
for t in threads: t.join()
n = 0
with open("merged.txt", "w") as out:
    for t in range(8):
        with open("log%d.txt" % t) as f:
            for line in f:
                out.write(line); n += 1
print(json.dumps({"workload": "thread_fileio", "ok": n == 16000, "lines": n}))
sys.exit(0 if n == 16000 else 1)
