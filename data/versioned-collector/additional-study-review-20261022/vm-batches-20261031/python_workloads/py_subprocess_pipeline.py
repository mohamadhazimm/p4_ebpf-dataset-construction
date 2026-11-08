"""Benign build-style script: generate data, then run sort, uniq and gzip as child processes."""
import json, random, subprocess, sys
random.seed(5)
with open("words.txt", "w") as f:
    for _ in range(100000):
        f.write("w%d\n" % random.randrange(5000))
sorted_ = subprocess.run(["/usr/bin/sort", "words.txt"], capture_output=True, check=True).stdout
counts = subprocess.run(["/usr/bin/uniq", "-c"], input=sorted_, capture_output=True, check=True).stdout
with open("counts.txt", "wb") as f:
    f.write(counts)
subprocess.run(["/usr/bin/gzip", "-k", "-f", "counts.txt"], check=True)
lines = counts.count(b"\n")
print(json.dumps({"workload": "subprocess_pipeline", "ok": lines > 4000, "distinct": lines}))
sys.exit(0 if lines > 4000 else 1)
