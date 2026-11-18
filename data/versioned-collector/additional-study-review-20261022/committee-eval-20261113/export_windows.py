"""Export the dataset's per-window signals (240 runs x 40 windows x 18 host + 29 network) for live streaming
verdicts on PC1 (p4_ebpf live_test/streaming/). Checked first: the five summaries of the 40 windows equal the
published columns of every row. Offline.

    /usr/bin/python3 export_windows.py OUT.csv.gz
"""
import csv
import gzip
import hashlib
import io
import sys

import numpy as np

import common as C

rows, hc, nc = C.load()
H, N, hs, ns = C.per_window(rows, hc, nc)
assert np.allclose(C.summarize(H), C.matrix(rows, hc), rtol=1e-12, atol=1e-12)
assert np.allclose(C.summarize(N), C.matrix(rows, nc), rtol=1e-12, atol=1e-12)
out = sys.argv[1]
meta = ["execution_id", "label", "category", "cv_group", "split", "window"]
with open(out, "wb") as raw, io.TextIOWrapper(gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=0), newline="") as f:
    w = csv.writer(f)
    w.writerow(meta + hs + ns)
    for i, r in enumerate(rows):
        for k in range(40):
            w.writerow([r["execution_id"], r["label"], r["category"], r["cv_group"], r["split"], k]
                       + [repr(float(x)) for x in H[i, k]] + [repr(float(x)) for x in N[i, k]])
print(out, len(rows) * 40, "rows;", len(hs), "host and", len(ns), "network signals; sha256",
      hashlib.sha256(open(out, "rb").read()).hexdigest())
