#!/usr/bin/env python3
"""Per-sample host and network features from the CIC-YNU-IoTMal 2026 tables.

The dataset publishes preprocessed tables, not raw traces (checked 2026-11-23):
  strace.parquet  one row per system call, holding the counts of each call name over the last W
                  calls (a sliding window of W = 20, stride 1); no timestamps, no process IDs;
  pcap.parquet    one row per group of about ten packets, CICIoT2023-style statistics; no 5-tuples
                  or timestamps.
Because the strace windows slide by one call, each sample's exact call sequence can be rebuilt by
differencing consecutive rows. This script rebuilds it, checks the rebuild against every row of
the table, and computes:
  host10   the ten call-sequence statistics of the thesis (features/host_model.py, unchanged) over
           the whole recorded execution, all processes merged (the table has no PIDs);
  hostc50  the same ten statistics over 40 equal-count chunks of the sequence, summarized by the
           thesis's five statistics (mean, max, sum, population std, chunks with calls);
  net      the dataset's 39 packet-group statistics summarized per sample by the same five
           statistics, plus the number of packet groups and of packets.
Usage: extract_cicynu.py <release repo> <arch name> <parquet dir> <out csv> <out json>
"""
import csv, json, math, sys, hashlib, collections
import numpy as np
import pyarrow.parquet as pq

release, arch, pdir, out_csv, out_json = sys.argv[1:6]
sys.path.insert(0, f"{release}/features")
import host_model  # noqa: E402  (the release's own definitions)

CHUNKS = 40
STATS = ("mean", "max", "sum", "std", "active")


def five(values):
    v = np.asarray(values, dtype=float)
    if v.size == 0:
        return [0.0] * 5
    return [float(v.mean()), float(v.max()), float(v.sum()), float(v.std()), float((v != 0).sum())]


def rebuild(X):
    """Call sequence (column indices) from sliding-window counts X (n x C). Returns seq, W."""
    n = X.shape[0]
    W = int(round(X.sum(1).max()))
    seq = np.full(n, -1, dtype=np.int64)
    if n == 0:
        return seq, W
    first_plus = (X[0] > 0.5)
    if first_plus.sum() != 1:
        return None, W
    seq[0] = int(np.argmax(X[0]))
    if n > 1:
        d = X[1:] - X[:-1]
        plus = d > 0.5
        has = plus.any(1)
        seq[1:][has] = np.argmax(plus[has], axis=1)
    # rows without a new count repeat the call that left the window (i - W): forward-fill per residue class
    m = int(math.ceil(n / W)) * W
    A = np.full(m, -1, dtype=np.int64); A[:n] = seq
    A = A.reshape(-1, W)
    valid = A >= 0
    idx = np.where(valid, np.arange(A.shape[0])[:, None], 0)
    idx = np.maximum.accumulate(idx, axis=0)
    filled = A[idx, np.arange(W)[None, :]]
    return filled.reshape(-1)[:n], W


def check(seq, X, W):
    """Exact recomputation of the table's windows from the rebuilt sequence."""
    n, C = X.shape
    if seq is None or (seq < 0).any():
        return n
    oh = np.zeros((n, C), dtype=np.int32); oh[np.arange(n), seq] = 1
    cum = np.cumsum(oh, axis=0)
    win = cum.copy(); win[W:] -= cum[:-W]
    return int((np.abs(win - np.rint(X)) > 0).any(1).sum())


def host_feats(seq):
    whole = host_model.ProcessWindow()
    chunks = [host_model.ProcessWindow() for _ in range(CHUNKS)]
    n = len(seq)
    bounds = np.minimum((np.arange(n) * CHUNKS) // max(n, 1), CHUNKS - 1)
    for s, c in zip(seq.tolist(), bounds.tolist()):
        whole.record(s); chunks[c].record(s)
    w = whole.row()
    rows = [c.row() if c.total else dict.fromkeys(host_model.SIGNALS, 0) for c in chunks]
    out = {f"h10_{k}": float(w[k]) for k in host_model.SIGNALS}
    for k in host_model.SIGNALS:
        for st, v in zip(STATS, five([r[k] for r in rows])):
            out[f"hc_{k}__{st}"] = v
    return out


f = pq.ParquetFile(f"{pdir}/strace.parquet")
cols = [c for c in f.schema_arrow.names if c.startswith("Call_")]
fam, feats, report = {}, {}, collections.Counter()
mismatched_rows = 0; windows_seen = collections.Counter(); seen = set()
buf_X, buf_h = [], None


def flush():
    global mismatched_rows
    if buf_h is None:
        return
    X = np.concatenate(buf_X).astype(np.float32)
    seq, W = rebuild(X)
    windows_seen[W] += 1
    bad = check(seq, X, W)
    mismatched_rows += bad
    report["samples"] += 1; report["rows"] += X.shape[0]
    if bad:
        report["samples_with_mismatch"] += 1
        return
    h = host_feats(seq)
    h["n_calls"] = int(len(seq)); h["window_W"] = W
    feats[buf_h] = h


for i in range(f.num_row_groups):
    t = f.read_row_group(i, columns=cols + ["Hash", "MalwareFamily"])
    X = np.column_stack([np.nan_to_num(t.column(c).to_numpy(zero_copy_only=False).astype(np.float32)) for c in cols])
    H = np.asarray(t.column("Hash").to_pylist(), dtype=object); F = t.column("MalwareFamily").to_pylist()
    starts = np.r_[0, np.where(H[1:] != H[:-1])[0] + 1]
    ends = np.r_[starts[1:], len(H)]
    for s, e in zip(starts, ends):
        h = H[s]
        if h != buf_h:
            flush()
            assert h not in seen, f"sample {h} not contiguous"
            seen.add(h); buf_X, buf_h = [], h; fam[h] = F[s]
        buf_X.append(X[s:e])
    print(f"{arch}: row group {i + 1}/{f.num_row_groups}", flush=True)
flush()

# network view: summaries of the dataset's packet-group rows
pt = pq.read_table(f"{pdir}/pcap.parquet").to_pandas()
num = [c for c in pt.columns if c not in ("Hash", "MalwareFamily", "Arch")]
net = {}
pfam = dict(zip(pt["Hash"], pt["MalwareFamily"]))
for h, g in pt.groupby("Hash", sort=False):
    row = {"n_pcap_rows": int(len(g)), "n_packets": float(g["Number"].sum())}
    for c in num:
        for st, v in zip(STATS, five(g[c].to_numpy(dtype=float))):
            row[f"net_{c}__{st}"] = v
    net[h] = row

keys = sorted(set(feats) & set(net))
host_cols = sorted({k for v in feats.values() for k in v})
net_cols = sorted({k for v in net.values() for k in v})
with open(out_csv, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["hash", "family", "arch"] + host_cols + net_cols)
    for h in keys:
        w.writerow([h, fam[h], arch] + [feats[h].get(c, 0.0) for c in host_cols] + [net[h].get(c, 0.0) for c in net_cols])
summary = {
    "arch": arch, "strace_samples": report["samples"], "strace_rows": report["rows"],
    "samples_with_rebuild_mismatch": report["samples_with_mismatch"], "mismatched_rows": mismatched_rows,
    "window_W": dict(windows_seen), "call_columns": len(cols),
    "pcap_samples": len(net), "pcap_families": dict(collections.Counter(pfam.values())),
    "samples_with_both_views": len(keys), "families_with_both": dict(collections.Counter(fam[h] for h in keys)),
    "strace_sha256": hashlib.sha256(open(f"{pdir}/strace.parquet", "rb").read()).hexdigest(),
    "pcap_sha256": hashlib.sha256(open(f"{pdir}/pcap.parquet", "rb").read()).hexdigest(),
}
json.dump(summary, open(out_json, "w"), indent=2)
print(json.dumps(summary, indent=1))
