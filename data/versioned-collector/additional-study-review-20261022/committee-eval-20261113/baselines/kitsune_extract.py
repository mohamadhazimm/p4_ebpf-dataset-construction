"""Kitsune (Mirsky et al., NDSS 2018) per-packet AfterImage features for every run, with the official code.

Pipeline per run (all outputs under baselines/cache/kitsune/):
  1. tshark parses the run's packet_capture.pcap with exactly the field list and flags of the official
     FeatureExtractor.pcap2tsv_with_tshark (-T fields ... -E header=y -E occurrence=f), into the cache;
  2. the rows of the 20-second observation window are kept (frame time in whole microseconds in
     [sample_started_wall_us, +20 s), the same packets as the thesis's network features), at most the first
     N_CAP = 20,000 of them; the row count is checked against an independent standard-library pcap reader;
  3. the official, unmodified FeatureExtractor.FE reads that .tsv (its documented tsv input path) and
     netStat/AfterImage produce one vector per packet, saved as float64. The current repository version yields
     100 features (FE.get_num_features()): the 15 "Host BW" statistics of the paper are commented out in
     netStat.updateGetStats; the code is used as published.

Why the cap: in the official pure-Python AfterImage every packet updates all covariance trackers of its source
stream, so the cost per packet grows with the number of distinct peers of a source; a source spraying SYNs to
~30k-100k addresses makes the run quadratic (measured on syn_fan_40k: 1k packets 3.7 s, 5k 99 s, 10k 548 s,
i.e. days for the 150k-packet fan-out floods). With the cap the slowest runs took 46 min (SYN fan-out floods)
and 86 min (udp_fan_60k, whose fixed source port adds a second quadratic stream). All packets are used for 224 of
the 240 runs; the 16 capped runs are 11 network-attack runs, the scanning Chaos sample and 4 network-benign runs.

Compatibility: the vendored code uses np.Inf, removed in NumPy 2.0; the alias np.Inf = np.inf is restored at
runtime (identical value). netStat.py calls pyximport.install(), so Cython is installed in vendor/pylib; no .pyx
module is imported (AfterImage.py, the pure-Python implementation, is used, as in the official FE).

    /usr/bin/python3 kitsune_extract.py
"""
import contextlib
import io
import json
import os
import struct
import subprocess
import sys
import time
from multiprocessing import Pool

import numpy as np

import bl_common as B

N_CAP = 20000
OUT = B.CACHE / "kitsune"
SRC = B.VENDOR / "kitsune-py" / "src"
TSHARK = "/usr/bin/tshark"
# Field list and options copied verbatim from FeatureExtractor.pcap2tsv_with_tshark (official code).
FIELDS = ("-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst -e tcp.srcport "
          "-e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e icmp.code -e arp.opcode "
          "-e arp.src.hw_mac -e arp.src.proto_ipv4 -e arp.dst.hw_mac -e arp.dst.proto_ipv4 -e ipv6.src "
          "-e ipv6.dst").split()


def import_official():
    sys.path.insert(0, str(B.VENDOR / "pylib"))
    sys.path.insert(0, str(SRC))
    np.Inf = np.inf  # alias removed in NumPy 2.0; same value
    with contextlib.redirect_stdout(io.StringIO()):
        import FeatureExtractor as FEmod  # noqa: E402
    return FEmod


def window_count(pcap, anchor):
    """Independent count of in-window frames (standard library), and the index range they occupy."""
    first = last = None
    n = 0
    inversions = 0  # a few frames in 7 runs are up to 95 us earlier than their predecessor; file order is kept
    with open(pcap, "rb") as f:
        h = f.read(24)
        assert h[:4] == b"\xd4\xc3\xb2\xa1", "classic little-endian microsecond pcap expected"
        k = 0
        prev = -1
        while True:
            r = f.read(16)
            if len(r) < 16:
                break
            s, us, cap, _ = struct.unpack("<IIII", r)
            f.seek(cap, 1)
            t = s * 1_000_000 + us
            inversions += t < prev
            prev = max(prev, t)
            if 0 <= t - anchor < 20_000_000:
                n += 1
                first = k if first is None else first
                last = k
            k += 1
    assert n == 0 or last - first + 1 == n, "in-window frames are not contiguous in the file"
    return n, first, last, k


def epoch_us(s):
    sec, _, frac = s.partition(".")
    return int(sec) * 1_000_000 + int((frac + "000000")[:6])


def work(args):
    i, od = args
    FEmod = import_official()
    t0 = time.time()
    rj = json.loads((od / "run.json").read_text())
    anchor = int(rj["sample_started_wall_us"])
    pcap = od / "packet_capture.pcap"
    n_win, first, last, n_all = window_count(pcap, anchor)
    (OUT / "tmp").mkdir(parents=True, exist_ok=True)
    (OUT / "tsv").mkdir(parents=True, exist_ok=True)
    (OUT / "vec").mkdir(parents=True, exist_ok=True)
    full = OUT / "tmp" / ("%03d.full.tsv" % i)
    with open(full, "w") as fo:
        subprocess.run([TSHARK, "-r", str(pcap), "-T", "fields", *FIELDS, "-E", "header=y", "-E", "occurrence=f"],
                       stdout=fo, stderr=subprocess.DEVNULL, check=True)
    tsv = OUT / "tsv" / ("%03d.tsv" % i)
    kept = 0
    with open(full) as fi, open(tsv, "w") as fo:
        fo.write(fi.readline())
        for k, line in enumerate(fi):
            t = epoch_us(line.split("\t", 1)[0])
            if 0 <= t - anchor < 20_000_000:
                assert first <= k <= last, (i, k)
                if kept < N_CAP:
                    fo.write(line)
                kept += 1
    full.unlink()
    assert kept == n_win, (i, "tshark rows in window", kept, "pcap frames in window", n_win)
    n_use = min(n_win, N_CAP)
    vecs = []
    dim = None
    if n_use:
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            fe = FEmod.FE(str(tsv), np.inf)
            dim = fe.get_num_features()
            while True:
                x = fe.get_next_vector()
                if len(x) == 0:
                    break
                vecs.append(x)
        assert len(vecs) == n_use, (i, "vectors", len(vecs), "rows", n_use, buf.getvalue()[-500:])
    V = np.asarray(vecs, dtype=np.float64).reshape(-1, 100)
    assert dim in (None, 100), dim
    np.save(OUT / "vec" / ("%03d.npy" % i), V)
    meta = {"row": i, "frames_in_file": n_all, "frames_in_window": n_win, "processed": n_use,
            "capped": bool(n_win > N_CAP), "seconds": round(time.time() - t0, 2),
            "finite": bool(np.isfinite(V).all())}
    (OUT / "meta").mkdir(parents=True, exist_ok=True)
    (OUT / "meta" / ("%03d.json" % i)).write_text(json.dumps(meta))
    return meta


def main():
    rows, y, g, cat, split, mode = B.dataset()
    dirs = B.C.run_dirs(rows)
    todo = []
    for i in range(len(rows)):
        if (OUT / "meta" / ("%03d.json" % i)).exists():
            continue
        todo.append((i, B.C.output_dir(dirs[i])))
    # most expensive first (fan-out floods and the scanning malware), then by capture size
    heavy = {"syn_fan_40k", "syn_fan_100k", "syn_fan_150k", "udp_fan_60k", "dns_10k", "dns_5k"}
    todo.sort(key=lambda t: (rows[t[0]]["execution_id"] not in heavy and rows[t[0]]["family"] != "Chaos",
                             -(t[1] / "packet_capture.pcap").stat().st_size))
    B.log("runs to process", len(todo))
    with Pool(B.MAX_JOBS) as p:
        for m in p.imap_unordered(work, todo, chunksize=1):
            B.log("row %3d %-24s window %6d processed %6d %7.1f s" % (
                m["row"], rows[m["row"]]["execution_id"][:24], m["frames_in_window"], m["processed"], m["seconds"]))
    metas = [json.loads((OUT / "meta" / ("%03d.json" % i)).read_text()) for i in range(len(rows))]
    summary = {"cap": N_CAP, "runs": len(metas), "runs_capped": sum(m["capped"] for m in metas),
               "packets_in_window": sum(m["frames_in_window"] for m in metas),
               "packets_processed": sum(m["processed"] for m in metas),
               "all_finite": all(m["finite"] for m in metas), "per_run": metas}
    B.write_json(OUT / "summary.json", summary)
    print({k: v for k, v in summary.items() if k != "per_run"})


if __name__ == "__main__":
    sys.exit(main())
