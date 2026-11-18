"""Unconstrained software network features: CICFlowMeter-like bidirectional flows from each run's capture.

Packets: the frames of the 20-second observation window (whole-microsecond time in [sample_started_wall_us,
+20 s), the same packets as the thesis's switch features), IPv4 TCP and UDP only (as CICFlowMeter), parsed with
the standard library. A flow is a bidirectional 5-tuple; the direction of its first packet is "forward". A TCP flow
is terminated by RST or once both directions have sent FIN; packets that still follow (the last ACK) stay in it,
and only a new SYN (without ACK) on a terminated 5-tuple starts a new flow, so a flow is one TCP connection (this
avoids CICFlowMeter's known split of connections at the first FIN). UDP flows are never split; there is no timeout
inside 20 s (CICFlowMeter's flow timeout is 120 s).

Per flow (38): duration; forward/backward packet counts and payload bytes; payload-length min/max/mean/std per
direction; inter-arrival mean/std/min/max overall and per direction; SYN/FIN/RST/PSH/ACK/URG counts; forward and
backward header bytes (IP + transport headers); payload bytes/s and packets/s; down/up packet ratio; average
payload size; TCP indicator.
Per run (115): number of flows, then mean, max and standard deviation over the run's flows of each per-flow
feature (all zero when the run has no flow).

Output: cache/flows/features.npz (240 x 115, rows in features.csv order).

    /usr/bin/python3 flow_extract.py            # extract all runs
    /usr/bin/python3 flow_extract.py --time F   # single-core throughput on whole capture files (packets/s)
"""
import argparse
import json
import struct
import sys
import time
from multiprocessing import Pool

import numpy as np

import bl_common as B

OUT = B.CACHE / "flows"
FLOW_FEATURES = [
    "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "fwd_len_min", "fwd_len_max", "fwd_len_mean", "fwd_len_std",
    "bwd_len_min", "bwd_len_max", "bwd_len_mean", "bwd_len_std",
    "iat_mean", "iat_std", "iat_min", "iat_max",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_min", "fwd_iat_max",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_min", "bwd_iat_max",
    "syn", "fin", "rst", "psh", "ack", "urg", "fwd_hdr_bytes", "bwd_hdr_bytes",
    "bytes_per_s", "pkts_per_s", "down_up_ratio", "avg_payload", "is_tcp",
]
RUN_FEATURES = ["flow_count"] + ["%s__%s" % (f, s) for f in FLOW_FEATURES for s in ("mean", "max", "std")]


def frames(path, anchor=None):
    """Yield (time in microseconds, frame bytes); only the observation window when anchor is given."""
    with open(path, "rb") as f:
        h = f.read(24)
        assert h[:4] == b"\xd4\xc3\xb2\xa1" and struct.unpack("<I", h[20:24])[0] == 1
        while True:
            r = f.read(16)
            if len(r) < 16:
                return
            s, us, cap, _ = struct.unpack("<IIII", r)
            fr = f.read(cap)
            t = s * 1_000_000 + us
            if anchor is None or 0 <= t - anchor < 20_000_000:
                yield t, fr


def parse(fr):
    """(src, sport, dst, dport, proto, payload length, header length, tcp flags) for IPv4 TCP/UDP, else None."""
    if len(fr) < 14:
        return None
    off, et, tags = 12, (fr[12] << 8) | fr[13], 0
    while et in (0x8100, 0x88A8):
        tags += 1
        if tags > 2 or len(fr) < off + 6:
            return None
        off += 4
        et = (fr[off] << 8) | fr[off + 1]
    off += 2
    if et != 0x0800 or len(fr) < off + 20 or fr[off] >> 4 != 4:
        return None
    ihl = (fr[off] & 0x0F) * 4
    total = (fr[off + 2] << 8) | fr[off + 3]
    proto = fr[off + 9]
    if ihl < 20 or total < ihl or proto not in (6, 17) or len(fr) < off + ihl:
        return None
    if ((fr[off + 6] & 0x1F) << 8 | fr[off + 7]) != 0:
        return None  # non-first fragment
    tp = off + ihl
    if proto == 6:
        if len(fr) < tp + 20:
            return None
        thl = (fr[tp + 12] >> 4) * 4
        flags = fr[tp + 13]
    else:
        if len(fr) < tp + 8:
            return None
        thl, flags = 8, 0
    src, dst = fr[off + 12:off + 16], fr[off + 16:off + 20]
    sport, dport = (fr[tp] << 8) | fr[tp + 1], (fr[tp + 2] << 8) | fr[tp + 3]
    return src, sport, dst, dport, proto, max(total - ihl - thl, 0), ihl + thl, flags


class Flow:
    __slots__ = ("fwd", "t", "d", "ln", "hdr", "flags", "proto", "fin_f", "fin_b")

    def __init__(self, fwd, proto):
        self.fwd, self.proto = fwd, proto
        self.t, self.d, self.ln, self.hdr, self.flags = [], [], [], [], []
        self.fin_f = self.fin_b = False

    def add(self, t, is_fwd, ln, hdr, flags):
        self.t.append(t); self.d.append(is_fwd); self.ln.append(ln); self.hdr.append(hdr); self.flags.append(flags)
        if flags & 0x01:
            if is_fwd:
                self.fin_f = True
            else:
                self.fin_b = True

    def terminated(self):
        return self.proto == 6 and (any(f & 0x04 for f in self.flags) or (self.fin_f and self.fin_b))

    def features(self):
        t = np.asarray(self.t, dtype=np.float64) / 1e6
        d = np.asarray(self.d, dtype=bool)
        ln = np.asarray(self.ln, dtype=np.float64)
        hdr = np.asarray(self.hdr, dtype=np.float64)
        fl = np.asarray(self.flags, dtype=np.int64)
        dur = float(t[-1] - t[0])

        def stats(x):
            return [float(x.min()), float(x.max()), float(x.mean()), float(x.std())] if len(x) else [0.0] * 4

        def iat(x):
            g = np.diff(x)
            return [float(g.mean()), float(g.std()), float(g.min()), float(g.max())] if len(g) else [0.0] * 4

        nf, nb = int(d.sum()), int((~d).sum())
        tot_bytes = float(ln.sum())
        out = [dur, nf, nb, float(ln[d].sum()), float(ln[~d].sum())]
        out += stats(ln[d]) + stats(ln[~d])
        out += iat(t) + iat(t[d]) + iat(t[~d])
        out += [int(((fl & m) > 0).sum()) for m in (0x02, 0x01, 0x04, 0x08, 0x10, 0x20)]
        out += [float(hdr[d].sum()), float(hdr[~d].sum())]
        out += [tot_bytes / dur if dur > 0 else 0.0, len(t) / dur if dur > 0 else 0.0,
                nb / nf if nf else 0.0, tot_bytes / len(t), float(self.proto == 6)]
        return out


def run_flows(path, anchor=None):
    active, done = {}, []
    for t, fr in frames(path, anchor):
        p = parse(fr)
        if p is None:
            continue
        src, sport, dst, dport, proto, ln, hdr, flags = p
        a, b = (src, sport), (dst, dport)
        key = (proto, a, b) if a <= b else (proto, b, a)
        fl = active.get(key)
        if fl is not None and proto == 6 and (flags & 0x12) == 0x02 and fl.terminated():
            done.append(fl)  # new connection on a terminated 5-tuple
            fl = None
        if fl is None:
            fl = active[key] = Flow(a, proto)
        fl.add(t, a == fl.fwd, ln, hdr, flags)
    done.extend(active.values())
    return done


def run_vector(flows):
    if not flows:
        return np.zeros(len(RUN_FEATURES))
    M = np.asarray([f.features() for f in flows], dtype=np.float64)
    agg = np.stack([M.mean(0), M.max(0), M.std(0)], axis=1).reshape(-1)  # feature-major: mean, max, std
    return np.concatenate([[len(flows)], agg])


def work(args):
    i, od = args
    anchor = int(json.loads((od / "run.json").read_text())["sample_started_wall_us"])
    fl = run_flows(od / "packet_capture.pcap", anchor)
    return i, run_vector(fl), len(fl)


def timing(paths):
    out = []
    for p in paths:
        n = sum(1 for _ in frames(p))
        t0 = time.process_time()
        fl = run_flows(p)
        v = run_vector(fl)
        dt = time.process_time() - t0
        out.append({"pcap": str(p), "packets": n, "flows": len(fl), "cpu_seconds": dt, "packets_per_s": n / dt})
        print(out[-1])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--time", nargs="*", help="pcap files to time (whole files, one core)")
    a = ap.parse_args()
    if a.time:
        r = timing(a.time)
        B.write_json(B.RESULTS / "throughput_flow_extractor.json", r)
        return
    rows, *_ = B.dataset()
    dirs = B.C.run_dirs(rows)
    with Pool(B.MAX_JOBS) as p:
        res = p.map(work, [(i, B.C.output_dir(dirs[i])) for i in range(len(rows))], chunksize=1)
    res.sort(key=lambda t: t[0])
    X = np.stack([r[1] for r in res])
    assert X.shape == (240, len(RUN_FEATURES)) and np.isfinite(X).all()
    OUT.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(OUT / "features.npz", X=X, columns=np.asarray(RUN_FEATURES),
                        flows=np.asarray([r[2] for r in res]))
    print("flows per run: median %d max %d; runs without flows %d" % (
        np.median([r[2] for r in res]), max(r[2] for r in res), sum(r[2] == 0 for r in res)))


if __name__ == "__main__":
    sys.exit(main())
