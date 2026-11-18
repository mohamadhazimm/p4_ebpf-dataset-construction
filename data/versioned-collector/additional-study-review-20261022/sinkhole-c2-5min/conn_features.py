"""Connection-shape features for the sinkhole C2 experiment (pre-registered 2026-11-13).

Defined before any model was trained on the sinkhole runs; see PREREGISTRATION_conn_features.json for the freeze,
what had been looked at before it, and the decision rules.

Payload-free: only packet headers, sizes and times. One vector per run and prefix T, from the guest capture
(packet_capture.pcap) in [sample start, sample start + T). A switch could keep the state behind them (per-flow
first payload sizes and per-destination start-time statistics, next to the existing per-flow counters); here they
are computed offline from the same packets the switch features use.

TCP connection = (guest port, remote address, remote port) started by a guest SYN inside the window.
UDP traffic to remote port 53 is counted as DNS only (no payload parsing). Everything else is ignored.

    python3 conn_features.py --self-test
"""
import statistics
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

GUEST = "10.0.0.10"
NAMES = [
    "tcp_conns", "tcp_dests", "tcp_top_dest_share",
    "tcp_gap_median", "tcp_gap_cv", "tcp_gap_min", "tcp_gap_max",
    "conn_out_median", "conn_in_median", "conn_out_cv", "conn_zero_out_share", "conn_zero_in_share",
    "conn_dur_median", "conn_dur_max", "conn_open_share",
    "out_p1", "out_p2", "out_p3", "in_p1", "in_p2", "in_p3", "out_triple_repeat",
    "udp_dgrams", "udp_dests", "udp_size_median", "udp_size_cv", "udp_gap_median", "udp_gap_cv",
    "dns_packets", "first_contact_delay",
]
NO_FIRST_CONTACT = [i for i, n in enumerate(NAMES) if n != "first_contact_delay"]


def _ip(b):
    return "%d.%d.%d.%d" % tuple(b)


def packets(data):
    """Yield (time, src, dst, proto, sport, dport, tcp_flags, payload_len) for IPv4 TCP/UDP frames."""
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError("not a classic pcap")
    scale = 1e-9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e-6
    if struct.unpack(e + "I", data[20:24])[0] != 1:
        raise ValueError("link type is not Ethernet")
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        f = data[off:off + incl]
        off += incl
        if len(f) < 34 or f[12:14] != b"\x08\x00":
            continue
        ihl = (f[14] & 15) * 4
        total = struct.unpack(">H", f[16:18])[0]
        proto, h = f[23], 14 + ihl
        t = sec + frac * scale
        if proto == 6 and len(f) >= h + 14:
            sport, dport = struct.unpack(">HH", f[h:h + 4])
            yield t, _ip(f[26:30]), _ip(f[30:34]), 6, sport, dport, f[h + 13], max(0, total - ihl - (f[h + 12] >> 4) * 4)
        elif proto == 17 and len(f) >= h + 8:
            sport, dport, ulen = struct.unpack(">HHH", f[h:h + 6])
            yield t, _ip(f[26:30]), _ip(f[30:34]), 17, sport, dport, 0, max(0, ulen - 8)


def flows(data, t0, seconds):
    """Guest TCP connections and UDP datagrams in [t0, t0 + seconds)."""
    conns, done, udp, dns = {}, [], [], []
    for t, src, dst, proto, sport, dport, flags, pay in packets(data):
        rel = t - t0
        if not 0 <= rel < seconds:
            continue
        if proto == 6:
            if src == GUEST:
                key, out = (sport, dst, dport), True
            elif dst == GUEST:
                key, out = (dport, src, sport), False
            else:
                continue
            if key in conns and conns[key]["closed"] and out and flags & 0x12 == 0x02:
                done.append((key, conns.pop(key)))    # same port reused after a close: a new connection
            if key not in conns:
                if out and flags & 0x12 == 0x02:
                    conns[key] = {"start": rel, "end": rel, "closed": False, "out": 0, "in": 0,
                                  "out_seq": [], "in_seq": []}
                continue
            c = conns[key]
            c["end"] = rel
            if flags & 0x05:                      # FIN or RST from either side
                c["closed"] = True
            if pay:
                c["out" if out else "in"] += pay
                c["out_seq" if out else "in_seq"].append(pay)
        elif proto == 17 and src == GUEST:
            (dns if dport == 53 else udp).append((rel, (dst, dport), pay))
    return done + list(conns.items()), udp, dns


def _cv(values):
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else 0.0


def _gaps(times):
    times = sorted(times)
    return [b - a for a, b in zip(times, times[1:])]


def _top(counter):
    return max(sorted(counter), key=lambda k: counter[k])


def features(data, t0, seconds):
    conns, udp, dns = flows(data, t0, seconds)
    v = dict.fromkeys(NAMES, 0.0)
    v["first_contact_delay"] = float(seconds)
    starts = [c["start"] for _, c in conns] + [t for t, _, _ in udp]
    if starts:
        v["first_contact_delay"] = min(starts)
    if conns:
        dests = Counter((k[1], k[2]) for k, _ in conns)
        top = _top(dests)
        gaps = _gaps([c["start"] for k, c in conns if (k[1], k[2]) == top])
        cs = [c for _, c in conns]
        outs, ins = [c["out"] for c in cs], [c["in"] for c in cs]
        triples = [tuple((c["out_seq"] + [0, 0, 0])[:3]) for c in cs]
        v.update({
            "tcp_conns": len(cs), "tcp_dests": len(dests), "tcp_top_dest_share": dests[top] / len(cs),
            "tcp_gap_median": statistics.median(gaps) if gaps else 0.0,
            "tcp_gap_cv": _cv(gaps), "tcp_gap_min": min(gaps) if gaps else 0.0, "tcp_gap_max": max(gaps) if gaps else 0.0,
            "conn_out_median": statistics.median(outs), "conn_in_median": statistics.median(ins),
            "conn_out_cv": _cv(outs),
            "conn_zero_out_share": sum(1 for x in outs if x == 0) / len(cs),
            "conn_zero_in_share": sum(1 for x in ins if x == 0) / len(cs),
            "conn_dur_median": statistics.median(c["end"] - c["start"] for c in cs),
            "conn_dur_max": max(c["end"] - c["start"] for c in cs),
            "conn_open_share": sum(1 for c in cs if not c["closed"]) / len(cs),
            "out_triple_repeat": Counter(triples).most_common(1)[0][1] / len(cs),
        })
        for i in range(3):
            v["out_p%d" % (i + 1)] = statistics.median((c["out_seq"] + [0, 0, 0])[i] for c in cs)
            v["in_p%d" % (i + 1)] = statistics.median((c["in_seq"] + [0, 0, 0])[i] for c in cs)
    if udp:
        dests = Counter(d for _, d, _ in udp)
        top = _top(dests)
        sizes = [p for _, _, p in udp]
        gaps = _gaps([t for t, d, _ in udp if d == top])
        v.update({"udp_dgrams": len(udp), "udp_dests": len(dests), "udp_size_median": statistics.median(sizes),
                  "udp_size_cv": _cv(sizes), "udp_gap_median": statistics.median(gaps) if gaps else 0.0,
                  "udp_gap_cv": _cv(gaps)})
    v["dns_packets"] = len(dns)
    return [float(v[n]) for n in NAMES]


def for_run(run_dir, prefixes_s):
    """Feature vectors of one run (directory with run.json and packet_capture.pcap) for each prefix in seconds."""
    import json
    meta = json.loads((Path(run_dir) / "run.json").read_text())
    data = (Path(run_dir) / "packet_capture.pcap").read_bytes()
    t0 = meta["sample_started_wall_us"] / 1e6
    return {s: features(data, t0, s) for s in prefixes_s}


# ----------------------------------------------------------------------------------------------- self-test
def _frame(src, dst, proto, sport, dport, flags=0, payload=0):
    ip_src, ip_dst = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
    if proto == 6:
        l4 = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + b"\0" * payload
    else:
        l4 = struct.pack(">HHHH", sport, dport, 8 + payload, 0) + b"\0" * payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, ip_src, ip_dst)
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + l4


def _pcap(records):
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)]
    for t, frame in records:
        sec = int(t)
        out.append(struct.pack("<IIII", sec, round((t - sec) * 1e6), len(frame), len(frame)) + frame)
    return b"".join(out)


def self_test():
    t0, G, R = 1000.0, GUEST, "192.0.2.1"
    rec = [(t0 - 1, _frame(G, R, 6, 40000, 443, 0x02))]                     # before the window: ignored
    for n, start in enumerate((1.0, 11.0, 21.0)):
        p = 40001 + n
        rec += [(t0 + start, _frame(G, R, 6, p, 443, 0x02)),
                (t0 + start + .01, _frame(R, G, 6, 443, p, 0x12)),
                (t0 + start + .02, _frame(G, R, 6, p, 443, 0x10)),
                (t0 + start + .1, _frame(G, R, 6, p, 443, 0x18, 100))]
        if n < 2:
            rec += [(t0 + start + .2, _frame(R, G, 6, 443, p, 0x18, 50)),
                    (t0 + start + .5, _frame(G, R, 6, p, 443, 0x11))]
    rec += [(t0 + .2, _frame(G, "10.0.0.1", 17, 5000, 53, payload=30)),
            (t0 + .5, _frame(G, "198.51.100.5", 17, 5001, 5553, payload=148)),
            (t0 + 5.5, _frame(G, "198.51.100.5", 17, 5001, 5553, payload=148)),
            (t0 + 40, _frame(G, R, 6, 40009, 443, 0x02))]                    # after T=30: ignored
    rec.sort()
    data = _pcap(rec)
    v = dict(zip(NAMES, features(data, t0, 30)))
    want = {"tcp_conns": 3, "tcp_dests": 1, "tcp_top_dest_share": 1, "tcp_gap_median": 10, "tcp_gap_cv": 0,
            "tcp_gap_min": 10, "tcp_gap_max": 10, "conn_out_median": 100, "conn_in_median": 50, "conn_out_cv": 0,
            "conn_zero_out_share": 0, "conn_zero_in_share": 1 / 3, "conn_dur_median": .5, "conn_dur_max": .5,
            "conn_open_share": 1 / 3, "out_p1": 100, "out_p2": 0, "out_p3": 0, "in_p1": 50, "in_p2": 0, "in_p3": 0,
            "out_triple_repeat": 1, "udp_dgrams": 2, "udp_dests": 1, "udp_size_median": 148, "udp_size_cv": 0,
            "udp_gap_median": 5, "udp_gap_cv": 0, "dns_packets": 1, "first_contact_delay": .5}
    bad = {k: (v[k], w) for k, w in want.items() if abs(v[k] - w) > 1e-6}
    short = dict(zip(NAMES, features(data, t0, 10)))
    if short["tcp_conns"] != 1 or short["tcp_gap_median"] != 0 or short["udp_dgrams"] != 2:
        bad["T=10"] = (short["tcp_conns"], short["tcp_gap_median"], short["udp_dgrams"])
    empty = dict(zip(NAMES, features(_pcap([]), t0, 20)))
    if empty["first_contact_delay"] != 20 or any(empty[n] for n in NAMES if n != "first_contact_delay"):
        bad["empty"] = empty
    assert len(NAMES) == 30 and len(NO_FIRST_CONTACT) == 29
    print("self-test", "passed" if not bad else "FAILED %s" % bad)
    return not bad


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(0 if self_test() else 1)
    print(__doc__)
