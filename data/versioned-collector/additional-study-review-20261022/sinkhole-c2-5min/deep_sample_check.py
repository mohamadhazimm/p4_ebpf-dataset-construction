"""Deep check of the sinkhole C2 runs finished so far: is each run technically sound, what does each sample do
on the host and on the wire, and is the data useful for studying C2. Offline, read-only on the runs.

Per run: collector checks (quality, exec, loss, PCAP counters), exit code, first lines of the program's output,
host activity (system calls, threads, child programs, file writes), and every TCP connection and UDP datagram
the guest sent: destination, timing, bytes each way, what the guest sent first (TLS ClientHello with SNI, HTTP
request line and Host, SSH banner, or an unknown protocol with its first bytes and entropy) and what came back
(INetSim's TLS or HTTP, or nothing). DNS names come from the queries. Payload is read here only to describe the
samples; the detection features stay payload-free.

Run: nice -n 19 /usr/bin/python3 deep_sample_check.py ATTEMPT_DIR
Writes ATTEMPT_DIR/analysis/sample-check-<UTC>.json (never overwrites).
"""
import csv
import hashlib
import json
import math
import statistics
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

GUEST = "10.0.0.10"
METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ")
HOST_SUMS = ("ebpf_fork_count", "ebpf_execve_count", "ebpf_connect_count", "ebpf_openat_count",
             "ebpf_unlinkat_count", "ebpf_renameat_count", "ebpf_renameat2_count", "ebpf_file_write_bytes")


def ip(b):
    return "%d.%d.%d.%d" % tuple(b)


def printable(raw, n=110):
    text = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in raw.decode("utf-8", "replace"))
    return text.strip()[:n]


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    return -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())


def sni(p):
    """Server name from a TLS ClientHello in one segment; None if absent or not parseable."""
    try:
        if len(p) < 44 or p[0] != 0x16 or p[5] != 0x01:
            return None
        pos = 43
        pos += 1 + p[pos]                                   # session id
        pos += 2 + struct.unpack(">H", p[pos:pos + 2])[0]   # cipher suites
        pos += 1 + p[pos]                                   # compression methods
        end = pos + 2 + struct.unpack(">H", p[pos:pos + 2])[0]
        pos += 2
        while pos + 4 <= min(end, len(p)):
            typ, ln = struct.unpack(">HH", p[pos:pos + 4])
            if typ == 0 and ln >= 5:
                nl = struct.unpack(">H", p[pos + 7:pos + 9])[0]
                return p[pos + 9:pos + 9 + nl].decode("ascii", "replace")
            pos += 4 + ln
    except (IndexError, struct.error):
        return None
    return None


def describe_out(p):
    if not p:
        return {"kind": "none"}
    if p[0] == 0x16 and len(p) > 5 and p[1] == 0x03:
        return {"kind": "TLS ClientHello" if p[5] == 1 else "TLS handshake", "sni": sni(p), "len": len(p)}
    if p.startswith(METHODS):
        lines = p.split(b"\r\n")
        host = next((printable(x[5:], 60) for x in lines[1:] if x.lower().startswith(b"host:")), None)
        return {"kind": "HTTP request", "line": printable(lines[0], 90), "host": host, "len": len(p)}
    if p.startswith(b"SSH-"):
        return {"kind": "SSH banner", "line": printable(p.split(b"\r\n")[0], 60)}
    return {"kind": "unknown protocol", "first_bytes": p[:4].hex(), "entropy": round(entropy(p[:256]), 2),
            "len": len(p)}


def describe_in(p):
    if not p:
        return "nothing"
    if p[0] in (0x14, 0x15, 0x16, 0x17) and len(p) > 2 and p[1] == 0x03:
        return {0x16: "TLS handshake", 0x15: "TLS alert", 0x17: "TLS data", 0x14: "TLS change-cipher"}[p[0]]
    if p.startswith(b"HTTP/"):
        return printable(p.split(b"\r\n")[0], 40)
    return "binary " + p[:4].hex()


def qname(b, o):
    labels, jumped, end = [], False, o
    for _ in range(64):
        if o >= len(b):
            break
        n = b[o]
        if n == 0:
            if not jumped:
                end = o + 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = o + 2
            jumped = True
            o = ((n & 0x3F) << 8) | b[o + 1]
            continue
        labels.append(b[o + 1:o + 1 + n].decode("ascii", "replace"))
        o += 1 + n
    return ".".join(labels), end


QTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


def dns_message(pay):
    """(is_response, name, query type, [A answers])"""
    flags, qd, an = struct.unpack(">HHH", pay[2:8])
    name, o = qname(pay, 12)
    qtype = QTYPES.get(struct.unpack(">H", pay[o:o + 2])[0], "type%d" % struct.unpack(">H", pay[o:o + 2])[0])
    answers = []
    if flags & 0x8000:
        o += 4
        for _ in range(an):
            _, o = qname(pay, o)
            if o + 10 > len(pay):
                break
            typ, _, _, rdl = struct.unpack(">HHIH", pay[o:o + 10])
            o += 10
            if typ == 1 and rdl == 4:
                answers.append(ip(pay[o:o + 4]))
            o += rdl
    return bool(flags & 0x8000), name, qtype, answers


def capture(run, t0, seconds=300):
    data = (run / "packet_capture.pcap").read_bytes()
    e = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    off, conns, closed_keys, udp, dns_q, dns_a = 24, {}, [], [], Counter(), Counter()
    order = []
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        f = data[off:off + incl]
        off += incl
        rel = sec + frac / 1e6 - t0
        if not 0 <= rel < seconds or len(f) < 34 or f[12:14] != b"\x08\x00":
            continue
        ihl = (f[14] & 15) * 4
        total = struct.unpack(">H", f[16:18])[0]
        src, dst, proto, h = ip(f[26:30]), ip(f[30:34]), f[23], 14 + ihl
        if proto == 6 and len(f) >= h + 20:
            sp, dp = struct.unpack(">HH", f[h:h + 4])
            flags, doff = f[h + 13], (f[h + 12] >> 4) * 4
            pay = f[h + doff:14 + total]
            out = src == GUEST
            key = (sp, dst, dp) if out else (dp, src, sp)
            if out and flags & 0x12 == 0x02 and (key not in conns or conns[key]["closed"]):
                if key in conns:
                    closed_keys.append(conns.pop(key))
                conns[key] = {"dst": "%s:%d" % (key[1], key[2]), "start": rel, "end": rel, "closed": False,
                              "answered": False, "out": 0, "in": 0, "pkts": 0, "first_out": b"", "first_in": b""}
                order.append(key)
                continue
            c = conns.get(key)
            if c is None:
                continue
            c["end"], c["pkts"] = rel, c["pkts"] + 1
            if not out and flags & 0x12 == 0x12:
                c["answered"] = True
            if flags & 0x05:
                c["closed"] = True
            if pay:
                if out:
                    c["out"] += len(pay)
                    c["first_out"] = c["first_out"] or bytes(pay)
                else:
                    c["in"] += len(pay)
                    c["first_in"] = c["first_in"] or bytes(pay)
        elif proto == 17 and len(f) >= h + 8:
            sp, dp, ulen = struct.unpack(">HHH", f[h:h + 6])
            pay = f[h + 8:h + ulen]
            if (dp == 53 or sp == 53) and len(pay) >= 12:
                try:
                    is_resp, name, qtype, answers = dns_message(pay)
                except (IndexError, struct.error):
                    continue
                if is_resp:
                    for a in answers:
                        dns_a[(name, a)] += 1
                elif src == GUEST:
                    dns_q["%s %s" % (name, qtype)] += 1
            elif src == GUEST:
                udp.append((rel, "%s:%d" % (dst, dp), len(pay), bytes(pay[:1])))
    return closed_keys + [conns[k] for k in order if k in conns], udp, dns_q, dns_a


def gaps(times):
    t = sorted(times)
    return [round(b - a, 1) for a, b in zip(t, t[1:])]


def summarize_net(conns, udp, dns_q, dns_a):
    out = {"tcp_connections": len(conns), "answered": sum(c["answered"] for c in conns),
           "bytes_out": sum(c["out"] for c in conns), "bytes_in": sum(c["in"] for c in conns),
           "udp_datagrams": len(udp), "dns_names": sorted(dns_q), "dns_answers": sorted({a for _, a in dns_a})}
    if conns:
        dests = Counter(c["dst"] for c in conns)
        top = max(sorted(dests), key=lambda d: dests[d])
        g = gaps([c["start"] for c in conns if c["dst"] == top])
        firsts = [describe_out(c["first_out"]) for c in conns]
        kinds = Counter(x["kind"] for x in firsts)
        out.update({
            "destinations": dict(dests), "first_contact_s": round(min(c["start"] for c in conns), 1),
            "reconnect_gap_s": {"median": statistics.median(g), "min": min(g), "max": max(g)} if g else None,
            "connections_open_at_end": sum(1 for c in conns if not c["closed"]),
            "longest_connection_s": round(max(c["end"] - c["start"] for c in conns), 1),
            "first_sent": dict(kinds),
            "sni": sorted({x["sni"] for x in firsts if x.get("sni")}),
            "http": sorted({"%s | Host: %s" % (x["line"], x["host"]) for x in firsts if x["kind"] == "HTTP request"})[:4],
            "unknown_protocol": sorted({"%s.. %dB entropy %.2f" % (x["first_bytes"], x["len"], x["entropy"])
                                        for x in firsts if x["kind"] == "unknown protocol"})[:4],
            "server_replied": dict(Counter(describe_in(c["first_in"]) for c in conns)),
            "bytes_out_per_connection": sorted(Counter(c["out"] for c in conns).most_common(3))})
    if udp:
        ud = Counter(d for _, d, _, _ in udp)
        top = max(sorted(ud), key=lambda d: ud[d])
        g = gaps([t for t, d, _, _ in udp if d == top])
        out.update({"udp_destinations": dict(ud), "udp_sizes": dict(Counter(s for _, _, s, _ in udp).most_common(3)),
                    "udp_first_byte": dict(Counter(b.hex() for _, _, _, b in udp).most_common(2)),
                    "udp_gap_s": {"median": statistics.median(g), "min": min(g), "max": max(g)} if g else None,
                    "udp_first_contact_s": round(min(t for t, *_ in udp), 1)})
    return out


def category(n, host):
    if not n["tcp_connections"]:
        if n["udp_datagrams"]:
            return "UDP only, repeated" if n["udp_datagrams"] >= 3 else "UDP only, little"
        return "DNS only" if n["dns_names"] else "no network"
    reps = "repeated connections" if n["tcp_connections"] >= 2 else "one connection"
    if n["bytes_in"] > 0:
        return reps + ", server replied"
    if n["bytes_out"] == 0:
        return reps + ", sends nothing"
    return reps + ", server silent"


def main():
    attempt = Path(sys.argv[1]).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    records = []
    for case in protocol["cases"]:
        runs = sorted((attempt / "runs" / case["sample"] / "output").glob("run_*/run.json"))
        if len(runs) != 1:
            continue
        run = runs[0].parent
        m = json.loads(runs[0].read_text())
        tel = list(csv.DictReader(open(run / "telemetry.csv")))
        calls = [float(t["host_total_syscalls_total"]) for t in tel]
        active = [i for i, v in enumerate(calls) if v]
        execs = []
        for row in csv.DictReader(open(run / "exec_events.csv")):
            if row["event"] == "exec_success":
                fn = row["detail"].split("filename=", 1)[-1]
                if fn not in ("/bin/bash",) and not fn.startswith("/tmp/malware-lab/extracted/"):
                    execs.append(fn)
        te = m.get("target_exec") or {}
        pcs = m.get("packet_capture_statistics") or {}
        conns, udp, dns_q, dns_a = capture(run, m["sample_started_wall_us"] / 1e6)
        net = summarize_net(conns, udp, dns_q, dns_a)
        rec = {"position": case["position"], "label": case["label"], "mode": case["mode"],
               "group": case.get("family") or case.get("program") or "null", "variant": case.get("variant"),
               "sample": case["sample"],
               "checks": {"quality": m.get("collection_quality_status"), "reasons": m.get("collection_quality_reasons"),
                          "exec": te.get("status"), "windows": len(tel), "ebpf_lost": m.get("ebpf_lost_event_count"),
                          "overflow": m.get("ebpf_events_overflow"),
                          "pcap_received": pcs.get("packets_received_by_filter"),
                          "pcap_captured": pcs.get("packets_captured"), "pcap_dropped": pcs.get("dropped_by_kernel")},
               "rc": m.get("return_code"),
               "stdout": [printable(x.encode()) for x in (run / "sample.stdout.log").read_text(errors="replace").splitlines()[:2]],
               "stderr": [printable(x.encode()) for x in (run / "sample.stderr.log").read_text(errors="replace").splitlines()[:2]],
               "host": {"post_target_calls": te.get("post_target_lineage_raw_syscalls"),
                        "active_windows": len(active), "last_active_window": active[-1] if active else -1,
                        "max_threads": int(max(float(t["ebpf_unique_threads"]) for t in tel)),
                        **{k.replace("ebpf_", ""): int(sum(float(t[k]) for t in tel)) for k in HOST_SUMS},
                        "child_programs": sorted(Counter(execs).items())[:8]},
               "network": net}
        rec["category"] = category(net, rec["host"])
        records.append(rec)
    healthy = [r for r in records if r["checks"]["quality"] == "accepted" and r["checks"]["windows"] == 600 and
               (r["label"] == "null" or r["checks"]["exec"] == "observed") and not r["checks"]["ebpf_lost"] and
               not r["checks"]["overflow"] and r["checks"]["pcap_received"] == r["checks"]["pcap_captured"] and
               not r["checks"]["pcap_dropped"]]
    out = {"created_utc": datetime.now(timezone.utc).isoformat(), "attempt": str(attempt),
           "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
           "runs": len(records), "runs_technically_sound": len(healthy),
           "categories": {lab: dict(Counter(r["category"] for r in records if r["label"] == lab))
                          for lab in ("malware", "benign", "null")},
           "records": records}
    (attempt / "analysis").mkdir(exist_ok=True)
    path = attempt / "analysis" / ("sample-check-%s.json" % datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    with open(path, "x") as f:
        json.dump(out, f, indent=1, default=str)
    print(json.dumps({k: out[k] for k in ("runs", "runs_technically_sound", "categories")}, indent=1))
    print("saved", path)


if __name__ == "__main__":
    main()
