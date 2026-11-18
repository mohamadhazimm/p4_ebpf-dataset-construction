#!/usr/bin/env python3
"""Post hoc check of a possible lab cue in the session lab: the passive sinkhole's catch-all listener accepts every
TCP connection that INetSim does not serve (any port but 53/80/443 of an outside address) and never sends data. So a
program that talks to such a port gets a completed handshake and then silence, which a real server would rarely do.
If only malware meets that silence, a network detector can learn "the server never spoke" instead of the malware's
traffic -- the same kind of artifact as the dataset's unanswered connections (AGENTS.md "Lab cue").

For every accepted program session of the given runs, the injected program's own flows (attributed exactly as in
analyze_session_lab.py: sockowner records, DNS relayed by the stub resolver given to the asking cgroup) are read from
the Sink capture over the first SPAN seconds after the injection, with each packet's IPv4/TCP/UDP payload length.
Per program: TCP flows whose server sent packets but no payload ("silent server"), TCP flows the server never answered,
and the same for UDP. The rule "flag the program if one of its TCP flows met a silent server" is scored on the same
populations as the detectors (all programs; the C2/backdoor implants against the benign), with no fitting.

Writes <out>/silent_server.json and <out>/silent_server_rows.csv. Read-only on the run folders; nothing is executed.

  /usr/bin/python3 silent_server_check.py --runs triage,tpilot --out <dir> [--span 20]
"""
import argparse
import csv
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

import analyze_session_lab as A
import build_base as BB

C2 = set(BB.C2_FAMILIES)
KINDS = ("malware", "benign", "null")


def frame_info(frame):
    """(src, dst, proto, sport, dport, tcp_flags, payload_len) of an Ethernet IPv4 TCP/UDP frame, else None."""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    if proto not in (6, 17) or len(ip) < ihl + 8:
        return None
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    l4 = ip[ihl:]
    sport, dport = struct.unpack("!HH", l4[:4])
    if proto == 6:
        if len(l4) < 20:
            return None
        doff = (l4[12] >> 4) * 4
        flags = l4[13]
        payload = max(0, total - ihl - doff)
    else:
        flags = 0
        payload = max(0, total - ihl - 8)
    return src, dst, proto, sport, dport, flags, payload


def owners(attempt, s):
    """flow key -> owner label, as analyze_session_lab.session_report assigns it."""
    sdir = Path(attempt) / "sessions" / s["sid"]
    g = sdir / "guest"
    cg = A.lab.load(g / "cgroups.json") if (g / "cgroups.json").is_file() else {}
    names = {v: k for k, v in cg.items()}
    socks, sflows, _ = A.sock_records(g / "sock.log")
    owner = defaultdict(set)
    for f in sflows:
        if f["cookie"] in socks or f["cgroup"] != 1:
            owner[f["key"]].add(names.get(f["cgroup"], "other:%d" % f["cgroup"]))
    for f in sflows:
        if f["key"] not in owner:
            owner[f["key"]].add(names.get(f["cgroup"], "other:%d" % f["cgroup"]))
    for key, who in A.relayed_dns(socks, sflows, names).items():
        owner[key] = {who}
    return {k: (sorted(v)[0] if len(v) == 1 else "several") for k, v in owner.items()}


def program_flows(attempt, protocol, s, span_s):
    sdir = Path(attempt) / "sessions" / s["sid"]
    g = sdir / "guest"
    if not (g / "clock-start.json").is_file() or not (sdir / "sink.pcap").is_file():
        return None
    start = A.lab.load(g / "clock-start.json")
    clocks = A.clock_map(sdir / "sink.pcap", s["sid"])
    if "start_offset_ns" not in clocks:
        return None
    inj_us = A.to_capture_us(clocks, start["t0_mono_ns"] + int(round(s["t_inject_s"] * 1e9)))
    end_us = inj_us + span_s * 1e6
    own = owners(attempt, s)
    flows = {}
    for time_us, _ts, frame in A.sm.read_pcap(str(sdir / "sink.pcap")):
        if not inj_us <= time_us < end_us:
            continue
        fi = frame_info(frame)
        if fi is None:
            continue
        src, dst, proto, sport, dport, flags, payload = fi
        if A.GUEST_IP not in (src, dst):
            continue
        key = A.flow_key(proto, src, sport, dst, dport)
        if own.get(key) != "app-b":
            continue
        out = src == A.GUEST_IP
        f = flows.setdefault(key, {"proto": proto, "rport": dport if out else sport,
                                   "pk_out": 0, "pk_in": 0, "pl_out": 0, "pl_in": 0})
        f["pk_out" if out else "pk_in"] += 1
        f["pl_out" if out else "pl_in"] += payload
    return list(flows.values())


def classify(flows):
    tcp = [f for f in flows if f["proto"] == 6]
    udp = [f for f in flows if f["proto"] == 17]
    return {"tcp": len(tcp),
            "tcp_silent_server": sum(1 for f in tcp if f["pk_in"] > 0 and f["pl_in"] == 0),
            "tcp_silent_server_client_sent": sum(1 for f in tcp if f["pk_in"] > 0 and f["pl_in"] == 0 and f["pl_out"] > 0),
            "tcp_unanswered": sum(1 for f in tcp if f["pk_in"] == 0),
            "tcp_server_spoke": sum(1 for f in tcp if f["pl_in"] > 0),
            "udp": len(udp), "udp_unanswered": sum(1 for f in udp if f["pk_in"] == 0),
            "silent_ports": sorted({f["rport"] for f in tcp if f["pk_in"] > 0 and f["pl_in"] == 0})[:8]}


def ba(y, flag):
    tp = sum(1 for a, b in zip(y, flag) if a and b)
    fn = sum(1 for a, b in zip(y, flag) if a and not b)
    tn = sum(1 for a, b in zip(y, flag) if not a and not b)
    fp = sum(1 for a, b in zip(y, flag) if not a and b)
    rec = tp / (tp + fn) if tp + fn else float("nan")
    spec = tn / (tn + fp) if tn + fp else float("nan")
    return {"balanced_accuracy": round((rec + spec) / 2, 3), "recall": round(rec, 3), "specificity": round(spec, 3),
            "tp": tp, "fn": fn, "tn": tn, "fp": fp}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--runs", default="triage,tpilot")
    p.add_argument("--out", required=True)
    p.add_argument("--span", type=float, default=20.0)
    p.add_argument("--kinds", default="malware,benign,null", help="session kinds to include (attack = malicious)")
    a = p.parse_args()
    global KINDS
    KINDS = tuple(a.kinds.split(","))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for run in [r for r in a.runs.split(",") if r]:
        attempt = BB.HERE / "runs" / BB.RUNS[run]
        protocol = A.lab.load(attempt / "protocol.json")
        for s in protocol["sessions"]:
            if s["kind"] not in KINDS:
                continue
            res = attempt / "sessions" / s["sid"] / "result.json"
            if not res.is_file() or A.lab.load(res).get("status") != "accepted":
                continue
            fl = program_flows(attempt, protocol, s, a.span)
            if fl is None:
                continue
            c = classify(fl)
            fam = s.get("family", "") if s["kind"] == "malware" else ""
            rows.append(dict(run=run, sid=s["sid"], kind=s["kind"], name=s["name"], family=fam,
                             label=int(s["kind"] in ("malware", "attack")), c2=int(fam in C2), **c))
    with (out / "silent_server_rows.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(dict(r, silent_ports=" ".join(map(str, r["silent_ports"]))))
    res = {"span_s": a.span, "runs": a.runs, "programs": len(rows),
           "by_kind": dict(Counter(r["kind"] for r in rows))}
    flag_silent = [int(r["tcp_silent_server"] > 0) for r in rows]
    flag_silent_sent = [int(r["tcp_silent_server_client_sent"] > 0) for r in rows]
    y = [r["label"] for r in rows]
    res["rule_silent_server_all_programs"] = ba(y, flag_silent)
    res["rule_silent_server_client_sent_all_programs"] = ba(y, flag_silent_sent)
    sub = [i for i, r in enumerate(rows) if r["label"] == 0 or r["c2"]]
    res["rule_silent_server_c2_vs_benign"] = ba([y[i] for i in sub], [flag_silent[i] for i in sub])
    res["rule_silent_server_client_sent_c2_vs_benign"] = ba([y[i] for i in sub], [flag_silent_sent[i] for i in sub])
    fam = defaultdict(list)
    for r, f in zip(rows, flag_silent):
        key = ("family::" + r["family"]) if r["label"] else ("benign::" + r["name"].split("-")[0])
        fam[key].append(f)
    res["share_with_silent_server_flow"] = {k: round(sum(v) / len(v), 3) for k, v in sorted(fam.items())}
    net_benign = [r for r in rows if r["label"] == 0 and (r["tcp"] or r["udp"])]
    res["network_active_benign"] = {"n": len(net_benign),
                                    "with_silent_server_flow": sum(1 for r in net_benign if r["tcp_silent_server"] > 0)}
    (out / "silent_server.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    sys.exit(main())
