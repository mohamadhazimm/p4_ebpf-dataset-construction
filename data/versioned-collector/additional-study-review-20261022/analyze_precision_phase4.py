"""Offline precision analysis for Phase 4 (no VM, no model promotion, no dataset merge).

Reads a precision-phase4 run directory (campaign.json + per-sample .pcap) and computes, for every captured sample:
  HOST-ACTIVITY features (from the in-kernel bpftrace syscall counter):
     syscalls_total, syscalls_per_sec, distinct_syscalls, top_syscall_frac, send_family_frac
  NETWORK-VOLUME features (from true NIC counters): tx/rx packets+bytes, pps, bps
  NETWORK-SHAPE features (from the tcpdump PCAP, snaplen 96): syn_only_frac, handshake_completed,
     bidirectional, distinct_dst_ip, pkts_per_dst, frac_tiny(<=74B), mean/std frame length, udp_frac

Then it makes the PRECISION argument explicitly:
  * host-activity axis: malicious floods and benign bulk/high-rate BOTH sit high (a volume/shape threshold that
    catches the flood also flags benign bulk -> false positives);
  * network-shape axis: floods (SYN-only, no handshake, ~1 pkt/dst, many dsts) vs benign (handshake-completed,
    bidirectional, 1 dst, many pkts/dst) separate cleanly.
It also fits leave-one-out logistic classifiers (host-activity-only vs network-shape-only vs hybrid) over the
malicious-vs-benign samples as an illustrative separability check (small N -> descriptive, not a detector claim).

x86-64 syscall ids used for the send/recv family: write=1, read=0, sendto=44, recvfrom=45, sendmsg=46,
recvmsg=47, sendmmsg=307, recvmmsg=299, connect=42, socket=41, close=3.
"""
import argparse
import json
import math
import statistics
import sys
from pathlib import Path

SEND_FAMILY = {1, 44, 46, 307}          # write/sendto/sendmsg/sendmmsg
RECV_FAMILY = {0, 45, 47, 299}          # read/recvfrom/recvmsg/recvmmsg
CONN_FAMILY = {41, 42, 3}               # socket/connect/close
SINK = "10.0.0.1"
GUEST = "10.0.0.10"


def host_features(result):
    by = {int(k): int(v) for k, v in (result.get("syscalls_by_id") or {}).items()}
    total = int(result.get("syscalls_total") or 0)
    secs = float(result.get("active_seconds") or 0) or 1.0
    send = sum(by.get(i, 0) for i in SEND_FAMILY)
    recv = sum(by.get(i, 0) for i in RECV_FAMILY)
    conn = sum(by.get(i, 0) for i in CONN_FAMILY)
    top = max(by.values()) if by else 0
    # shannon entropy of the syscall-id distribution (host "shape" dispersion)
    ent = 0.0
    if total > 0:
        for v in by.values():
            p = v / total
            if p > 0:
                ent -= p * math.log2(p)
    return {"syscalls_total": total, "syscalls_per_sec": round(total / secs, 1),
            "distinct_syscalls": len(by), "top_syscall_frac": round(top / total, 4) if total else 0.0,
            "send_family_frac": round(send / total, 4) if total else 0.0,
            "recv_family_frac": round(recv / total, 4) if total else 0.0,
            "conn_family_frac": round(conn / total, 4) if total else 0.0,
            "syscall_id_entropy": round(ent, 3)}


def net_volume(result):
    d = result.get("nic_delta") or {}
    secs = float(result.get("active_seconds") or 0) or 1.0
    txp = d.get("tx_packets") or 0
    rxp = d.get("rx_packets") or 0
    txb = d.get("tx_bytes") or 0
    rxb = d.get("rx_bytes") or 0
    return {"tx_packets": txp, "rx_packets": rxp, "tx_bytes": txb, "rx_bytes": rxb,
            "tx_pps": round(txp / secs, 1), "total_pps": round((txp + rxp) / secs, 1),
            "total_bps": round(8 * (txb + rxb) / secs, 1)}


def net_shape(pcap_path, maxpkts=400000):
    from scapy.all import PcapReader, IP, TCP, UDP   # noqa
    n = syn = synack = ack_only = rst = fin = udp = tiny = frm_sink = 0
    lens = []
    dst_ips = set(); dst_ports = set(); src_ports = set()
    try:
        with PcapReader(str(pcap_path)) as pr:
            for p in pr:
                if n >= maxpkts:
                    break
                n += 1
                L = len(p)
                lens.append(L)
                if L <= 74:
                    tiny += 1
                if IP not in p:
                    continue
                ip = p[IP]
                if ip.src == SINK:
                    frm_sink += 1
                if ip.dst not in (SINK, GUEST):
                    dst_ips.add(ip.dst)
                elif ip.dst == SINK:
                    dst_ips.add(ip.dst)
                if TCP in p:
                    t = p[TCP]; fl = int(t.flags)
                    s = bool(fl & 0x02); a = bool(fl & 0x10)
                    if s and not a: syn += 1
                    elif s and a: synack += 1
                    elif a and not s: ack_only += 1
                    if fl & 0x04: rst += 1
                    if fl & 0x01: fin += 1
                    dst_ports.add(int(t.dport)); src_ports.add(int(t.sport))
                elif UDP in p:
                    udp += 1
                    dst_ports.add(int(p[UDP].dport)); src_ports.add(int(p[UDP].sport))
    except Exception as e:
        return {"pcap_error": str(e), "pkts": 0}
    tcp = syn + synack + ack_only
    return {"pkts": n, "syn": syn, "synack": synack, "ack_only": ack_only, "rst": rst, "fin": fin, "udp": udp,
            "frac_syn_only": round(syn / n, 4) if n else 0.0,
            "frac_tiny_le74": round(tiny / n, 4) if n else 0.0,
            "handshake_completed": bool(synack > 0 and ack_only > 0),
            "bidirectional": bool(frm_sink > 0),
            "frames_from_sink": frm_sink,
            "distinct_dst_ip": len(dst_ips), "distinct_dst_port": len(dst_ports), "distinct_src_port": len(src_ports),
            "pkts_per_dst_ip": round(n / len(dst_ips), 2) if dst_ips else float(n),
            "mean_len": round(statistics.mean(lens), 1) if lens else 0.0,
            "std_len": round(statistics.pstdev(lens), 1) if len(lens) > 1 else 0.0}


def loo_logreg(X, y, names):
    """Leave-one-out balanced accuracy with a standardized logistic regression. Returns (BA, per-sample correct)."""
    try:
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
    except Exception as e:
        return {"error": "sklearn unavailable: " + str(e)}
    X = np.asarray(X, float); y = np.asarray(y, int)
    preds = []
    for i in range(len(y)):
        tr = [j for j in range(len(y)) if j != i]
        if len(set(y[tr].tolist())) < 2:
            preds.append(None); continue
        sc = StandardScaler().fit(X[tr])
        clf = LogisticRegression(max_iter=2000, class_weight="balanced").fit(sc.transform(X[tr]), y[tr])
        preds.append(int(clf.predict(sc.transform(X[i:i+1]))[0]))
    # balanced accuracy over samples with a prediction
    tp = sum(1 for i in range(len(y)) if preds[i] == 1 and y[i] == 1)
    tn = sum(1 for i in range(len(y)) if preds[i] == 0 and y[i] == 0)
    fp = sum(1 for i in range(len(y)) if preds[i] == 1 and y[i] == 0)
    fn = sum(1 for i in range(len(y)) if preds[i] == 0 and y[i] == 1)
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    spec = tn / (tn + fp) if (tn + fp) else 0.0
    return {"balanced_accuracy": round((rec + spec) / 2, 4), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "recall": round(rec, 4), "specificity": round(spec, 4),
            "errors": [names[i] for i in range(len(y)) if preds[i] is not None and preds[i] != y[i]]}


def analyze(run_dir, extra_flood_pcaps=None):
    run_dir = Path(run_dir)
    campaign = json.load(open(run_dir / "campaign.json"))
    rows = []
    for rec in campaign["records"]:
        s = rec.get("sample", {}); res = rec.get("result")
        if not res:
            rows.append({"name": s.get("name"), "kind": s.get("kind"), "error": rec.get("error", "no result")})
            continue
        row = {"name": s.get("name"), "kind": s.get("kind"), "family": s.get("family", ""),
               "active_seconds": res.get("active_seconds")}
        row.update(host_features(res))
        row.update(net_volume(res))
        pcap = run_dir / (s.get("name") + ".pcap")
        row.update(net_shape(pcap) if pcap.is_file() else {"pcap": "missing"})
        rows.append(row)
    # enrich malicious network-shape with any extra captured flood pcaps (descriptive only)
    for pc in (extra_flood_pcaps or []):
        pc = Path(pc)
        if pc.is_file():
            r = {"name": "extra_flood:" + pc.parent.parent.name, "kind": "malware", "family": "Gafgyt/Kaiten"}
            r.update(net_shape(pc)); rows.append(r)

    mal = [r for r in rows if r.get("kind") in ("malware", "malware_c2") and "syscalls_total" in r]
    ben = [r for r in rows if r.get("kind") == "benign" and "syscalls_total" in r]
    null = [r for r in rows if r.get("kind") == "null" and "syscalls_total" in r]
    # split malicious into network-flood (real in-window flow) vs host-storm (host-loud, network-silent)
    FLOODN = 2000   # tx_packets threshold for "produced a real network flow" (null noise is < ~50)
    mal_flood = [r for r in mal if (r.get("tx_packets") or 0) > FLOODN]
    mal_storm = [r for r in mal if (r.get("tx_packets") or 0) <= FLOODN]

    def rng(items, key):
        vals = [r[key] for r in items if isinstance(r.get(key), (int, float))]
        return {"n": len(vals), "min": min(vals) if vals else None, "med": round(statistics.median(vals), 2) if vals else None,
                "max": max(vals) if vals else None}

    summary = {"n_rows": len(rows), "malicious": len(mal), "malicious_network_flood": len(mal_flood),
               "malicious_host_storm": len(mal_storm), "benign": len(ben), "null": len(null)}
    # HOST-ACTIVITY axis: show flood / host-storm / benign-bulk are all "high" (host cannot separate by volume/shape)
    summary["host_activity"] = {k: {"mal_flood": rng(mal_flood, k), "mal_host_storm": rng(mal_storm, k),
                                    "benign": rng(ben, k), "null": rng(null, k)}
                                for k in ("syscalls_total", "syscalls_per_sec", "send_family_frac",
                                          "top_syscall_frac", "syscall_id_entropy")}
    # NETWORK-SHAPE axis: flood vs benign-bulk separate cleanly
    summary["network_shape"] = {k: {"mal_flood": rng(mal_flood, k), "benign": rng(ben, k)}
                                for k in ("frac_syn_only", "pkts_per_dst_ip", "distinct_dst_ip",
                                          "frac_tiny_le74", "mean_len")}
    summary["network_shape_bool"] = {
        "mal_flood_handshake_completed": sum(1 for r in mal_flood if r.get("handshake_completed")),
        "benign_handshake_completed": sum(1 for r in ben if r.get("handshake_completed")),
        "mal_flood_bidirectional": sum(1 for r in mal_flood if r.get("bidirectional")),
        "benign_bidirectional": sum(1 for r in ben if r.get("bidirectional"))}

    # illustrative leave-one-out separability over malicious(1) vs benign(0) that have BOTH host + pcap
    labelled = [(r, 1) for r in mal if "pkts" in r and "syscalls_total" in r] + \
               [(r, 0) for r in ben if "pkts" in r and "syscalls_total" in r]
    if len(labelled) >= 4 and len({y for _, y in labelled}) == 2:
        names = [r["name"] for r, _ in labelled]
        y = [yy for _, yy in labelled]
        HOST = ["syscalls_per_sec", "send_family_frac", "top_syscall_frac", "distinct_syscalls", "syscall_id_entropy"]
        NET = ["frac_syn_only", "pkts_per_dst_ip", "distinct_dst_ip", "frac_tiny_le74", "mean_len", "std_len"]
        Xh = [[float(r.get(k, 0) or 0) for k in HOST] for r, _ in labelled]
        Xn = [[float(r.get(k, 0) or 0) for k in NET] for r, _ in labelled]
        Xhy = [hh + nn for hh, nn in zip(Xh, Xn)]
        summary["loo_separability"] = {"n": len(labelled), "pos_malware": sum(y), "neg_benign": len(y) - sum(y),
                                       "host_only": loo_logreg(Xh, y, names),
                                       "network_only": loo_logreg(Xn, y, names),
                                       "hybrid": loo_logreg(Xhy, y, names)}
    return rows, summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--extra-flood", nargs="*", default=[])
    ap.add_argument("--out")
    a = ap.parse_args()
    rows, summary = analyze(a.run_dir, a.extra_flood)
    out = Path(a.out) if a.out else Path(a.run_dir) / "precision_analysis.json"
    json.dump({"rows": rows, "summary": summary}, open(out, "w"), indent=2)
    print(json.dumps(summary, indent=2))
    print("\nwrote", out)


if __name__ == "__main__":
    main()
