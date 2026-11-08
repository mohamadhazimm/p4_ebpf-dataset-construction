"""Did the lab's emulated internet server (the Sink, 10.0.0.1) answer, run by run?

On 2026-11-07 the paper's network benign tasks (curl/wget/openssl/telnet to 10.0.0.1) exited with connection
errors where they had exited 0 on 2026-10-25, and their captures show every SYN to 10.0.0.1:80 answered by RST:
the Sink's TCP services were down while the host answered. This scans every run's packet capture: the reply of
10.0.0.1 to the guest's TCP SYNs (SYN-ACK = a service listened, RST = closed port; split into the collector's own
capture probes to port 80 and the sample's connections), and DNS (answers from 10.0.0.1:53, or ICMP
port-unreachable from 10.0.0.1). Per run: start time, batch, label; per batch: the timeline.
Offline; no VM.   Run: nice -n 19 /usr/bin/python3 sink_status.py
"""
import glob
import json
import struct
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

HERE = __file__.rsplit("/", 1)[0]
PROJ = HERE.rsplit("/", 1)[0]
OUT = HERE + "/sink_status.json"
SINK, GUEST = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 10])
ATTEMPTS = [
    ("paper-revision5", "revision5-collection/20261025T100025568989Z"),
    ("flood21-a", "flood21-collect/20261026T150016786262Z"),
    ("flood21-b", "flood21-collect/20261026T151240756153Z"),
    ("flood21-c", "flood21-collect/20261026T154421063760Z"),
    ("realtools", "realtools-collect/20261026T165642798242Z"),
    ("pilot-5min", "pilot-5min/20261105T212404537976Z"),
    ("scale-5min", "scale-5min/20261105T224558731619Z"),
    ("lowrate21", "lowrate21-collect/20261106T070056187569Z"),
    ("topup-5min", "topup-5min/20261106T073625330426Z"),
    ("topup-finish", "topup-5min-finish/20261106T155820346732Z"),
    ("benign-expanded", "benign-expanded-5min/20261106T204303086228Z"),
    ("wgetp", "wgetp-5min/20261107T015242522524Z"),
    ("benign-bursty", "benign-bursty-5min/20261107T071120390917Z"),
    ("benign-rest", "benign-rest-5min/20261107T080517413667Z"),
]


def scan(path):
    """Counts of the Sink's replies in one classic-PCAP capture (Ethernet, IPv4)."""
    c = Counter()
    pending = {}                    # (sport, dport) of a guest SYN to the Sink -> "probe" | "sample"
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return c
        end = "<" if struct.unpack("<I", head[:4])[0] in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        first_probe = None
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            incl = struct.unpack(end + "IIII", rec)[2]
            d = f.read(incl)
            if len(d) < incl or len(d) < 34 or d[12:14] != b"\x08\x00":
                continue
            ihl = (d[14] & 15) * 4
            proto, src, dst = d[23], d[26:30], d[30:34]
            l4 = 14 + ihl
            if proto == 6 and len(d) >= l4 + 14:
                sp, dp = struct.unpack("!HH", d[l4:l4 + 4])
                flags = d[l4 + 13]
                if src == GUEST and dst == SINK and flags & 0x12 == 0x02:
                    kind = "probe" if dp == 80 and first_probe is None else "sample"
                    if dp == 80 and first_probe is None:
                        first_probe = (sp, dp)
                    pending[(sp, dp)] = kind
                    c[kind + "_syn"] += 1
                elif src == SINK and dst == GUEST and (dp, sp) in pending:
                    kind = pending.pop((dp, sp))
                    if flags & 0x12 == 0x12:
                        c[kind + "_synack"] += 1
                        c["synack_port_%d" % sp] += 1
                    elif flags & 0x04:
                        c[kind + "_rst"] += 1
                        c["rst_port_%d" % sp] += 1
            elif proto == 17 and len(d) >= l4 + 4:
                sp, dp = struct.unpack("!HH", d[l4:l4 + 4])
                if src == GUEST and dst == SINK and dp == 53:
                    c["dns_query"] += 1
                elif src == SINK and dst == GUEST and sp == 53:
                    c["dns_answer"] += 1
            elif proto == 1 and src == SINK and dst == GUEST and len(d) > l4 and d[l4] == 3:
                c["icmp_unreachable"] += 1
    return c


def job(args):
    tag, att, rj = args
    d = json.load(open(rj))
    pcap = rj.rsplit("/", 1)[0] + "/packet_capture.pcap"
    try:
        counts = scan(pcap)
    except OSError:
        counts = Counter({"no_pcap": 1})
    return {"batch": tag, "sample": rj.split("/runs/")[1].split("/")[0],
            "started": d.get("sample_started_at_utc") or d.get("started_at_utc"), "counts": dict(counts)}


def label_of(att):
    meta = {}
    for p in (att + "/protocol.json", att + "/payload/cases.json"):
        try:
            obj = json.load(open(p))
        except (OSError, ValueError):
            continue
        cases = obj.get("cases", []) if isinstance(obj, dict) else obj
        for c in cases if isinstance(cases, list) else []:
            if isinstance(c, dict) and "sample" in c:
                meta[c["sample"]] = c.get("label", "")
    return meta


def main():
    jobs, labels = [], {}
    for tag, rel in ATTEMPTS:
        att = PROJ + "/" + rel
        labels[tag] = label_of(att)
        jobs += [(tag, att, rj) for rj in sorted(glob.glob(att + "/runs/*/output/run_*/run.json"))]
    with Pool(8) as pool:
        rows = pool.map(job, jobs)
    for r in rows:
        r["label"] = labels[r["batch"]].get(r["sample"], "?")
        k = r["counts"]
        r["probe"] = "synack" if k.get("probe_synack") else ("rst" if k.get("probe_rst") else "none")
    rows.sort(key=lambda r: r["started"] or "")
    per = {}
    print("%-16s %5s  %-21s %-21s  probe SYN-ACK/RST/none   sample SYN: SYN-ACK / RST   DNS q/a/unreach"
          % ("batch", "runs", "first start", "last start"))
    for tag, _ in ATTEMPTS:
        rs = [r for r in rows if r["batch"] == tag]
        if not rs:
            continue
        s = Counter()
        for r in rs:
            s.update(r["counts"])
        pr = Counter(r["probe"] for r in rs)
        per[tag] = {"runs": len(rs), "first": rs[0]["started"], "last": rs[-1]["started"], "probe": dict(pr),
                    "sample_syn": s["sample_syn"], "sample_synack": s["sample_synack"], "sample_rst": s["sample_rst"],
                    "dns_query": s["dns_query"], "dns_answer": s["dns_answer"], "icmp_unreachable": s["icmp_unreachable"],
                    "labels": dict(Counter(r["label"] for r in rs))}
        print("%-16s %5d  %-21s %-21s  %4d / %4d / %4d         %6d: %6d / %6d        %d/%d/%d"
              % (tag, len(rs), (rs[0]["started"] or "")[:19], (rs[-1]["started"] or "")[:19], pr["synack"], pr["rst"],
                 pr["none"], s["sample_syn"], s["sample_synack"], s["sample_rst"], s["dns_query"], s["dns_answer"],
                 s["icmp_unreachable"]))
    up = [r for r in rows if r["probe"] == "synack"]
    down = [r for r in rows if r["probe"] == "rst"]
    last_up = up[-1] if up else None
    first_down = down[0] if down else None
    print("\nlast run whose probe got a SYN-ACK: %s %s %s" % ((last_up or {}).get("started"), (last_up or {}).get("batch"),
                                                             (last_up or {}).get("sample")))
    print("first run whose probe got a RST:     %s %s %s" % ((first_down or {}).get("started"),
                                                             (first_down or {}).get("batch"),
                                                             (first_down or {}).get("sample")))
    flips = [(a["started"], b["started"], a["batch"], b["batch"]) for a, b in zip(rows, rows[1:])
             if a["probe"] != b["probe"] and "none" not in (a["probe"], b["probe"])]
    print("probe state changes between consecutive runs: %d %s" % (len(flips), flips[:6]))
    json.dump({"per_batch": per, "last_up": last_up, "first_down": first_down, "flips": flips, "rows": rows},
              open(OUT, "w"), indent=1)
    print("saved", OUT)


if __name__ == "__main__":
    main()
