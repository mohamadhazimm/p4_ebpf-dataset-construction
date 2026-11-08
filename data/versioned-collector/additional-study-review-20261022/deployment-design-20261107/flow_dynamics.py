"""Flow dynamics of the 240-run pool, for sizing the switch readout: new flows per second, flow lifetimes, concurrent
active flows, and what each readout architecture would cost at the measured per-flow read price.

Reads every run's packet_capture.pcap with a minimal classic-pcap/Ethernet/IPv4 parser (no scapy): per run, the
unordered 5-tuple flows (TCP/UDP), their first and last packet time, new flows per 0.5-s window, and active flows per
window with the switch model's 3-window idle TTL. Runs are the 240 rows of the released dataset (paper-check pool).

Architectures costed with the measured constants (impl p4_perf.md section 6.2): 1.14 ms per flow with a register sync
and shadow reads (persistent session), 1.40 ms with per-cell reads; whole-table read 55-62 s; CPU reports 100%
delivered up to 50,000 new flows/s; 32-bit ns timestamps wrap at 4.295 s.
  A  periodic sweep: read every active bucket every D            cost/D = active x c
  B  bounded watch:  read every bucket whose flow started within the last T seconds, every D   cost/D = watched x c
  C  data-plane push: the switch emits one report per active flow per window (not implemented); cost = reports/s
Offline; no VM. Run: nice -n 19 /usr/bin/python3 flow_dynamics.py
"""
import glob
import json
import os
import struct
import sys
from collections import defaultdict
from multiprocessing import Pool

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
POOL = PROJ + "/paper-check-20261028/independent_pool.json"
ROOTS = [PROJ + "/revision5-collection/20261025T100025568989Z"] + sorted(glob.glob(PROJ + "/flood21-collect/*")) + \
        sorted(glob.glob(PROJ + "/realtools-collect/*"))
W = 0.5          # window, s
TTL = 3          # idle windows before a flow leaves the active set (switch model)
C_SYNC, C_CELL = 1.14e-3, 1.40e-3
OUT = HERE + "/flow_dynamics.json"


def find_pcap(sample):
    for name in (sample, sample + ".zip"):            # dataset rows name attack/benign runs without the .zip
        for root in ROOTS:
            hits = glob.glob("%s/runs/%s/output/run_*/packet_capture.pcap" % (root, name))
            if hits:
                return hits[0]
    return None


def parse(path):
    """-> dict of flow -> [first_ts, last_ts, packets]; only IPv4 TCP/UDP over Ethernet."""
    flows = {}
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return flows, 0
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            end, nano = "<", magic == 0xa1b23c4d
        elif magic in (0xd4c3b2a1, 0x4d3cb2a1):
            end, nano = ">", magic == 0x4d3cb2a1
        else:
            raise ValueError("not a classic pcap: " + path)
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        if linktype != 1:
            raise ValueError("linktype %d (expected Ethernet)" % linktype)
        n = 0
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts, tfrac, incl, _ = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            n += 1
            t = ts + tfrac / (1e9 if nano else 1e6)
            if incl < 34 or data[12:14] != b"\x08\x00":
                continue
            ihl = (data[14] & 0x0f) * 4
            proto = data[23]
            if proto not in (6, 17) or incl < 14 + ihl + 4:
                continue
            sip, dip = data[26:30], data[30:34]
            sp, dp = struct.unpack("!HH", data[14 + ihl:14 + ihl + 4])
            a, b = (sip, sp), (dip, dp)
            key = (proto,) + (a + b if a <= b else b + a)
            rec = flows.get(key)
            if rec is None:
                flows[key] = [t, t, 1]
            else:
                rec[1] = t; rec[2] += 1
    return flows, n


def analyse(args):
    sample, category = args
    path = find_pcap(sample)
    if path is None:
        return {"sample": sample, "category": category, "error": "pcap not found"}
    flows, npk = parse(path)
    if not flows:
        return {"sample": sample, "category": category, "packets": npk, "flows": 0}
    t0 = min(v[0] for v in flows.values())
    first = np.array([v[0] - t0 for v in flows.values()]); last = np.array([v[1] - t0 for v in flows.values()])
    pk = np.array([v[2] for v in flows.values()])
    life = last - first
    span = max(20.0, last.max())
    nwin = int(np.ceil(span / W)) + 1
    new = np.bincount((first / W).astype(int), minlength=nwin)
    fw, lw = (first / W).astype(int), (last / W).astype(int)
    active = np.zeros(nwin, int)
    for a, b in zip(fw, lw):
        active[a:min(nwin, b + TTL + 1)] += 1          # active while seen in the last TTL+1 windows
    # watched set for bounded watch, T seconds after the flow's first packet
    watched = {}
    for T in (5, 10, 20):
        wt = np.zeros(nwin, int)
        for a in fw:
            wt[a:min(nwin, a + int(T / W))] += 1
        watched["T%ds" % T] = int(wt.max())
    return {"sample": sample, "category": category, "packets": int(npk), "flows": int(len(flows)),
            "obs_s": float(span), "new_per_s_mean": float(len(flows) / span),
            "new_per_window_max": int(new.max()), "active_max": int(active.max()), "active_median": float(np.median(active)),
            "lifetime_s": {"p50": float(np.percentile(life, 50)), "p90": float(np.percentile(life, 90)), "max": float(life.max())},
            "share_single_packet": float((pk == 1).mean()), "share_life_lt_1s": float((life < 1).mean()),
            "share_life_lt_5s": float((life < 5).mean()), "watched_max": watched}


def q(vals, p):
    return float(np.percentile(vals, p)) if len(vals) else float("nan")


def main():
    rows = json.load(open(POOL))
    cat = {}
    for r in rows:
        cat[r["sample"]] = r["stratum"]
    jobs = [(s, c) for s, c in cat.items()]
    with Pool(8) as pool:
        res = pool.map(analyse, jobs)
    errors = [r for r in res if "error" in r]
    ok = [r for r in res if "error" not in r and r.get("flows", 0) > 0]
    print("runs %d | pcap parsed %d | no flows %d | errors %d" % (len(res), len(ok), len([r for r in res if r.get("flows") == 0]), len(errors)))
    for e in errors[:5]:
        print("  error:", e)
    summary = {}
    print("\n%-18s %4s %9s %9s %9s %9s %10s %10s %8s %8s %9s" % ("stratum", "n", "flows/s", "flows/s", "newmax/w", "active", "life p50", "life p90", "<1s", "1pkt", "watch20s"))
    print("%-18s %4s %9s %9s %9s %9s %10s %10s %8s %8s %9s" % ("", "", "median", "max", "max", "max", "median", "median", "share", "share", "max"))
    for s in sorted({r["category"] for r in ok}):
        g = [r for r in ok if r["category"] == s]
        d = {"n": len(g), "new_per_s": {"median": q([r["new_per_s_mean"] for r in g], 50), "p90": q([r["new_per_s_mean"] for r in g], 90),
                                        "max": max(r["new_per_s_mean"] for r in g)},
             "new_per_window_max": max(r["new_per_window_max"] for r in g),
             "active_max": {"median": q([r["active_max"] for r in g], 50), "p90": q([r["active_max"] for r in g], 90), "max": max(r["active_max"] for r in g)},
             "lifetime_p50_median": q([r["lifetime_s"]["p50"] for r in g], 50), "lifetime_p90_median": q([r["lifetime_s"]["p90"] for r in g], 50),
             "share_life_lt_1s_median": q([r["share_life_lt_1s"] for r in g], 50), "share_single_packet_median": q([r["share_single_packet"] for r in g], 50),
             "watched_max": {T: max(r["watched_max"][T] for r in g) for T in ("T5s", "T10s", "T20s")},
             "watched_median": {T: q([r["watched_max"][T] for r in g], 50) for T in ("T5s", "T10s", "T20s")}}
        summary[s] = d
        print("%-18s %4d %9.2f %9.1f %9d %9d %10.3f %10.3f %8.0f%% %8.0f%% %9d" % (
            s, d["n"], d["new_per_s"]["median"], d["new_per_s"]["max"], d["new_per_window_max"], d["active_max"]["max"],
            d["lifetime_p50_median"], d["lifetime_p90_median"], 100 * d["share_life_lt_1s_median"], 100 * d["share_single_packet_median"],
            d["watched_max"]["T20s"]))
    # architecture costs
    print("\nReadout cost at the measured 1.14 ms/flow (sync + shadow). duty = read time / window; >0.8 means the reader cannot keep up.")
    arch = {}
    for s in sorted({r["category"] for r in ok}):
        g = [r for r in ok if r["category"] == s]
        act_max = max(r["active_max"] for r in g); act_p90 = q([r["active_max"] for r in g], 90)
        watched20 = max(r["watched_max"]["T20s"] for r in g)
        new_s = max(r["new_per_s_mean"] for r in g)
        arch[s] = {}
        for D in (0.5, 1, 2):
            arch[s]["D%gs" % D] = {"A_sweep_duty_p90": act_p90 * C_SYNC / D, "A_sweep_duty_max": act_max * C_SYNC / D,
                                    "B_watch20_duty_max": watched20 * C_SYNC / D, "C_reports_per_s_max": act_max / D}
            print("  %-16s D=%3g s  A(sweep) duty p90 %6.3f max %7.3f | B(watch 20 s) duty max %7.3f | C(push) %8.0f reports/s (cap 50,000; new flows/s max %.0f)"
                  % (s, D, act_p90 * C_SYNC / D, act_max * C_SYNC / D, watched20 * C_SYNC / D, act_max / D, new_s))
    json.dump({"per_run": res, "summary": summary, "architecture_cost": arch,
               "constants": {"c_sync_s": C_SYNC, "c_cell_s": C_CELL, "ttl_windows": TTL, "window_s": W,
                             "report_capacity_per_s": 50000, "timestamp_wrap_s": 4.294967296, "full_table_read_s": "55-62"}},
              open(OUT, "w"), indent=1, default=float)
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()
