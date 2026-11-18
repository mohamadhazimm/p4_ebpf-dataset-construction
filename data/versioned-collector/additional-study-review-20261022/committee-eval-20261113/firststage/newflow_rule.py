"""Committee item 5 (optional): a first stage in the switch's data plane. Offline.

Could a rule the switch evaluates per packet stop the floods sooner than the learned detectors, which decide only
after a 0.5-s window and a register read (median containment 0.86 s, mitigation/README.md)? The rule counts new
flows (first frames of TCP/UDP 5-tuples, which the switch already reports to its CPU) per source IP or per
destination IP in tumbling bins of 1, 10 or 100 ms, raises an alarm when a bin's count exceeds k, and then drops
the host's traffic, at once (rule in the data plane) or 10 ms later (drop entry installed by the control plane).
k0 is the largest count of any benign row, so these thresholds are set on the same data; the margins (2, 5 and
10 times k0) show how much room there is. Protocol written first: results/firststage_protocol.json. After the
first run (kept as results/firststage_v1_newflow_only.json) showed that a UDP flood to one server is one flow, the
addendum results/firststage_protocol_addendum.json added two packet-rate rules (packets per flow, packets per host,
counted as wire-size packets) and the combination "new flows per source or packets per flow".

    nice -n 19 /usr/bin/python3 firststage/newflow_rule.py
"""
import importlib.util
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
EVAL = HERE.parent
sys.path.insert(0, str(EVAL))
import common as C  # noqa: E402

OUT = EVAL / "results" / "firststage.json"
PROTOCOL = EVAL / "results" / "firststage_protocol.json"
MITIGATION = EVAL / "mitigation" / "results.json"
GUEST_MAC = bytes.fromhex("001b210aee09")
BINS_MS = (1, 10, 100)
MULTS = (1, 2, 5, 10)
LAT_US = (0, 10_000)
SPAN_US = 20_000_000


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


sm = _load("switch_model", C.RELEASE / "features" / "switch_model.py")
seg = _load("resegment", EVAL / "offload" / "resegment.py")  # segments(): wire-size TCP segments of offload frames
SCOPES = ("src", "dst", "flow", "host")


def scan(out_dir):
    """Offsets (us) of the guest's IPv4 frames (captured), of its wire packets (offload frames split), of the new
    flows it opened (by source and by destination IP) and of its wire packets per TCP/UDP flow."""
    out_dir = Path(out_dir)
    start = int(json.load(open(out_dir / "run.json"))["sample_started_wall_us"])
    frames, wire, seen, by_src, by_dst, by_flow = [], [], set(), {}, {}, {}
    for time_us, _ts, frame in sm.read_pcap(str(out_dir / "packet_capture.pcap")):
        off = time_us - start
        if off < 0 or off >= SPAN_US or frame[6:12] != GUEST_MAC or frame[12:14] != b"\x08\x00":
            continue
        n = len(seg.segments(frame)) if len(frame) > 1514 else 1
        frames.append(off)
        wire.extend([off] * n)
        p = sm.parse_flow_packet(frame)
        if p is None:
            continue
        src, dst, proto, ports, _flags = p
        a, b = (src, ports[0]), (dst, ports[1])
        key = (proto,) + ((a, b) if a <= b else (b, a))
        by_flow.setdefault(key, []).extend([off] * n)
        if key in seen:
            continue
        seen.add(key)
        by_src.setdefault(src, []).append(off)
        by_dst.setdefault(dst, []).append(off)
    arr = lambda d: {k: np.asarray(v, dtype=np.int64) for k, v in d.items()}  # noqa: E731
    return {"frames": np.asarray(frames, dtype=np.int64), "src": arr(by_src), "dst": arr(by_dst),
            "flow": arr(by_flow), "host": {"host": np.asarray(wire, dtype=np.int64)}}


def max_per_bin(groups, bin_us):
    best = 0
    for offs in groups.values():
        if len(offs):
            best = max(best, int(np.unique(offs // bin_us, return_counts=True)[1].max()))
    return best


def first_crossing(groups, bin_us, k):
    """Earliest offset at which one group's count in a bin exceeds k (the (k+1)-th new flow of that bin), else None."""
    best = None
    for offs in groups.values():
        if len(offs) <= k:
            continue
        b = offs // bin_us
        starts = np.flatnonzero(np.r_[True, b[1:] != b[:-1]])
        counts = np.diff(np.r_[starts, len(b)])
        hit = np.flatnonzero(counts > k)
        if len(hit):
            t = int(offs[starts[hit[0]] + k])
            best = t if best is None else min(best, t)
    return best


def summarize_run(sc):
    res = {"guest_frames": int(len(sc["frames"])),
           "new_flows": int(sum(len(v) for v in sc["src"].values())),
           "max_per_bin": {scope: {str(w): max_per_bin(sc[scope], w * 1000) for w in BINS_MS} for scope in SCOPES}}
    return res


def _job(out_dir):
    sc = scan(out_dir)
    return sc, summarize_run(sc)


def main():
    proto = json.load(open(PROTOCOL))
    rows, _, _ = C.load()
    cats = np.asarray([r["category"] for r in rows])
    dirs = [str(C.output_dir(d)) for d in C.run_dirs(rows)]
    with Pool(12) as pool:
        res = pool.map(_job, dirs, chunksize=1)
    scans, summ = [r[0] for r in res], [r[1] for r in res]
    benign = np.flatnonzero(np.isin(cats, ("benign", "network_benign", "null")))
    attack = np.flatnonzero(cats == "network_attack")
    malware = np.flatnonzero(cats == "malware")
    mit = json.load(open(MITIGATION))["per_attack_run"]

    out = {"protocol_written_utc": proto["written_utc"], "bins_ms": BINS_MS, "multiples": MULTS,
           "latencies_us": LAT_US, "rules": {}}
    for scope in SCOPES + ("src+flow",):
        for w in BINS_MS:
            parts = scope.split("+")
            k0s = {q: max(summ[i]["max_per_bin"][q][str(w)] for i in benign) for q in parts}
            k0 = k0s[parts[0]] if len(parts) == 1 else k0s
            benign_max = {q: {c: max(summ[i]["max_per_bin"][q][str(w)] for i in np.flatnonzero(cats == c))
                              for c in ("benign", "network_benign", "null")} for q in parts}
            arg = {q: rows[max(benign, key=lambda i: summ[i]["max_per_bin"][q][str(w)])]["execution_id"] for q in parts}

            def cross(i, m):
                ts = [first_crossing(scans[i][q], w * 1000, max(1, k0s[q]) * m) for q in parts]
                ts = [t for t in ts if t is not None]
                return min(ts) if ts else None
            for m in MULTS:
                k = {q: max(1, k0s[q]) * m for q in parts}
                k = k[parts[0]] if len(parts) == 1 else k
                per_attack, per_type = {}, {}
                for i in attack:
                    name, t = rows[i]["execution_id"], rows[i]["attack_type"]
                    td = cross(i, m)
                    fr = scans[i]["frames"]
                    stop = {str(L): (float((fr >= td + L).mean()) if td is not None and len(fr) else 0.0) for L in LAT_US}
                    per_attack[name] = {"type": t, "max_per_bin": {q: summ[i]["max_per_bin"][q][str(w)] for q in parts},
                                        "detected": td is not None, "detect_s": None if td is None else td / 1e6,
                                        "stopped_share": stop,
                                        "stacked_hybrid_stopped_share": mit[name]["stacked"]["packets_stopped_share_mean"]}
                    per_type.setdefault(t, []).append(per_attack[name])
                types = {}
                for t, xs in per_type.items():
                    det = [x for x in xs if x["detected"]]
                    types[t] = {"runs": len(xs), "detected": len(det),
                                "detect_s_median": float(np.median([x["detect_s"] for x in det])) if det else None,
                                "stopped_share_mean": {str(L): float(np.mean([x["stopped_share"][str(L)] for x in xs]))
                                                       for L in LAT_US},
                                "stacked_hybrid_stopped_share_mean": float(np.mean([x["stacked_hybrid_stopped_share"]
                                                                                    for x in xs]))}
                all_frames = sum(len(scans[i]["frames"]) for i in attack)
                pooled = {str(L): float(sum(x["stopped_share"][str(L)] * len(scans[i]["frames"])
                                            for i, x in zip(attack, per_attack.values())) / all_frames)
                          for L in LAT_US}
                mal = []
                for i in malware:
                    td = cross(i, m)
                    if td is not None:
                        mal.append({"family": rows[i]["family"], "detect_s": td / 1e6})
                ben_alarm = [rows[i]["execution_id"] for i in benign if cross(i, m) is not None]
                out["rules"]["%s|%dms|%dx" % (scope, w, m)] = {
                    "k": k, "k0": k0, "k0_from": arg, "benign_max_by_category": benign_max, "benign_alarms": ben_alarm,
                    "attack_by_type": types, "attack_packets_stopped_pooled": pooled, "per_attack_run": per_attack,
                    "malware_tripping": {"runs": len(mal), "families": sorted({x["family"] for x in mal}),
                                         "detect_s_median": float(np.median([x["detect_s"] for x in mal])) if mal else None}}
    out["per_run_max_per_bin"] = {rows[i]["execution_id"]: {"category": rows[i]["category"], **summ[i]} for i in range(len(rows))}
    C.write_json(OUT, out)
    for key in ("src|10ms|1x", "src|10ms|10x", "flow|10ms|1x", "flow|10ms|10x", "host|10ms|1x", "src+flow|10ms|1x",
                "src+flow|10ms|5x", "src+flow|10ms|10x", "src+flow|100ms|1x", "src+flow|1ms|1x"):
        r = out["rules"][key]
        print(key, "k", r["k"], "from", r["k0_from"], "benign max", r["benign_max_by_category"], "benign alarms",
              r["benign_alarms"])
        for t, v in r["attack_by_type"].items():
            print("   %-10s %d/%d detected, median %.3f s, stopped %s (stacked hybrid %.2f)" % (
                t, v["detected"], v["runs"], v["detect_s_median"] or -1, {L: round(s, 2) for L, s in v["stopped_share_mean"].items()},
                v["stacked_hybrid_stopped_share_mean"]))
        print("   pooled attack packets stopped", {L: round(s, 3) for L, s in r["attack_packets_stopped_pooled"].items()},
              "malware tripping", r["malware_tripping"])
    print("wrote", OUT)


if __name__ == "__main__":
    main()
