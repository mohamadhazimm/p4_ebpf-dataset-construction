"""Sliver testbed: the within-run results recomputed without our server's stray WireGuard packets (offline).

After the first WireGuard session (position 16) our Sliver server kept sending WireGuard handshake initiations
(UDP from 10.0.0.1:51820, about one per 5 s) to the guest during later runs. They are not traffic of those runs'
programs, but the switch counts them as a UDP flow (found by committee-eval-20261113/encryption/sliver_transports.py).
This reruns the frozen analyses on the same attempt with every run's switch features (release switch model loop,
sliver_transports.switch_windows) and connection features (conn_features.features, unchanged) computed without
UDP packets to or from port 51820 on a guest port the run's own program did not use (the WireGuard implants keep
their own traffic):
  - analyze_sinkhole_c2.detection (frozen): all 24 classifier runs, and the 22 that sent traffic
  - analyze_sliver.command_phase, transports, published, server_down_vs_up (frozen)
  - the around-tasking measure of command_phase.py (same computation, copied below)
Each is first run as collected and must reproduce the saved analysis/results.json, sliver_results.json and
command_phase_around.json exactly. Outputs: analysis/*_without_stray_wireguard.json (the saved files stay).

    nice -n 19 /usr/bin/python3 recompute_without_stray_wg.py
"""
import json
import struct
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
ATTEMPT = HERE / "20261113T175035504465Z"
OUTD = ATTEMPT / "analysis"
sys.path.insert(0, str(HERE))
import analyze_sliver as S  # noqa: E402  frozen; brings A (frozen sinkhole analysis) and C (committee loader)
A, C = S.A, S.C
cf = A.cf
sys.path.insert(0, str(PROJ / "committee-eval-20261113" / "encryption"))
import sliver_transports as T  # noqa: E402  switch_windows: the release switch model loop with a packet filter

SM = T.SM
SINK, GUEST, WG_PORT = "10.0.0.1", "10.0.0.10", 51820


def run_dir(case):
    found = sorted((ATTEMPT / "runs" / case["sample"] / "output").glob("run_*/run.json"))
    assert len(found) == 1, case["sample"]
    return found[0].parent


def records(data):
    """(record bytes, frame) of a little-endian microsecond classic pcap."""
    assert data[:4] == b"\xd4\xc3\xb2\xa1", data[:4]
    off = 24
    while off < len(data):
        incl = struct.unpack("<IIII", data[off:off + 16])[2]
        yield data[off:off + 16 + incl], data[off + 16:off + 16 + incl]
        off += 16 + incl


def own_wg_ports(data):
    """Guest ports the run's own program used to send to the Sink's WireGuard port."""
    own = set()
    for _, frame in records(data):
        p = SM.parse_flow_packet(frame)
        if p and p[2] == 17 and p[0] == GUEST and p[1] == SINK and p[3][1] == WG_PORT:
            own.add(p[3][0])
    return own


def make_drop(own):
    def drop(p):
        src, dst, proto, ports, _flags = p
        if proto != 17 or WG_PORT not in ports or SINK not in (src, dst):
            return False
        guest_port = ports[1] if src == SINK else ports[0]
        return guest_port not in own
    return drop


def filtered(data, drop):
    out, n = [data[:24]], 0
    for rec, frame in records(data):
        p = SM.parse_flow_packet(frame)
        if p is not None and drop(p):
            n += 1
        else:
            out.append(rec)
    return b"".join(out), n


def clean_rows(rows, net):
    cleaned, drops = [], {}
    for r in rows:
        name = r["case"]["sample"].removesuffix(".zip")
        d = run_dir(r["case"])
        data = (d / "packet_capture.pcap").read_bytes()
        start = int(r["meta"]["sample_started_wall_us"])
        own = own_wg_ports(data)
        drop = make_drop(own)
        full, _ = T.switch_windows(str(d / "packet_capture.pcap"), start, 600, net)
        assert np.abs(full - r["N"]).max() <= 1e-9 * max(1.0, np.abs(r["N"]).max()), name
        N_clean, n_win = T.switch_windows(str(d / "packet_capture.pcap"), start, 600, net, drop=drop)
        data_clean, n_all = filtered(data, drop)
        r2 = dict(r)
        if n_all:
            r2["N"] = N_clean
            conn = {s: cf.features(data_clean, start / 1e6, s) for s in [k / 2 for k, _ in A.PREFIXES]}
            r2["C"] = {k: np.array(conn[k / 2]) for k, _ in A.PREFIXES}
        drops[name] = {"position": r["case"]["position"], "label": r["label"], "own_wireguard_ports": sorted(own),
                       "dropped_in_feature_windows": n_win, "dropped_whole_capture": n_all,
                       "dropped_first_20s": T.switch_windows(str(d / "packet_capture.pcap"), start, 40, net,
                                                             drop=drop)[1]}
        cleaned.append(r2)
    return cleaned, drops


def around(rows, host, net):
    """command_phase.py's computation, unchanged except that it returns instead of writing."""
    from command_phase import BEFORE, AFTER, SKIP_S
    log = [json.loads(line) for line in open(ATTEMPT / "autotask.jsonl") if line.strip()]
    hi, ni = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    per, pooled = {}, {"host_around": [], "host_other": [], "net_around": [], "net_other": []}
    for r in rows:
        if r["label"] != "malware":
            continue
        name = r["case"]["sample"].removesuffix(".zip")
        t0, t1 = r["start"].timestamp(), r["end"].timestamp()
        ev = [e for e in log if e.get("name") == name and t0 <= e.get("t", 0) < t1]
        win = set()
        for e in ev:
            lo = max(0, int((e["t"] - BEFORE - t0) / 0.5))
            hi_w = min(600, int((e["t"] + AFTER - t0) / 0.5) + 1)
            win.update(range(lo, hi_w))
        keep = set(range(int(SKIP_S / 0.5), 600))
        other = sorted(keep - win)
        a = sorted(win & keep)
        H, N = r["H"][:, hi], r["N"][:, ni]
        per[name] = {"kind": r["case"]["family"], "taskings": len(ev),
                     "windows_around": len(a), "windows_other": len(other),
                     "host_calls_per_window_around": round(float(H[a].mean()), 1) if a else None,
                     "host_calls_per_window_other": round(float(H[other].mean()), 1) if other else None,
                     "packets_per_window_around": round(float(N[a].mean()), 2) if a else None,
                     "packets_per_window_other": round(float(N[other].mean()), 2) if other else None}
        if a and other:
            pooled["host_around"].extend(H[a]); pooled["host_other"].extend(H[other])
            pooled["net_around"].extend(N[a]); pooled["net_other"].extend(N[other])
    return {"attempt": str(ATTEMPT), "window_s": [-BEFORE, AFTER], "startup_left_out_s": SKIP_S, "per_implant": per,
            "pooled_mean_per_window": {k: round(float(np.mean(v)), 2) for k, v in pooled.items() if v}}


def same(a, b, path=""):
    """Exact structural equality of two JSON-like values (after a JSON round trip)."""
    a, b = json.loads(json.dumps(a, default=str)), json.loads(json.dumps(b, default=str))
    return a == b


def sliver_sections(rows, host, net):
    return {"command_phase": S.command_phase(ATTEMPT, rows, host, net), "transports": S.transports(rows, host, net),
            "published_detectors": S.published(rows, host, net),
            "server_down_vs_up": S.server_down_vs_up(rows, host, net)}


def main():
    host, net = A.tc.signals()
    _, rows = A.load_runs(ATTEMPT, host, net)
    saved = json.load(open(OUTD / "results.json"))
    saved_s = json.load(open(OUTD / "sliver_results.json"))
    saved_c = json.load(open(OUTD / "command_phase_around.json"))
    wire_names = {t["sample"] for t in saved["per_run"] if t["label"] == "benign" or
                  (t["label"] == "malware" and (t["p4_packets_5min"] > 0 or t["catchall_tcp"] or t["catchall_udp"]))}

    def subsets(rs):
        scored = [r for r in rs if r["label"] in ("malware", "benign")]
        wire = [r for r in scored if r["case"]["sample"] in wire_names or
                r["case"]["sample"].removesuffix(".zip") in wire_names]
        return scored, wire

    # as collected: must reproduce the saved files
    scored, wire = subsets(rows)
    assert len(scored) == saved["detection_all"]["n"] and len(wire) == saved["detection_wire_malware_only"]["n"]
    det = {"detection_all": A.detection(scored, host, net), "detection_wire_malware_only": A.detection(wire, host, net)}
    for k in det:
        assert same(det[k], saved[k]), k
    sec = sliver_sections(rows, host, net)
    for k in sec:
        assert same(sec[k], saved_s[k]), k
    assert same(around(rows, host, net), saved_c)
    print("as collected: reproduced results.json, sliver_results.json, command_phase_around.json", flush=True)

    # without the stray WireGuard packets
    clean, drops = clean_rows(rows, net)
    scored, wire = subsets(clean)
    det = {"detection_all": A.detection(scored, host, net), "detection_wire_malware_only": A.detection(wire, host, net)}
    res = {"attempt": str(ATTEMPT), "rule": "UDP packets to or from 10.0.0.1:51820 on a guest port the run's own "
                                            "program did not send WireGuard from are dropped",
           "dropped_packets": drops, "reproduced_as_collected": True, **det}
    C.write_json(OUTD / "results_without_stray_wireguard.json", res)
    C.write_json(OUTD / "sliver_results_without_stray_wireguard.json", sliver_sections(clean, host, net))
    C.write_json(OUTD / "command_phase_around_without_stray_wireguard.json", around(clean, host, net))
    for name, v in drops.items():
        if v["dropped_whole_capture"]:
            print("dropped", name, v)
    for key, d in det.items():
        print(key, {n: (round(d["scores"][n]["ba"]["mean"], 3), round(saved[key]["scores"][n]["ba"]["mean"], 3))
                    for n in ("20s|host", "20s|network", "20s|hybrid", "20s|stacked-hybrid", "5min|network")})
    print("saved *_without_stray_wireguard.json in", OUTD)


if __name__ == "__main__":
    main()
