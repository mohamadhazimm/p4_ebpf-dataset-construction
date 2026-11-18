"""Frames above the MTU in the dataset's captures: what the switch would have seen, and does it matter? Offline.

The guest captured its traffic before the NIC's segmentation offload split it, so a large TCP send can appear as
one frame of up to 64 KB. On the wire (and at the switch) it is several MTU-size segments. Only three of the 240
runs hold such frames: the bulk uploads bulkup_200, bulkup_400 and bulkup_700 (network-benign rows of the
combined pool, Table V; Table IV's 204 rows are not affected).

1. Check: the release's switch_model.window_features on each original capture reproduces the row's 145 network
   columns.
2. Wire view: each IPv4/TCP frame longer than 1514 B is replaced by back-to-back segments of at most 1500 B of
   IPv4 (same timestamp, same flags, the payload split at the MSS the frame's own headers leave), and the window
   features are computed again.
3. Table V with those three rows' network columns replaced (protocol unchanged: ten fold assignments, the four
   detectors), against the published rows; and how often each detector flags the three uploads.

    /usr/bin/python3 offload/resegment.py
"""
import csv
import importlib.util
import json
import struct
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
OUT = HERE.parent / "results" / "offload_resegment.json"
IDS = ["bulkup_200", "bulkup_400", "bulkup_700"]
MTU = 1500


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


sm = load("switch_model", RELEASE / "features" / "switch_model.py")
summary = load("summary", RELEASE / "features" / "summary.py")


def segments(frame):
    """The wire segments of one frame: itself if it fits, else MTU-size TCP segments (lengths only matter here)."""
    if len(frame) <= 14 + MTU:
        return [frame]
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != 0x0800 or frame[23] != 6:
        return [frame]
    ihl = (frame[14] & 0x0F) * 4
    thl = (frame[14 + ihl + 12] >> 4) * 4
    head = 14 + ihl + thl
    payload = frame[head:]
    mss = MTU - ihl - thl
    out = []
    for k in range(0, len(payload), mss):
        chunk = payload[k:k + mss]
        ip = bytearray(frame[14:14 + ihl])
        ip[2:4] = struct.pack("!H", ihl + thl + len(chunk))
        out.append(frame[:14] + bytes(ip) + frame[14 + ihl:head] + chunk)
    return out


def window_features_wire(pcap_path, start_us, windows=40, window_seconds=0.5, ttl=3):
    """switch_model.window_features with every oversized TCP frame split into its wire segments."""
    window_us = int(round(window_seconds * 1_000_000))
    table = sm.FlowTable(window_seconds, ttl)
    result, current, split = [], 0, 0
    for time_us, timestamp, frame in sm.read_pcap(pcap_path):
        offset = time_us - start_us
        if offset < 0 or offset // window_us >= windows:
            continue
        window = offset // window_us
        while current < window:
            result.append(table.read_window(current))
            current += 1
        parts = segments(frame)
        split += len(parts) > 1
        for seg in parts:
            packet = sm.parse_flow_packet(seg)
            if packet is not None:
                source, destination, protocol, ports, flags = packet
                table.update(window, timestamp, source, destination, protocol, ports, flags, len(seg))
    while current < windows:
        result.append(table.read_window(current))
        current += 1
    return result, split


def main():
    sys.path.insert(0, str(HERE.parent))
    import common as C  # noqa: E402  the committee loader (imported here: other scripts reuse this module's functions)
    rows, hc, nc = C.load()
    dirs = C.run_dirs(rows)
    idx = [next(i for i, r in enumerate(rows) if r["execution_id"] == e) for e in IDS]
    Xh, Xn, y = C.matrix(rows, hc), C.matrix(rows, nc), C.labels(rows)
    Xn_wire = Xn.copy()
    per_run = {}
    for e, i in zip(IDS, idx):
        out = C.output_dir(dirs[i])
        meta = json.load(open(out / "run.json"))
        start = int(meta["sample_started_wall_us"])
        pcap = str(out / "packet_capture.pcap")
        orig = summary.summarize(sm.window_features(pcap, start), sm.FEATURES)
        got = np.asarray([orig[c] for c in nc])
        rel = float(np.max(np.abs(got - Xn[i]) / np.maximum(np.abs(Xn[i]), 1e-9)))
        assert rel < 1e-9, (e, rel)
        wire_w, split = window_features_wire(pcap, start)
        wire = summary.summarize(wire_w, sm.FEATURES)
        Xn_wire[i] = [wire[c] for c in nc]
        pk = nc.index("net_pkts_total_delta__sum")
        mx = nc.index("net_max_len_max__max")
        av = nc.index("net_avg_pkt_size_delta__mean")
        per_run[e] = {"row": i, "reproduced_max_rel_diff": rel, "frames_split": split,
                      "packets_dataset": Xn[i][pk], "packets_wire": Xn_wire[i][pk],
                      "max_len_dataset": Xn[i][mx], "max_len_wire": Xn_wire[i][mx],
                      "avg_size_mean_dataset": Xn[i][av], "avg_size_mean_wire": Xn_wire[i][av]}
    groups = C.groups_published(rows)
    res = {}
    for name, XN in (("published", Xn), ("wire", Xn_wire)):
        P, _ = C.cv_all(Xh, XN, y, groups)
        res[name] = {d: {"ba_mean": float(np.mean([C.metrics(y, P[d][s])["balanced_accuracy"] for s in range(len(P[d]))])),
                         "ba_sd": float(np.std([C.metrics(y, P[d][s])["balanced_accuracy"] for s in range(len(P[d]))], ddof=1)),
                         "uploads_flagged_share": {e: float(np.mean(P[d][:, i] >= 0.5)) for e, i in zip(IDS, idx)}}
                     for d in C.DETECTORS}
    result = {"runs": per_run, "table_v": res,
              "note": "only these three of the 240 runs hold frames above 1514 B (checked over every capture with "
                      "traffic: the 77 cohort and 33 extra captures)"}
    C.write_json(OUT, result)
    print(json.dumps(per_run, indent=1))
    for name in res:
        print(name, {d: round(res[name][d]["ba_mean"], 3) for d in C.DETECTORS})
        print("   uploads flagged", {d: res[name][d]["uploads_flagged_share"] for d in C.DETECTORS})


if __name__ == "__main__":
    main()
