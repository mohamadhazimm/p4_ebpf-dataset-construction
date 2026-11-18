"""Mitigation as an offline estimate (committee item 6). Offline, read-only on the data.

On a malicious verdict the switch drops (or rate-limits) the host's flows. The rule itself is measured later on the
hardware; this estimates from the recorded runs how soon a run would be contained and how much of its traffic a
drop rule would have stopped.

Detection: the streaming setup of REPORT 2.6, reproduced with the same code and protocol: per detector one model
trained on the training rows at the nine prefixes of compute_oof.STREAM_PREFIXES (0.5, 1, 2, 3, 5, 8, 10, 15, 20 s),
models from compute_oof._fit_stream_models / _predict_stream, Table V protocol (StratifiedGroupKFold(5, shuffle),
fold seeds 42, 0..8, published groups). The predictions at the nine prefixes must equal cache/stream.npz; then every
test row is scored after every 0.5-s window (prefixes 1..40). Per run and fold assignment: the first window w whose
probability is >= the threshold (0.5, 0.8, 0.9); never flagged within the 20 s = not contained.

Containment: T = (w + 1) * 0.5 s + R + L, R = 0.35 s (the collector's read budget, 70 % of a window),
L = 0.001, 0.01, 0.1 s (rule install, unmeasured). The rule is per host (it matches the host's address or switch
port), so every IPv4 frame the host sends at or after T is dropped; frames sent before T get through.

Traffic: from each run's packet_capture.pcap, the IPv4 frames sent by the guest's NIC (Ethernet source = the guest
MAC) with whole-microsecond offset in [0, 20 s) from sample_started_wall_us (the window anchor of the switch model);
packets and frame bytes before and after T. Benign runs: the same, as traffic that would be wrongly cut.

    /usr/bin/python3 mitigation/mitigation.py [--jobs 8]
"""
import argparse
import hashlib
import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/features")
import analyze_rigor as AR  # noqa: E402
import common as C  # noqa: E402
import compute_oof as CO  # noqa: E402
import switch_model as SM  # noqa: E402

GUEST_MAC = bytes.fromhex("001b210aee09")
GUEST_IP = bytes([10, 0, 0, 10])
WIN_US, OBS_US, NWIN = 500_000, 20_000_000, 40
R_S = 0.35
L_S = [0.001, 0.01, 0.1]
THRESHOLDS = [0.5, 0.8, 0.9]
PRIMARY = ("stacked", 0.5, 0.01)
ATTACK_TYPES = ("syn_flood", "udp_flood", "slowloris", "goldeneye")
NAMES = {"host": "Host-only", "network": "Network-only", "concat": "Hybrid (concatenated)",
         "stacked": "Hybrid (stacked)"}
D = {}


# ------------------------------------------------------------------------------------------ detection
def stream_job(seed):
    """compute_oof.stream_job's models, scored at every prefix 1..40 instead of the nine STREAM_PREFIXES."""
    y, g, H, N = D["y"], D["g"], D["H"], D["N"]
    feats = {k: (C.summarize(H, k), C.summarize(N, k)) for k in range(1, NWIN + 1)}
    out = {d: np.zeros((NWIN, len(y))) for d in C.DETECTORS}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(H[:, 0, :1], y, g):
        Xh_tr = np.vstack([feats[k][0][tr] for k in CO.STREAM_PREFIXES])
        Xn_tr = np.vstack([feats[k][1][tr] for k in CO.STREAM_PREFIXES])
        y_tr = np.concatenate([y[tr]] * len(CO.STREAM_PREFIXES))
        g_tr = np.concatenate([g[tr]] * len(CO.STREAM_PREFIXES))
        models = CO._fit_stream_models(Xh_tr, Xn_tr, y_tr, g_tr, np.arange(len(y_tr)))
        Xh_te = np.vstack([feats[k][0][te] for k in range(1, NWIN + 1)])
        Xn_te = np.vstack([feats[k][1][te] for k in range(1, NWIN + 1)])
        P = CO._predict_stream(models, Xh_te, Xn_te)
        for d in C.DETECTORS:
            out[d][:, te] = P[d].reshape(NWIN, len(te))
    return seed, out


def first_windows(P, thr):
    """P: (seeds, 40, rows) -> first flagged window per (seed, row), -1 if never."""
    flag = P >= thr
    return np.where(flag.any(1), flag.argmax(1), -1)


# -------------------------------------------------------------------------------------------- traffic
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pcap_job(i):
    """Outbound IPv4 frames of row i inside the observation: sorted offsets (us) and frame lengths."""
    out = C.output_dir(D["dirs"][i])
    pcap = out / "packet_capture.pcap"
    start = int(json.loads((out / "run.json").read_text())["sample_started_wall_us"])
    off, ln = [], []
    flow_packets = non_ip_out = spoofed = tcp_udp_out = 0
    guest_ip_macs = set()
    for time_us, ts, frame in SM.read_pcap(pcap):
        o = time_us - start
        if o < 0 or o >= OBS_US:
            continue
        if SM.parse_flow_packet(frame) is not None:
            flow_packets += 1
        ipv4 = len(frame) >= 34 and frame[12:14] == b"\x08\x00"
        if ipv4 and frame[26:30] == GUEST_IP:
            guest_ip_macs.add(frame[6:12].hex(":"))
        if frame[6:12] != GUEST_MAC:
            continue
        if not ipv4:
            non_ip_out += 1
            continue
        spoofed += frame[26:30] != GUEST_IP
        tcp_udp_out += frame[23] in (6, 17)
        off.append(o); ln.append(len(frame))
    off, ln = np.asarray(off, np.int64), np.asarray(ln, np.int64)
    srt = np.argsort(off, kind="stable")  # a few captures hold <0.1 ms timestamp inversions
    off, ln = off[srt], ln[srt]
    return int(i), {"off": off, "cumbytes": np.concatenate([[0], np.cumsum(ln)]),
                    "flow_packets": flow_packets, "non_ipv4_out": non_ip_out, "spoofed_source": int(spoofed),
                    "tcp_udp_out": int(tcp_udp_out), "guest_ip_macs": sorted(guest_ip_macs),
                    "pcap_sha256": sha256(pcap)}


def stopped(tr, T_us):
    """Packets and bytes sent at or after T_us (array) by a run with traffic record tr."""
    idx = np.searchsorted(tr["off"], T_us, side="left")
    return len(tr["off"]) - idx, tr["cumbytes"][-1] - tr["cumbytes"][idx]


def t_us(fw, L):
    """Containment time (us) per first window; huge for never-flagged."""
    return np.where(fw >= 0, (fw + 1) * WIN_US + int(round((R_S + L) * 1e6)), 1 << 62)


# -------------------------------------------------------------------------------------------- summaries
def r3(x):
    return None if x is None or (isinstance(x, float) and np.isnan(x)) else round(float(x), 3)


def group_stats(members, fw, L, traffic):
    """Detection, containment time and stopped traffic over the (assignment, run) pairs of the members."""
    members = np.asarray(members, int)
    f = fw[:, members]
    det = f >= 0
    T = t_us(f, L)
    Td = T[det] / 1e6
    res = {"runs": int(len(members)), "pairs": int(det.size), "detected_by_20s": r3(det.mean()),
           "T_median_s": r3(np.median(Td)) if Td.size else None,
           "T_p25_s": r3(np.percentile(Td, 25)) if Td.size else None,
           "T_p75_s": r3(np.percentile(Td, 75)) if Td.size else None,
           "T_max_s": r3(Td.max()) if Td.size else None,
           "contained_within_1s": r3((det & (T <= 1_000_000)).mean()),
           "contained_within_2s": r3((det & (T <= 2_000_000)).mean()),
           "contained_within_5s": r3((det & (T <= 5_000_000)).mean())}
    with_tr = [j for j, i in enumerate(members) if len(traffic[int(i)]["off"])]
    res["runs_with_outbound_traffic"] = len(with_tr)
    if not with_tr:
        return res
    sp, sb, tp, tb, cp, cb = [], [], [], [], [], []
    T0 = np.asarray([WIN_US + int(round((R_S + L) * 1e6))])  # flagged in the first window: the earliest rule
    for j in with_tr:
        tr = traffic[int(members[j])]
        p, b = stopped(tr, T[:, j])
        n, nb = len(tr["off"]), tr["cumbytes"][-1]
        sp.append(p / n); sb.append(b / nb); tp.append(p.sum()); tb.append(b.sum())
        p0, b0 = stopped(tr, T0)
        cp.append(p0[0] / n); cb.append(b0[0] / nb)
    tot_p = sum(len(traffic[int(members[j])]["off"]) for j in with_tr) * fw.shape[0]
    tot_b = sum(int(traffic[int(members[j])]["cumbytes"][-1]) for j in with_tr) * fw.shape[0]
    sp, sb = np.asarray(sp), np.asarray(sb)
    res.update({
        "outbound_packets": int(tot_p / fw.shape[0]), "outbound_bytes": int(tot_b / fw.shape[0]),
        "packets_stopped_share_mean": r3(sp.mean()),   # per (assignment, run), runs weigh equally
        "bytes_stopped_share_mean": r3(sb.mean()),
        "packets_stopped_share_pooled": r3(sum(tp) / tot_p),   # all packets of the group together
        "bytes_stopped_share_pooled": r3(sum(tb) / tot_b),
        "packets_stopped_share_mean_detected_only": r3(sp[det[:, with_tr].T].mean()) if det[:, with_tr].any() else None,
        "ceiling_first_window_packets_share_mean": r3(np.mean(cp)),
        "ceiling_first_window_bytes_share_mean": r3(np.mean(cb)),
    })
    return res


def traffic_profile(tr):
    off = tr["off"] / 1e6
    if not len(off):
        return {"outbound_packets": 0}
    q50, q90 = np.quantile(off, [0.5, 0.9])
    return {"outbound_packets": int(len(off)), "outbound_bytes": int(tr["cumbytes"][-1]),
            "first_s": r3(off[0]), "half_sent_by_s": r3(q50), "ninety_pct_sent_by_s": r3(q90), "last_s": r3(off[-1]),
            "share_sent_before_0.86s": r3((off < 0.86).mean())}


def unit_of(r):
    return {"malware": "family::" + r["family"], "network_attack": "attack::" + r["execution_id"],
            "benign": "project::" + r["project"], "network_benign": "network_benign::" + r["execution_id"],
            "null": "null::" + r["execution_id"]}[r["category"]]


# ------------------------------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=8)
    a = ap.parse_args()
    jobs = min(10, a.jobs)
    t0 = time.time()
    rows, hc, nc = C.load()
    y = C.labels(rows)
    H, N, _, _ = C.per_window(rows, hc, nc)
    assert np.allclose(C.summarize(H), C.matrix(rows, hc)) and np.allclose(C.summarize(N), C.matrix(rows, nc))
    dirs = C.run_dirs(rows)
    cats = np.asarray([r["category"] for r in rows])
    D.update(y=y, g=C.groups_published(rows), H=H, N=N, dirs=dirs)

    # ---------------------------------------------------------------- streaming predictions, 40 windows
    with Pool(min(jobs, len(C.FOLD_SEEDS))) as pool:
        res = dict(pool.map(stream_job, C.FOLD_SEEDS, chunksize=1))
        traf = dict(pool.map(pcap_job, range(len(rows)), chunksize=4))
    P = {d: np.stack([res[s][d] for s in C.FOLD_SEEDS]) for d in C.DETECTORS}  # seeds x 40 x rows
    z = np.load(C.CACHE / "stream.npz")
    pos = [k - 1 for k in z["prefixes"]]
    assert list(z["seeds"]) == C.FOLD_SEEDS
    stream_diff = {d: float(np.abs(P[d][:, pos, :] - z[d]).max()) for d in C.DETECTORS}
    assert all(v == 0.0 for v in stream_diff.values()), stream_diff
    rigor = json.loads((C.HERE / "results" / "rigor.json").read_text())
    report_stream = json.loads(json.dumps(AR.streaming(rows, y), default=float))
    stream_report_equal = report_stream == rigor["F_streaming"]
    assert stream_report_equal
    print("streaming reproduced; %.0f s" % (time.time() - t0), flush=True)

    # ---------------------------------------------------------------- traffic checks
    col = nc.index("net_pkts_total_delta__sum")
    Xn = C.matrix(rows, nc)
    macs = sorted({m for t in traf.values() for m in t["guest_ip_macs"]})
    checks = {
        "stream_predictions_max_abs_diff_vs_cache_stream_npz": stream_diff,
        "report_2_6_streaming_reproduced_from_rigor_json": stream_report_equal,
        "flow_packets_equal_dataset_net_pkts_total_delta_sum": int(sum(traf[i]["flow_packets"] == int(Xn[i, col])
                                                                      for i in range(len(rows)))),
        "source_macs_of_frames_from_10.0.0.10": macs,
        "outbound_ipv4_with_other_source_address": int(sum(t["spoofed_source"] for t in traf.values())),
        "outbound_non_ipv4_frames_excluded": int(sum(t["non_ipv4_out"] for t in traf.values())),
        "rows": len(rows),
    }
    assert checks["flow_packets_equal_dataset_net_pkts_total_delta_sum"] == len(rows)
    assert macs == [GUEST_MAC.hex(":")], macs

    # ---------------------------------------------------------------- first windows and containment
    FW = {d: {thr: first_windows(P[d], thr) for thr in THRESHOLDS} for d in C.DETECTORS}
    mal = np.flatnonzero(y == 1)
    groups = {"attack::" + t: np.flatnonzero(np.asarray([r["attack_type"] for r in rows]) == t) for t in ATTACK_TYPES}
    groups["attacks_all"] = np.flatnonzero(cats == "network_attack")
    groups["malware_with_traffic"] = np.asarray([i for i in np.flatnonzero(cats == "malware") if len(traf[i]["off"])])
    groups["malware_all"] = np.flatnonzero(cats == "malware")
    groups["malicious_all"] = mal
    bgroups = {"benign_cli": np.flatnonzero(cats == "benign"), "network_benign": np.flatnonzero(cats == "network_benign"),
               "null": np.flatnonzero(cats == "null"), "benign_all": np.flatnonzero(y == 0)}
    containment, benign = {}, {}
    for d in C.DETECTORS:
        for thr in THRESHOLDS:
            for L in L_S:
                key = "%s|%g|%g" % (d, thr, L)
                containment[key] = {gname: group_stats(m, FW[d][thr], L, traf) for gname, m in groups.items()}
                benign[key] = {gname: group_stats(m, FW[d][thr], L, traf) for gname, m in bgroups.items()}
    # streaming summary at 40 windows (same quantities as REPORT 2.6, evaluated after every window)
    stream40 = {}
    for d in C.DETECTORS:
        stream40[d] = {}
        for thr in THRESHOLDS:
            fw = FW[d][thr]
            stream40[d][str(thr)] = {
                "flagged_in_first_window_malicious": r3((fw[:, mal] == 0).mean()),
                "detected_by_20s_malicious": r3((fw[:, mal] >= 0).mean()),
                "detected_by_20s_malware": r3((fw[:, cats == "malware"] >= 0).mean()),
                "detected_by_20s_attacks": r3((fw[:, cats == "network_attack"] >= 0).mean()),
                "anytime_false_alarm_benign_20s": r3((fw[:, y == 0] >= 0).mean()),
                "anytime_false_alarm_benign_first_window": r3((fw[:, y == 0] == 0).mean()),
                "share_of_detections_in_first_window": r3((fw[:, mal] == 0).sum() / max(1, (fw[:, mal] >= 0).sum())),
            }
    # per run: attacks (all detectors at thr 0.5, L 0.01) and malware families / benign units (primary)
    d0, thr0, L0 = PRIMARY

    def per_run(i, thr=0.5, L=L0):
        r = rows[i]
        e = {"category": r["category"], "attack_type": r["attack_type"], **traffic_profile(traf[i])}
        for d in C.DETECTORS:
            fw = FW[d][thr][:, i]
            det = fw >= 0
            T = t_us(fw, L)
            x = {"detected_assignments": int(det.sum()),
                 "first_window_median": float(np.median(fw[det])) if det.any() else None,
                 "T_median_s": r3(np.median(T[det]) / 1e6) if det.any() else None}
            if len(traf[i]["off"]):
                p, b = stopped(traf[i], T)
                x.update({"packets_stopped_share_mean": r3((p / len(traf[i]["off"])).mean()),
                          "bytes_stopped_share_mean": r3((b / traf[i]["cumbytes"][-1]).mean())})
            e[d] = x
        return e

    per_attack = {rows[i]["execution_id"]: per_run(i) for i in groups["attacks_all"]}
    per_network_benign = {rows[i]["execution_id"]: per_run(i) for i in bgroups["network_benign"]}
    by_unit = {}
    fw = FW[d0][thr0]
    for i in range(len(rows)):
        u = unit_of(rows[i])
        by_unit.setdefault(u, []).append(i)
    unit_table = {}
    for u, members in sorted(by_unit.items()):
        st = group_stats(members, fw, L0, traf)
        unit_table[u] = {"label": int(y[members[0]]), **{k: st.get(k) for k in (
            "runs", "detected_by_20s", "T_median_s", "runs_with_outbound_traffic", "outbound_packets",
            "packets_stopped_share_mean", "bytes_stopped_share_mean")}}
    files = {
        "features.csv": C.FEATURES, "independent_pool.json": C.POOL, "cache/windows.npz": C.CACHE / "windows.npz",
        "cache/stream.npz": C.CACHE / "stream.npz", "results/rigor.json": C.HERE / "results" / "rigor.json",
        "common.py": C.HERE / "common.py", "compute_oof.py": C.HERE / "compute_oof.py",
        "analyze_rigor.py": C.HERE / "analyze_rigor.py", "switch_model.py": Path(SM.__file__),
        "mitigation.py": Path(__file__).resolve(),
    }
    pcaps = {rows[i]["execution_id"]: traf[i]["pcap_sha256"] for i in range(len(rows))}
    out = {
        "protocol": {
            "detection": "streaming models of REPORT 2.6 (trained on the nine prefixes %s windows), Table V protocol, "
                         "fold seeds %s; scored after every 0.5-s window" % (list(CO.STREAM_PREFIXES), C.FOLD_SEEDS),
            "first_window": "first window w (0-based) with probability >= threshold; -1 = not within 20 s",
            "containment_time": "T = (w + 1) * 0.5 s + R + L; R = %.2f s, L in %s s" % (R_S, L_S),
            "rule": "per host: every IPv4 frame the host sends at or after T is dropped",
            "traffic": "IPv4 frames with Ethernet source %s and offset in [0, 20 s) from sample_started_wall_us"
                       % GUEST_MAC.hex(":"),
            "thresholds": THRESHOLDS, "primary": {"detector": d0, "threshold": thr0, "L_s": L0},
            "first_window_per_run": "per run, detector and threshold: first flagged window in each of the ten fold "
                                    "assignments (order %s), -1 = not flagged within 20 s" % C.FOLD_SEEDS,
            "shares": "packets_stopped_share_mean: mean over (assignment, run) pairs of the run's stopped share "
                      "(never flagged = 0); pooled: all packets of the group together; ceiling: flagged in the first "
                      "window in every assignment",
        },
        "checks": checks,
        "streaming_40_windows": stream40,
        "containment": containment,
        "benign_blocked": benign,
        "per_attack_run": per_attack,
        "per_network_benign_run": per_network_benign,
        "first_window_per_run": {rows[i]["execution_id"]: {d: {str(thr): FW[d][thr][:, i].tolist() for thr in THRESHOLDS}
                                                           for d in C.DETECTORS} for i in range(len(rows))},
        "per_unit_primary": unit_table,
        "traffic_profile": {rows[i]["execution_id"]: traffic_profile(traf[i]) for i in range(len(rows))
                            if len(traf[i]["off"])},
        "inputs_sha256": {k: sha256(p) for k, p in files.items()},
        "pcap_sha256": pcaps,
        "pcap_sha256_digest": hashlib.sha256(json.dumps(pcaps, sort_keys=True).encode()).hexdigest(),
        "runtime_seconds": round(time.time() - t0, 1),
    }
    C.write_json(HERE / "results.json", out)
    print("wrote mitigation/results.json in %.0f s" % (time.time() - t0))


if __name__ == "__main__":
    main()
