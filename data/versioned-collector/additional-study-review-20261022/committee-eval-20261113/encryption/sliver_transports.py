"""Encryption check, part 2: Sliver implants over HTTP vs HTTPS vs mutual TLS (offline, read-only).

Our own Sliver v1.7.9 implants under our own server in the sealed lab (attempt
sliver-c2-5min/20261113T175035504465Z, runner .22 = .21 plus an event-count guard, same 169 features): the same
framework and beacon configuration (5-s interval, no jitter), two separately generated implants per transport
(a and b, used as repeats), each observed 5 min (600 windows) while the operator issued the same fixed task list
(one tasking in the first 20 s and twelve in 5 min for every tasked implant). Beacon transports: HTTP (port 8080;
cleartext HTTP framing, the message bodies are encrypted by Sliver itself), HTTPS (TLS 1.3, port 8444) and mutual
TLS (TLS 1.3 with a client certificate, port 8443). The WireGuard beacons exited (status 2) without traffic and are
listed but not compared; the mTLS and WireGuard sessions (one long connection) are a second C2 mode, for reference.

Artifact found here: after the first WireGuard session (position 16) the Sliver server kept sending WireGuard
handshake initiations (UDP from 10.0.0.1:51820, about one per 5 s) to the guest during several later runs; the guest
answers with ICMP port unreachable. They are not traffic of those runs' programs but the switch counts them as a
UDP flow. So every result is given twice: as collected, and with the switch features recomputed by the release's
switch model (features/switch_model.py, unchanged) without UDP packets to or from port 51820 in runs that are not
WireGuard implants. The unfiltered recomputation must equal the collected telemetry.

The frozen loaders are imported unchanged (sinkhole-c2-5min/analyze_sinkhole_c2.load_runs and
sliver-c2-5min/analyze_sliver.five). Feature contrasts at 20 s (first 40 windows) and 5 min (600 windows): per column
the change between transports vs the a/b difference; the scale is the column SD over the testbed's 27 runs at the
same length (and over the 240 dataset rows at 20 s). Detectors: the paper's four, trained on all 240 dataset rows
(common.fit_predict), applied to each run's first 40 windows; the as-collected scores must reproduce the saved
analysis/sliver_results.json. Secondary: the same fitted models on every consecutive 20-s block of the 5-min runs
(blocks after the first lack the process start, so host and hybrid scores there are outside the training conditions).

    nice -n 19 /usr/bin/python3 sliver_transports.py
"""
import hashlib
import importlib.util
import json
import sys
import time
from collections import defaultdict
from itertools import combinations
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent.parent  # additional-study-review-20261022
sys.path.insert(0, str(PROJ / "sliver-c2-5min"))
import analyze_sliver as S  # noqa: E402  frozen; brings the frozen sinkhole loader (A) and the committee loader (C)
A, C = S.A, S.C
sys.path.insert(0, str(HERE))
import contrast as K  # noqa: E402
import wire  # noqa: E402

_spec = importlib.util.spec_from_file_location("release_switch_model", C.RELEASE / "features/switch_model.py")
SM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SM)

ATTEMPT = PROJ / "sliver-c2-5min/20261113T175035504465Z"
PREFIXES = ((40, "20s"), (600, "5min"))
BEACON_CONTRASTS = (("http-beacon", "https-beacon"), ("http-beacon", "mtls-beacon"), ("https-beacon", "mtls-beacon"))
REFERENCE_CONTRASTS = (("mtls-beacon", "mtls-session"), ("mtls-session", "wg-session"))
VARIANTS = ("as_collected", "without_stray_wireguard")
WG_PORT = 51820
BLOCK = 40


def run_out(case):
    found = sorted((ATTEMPT / "runs" / case["sample"] / "output").glob("run_*/run.json"))
    assert len(found) == 1, case["sample"]
    return found[0].parent


def switch_windows(pcap, start_us, windows, net, drop=None):
    """release switch_model.window_features (same loop), with an optional filter on parsed packets."""
    window_us = 500_000
    table = SM.FlowTable(0.5, 3)
    rows, current, dropped = [], 0, 0
    for time_us, timestamp, frame in SM.read_pcap(pcap):
        offset = time_us - start_us
        if offset < 0 or offset // window_us >= windows:
            continue
        window = offset // window_us
        assert window >= current
        while current < window:
            rows.append(table.read_window(current))
            current += 1
        packet = SM.parse_flow_packet(frame)
        if packet is not None:
            if drop is not None and drop(packet):
                dropped += 1
                continue
            source, destination, protocol, ports, flags = packet
            table.update(window, timestamp, source, destination, protocol, ports, flags, len(frame))
    while current < windows:
        rows.append(table.read_window(current))
        current += 1
    return np.array([[r[f] for f in net] for r in rows]), dropped


def main():
    t0 = time.time()
    host, net = A.tc.signals()
    protocol, runs = A.load_runs(ATTEMPT, host, net)
    drows, hc, nc = C.load()
    assert C.signals(hc) == host and C.signals(nc) == net
    Xh_d, Xn_d, y_d, g_d = C.matrix(drows, hc), C.matrix(drows, nc), C.labels(drows), C.groups_published(drows)
    cols = hc + nc
    names = [r["case"]["sample"].removesuffix(".zip") for r in runs]
    kind = ["%s-%s" % (r["case"]["transport"], r["case"]["c2_mode"]) if r["label"] == "malware" else r["label"]
            for r in runs]
    position = {c["sample"].removesuffix(".zip"): c["position"] for c in protocol["cases"]}
    pk, by = net.index("net_pkts_total_delta"), net.index("net_bytes_total_delta")

    # switch features recomputed with the release model: unfiltered (== telemetry) and without stray WireGuard
    stray = lambda p: p[2] == 17 and WG_PORT in p[3]  # noqa: E731
    N_var = {v: [] for v in VARIANTS}
    stray_counts, recompute_diff = [], 0.0
    for r, kd in zip(runs, kind):
        pcap = run_out(r["case"]) / "packet_capture.pcap"
        start = r["meta"]["sample_started_wall_us"]
        full, _ = switch_windows(pcap, start, 600, net)
        recompute_diff = max(recompute_diff, float(np.abs(full - r["N"]).max() / max(1.0, np.abs(r["N"]).max())))
        if kd.startswith("wg-"):
            clean, n_drop, n_drop20 = full, 0, 0
        else:
            clean, n_drop = switch_windows(pcap, start, 600, net, drop=stray)
            n_drop20 = switch_windows(pcap, start, 40, net, drop=stray)[1]
        N_var["as_collected"].append(r["N"])
        N_var["without_stray_wireguard"].append(clean)
        stray_counts.append({"first_20s": n_drop20, "5min": n_drop})
    assert recompute_diff <= 1e-9, recompute_diff

    feats, wires = {v: {} for v in VARIANTS}, {}
    for k, lab in PREFIXES:
        for v in VARIANTS:
            F = np.array([np.concatenate([S.five(r["H"], host, hc, k), S.five(N, net, nc, k)])
                          for r, N in zip(runs, N_var[v])])
            if v == "as_collected":
                G = np.array([np.concatenate([C.summarize(r["H"][None], k)[0], C.summarize(r["N"][None], k)[0]])
                              for r in runs])
                assert np.abs(F - G).max() <= 1e-9 * max(1.0, np.abs(F).max())  # frozen five() == summarize()
            feats[v][lab] = F
        wires[lab] = []
        for r in runs:
            w = wire.summarize(run_out(r["case"]) / "packet_capture.pcap", r["meta"]["sample_started_wall_us"], k)
            assert w["ipv4_tcp_udp_frames"] == int(r["N"][:k, pk].sum()), r["case"]["sample"]
            assert w["ipv4_tcp_udp_frame_bytes"] == int(r["N"][:k, by].sum()), r["case"]["sample"]
            wires[lab].append(w)

    group = defaultdict(list)
    for i, kd in enumerate(kind):
        group[kd].append(i)
    assert all(len(group[g]) == 2 for g in ("http-beacon", "https-beacon", "mtls-beacon", "mtls-session",
                                             "wg-session", "wg-beacon"))
    host_idx, net_idx = np.arange(90), np.arange(90, 235)
    sd_data = np.hstack([Xh_d, Xn_d]).std(0, ddof=1)

    contrasts = []
    for v in VARIANTS:
        for k, lab in PREFIXES:
            F = feats[v][lab]
            sd_tb = feats["as_collected"][lab].std(0, ddof=1)  # spread over the testbed's 27 runs, as collected
            scales = {"testbed_sd": sd_tb}
            if k == 40:
                scales["dataset_sd"] = sd_data
            for (ga, gb), role in ([(c, "transport") for c in BEACON_CONTRASTS] +
                                   [(c, "reference") for c in REFERENCE_CONTRASTS]):
                Ai, Bi = group[ga], group[gb]
                rec = {"variant": v, "length": lab, "role": role, "a": ga, "b": gb,
                       "runs_a": [names[i] for i in Ai], "runs_b": [names[i] for i in Bi],
                       "transport_observed_a": [wires[lab][i]["transport_observed"] for i in Ai],
                       "transport_observed_b": [wires[lab][i]["transport_observed"] for i in Bi]}
                for sname, sc in scales.items():
                    st = K.stats(F[Ai], F[Bi], sc)
                    Z = np.where(sc > 0, F / np.where(sc > 0, sc, 1), 0.0)
                    rec[sname] = {"host": K.block_summary(st, host_idx, cols, Z[Ai], Z[Bi]),
                                  "network": K.block_summary(st, net_idx, cols, Z[Ai], Z[Bi])}
                # change between the two sides vs the larger of the two a/b differences, per column
                st = K.stats(F[Ai], F[Bi], sd_tb)
                rep = np.maximum(np.abs(F[Ai[0]] - F[Ai[1]]), np.abs(F[Bi[0]] - F[Bi[1]]))
                ch = np.abs(st["delta"])
                for blk, idx in (("host", host_idx), ("network", net_idx)):
                    rec["testbed_sd"][blk]["change_exceeds_both_repeat_differences"] = int((ch[idx] > rep[idx]).sum())
                contrasts.append(rec)

    # per-signal table for the beacons and sessions: per-window mean, sum and max of every signal, per implant
    per_signal = {}
    for v in VARIANTS:
        per_signal[v] = {}
        for k, lab in PREFIXES:
            tab = {}
            for blk, sigs in (("host", host), ("network", net)):
                for j, s in enumerate(sigs):
                    cell = {}
                    for gname in ("http-beacon", "https-beacon", "mtls-beacon", "mtls-session", "wg-session"):
                        series = [runs[i]["H"][:k, j] if blk == "host" else N_var[v][i][:k, j] for i in group[gname]]
                        cell[gname] = {"sum": [float(x.sum()) for x in series], "mean": [float(x.mean()) for x in series],
                                       "max": [float(x.max()) for x in series]}
                    tab[s] = cell
            per_signal[v][lab] = tab

    # detectors trained on all 240 dataset rows, applied to every 20-s block of both variants
    nb = 600 // BLOCK
    Xh_t, Xn_t = [], []
    for v in VARIANTS:
        for r, N in zip(runs, N_var[v]):
            for b in range(nb):
                Xh_t.append(C.summarize(r["H"][None, b * BLOCK:(b + 1) * BLOCK])[0])
                Xn_t.append(C.summarize(N[None, b * BLOCK:(b + 1) * BLOCK])[0])
    Xh_t, Xn_t = np.array(Xh_t), np.array(Xn_t)
    Xh, Xn = np.vstack([Xh_d, Xh_t]), np.vstack([Xn_d, Xn_t])
    y = np.concatenate([y_d, np.zeros(len(Xh_t), int)])
    g = np.concatenate([g_d, ["testbed"] * len(Xh_t)])
    tr, te = np.arange(len(drows)), np.arange(len(drows), len(y))
    Pall = C.fit_predict(Xh, Xn, y, g, tr, te)
    P = {v: {d: Pall[d].reshape(len(VARIANTS), len(runs), nb)[vi] for d in C.DETECTORS} for vi, v in enumerate(VARIANTS)}
    assert np.allclose(Xh_t[:len(runs) * nb:nb], feats["as_collected"]["20s"][:, :90])
    assert np.allclose(Xn_t[:len(runs) * nb:nb], feats["as_collected"]["20s"][:, 90:])
    saved = json.load(open(ATTEMPT / "analysis/sliver_results.json"))["published_detectors"]["trained_on_all_240"]
    max_diff = max(abs(round(float(P["as_collected"][d][i, 0]), 3) - saved["per_detector"][d]["by_run"][n])
                   for d in C.DETECTORS for i, n in enumerate(names))
    assert max_diff < 1e-9, max_diff  # reproduces the saved analysis to its 3 decimals

    detectors = {}
    for v in VARIANTS:
        first = {n: {d: round(float(P[v][d][i, 0]), 4) for d in C.DETECTORS} for i, n in enumerate(names)}
        decisions = {}
        for d in C.DETECTORS:
            flag = P[v][d][:, 0] >= 0.5
            bea = [i for gname in ("http-beacon", "https-beacon", "mtls-beacon") for i in group[gname]]
            within = [flag[i] != flag[j] for gname in ("http-beacon", "https-beacon", "mtls-beacon")
                      for i, j in combinations(group[gname], 2)]
            between = [flag[i] != flag[j] for ga, gb in BEACON_CONTRASTS for i in group[ga] for j in group[gb]]
            decisions[d] = {"flagged": {gname: [bool(flag[i]) for i in idx] for gname, idx in sorted(group.items())},
                            "beacons_flagged": int(flag[bea].sum()), "beacons": len(bea),
                            "disagree_within_transport_pairs": [int(sum(within)), len(within)],
                            "disagree_between_transport_pairs": [int(sum(between)), len(between)],
                            "benign_flagged": int(flag[group["benign"]].sum()), "benign": len(group["benign"]),
                            "nulls_flagged": int(flag[group["null"]].sum()), "nulls": len(group["null"])}
        blocks = {gname: {d: {"flag_rate_all_blocks": float((P[v][d][idx] >= .5).mean()),
                              "flag_rate_blocks_after_first": float((P[v][d][idx, 1:] >= .5).mean()),
                              "mean_prob_blocks_after_first": float(P[v][d][idx, 1:].mean()),
                              "flags_by_block": [[int(x) for x in (P[v][d][i] >= .5)] for i in idx]}
                          for d in C.DETECTORS}
                  for gname, idx in sorted(group.items())}
        detectors[v] = {"probabilities_first_20s": first, "decisions_first_20s": decisions, "blocks_20s": blocks}

    autotask = [json.loads(line) for line in open(ATTEMPT / "autotask.jsonl")]
    per_run = []
    for i, r in enumerate(runs):
        t_start = r["meta"]["sample_started_wall_us"] / 1e6
        ts = [e["t"] - t_start for e in autotask if e.get("name") == names[i] and 0 <= e["t"] - t_start < 300]
        per_run.append({"run": names[i], "position": position[names[i]], "kind": kind[i], "label": r["label"],
                        "mode": r["mode"], "return_code": r["meta"].get("return_code"),
                        "runner_sha256": r["meta"].get("malware_runner_sha256"),
                        "schema": r["meta"].get("telemetry_schema_version"),
                        "operator_taskings": {"first_20s": sum(1 for x in ts if x < 20), "5min": len(ts)},
                        "stray_wireguard_packets": stray_counts[i],
                        "wire_20s": wires["20s"][i], "wire_5min": wires["5min"][i],
                        "host_calls_20s": float(r["H"][:40, 0].sum()), "host_calls_5min": float(r["H"][:, 0].sum()),
                        "scores_first_20s": {v: detectors[v]["probabilities_first_20s"][names[i]] for v in VARIANTS},
                        "features": {v: {lab: feats[v][lab][i].tolist() for _, lab in PREFIXES} for v in VARIANTS}})

    out = {"attempt": str(ATTEMPT),
           "protocol_sha256": hashlib.sha256((ATTEMPT / "protocol.json").read_bytes()).hexdigest(),
           "switch_model_sha256": hashlib.sha256((C.RELEASE / "features/switch_model.py").read_bytes()).hexdigest(),
           "switch_model_recompute_equals_telemetry_max_rel_diff": recompute_diff,
           "detectors_trained_on": "all 240 dataset rows (release features.csv)",
           "as_collected_scores_reproduce_saved_sliver_results_max_diff_3dp": max_diff,
           "accepted_runs": len(runs), "kinds": {kd: [names[i] for i in idx] for kd, idx in sorted(group.items())},
           "columns": cols, "contrasts": contrasts, "per_signal": per_signal, "detectors": detectors,
           "per_run": per_run, "elapsed_s": round(time.time() - t0, 1)}
    C.write_json(HERE / "results_sliver.json", out)
    print("accepted %d runs; switch-model recompute rel diff %.2g; saved-score max diff %g; %.0f s" % (
        len(runs), recompute_diff, max_diff, time.time() - t0))
    for i in np.argsort([position[n] for n in names]):
        if stray_counts[i]["5min"]:
            print("  stray WireGuard packets: pos %2d %-48s 20s %3d  5min %4d" % (
                position[names[i]], names[i], stray_counts[i]["first_20s"], stray_counts[i]["5min"]))
    for c in contrasts:
        h, n = c["testbed_sd"]["host"], c["testbed_sd"]["network"]
        print("%-23s %-5s %-9s %-13s vs %-13s host D %5.2f (rep %5.2f) chg>rep %2d/90 | net D %5.2f (rep %5.2f) chg>rep %3d/145" % (
            c["variant"], c["length"], c["role"], c["a"], c["b"], h["distance"]["between_means"],
            h["distance"]["mean_within_pair"], h["change_exceeds_both_repeat_differences"],
            n["distance"]["between_means"], n["distance"]["mean_within_pair"],
            n["change_exceeds_both_repeat_differences"]))
    for v in VARIANTS:
        for d in C.DETECTORS:
            x = detectors[v]["decisions_first_20s"][d]
            print("%-23s %-8s beacons %d/%d  within %s  between %s  benign %d/%d  nulls %d/%d" % (
                v, d, x["beacons_flagged"], x["beacons"], x["disagree_within_transport_pairs"],
                x["disagree_between_transport_pairs"], x["benign_flagged"], x["benign"], x["nulls_flagged"], x["nulls"]))


if __name__ == "__main__":
    main()
