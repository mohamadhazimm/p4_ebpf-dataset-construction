"""Per-run, per-window flow aggregates that can be recombined into the switch features of concurrent traffic.

Flows of different programs never share switch state (distinct 5-tuples), so the 29 window features of a
mixture of programs follow exactly from per-program aggregates, provided start offsets are whole windows:
sums of deltas and active-flow counts add; minima, maxima, means and ratios are recomputed from the sums.

For every run: the release's switch model (features/switch_model.py) replays the capture from the run's
anchor, and at each window readout we record 18 aggregates of the active flows instead of the 29 features.
`features(agg)` turns (summed) aggregates back into the 29 features; on a single run it must equal the stored
telemetry exactly (checked in main()).

    /usr/bin/python3 components.py      # writes ../cache/components.npz
"""
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/features")
import common as C  # noqa: E402
import switch_model as SM  # noqa: E402

FIELDS = ["n_active", "sum_min_len", "sum_max_len", "min_min_len", "max_max_len", "sum_dur", "max_dur",
          "flows_with_ab", "flows_with_ba", "packets", "bytes", "ab_packets", "ab_bytes", "ba_packets",
          "ba_bytes", "syn", "ack", "rst"]
F = {f: i for i, f in enumerate(FIELDS)}
SUM_FIELDS = [F[f] for f in FIELDS if f not in ("min_min_len", "max_max_len", "max_dur")]
INF = 1e18


class AggTable(SM.FlowTable):
    def read_aggregates(self, window):
        a = np.zeros(len(FIELDS))
        a[F["min_min_len"]] = INF
        delta, self.window_delta = self.window_delta, {}
        for key, seen in self.last_seen.items():
            if not 0 <= window - seen <= self.active_ttl_windows:
                continue
            st = self.state[key]
            d = delta.get(key, {})
            for name in ("packets", "bytes", "ab_packets", "ab_bytes", "ba_packets", "ba_bytes", "syn", "ack", "rst"):
                a[F[name]] += d.get(name, 0)
            dur = max(st["last_ts"] - st["first_ts"], 0.0)
            a[F["n_active"]] += 1
            a[F["sum_min_len"]] += st["min_len"]; a[F["sum_max_len"]] += st["max_len"]
            a[F["min_min_len"]] = min(a[F["min_min_len"]], st["min_len"])
            a[F["max_max_len"]] = max(a[F["max_max_len"]], st["max_len"])
            a[F["sum_dur"]] += dur; a[F["max_dur"]] = max(a[F["max_dur"]], dur)
            a[F["flows_with_ab"]] += int(st["ab_packets"] > 0); a[F["flows_with_ba"]] += int(st["ba_packets"] > 0)
        return a


def run_aggregates(pcap, start_us, window_seconds=0.5, windows=40):
    """(windows, 18) aggregates for one capture, replaying it like switch_model.window_features."""
    window_us = int(round(window_seconds * 1_000_000))
    table = AggTable(window_seconds, 3)
    out, current = [], 0
    for time_us, timestamp, frame in SM.read_pcap(pcap):
        offset = time_us - start_us
        if offset < 0 or offset // window_us >= windows:
            continue
        window = offset // window_us
        while current < window:
            out.append(table.read_aggregates(current)); current += 1
        p = SM.parse_flow_packet(frame)
        if p is not None:
            table.update(window, timestamp, *p, len(frame))
    while current < windows:
        out.append(table.read_aggregates(current)); current += 1
    return np.asarray(out)


def combine(parts):
    """Sum per-window aggregates of several components (list of (windows,18) arrays, already shifted)."""
    a = np.zeros_like(parts[0])
    a[:, F["min_min_len"]] = INF
    for p in parts:
        a[:, SUM_FIELDS] += p[:, SUM_FIELDS]
        a[:, F["min_min_len"]] = np.minimum(a[:, F["min_min_len"]], p[:, F["min_min_len"]])
        a[:, F["max_max_len"]] = np.maximum(a[:, F["max_max_len"]], p[:, F["max_max_len"]])
        a[:, F["max_dur"]] = np.maximum(a[:, F["max_dur"]], p[:, F["max_dur"]])
    return a


def shifted(agg, shift):
    """Aggregates of a component that starts `shift` windows after the target (empty windows before it)."""
    out = np.zeros_like(agg)
    out[:, F["min_min_len"]] = INF
    if shift < agg.shape[0]:
        out[shift:] = agg[:agg.shape[0] - shift]
    return out


def features(a, window_seconds=0.5):
    """(windows, 29) switch features from (summed) aggregates, in SM.FEATURES order."""
    n = a[:, F["n_active"]]
    pk, by = a[:, F["packets"]], a[:, F["bytes"]]
    abp, abb, bap, bab = a[:, F["ab_packets"]], a[:, F["ab_bytes"]], a[:, F["ba_packets"]], a[:, F["ba_bytes"]]
    div = lambda x, y: np.divide(x, y, out=np.zeros_like(x, dtype=float), where=y != 0)
    cols = {
        "net_flow_count_seen": n, "net_pkts_total_delta": pk, "net_bytes_total_delta": by,
        "net_pkts_ab_delta": abp, "net_bytes_ab_delta": abb, "net_pkts_ba_delta": bap, "net_bytes_ba_delta": bab,
        "net_min_len_mean": div(a[:, F["sum_min_len"]], n), "net_max_len_mean": div(a[:, F["sum_max_len"]], n),
        "net_min_len_min": np.where(n > 0, a[:, F["min_min_len"]], 0.0), "net_max_len_max": a[:, F["max_max_len"]],
        "net_avg_pkt_size_delta": div(by, pk), "net_avg_pkt_size_ab_delta": div(abb, abp),
        "net_avg_pkt_size_ba_delta": div(bab, bap), "net_flow_duration_mean": div(a[:, F["sum_dur"]], n),
        "net_flow_duration_max": a[:, F["max_dur"]], "net_bytes_per_sec_delta": by / window_seconds,
        "net_pkts_per_sec_delta": pk / window_seconds, "net_down_up_ratio_delta": div(bab, abb),
        "net_ab_ratio_pkt_delta": div(abp, pk), "net_ba_ratio_pkt_delta": div(bap, pk),
        "net_ab_ratio_byte_delta": div(abb, by), "net_ba_ratio_byte_delta": div(bab, by),
        "net_syn_delta": a[:, F["syn"]], "net_ack_delta": a[:, F["ack"]], "net_rst_delta": a[:, F["rst"]],
        "net_flows_with_ab": a[:, F["flows_with_ab"]], "net_flows_with_ba": a[:, F["flows_with_ba"]],
        "net_dir_valid_count": n,
    }
    return np.stack([cols[f] for f in SM.FEATURES], axis=1)


def _job(i_dir):
    i, d = i_dir
    out = C.output_dir(d)
    start = json.loads((out / "run.json").read_text())["sample_started_wall_us"]
    return i, run_aggregates(out / "packet_capture.pcap", int(start))


def main():
    from multiprocessing import Pool
    rows, hc, nc = C.load()
    _, N, _, ns = C.per_window(rows, hc, nc)
    order = [ns.index(f) for f in SM.FEATURES]
    with Pool(8) as p:
        res = dict(p.map(_job, list(enumerate(C.run_dirs(rows))), chunksize=4))
    A = np.stack([res[i] for i in range(len(rows))])
    worst = 0.0
    for i in range(len(rows)):
        got = features(A[i])
        want = N[i][:, order]
        worst = max(worst, float(np.max(np.abs(got - want) / np.maximum(1.0, np.abs(want)))))
    print("max relative difference vs stored per-window switch features: %.3e" % worst)
    assert worst < 1e-9, worst
    np.savez_compressed(C.CACHE / "components.npz", A=A, fields=np.asarray(FIELDS))
    print("wrote cache/components.npz", A.shape)


if __name__ == "__main__":
    main()
