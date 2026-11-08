"""Switch-faithful software model of the flow features (E3).

Unlike the idealized model (p4-ebpf-malware-detection/features/switch_model.py), this follows the P4
program and the deployed control plane:

  * flows are CRC-16/ARC buckets (65,536), so different flows with equal address-XOR and port-XOR share
    a bucket and its counters (flow_index.py);
  * direction is decided by the first packet's ports only; a reversed pair is B->A, anything else
    (including equal ports and collisions) counts as A->B;
  * packet length is the IPv4 total length, not the Ethernet frame length;
  * timestamps are the low 32 bits of a nanosecond clock, so a flow's duration is taken modulo 2^32 ns
    (about 4.295 s) and wraps for longer flows;
  * registers are cumulative and read once per window; a bucket is dropped after three idle reads;
  * the control plane reads at most `cap` buckets per window (None = unlimited). When more buckets are
    active, the `cap` with the most packets in the window are read (a best case for the limit).

The 29 window features and their names are exactly those of the idealized model.
"""
import sys
from pathlib import Path

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(REL / "features"))
import switch_model  # noqa: E402  (read_pcap, parse_flow_packet, FEATURES, DELTA/COUNTERS)
sys.path.insert(0, str(REL / "p4/control_plane"))
from flow_index import compute_flow_index  # noqa: E402

FEATURES = switch_model.FEATURES
COUNTERS = switch_model.COUNTERS
DELTA_FEATURES = switch_model.DELTA_FEATURES
WRAP = 1 << 32  # 32-bit nanosecond clock


class FaithfulFlowTable:
    def __init__(self, window_seconds, cap=None, active_ttl_windows=3):
        self.window_seconds = window_seconds
        self.cap = cap
        self.active_ttl_windows = active_ttl_windows
        self.ref = {}            # bucket -> (ref_sport, ref_dport) from the first packet
        self.state = {}          # bucket -> cumulative counters + min/max/first_ts/last_ts
        self.last_seen = {}      # bucket -> last window with a packet
        self.window_delta = {}   # bucket -> per-window counters

    def update(self, window, ts_ns, source, destination, protocol, ports, flags, ip_len):
        bucket = compute_flow_index(source, destination, ports[0], ports[1], protocol)
        ref = self.ref.setdefault(bucket, (ports[0], ports[1]))
        if ports == ref:
            direction = "ab"
        elif ports == (ref[1], ref[0]):
            direction = "ba"
        else:
            direction = "ab"  # collision / equal ports / ambiguous -> A->B, as the data plane does
        syn, ack, rst = int(bool(flags & 0x02)), int(bool(flags & 0x10)), int(bool(flags & 0x04))
        ts32 = ts_ns & 0xFFFFFFFF
        state = self.state.setdefault(bucket, dict.fromkeys(COUNTERS, 0) | {
            "min_len": ip_len, "max_len": ip_len, "first_ts": ts32, "last_ts": ts32})
        delta = self.window_delta.setdefault(bucket, dict.fromkeys(COUNTERS, 0))
        for counters in (state, delta):
            counters["packets"] += 1
            counters["bytes"] += ip_len
            counters[direction + "_packets"] += 1
            counters[direction + "_bytes"] += ip_len
            counters["syn"] += syn
            counters["ack"] += ack
            counters["rst"] += rst
        state["min_len"] = min(state["min_len"], ip_len)
        state["max_len"] = max(state["max_len"], ip_len)
        state["last_ts"] = ts32  # the register keeps the latest, not the maximum
        self.last_seen[bucket] = window

    def read_window(self, window):
        out = dict.fromkeys(FEATURES, 0)
        delta, self.window_delta = self.window_delta, {}
        active = [b for b, seen in self.last_seen.items() if 0 <= window - seen <= self.active_ttl_windows]
        if self.cap is not None and len(active) > self.cap:
            active.sort(key=lambda b: delta.get(b, {}).get("packets", 0), reverse=True)
            active = active[: self.cap]
        min_lengths, max_lengths, durations = [], [], []
        for bucket in active:
            state = self.state[bucket]
            for feature, counter in DELTA_FEATURES:
                out[feature] += delta.get(bucket, {}).get(counter, 0)
            min_lengths.append(state["min_len"])
            max_lengths.append(state["max_len"])
            durations.append(((state["last_ts"] - state["first_ts"]) % WRAP) / 1e9)
            out["net_flows_with_ab"] += int(state["ab_packets"] > 0)
            out["net_flows_with_ba"] += int(state["ba_packets"] > 0)
            out["net_dir_valid_count"] += 1
        # drop buckets idle for more than active_ttl_windows (register cleared after idle reads)
        for b in [b for b, seen in self.last_seen.items() if window - seen > self.active_ttl_windows]:
            self.last_seen.pop(b, None); self.state.pop(b, None); self.ref.pop(b, None)
        packets, size = out["net_pkts_total_delta"], out["net_bytes_total_delta"]
        ab_p, ab_b = out["net_pkts_ab_delta"], out["net_bytes_ab_delta"]
        ba_p, ba_b = out["net_pkts_ba_delta"], out["net_bytes_ba_delta"]
        out.update({
            "net_flow_count_seen": len(active),
            "net_min_len_mean": sum(min_lengths) / len(min_lengths) if min_lengths else 0.0,
            "net_max_len_mean": sum(max_lengths) / len(max_lengths) if max_lengths else 0.0,
            "net_min_len_min": min(min_lengths, default=0),
            "net_max_len_max": max(max_lengths, default=0),
            "net_avg_pkt_size_delta": size / packets if packets else 0.0,
            "net_avg_pkt_size_ab_delta": ab_b / ab_p if ab_p else 0.0,
            "net_avg_pkt_size_ba_delta": ba_b / ba_p if ba_p else 0.0,
            "net_flow_duration_mean": sum(durations) / len(durations) if durations else 0.0,
            "net_flow_duration_max": max(durations, default=0.0),
            "net_bytes_per_sec_delta": size / self.window_seconds,
            "net_pkts_per_sec_delta": packets / self.window_seconds,
            "net_down_up_ratio_delta": ba_b / ab_b if ab_b else 0.0,
            "net_ab_ratio_pkt_delta": ab_p / packets if packets else 0.0,
            "net_ba_ratio_pkt_delta": ba_p / packets if packets else 0.0,
            "net_ab_ratio_byte_delta": ab_b / size if size else 0.0,
            "net_ba_ratio_byte_delta": ba_b / size if size else 0.0,
        })
        return out


def ipv4_total_length(frame):
    """IPv4 total length of a flow frame (the value the switch counts), or None."""
    offset, ethertype, tags = 12, (frame[12] << 8) | frame[13], 0
    while ethertype in (0x8100, 0x88A8):
        tags += 1
        if tags > 2 or len(frame) < offset + 6:
            return None
        offset += 4
        ethertype = (frame[offset] << 8) | frame[offset + 1]
    offset += 2
    if ethertype != 0x0800 or len(frame) < offset + 4:
        return None
    return (frame[offset + 2] << 8) | frame[offset + 3]


def window_features(pcap_path, start_us, window_seconds=0.5, windows=40, cap=None):
    window_us = int(round(window_seconds * 1_000_000))
    table = FaithfulFlowTable(window_seconds, cap)
    result, current = [], 0
    for time_us, time_s, frame in switch_model.read_pcap(pcap_path):
        offset = time_us - start_us
        if offset < 0 or offset // window_us >= windows:
            continue
        window = offset // window_us
        while current < window:
            result.append(table.read_window(current)); current += 1
        packet = switch_model.parse_flow_packet(frame)
        if packet is not None:
            source, destination, protocol, ports, flags = packet
            ip_len = ipv4_total_length(frame)
            if ip_len is not None:
                table.update(window, int(round(time_s * 1e9)), source, destination, protocol, ports, flags, ip_len)
    while current < windows:
        result.append(table.read_window(current)); current += 1
    return result
