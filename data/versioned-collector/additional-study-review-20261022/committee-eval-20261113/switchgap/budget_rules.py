"""SwitchRules with the control plane's read budget (offline emulation of overload).

Identical to p4_ebpf/live_test/package_cohort.SwitchRules.run except in read(w): when more buckets are active
than `budget`, only the `budget` most recently changed ones are read (ties by key), as the live collector's
budgeted reader selects (RUNBOOK 11/13: most recently reported or changed first). Unread buckets are not
counted in the window and keep their previous read, so their deltas carry over to the read that reaches them.
Expired buckets are cleared whether read or not (the live collector's --clear-expired). Measured capacity of
the raw-wire batched reader on the Wedge: ~750-880 buckets per 0.5 s read (RUNBOOK 12); 350 is the slower
sync+shadow route.
"""
import sys
from decimal import Decimal

sys.path.insert(0, "/home/ali/Desktop/Hazim/p4_ebpf/live_test")
import package_cohort as PC  # noqa: E402


class BudgetRules(PC.SwitchRules):
    def __init__(self, release, window_seconds, windows, rules=PC.RULES, budget=None, **kw):
        super().__init__(release, window_seconds, windows, rules=rules, **kw)
        self.budget = budget
        self.overloaded_windows = 0
        self.skipped_reads = 0

    def run(self, records, start_us):
        r = self.rules
        buckets, order, last_change, prev = {}, {}, {}, {}
        out, current = [], 0
        mask = (1 << 32) - 1

        def read(w):
            rows = sorted(last_change) if "key" in r else [k for k in order if k in last_change]
            active = [k for k in rows if 0 <= w - last_change[k] <= self.ttl]
            rows = active
            if self.budget is not None and len(active) > self.budget:
                self.overloaded_windows += 1
                rank = sorted(active, key=lambda k: -last_change[k])  # stable: ties keep key order
                keep = set(rank[:self.budget])
                rows = [k for k in active if k in keep]
                self.skipped_reads += len(active) - len(rows)
            feats = dict.fromkeys(self.sm.FEATURES, 0)
            if rows:
                mins, maxs, durs = [], [], []
                tot = dict.fromkeys(("p", "b", "pa", "ba_", "pb", "bb", "syn", "ack", "rst"), 0)
                for k in rows:
                    s, q = buckets[k], prev.get(k)
                    pkts_ba, bytes_ba = max(0, s["pkts"] - s["pkts_ab"]), max(0, s["bytes"] - s["bytes_ab"])
                    if q is None:
                        q = {"pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0, "syn": 0, "ack": 0, "rst": 0}
                    q_pba, q_bba = max(0, q["pkts"] - q["pkts_ab"]), max(0, q["bytes"] - q["bytes_ab"])
                    tot["p"] += max(0, s["pkts"] - q["pkts"])
                    tot["b"] += max(0, s["bytes"] - q["bytes"])
                    tot["pa"] += max(0, s["pkts_ab"] - q["pkts_ab"])
                    tot["ba_"] += max(0, s["bytes_ab"] - q["bytes_ab"])
                    tot["pb"] += max(0, pkts_ba - q_pba)
                    tot["bb"] += max(0, bytes_ba - q_bba)
                    for flag in ("syn", "ack", "rst"):
                        tot[flag] += max(0, s[flag] - q[flag])
                    mins.append(s["min_len"]); maxs.append(s["max_len"])
                    if "time" in r:
                        durs.append(((s["last_ts"] - s["first_ts"]) % (1 << 32)) / 1e9)
                    else:
                        durs.append(max(s["last_ts"] - s["first_ts"], 0.0))
                    feats["net_flows_with_ab"] += int(s["pkts_ab"] > 0 or s["bytes_ab"] > 0)
                    feats["net_flows_with_ba"] += int(pkts_ba > 0 or bytes_ba > 0)
                    feats["net_dir_valid_count"] += 1
                    prev[k] = dict(s)
                ws = self.window_seconds
                p, b, pa, ba, pb, bb = tot["p"], tot["b"], tot["pa"], tot["ba_"], tot["pb"], tot["bb"]
                feats.update({
                    "net_flow_count_seen": len(rows), "net_pkts_total_delta": p, "net_bytes_total_delta": b,
                    "net_pkts_ab_delta": pa, "net_bytes_ab_delta": ba, "net_pkts_ba_delta": pb, "net_bytes_ba_delta": bb,
                    "net_syn_delta": tot["syn"], "net_ack_delta": tot["ack"], "net_rst_delta": tot["rst"],
                    "net_min_len_mean": sum(mins) / len(mins), "net_max_len_mean": sum(maxs) / len(maxs),
                    "net_min_len_min": min(mins), "net_max_len_max": max(maxs),
                    "net_avg_pkt_size_delta": b / p if p else 0.0,
                    "net_avg_pkt_size_ab_delta": ba / pa if pa else 0.0,
                    "net_avg_pkt_size_ba_delta": bb / pb if pb else 0.0,
                    "net_flow_duration_mean": sum(durs) / len(durs), "net_flow_duration_max": max(durs),
                    "net_bytes_per_sec_delta": b / ws, "net_pkts_per_sec_delta": p / ws,
                    "net_down_up_ratio_delta": bb / ba if ba else 0.0,
                    "net_ab_ratio_pkt_delta": pa / p if p else 0.0, "net_ba_ratio_pkt_delta": pb / p if p else 0.0,
                    "net_ab_ratio_byte_delta": ba / b if b else 0.0, "net_ba_ratio_byte_delta": bb / b if b else 0.0,
                })
            if "idle" in r:
                for k in active:  # expired buckets are cleared whether read in this window or not
                    if w - last_change[k] >= self.idle:
                        del buckets[k], last_change[k]
                        prev.pop(k, None)
            return feats

        for sec, usec, _orig, frame in records:
            t_us = sec * 1_000_000 + usec
            offset = t_us - start_us
            if offset < 0 or offset // self.window_us >= self.windows:
                continue
            w = offset // self.window_us
            while current < w:
                out.append(read(current)); current += 1
            p = self.parse(frame)
            if p is None:
                continue
            key, src, ports, proto, flags, length = p
            s = buckets.get(key)
            if s is None:
                ts0 = (t_us * 1000) & mask if "time" in r else float(Decimal(sec) + Decimal(usec).scaleb(-6))
                s = buckets[key] = {"pkts": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0, "syn": 0, "ack": 0, "rst": 0,
                                    "min_len": length, "max_len": length, "first_ts": ts0, "last_ts": ts0,
                                    "ref_src": src, "ref_ports": ports}
                order.setdefault(key, None)
                ab = True
            elif "direction" in r:
                ref = s["ref_ports"]
                ab = not (ports != ref and ports == (ref[1], ref[0]))
            else:
                ab = src == s["ref_src"]
            ts = (t_us * 1000) & mask if "time" in r else float(Decimal(sec) + Decimal(usec).scaleb(-6))
            s["pkts"] += 1
            s["bytes"] += length
            if ab:
                s["pkts_ab"] += 1
                s["bytes_ab"] += length
            s["syn"] += int(bool(flags & 0x002))
            s["ack"] += int(bool(flags & 0x010))
            s["rst"] += int(bool(flags & 0x004))
            s["min_len"] = min(s["min_len"], length)
            s["max_len"] = max(s["max_len"], length)
            s["last_ts"] = ts
            last_change[key] = w
        while current < self.windows:
            out.append(read(current)); current += 1
        return out
