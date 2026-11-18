"""Offline analysis of a socket-ownership live check (run_sockowner_check.py output). No VM.

Ground truth: every client wrote a receipt for each flow it opened (its own local port, the remote
end, its process and the process that created the socket). Measured:
  1. coverage: share of the clients' flows in the capture that sockowner saw on a socket;
  2. correctness: share attributed to the right cgroup, and to the process that created the socket;
  3. timing: sockowner's sighting vs the flow's first packet in the capture;
  4. what else was on the wire, and who owned it;
  5. window-level vs socket-level join: per client cgroup, the 29 window features of the switch
     model (40 windows of 0.5 s) from (a) every packet, (b) the flows sockowner gives that cgroup,
     (c) the flows of that client's receipts; (b) should equal (c) and (a) should not.

  /usr/bin/python3 analyze_sockowner_check.py runs/<attempt>
"""
import collections
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HAZIM = HERE.parents[5]
sys.path.insert(0, str(HAZIM / "p4_ebpf"))
sys.path.insert(0, str(HAZIM / "p4-ebpf-malware-detection" / "features"))
import sockjoin as sj  # noqa: E402
import summary  # noqa: E402
import switch_model as sm  # noqa: E402

CGROUP_OF = {"c1a": "c1", "c1b": "c1", "c2": "c2", "c3": "c3", "c4": "c4", "c5": "c5", "c6": "c6"}


def receipts(attempt):
    out = []
    for path in sorted(attempt.glob("receipts-*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


def capture_flows(pcap):
    flows = {}
    for time_us, _, frame in sm.read_pcap(str(pcap)):
        packet = sm.parse_flow_packet(frame)
        if packet is None:
            continue
        source, destination, protocol, ports, _ = packet
        key = sj.flow_key(protocol, source, ports[0], destination, ports[1])
        first, count = flows.get(key, (time_us, 0))
        flows[key] = (min(first, time_us), count + 1)
    return flows


def main():
    attempt = Path(sys.argv[1]).resolve()
    log = sj.read_log(str(attempt / "sockowner.log"))
    table = sj.OwnerTable(log)
    text = (attempt / "cgroups.json").read_text() if (attempt / "cgroups.json").exists() else ""
    cgroups = json.loads(text) if text.strip() else {}
    clocks = json.loads((attempt / "clocks.json").read_text())
    offset_ns = int(statistics.median(m - w for w, m in clocks))  # monotonic = wall + offset
    recs = receipts(attempt)
    flows = capture_flows(attempt / "capture.pcap")
    if not any(r["client"] == "c6" for r in recs):
        # The raw client's receipts were not readable (written by root under sudo's umask 077): its ground
        # truth is its design instead: TCP SYNs from local ports 36000-36199 to the Sink's port 65004.
        for key, (first_us, _) in flows.items():
            proto, a, b = key
            local = a if a[0] == "10.0.0.10" else b
            remote = b if local is a else a
            if proto == 6 and 36000 <= local[1] <= 36199 and remote == ("10.0.0.1", 65004):
                recs.append({"client": "c6", "mode": "raw", "proto": 6, "laddr": local[0], "lport": local[1],
                             "raddr": remote[0], "rport": remote[1], "pid": None, "owner_pid": None,
                             "t_wall_ns": first_us * 1000, "from_design": True})
        res_design = True
    else:
        res_design = False
    res = {"attempt": str(attempt), "kernel": (attempt / "kernel.txt").read_text().strip()
           if (attempt / "kernel.txt").exists() else None,
           "sockowner_health": log.health, "sockowner_malformed_lines": log.malformed,
           "sockets_seen": len(log.sockets), "flow_sightings": len(log.sightings),
           "capture_flows": len(flows), "receipts": len(recs)}

    # 1-3: per client flow
    truth = {}
    for r in recs:
        key = sj.flow_key(r["proto"], r["laddr"], r["lport"], r["raddr"], r["rport"])
        truth.setdefault(key, r)
    per_client = collections.defaultdict(lambda: collections.Counter())
    seen_cgroups = collections.defaultdict(collections.Counter)
    lat = []
    wrong = []
    for key, r in truth.items():
        c = per_client[r["client"]]
        c["flows"] += 1
        if key not in flows:
            c["not_in_capture"] += 1
            continue
        c["in_capture"] += 1
        first_us = flows[key][0]
        at = first_us * 1000 + offset_ns
        s = table.owner(key, at, slack_ns=50_000_000)
        if s is None:
            c["unattributed"] += 1
            wrong.append({"client": r["client"], "key": key, "why": "no sighting"})
            continue
        c["attributed"] += 1
        seen_cgroups[r["client"]][s.cgroup_id] += 1
        if cgroups:
            if s.cgroup_id == cgroups[CGROUP_OF[r["client"]]]:
                c["cgroup_correct"] += 1
            else:
                wrong.append({"client": r["client"], "key": key, "why": "cgroup %s" % s.cgroup_id})
        sock = table.process(s)
        if sock is None:
            c["no_socket_event"] += 1
        elif r["owner_pid"] is None:
            c["process_not_known"] += 1
        elif sock.tgid == r["owner_pid"]:
            c["process_correct"] += 1
        else:
            c["process_wrong"] += 1
            wrong.append({"client": r["client"], "key": key, "why": "tgid %s vs %s" % (sock.tgid, r["owner_pid"])})
        lat.append((s.ts_ns - at) / 1e6)
    if not cgroups:
        # No cgroup ids from the guest: check the partition instead. Each client's flows must map to one
        # cgroup, c1a and c1b to the same one, every other client to its own; then count flows on the
        # cgroup that holds the client's majority.
        majority = {cl: cnt.most_common(1)[0][0] for cl, cnt in seen_cgroups.items() if cnt}
        for cl, cnt in seen_cgroups.items():
            per_client[cl]["cgroup_correct"] = cnt[majority[cl]]
        groups = collections.defaultdict(set)
        for cl, cg in majority.items():
            groups[CGROUP_OF[cl]].add(cg)
        distinct = len({next(iter(v)) for v in groups.values() if len(v) == 1}) == len(groups)
        res["cgroup_partition"] = {"per_client_cgroups": {cl: dict(cnt) for cl, cnt in seen_cgroups.items()},
                                   "one_cgroup_per_designed_group": all(len(v) == 1 for v in groups.values()),
                                   "designed_groups_distinct": distinct}
        cgroups = {name: next(iter(v)) for name, v in groups.items() if len(v) == 1}
        res["cgroup_ids_from"] = "partition of sockowner's sightings (cgroups.json unreadable in the guest)"
    res["c6_truth_from_design"] = res_design
    total = collections.Counter()
    for c in per_client.values():
        total.update(c)
    res["per_client"] = {k: dict(v) for k, v in sorted(per_client.items())}
    res["total"] = dict(total)
    res["coverage"] = total["attributed"] / total["in_capture"] if total["in_capture"] else None
    res["cgroup_accuracy"] = total["cgroup_correct"] / total["in_capture"] if total["in_capture"] else None
    res["process_accuracy_where_socket_seen"] = (total["process_correct"] /
                                                 (total["process_correct"] + total["process_wrong"])
                                                 if total["process_correct"] + total["process_wrong"] else None)
    res["sighting_minus_first_packet_ms"] = ({"median": statistics.median(lat), "min": min(lat), "max": max(lat),
                                              "p99": sorted(lat)[int(0.99 * (len(lat) - 1))]} if lat else None)
    res["errors_sample"] = [dict(e, key=str(e["key"])) for e in wrong[:30]]

    # 4: other flows on the wire
    others = collections.Counter()
    for key, (first_us, count) in flows.items():
        if key in truth:
            continue
        s = table.owner(key, first_us * 1000 + offset_ns, slack_ns=50_000_000)
        sock = table.process(s)
        owner = "unattributed" if s is None else (sock.comm if sock else "cgroup %s" % s.cgroup_id)
        others[(key[0], owner, str(key[1:]) if s is None else "")] += 1
    res["other_capture_flows"] = {" ".join(str(x) for x in k if x != ""): n for k, n in sorted(others.items())}

    # 5: window vs socket join per client cgroup
    t0_us = min(r["t_wall_ns"] for r in recs) // 1000 - 500_000
    all_windows = sm.window_features(str(attempt / "capture.pcap"), t0_us)
    keys_by_cgroup = collections.defaultdict(set)
    for key, r in truth.items():
        keys_by_cgroup[CGROUP_OF[r["client"]]].add(key)
    join = {}
    for name in sorted(keys_by_cgroup):
        truth_keys = keys_by_cgroup[name]
        want = sj.window_features_selected(sm, str(attempt / "capture.pcap"), t0_us, lambda k, t: k in truth_keys)
        got = sj.window_features_selected(sm, str(attempt / "capture.pcap"), t0_us,
                                          sj.packet_filter(table, sj.Selector(cgroup_ids={cgroups[name]}), offset_ns))
        equal_socket = sum(w == g for w, g in zip(want, got))
        equal_window = sum(w == a for w, a in zip(want, all_windows))
        vec_want = summary.summarize(want, sm.FEATURES)
        vec_got = summary.summarize(got, sm.FEATURES)
        vec_all = summary.summarize(all_windows, sm.FEATURES)
        join[name] = {"windows": len(want), "socket_join_windows_equal_truth": equal_socket,
                      "window_join_windows_equal_truth": equal_window,
                      "socket_join_vector_equal_truth": vec_want == vec_got,
                      "window_join_vector_equal_truth": vec_want == vec_all,
                      "socket_join_columns_differing": sum(vec_want[k] != vec_got[k] for k in vec_want),
                      "window_join_columns_differing": sum(vec_want[k] != vec_all[k] for k in vec_want),
                      "truth_packets": sum(w["net_pkts_total_delta"] for w in want),
                      "socket_join_packets": sum(w["net_pkts_total_delta"] for w in got),
                      "window_join_packets": sum(w["net_pkts_total_delta"] for w in all_windows)}
    res["window_vs_socket_join"] = join
    # process-level selection inside one cgroup (c1 holds two processes)
    pids = {r["client"]: r["owner_pid"] for r in recs if r["client"] in ("c1a", "c1b") and r["owner_pid"]}
    proc = {}
    for client, pid in sorted(pids.items()):
        truth_keys = {k for k, r in truth.items() if r["client"] == client}
        want = sj.window_features_selected(sm, str(attempt / "capture.pcap"), t0_us, lambda k, t: k in truth_keys)
        got = sj.window_features_selected(sm, str(attempt / "capture.pcap"), t0_us,
                                          sj.packet_filter(table, sj.Selector(tgids={pid}), offset_ns))
        proc[client] = {"windows_equal_truth": sum(w == g for w, g in zip(want, got)), "windows": len(want)}
    res["process_level_join_in_shared_cgroup"] = proc
    # 6: per-datagram cost of the tracer (udp_send_bench: one 5-tuple, 200,000 datagrams per run)
    bench_path = attempt / "bench.jsonl"
    if bench_path.exists():
        runs = collections.defaultdict(list)
        for line in bench_path.read_text().splitlines():
            if line.strip():
                b = json.loads(line)
                runs[b["label"]].append(b["ns_per_send"])
        off = runs.get("off-before", []) + runs.get("off-after", [])
        res["udp_send_ns_per_datagram"] = {k: {"runs": v, "median": statistics.median(v)} for k, v in runs.items()}
        if off and runs.get("on"):
            res["tracer_cost_ns_per_datagram"] = statistics.median(runs["on"]) - statistics.median(off)
    out = attempt / "analysis.json"
    out.write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps({k: res[k] for k in ("sockowner_health", "capture_flows", "receipts", "coverage",
                                          "cgroup_accuracy", "process_accuracy_where_socket_seen",
                                          "sighting_minus_first_packet_ms", "total")}, indent=1, default=str))
    print(json.dumps(join, indent=1))
    print(json.dumps(proc, indent=1))
    print(json.dumps(res["other_capture_flows"], indent=1))
    print(json.dumps({k: res.get(k) for k in ("udp_send_ns_per_datagram", "tracer_cost_ns_per_datagram")}, indent=1))


if __name__ == "__main__":
    main()
