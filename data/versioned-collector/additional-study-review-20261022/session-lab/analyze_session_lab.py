#!/usr/bin/env python3
"""Session lab analysis (offline): pilot checks per session, and per-window features for the comparisons.

Per session (sessions/<sid>/ of an attempt):
  capture   tcpdump on the Sink: received = captured, no drops; packets inside the session;
  clocks    the guest's clock probes (3 before t0, 3 after the end) in the Sink's capture: offset of the Sink's
            capture clock against the guest's monotonic clock, its spread and its drift over the session;
  host      both monitors (app-a background, app-b injected): windows recorded, rows, health lines;
  flows     every IPv4 TCP/UDP 5-tuple of the guest seen by the Sink during the session, matched to the socket
            tracer's FLOW records: attributed to app-a, app-b, another cgroup, or nobody;
  injected  the injected program: first window with host activity, its flows (answered or not, destinations,
            first contact after the injection).
Features (--features): per 0.5-s window, the 18 host features (release host_model.combine) and the 29 switch
features (release switch_model FlowTable), for the whole machine (both cgroups, all traffic) and for the injected
program alone (its cgroup's rows, its own flows).

  /usr/bin/python3 analyze_session_lab.py <attempt> [--features]
"""
import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab  # noqa: E402

sys.path.insert(0, str(lab.RELEASE / "features"))
import host_model as hm      # noqa: E402
import switch_model as sm    # noqa: E402

GUEST_IP, SINK_IP = lab.GUEST_IP, lab.SINK_IP
WINDOW_US = 500_000


def flow_key(proto, a, ap, b, bp):
    return (proto, *sorted(((a, ap), (b, bp))))


def log_lines(path):
    """Lines of a monitor or tracer log, split at "\n" only. The monitors print raw process names (quoted), and a
    process may rename itself with characters that str.splitlines() also treats as line breaks (a Mirai sample in
    the rest run did, with a vertical tab), which would cut its rows in two."""
    return Path(path).read_bytes().decode(errors="replace").split("\n")


def sock_records(path):
    """sockowner output: cookie -> SOCK record, list of FLOW records, health line."""
    socks, flows, health = {}, [], None
    if not Path(path).is_file():
        return socks, flows, health
    for line in log_lines(path):
        parts = line.split(",")
        if parts[0] == "SOCK" and len(parts) >= 10:
            socks[parts[2]] = {"ns": int(parts[1]), "tgid": int(parts[3]), "cgroup": int(parts[5]),
                               "comm": ",".join(parts[9:])}
        elif parts[0] == "FLOW" and len(parts) == 10:
            proto = 6 if parts[5] == "tcp" else 17
            flows.append({"ns": int(parts[1]), "cookie": parts[2], "cgroup": int(parts[3]), "dir": parts[4],
                          "key": flow_key(proto, parts[6], int(parts[7]), parts[8], int(parts[9]))})
        elif parts[0] == "SOCKOWNER_HEALTH":
            health = line
    return socks, flows, health


def relayed_dns(socks, sflows, names, limit_ns=3_000_000_000):
    """DNS the guest's stub resolver (systemd-resolved, its own cgroup) sends on the wire for a program that asked
    127.0.0.53: each of the resolver's wire queries is given to the cgroup of the latest loopback query made at
    most limit_ns before it. Pilot: the resolver's query follows the program's by 0.5-1.5 ms, its retries by about
    2.5 s (s12); neither the background nor the benign tasks use the resolver (they connect to addresses)."""
    queries = sorted((f["ns"], f["cgroup"]) for f in sflows
                     if f["dir"] == "egress" and ("127.0.0.53", 53) in f["key"][1:] and f["cookie"] in socks
                     and not socks[f["cookie"]]["comm"].startswith("systemd-resolve"))
    out = {}
    for f in sflows:
        so = socks.get(f["cookie"])
        if so and so["comm"].startswith("systemd-resolve") and f["dir"] == "egress" and (SINK_IP, 53) in f["key"][1:]:
            prior = [q for q in queries if 0 <= f["ns"] - q[0] <= limit_ns]
            if prior:
                out[f["key"]] = names.get(prior[-1][1], "other:%d" % prior[-1][1])
    return out


def capture_flows(pcap, start_us, end_us):
    """Per 5-tuple of the guest inside [start_us, end_us): packets each way, bytes, first/last time, SYN-only."""
    flows = {}
    for time_us, _ts, frame in sm.read_pcap(str(pcap)):
        if not start_us <= time_us < end_us:
            continue
        p = sm.parse_flow_packet(frame)
        if p is None:
            continue
        src, dst, proto, ports, flags = p
        if GUEST_IP not in (src, dst):
            continue
        key = flow_key(proto, src, ports[0], dst, ports[1])
        f = flows.setdefault(key, {"out": 0, "in": 0, "bytes": 0, "first_us": time_us, "last_us": time_us,
                                   "remote": dst if src == GUEST_IP else src,
                                   "rport": ports[1] if src == GUEST_IP else ports[0]})
        f["out" if src == GUEST_IP else "in"] += 1
        f["bytes"] += len(frame)
        f["last_us"] = time_us
    return flows


def clock_map(pcap, sid):
    """Linear map from the guest's monotonic clock to the Sink's capture clock, from the 3 start and 3 end probes:
    capture_ns = mono_ns + offset + slope * (mono_ns - mono_start). Jitter within each set, drift between them."""
    probes = [p for p in lab.sync_probes(pcap) if p[1] == sid]
    by = defaultdict(list)
    for t_us, _sid, phase, _n, mono, _real in probes:
        by[phase].append((mono, t_us * 1000 - mono))
    out = {"probes": {k: len(v) for k, v in by.items()}}
    for phase in ("start", "end"):
        if by.get(phase):
            offs = [o for _, o in by[phase]]
            out["jitter_%s_ms" % phase] = (max(offs) - min(offs)) / 1e6
            out["%s_mono_ns" % phase] = statistics.median(m for m, _ in by[phase])
            out["%s_offset_ns" % phase] = statistics.median(offs)
    if "start_offset_ns" in out and "end_offset_ns" in out:
        span = out["end_mono_ns"] - out["start_mono_ns"]
        out["drift_ms"] = (out["end_offset_ns"] - out["start_offset_ns"]) / 1e6
        out["slope"] = (out["end_offset_ns"] - out["start_offset_ns"]) / span if span else 0.0
    return out


def to_capture_us(clocks, mono_ns):
    """The Sink capture time (us) of a guest monotonic time (ns), by the linear map."""
    offset = clocks["start_offset_ns"] + clocks.get("slope", 0.0) * (mono_ns - clocks["start_mono_ns"])
    return (mono_ns + offset) / 1000.0


def monitor(path, windows):
    lines = log_lines(path) if Path(path).is_file() else []
    text = "\n".join(lines)
    rows = hm.parse_monitor(lines, windows)
    health = [l for l in lines if l.startswith("HOSTMON_HEALTH")]
    return {"windows": text.count("==== HOST WINDOW"), "rows": sum(len(r) for r in rows),
            "active_windows": sum(1 for r in rows if r), "health": health[-1] if health else None}, rows


def session_report(attempt, protocol, s):
    sdir = Path(attempt) / "sessions" / s["sid"]
    g = sdir / "guest"
    rec = lab.load(sdir / "result.json")
    status, reasons = rec.get("status"), rec.get("checks", {}).get("reasons")
    if (sdir / "checks-recheck.json").is_file():      # the corrected probe check (s01 of the pilot)
        recheck = lab.load(sdir / "checks-recheck.json")["recheck"]
        status, reasons = ("accepted" if recheck["accepted"] else "rejected"), recheck["reasons"]
    out = {"sid": s["sid"], "kind": s["kind"], "name": s["name"], "status": status,
           "reasons": reasons, "capture": rec.get("capture", {}).get("counters"),
           "timings_s": rec.get("timings_s")}
    if not (g / "clock-start.json").is_file() or not (sdir / "sink.pcap").is_file():
        return out, None
    start = lab.load(g / "clock-start.json")
    clocks = clock_map(sdir / "sink.pcap", s["sid"])
    out["clocks"] = clocks
    windows = 2 * protocol["duration_s"]
    t0_us = to_capture_us(clocks, start["t0_mono_ns"])
    win_us = WINDOW_US * (1.0 + clocks.get("slope", 0.0))         # a 0.5-s guest window, in capture time
    end_us = t0_us + windows * win_us
    inj_us = to_capture_us(clocks, start["t0_mono_ns"] + int(round(s["t_inject_s"] * 1e9)))
    host_a, rows_a = monitor(g / "host-a.log", windows)
    host_b, rows_b = monitor(g / "host-b.log", windows)
    out["host"] = {"app-a": host_a, "app-b": host_b}
    first_b = next((w for w, r in enumerate(rows_b) if r), None)
    out["injected_first_host_window"] = first_b
    out["injection_window"] = int(s["t_inject_s"] // 0.5)
    cg = lab.load(g / "cgroups.json") if (g / "cgroups.json").is_file() else {}
    names = {v: k for k, v in cg.items()}
    socks, sflows, shealth = sock_records(g / "sock.log")
    out["sock_health"] = shealth
    owner = defaultdict(set)
    for f in sflows:
        if f["cookie"] in socks or f["cgroup"] != 1:   # the kernel's post-close (TIME_WAIT) packets: root cgroup,
            owner[f["key"]].add(names.get(f["cgroup"], "other:%d" % f["cgroup"]))   # no socket record
    for f in sflows:
        if f["key"] not in owner:
            owner[f["key"]].add(names.get(f["cgroup"], "other:%d" % f["cgroup"]))
    relayed = relayed_dns(socks, sflows, names)
    for key, who in relayed.items():
        owner[key] = {who}
    out["dns_relayed"] = dict(Counter(relayed.values()))
    flows = capture_flows(sdir / "sink.pcap", t0_us, end_us)
    groups = defaultdict(list)
    for key, f in flows.items():
        who = owner.get(key)
        label = "nobody" if not who else (sorted(who)[0] if len(who) == 1 else "several")
        groups[label].append(key)
    out["flows"] = {k: len(v) for k, v in groups.items()}
    out["unattributed_examples"] = [[k[0], k[1], k[2], flows[k]["out"], flows[k]["in"]]
                                    for k in groups.get("nobody", [])[:5]]
    mine = [flows[k] | {"key": k} for k in groups.get("app-b", [])]
    out["injected_flows"] = {
        "flows": len(mine), "answered": sum(1 for f in mine if f["in"] > 0),
        "dns_relayed": sum(1 for k in groups.get("app-b", []) if k in relayed),
        "packets_out": sum(f["out"] for f in mine), "packets_in": sum(f["in"] for f in mine),
        "remotes": sorted({f["remote"] for f in mine})[:12], "remote_count": len({f["remote"] for f in mine}),
        "ports": sorted({f["rport"] for f in mine})[:12],
        "first_contact_s": round((min(f["first_us"] for f in mine) - inj_us) / 1e6, 3) if mine else None,
        "flows_20s": sum(1 for f in mine if f["first_us"] < inj_us + 20e6),       # as long as a dataset run
        "answered_20s": sum(1 for f in mine if f["first_us"] < inj_us + 20e6 and f["in"] > 0)}
    bg = [flows[k] for k in groups.get("app-a", [])]
    out["background_flows"] = {"flows": len(bg), "answered": sum(1 for f in bg if f["in"] > 0),
                               "remotes": len({f["remote"] for f in bg})}
    procs = (g / "b-procs.txt").read_text().split("\n") if (g / "b-procs.txt").is_file() else []
    out["injected_alive_at_end"] = len([p for p in procs if p.strip()])
    data = {"t0_us": t0_us, "inj_us": inj_us, "win_us": win_us, "rows_a": rows_a, "rows_b": rows_b,
            "app_b_keys": set(groups.get("app-b", [])), "pcap": sdir / "sink.pcap", "windows": windows}
    return out, data


def network_windows(pcap, start_us, windows, keep=None, win_us=WINDOW_US):
    """The release switch model's 29 features per window (windows of win_us capture microseconds from start_us, a
    0.5-s guest window each); keep = only these 5-tuples (one program's flows)."""
    table = sm.FlowTable(0.5, 3)
    result, current = [], 0
    for time_us, timestamp, frame in sm.read_pcap(str(pcap)):
        offset = time_us - start_us
        if offset < 0 or int(offset // win_us) >= windows:
            continue
        window = int(offset // win_us)
        while current < window:
            result.append(table.read_window(current))
            current += 1
        p = sm.parse_flow_packet(frame)
        if p is None:
            continue
        src, dst, proto, ports, flags = p
        if keep is not None and flow_key(proto, src, ports[0], dst, ports[1]) not in keep:
            continue
        table.update(window, timestamp, src, dst, proto, ports, flags, len(frame))
    while current < windows:
        result.append(table.read_window(current))
        current += 1
    return result


def features(data):
    """Per-window host (18) and network (29) features for the machine and for the injected program."""
    w = data["windows"]
    machine_host = [hm.combine(a + b) for a, b in zip(data["rows_a"], data["rows_b"])]
    program_host = [hm.combine(b) for b in data["rows_b"]]
    machine_net = network_windows(data["pcap"], data["t0_us"], w, win_us=data["win_us"])
    program_net = network_windows(data["pcap"], data["t0_us"], w, keep=data["app_b_keys"], win_us=data["win_us"])
    return {"machine": {"host": machine_host, "net": machine_net}, "program": {"host": program_host, "net": program_net}}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("attempt")
    p.add_argument("--features", action="store_true")
    p.add_argument("--keep-going", action="store_true",
                   help="record a session that cannot be analysed (e.g. a rejected session without clock probes) "
                        "in analysis.json's 'errors' and go on; without it the first such session stops the run")
    a = p.parse_args()
    attempt = Path(a.attempt).resolve()
    protocol = lab.load(attempt / "protocol.json")
    reports, errors = [], []
    for s in protocol["sessions"]:
        if not (attempt / "sessions" / s["sid"] / "result.json").is_file():
            continue
        try:
            report, data = session_report(attempt, protocol, s)
        except Exception as error:
            if not a.keep_going:
                raise
            errors.append({"sid": s["sid"], "kind": s["kind"], "name": s["name"],
                           "error": "%s: %s" % (type(error).__name__, error)})
            print("%s %-8s %-18s not analysed: %s" % (s["sid"], s["kind"], s["name"][:18], errors[-1]["error"]))
            continue
        if a.features and data is not None:
            f = features(data)
            out = attempt / "sessions" / s["sid"] / "windows.json"
            out.write_text(json.dumps({"t0_us": data["t0_us"], "inj_us": data["inj_us"], "features": f}))
            report["windows_file"] = str(out.relative_to(attempt))
        reports.append(report)
        b = report.get("injected_flows", {})
        print("%s %-8s %-18s %-9s flows %-28s injected: host-win %s flows %s answered %s remotes %s first %s s" % (
            s["sid"], s["kind"], s["name"][:18], report["status"], json.dumps(report.get("flows", {})),
            report.get("injected_first_host_window"), b.get("flows"), b.get("answered"), b.get("remote_count"),
            b.get("first_contact_s")))
    out = {"sessions": reports}
    if a.keep_going:
        out["errors"] = errors
    lab.save(attempt / "analysis.json", out)
    print("wrote", attempt / "analysis.json", "(%d not analysed)" % len(errors) if a.keep_going else "")


if __name__ == "__main__":
    main()
