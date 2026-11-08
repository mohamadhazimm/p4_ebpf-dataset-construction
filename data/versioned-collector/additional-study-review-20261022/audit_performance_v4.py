"""Saved-only V4 audit: inherited independent V2 evidence/performance gates plus raw per-case probe recovery.

Probe recovery is re-derived here with Scapy, separately from the guest's own struct parser, and bound to the
recorded telemetry windows and observation clocks rather than to the guest's computed window.
"""

import argparse
import ast
import csv
import datetime
import inspect
import io
import json
from decimal import Decimal
from pathlib import Path

import audit_performance_v2 as frozen
import run_performance_v4 as version


FROZEN_SHA256 = "272ddebf33498433d125dee4ec174887a588538993e2e50e05f6109576d81327"
SINK = ("10.0.0.1", 80)
SLACK_NS = 1_000_000_000
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
require = frozen.require


def utc_ns(text):
    moment = datetime.datetime.fromisoformat(text)
    require(moment.tzinfo is not None, "Naive telemetry timestamp")
    delta = moment - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def frames(content):
    from scapy.layers.inet import IP, TCP
    from scapy.utils import PcapReader

    result = []
    with PcapReader(io.BytesIO(content)) as reader:
        for packet in reader:
            frame = {"ns": int(Decimal(str(packet.time)) * 1_000_000_000), "tcp": IP in packet and TCP in packet}
            if frame["tcp"]:
                frame.update(src=packet[IP].src, dst=packet[IP].dst, sport=packet[TCP].sport,
                             dport=packet[TCP].dport, flags=int(packet[TCP].flags))
            result.append(frame)
    return result


def audit_probe(metadata, saved, pcap, telemetry):
    probe = metadata.get("capture_path_probe")
    require(probe is not None and probe == saved, "Probe summary missing or differs from saved probe file")
    require(probe["status"] == "recovered" and probe["findings"] == [] and probe["target"] == "%s:%d" % SINK,
            "Guest probe status not recovered")
    rows = list(csv.DictReader(io.StringIO(telemetry)))
    require(len(rows) == 40, "Telemetry window count differs")
    start, end = utc_ns(rows[0]["window_start_utc"]), utc_ns(rows[-1]["window_end_utc"])
    require(start < end, "Telemetry window bounds invalid")
    parsed = frames(pcap)
    result, ports = {}, []
    for phase in ("pre", "post"):
        record = probe["probes"][phase]
        port = record["local_port"]
        require(type(port) is int and 0 < port < 65536, "Probe local port invalid: " + phase)
        ports.append(port)
        low, high = record["started_wall_ns"] - SLACK_NS, record["ended_wall_ns"] + SLACK_NS
        flow = [frame for frame in parsed if frame["tcp"] and (
            (frame["sport"] == port and frame["dst"] == SINK[0] and frame["dport"] == SINK[1])
            or (frame["src"] == SINK[0] and frame["sport"] == SINK[1] and frame["dport"] == port))]
        syn = [frame for frame in flow if frame["sport"] == port and frame["flags"] & 0x02
               and not frame["flags"] & 0x10 and low <= frame["ns"] <= high]
        reply = [frame for frame in flow if frame["sport"] == SINK[1] and low <= frame["ns"] <= high
                 and ((frame["flags"] & 0x12) == 0x12 or frame["flags"] & 0x04)]
        inside = [frame for frame in flow if start <= frame["ns"] < end]
        require(syn and reply and not inside, "Probe not independently recovered outside feature windows: " + phase)
        if phase == "pre":
            require(record["ended_wall_ns"] < start
                    and record["ended_monotonic_ns"] < metadata["sample_started_monotonic_ns"],
                    "Pre probe does not precede the feature windows and sample start")
        else:
            require(record["started_wall_ns"] >= end
                    and record["started_monotonic_ns"] >= metadata["observation_ended_monotonic_ns"],
                    "Post probe does not follow the feature windows and observation end")
        guest = probe["recovery"][phase]
        require(guest["recovered"] and guest["local_port"] == port and guest["outbound_syn"] == len(syn)
                and guest["sink_reply"] == len(reply) and guest["frames_inside_feature_windows"] == 0,
                "Guest probe counts differ from independent recovery: " + phase)
        result[phase] = {"local_port": port, "outbound_syn": len(syn), "sink_reply": len(reply),
                         "connected": record.get("connected"), "flow_frames": len(flow)}
    require(ports[0] != ports[1], "Pre and post probes reuse one local port")
    in_window = sum(1 for frame in parsed if start <= frame["ns"] < end)
    result.update(pcap_frames=len(parsed), in_window_frames=in_window, quiet_in_window=in_window == 0)
    return result


def audit(attempt):
    require(version.identity.digest(frozen.__file__) == FROZEN_SHA256, "Frozen independent V2 auditor changed")
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(protocol["schema"] == version.performance.SCHEMA and protocol["capture_path_probes_per_sensor_case"] == 2
            and protocol["original_quality_function_unchanged"] and protocol["helper_transactions"] == 0
            and not protocol["automatic_retry_authorized"] and not protocol["malware_launch_authorized"],
            "V4 authorization/schema differs")
    tree = ast.parse(inspect.getsource(frozen.audit))
    namespace = {**vars(frozen), "version": version}
    exec(compile(tree, "<independent-v4-saved-audit>", "exec"), namespace)
    result = namespace["audit"](attempt)
    manifest = json.loads((attempt / "manifest.json").read_text())
    evidence = frozen.original.members(attempt / "evidence.tgz", 2 * 1024 * 1024 * 1024)
    directories = sorted(name.rsplit("/", 1)[0] for name in evidence if name.endswith("/run.json"))
    probes = []
    for index, directory in enumerate(directories):
        case = manifest["cases"][index]
        metadata = json.loads(evidence[directory + "/run.json"])
        probe_name = directory + "/" + version.performance.PROBE_FILE
        if case["condition"] == "baseline":
            require(probe_name not in evidence and "capture_path_probe" not in metadata, "Baseline unexpectedly probed")
            continue
        measured = index < result["accepted_measurements"]
        pcaps = [content for name, content in evidence.items() if name.startswith(directory + "/") and name.endswith(".pcap")]
        try:
            require(probe_name in evidence and len(pcaps) == 1, "Probe file or PCAP missing")
            row = audit_probe(metadata, json.loads(evidence[probe_name]), pcaps[0],
                              evidence[directory + "/telemetry.csv"].decode())
        except (ValueError, KeyError) as error:
            # Only the preserved failed final case may lack valid probe evidence.
            require(not measured and index == len(directories) - 1, "Accepted measurement lacks recovered probes")
            row = {"failed_final_case_probe_error": str(error)}
        probes.append({"position": index, "condition": case["condition"], "task": case["task"],
                       "abi": case["abi"], "accepted_measurement": measured, **row})
    recovered = [row for row in probes if "failed_final_case_probe_error" not in row]
    result.update(
        status=result["status"].replace("independently_audited", "probe_bracketed_independently_audited"),
        capture_path_probes=probes, probed_cases_recovered=len(recovered),
        quiet_in_window_cases=sum(1 for row in recovered if row["quiet_in_window"]),
        auditor_sha256=version.identity.digest(__file__), inherited_auditor_sha256=FROZEN_SHA256,
        probe_negative_guards=self_test_probe(),
        probe_limitation="Recovered pre/post probes show this case's tcpdump captured real enp0s3 traffic just before and "
                         "after the feature windows. They do not prove continuous in-window completeness.")
    return result


def self_test_probe():
    import tempfile

    performance = version.performance
    start = 1_800_000_000_000_000_000
    end = start + 20_000_000_000
    stamp = lambda ns: datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc).isoformat()
    header = "window_start_utc,window_end_utc\n"
    telemetry = header + "".join(stamp(start + i * 500_000_000) + "," + stamp(start + (i + 1) * 500_000_000) + "\n"
                                 for i in range(40))

    def flow(port, at, reply=0x12):
        return [(at, performance.tcp_frame("10.0.0.10", "10.0.0.1", port, 80, 0x02)),
                (at + 300_000, performance.tcp_frame("10.0.0.1", "10.0.0.10", 80, port, reply)),
                (at + 400_000, performance.tcp_frame("10.0.0.10", "10.0.0.1", port, 80, 0x04))]

    pre = {"local_port": 40001, "connected": True, "started_wall_ns": start - 400_000_000,
           "ended_wall_ns": start - 390_000_000, "started_monotonic_ns": 100, "ended_monotonic_ns": 200}
    post = {"local_port": 40002, "connected": True, "started_wall_ns": end + 10_000_000,
            "ended_wall_ns": end + 20_000_000, "started_monotonic_ns": 30_000, "ended_monotonic_ns": 31_000}
    metadata_base = {"sample_started_monotonic_ns": 1_000, "observation_ended_monotonic_ns": 21_000}

    def build(packets, probes, nanosecond=False):
        with tempfile.TemporaryDirectory(prefix="hazim-audit-v4-") as directory:
            path = Path(directory) / "packet_capture.pcap"
            performance.write_pcap(path, sorted(packets), nanosecond)
            content = path.read_bytes()
            performance.PROBES.clear()
            performance.PROBES.update(probes)
            metadata = dict(metadata_base)
            performance.probe_quality(directory, metadata, True, start / 1e9, 0.5, [{}] * 40, "accepted", [])
            saved = json.loads((Path(directory) / performance.PROBE_FILE).read_text())
        performance.PROBES.clear()
        return metadata, saved, content

    good = flow(40001, pre["started_wall_ns"] + 1000) + flow(40002, post["started_wall_ns"] + 1000)
    metadata, saved, content = build(good, {"pre": pre, "post": post})
    accepted = audit_probe(metadata, saved, content, telemetry)
    require(accepted["quiet_in_window"] and accepted["pre"]["outbound_syn"] == 1, "Quiet bracketed fixture rejected")
    metadata, saved, content = build(good + [(start + 5_000_000_000, performance.tcp_frame("10.0.0.10", "10.0.0.1", 50000, 53, 0x02))],
                                     {"pre": pre, "post": post}, True)
    require(audit_probe(metadata, saved, content, telemetry)["in_window_frames"] == 1, "Ambient in-window frame not counted")
    rejected = []
    cases = {
        "summary_differs": lambda m, s, c: (m, {**s, "status": "other"}, c),
        "guest_status_rejected": lambda m, s, c: ({**m, "capture_path_probe": {**s, "status": "rejected"}}, {**s, "status": "rejected"}, c),
        "pre_after_sample_start": lambda m, s, c: ({**m, "sample_started_monotonic_ns": 150}, s, c),
        "post_before_observation_end": lambda m, s, c: ({**m, "observation_ended_monotonic_ns": 40_000}, s, c),
        "missing_summary": lambda m, s, c: ({}, s, c),
    }
    metadata, saved, content = build(good, {"pre": pre, "post": post})
    for name, mutate in cases.items():
        try:
            audit_probe(*mutate(metadata, saved, content), telemetry)
        except (ValueError, KeyError):
            rejected.append(name)
    # Raw-PCAP mutations: the guest summary still claims recovery, the independent parse must not agree.
    for name, packets in {"no_post_reply": flow(40001, pre["started_wall_ns"] + 1000) + flow(40002, post["started_wall_ns"] + 1000)[:1],
                          "no_pre_syn": flow(40001, pre["started_wall_ns"] + 1000)[1:] + flow(40002, post["started_wall_ns"] + 1000),
                          "probe_frame_inside": good + [(start + 1_000_000, performance.tcp_frame("10.0.0.1", "10.0.0.10", 80, 40001, 0x11))],
                          "empty": []}.items():
        _metadata, _saved, mutated = build(packets, {"pre": pre, "post": post})
        try:
            audit_probe(metadata, saved, mutated, telemetry)
        except (ValueError, KeyError):
            rejected.append(name)
    try:
        same_port = dict(post, local_port=40001)
        metadata_same, saved_same, content_same = build(flow(40001, pre["started_wall_ns"] + 1000)
                                                        + flow(40001, post["started_wall_ns"] + 1000), {"pre": pre, "post": same_port})
        audit_probe(metadata_same, saved_same, content_same, telemetry)
    except (ValueError, KeyError):
        rejected.append("reused_port")
    expected = list(cases) + ["no_post_reply", "no_pre_syn", "probe_frame_inside", "empty", "reused_port"]
    require(rejected == expected, "Probe negative guard did not reject: " + str(sorted(set(expected) - set(rejected))))
    return rejected


def self_test():
    require(version.identity.digest(frozen.__file__) == FROZEN_SHA256, "Frozen auditor changed")
    frozen.self_test()
    rows = [{**case, "usage": {"wall_ns": 100, "user_seconds": .1, "system_seconds": .01},
             "recorder_usage": {"peak_rss_kib": 1024}} for case in version.gate.plan()]
    require(frozen.summary(rows, version.gate.approved_contract()["performance_limits"])["performance_accepted"],
            "Complete local fixture rejected")
    guards = self_test_probe()
    print("PASS independent V4 binding, inherited incomplete/lifecycle/performance guards and %d Scapy probe-recovery "
          "negative guards; SIMULATED only" % len(guards))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    self_test()
    if options.attempt:
        attempt = options.attempt.resolve()
        result = audit(attempt)
        output = attempt / ("audit-v4-derived-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        version.identity.save(output, result)
        print(output)
        print(json.dumps({key: result[key] for key in ("status", "performance_accepted", "collection_ready", "actual_cases",
                                                       "accepted_measurements", "probed_cases_recovered",
                                                       "quiet_in_window_cases", "first_failing_pair")}, indent=2))
