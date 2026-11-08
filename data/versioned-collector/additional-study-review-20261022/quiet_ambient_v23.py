"""Quiet-v2.3: quiet-v2.2 with a boot-trace audit that matches what a VirtualBox power-on NIC trace contains.

The first ever power-on trace (quiet-ambient-v2-2/20261024T133443341773Z, boot-01) showed three things the frozen
boot audit did not anticipate:
  1. VirtualBox writes a truncated 4-byte all-zero start record first (incl 4, orig 60, t=0). It is not an Ethernet
     frame and crashed the frozen classifier's description().
  2. Record timestamps are trace-relative (0..60 s), not wall clock, so the frozen check comparing the HTTP stream to
     the guest receipt's epoch nanoseconds cannot be satisfied.
  3. Normal IPv4 link-up appears in full: 3 RFC 5227 address probes (sender 0.0.0.0), 3 announcements 2 s apart
     (the strict rule allowed at most 2), and one IPv6 router solicitation sent by the Sink, not the guest.
This version keeps every frozen check and adds only these bounded, explicitly labelled allowances:
  * the VirtualBox start record, only as record 1 at t<1 s, exactly 4 zero bytes;
  * guest IPv4 conflict probes: ARP request from the pinned guest MAC to broadcast, sender 0.0.0.0, target 10.0.0.10,
    at most 3, all within 1 s, all before the first announcement;
  * guest announcements: the frozen rule extended from <=2 to <=3, same fields, 1.8-2.2 s spacing;
  * Sink IPv6 router solicitation: at most 3 ICMPv6 type-133 frames to ff02::2 whose source MAC is the MAC that answered
    ARP for 10.0.0.1 in the same capture and whose link-local source is that MAC's EUI-64 address.
The HTTP control is bound by trace-relative time instead: it must lie inside the trace, last no longer than the guest
receipt plus 1 s, and sit 0-15 s after the guest's own uptime (power-on to kernel start). Everything else is inherited.
"""

import argparse
import ast
import base64
import collections
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v22 as v22  # noqa: E402

v21, base, frozen, network, traffic = v22.v21, v22.base, v22.frozen, v22.network, v22.traffic
V22_SHA256 = "c175008819a02e9981c0b9a3c7b89c05f6d74810b5f3b0effa7e996605cee8a8"
VALIDATOR_SHA256 = "46db84e9dd6527c5f292fca8ddf56ea32416ae3c526480cda545fd73402aefb5"
FORMAT = "quiet-v2.3-multiboot-v1"
GUEST_MAC = traffic.GUEST_MAC
BROADCAST = "ff:ff:ff:ff:ff:ff"
frozen_classify = traffic.classify


def arp_fields(packet):
    if not isinstance(packet, traffic.Ether) or not isinstance(packet.payload, traffic.ARP):
        return None
    arp = traffic.ARP(bytes(packet[traffic.ARP]))
    return {"src": packet.src.lower(), "dst": packet.dst.lower(), "op": int(arp.op), "hwsrc": arp.hwsrc.lower(),
            "hwdst": arp.hwdst.lower(), "psrc": arp.psrc, "pdst": arp.pdst, "ptype": int(arp.ptype)}


def link_local(mac):
    octets = bytearray(int(part, 16) for part in mac.split(":"))
    octets[0] ^= 0x02
    return bytes.fromhex("fe80000000000000") + bytes(octets[:3]) + b"\xff\xfe" + bytes(octets[3:])


def sink_router_solicitation(packet, sink_mac):
    raw = bytes(packet)
    if sink_mac is None or len(raw) < 14 + 40 + 8 or raw[12:14] != b"\x86\xdd":
        return False
    header, icmp = raw[14:54], raw[54:]
    return (raw[6:12] == bytes.fromhex(sink_mac.replace(":", "")) and raw[0:6] == bytes.fromhex("333300000002")
            and header[0] >> 4 == 6 and header[6] == 58 and header[7] == 255
            and header[8:24] == link_local(sink_mac) and header[24:40] == bytes.fromhex("ff02" + "00" * 13 + "02")
            and icmp[0] == 133 and icmp[1] == 0)


def link_up_labels(parsed, guest_mac=GUEST_MAC):
    """1-based frame index -> label for the bounded boot link-up allowances, plus the reasons any bound failed."""
    labels, reasons = {}, []
    fields = [(index, packet, arp_fields(packet)) for index, packet in enumerate(parsed, 1)]
    common = lambda arp: (arp["src"] == arp["hwsrc"] == guest_mac and arp["dst"] == BROADCAST and arp["op"] == 1
                          and arp["hwdst"] == "00:00:00:00:00:00" and arp["ptype"] == 0x800)
    probes = [(index, packet) for index, packet, arp in fields
              if arp and arp["psrc"] == "0.0.0.0" and arp["pdst"] == traffic.GUEST]
    announces = [(index, packet) for index, packet, arp in fields
                 if arp and arp["psrc"] == arp["pdst"] == traffic.GUEST]
    if probes:
        times = [traffic.packet_ns(packet) for _index, packet in probes]
        if (len(probes) <= 3 and all(common(arp_fields(packet)) for _index, packet in probes)
                and max(times) - min(times) <= 1_000_000_000
                and (not announces or max(times) < traffic.packet_ns(announces[0][1]))):
            labels.update({index: "guest_ipv4_conflict_probe" for index, _packet in probes})
        else:
            reasons.append("guest_conflict_probes_outside_bounds")
    if announces:
        times = [traffic.packet_ns(packet) for _index, packet in announces]
        spacing = [later - earlier for earlier, later in zip(times, times[1:])]
        if (len(announces) <= 3 and all(common(arp_fields(packet)) for _index, packet in announces)
                and all(1_800_000_000 <= gap <= 2_200_000_000 for gap in spacing)):
            labels.update({index: "guest_self_announcement" for index, _packet in announces})
        else:
            reasons.append("guest_announcements_outside_bounds")
    sink_macs = {arp["hwsrc"] for _index, _packet, arp in fields
                 if arp and arp["op"] == 2 and arp["psrc"] == traffic.SINK and arp["src"] == arp["hwsrc"]}
    sink_mac = next(iter(sink_macs)) if len(sink_macs) == 1 else None
    solicitations = [index for index, packet in enumerate(parsed, 1) if sink_router_solicitation(packet, sink_mac)]
    if len(solicitations) <= 3:
        labels.update({index: "sink_ipv6_router_solicitation" for index in solicitations})
    else:
        reasons.append("sink_router_solicitations_outside_bounds")
    return labels, reasons


def classify(parsed, bounds, verified_probes=(), http=(), udp=(), guest_mac=GUEST_MAC):
    """Frozen classify, made total over non-Ethernet frames, plus the bounded link-up allowances."""
    ethernet = [(index, packet) for index, packet in enumerate(parsed, 1) if isinstance(packet, traffic.Ether)]
    result = frozen_classify([packet for _index, packet in ethernet], bounds, verified_probes, http, udp, guest_mac)
    rows = []
    for row in result["frames"]:
        row["frame"] = ethernet[row["frame"] - 1][0]
        rows.append(row)
    for index, packet in enumerate(parsed, 1):
        if not isinstance(packet, traffic.Ether):
            timestamp = traffic.packet_ns(packet)
            rows.append({"frame": index, "epoch_ns": timestamp, "category": "unexplained",
                         "in_window": any(start <= timestamp < end for start, end in bounds),
                         "protocol": "non-Ethernet record", "bytes": len(bytes(packet))})
    rows.sort(key=lambda row: row["frame"])
    labels, bound_reasons = link_up_labels(parsed, guest_mac)
    for row in rows:
        if row["frame"] in labels and row["category"] in ("unexplained", "guest_self_announcement"):
            row["category"] = labels[row["frame"]]
    unexplained = [row["frame"] for row in rows if row["in_window"] and row["category"] == "unexplained"]
    reasons = [reason for reason in result["reasons"] if reason != "unexplained_in_window_traffic"] + bound_reasons
    if unexplained:
        reasons.append("unexplained_in_window_traffic")
    by_source = collections.Counter(json.dumps({key: row[key] for key in row if key not in ("frame", "epoch_ns", "in_window")},
                                               sort_keys=True) for row in rows)
    return {**result, "accepted": not reasons, "reasons": reasons, "unexplained_in_window_frames": unexplained,
            "frames": rows, "by_source": dict(by_source),
            "categories": dict(collections.Counter(row["category"].split(":")[0] for row in rows))}


def trace_records(content):
    frozen.require(len(content) >= 24 and struct.unpack("<I", content[:4])[0] == 0xA1B2C3D4
                   and struct.unpack("<I", content[20:24])[0] == 1, "Boot trace is not a little-endian Ethernet pcap")
    offset, records = 24, []
    while offset < len(content):
        frozen.require(offset + 16 <= len(content), "Truncated pcap record header")
        seconds, micros, included, original = struct.unpack("<IIII", content[offset:offset + 16])
        frozen.require(offset + 16 + included <= len(content) and micros < 1_000_000, "Truncated or invalid pcap record")
        records.append((seconds * 1_000_000 + micros, included, original, content[offset + 16:offset + 16 + included]))
        offset += 16 + included
    return records


def audit_boot(directory, marker):
    receipt = frozen.load(directory / "control.json")
    trace = frozen.load(directory / "trace.json")
    frozen.require(trace["enabled_before_start"] is True and trace["stop_returncode"] == 0,
                   "Capture was not enabled before power-on or did not stop successfully")
    duration = trace["stop_requested_ns"] - trace["power_requested_ns"]
    frozen.require(base.CAPTURE_SECONDS * 1_000_000_000 <= duration <= (base.CAPTURE_SECONDS + 2) * 1_000_000_000,
                   "Boot trace interval differs from sixty-second contract")
    frozen.require(trace["stop_ended_ns"] - trace["stop_requested_ns"] <= 5_000_000_000, "Trace stop command exceeded five seconds")
    frozen.require(receipt["path"] == marker and receipt["boot_id"]
                   and 0 < receipt["uptime_seconds"] < base.CAPTURE_SECONDS, "Boot control identity/lifetime differs")
    content = (directory / "boot.pcap").read_bytes()
    records = trace_records(content)
    frozen.require(records and records[0][0] < 1_000_000 and records[0][1] == 4 and records[0][3] == b"\0" * 4,
                   "First record is not the VirtualBox trace start record")
    frozen.require(all(record[1] >= 14 for record in records[1:]), "Unexpected short record after the start record")
    times = [record[0] for record in records]
    frozen.require(times == sorted(times) and times[-1] <= (base.CAPTURE_SECONDS + 2) * 1_000_000,
                   "Trace timestamps are not trace-relative within the capture")
    parsed = traffic.packets(content)
    frozen.require(len(parsed) == len(records) and parsed, "Scapy and raw record counts differ")
    frames = parsed[1:]
    all_time = [(0, 2 ** 63 - 1)]
    classified = classify(frames, all_time, http=[{"path": marker}])
    frozen.require(classified["accepted"], "Unexplained boot traffic: " + str(classified["reasons"]))
    key, size = traffic.http_flow(frames, {"path": marker}, all_time)
    selected = [packet for packet in frames if traffic.flow_key(packet) == key]
    first, last = min(map(traffic.packet_ns, selected)), max(map(traffic.packet_ns, selected))
    receipt_ns = receipt["ended_wall_ns"] - receipt["started_wall_ns"]
    offset_ns = last - int(receipt["uptime_seconds"] * 1_000_000_000)
    frozen.require(0 < first and last <= base.CAPTURE_SECONDS * 1_000_000_000
                   and last - first <= receipt_ns + 1_000_000_000 and 0 <= offset_ns <= 15_000_000_000,
                   "Marked HTTP stream is not consistent with the guest receipt in trace-relative time")
    saved = base64.b64decode(receipt["response_base64"], validate=True)
    frozen.require(saved == traffic.tcp_bytes(selected, traffic.SINK), "Boot saved response differs from capture")
    return {"status": "accepted", "boot_id": receipt["boot_id"], "pcap_sha256": hashlib.sha256(content).hexdigest(),
            "pcap_frames": len(parsed), "http_body_bytes": size, "traffic": classified,
            "categories": dict(classified["categories"], hypervisor_trace_start_record=1),
            "timestamps": "trace-relative; HTTP bound via guest uptime offset %.3f s" % (offset_ns / 1e9),
            "limitation": "NIC trace has no independent drop counter and does not prove continuous completeness"}


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["capture_seconds"] == base.CAPTURE_SECONDS
                   and protocol["production_hashes"] == frozen.PINNED, "Protocol contract differs")
    check_frozen()
    frozen.verify_production()
    for name, checksum in protocol["source_hashes"].items():
        frozen.require(frozen.digest(name) == checksum, "Frozen source changed: " + name)
    for name, checksum in protocol["files"].items():
        frozen.require(frozen.digest(attempt / name) == checksum, "Frozen prepared artifact changed: " + name)
    return protocol


def check_frozen():
    frozen.require(frozen.digest(base.__file__) == v21.BASE_SHA256 and frozen.digest(v21.__file__) == v22.V21_SHA256
                   and frozen.digest(v22.__file__) == V22_SHA256 and frozen.digest(traffic.__file__) == VALIDATOR_SHA256,
                   "A frozen quiet-v2 layer or the frozen validator changed")


def freeze():
    check_frozen()
    frozen.verify_production()
    attempt = ROOT / "quiet-ambient-v2-3" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, v22.__file__, v21.__file__, base.__file__, network.__file__, traffic.__file__, base.POLICY,
                 ROOT / "quiet_ambient.py", ROOT / "capture_liveness_v4.py", ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT,
        "derived_from": {"quiet_ambient_v22.py": V22_SHA256, "quiet_ambient_v21.py": v22.V21_SHA256,
                         "quiet_ambient_v2.py": v21.BASE_SHA256, "validate_quiet_v2.py": VALIDATOR_SHA256,
                         "evidence": "quiet-ambient-v2-2/20261024T133443341773Z/phases/multiboot/boot-01",
                         "superseded_attempts": ["quiet-ambient-v2/20261024T110014475263Z",
                                                 "quiet-ambient-v2-1/20261024T132922140215Z",
                                                 "quiet-ambient-v2-2/20261024T133443341773Z"]},
        "boot_count": base.BOOT_COUNT, "capture_seconds": base.CAPTURE_SECONDS, "production_hashes": frozen.PINNED,
        "baseline": frozen.BASELINE, "baseline_uuid": base.BASELINE_UUID, "original_uuid": base.ORIGINAL_UUID,
        "original_trace": v21.ORIGINAL_TRACE,
        "new_snapshot": "clean-final-quiet-v19-" + attempt.name,
        "staged_snapshot": "clean-final-quiet-v19-payload-" + attempt.name,
        "guest_mac": GUEST_MAC, "control_paths": ["/hazim-final/boot/" + attempt.name + "/" + str(index)
                                                 for index in range(1, base.BOOT_COUNT + 1)],
        "source_hashes": sources, "files": files, "approval": None, "vm_steps_authorized": [],
        "collection_ready": False, "retries": False, "model_fits": 0, "merge_with_v18": False,
        "future_batch_cases": plan["cases"],
        "phases": ["preflight", "configure", "multiboot", "stage", "dry-run", "benign"],
        "allowances_added": ["VirtualBox 4-byte trace start record (record 1 only)",
                             "<=3 guest IPv4 conflict probes within 1 s, before the first announcement",
                             "<=3 guest announcements at 1.8-2.2 s spacing (frozen rule allowed <=2)",
                             "<=3 Sink IPv6 router solicitations from the MAC answering ARP for 10.0.0.1"],
        "criteria": ["Setup/credential directory absence positively confirmed by the guest before the snapshot",
                     "Trace enabled (confirmed from the NIC 1 line) before power-on; stop sixty seconds after power-on",
                     "Ten distinct boot IDs, each restored from the same policy child",
                     "One bounded numeric-Sink HTTP200 control per boot; exact saved response equals PCAP; stream bound "
                     "to the guest receipt in trace-relative time",
                     "Every boot frame is the start record, a bounded link-up frame, guest/Sink ARP or the control; "
                     "anything else rejects",
                     "Every case in the later benign batch must independently pass the strict validator (same allowances)",
                     "Cleanup restores the original snapshot and trace off/none without writing a literal file name"],
        "limitations": ["Hypervisor NIC tracing has no independent drop counter; not a completeness proof",
                        "Ten sixty-second boots do not exercise every later timer",
                        "Network controls repeat one diagnostic source; no independent software diversity claim",
                        "Sink router solicitations are Sink behaviour, allowed by bound, not suppressed",
                        "No VM phase, batch, malware, fit or merge is authorized by preparation"]}
    frozen.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": frozen.digest(attempt / "protocol.json"),
                      "vm_steps_authorized": [], "collection_ready": False}, indent=2))
    return attempt


def install():
    v22.install()
    check_frozen()
    base.audit_boot, base.verify_plan = audit_boot, verify_plan
    traffic.classify = classify  # the frozen batch audit resolves classify through its module globals


SAVED_BOOT = ROOT / "quiet-ambient-v2-2/20261024T133443341773Z/phases/multiboot/boot-01"


def self_test():
    import shutil
    import tempfile
    from unittest.mock import patch
    marker = "/hazim-final/boot/20261024T133443341773Z/1"
    accepted = audit_boot(SAVED_BOOT, marker)
    expected = {"hypervisor_trace_start_record": 1, "sink_ipv6_router_solicitation": 1, "guest_ipv4_conflict_probe": 3,
                "guest_self_announcement": 3, "guest_sink_arp": 4, "declared_http": 12}
    frozen.require(accepted["categories"] == expected, "Saved boot-01 categories differ: %r" % accepted["categories"])
    print("PASS saved real boot-01 (v2.2 attempt) accepted:", accepted["categories"], accepted["timestamps"])

    def mutated(change):
        records = trace_records((SAVED_BOOT / "boot.pcap").read_bytes())
        records = change(records)
        out = bytearray((SAVED_BOOT / "boot.pcap").read_bytes()[:24])
        for micros, included, original, data in records:
            out += struct.pack("<IIII", micros // 1_000_000, micros % 1_000_000, len(data), max(original, len(data))) + data
        directory = Path(tempfile.mkdtemp())
        for name in ("control.json", "trace.json"):
            shutil.copy(SAVED_BOOT / name, directory / name)
        (directory / "boot.pcap").write_bytes(bytes(out))
        try:
            audit_boot(directory, marker)
            return "accepted"
        except ValueError as error:
            return str(error)
        finally:
            shutil.rmtree(directory)
    announce = lambda records: [record for record in records if record[3][12:14] == b"\x08\x06"
                                and record[3][28:32] == record[3][38:42] == bytes([10, 0, 0, 10])]
    probes = lambda records: [record for record in records if record[3][12:14] == b"\x08\x06" and record[3][28:32] == b"\0" * 4]
    cases = {
        "fourth announcement": lambda r: r + [(r[-1][0] + 1, *announce(r)[-1][1:])],
        "fourth conflict probe": lambda r: sorted(r + [(probes(r)[-1][0] + 1000, *probes(r)[-1][1:])]),
        "probe from another MAC": lambda r: [(t, i, o, d.replace(bytes.fromhex("001b210aee09"), bytes.fromhex("001b210aee10"))
                                              if d[28:32] == b"\0" * 4 else d) for t, i, o, d in r],
        "solicitation from a non-Sink MAC": lambda r: [(t, i, o, d[:6] + bytes.fromhex("020000000099") + d[12:]
                                                        if d[12:14] == b"\x86\xdd" else d) for t, i, o, d in r],
        "extra UDP frame": lambda r: r + [(r[-1][0] + 1, 60, 60, bytes.fromhex("001b21079477001b210aee090800") + bytes(
            [0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 10, 8, 8, 8, 8, 0x30, 0x39, 0, 53, 0, 8, 0, 0]) + b"\0" * 18)],
        "start record missing": lambda r: r[1:],
        "start record not first": lambda r: [r[1], r[0]] + r[2:],
        "epoch timestamps": lambda r: [(t + 1_792_848_970_000_000, i, o, d) for t, i, o, d in r],
    }
    for name, change in cases.items():
        outcome = mutated(change)
        frozen.require(outcome != "accepted", "Mutation accepted: " + name)
    print("PASS %d mutated boot traces rejected (%s)" % (len(cases), ", ".join(cases)))

    # Batch path: the frozen 18-case saved regression must give the same verdicts through the patched classify.
    with patch.object(traffic, "classify", classify):
        traffic.historical_test()
    v22.self_test()
    install()
    frozen.require(base.audit_boot is audit_boot and traffic.classify is classify and base.configure is v22.configure,
                   "Inherited phase machinery not routed through v2.3")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--audit-batch", action="store_true")
    action.add_argument("--phase", choices=("preflight", *base.PREDECESSOR))
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    options = parser.parse_args()
    if options.self_test:
        self_test()
        return
    if options.freeze_only:
        freeze()
        return
    install()
    frozen.require(options.attempt is not None, "Frozen attempt required")
    attempt = options.attempt.resolve()
    if options.audit_batch:
        base.audit_batch(attempt, verify_plan(attempt, options.protocol_sha256))
    else:
        base.perform_phase(attempt, options.phase, options.protocol_sha256, options.approval)


if __name__ == "__main__":
    main()
