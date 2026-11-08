"""Quiet-v3.5 classifier fix and saved-only re-audit of the quiet-v3.4 benign batch.

Evidence (quiet-ambient-v3-4/20261024T150104720304Z, benign phase): 12/14 cases accepted, every null clean
(environment_valid=true); both network controls were excluded for exactly 6 unexplained frames each, which are the
Sink's ICMP port-unreachable replies (type 3 code 3) to the 6 declared UDP datagrams. The frozen classifier labels such
a reply only if its quoted bytes start with the captured datagram's IP header + 8 bytes. Byte comparison shows the
quote differs from the guest's capture only in the 2 UDP checksum bytes (captured 143f, quoted 8949): transmit
checksum offload means the guest's tcpdump sees the datagram before the virtual NIC fills in the checksum.
Fix: an ICMP port-unreachable from the Sink to the guest is a declared-UDP quote if its quoted bytes equal one declared
datagram's captured IP bytes everywhere except UDP checksum bytes 26-27 (IP id, addresses, ports, length and the marker
payload must all match). Everything else is the v3.4 classifier. The original failed phase result is preserved; this
writes a separate derived report.
"""

import argparse
import collections
import glob
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v34 as v34  # noqa: E402

v23, base, frozen, traffic = v34.v23, v34.base, v34.frozen, v34.traffic
V34_SHA256 = "85cbac38a3dae3b0bc4666a7fbcce94e1e9342fe691fe14bdd1deec5ca85689a"
ATTEMPT = ROOT / "quiet-ambient-v3-4/20261024T150104720304Z"
CHECKSUM = slice(26, 28)


def quote_matches(quoted, datagram):
    """Quoted bytes equal the captured datagram except the UDP checksum (and may be truncated after 28 bytes)."""
    if len(quoted) < 28 or len(datagram) < 28:
        return False
    length = min(len(quoted), len(datagram))
    mask = lambda data: data[:CHECKSUM.start] + b"\0\0" + data[CHECKSUM.stop:length]
    return mask(quoted) == mask(datagram)


def classify(parsed, bounds, verified_probes=(), http=(), udp=(), guest_mac=traffic.GUEST_MAC):
    result = v23.classify(parsed, bounds, verified_probes, http, udp, guest_mac)
    rows = {row["frame"]: row for row in result["frames"]}
    datagrams = [bytes(traffic.direct_ip(parsed[index - 1])) for index, row in rows.items()
                 if row["category"].startswith("declared_udp:")]
    relabelled = 0
    for index, row in rows.items():
        if row["category"] != "unexplained":
            continue
        address = traffic.direct_ip(parsed[index - 1])
        if (address is not None and address.src == traffic.SINK and address.dst == traffic.GUEST
                and isinstance(address.payload, traffic.ICMP) and int(address.payload.type) == 3
                and int(address.payload.code) == 3):
            quoted = bytes(address.payload.payload)
            if any(quote_matches(quoted, datagram) for datagram in datagrams):
                row["category"] = "declared_udp_icmp_quote"
                relabelled += 1
    frames = [rows[index] for index in sorted(rows)]
    unexplained = [row["frame"] for row in frames if row["in_window"] and row["category"] == "unexplained"]
    reasons = [reason for reason in result["reasons"] if reason != "unexplained_in_window_traffic"]
    if unexplained:
        reasons.append("unexplained_in_window_traffic")
    return {**result, "frames": frames, "accepted": not reasons, "reasons": reasons,
            "unexplained_in_window_frames": unexplained, "icmp_quotes_relabelled_checksum_offload": relabelled,
            "categories": dict(collections.Counter(row["category"].split(":")[0] for row in frames))}


def install():
    v34.install()
    frozen.require(frozen.digest(v34.__file__) == V34_SHA256, "Frozen quiet-v3.4 driver changed")
    traffic.classify = classify


def rederive():
    install()
    protocol = frozen.load(ATTEMPT / "protocol.json")
    plan = frozen.load(ATTEMPT / "controls/plan.json")
    original = frozen.load(sorted(ATTEMPT.glob("batch-audit-*.json"))[-1])
    tools = frozen.validation_tools()
    rows = []
    for case in plan["cases"]:
        result = traffic.audit_case(ATTEMPT / "runs" / case["sample"], case, plan["settings_required"], tools)
        before = next(row for row in original["results"] if row["sample"] == case["sample"])
        rows.append({"sample": case["sample"], "label": case["label"], "mode": case["mode"], **result,
                     "original_status": before["status"]})
    verdict = traffic.batch_environment(rows)
    report = {"status": "saved_only_rederived_icmp_checksum_offload", "attempt": str(ATTEMPT),
              "protocol_sha256": frozen.digest(ATTEMPT / "protocol.json"), "original_audit": original.get("status"),
              "rederiver_sha256": frozen.digest(__file__), "validator_sha256": frozen.digest(traffic.__file__),
              "results": rows, **verdict, "collection_ready": False, "model_fits": 0, "merged_cases": 0,
              "change": __doc__.split("Fix:", 1)[1].split("Everything else", 1)[0].strip()}
    path = ATTEMPT / ("batch-audit-derived-icmp-checksum-" + frozen.stamp() + ".json")
    frozen.save(path, report)
    print(json.dumps({"report": str(path), **verdict}, indent=2))
    for row in rows:
        traffic_result = row.get("traffic", {})
        print("%-45s %-6s %-9s (was %-9s) relabelled=%s unexplained=%d %s" % (
            row["sample"], row["label"], row["status"], row["original_status"],
            traffic_result.get("icmp_quotes_relabelled_checksum_offload"), len(traffic_result.get("unexplained_in_window_frames", [])),
            row.get("technical_error", "")))
    return report


def self_test():
    from scapy.layers.inet import ICMP, IP, UDP
    from scapy.layers.l2 import Ether
    datagram = bytes(IP(src=traffic.GUEST, dst=traffic.SINK, id=0xBF66) / UDP(sport=65201, dport=65003, chksum=0x143F)
                     / b"HAZIM_ATTR_final_net_r1_000")
    wire = datagram[:26] + b"\x89\x49" + datagram[28:]
    frozen.require(quote_matches(wire, datagram), "Checksum-only difference not matched")
    for name, changed in {"ip id": wire[:4] + b"\x00\x01" + wire[6:], "source port": wire[:20] + b"\x00\x01" + wire[22:],
                          "payload marker": wire[:-1] + b"X", "short quote": wire[:20]}.items():
        frozen.require(not quote_matches(changed, datagram), "Mismatch accepted: " + name)
    frames = [Ether(src=traffic.GUEST_MAC, dst="08:00:27:00:00:01") / IP(datagram),
              Ether(src="08:00:27:00:00:01", dst=traffic.GUEST_MAC) / IP(src=traffic.SINK, dst=traffic.GUEST) / ICMP(type=3, code=3) / wire]
    for index, frame in enumerate(frames):
        frame.time = 10 + index * 0.01
    parsed = traffic.packets(_pcap(frames))
    declaration = [{"payloads": ["HAZIM_ATTR_final_net_r1_00%d" % index for index in range(6)], "sport": 65201}]
    result = classify(parsed, [(0, 2 ** 63 - 1)], udp=declaration)
    frozen.require(result["icmp_quotes_relabelled_checksum_offload"] == 1
                   and "unexplained_in_window_traffic" not in result["reasons"], "Offload quote not relabelled: %r" % result["reasons"])
    print("PASS ICMP quote rule: checksum-only difference accepted; ip id/port/marker/short-quote mismatches rejected")


def _pcap(frames):
    import io
    from scapy.utils import PcapWriter
    output = io.BytesIO()
    writer = PcapWriter(output, linktype=1, sync=True)
    for frame in frames:
        writer.write(frame)
    return output.getvalue()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    install()
    self_test()
    if not options.self_test:
        rederive()
