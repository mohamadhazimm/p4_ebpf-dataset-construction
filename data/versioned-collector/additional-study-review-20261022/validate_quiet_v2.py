"""Saved-only allowlist audit for the prospective final quiet .19 environment."""

import argparse
import collections
import csv
import io
import json
import math
import subprocess
from decimal import Decimal
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapReader

import collect_v19 as frozen


ROOT = Path(__file__).resolve().parent
GUEST = "10.0.0.10"
SINK = "10.0.0.1"
PAIR = {GUEST, SINK}
GUEST_MAC = "00:1b:21:0a:ee:09"


def self_announcements(parsed, guest_mac):
    candidates = [(index, packet) for index, packet in enumerate(parsed, 1)
                  if isinstance(packet.payload, ARP)
                  and packet[ARP].psrc == packet[ARP].pdst == GUEST]
    if not 1 <= len(candidates) <= 2 or guest_mac != GUEST_MAC:
        return set()
    for _index, packet in candidates:
        arp = ARP(bytes(packet[ARP]))
        if not (packet.src.lower() == arp.hwsrc.lower() == guest_mac
                and packet.dst.lower() == "ff:ff:ff:ff:ff:ff"
                and arp.hwdst.lower() == "00:00:00:00:00:00"
                and int(arp.op) == 1 and int(arp.hwtype) == 1
                and int(arp.ptype) == 0x800 and int(arp.hwlen) == 6 and int(arp.plen) == 4):
            return set()
    if len(candidates) == 2:
        spacing = packet_ns(candidates[1][1]) - packet_ns(candidates[0][1])
        if not 1_800_000_000 <= spacing <= 2_200_000_000:
            return set()
    return {index for index, _packet in candidates}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def packets(content):
    with PcapReader(io.BytesIO(content)) as reader:
        require(reader.linktype == 1, "Expected Ethernet capture")
        return list(reader)


def packet_ns(packet):
    return int(Decimal(str(packet.time)) * 1_000_000_000)


def windows(telemetry):
    from audit_performance_v4 import utc_ns

    rows = list(csv.DictReader(io.StringIO(telemetry)))
    bounds = [(utc_ns(row["window_start_utc"]), utc_ns(row["window_end_utc"])) for row in rows]
    require(len(bounds) == 40 and all(start < end for start, end in bounds)
            and all(previous[1] <= following[0] for previous, following in zip(bounds, bounds[1:])),
            "Invalid recorded windows")
    return bounds


def direct_ip(packet):
    return packet.payload if isinstance(packet, Ether) and isinstance(packet.payload, IP) else None


def flow_key(packet):
    address = direct_ip(packet)
    if address is None or not isinstance(address.payload, TCP):
        return None
    tcp = address.payload
    return tuple(sorted(((address.src, int(tcp.sport)), (address.dst, int(tcp.dport)))))


def description(packet):
    address = direct_ip(packet)
    if address is not None:
        transport = address.payload
        row = {"src": address.src, "dst": address.dst, "ip_protocol": int(address.proto)}
        if isinstance(transport, (TCP, UDP)):
            row.update(sport=int(transport.sport), dport=int(transport.dport))
        return row
    if isinstance(packet.payload, ARP):
        return {"src": packet[ARP].psrc, "dst": packet[ARP].pdst, "protocol": "ARP"}
    return {"src": packet.src, "dst": packet.dst, "protocol": "EtherType:%s" % packet.type}


def tcp_bytes(selected, source):
    segments = sorted((int(packet[TCP].seq), bytes(packet[TCP].payload)) for packet in selected
                      if packet[IP].src == source and bytes(packet[TCP].payload))
    require(segments, "Missing TCP application bytes")
    origin = segments[0][0]
    combined = bytearray()
    for sequence, payload in segments:
        offset = sequence - origin
        require(0 <= offset <= len(combined), "TCP sequence gap")
        overlap = min(len(payload), len(combined) - offset)
        require(combined[offset:offset + overlap] == payload[:overlap], "Conflicting TCP overlap")
        combined.extend(payload[overlap:])
    return bytes(combined)


def http_flow(parsed, declaration, bounds):
    import http.client

    marker = declaration["path"]
    require(marker.startswith(("/hazim-final/", "/attribution-final_")) and "\r" not in marker and "\n" not in marker,
            "Invalid HTTP marker")
    candidates = collections.defaultdict(list)
    for packet in parsed:
        key = flow_key(packet)
        if key and (SINK, 80) in key and any(endpoint[0] == GUEST for endpoint in key):
            candidates[key].append(packet)
    recovered = []
    for key, selected in candidates.items():
        try:
            request = tcp_bytes(selected, GUEST)
        except ValueError:
            continue
        if not request.startswith(("GET " + marker + " HTTP/1.").encode("ascii")):
            continue
        require(request.count(b"GET ") == 1 and b"\r\n\r\n" in request, "HTTP request count/framing differs")
        inside = [packet for packet in selected if any(start <= packet_ns(packet) < end for start, end in bounds)]
        require(tcp_bytes(inside, GUEST) == request, "HTTP request not wholly inside measured windows")
        response = tcp_bytes(inside, SINK)

        class Socket:
            def makefile(self, *_args, **_kwargs):
                return io.BytesIO(response)

        message = http.client.HTTPResponse(Socket())
        message.begin()
        require(message.status == 200 and message.getheader('Content-Length') is not None,
            "Positive control is not length-framed HTTP200")
        body = message.read()
        require(body and message.length in (None, 0), "Incomplete/empty HTTP response")
        recovered.append((key, len(body)))
    require(len(recovered) == 1, "Expected exactly one marked HTTP stream: " + marker)
    return recovered[0]


def classify(parsed, bounds, verified_probes=(), http=(), udp=(), guest_mac=GUEST_MAC):
    labels = {}
    network = []
    reasons = []
    announcements = self_announcements(parsed, guest_mac)
    for declaration in http:
        try:
            key, size = http_flow(parsed, declaration, bounds)
        except Exception as error:
            reasons.append('declared_http_not_recovered:' + str(error))
            continue
        require(key not in labels, "Duplicate declared HTTP stream")
        labels[key] = "declared_http:" + declaration["path"]
        network.append({"path": declaration["path"], "response_body_bytes": size})
    datagrams = {}
    quotes = set()
    for declaration in udp:
        expected = [payload.encode('ascii') for payload in declaration['payloads']]
        require(len(expected) == len(set(expected)) == 6, 'Expected six distinct marked UDP payloads')
        found = []
        for index, packet in enumerate(parsed, 1):
            address = direct_ip(packet)
            if address is None or not isinstance(address.payload, UDP):
                continue
            transport = address.payload
            if (address.src, address.dst, int(transport.sport), int(transport.dport)) != (
                    GUEST, SINK, declaration['sport'], 65003):
                continue
            payload = bytes(transport.payload)
            if payload in expected and any(start <= packet_ns(packet) < end for start, end in bounds):
                found.append(payload)
                datagrams[index] = 'declared_udp:' + payload.decode('ascii')
                serialized = IP(bytes(address))
                quotes.add(bytes(serialized)[:int(serialized.ihl) * 4 + 8])
        if collections.Counter(found) != collections.Counter(expected):
            reasons.append('declared_udp_not_recovered')
        network.append({'udp_markers': len(found), 'sport': declaration['sport'], 'dport': 65003})
    rows = []
    for index, packet in enumerate(parsed, 1):
        timestamp = packet_ns(packet)
        inside = any(start <= timestamp < end for start, end in bounds)
        category = "unexplained"
        if index in announcements:
            category = "guest_self_announcement"
        if isinstance(packet.payload, ARP):
            arp = packet[ARP]
            if {arp.psrc, arp.pdst} == PAIR and int(arp.op) in (1, 2) and int(arp.ptype) == 0x800:
                category = "guest_sink_arp"
        key = flow_key(packet)
        if key in labels:
            category = labels[key]
        if index in datagrams:
            category = datagrams[index]
        address = direct_ip(packet)
        if (address is not None and address.src == SINK and address.dst == GUEST
                and isinstance(address.payload, ICMP) and int(address.payload.type) == 3
                and int(address.payload.code) == 3):
            quoted = bytes(address.payload.payload)
            if any(quoted.startswith(prefix) for prefix in quotes):
                category = 'declared_udp_icmp_quote'
        for probe in verified_probes:
            expected = tuple(sorted(((GUEST, probe["local_port"]), (SINK, 80))))
            if (key == expected and probe["low_ns"] <= timestamp <= probe["high_ns"]
                    and not bytes(packet[TCP].payload) and not inside):
                category = "capture_probe:" + probe["phase"]
        rows.append({"frame": index, "epoch_ns": timestamp, "in_window": inside,
                     "category": category, **description(packet)})
    unexplained = [row["frame"] for row in rows if row["in_window"] and row["category"] == "unexplained"]
    if unexplained:
        reasons.append('unexplained_in_window_traffic')
    return {"accepted": not reasons, "reasons": reasons,
            "unexplained_in_window_frames": unexplained, "frames": rows, "network_controls": network,
            "by_source": dict(collections.Counter(json.dumps({key: row[key] for key in row
                if key not in ("frame", "epoch_ns", "in_window")}, sort_keys=True) for row in rows)),
            "ownership_limitation": "Frame endpoints/protocol/marker classification is not OS-process ownership."}


def batch_environment(results):
    invalid = [row["sample"] for row in results if row["label"] == "null"
               and (not row.get('traffic', {}).get('accepted', False) or row['status'] != 'accepted')]
    return {"environment_valid": not invalid, "invalidating_nulls": invalid,
            "all_cases_accepted": bool(results) and all(row["status"] == "accepted" for row in results)}


def audit_case(sample_dir, case, settings, tools=None):
    try:
        return _audit_case(sample_dir, case, settings, tools)
    except Exception as error:
        return {'status': 'excluded', 'technical_error': type(error).__name__ + ': ' + str(error)}


def _audit_case(sample_dir, case, settings, tools=None):
    tools = tools or frozen.validation_tools()
    data, probes, _ambient, workloads = tools
    metadata_path = list((sample_dir / 'output').glob('run_*/run.json'))
    require(len(metadata_path) == 1, 'Missing or ambiguous metadata')
    run_dir = metadata_path[0].parent
    metadata = frozen.load(metadata_path[0])
    content = (run_dir / 'packet_capture.pcap').read_bytes()
    telemetry_text = (run_dir / 'telemetry.csv').read_text()
    parsed = packets(content)
    bounds = windows(telemetry_text)
    probe_audit = probes.audit_probe(metadata, frozen.load(run_dir / 'capture-path-probe.json'), content, telemetry_text)
    probe_flows = [{"phase": phase, "local_port": record['local_port'],
               "low_ns": record['started_wall_ns'] - 1_000_000_000,
               "high_ns": record['ended_wall_ns'] + 1_000_000_000}
              for phase, record in metadata['capture_path_probe']['probes'].items()]
    traffic = classify(parsed, bounds, probe_flows, case.get('http', ()), case.get('udp', ()))
    result = {'traffic': traffic, 'status': 'excluded'}
    try:
        host = dict(line.split('=', 1) for line in (sample_dir / 'host_run.txt').read_text().splitlines() if '=' in line)
        require(host.get('status') == 'completed', 'Retrieval not completed')
        frozen.metadata_checks(metadata, case, settings)
        archive_members = frozen.audit_archive(sample_dir)
        telemetry = data.p4.load_telemetry_rows(sample_dir)
        features = [name for group in metadata['telemetry_feature_groups'].values() for name in group]
        require(len(telemetry) == 40 and len(features) == len(set(features)) == 169
                and all(math.isfinite(float(window[name])) for window in telemetry for name in features),
                'Incomplete/nonfinite 40x169')
        statistics = metadata['packet_capture_statistics']
        require(len(parsed) == statistics['packets_captured'] == statistics['packets_received_by_filter']
                and statistics['dropped_by_kernel'] == 0, 'Independent PCAP/counter disagreement')
        extracted, _windows, diagnostics = data.p4.derive_p4_features(
            run_dir / 'packet_capture.pcap', telemetry, metadata, byte_layer='ethernet', rate_window='nominal')
        require(diagnostics['alignment_status'] == 'unique', 'P4 alignment not unique')
        comparisons = 0
        for name in data.p4.P4_FEATURES:
            for statistic, stored in data.aggregate([float(window[name]) for window in telemetry]).items():
                require(math.isclose(stored, float(extracted['network__p4_' + name + '__' + statistic]),
                                     rel_tol=1e-9, abs_tol=1e-9), 'P4 parity mismatch: ' + name)
                comparisons += 1
        if case.get('network_control'):
            from quiet_network_v2 import check_receipt
            result['application_control'] = check_receipt(case, run_dir, parsed, bounds, metadata)
        elif case['label'] == 'benign':
            process = subprocess.CompletedProcess([], metadata['return_code'],
                (run_dir / 'sample.stdout.log').read_text(), (run_dir / 'sample.stderr.log').read_text())
            workloads.check_result(case, process, run_dir / 'workspace', run_dir / 'unused-fixtures')
        elif case['label'] == 'null':
            require((run_dir / 'sample.stdout.log').read_bytes() == b'', 'Null emitted stdout')
        result.update(archive_members=archive_members, finite_cells=40 * 169, pcap_frames=len(parsed), probe=probe_audit,
                      p4_alignment='unique', p4_parity_comparisons=comparisons,
                      post_target_lineage_raw_syscalls=metadata['target_exec']['post_target_lineage_raw_syscalls'])
    except Exception as error:
        result['technical_error'] = type(error).__name__ + ': ' + str(error)
    if case.get('http'):
        response = run_dir / 'workspace' / case.get('response_file', 'pilot-http-response.bin')
        if not response.is_file() or response.stat().st_size == 0:
            result['technical_error'] = 'Missing saved HTTP response'
    if traffic['accepted'] and 'technical_error' not in result:
        result['status'] = 'accepted'
    return result


def historical_test():
    attempt = ROOT / 'v19-small-collection/20261024T091843893614Z'
    protocol = frozen.load(attempt / 'protocol.json')
    tools = frozen.validation_tools()
    results = []
    for case in protocol['cases']:
        result = audit_case(attempt / 'runs' / case['sample'], case, protocol['settings_required'], tools=tools)
        results.append({'sample': case['sample'], 'label': case['label'], **result})
    rejected = [row for row in results if row['status'] != 'accepted']
    require(len(results) == 18, 'Historical cases were skipped')
    require({row['sample'] for row in rejected if row['label'] != 'malware'} == {
        'null-native_amd64_dynamic-r1.zip'}, 'Strict historical control regression differs')
    flood = results[13]
    require(flood['sample'].startswith('5c9f496e') and flood['status'] == 'excluded'
            and 'Missing or ambiguous metadata' in flood.get('technical_error', ''),
            'Missing-metadata flood did not produce an excluded row')
    require(results[-1]['status'] == 'accepted', 'Validation did not continue after missing metadata')
    require(not batch_environment(results)['environment_valid'], 'Historical apt null did not invalidate environment')
    require(sum(row.get('p4_parity_comparisons', 0) for row in results if row['label'] != 'malware')
            == 12 * 145, 'Inherited P4 gates not exercised')
    print('PASS all 18 saved cases audited; eleven controls accepted, apt null excluded; flood excluded without abort; environment invalid')
    return results


def self_test():
    bounds = [(100, 200)]

    def at(packet):
        packet.time = Decimal(150) / 1_000_000_000
        return packet

    good = at(Ether() / ARP(psrc=GUEST, pdst=SINK))
    require(classify([good], bounds)["accepted"], "Pair-specific ARP rejected")
    mutations = [Ether() / ARP(psrc=GUEST, pdst=GUEST), Ether() / ARP(psrc="0.0.0.0", pdst=GUEST),
                 Ether() / IP(src=GUEST, dst=SINK) / TCP(dport=80),
                 Ether() / IP(src=GUEST, dst=SINK) / UDP(dport=53),
                 Ether() / IP(src=GUEST, dst=SINK) / ICMP(),
                 Ether() / IP(src=GUEST, dst=SINK) / TCP(dport=80) / Raw(b"GET /a.deb HTTP/1.1\r\n\r\n")]
    for packet in mutations:
        result = classify([at(packet)], bounds)
        require(not result["accepted"], "Unexplained frame accepted")
        require(not batch_environment([{"sample": "test-null", "label": "null", "status": "excluded",
                                        "traffic": result}])["environment_valid"], "Contaminated null did not invalidate environment")
    require(classify([at(mutations[2])], [(200, 300)])["accepted"], "Outside frame treated as in-window")
    print("PASS strict ARP/IP/HTTP/DNS/ICMP allowlist and null-environment guards; synthetic, no VM operation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--historical-test", action="store_true")
    options = parser.parse_args()
    require(options.self_test or options.historical_test, 'Select a saved-only test')
    self_test()
    if options.historical_test:
        historical_test()