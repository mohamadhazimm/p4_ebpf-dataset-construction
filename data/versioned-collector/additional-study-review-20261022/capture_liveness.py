#!/usr/bin/env python3
"""Bounded, separately versioned capture-liveness diagnostic primitives."""

import argparse
import copy
import hashlib
import http.client
import io
import json
import os
import re
import socket
import struct
import time
from pathlib import Path


SCHEMA = "2026-10-23.22-capture-liveness-diagnostic"
PROTOCOL_SHA256 = "17f448836fb3e9505bd88b4d80f385ecb054ab5f7f47baab29455fd81e6e0259"
TARGET_SHA256 = "da37ee8d8e49c7e864fea73593293932c5400761512bc2491db40354080c5038"
ARGUMENTS = ["null", "liveness_null", "1"]
SECOND = 1000000000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            result.update(block)
    return result.hexdigest()


def contract():
    path = Path(__file__).with_name("CAPTURE_LIVENESS_PROTOCOL_V2.md")
    require(digest(path) == PROTOCOL_SHA256, "V2 protocol changed")
    blocks = re.findall(r"```json\n(.*?)\n```", path.read_text(), re.S)
    require(len(blocks) == 1, "Ambiguous V2 contract")
    return json.loads(blocks[0])


def validate_arguments(arguments):
    require(arguments == ARGUMENTS, "Diagnostic target arguments differ")


def parse_response(data):
    require(0 < len(data) <= 16384, "HTTP response size differs")

    class CapturedBytes(io.BytesIO):
        def close(self):
            pass

    stream = CapturedBytes(data)

    class CapturedSocket:
        def makefile(self, _mode):
            return stream

    with http.client.HTTPResponse(CapturedSocket()) as response:
        response.begin()
        require(response.status == 200 and response.version in (10, 11), "HTTP application status/version differs")
        lengths = response.headers.get_all("Content-Length", [])
        transfers = response.headers.get_all("Transfer-Encoding", [])
        require(len(lengths) <= 1 and len(transfers) <= 1 and not (lengths and transfers), "Ambiguous HTTP framing")
        require(not lengths or re.fullmatch(r"[0-9]+", lengths[0].strip()), "Invalid HTTP length")
        require(not transfers or transfers[0].lower().strip() == "chunked", "Unsupported HTTP transfer coding")
        body = response.read()
        require(len(body) <= 16384 and stream.tell() == len(data), "Incomplete or trailing HTTP bytes")
        require(not lengths or len(body) == int(lengths[0]), "Incomplete declared HTTP body")
        return body


def remaining(deadline, clock=time.monotonic_ns):
    budget = deadline - clock()
    if budget <= 0:
        raise TimeoutError("Single total helper deadline expired")
    return budget / SECOND


def transaction(directory, config, cgroup, factory=socket.socket, clock=time.monotonic_ns):
    request = bytes.fromhex(config["request_hex"])
    require(0 < len(request) <= 512 and re.fullmatch(
        rb"GET /hazim-liveness/[a-zA-Z0-9_-]+/(?:original|full)-(?:pre|post)/[0-9a-f]{32} HTTP/1\.0\r\n"
        rb"Host: 10\.0\.0\.1\r\nConnection: close\r\n\r\n", request), "Unapproved helper request")
    require(config["source_ipv4"] == "10.0.0.10" and config["destination"] == ["10.0.0.1", 80],
            "Unapproved helper endpoints")
    membership = Path("/proc/self/cgroup").read_text()
    require(cgroup.name not in membership, "Helper belongs to target cgroup")
    start = clock()
    deadline = start + 2 * SECOND
    receipt = {"pid": os.getpid(), "start_ticks": Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19],
               "process_namespace": os.readlink("/proc/self/ns/pid"),
               "network_namespace": os.readlink("/proc/self/ns/net"), "cgroup_membership": membership,
               "helper_start_ns": start, "realtime_start_ns": time.time_ns(), "status": "failed_preserved"}
    received = bytearray()
    (directory / "helper-request.bin").write_bytes(request)
    try:
        with factory(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.bind(("10.0.0.10", 0))
            connection.settimeout(remaining(deadline, clock))
            connection.connect(("10.0.0.1", 80))
            receipt["local_endpoint"] = list(connection.getsockname())
            receipt["remote_endpoint"] = list(connection.getpeername())
            receipt["network_namespace_cookie"] = int.from_bytes(connection.getsockopt(socket.SOL_SOCKET, 71, 8),
                                                                    byteorder=__import__("sys").byteorder)
            offset = 0
            while offset < len(request):
                connection.settimeout(remaining(deadline, clock))
                sent = connection.send(request[offset:])
                require(sent > 0, "HTTP request send made no progress")
                offset += sent
            while True:
                connection.settimeout(remaining(deadline, clock))
                chunk = connection.recv(min(4096, 16385 - len(received)))
                if not chunk:
                    break
                received.extend(chunk)
                require(len(received) <= 16384, "HTTP response exceeds bound")
            remaining(deadline, clock)
            body = parse_response(bytes(received))
            require(hashlib.sha256(body).hexdigest() == config["expected_body_sha256"] and
                    len(body) == config["expected_body_bytes"], "HTTP body differs from frozen historical fixture")
        remaining(deadline, clock)
        receipt.update(status="accepted", body_sha256=hashlib.sha256(body).hexdigest(), body_bytes=len(body))
    except BaseException as error:
        receipt["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        receipt.update(helper_end_ns=clock(), realtime_end_ns=time.time_ns(),
                       request_sha256=hashlib.sha256(request).hexdigest(),
                       response_sha256=hashlib.sha256(received).hexdigest())
        (directory / "helper-response.bin").write_bytes(received)
        with (directory / "helper-receipt.json").open("x") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
    return receipt


def reassemble(segments, expected, maximum):
    require(segments and len(expected) <= maximum, "TCP stream is missing or oversized")
    initial = {sequence for sequence, flags, _payload in segments if flags & 2}
    require(len(initial) == 1, "TCP connection start is missing or ambiguous")
    origin = (next(iter(initial)) + 1) & 0xffffffff
    octets = {}
    for sequence, flags, payload in segments:
        offset = (sequence + bool(flags & 2) - origin) & 0xffffffff
        if not payload:
            continue
        require(offset + len(payload) <= maximum, "TCP payload outside bounded stream")
        for index, value in enumerate(payload, offset):
            require(index not in octets or octets[index] == value, "Conflicting TCP retransmission overlap")
            octets[index] = value
    require(set(octets) == set(range(len(expected))), "TCP stream contains missing or extra bytes")
    require(bytes(octets[index] for index in range(len(expected))) == expected, "TCP stream bytes differ")
    return len(expected)


def pcap_records(data):
    require(len(data) >= 24, "Missing classic PCAP header")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    require(data[:4] in formats, "Unsupported PCAP format")
    order, multiplier = formats[data[:4]]
    require(struct.unpack_from(order + "I", data, 20)[0] == 1, "Not Ethernet PCAP")
    offset = 24
    rows = []
    while offset < len(data):
        require(offset + 16 <= len(data), "Truncated PCAP record header")
        seconds, fraction, captured, original = struct.unpack_from(order + "IIII", data, offset)
        offset += 16
        require(captured == original and captured <= 1024 * 1024 and offset + captured <= len(data),
                "Truncated or oversized PCAP frame")
        rows.append((seconds * SECOND + fraction * multiplier, data[offset:offset + captured]))
        offset += captured
    return rows


def audit_transaction(data, receipt, request, response, config):
    require(receipt["status"] == "accepted" and request == bytes.fromhex(config["request_hex"]),
            "Application receipt or frozen request differs")
    require(receipt["remote_endpoint"] == ["10.0.0.1", 80] and receipt["local_endpoint"][0] == "10.0.0.10",
            "Application endpoints differ")
    require(receipt["request_sha256"] == hashlib.sha256(request).hexdigest() and
            receipt["response_sha256"] == hashlib.sha256(response).hexdigest(), "Application bytes changed")
    body = parse_response(response)
    require(hashlib.sha256(body).hexdigest() == config["expected_body_sha256"] and
            len(body) == config["expected_body_bytes"], "Recovered body differs from frozen fixture")
    streams = {"request": [], "response": []}
    for timestamp, frame in pcap_records(data):
        if len(frame) < 54 or frame[12:14] != b"\x08\x00":
            continue
        packet = frame[14:]
        header = (packet[0] & 15) * 4
        if packet[0] >> 4 != 4 or packet[9] != 6 or header < 20 or len(packet) < header + 20:
            continue
        source = socket.inet_ntoa(packet[12:16])
        destination = socket.inet_ntoa(packet[16:20])
        source_port, destination_port, sequence = struct.unpack_from("!HHI", packet, header)
        forward = [source, source_port] == receipt["local_endpoint"] and [destination, destination_port] == receipt["remote_endpoint"]
        reverse = [source, source_port] == receipt["remote_endpoint"] and [destination, destination_port] == receipt["local_endpoint"]
        if not (forward or reverse):
            continue
        require(receipt["realtime_start_ns"] - 5000000 <= timestamp <= receipt["realtime_end_ns"] + 5000000,
                "TCP tuple reused outside helper time bounds")
        total = struct.unpack_from("!H", packet, 2)[0]
        require(not struct.unpack_from("!H", packet, 6)[0] & 0x3fff and header + 20 <= total <= len(packet),
                "Fragmented or truncated helper TCP packet")
        tcp_end = header + (packet[header + 12] >> 4) * 4
        require(header + 20 <= tcp_end <= total, "Invalid helper TCP header")
        streams["request" if forward else "response"].append((sequence, packet[header + 13], packet[tcp_end:total]))
    return {"request_bytes": reassemble(streams["request"], request, 512),
            "response_bytes": reassemble(streams["response"], response, 16384),
            "body_sha256": hashlib.sha256(body).hexdigest(), "pcap_records": len(pcap_records(data))}


def validate_lifecycle(receipts, full, positive):
    names = ["ready_ns", "observation_start_ns", "observation_end_ns", "target_request_ns",
             "release_ack_ns", "finish_request_ns", "finish_ack_ns"]
    if full:
        names += ["attached_ns", "detach_ns", "recorder_exit_ns", "attached_lifetime_seconds"]
    if positive:
        names += ["helper_start_ns", "helper_end_ns"]
    else:
        require(not any(name.startswith("helper_") for name in receipts), "Quiet case contains a helper")
    require(all(type(receipts.get(name)) is int and receipts[name] > 0 for name in names),
            "Missing or invalid lifecycle receipt")
    ready = receipts["ready_ns"]
    start = receipts["observation_start_ns"]
    end = receipts["observation_end_ns"]
    target = receipts["target_request_ns"]
    finish = receipts["finish_request_ns"]
    require(ready <= start <= ready + 3 * SECOND, "Ready-to-observation deadline")
    require(20 * SECOND <= end - start <= 21 * SECOND, "Observation duration differs")
    require(start <= target <= ready + 4 * SECOND, "Target request deadline")
    require(target <= receipts["release_ack_ns"] <= target + 8 * SECOND, "Release acknowledgement deadline")
    require(end <= finish <= min(end + 3 * SECOND, ready + 30 * SECOND), "Finish request deadline")
    require(finish <= receipts["finish_ack_ns"] <= finish + 15 * SECOND, "Finish acknowledgement deadline")
    if positive:
        helper_start = receipts["helper_start_ns"]
        helper_end = receipts["helper_end_ns"]
        require(ready <= helper_start <= helper_end < start and helper_end - helper_start <= 2 * SECOND,
                "Helper escaped its total deadline or target boundary")
    if full:
        attached = receipts["attached_ns"]
        detach = receipts["detach_ns"]
        require(receipts["attached_lifetime_seconds"] == 28, "Inherited or changed recorder lifetime")
        require(attached <= ready <= attached + SECOND, "Stale attachment readiness")
        require(attached <= start < end <= detach, "Hooks do not cover the original observation")
        require(attached + 28 * SECOND <= detach <= receipts["recorder_exit_ns"] <= attached + 30 * SECOND,
                "Recorder did not exit naturally within the teardown bound")
        require(receipts["recorder_exit_ns"] <= receipts["finish_ack_ns"], "Acknowledgement preceded recorder exit")
    return {"status": "bounded_lifecycle_verified", "full": full, "positive": positive,
            "collection_ready": False, "performance_accepted": False}


def self_test():
    approved = contract()
    require(approved["null_target"]["arguments"] == ARGUMENTS, "V2 argument contract differs")
    require(len(approved["cases"]) == 6 and sum(row["helper_transactions"] for row in approved["cases"]) == 4,
            "Diagnostic case/transaction budget differs")
    for row in approved["cases"]:
        validate_arguments(row["target_arguments"])
    for changed in (["null"], ["null", "original-pre", "1"], ["null", "liveness_null", "0"],
                    ["null", "liveness_null", "3"], ["file", "liveness_null", "1"]):
        try:
            validate_arguments(changed)
        except ValueError:
            pass
        else:
            raise AssertionError("Changed argv accepted")
    receipts = {"attached_ns": SECOND, "ready_ns": 2 * SECOND, "helper_start_ns": 2 * SECOND,
                "helper_end_ns": 3999999999, "observation_start_ns": 5 * SECOND,
                "observation_end_ns": 26 * SECOND, "target_request_ns": 6 * SECOND,
                "release_ack_ns": 7 * SECOND, "finish_request_ns": 28 * SECOND,
                "detach_ns": 29 * SECOND, "recorder_exit_ns": 30 * SECOND,
                "finish_ack_ns": 31 * SECOND, "attached_lifetime_seconds": 28}
    validate_lifecycle(receipts, True, True)
    guards = {"attached_lifetime_seconds": 22, "ready_ns": 2000000001,
              "helper_end_ns": 4000000001, "observation_start_ns": 5000000001,
              "observation_end_ns": 26000000001, "target_request_ns": 6000000001,
              "release_ack_ns": 14000000001, "finish_request_ns": 29000000001,
              "finish_ack_ns": 43000000001, "detach_ns": 25999999999,
              "recorder_exit_ns": 31000000001}
    for name, value in guards.items():
        changed = {**receipts, name: value}
        try:
            validate_lifecycle(changed, True, True)
        except ValueError:
            pass
        else:
            raise AssertionError("Altered lifecycle accepted: " + name)
    for name in receipts:
        changed = copy.deepcopy(receipts)
        del changed[name]
        try:
            validate_lifecycle(changed, True, True)
        except ValueError:
            pass
        else:
            raise AssertionError("Missing lifecycle receipt accepted: " + name)
    quiet = {name: value for name, value in receipts.items() if not name.startswith("helper_")}
    validate_lifecycle(quiet, True, False)
    try:
        validate_lifecycle(receipts, True, False)
    except ValueError:
        pass
    else:
        raise AssertionError("Quiet helper accepted")
    response = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    require(parse_response(response) == b"body", "Standard HTTP parser differs")
    reassemble([(100, 2, b""), (101, 16, b"bo"), (103, 16, b"dy"), (101, 16, b"bo")], b"body", 16384)
    for segments in ([(101, 16, b"body")], [(100, 2, b""), (102, 16, b"ody")],
                     [(100, 2, b""), (101, 16, b"body"), (101, 16, b"evil")],
                     [(100, 2, b""), (200, 2, b""), (101, 16, b"body")]):
        try:
            reassemble(segments, b"body", 16384)
        except ValueError:
            pass
        else:
            raise AssertionError("Incomplete, conflicting or ambiguous TCP accepted")
    for observed in (2 * SECOND, 2 * SECOND + 1):
        try:
            remaining(2 * SECOND, lambda: observed)
        except TimeoutError:
            pass
        else:
            raise AssertionError("Partial progress extended the total helper deadline")
    print("PASS six exact argv, five argv guards, near-two-second helper/handoff/latest-end lifecycle, "
          "all phase bounds, missing receipts, quiet-helper rejection, HTTP parser, TCP retransmission/gap/overlap/"
          "ambiguity guards and non-resetting total deadline; no VM/BPF operation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.parse_args()
    self_test()