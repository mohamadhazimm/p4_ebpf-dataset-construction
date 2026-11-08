#!/usr/bin/env python3
"""Freeze and run an isolated benign-only sensor capability probe."""

import argparse
import base64
import ctypes
import fcntl
import hashlib
import io
import json
import os
import pwd
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "remediation-preparation/20261022T122641888212Z/attribution-allocator-builds/20261022T140636919722Z"
ABI_BUILD = ROOT / "remediation-preparation/20261022T122641888212Z/attribution-exec-abi-builds/20261022T172217791905Z"
SENSOR_NAME = "attribution-v5"
SENSOR_SCHEMA = "attribution-sensor-v5"
GUEST_BTF_SHA256 = "2b91134c0f8fdf86be01ddf92bd7bb12393b0137aedd190556d0f26bddddd12b"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def audit_records(rows):
    sessions = [row for row in rows if row.get("record") == "session"]
    finals = [row for row in rows if row.get("record") == "final"]
    events = [row for row in rows if row.get("record") == "observation"]
    if len(sessions) != 1 or len(finals) != 1 or not events:
        raise ValueError("Missing session, final counters or observations")
    if sessions[0]["schema"] not in (SENSOR_SCHEMA, "attribution-sensor-v6") or sum(row.get("record") == "attached" for row in rows) != 1:
        raise ValueError("Wrong schema or incomplete attachment")
    if any(row.get("schema") != sessions[0]["schema"] or (row["kind"] == 22 and row["schema"] != "attribution-sensor-v6") for row in events):
        raise ValueError("Observation/session schema mismatch")
    final = finals[0]
    if (final["returncode"] or not final["counters_available"] or final["invalid_records"]
            or len(final["counters"]) != 8 or any(final["counters"][1:])
            or final["events_emitted"] != len(events) or final["counters"][0] != len(events)):
        raise ValueError("Sensor error, loss or count mismatch")
    if any(row["ownership_verified"] or row["frame_link_verified"] for row in events):
        raise ValueError("Unvalidated ownership/frame claim")
    if sorted(row["sequence"] for row in events) != list(range(1, len(events) + 1)):
        raise ValueError("Missing or duplicate sensor sequence")
    return {"events": len(events), "kinds": sorted({row["kind"] for row in events}),
            "nonzero_socket_cookies": len({row["socket_cookie"] for row in events if row["socket_cookie"]})}


def audit_task(rows, receipt):
    events = [row for row in rows if row.get("record") == "observation"]
    if receipt.get("transport") == "i386-exec" and any(row.get("schema") == "attribution-sensor-v6" for row in events):
        if sum(row["kind"] == 22 for row in events) != 1:
            raise ValueError("Missing or duplicate actual cross-ABI exec return")
    entries = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}
    forks = [row for row in events if row["kind"] == 20]
    inherited_returns = 0
    for row in events:
        if row["kind"] not in (2, 22):
            continue
        entry = entries.get(row["operation_begin_ns"])
        if row["kind"] == 22:
            successful = [event for event in events if event["kind"] == 9 and event["monotonic_ns"] == row["arguments"][2] and
                          event.get("operation_begin_ns") == row["operation_begin_ns"] and event["arguments"][:2] == [59, 0] and event["abi"] == 1 and
                          (event["pid"], event["tid"], event["thread_start_ns"]) == (row["pid"], row["tid"], row["thread_start_ns"])]
            if (not entry or row.get("schema") != "attribution-sensor-v6" or entry["abi"] != 0 or entry["syscall_id"] != 59 or
                    row["abi"] != 1 or row["syscall_id"] != 11 or row["result"] != 0 or row["related_pid"] or
                    row["arguments"][:2] != [59, 0] or len(successful) != 1 or
                    not entry["monotonic_ns"] < row["arguments"][2] < row["monotonic_ns"] or
                    (entry["pid"], entry["tid"], entry["thread_start_ns"]) != (row["pid"], row["tid"], row["thread_start_ns"])):
                raise ValueError("Cross-ABI return lacks actual entry/exit and same-task exec-success evidence")
            continue
        if not entry or entry["syscall_id"] != row["syscall_id"] or entry["abi"] != row["abi"]:
            raise ValueError("Unmatched syscall return")
        if row["related_pid"]:
            if row["result"] != 0 or entry["tid"] != row["related_pid"] or not any(
                    fork["pid"] == entry["pid"] and fork["tid"] == entry["tid"] and
                    fork["related_pid"] == row["tid"] and fork["arguments"][:2] == [row["thread_start_ns"], row["pid"]] and
                    entry["monotonic_ns"] < fork["monotonic_ns"] < row["monotonic_ns"] for fork in forks):
                raise ValueError("Child return lacks observed parent entry and fork identity")
            inherited_returns += 1
        elif (entry["pid"], entry["tid"], entry["thread_start_ns"]) != (row["pid"], row["tid"], row["thread_start_ns"]):
            raise ValueError("Syscall return crossed process/thread lifetime")
    expected_children = 0 if receipt.get("transport") in ("ethernet-http", "exec-cloexec", "i386-exec") else 1
    if inherited_returns != expected_children or not any(row["kind"] == 9 and row["pid"] == receipt["pid"] for row in events):
        raise ValueError("Missing controlled exec/thread evidence")
    if receipt.get("transport") == "ethernet-http":
        return {"parent_linked_child_returns": inherited_returns, **audit_http_task(events, receipt)}
    if receipt.get("transport") == "tcp":
        return {"parent_linked_child_returns": inherited_returns, **audit_tcp_task(events, receipt)}
    if receipt.get("transport") == "fd-history":
        return {"parent_linked_child_returns": inherited_returns, **audit_fd_history(events, receipt)}
    if receipt.get("transport") == "exec-cloexec":
        return {"parent_linked_child_returns": inherited_returns, **audit_exec_cloexec(events, receipt)}
    if receipt.get("transport") == "i386-exec":
        return {"parent_linked_child_returns": inherited_returns, **audit_i386_task(events, receipt)}
    server_port, client_port = receipt["endpoint"][1], receipt["client_endpoint"][1]
    markers = [prefix + "%03d" % index for prefix in ("HAZIM_LIVE_", "HAZIM_CONN_") for index in range(16)]
    if receipt["status"] != "accepted" or receipt["messages_received_and_echoed"] != markers:
        raise ValueError("Application receipts differ")
    observed = {(kind, source, target): [] for kind in (7, 8) for source, target in ((client_port, server_port), (server_port, client_port))}
    for row in events:
        if row["kind"] not in (7, 8):
            continue
        body = bytes.fromhex(row["snapshot_hex"])
        if len(body) != 42 or row["wire_size"] != 42 or row["captured_size"] != 42 or not row["socket_cookie"]:
            raise ValueError("Missing or truncated controlled packet")
        version, _, length, _, fragments, _, protocol, _, source, target = struct.unpack("!BBHHHBBH4s4s", body[:20])
        source_port, target_port, udp_length, _ = struct.unpack("!HHHH", body[20:28])
        key = row["kind"], source_port, target_port
        if (version != 0x45 or length != 42 or fragments & 0x3fff or protocol != 17 or udp_length != 22 or
                source != socket.inet_aton("127.0.0.1") or target != source or key not in observed):
            raise ValueError("Controlled packet endpoints/header differ")
        observed[key].append(body[28:].decode("ascii"))
    if any(sorted(values) != sorted(markers) for values in observed.values()):
        raise ValueError("Missing, duplicated or changed UDP packet marker")
    receives = [row for row in events if row["kind"] == 6]
    if len(receives) != 64 or any(row["pid"] != receipt["pid"] or row["result"] != 14 or not row["operation_begin_ns"] for row in receives):
        raise ValueError("UDP receive operations disagree with receipts")
    sends = [row for row in events if row["kind"] == 4]
    socket_entries = {row["monotonic_ns"]: row for row in events if row["kind"] in (3, 5)}
    if len(sends) != 64 or len(socket_entries) != 128:
        raise ValueError("Missing UDP send or receive entry/return")
    for row in sends + receives:
        entry = socket_entries.get(row["operation_begin_ns"])
        if (not entry or entry["kind"] + 1 != row["kind"] or entry["tid"] != row["tid"] or
                entry["thread_start_ns"] != row["thread_start_ns"] or row["pid"] != receipt["pid"] or
                row["result"] != 14 or not row["socket_cookie"] or
                (row["local_port"], row["remote_port"]) not in ((client_port, server_port), (server_port, client_port))):
            raise ValueError("UDP operation identity, endpoints, completion or cookie differs")
    original, duplicate = receipt["original_descriptor"], receipt["duplicate_descriptor"]
    duplicates = [row for row in entries.values() if row["pid"] == receipt["pid"] and row["abi"] == 0 and
                  row["syscall_id"] == 72 and row["arguments"][:2] == [original, 1030]]
    if original == duplicate or len(duplicates) != 1 or not any(row["kind"] == 2 and
            row["operation_begin_ns"] == duplicates[0]["monotonic_ns"] and row["result"] == duplicate for row in events):
        raise ValueError("Descriptor duplication lacks actual successful syscall evidence")
    installs = [row for row in events if row["kind"] == 12 and row["pid"] == receipt["pid"] and row["arguments"][0] == original]
    if len(installs) != 1:
        raise ValueError("Original socket installation is ambiguous")
    installed = installs[0]
    finals = [row for row in events if row["kind"] == 14 and row["arguments"][1] == installed["arguments"][1] and
              row["arguments"][4] == installed["arguments"][4]]
    cookies = {row["socket_cookie"] for row in sends + receives if row["local_port"] == client_port}
    if len(finals) != 1 or cookies != {finals[0]["socket_cookie"]}:
        raise ValueError("Aliased socket final lifetime/cookie differs")
    for descriptor in (original, duplicate):
        closes = [row for row in entries.values() if row["pid"] == receipt["pid"] and row["syscall_id"] == 3 and
                  row["arguments"][0] == descriptor and row["monotonic_ns"] > duplicates[0]["monotonic_ns"]]
        if len(closes) != 1 or not any(row["kind"] == 2 and row["operation_begin_ns"] == closes[0]["monotonic_ns"] and row["result"] == 0 for row in events):
            raise ValueError("Missing successful descriptor-alias close")
        if finals[0]["monotonic_ns"] < closes[0]["monotonic_ns"]:
            raise ValueError("Socket finalized before both descriptor closes")
    return {"controlled_packet_observations": 128, "parent_linked_child_returns": inherited_returns,
            "actual_udp_receive_returns": len(receives), "actual_udp_send_returns": len(sends),
            "bounded_duplicate_close_check_passed": True}


def audit_i386_task(events, receipt):
    from collections import Counter
    markers = ["HAZIM_I386_A", "HAZIM_I386_B"]
    loopback_hex = "7f000001" + "0" * 24
    unknown_hex = "0" * 32
    identities = [receipt[name] for name in ("server_identity", "client_identity")]
    if (receipt["status"] != "accepted" or receipt["pointer_bits"] != 32 or
            receipt["messages_received_and_echoed"] != markers or
            len({item["cookie"] for item in identities}) != 2 or any(not item["cookie"] for item in identities) or
            any(item["local_endpoint"][0] != "127.0.0.1" for item in identities)):
        raise ValueError("Actual i386 application identities or echoes differ")
    raw = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}
    returns = [row for row in events if row["kind"] == 2]
    successes = sorted((row for row in events if row["kind"] == 9 and row["pid"] == receipt["pid"]), key=lambda row: row["monotonic_ns"])
    if len(successes) != 2:
        raise ValueError("Missing initial amd64 or replacement i386 exec")
    executing = [row for row in raw.values() if row["syscall_id"] == 59 and row["abi"] == 0 and
                 successes[0]["monotonic_ns"] < row["monotonic_ns"] < successes[1]["monotonic_ns"]]
    if (len(executing) != 1 or not successes[1]["monotonic_ns"] < receipt["begin_monotonic_ns"] < receipt["end_monotonic_ns"] or
            any((row["pid"], row["tid"], row["thread_start_ns"]) !=
                (executing[0]["pid"], executing[0]["tid"], executing[0]["thread_start_ns"]) for row in successes)):
        raise ValueError("ABI transition lacks actual same-task exec interval")
    task = (executing[0]["pid"], executing[0]["tid"], executing[0]["thread_start_ns"])
    after = [row for row in raw.values() if row["monotonic_ns"] > successes[1]["monotonic_ns"]]
    if not after or any(row["abi"] != 1 or (row["pid"], row["tid"], row["thread_start_ns"]) != task for row in after):
        raise ValueError("Post-exec raw events are not actual same-task i386")
    if not any(row["syscall_id"] == 4 and row["abi"] == 1 and row["result"] > 0 for row in returns):
        raise ValueError("Missing actual i386 receipt write")
    installed = {}
    closed = {}
    for identity in identities:
        installs = [row for row in events if row["kind"] == 12 and row["abi"] == 1 and row["pid"] == receipt["pid"] and
                    row["arguments"][0] == identity["fd"] and row["arguments"][4] == identity["inode"] and
                    receipt["begin_monotonic_ns"] < row["monotonic_ns"] < receipt["end_monotonic_ns"]]
        if len(installs) != 1 or not installs[0]["arguments"][1] or not installs[0]["arguments"][2]:
            raise ValueError("Missing i386 socket install/table identity")
        installed[identity["cookie"]] = installs[0]
        closes = [row for row in returns if row["syscall_id"] == 6 and row["abi"] == 1 and row["result"] == 0 and
                  raw[row["operation_begin_ns"]]["arguments"][0] == identity["fd"] and
                  installs[0]["monotonic_ns"] < row["monotonic_ns"] < receipt["end_monotonic_ns"]]
        finals = [row for row in events if row["kind"] == 14 and row["socket_cookie"] == identity["cookie"] and
                  row["arguments"][1] == installs[0]["arguments"][1] and row["arguments"][4] == identity["inode"]]
        if len(closes) != 1 or len(finals) != 1 or not closes[0]["operation_begin_ns"] < finals[0]["monotonic_ns"] < receipt["end_monotonic_ns"]:
            raise ValueError("Missing actual i386 socket close/final")
        closed[identity["cookie"]] = closes[0]["operation_begin_ns"]
    if len({row["arguments"][2] for row in installed.values()}) != 1:
        raise ValueError("I386 socket installs disagree on actual files table")
    operations = {row["monotonic_ns"]: row for row in events if row["kind"] in (3, 5)}
    completed = [row for row in events if row["kind"] in (4, 6)]
    if len(operations) != 8 or len(completed) != 8:
        raise ValueError("Missing i386 UDP operations")
    counts = Counter()
    for completion in completed:
        entry = operations.get(completion["operation_begin_ns"])
        identity = next((item for item in identities if item["cookie"] == completion["socket_cookie"]), None)
        if identity is None:
            raise ValueError("Unknown i386 operation cookie")
        peer = next(item for item in identities if item != identity)
        if (not entry or entry["kind"] + 1 != completion["kind"] or completion["result"] != len(markers[0]) or
                any(row["abi"] != 1 or row["socket_cookie"] != identity["cookie"] or row["protocol"] != 17 or
                    (row["pid"], row["tid"], row["thread_start_ns"]) != task or
                    row["local_port"] != identity["local_endpoint"][1] or row["local_address_hex"] != loopback_hex
                    for row in (entry, completion)) or
                completion["remote_port"] != peer["local_endpoint"][1] or completion["remote_address_hex"] != loopback_hex or
                ((entry["remote_port"], entry["remote_address_hex"]) != (peer["local_endpoint"][1], loopback_hex) and
                 not (entry["kind"] == 5 and (entry["remote_port"], entry["remote_address_hex"]) == (0, unknown_hex)))):
            raise ValueError("Actual i386 UDP operation task/ABI/peer/cookie differs")
        calls = [row for row in returns if row["abi"] == 1 and row["syscall_id"] == (369 if entry["kind"] == 3 else 371) and
                 row["result"] == len(markers[0]) and raw[row["operation_begin_ns"]]["arguments"][0] == identity["fd"] and
                 row["operation_begin_ns"] < entry["monotonic_ns"] < completion["monotonic_ns"] < row["monotonic_ns"]]
        if (len(calls) != 1 or raw[calls[0]["operation_begin_ns"]]["arguments"][2] < len(markers[0]) or
            (entry["kind"] == 3 and raw[calls[0]["operation_begin_ns"]]["arguments"][2] != len(markers[0])) or
            not installed[identity["cookie"]]["monotonic_ns"] < entry["monotonic_ns"] < completion["monotonic_ns"] < closed[identity["cookie"]]):
            raise ValueError("I386 operation lacks exact containing raw FD call")
        counts[completion["kind"], identity["cookie"]] += 1
    if any(counts[kind, identity["cookie"]] != 2 for kind in (4, 6) for identity in identities):
        raise ValueError("I386 application operation totals differ")
    packets = Counter()
    for row in events:
        if row["kind"] not in (7, 8):
            continue
        body = bytes.fromhex(row["snapshot_hex"])
        if (len(body) != 28 + len(markers[0]) or row["wire_size"] != len(body) or row["captured_size"] != len(body) or
            not receipt["begin_monotonic_ns"] < row["monotonic_ns"] < receipt["end_monotonic_ns"]):
            raise ValueError("Truncated i386 packet snapshot")
        version, _, length, _, fragments, _, protocol, _, source, target = struct.unpack("!BBHHHBBH4s4s", body[:20])
        source_port, target_port, udp_length, _ = struct.unpack("!HHHH", body[20:28])
        ports = [identity["local_endpoint"][1] for identity in identities]
        local_port = source_port if row["kind"] == 7 else target_port
        identity = next((item for item in identities if item["local_endpoint"][1] == local_port), None)
        if (version != 0x45 or length != len(body) or fragments & 0x3fff or protocol != 17 or udp_length != len(body) - 20 or
                source != socket.inet_aton("127.0.0.1") or target != source or sorted((source_port, target_port)) != sorted(ports) or
                identity is None or row["socket_cookie"] != identity["cookie"] or body[28:].decode("ascii") not in markers):
            raise ValueError("Actual i386 marked packet header/peer/cookie differs")
        packets[row["kind"], source_port, target_port, body[28:].decode("ascii")] += 1
    ports = [identity["local_endpoint"][1] for identity in identities]
    expected = Counter((kind, source, target, marker) for kind in (7, 8) for source, target in (ports, ports[::-1]) for marker in markers)
    if packets != expected:
        raise ValueError("Missing, duplicate or changed i386 packet markers")
    return {"same_task_amd64_to_i386_exec_verified": True, "i386_application_echoes": 2,
            "actual_udp_send_returns": 4, "actual_udp_receive_returns": 4, "controlled_packet_observations": 8,
            "i386_socket_install_close_final_matches": 2}


def i386_negative_checks(rows, receipt):
    import copy
    variants = []
    changed_receipt = copy.deepcopy(receipt)
    changed_receipt["pointer_bits"] = 64
    variants.append((copy.deepcopy(rows), changed_receipt))
    for mutation in ("raw_abi", "operation_abi", "raw_fd", "peer", "final", "install", "marker", "exec", "task", "close",
                     "boundary_entry", "boundary_success", "boundary_exit_abi", "boundary_context_id", "boundary_missing", "boundary_duplicate"):
        changed = copy.deepcopy(rows)
        if mutation.startswith("boundary_"):
            returned = next(row for row in changed if row.get("kind") == 22)
            if mutation == "boundary_entry":
                returned["arguments"][0] = 11
            elif mutation == "boundary_success":
                returned["arguments"][2] = returned["monotonic_ns"] + 1
            elif mutation == "boundary_exit_abi":
                returned["abi"] = 0
            elif mutation == "boundary_missing":
                changed.remove(returned)
            elif mutation == "boundary_duplicate":
                changed.append(copy.deepcopy(returned))
            else:
                returned["syscall_id"] = 59
        elif mutation in ("raw_abi", "raw_fd"):
            entry = next(row for row in changed if row.get("kind") == 1 and row["syscall_id"] == 369)
            if mutation == "raw_fd":
                entry["arguments"][0] += 100
            else:
                entry["abi"] = 0
                next(row for row in changed if row.get("kind") == 2 and row["operation_begin_ns"] == entry["monotonic_ns"])["abi"] = 0
        elif mutation == "operation_abi":
            entry = next(row for row in changed if row.get("kind") == 3)
            entry["abi"] = 0
            next(row for row in changed if row.get("kind") == 4 and row["operation_begin_ns"] == entry["monotonic_ns"])["abi"] = 0
        elif mutation == "peer":
            next(row for row in changed if row.get("kind") == 6)["remote_port"] += 1
        elif mutation == "final":
            changed.remove(next(row for row in changed if row.get("kind") == 14 and row["socket_cookie"] == receipt["server_identity"]["cookie"]))
        elif mutation == "install":
            next(row for row in changed if row.get("kind") == 12 and row["arguments"][4] == receipt["server_identity"]["inode"])["arguments"][4] += 1
        elif mutation == "marker":
            entry = next(row for row in changed if row.get("kind") == 7)
            entry["snapshot_hex"] = entry["snapshot_hex"][:-2] + "00"
        elif mutation == "exec":
            changed.remove(max((row for row in changed if row.get("kind") == 9), key=lambda row: row["monotonic_ns"]))
        elif mutation == "task":
            next(row for row in changed if row.get("kind") == 3)["thread_start_ns"] += 1
        elif mutation == "close":
            changed.remove(next(row for row in changed if row.get("kind") == 2 and row["syscall_id"] == 6))
        variants.append((changed, receipt))
    for changed, changed_receipt in variants:
        try:
            audit_task(changed, changed_receipt)
        except ValueError:
            continue
        raise AssertionError("Corrupt i386 ABI/task/socket evidence accepted")
    return len(variants)


def i386_audit_self_test():
    receipt = {"transport": "i386-exec", "status": "accepted", "pointer_bits": 32, "pid": 100,
               "begin_monotonic_ns": 30, "end_monotonic_ns": 1000,
               "messages_received_and_echoed": ["HAZIM_I386_A", "HAZIM_I386_B"],
               "server_identity": {"fd": 4, "inode": 104, "cookie": 204, "local_endpoint": ["127.0.0.1", 40000]},
               "client_identity": {"fd": 5, "inode": 105, "cookie": 205, "local_endpoint": ["127.0.0.1", 40001]}}
    common = {"record": "observation", "schema": "attribution-sensor-v6", "pid": 100, "tid": 100, "thread_start_ns": 1, "related_pid": 0,
              "abi": 1, "socket_cookie": 204, "arguments": [0] * 6, "syscall_id": 0}
    events = [{**common, "kind": 9, "monotonic_ns": 10, "abi": 0},
              {**common, "kind": 1, "monotonic_ns": 19, "syscall_id": 59, "abi": 0},
              {**common, "kind": 9, "monotonic_ns": 20, "operation_begin_ns": 19, "arguments": [59, 0, 0, 0, 0, 0]},
              {**common, "kind": 22, "schema": "attribution-sensor-v6", "monotonic_ns": 21, "operation_begin_ns": 19,
               "syscall_id": 11, "abi": 1, "result": 0, "arguments": [59, 0, 20, 0, 0, 0]}]

    def syscall(descriptor, syscall_id, beginning, ending, result):
        actual = {**common, "arguments": [descriptor, 0, 12, 0, 0, 0], "syscall_id": syscall_id}
        events.extend([{**actual, "kind": 1, "monotonic_ns": beginning},
                       {**actual, "kind": 2, "monotonic_ns": ending, "operation_begin_ns": beginning, "result": result}])

    for index, identity in enumerate((receipt["server_identity"], receipt["client_identity"])):
        arguments = [identity["fd"], identity["inode"] + 200, 10, 1, identity["inode"], 0]
        events.append({**common, "kind": 12, "monotonic_ns": 35 + index, "arguments": arguments})
        syscall(identity["fd"], 6, 800 + index * 10, 802 + index * 10, 0)
        events.append({**common, "kind": 14, "monotonic_ns": 801 + index * 10,
                       "arguments": arguments, "socket_cookie": identity["cookie"]})
    syscall(3, 4, 1100, 1101, 200)
    for index, marker in enumerate(receipt["messages_received_and_echoed"]):
        for kind in (3, 5):
            for identity_name, peer_name, offset in (("client_identity", "server_identity", 0), ("server_identity", "client_identity", 10)):
                identity, peer = receipt[identity_name], receipt[peer_name]
                beginning = 100 + index * 100 + (kind - 3) * 10 + offset
                actual = {**common, "socket_cookie": identity["cookie"], "protocol": 17,
                          "local_port": identity["local_endpoint"][1], "remote_port": peer["local_endpoint"][1],
                          "local_address_hex": "7f000001" + "0" * 24, "remote_address_hex": "7f000001" + "0" * 24}
                syscall(identity["fd"], 369 if kind == 3 else 371, beginning - 1, beginning + 2, len(marker))
                events.extend([{**actual, "kind": kind, "monotonic_ns": beginning},
                               {**actual, "kind": kind + 1, "monotonic_ns": beginning + 1,
                                "operation_begin_ns": beginning, "result": len(marker)}])
        for kind in (7, 8):
            for source, target in ((40000, 40001), (40001, 40000)):
                body = struct.pack("!BBHHHBBH4s4sHHHH", 0x45, 0, 28 + len(marker), 0, 0, 64, 17, 0,
                                   socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"), source, target, 8 + len(marker), 0) + marker.encode()
                local = source if kind == 7 else target
                events.append({**common, "kind": kind, "monotonic_ns": 150 + index * 100,
                               "snapshot_hex": body.hex(), "wire_size": len(body), "captured_size": len(body),
                               "socket_cookie": 204 if local == 40000 else 205})
    assert audit_task(events, receipt)["same_task_amd64_to_i386_exec_verified"]
    assert i386_negative_checks(events, receipt) == 17


def audit_exec_cloexec(events, receipt):
    from collections import Counter

    names = ("server_identity", "closed_identity", "retained_identity")
    server, closed, retained = [receipt[name] for name in names]
    if (receipt["status"] != "accepted" or not receipt["closed_descriptor_ebadf"] or
            not closed["cloexec"] or server["cloexec"] or retained["cloexec"] or
            receipt["retained_identity_after_exec"] != retained or
            receipt["messages_received_and_echoed"] != ["HAZIM_EXEC_BEFORE", "HAZIM_EXEC_AFTER"] or
            len({receipt[name]["cookie"] for name in names}) != 3 or any(not receipt[name]["cookie"] for name in names) or
            any(receipt[name]["endpoint"][0] != "127.0.0.1" for name in names)):
        raise ValueError("Actual exec/CLOEXEC application identities or receipts differ")
    raw = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}
    successes = sorted((row for row in events if row["kind"] == 9 and row["pid"] == receipt["pid"]), key=lambda row: row["monotonic_ns"])
    if len(successes) != 2:
        raise ValueError("Expected initial and replacement exec success evidence")
    succeeded = successes[1]
    execs = [row for row in raw.values() if row["syscall_id"] == 59 and row["abi"] == 0 and row["pid"] == receipt["pid"] and
             receipt["before_exec_monotonic_ns"] < row["monotonic_ns"] < succeeded["monotonic_ns"]]
    if len(execs) != 1 or not succeeded["monotonic_ns"] < receipt["after_exec_monotonic_ns"] or any(
            (row["pid"], row["tid"], row["thread_start_ns"]) != (execs[0]["pid"], execs[0]["tid"], execs[0]["thread_start_ns"]) for row in successes):
        raise ValueError("Replacement exec lacks actual same-task entry/success interval")
    executing = execs[0]
    tables = set()
    installed = {}
    finalized = {}
    for name in names:
        identity = receipt[name]
        installs = [row for row in events if row["kind"] == 12 and row["pid"] == receipt["pid"] and
                    row["arguments"][0] == identity["fd"] and row["arguments"][4] == identity["inode"] and
                    successes[0]["monotonic_ns"] < row["monotonic_ns"] < executing["monotonic_ns"]]
        if len(installs) != 1 or not installs[0]["arguments"][1] or not installs[0]["arguments"][2]:
            raise ValueError("Exec task lacks actual socket installation/table identity")
        install = installed[name] = installs[0]
        tables.add(install["arguments"][2])
        finals = [row for row in events if row["kind"] == 14 and row["arguments"][1] == install["arguments"][1] and
                  row["arguments"][4] == identity["inode"] and row["socket_cookie"] == identity["cookie"]]
        if len(finals) != 1:
            raise ValueError("Exec socket lacks unique file-final/inode/cookie evidence")
        finalized[name] = finals[0]
        flags = [row for row in events if row["kind"] == 2 and row["syscall_id"] == 72 and row["pid"] == receipt["pid"] and
                 raw[row["operation_begin_ns"]]["arguments"][:2] == [identity["fd"], 1] and
                 install["monotonic_ns"] < row["monotonic_ns"] < executing["monotonic_ns"]]
        if len(flags) != 1 or flags[0]["result"] != int(identity["cloexec"]):
            raise ValueError("Actual pre-exec F_GETFD result differs")
    exec_closes = [row for row in events if row["kind"] == 13 and row["pid"] == receipt["pid"] and
                   row["arguments"][1] == installed["closed_identity"]["arguments"][1] and
                   row["arguments"][4] == closed["inode"] and row["socket_cookie"] == closed["cookie"] and
                   row["arguments"][2] == installed["closed_identity"]["arguments"][2] and
                   row["tid"] == executing["tid"] and row["thread_start_ns"] == executing["thread_start_ns"]]
    if (len(tables) != 1 or len(exec_closes) != 1 or
            not executing["monotonic_ns"] < exec_closes[0]["monotonic_ns"] < succeeded["monotonic_ns"] or
            not exec_closes[0]["monotonic_ns"] < finalized["closed_identity"]["monotonic_ns"] < receipt["after_exec_monotonic_ns"]):
        raise ValueError("CLOEXEC lacks in-exec file close and final release before application resume")
    if any(row["syscall_id"] == 3 and row["pid"] == receipt["pid"] and row["arguments"][0] == closed["fd"] and
           installed["closed_identity"]["monotonic_ns"] < row["monotonic_ns"] < succeeded["monotonic_ns"] for row in raw.values()):
        raise ValueError("Explicit close cannot substitute for exec-time CLOEXEC closure")
    if not any(row["kind"] == 2 and row["pid"] == receipt["pid"] and row["syscall_id"] in (5, 262) and row["result"] == -9 and
               raw[row["operation_begin_ns"]]["arguments"][0] == closed["fd"] and
               succeeded["monotonic_ns"] < row["operation_begin_ns"] < row["monotonic_ns"] for row in events):
        raise ValueError("Missing actual post-exec EBADF descriptor check")
    expected = Counter()
    packets = Counter()
    for identity, marker in ((closed, b"HAZIM_EXEC_BEFORE"), (retained, b"HAZIM_EXEC_AFTER")):
        for kind in (4, 6):
            for current in (server, identity):
                expected[kind, current["cookie"], len(marker)] += 1
        for source, target in ((identity, server), (server, identity)):
            packets[7, source["endpoint"][1], target["endpoint"][1], source["cookie"], marker] += 1
            packets[8, source["endpoint"][1], target["endpoint"][1], target["cookie"], marker] += 1
    actual = Counter()
    entries = {row["monotonic_ns"]: row for row in events if row["kind"] in (3, 5)}
    operations = [row for row in events if row["kind"] in (4, 6)]
    if len(entries) != 8 or len(operations) != 8:
        raise ValueError("Exec task UDP operation counts differ")
    uninitialized_send_entries = 0
    for row in operations:
        entry = entries.get(row["operation_begin_ns"])
        phase = 0 if row["result"] == len(b"HAZIM_EXEC_BEFORE") else 1
        client = closed if phase == 0 else retained
        if (entry is None or entry["kind"] + 1 != row["kind"] or row["pid"] != receipt["pid"] or row["protocol"] != 17 or
                (entry["pid"], entry["tid"], entry["thread_start_ns"]) != (row["pid"], row["tid"], row["thread_start_ns"]) or
                (row["local_port"], row["remote_port"]) not in ((server["endpoint"][1], client["endpoint"][1]), (client["endpoint"][1], server["endpoint"][1])) or
                not entry["monotonic_ns"] < row["monotonic_ns"] or
                (phase == 0 and row["monotonic_ns"] >= executing["monotonic_ns"]) or
                (phase == 1 and entry["monotonic_ns"] <= succeeded["monotonic_ns"])):
            raise ValueError("Exec UDP operation crossed task, socket, endpoint or exec lifetime")
        if entry["socket_cookie"] != row["socket_cookie"]:
            containing = [returned for returned in events if returned["kind"] == 2 and returned["syscall_id"] == 44 and
                          returned["abi"] == 0 and (returned["pid"], returned["tid"], returned["thread_start_ns"]) == (row["pid"], row["tid"], row["thread_start_ns"]) and
                          raw[returned["operation_begin_ns"]]["arguments"][0] == closed["fd"] and
                          raw[returned["operation_begin_ns"]]["arguments"][2] == len(b"HAZIM_EXEC_BEFORE") and
                          returned["operation_begin_ns"] < entry["monotonic_ns"] < row["monotonic_ns"] < returned["monotonic_ns"] and returned["result"] == row["result"]]
            if entry["socket_cookie"] or row["kind"] != 4 or phase != 0 or row["socket_cookie"] != closed["cookie"] or len(containing) != 1:
                raise ValueError("Uninitialized send-entry cookie lacks actual descriptor-bound raw call")
            uninitialized_send_entries += 1

    if uninitialized_send_entries > 1:
        raise ValueError("More than one controlled send-entry cookie is uninitialized")
    for row in operations:
        actual[row["kind"], row["socket_cookie"], row["result"]] += 1
    if actual != expected:
        raise ValueError("Exec before/after UDP returns differ from actual echoes")
    observed = Counter()
    for row in events:
        if row["kind"] not in (7, 8):
            continue
        body = bytes.fromhex(row["snapshot_hex"])
        if (len(body) < 28 or body[0] != 0x45 or body[9] != 17 or
                len(body) != row["wire_size"] or len(body) != row["captured_size"] or
                struct.unpack("!H", body[2:4])[0] != len(body) or struct.unpack("!H", body[6:8])[0] & 0x3fff or
                body[12:16] != socket.inet_aton("127.0.0.1") or body[16:20] != body[12:16] or
                struct.unpack("!H", body[24:26])[0] != len(body) - 20):
            raise ValueError("Exec packet snapshot/header is incomplete")
        source, target = struct.unpack("!HH", body[20:24])
        observed[row["kind"], source, target, row["socket_cookie"], body[28:]] += 1
    if observed != packets:
        raise ValueError("Exec packet cookie/endpoints/markers differ")
    for name in ("server_identity", "retained_identity"):
        identity = receipt[name]
        last_use = max(row["monotonic_ns"] for row in operations if row["socket_cookie"] == identity["cookie"])
        closes = sorted((row for row in events if row["kind"] == 2 and row["syscall_id"] == 3 and row["pid"] == receipt["pid"] and row["result"] == 0 and
                         raw[row["operation_begin_ns"]]["arguments"][0] == identity["fd"] and row["operation_begin_ns"] > last_use), key=lambda row: row["operation_begin_ns"])
        if not closes or not closes[0]["operation_begin_ns"] <= finalized[name]["monotonic_ns"]:
            raise ValueError("Retained socket lacks explicit post-use close/final-file evidence")
    return {"exec_cloexec_application_echoes": 2, "exec_time_cloexec_close_and_final_verified": True,
            "closed_file_final_after_exec_success_ns": finalized["closed_identity"]["monotonic_ns"] - succeeded["monotonic_ns"],
            "send_entry_cookies_uninitialized_with_exact_raw_fd_proof": uninitialized_send_entries,
            "retained_socket_use_after_exec_verified": True, "controlled_packet_observations": 8,
            "actual_udp_send_returns": 4, "actual_udp_receive_returns": 4}


def exec_cloexec_negative_checks(rows, receipt):
    import copy

    events = [row for row in rows if row.get("record") == "observation"]
    closed = receipt["closed_identity"]
    raw = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}
    succeeded = max(row["monotonic_ns"] for row in events if row["kind"] == 9 and row["pid"] == receipt["pid"])
    executing = max(row["monotonic_ns"] for row in events if row["kind"] == 1 and row["syscall_id"] == 59 and row["monotonic_ns"] < succeeded)
    guards = 0
    mutations = ["early_final", "late_final", "wrong_flags", "wrong_retained", "wrong_peer", "missing_exec", "missing_ebadf", "missing_exec_close", "wrong_exec_close", "unexplained_zero_cookie", "wrong_entry_cookie", "missing_retained_close"]
    if any(row["kind"] == 3 and not row["socket_cookie"] for row in events):
        mutations.append("wrong_raw_fd_for_zero_cookie")
    for mutation in mutations:
        changed = copy.deepcopy(rows)
        if mutation in ("early_final", "late_final"):
            next(row for row in changed if row.get("kind") == 14 and row["socket_cookie"] == closed["cookie"])["monotonic_ns"] = executing - 1 if mutation == "early_final" else receipt["after_exec_monotonic_ns"] + 1
        elif mutation == "wrong_flags":
            next(row for row in changed if row.get("kind") == 2 and row["syscall_id"] == 72 and row["result"] == 1 and
                 raw[row["operation_begin_ns"]]["arguments"][:2] == [closed["fd"], 1] and row["monotonic_ns"] < executing)["result"] = 0
        elif mutation == "wrong_retained":
            next(row for row in changed if row.get("kind") == 4 and row["socket_cookie"] == receipt["retained_identity"]["cookie"])["socket_cookie"] = closed["cookie"]
        elif mutation == "wrong_peer":
            next(row for row in changed if row.get("kind") == 6)["remote_port"] = 0
        elif mutation == "missing_exec":
            changed = [row for row in changed if row.get("kind") != 9 or row["monotonic_ns"] != succeeded]
        elif mutation == "missing_ebadf":
            changed = [row for row in changed if row.get("kind") != 2 or row["syscall_id"] not in (5, 262) or row["result"] != -9]
        elif mutation == "missing_exec_close":
            changed = [row for row in changed if row.get("kind") != 13]
        elif mutation == "wrong_exec_close":
            next(row for row in changed if row.get("kind") == 13)["arguments"][1] = 0
        elif mutation == "unexplained_zero_cookie":
            next(row for row in changed if row.get("kind") == 3 and row["socket_cookie"] == receipt["retained_identity"]["cookie"])["socket_cookie"] = 0
        elif mutation == "wrong_entry_cookie":
            next(row for row in changed if row.get("kind") == 3)["socket_cookie"] = max(receipt[name]["cookie"] for name in ("server_identity", "closed_identity", "retained_identity")) + 1
        elif mutation == "missing_retained_close":
            changed = [row for row in changed if row.get("kind") != 2 or row["syscall_id"] != 3 or
                       raw[row["operation_begin_ns"]]["arguments"][0] != receipt["retained_identity"]["fd"]]
        else:
            uninitialized = next(row for row in events if row["kind"] == 3 and not row["socket_cookie"])
            returned = next(row for row in events if row["kind"] == 4 and row["operation_begin_ns"] == uninitialized["monotonic_ns"])
            completed = next(row for row in events if row["kind"] == 2 and row["syscall_id"] == 44 and row["pid"] == receipt["pid"] and
                             row["operation_begin_ns"] < uninitialized["monotonic_ns"] < returned["monotonic_ns"] < row["monotonic_ns"])
            next(row for row in changed if row.get("kind") == 1 and row["monotonic_ns"] == completed["operation_begin_ns"])["arguments"][0] = receipt["retained_identity"]["fd"]
        try:
            audit_task(changed, receipt)
        except ValueError:
            guards += 1
        else:
            raise AssertionError("Corrupt exec lifecycle evidence accepted: " + mutation)
    return guards


def audit_fd_history(events, receipt):
    from collections import Counter

    markers = [b"HAZIM_INHERIT", b"HAZIM_SHARED", b"HAZIM_TRANSFER"]
    child = receipt["child"]
    parent_pid, child_pid = receipt["pid"], receipt["child_pid"]
    shared, server = receipt["shared_identity"], receipt["server_identity"]
    if (receipt["status"] != "accepted" or child["status"] != "accepted" or child["pid"] != child_pid or
            parent_pid == child_pid or not child["received_cloexec"] or
            receipt["messages_received_and_echoed"] != [marker.decode() for marker in markers] or
            receipt["endpoint"][0] != "127.0.0.1" or receipt["client_endpoint"][0] != "127.0.0.1" or
            shared["cookie"] <= 0 or server["cookie"] <= 0 or shared["cookie"] == server["cookie"] or
            any(child[name][key] != shared[key] for name in ("inherited_identity", "transferred_identity") for key in ("inode", "cookie"))):
        raise ValueError("Descriptor application identities/receipts differ")
    forks = [row for row in events if row["kind"] == 20 and row["pid"] == parent_pid and row["related_pid"] == child_pid]
    if len(forks) != 1 or forks[0]["arguments"][1] != child_pid:
        raise ValueError("Missing exact descriptor child fork")
    fork = forks[0]
    parent_table, child_table = fork["arguments"][2:4]
    if not parent_table or not child_table or parent_table == child_table:
        raise ValueError("Fork must show distinct parent/child descriptor tables")
    raw_entries = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}

    def successful(syscall_id, pid, descriptor):
        return [row for row in events if row["kind"] == 2 and row["pid"] == pid and row["abi"] == 0 and
                row["syscall_id"] == syscall_id and row["operation_begin_ns"] in raw_entries and
                raw_entries[row["operation_begin_ns"]]["arguments"][0] == descriptor]

    installs = [row for row in events if row["kind"] == 12 and row["pid"] == parent_pid and
                row["arguments"][0] == shared["fd"] and row["arguments"][4] == shared["inode"]]
    if len(installs) != 1 or not installs[0]["arguments"][1] or installs[0]["arguments"][2] != parent_table:
        raise ValueError("Original shared socket install/table is ambiguous")
    installed = installs[0]
    file_id = installed["arguments"][1]
    if installed["monotonic_ns"] >= fork["monotonic_ns"]:
        raise ValueError("Shared socket was not installed before fork")
    sent = successful(46, parent_pid, receipt["control_fd"])
    received = successful(47, child_pid, child["control_fd"])
    if len(sent) != 1 or len(received) != 1 or sent[0]["result"] != 1 or received[0]["result"] != 1:
        raise ValueError("Missing successful sendmsg/recvmsg transfer calls")
    transfer = received[0]
    if raw_entries[sent[0]["operation_begin_ns"]]["monotonic_ns"] >= transfer["monotonic_ns"]:
        raise ValueError("Transfer receive completed before sender entry")
    receive_checks = [row for row in events if row["kind"] == 15 and row["pid"] == child_pid and
                      row["arguments"][1] == file_id and transfer["operation_begin_ns"] < row["monotonic_ns"] < transfer["monotonic_ns"]]
    received_installs = [row for row in events if row["kind"] == 12 and row["pid"] == child_pid and
                         row["arguments"][0] == child["transferred_identity"]["fd"] and row["arguments"][1] == file_id and
                         transfer["operation_begin_ns"] < row["monotonic_ns"] < transfer["monotonic_ns"]]
    if len(receive_checks) != 1 or len(received_installs) != 1 or receive_checks[0]["result"] != 0:
        raise ValueError("Transfer requires successful receive check plus actual descriptor installation")
    for row in receive_checks + received_installs:
        if (row["socket_cookie"] != shared["cookie"] or row["arguments"][4] != shared["inode"] or
                row["arguments"][2] != child_table or row["thread_start_ns"] != fork["arguments"][0]):
            raise ValueError("Transferred file/socket/table/child lifetime differs")
    def first_close(pid, descriptor, installed_at, deadline):
        closes = sorted((row for row in successful(3, pid, descriptor) if
                         installed_at < row["operation_begin_ns"] < deadline and row["result"] == 0), key=lambda row: row["monotonic_ns"])
        if not closes:
            raise ValueError("Descriptor lifetime lacks a successful close")
        closing = closes[0]
        for row in events:
            if (row["kind"] != 2 or row["pid"] != pid or row["result"] != descriptor or
                    not installed_at < row["operation_begin_ns"] < row["monotonic_ns"] < closing["operation_begin_ns"]):
                continue
            if row["syscall_id"] in (2, 32, 33, 41, 43, 85, 257, 288, 292, 437) or (
                    row["syscall_id"] == 72 and raw_entries[row["operation_begin_ns"]]["arguments"][1] in (0, 1030)):
                raise ValueError("Descriptor was reassigned before its observed close")
        return [closing]

    early_closes = first_close(child_pid, child["inherited_identity"]["fd"], fork["monotonic_ns"], transfer["operation_begin_ns"])
    late_closes = first_close(child_pid, child["transferred_identity"]["fd"], transfer["monotonic_ns"], float("inf"))
    parent_closes = first_close(parent_pid, shared["fd"], installed["monotonic_ns"], float("inf"))
    if parent_closes[0]["operation_begin_ns"] <= transfer["monotonic_ns"]:
        raise ValueError("Parent did not retain the shared descriptor through transfer")
    finals = [row for row in events if row["kind"] == 14 and row["arguments"][1] == file_id]
    if (len(finals) != 1 or finals[0]["arguments"][4] != shared["inode"] or finals[0]["socket_cookie"] != shared["cookie"] or
            finals[0]["monotonic_ns"] <= max(row["operation_begin_ns"] for row in late_closes + parent_closes)):
        raise ValueError("Shared socket final lifetime differs or ends before all alias closes")
    expected_operations = Counter({(parent_pid, server["cookie"], len(marker)): 1 for marker in markers})
    expected_operations[(parent_pid, shared["cookie"], len(markers[1]))] = 1
    expected_operations.update({(child_pid, shared["cookie"], len(marker)): 1 for marker in (markers[0], markers[2])})
    operation_entries = {row["monotonic_ns"]: row for row in events if row["kind"] in (3, 5) and row["protocol"] == 17}
    if len(operation_entries) != 12:
        raise ValueError("Descriptor UDP operation entry count differs")
    server_port, client_port = receipt["endpoint"][1], receipt["client_endpoint"][1]
    receives_without_peer_output = 0
    for kind in (4, 6):
        operations = [row for row in events if row["kind"] == kind and row["protocol"] == 17]
        if Counter((row["pid"], row["socket_cookie"], row["result"]) for row in operations) != expected_operations:
            raise ValueError("Descriptor socket-use completions differ from application receipts")
        for row in operations:
            entry = operation_entries.get(row["operation_begin_ns"])
            expected_ports = (server_port, client_port) if row["socket_cookie"] == server["cookie"] else (client_port, server_port)
            if kind == 6 and row["socket_cookie"] == shared["cookie"] and row["remote_port"] == 0:
                descriptor = shared["fd"] if row["pid"] == parent_pid else (
                    child["inherited_identity"]["fd"] if row["monotonic_ns"] < transfer["operation_begin_ns"] else child["transferred_identity"]["fd"])
                raw_receives = [raw for raw in successful(45, row["pid"], descriptor) if
                                raw["tid"] == row["tid"] and raw["result"] == row["result"] and
                                raw["operation_begin_ns"] < row["operation_begin_ns"] < row["monotonic_ns"] < raw["monotonic_ns"] and
                                raw_entries[raw["operation_begin_ns"]]["arguments"][4:6] == [0, 0]]
                if len(raw_receives) != 1:
                    raise ValueError("Missing UDP receive peer lacks actual null-output recvfrom evidence")
                expected_ports = client_port, 0
                receives_without_peer_output += 1
            if (not entry or entry["kind"] + 1 != kind or
                    (entry["pid"], entry["tid"], entry["thread_start_ns"]) != (row["pid"], row["tid"], row["thread_start_ns"]) or
                    entry["socket_cookie"] != row["socket_cookie"] or
                    (row["local_port"], row["remote_port"]) != expected_ports):
                raise ValueError("Descriptor socket operation crossed lifetime/cookie/endpoints")
            if row["pid"] == child_pid:
                if row["thread_start_ns"] != fork["arguments"][0]:
                    raise ValueError("Child socket operation crossed task lifetime")
                allowed = ((fork["monotonic_ns"], early_closes[0]["operation_begin_ns"]),
                           (transfer["monotonic_ns"], late_closes[0]["operation_begin_ns"]))
                if not any(lower < row["operation_begin_ns"] < row["monotonic_ns"] < upper for lower, upper in allowed):
                    raise ValueError("Child used socket outside either descriptor lifetime")
    packets = Counter()
    for row in events:
        if row["kind"] not in (7, 8):
            continue
        body = bytes.fromhex(row["snapshot_hex"])
        if (len(body) < 28 or row["captured_size"] != row["wire_size"] or len(body) != row["wire_size"] or
                body[0] != 0x45 or body[9] != 17 or body[12:20] != socket.inet_aton("127.0.0.1") * 2 or
                struct.unpack("!H", body[2:4])[0] != len(body) or struct.unpack("!H", body[6:8])[0] & 0x3fff):
            raise ValueError("Descriptor packet header/length differs")
        source_port, target_port, udp_size, _checksum = struct.unpack("!HHHH", body[20:28])
        if (udp_size != len(body) - 20 or body[28:] not in markers or
                (source_port, target_port) not in ((client_port, server_port), (server_port, client_port))):
            raise ValueError("Descriptor packet marker/peer differs")
        local_port = source_port if row["kind"] == 7 else target_port
        if row["socket_cookie"] != (shared["cookie"] if local_port == client_port else server["cookie"]):
            raise ValueError("Descriptor packet cookie differs")
        packets[(row["kind"], source_port, target_port, body[28:])] += 1
    if packets != Counter({(kind, source, target, marker): 1 for kind in (7, 8)
                          for source, target in ((client_port, server_port), (server_port, client_port)) for marker in markers}):
        raise ValueError("Missing/duplicate descriptor packet snapshots")
    return {"fd_history_application_echoes": 3, "inherited_socket_use_verified": True,
            "retained_parent_socket_use_verified": True, "scm_rights_install_use_close_verified": True,
            "distinct_forked_files_tables": True, "controlled_packet_observations": 12,
            "actual_udp_send_returns": 6, "actual_udp_receive_returns": 6,
            "receive_peers_not_requested_by_application": receives_without_peer_output}


def fd_history_negative_checks(rows, receipt):
    import copy

    events = [row for row in rows if row.get("record") == "observation"]
    inode = receipt["shared_identity"]["inode"]
    checks = 0
    for kind, field, value in ((20, "arguments", [1, receipt["child_pid"], 1, 1, 0, 0]), (15, "result", -1),
                               (14, "monotonic_ns", 1), (12, "arguments", [receipt["shared_identity"]["fd"], 0, 0, 0, inode, 0]),
                               (4, "socket_cookie", 0), (7, "snapshot_hex", "00")):
        changed = copy.deepcopy(rows)
        next(row for row in changed if row.get("kind") == kind and
             (kind not in (12, 14) or row["arguments"][4] == inode))[field] = value
        try:
            audit_task(changed, receipt)
        except ValueError:
            checks += 1
            continue
        raise AssertionError("Corrupt descriptor evidence accepted: " + field)
    for kind in (15, 12):
        changed = [row for row in rows if not (row.get("kind") == kind and row["pid"] == receipt["child_pid"])]
        try:
            audit_task(changed, receipt)
        except ValueError:
            checks += 1
            continue
        raise AssertionError("Missing received descriptor evidence accepted")
    receive = next(row for row in events if row["kind"] == 6 and row["socket_cookie"] == receipt["shared_identity"]["cookie"] and row["remote_port"] == 0)
    raw_entry = next(row for row in events if row["kind"] == 1 and row["syscall_id"] == 45 and
                     row["pid"] == receive["pid"] and row["monotonic_ns"] < receive["operation_begin_ns"] and
                     row["arguments"][4:6] == [0, 0] and any(
                         ending["kind"] == 2 and ending["operation_begin_ns"] == row["monotonic_ns"] and ending["monotonic_ns"] > receive["monotonic_ns"] for ending in events))
    changed = copy.deepcopy(rows)
    next(row for row in changed if row.get("kind") == 1 and row["monotonic_ns"] == raw_entry["monotonic_ns"])["arguments"][4] = 1
    try:
        audit_task(changed, receipt)
    except ValueError:
        checks += 1
    else:
        raise AssertionError("Unexplained missing receive peer accepted")
    transfer = next(row for row in events if row["kind"] == 2 and row["pid"] == receipt["child_pid"] and row["syscall_id"] == 47)
    raw_entries = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}
    closing = min((row for row in events if row["kind"] == 2 and row["pid"] == receipt["child_pid"] and row["syscall_id"] == 3 and
                   raw_entries[row["operation_begin_ns"]]["arguments"][0] == receipt["child"]["transferred_identity"]["fd"] and
                   row["operation_begin_ns"] > transfer["monotonic_ns"] and row["result"] == 0), key=lambda row: row["monotonic_ns"])
    changed = [row for row in rows if row.get("sequence") not in (closing["sequence"], raw_entries[closing["operation_begin_ns"]]["sequence"])]
    try:
        audit_task(changed, receipt)
    except ValueError:
        checks += 1
    else:
        raise AssertionError("Reused regular-file FD close substituted for missing socket close")
    return checks


def audit_tcp_task(events, receipt):
    markers = ["HAZIM_TCP_%03d" % index for index in range(16)]
    if receipt["status"] != "accepted" or receipt["messages_received_and_echoed"] != markers:
        raise ValueError("TCP application receipts differ")
    server_port, client_port = receipt["endpoint"][1], receipt["client_endpoint"][1]
    states = {client_port: receipt["client_identity"], server_port: receipt["accepted_identity"]}
    entries = {row["monotonic_ns"]: row for row in events if row["kind"] in (3, 5)}
    totals = {(kind, port): 0 for kind in (4, 6) for port in states}
    for row in events:
        if row["kind"] not in (4, 6):
            continue
        entry = entries.get(row["operation_begin_ns"])
        local = row["local_port"]
        if (not entry or entry["kind"] + 1 != row["kind"] or
                (entry["pid"], entry["tid"], entry["thread_start_ns"]) != (row["pid"], row["tid"], row["thread_start_ns"]) or
                row["pid"] != receipt["pid"] or row["protocol"] != 6 or local not in states or
                row["remote_port"] != (server_port if local == client_port else client_port) or
                row["socket_cookie"] != states[local]["cookie"] or row["result"] <= 0):
            raise ValueError("TCP completion identity, cookie, endpoints or result differs")
        totals[row["kind"], local] += row["result"]
    if any(total != 208 for total in totals.values()) or len(entries) != sum(row["kind"] in (4, 6) for row in events):
        raise ValueError("TCP byte totals or paired operations differ")
    observed = {(kind, source, target): [] for kind in (7, 8) for source, target in ((client_port, server_port), (server_port, client_port))}
    for row in events:
        if row["kind"] not in (7, 8):
            continue
        body = bytes.fromhex(row["snapshot_hex"])
        if len(body) < 40 or body[0] != 0x45 or body[9] != 6 or len(body) != row["wire_size"] or len(body) != row["captured_size"]:
            raise ValueError("TCP snapshot is missing or truncated")
        if struct.unpack("!H", body[2:4])[0] != len(body) or body[12:16] != socket.inet_aton("127.0.0.1") or body[16:20] != body[12:16]:
            raise ValueError("TCP IP endpoints/length differ")
        source, target = struct.unpack("!HH", body[20:24])
        offset = 20 + (body[32] >> 4) * 4
        if offset < 40 or offset > len(body) or (row["kind"], source, target) not in observed:
            raise ValueError("TCP header or port differs")
        payload = body[offset:]
        if payload:
            local = source if row["kind"] == 7 else target
            if row["socket_cookie"] != states[local]["cookie"]:
                raise ValueError("TCP data snapshot cookie differs from application socket")
            observed[row["kind"], source, target].append(payload.decode("ascii"))
    if any(sorted(values) != markers for values in observed.values()):
        raise ValueError("TCP data markers are missing, changed or duplicated")
    for identity in (receipt["listener_identity"], receipt["client_identity"], receipt["accepted_identity"]):
        installs = [row for row in events if row["kind"] == 12 and row["arguments"][0] == identity["fd"] and row["arguments"][4] == identity["inode"]]
        if len(installs) != 1 or identity["cookie"] == 0:
            raise ValueError("TCP application descriptor/inode installation differs")
        finals = [row for row in events if row["kind"] == 14 and row["arguments"][1] == installs[0]["arguments"][1] and
                  row["arguments"][4] == identity["inode"] and row["socket_cookie"] == identity["cookie"]]
        if len(finals) != 1:
            raise ValueError("TCP socket final identity/cookie differs")
    raw = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}
    connects = [row for row in events if row["kind"] == 2 and row["syscall_id"] == 42 and
                raw[row["operation_begin_ns"]]["arguments"][0] == receipt["client_identity"]["fd"]]
    if len(connects) != 1 or connects[0]["result"] not in (0, -115):
        raise ValueError("TCP connect lacks an immediate or nonblocking completion path")
    if connects[0]["result"] == -115:
        first_send = min(row["monotonic_ns"] for row in events if row["kind"] == 3 and row["local_port"] == client_port)
        if not any(row["kind"] == 2 and row["syscall_id"] == 55 and row["result"] == 0 and
                   raw[row["operation_begin_ns"]]["arguments"][:3] == [receipt["client_identity"]["fd"], 1, 4] and
                   connects[0]["monotonic_ns"] < row["monotonic_ns"] < first_send for row in events):
            raise ValueError("Nonblocking connect lacks SO_ERROR check before successful data exchange")
    if not any(row["kind"] == 2 and row["syscall_id"] == 288 and row["result"] == receipt["accepted_identity"]["fd"] and
               raw[row["operation_begin_ns"]]["arguments"][0] == receipt["listener_identity"]["fd"] for row in events):
        raise ValueError("Missing successful TCP accept syscall")
    forks = [row for row in events if row["kind"] == 20 and row["pid"] == receipt["pid"]]
    if len(forks) != 1 or forks[0]["arguments"][1] != receipt["pid"] or not forks[0]["arguments"][2] or forks[0]["arguments"][2] != forks[0]["arguments"][3]:
        raise ValueError("TCP worker lacks actual shared descriptor-table evidence")
    worker = forks[0]
    for name in ("listener_identity", "client_identity", "accepted_identity"):
        identity = receipt[name]
        install = next(row for row in events if row["kind"] == 12 and row["arguments"][0] == identity["fd"] and row["arguments"][4] == identity["inode"])
        if install["arguments"][2] != worker["arguments"][2]:
            raise ValueError("TCP socket installation crossed shared descriptor table")
        if name == "accepted_identity" and (install["tid"] != worker["related_pid"] or install["thread_start_ns"] != worker["arguments"][0]):
            raise ValueError("Accepted socket installation lacks actual worker identity")
    return {"tcp_application_echoes": 16, "tcp_bytes_per_direction": 208,
            "tcp_data_packet_observations": 64, "tcp_socket_install_final_matches": 3,
            "tcp_nonblocking_connect_observed": connects[0]["result"] == -115,
            "tcp_worker_shared_files_table_verified": True}


def audit_http_task(events, receipt):
    import http.client
    transactions = receipt["transactions"]
    if (receipt["status"] != "accepted" or receipt["endpoint"] != ["10.0.0.1", 80] or len(transactions) != 4 or
            len({item["cookie"] for item in transactions}) != 4):
        raise ValueError("HTTP workload endpoint/count/cookies differ")
    entries = {row["monotonic_ns"]: row for row in events if row["kind"] in (3, 5)}
    raw = {row["monotonic_ns"]: row for row in events if row["kind"] == 1}
    known_cookies = {item["cookie"] for item in transactions}
    completions = [row for row in events if row["kind"] in (4, 6)]
    if len(entries) != len(completions):
        raise ValueError("HTTP socket operations are unpaired")
    for row in completions:
        entry = entries.get(row["operation_begin_ns"])
        if (not entry or entry["kind"] + 1 != row["kind"] or row["socket_cookie"] not in known_cookies or
                (entry["pid"], entry["tid"], entry["thread_start_ns"]) != (row["pid"], row["tid"], row["thread_start_ns"]) or
                row["pid"] != receipt["pid"] or row["protocol"] != 6 or row["result"] < 0 or row["remote_port"] != 80 or
                row["remote_address_hex"][:8] != "0a000001" or row["local_address_hex"][:8] != "0a00000a"):
            raise ValueError("HTTP socket identity, endpoint or result differs")
    for index, item in enumerate(transactions):
        marker = "/hazim-attribution-" + receipt["stamp"] + "/" + str(index)
        if (item["marker"] != marker or item["status"] != 200 or not 0 < item["response_size"] <= 65536 or
                not item["cookie"] or item["local_endpoint"][0] != "10.0.0.10"):
            raise ValueError("HTTP application receipt differs")
        sends = [row for row in completions if row["kind"] == 4 and row["socket_cookie"] == item["cookie"]]
        receives = [row for row in completions if row["kind"] == 6 and row["socket_cookie"] == item["cookie"]]
        if sum(row["result"] for row in sends) < len(marker) + 16 or sum(row["result"] for row in receives) < item["response_size"]:
            raise ValueError("HTTP socket byte counts cannot contain application data")
        if any(row["local_port"] != item["local_endpoint"][1] for row in sends + receives):
            raise ValueError("HTTP local port differs")
        streams = {7: bytearray(), 8: bytearray()}
        for row in events:
            if row["kind"] not in streams or row["socket_cookie"] != item["cookie"]:
                continue
            body = bytes.fromhex(row["snapshot_hex"])
            if len(body) < 40 or body[0] != 0x45 or body[9] != 6 or struct.unpack("!H", body[6:8])[0] & 0x3fff:
                raise ValueError("HTTP snapshot IPv4/TCP header differs")
            offset = 20 + (body[32] >> 4) * 4
            if offset < 40 or offset > len(body):
                raise ValueError("HTTP TCP header length differs")
            streams[row["kind"]].extend(body[offset:])
        if streams[7].count(("GET " + marker + " HTTP/1.1\r\n").encode()) != 1 or streams[8].count(b" 200 ") != 1:
            raise ValueError("HTTP request/response marker does not occur exactly once")

        class CapturedSocket:
            def makefile(self, _mode):
                return io.BytesIO(streams[8])

        with http.client.HTTPResponse(CapturedSocket()) as response:
            response.begin()
            response_body = response.read(65537)
            if (response.status != item["status"] or len(response_body) != item["response_size"] or
                    hashlib.sha256(response_body).hexdigest() != item["response_sha256"]):
                raise ValueError("Captured HTTP response differs from actual application receipt")
        installs = [row for row in events if row["kind"] == 12 and row["arguments"][0] == item["fd"] and row["arguments"][4] == item["inode"]]
        if len(installs) != 1 or len([row for row in events if row["kind"] == 14 and
                row["arguments"][1] == installs[0]["arguments"][1] and row["arguments"][4] == item["inode"] and row["socket_cookie"] == item["cookie"]]) != 1:
            raise ValueError("HTTP socket installation/final lifetime differs")
        first_send = min(row["operation_begin_ns"] for row in sends)
        connects = [row for row in events if row["kind"] == 2 and row["syscall_id"] == 42 and
                    installs[0]["monotonic_ns"] < row["monotonic_ns"] < first_send and
                    raw[row["operation_begin_ns"]]["arguments"][0] == item["fd"]]
        if len(connects) != 1 or connects[0]["result"] not in (0, -115):
            raise ValueError("HTTP connect failed or is ambiguous")
        if connects[0]["result"] == -115 and not any(row["kind"] == 2 and row["syscall_id"] == 55 and row["result"] == 0 and
                connects[0]["monotonic_ns"] < row["monotonic_ns"] < first_send and
                raw[row["operation_begin_ns"]]["arguments"][:3] == [item["fd"], 1, 4] for row in events):
            raise ValueError("HTTP nonblocking connect lacks SO_ERROR call")
    return {"http_application_receipts": 4, "http_socket_install_final_matches": 4}


def audit_frames(rows, receipt, data, capture_netns_inum, capture_netns_cookie):
    from scapy.utils import RawPcapReader
    clocks = [row for row in rows if row.get("record") == "clock"]
    if len(clocks) != 2 or {row["phase"] for row in clocks} != {"before", "after"}:
        raise ValueError("Frame join lacks recorder clock bounds")
    lower = min(row["realtime_before_ns"] - row["monotonic_ns"] for row in clocks)
    upper = max(row["realtime_after_ns"] - row["monotonic_ns"] for row in clocks)
    if (upper < lower or upper - lower > 1000000 or receipt["netns_inum"] != capture_netns_inum or
            not capture_netns_cookie or receipt["netns_cookie"] != capture_netns_cookie or
            any(item["netns_cookie"] != capture_netns_cookie for item in receipt["transactions"])):
        raise ValueError("Frame join clock uncertainty or capture namespace differs")
    frames = []
    by_hash = {}
    with RawPcapReader(io.BytesIO(data)) as reader:
        if reader.linktype != 1:
            raise ValueError("Capture is not Ethernet DLT_EN10MB")
        for ordinal, (body, metadata) in enumerate(reader):
            if metadata.caplen != metadata.wirelen or len(body) != metadata.caplen:
                raise ValueError("Ethernet frame is truncated")
            stamp = metadata.sec * 1000000000 + metadata.usec * (1 if reader.nano else 1000)
            frame = {"ordinal": ordinal, "realtime_ns": stamp, "frame_sha256": hashlib.sha256(body).hexdigest(), "frame_size": len(body)}
            frames.append(frame)
            if len(body) >= 34 and body[12:14] == b"\x08\x00":
                size = struct.unpack("!H", body[16:18])[0]
                if size < 20 or size + 14 > len(body):
                    raise ValueError("Ethernet IPv4 frame length differs")
                key = hashlib.sha256(body[14:14 + size]).hexdigest()
                by_hash.setdefault(key, []).append(frame)
    bindings = []
    used = set()
    for row in rows:
        if row.get("kind") not in (7, 8):
            continue
        snapshot = bytes.fromhex(row["snapshot_hex"])
        if (len(snapshot) != row["wire_size"] or len(snapshot) != row["captured_size"] or
                not row["socket_cookie"] or row["netns_cookie"] != capture_netns_cookie):
            raise ValueError("Snapshot is truncated or lacks socket/namespace identity")
        key = hashlib.sha256(snapshot).hexdigest()
        candidates = [frame for frame in by_hash.get(key, []) if
                      row["monotonic_ns"] + lower - 5000000 <= frame["realtime_ns"] <= row["monotonic_ns"] + upper + 5000000]
        if len(candidates) != 1 or candidates[0]["ordinal"] in used:
            raise ValueError("Exact IP-to-Ethernet frame join is missing, ambiguous or reused")
        frame = candidates[0]
        used.add(frame["ordinal"])
        bindings.append({**frame, "observation_sequence": row["sequence"], "snapshot_sha256": key,
                         "socket_cookie": row["socket_cookie"], "kind": row["kind"]})
    if not bindings:
        raise ValueError("No actual snapshot-to-Ethernet matches")
    return {"exact_ethernet_frame_matches": len(bindings), "capture_frames": len(frames),
            "unassigned_capture_frames": len(frames) - len(used), "clock_uncertainty_ns": upper - lower,
            "capture_netns_inum": capture_netns_inum, "capture_netns_cookie": capture_netns_cookie, "frame_bindings": bindings}


def audit_capture(rows, receipt, data, log, capture_netns_inum, capture_netns_cookie):
    import re
    facts = audit_frames(rows, receipt, data, capture_netns_inum, capture_netns_cookie)
    counters = []
    for label in ("captured", "received by filter", "dropped by kernel"):
        matches = re.findall(r"^(\d+) packets " + label + r"$", log, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("Missing/ambiguous tcpdump counter: " + label)
        counters.append(int(matches[0]))
    if counters != [facts["capture_frames"], facts["capture_frames"], 0]:
        raise ValueError("PCAP record/drop/counter discrepancy")
    return {**facts, "tcpdump_captured": counters[0], "tcpdump_received": counters[1], "tcpdump_dropped": counters[2]}


def http_workload(root, endpoint=("10.0.0.1", 80)):
    import http.client
    manifest = json.loads((root / "manifest.json").read_text())
    transactions = []
    for index in range(4):
        marker = "/hazim-attribution-" + manifest["stamp"] + "/" + str(index)
        connection = http.client.HTTPConnection(*endpoint, timeout=3)
        try:
            connection.connect()
            client = connection.sock
            identity = {"fd": client.fileno(), "inode": os.fstat(client.fileno()).st_ino,
                        "cookie": struct.unpack("=Q", client.getsockopt(socket.SOL_SOCKET, 57, 8))[0],
                        "netns_cookie": struct.unpack("=Q", client.getsockopt(socket.SOL_SOCKET, 71, 8))[0],
                        "local_endpoint": client.getsockname()}
            connection.request("GET", marker, headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read(65537)
            if response.status != 200 or not body or len(body) > 65536:
                raise ValueError("HTTP fixture did not return bounded successful application data")
            transactions.append({**identity, "marker": marker, "status": response.status,
                                 "response_size": len(body), "response_sha256": hashlib.sha256(body).hexdigest()})
        finally:
            connection.close()
    save(root / "workload.json", {"transport": "ethernet-http", "status": "accepted", "pid": os.getpid(),
            "stamp": manifest["stamp"], "endpoint": endpoint, "transactions": transactions,
            "netns_cookie": transactions[0]["netns_cookie"],
            "netns_inum": os.stat("/proc/self/ns/net").st_ino})


def tcp_workload(root):
    received = []
    errors = []
    accepted = []

    def identity(connection):
        return {"fd": connection.fileno(), "inode": os.fstat(connection.fileno()).st_ino,
                "cookie": struct.unpack("=Q", connection.getsockopt(socket.SOL_SOCKET, 57, 8))[0]}

    def receive_exact(connection, size):
        content = bytearray()
        while len(content) < size:
            body = connection.recv(size - len(content))
            if not body:
                raise ValueError("Premature TCP EOF")
            content.extend(body)
        return bytes(content)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(3)
        endpoint = server.getsockname()
        listener_identity = identity(server)

        def receive():
            try:
                connection, _peer = server.accept()
                with connection:
                    connection.settimeout(3)
                    accepted.append(identity(connection))
                    for index in range(16):
                        expected = ("HAZIM_TCP_%03d" % index).encode()
                        body = receive_exact(connection, len(expected))
                        if body != expected:
                            raise ValueError("TCP marker differs")
                        received.append(body.decode())
                        connection.sendall(body)
            except Exception as error:
                errors.append(str(error))

        thread = threading.Thread(target=receive)
        thread.start()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client_identity = identity(client)
            client.connect(endpoint)
            client_endpoint = client.getsockname()
            for index in range(16):
                body = ("HAZIM_TCP_%03d" % index).encode()
                client.sendall(body)
                if receive_exact(client, len(body)) != body:
                    raise ValueError("TCP application echo differs")
        thread.join(timeout=4)
        if thread.is_alive() or errors or len(received) != 16 or len(accepted) != 1:
            raise ValueError("TCP fixture failed: " + repr(errors))
    save(root / "workload.json", {"transport": "tcp", "status": "accepted", "pid": os.getpid(),
         "messages_received_and_echoed": received, "endpoint": endpoint, "client_endpoint": client_endpoint,
         "listener_identity": listener_identity, "client_identity": client_identity, "accepted_identity": accepted[0]})


def workload(root):
    if (root / "manifest.json").exists() and json.loads((root / "manifest.json").read_text()).get("task_mode") == "i386-exec":
        binary = root / "attribution-i386"
        binary.chmod(0o700)
        os.execv(str(binary), [str(binary), str(root / "workload.json")])
    if (root / "manifest.json").is_file():
        mode = json.loads((root / "manifest.json").read_text()).get("task_mode")
        if mode == "tcp":
            return tcp_workload(root)
        if mode == "ethernet-http":
            return http_workload(root)
        if mode == "fd-history":
            return fd_history_workload(root)
        if mode == "exec-cloexec":
            return exec_cloexec_workload(root)
    received = []
    errors = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(3)
        endpoint = server.getsockname()

        def receive():
            try:
                for index in range(32):
                    body, peer = server.recvfrom(4096)
                    prefix = "HAZIM_LIVE_" if index < 16 else "HAZIM_CONN_"
                    if body != (prefix + "%03d" % (index % 16)).encode():
                        raise ValueError("UDP marker mismatch")
                    received.append(body.decode())
                    server.sendto(body, peer)
            except Exception as error:
                errors.append(str(error))

        thread = threading.Thread(target=receive)
        thread.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            for index in range(16):
                body = ("HAZIM_LIVE_%03d" % index).encode()
                client.sendto(body, endpoint)
                echoed, peer = client.recvfrom(4096)
                if echoed != body or peer != endpoint:
                    raise ValueError("UDP application echo differs")
            original_descriptor = client.fileno()
            with client.dup() as connected:
                duplicate_descriptor = connected.fileno()
                connected.connect(endpoint)
                for index in range(16):
                    body = ("HAZIM_CONN_%03d" % index).encode()
                    if connected.send(body) != len(body) or connected.recv(4096) != body:
                        raise ValueError("Connected UDP echo differs")
            client_endpoint = client.getsockname()
        thread.join(timeout=4)
        if thread.is_alive() or errors or len(received) != 32:
            raise ValueError("UDP fixture failed: " + repr(errors))
    save(root / "workload.json", {"pid": os.getpid(), "messages_received_and_echoed": received,
                                  "endpoint": endpoint, "client_endpoint": client_endpoint, "status": "accepted",
                                  "original_descriptor": original_descriptor, "duplicate_descriptor": duplicate_descriptor})


def exec_cloexec_workload(root, resumed=False):
    def identity(connection):
        descriptor = connection.fileno()
        return {"fd": descriptor, "inode": os.fstat(descriptor).st_ino,
                "cookie": struct.unpack("=Q", connection.getsockopt(socket.SOL_SOCKET, 57, 8))[0],
                "cloexec": bool(fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC),
                "endpoint": list(connection.getsockname())}

    def echo(server, client, marker):
        endpoint = server.getsockname()
        if client.sendto(marker, endpoint) != len(marker):
            raise ValueError("Incomplete close-on-exec UDP send")
        body, peer = server.recvfrom(4096)
        if body != marker or peer != client.getsockname() or server.sendto(body, peer) != len(body):
            raise ValueError("Close-on-exec fixture receipt differs")
        body, peer = client.recvfrom(4096)
        if body != marker or peer != endpoint:
            raise ValueError("Close-on-exec application echo differs")

    if not resumed:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as closed, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as retained:
            for connection in (server, closed, retained):
                connection.bind(("127.0.0.1", 0))
                connection.settimeout(2)
            os.set_inheritable(server.fileno(), True)
            os.set_inheritable(retained.fileno(), True)
            receipt = {"transport": "exec-cloexec", "pid": os.getpid(),
                       "server_identity": identity(server), "closed_identity": identity(closed),
                       "retained_identity": identity(retained), "before_exec_monotonic_ns": time.monotonic_ns()}
            if not receipt["closed_identity"]["cloexec"] or receipt["retained_identity"]["cloexec"] or receipt["server_identity"]["cloexec"]:
                raise ValueError("Actual pre-exec descriptor flags differ")
            echo(server, closed, b"HAZIM_EXEC_BEFORE")
            receipt["before_exec_monotonic_ns"] = time.monotonic_ns()
            save(root / "pre_exec.json", receipt)
            os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve()), "--exec-cloexec-resume", str(root)])
    else:
        before = json.loads((root / "pre_exec.json").read_text())
        after_exec = time.monotonic_ns()
        if before["pid"] != os.getpid():
            raise ValueError("Exec changed expected process identity")
        with socket.socket(fileno=before["server_identity"]["fd"]) as server, socket.socket(fileno=before["retained_identity"]["fd"]) as retained:
            server.settimeout(2)
            retained.settimeout(2)
            server_after, retained_after = identity(server), identity(retained)
            if server_after != before["server_identity"] or retained_after != before["retained_identity"]:
                raise ValueError("Retained socket identity changed across exec")
            try:
                os.fstat(before["closed_identity"]["fd"])
            except OSError as error:
                if error.errno != 9:
                    raise
            else:
                raise ValueError("CLOEXEC descriptor remains open after exec")
            echo(server, retained, b"HAZIM_EXEC_AFTER")
        save(root / "workload.json", {**before, "status": "accepted", "after_exec_monotonic_ns": after_exec,
             "closed_descriptor_ebadf": True, "retained_identity_after_exec": retained_after,
             "messages_received_and_echoed": ["HAZIM_EXEC_BEFORE", "HAZIM_EXEC_AFTER"]})


def fd_history_workload(root):
    import array

    def identity(connection):
        return {"fd": connection.fileno(), "inode": os.fstat(connection.fileno()).st_ino,
                "cookie": struct.unpack("=Q", connection.getsockopt(socket.SOL_SOCKET, 57, 8))[0]}

    markers = [b"HAZIM_INHERIT", b"HAZIM_SHARED", b"HAZIM_TRANSFER"]
    child_pid = None
    child_waited = False
    parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent_control.settimeout(2)
    child_control.settimeout(2)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as shared:
            server.bind(("127.0.0.1", 0))
            shared.bind(("127.0.0.1", 0))
            server.settimeout(2)
            shared.settimeout(2)
            endpoint = server.getsockname()
            client_endpoint = shared.getsockname()
            server_identity, shared_identity = identity(server), identity(shared)
            child_pid = os.fork()
            if child_pid == 0:
                try:
                    server.close()
                    parent_control.close()
                    inherited_identity = identity(shared)
                    shared.sendto(markers[0], endpoint)
                    if shared.recv(4096) != markers[0]:
                        raise ValueError("Inherited socket echo differs")
                    shared.close()
                    child_control.send(b"closed")
                    content, ancillary, flags, _peer = child_control.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize), socket.MSG_CMSG_CLOEXEC)
                    if content != b"F" or flags & socket.MSG_CTRUNC or len(ancillary) != 1 or ancillary[0][:2] != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                        raise ValueError("Descriptor transfer control message differs")
                    descriptors = array.array("i")
                    descriptors.frombytes(ancillary[0][2])
                    if len(descriptors) != 1:
                        raise ValueError("Descriptor transfer count differs")
                    with socket.socket(fileno=descriptors[0]) as transferred:
                        transferred.settimeout(2)
                        transferred_identity = identity(transferred)
                        if transferred_identity["inode"] != inherited_identity["inode"] or transferred_identity["cookie"] != inherited_identity["cookie"]:
                            raise ValueError("Received socket identity changed")
                        cloexec = bool(fcntl.fcntl(transferred.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
                        if not cloexec:
                            raise ValueError("Received descriptor lacks requested CLOEXEC")
                        transferred.sendto(markers[2], endpoint)
                        if transferred.recv(4096) != markers[2]:
                            raise ValueError("Transferred socket echo differs")
                    save(root / "child_receipt.json", {"pid": os.getpid(), "inherited_identity": inherited_identity,
                         "transferred_identity": transferred_identity, "received_cloexec": cloexec,
                         "control_fd": child_control.fileno(), "status": "accepted"})
                    child_control.close()
                    os._exit(0)
                except BaseException as error:
                    save(root / "child_error.json", {"error": type(error).__name__ + ": " + str(error)})
                    os._exit(1)
            child_control.close()
            body, peer = server.recvfrom(4096)
            if body != markers[0] or peer != client_endpoint:
                raise ValueError("Inherited socket application marker/peer differs")
            server.sendto(body, peer)
            if parent_control.recv(32) != b"closed":
                raise ValueError("Child did not close inherited descriptor")
            shared.sendto(markers[1], endpoint)
            body, peer = server.recvfrom(4096)
            if body != markers[1] or peer != client_endpoint:
                raise ValueError("Shared socket application marker/peer differs")
            server.sendto(body, peer)
            if shared.recv(4096) != markers[1]:
                raise ValueError("Shared socket echo differs")
            if parent_control.sendmsg([b"F"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [shared.fileno()]))]) != 1:
                raise ValueError("Descriptor transfer send failed")
            body, peer = server.recvfrom(4096)
            if body != markers[2] or peer != client_endpoint:
                raise ValueError("Transferred socket application marker/peer differs")
            server.sendto(body, peer)
            waited_pid, child_status = os.waitpid(child_pid, 0)
            child_waited = True
            if waited_pid != child_pid or not os.WIFEXITED(child_status) or os.WEXITSTATUS(child_status) != 0:
                raise ValueError("Descriptor child did not complete successfully")
        child = json.loads((root / "child_receipt.json").read_text())
        save(root / "workload.json", {"transport": "fd-history", "status": "accepted", "pid": os.getpid(),
             "child_pid": child_pid, "child": child, "endpoint": endpoint, "client_endpoint": client_endpoint,
             "server_identity": server_identity, "shared_identity": shared_identity,
             "control_fd": parent_control.fileno(), "messages_received_and_echoed": [marker.decode() for marker in markers]})
    finally:
        parent_control.close()
        child_control.close()
        if child_pid and not child_waited:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child_pid, 0)


def stop_process(process, first_signal):
    if process is None:
        return None
    if process.poll() is None:
        try:
            os.killpg(process.pid, first_signal)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    return process.returncode


def root_probe(root):
    manifest = json.loads((root / "manifest.json").read_text())
    sensor_name = manifest.get("sensor_name", SENSOR_NAME)
    for name, expected in manifest["files"].items():
        if digest(root / name) != expected:
            raise ValueError("Guest payload identity changed: " + name)
    if os.geteuid() != 0:
        raise ValueError("Authenticated root access required for this explicit probe")
    if digest(Path("/sys/kernel/btf/vmlinux")) != manifest["guest_btf_sha256"]:
        raise ValueError("Guest kernel BTF differs from verified candidate input")
    if manifest["task_mode"] == "overhead":
        from attribution_overhead import run
        return run(root, manifest)
    identity = pwd.getpwnam("csci")
    cgroup = Path("/sys/fs/cgroup") / ("hazim-attribution-" + manifest["stamp"])
    cgroup.mkdir()
    process = None
    capture = None
    capture_log = None
    watcher = -1
    report = {"status": "failed_preserved", "collection_ready": False, "malware_executions": 0,
              "ownership_verified": False, "frame_mapping_verified": False}
    try:
        library = ctypes.CDLL(None, use_errno=True)
        watcher = library.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if watcher < 0 or library.inotify_add_watch(watcher, os.fsencode(root), 2 | 8 | 256) < 0:
            raise OSError(ctypes.get_errno(), "inotify capability readiness")
        with (root / "sensor.log").open("xb") as log:
            process = subprocess.Popen([str(root / sensor_name), "--capture", str(root / "lifecycle.bpf.o"),
                         str(cgroup), "8", "benign-" + manifest["stamp"], str(root / "observations.jsonl")],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 15
            while True:
                observations = root / "observations.jsonl"
                lines = observations.read_text().splitlines() if observations.exists() else []
                if any('"record":"attached"' in line for line in lines):
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError("Sensor failed before readiness; inspect sensor.log")
                readable, _, _ = select.select([watcher], [], [], max(0, deadline - time.monotonic()))
                if readable:
                    os.read(watcher, 65536)
            if manifest["task_mode"] == "ethernet-http":
                if (Path("/sys/class/net/enp0s3/operstate").read_text().strip() != "up" or
                        Path("/sys/class/net/enp0s3/carrier").read_text().strip() != "1"):
                    raise ValueError("Diagnostic Ethernet interface is not ready")
                report["capture_netns_inum"] = os.stat("/proc/self/ns/net").st_ino
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as namespace_socket:
                    report["capture_netns_cookie"] = struct.unpack("=Q", namespace_socket.getsockopt(socket.SOL_SOCKET, 71, 8))[0]
                report["tcpdump_sha256"] = digest(Path("/usr/bin/tcpdump"))
                report["tcpdump_version"] = subprocess.run(["/usr/bin/tcpdump", "--version"], capture_output=True, text=True, check=True).stdout
                capture_log = (root / "tcpdump.log").open("xb")
                capture = subprocess.Popen(["/usr/bin/tcpdump", "-i", "enp0s3", "-n", "-s", "0", "-U", "--immediate-mode",
                            "-B", "4096", "-Z", "root", "-w", str(root / "interface.pcap")],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=capture_log, start_new_session=True)
                deadline = time.monotonic() + 3
                while b"listening on enp0s3," not in (root / "tcpdump.log").read_bytes():
                    if capture.poll() is not None or time.monotonic() >= deadline:
                        raise ValueError("Ethernet capture did not become ready")
                    readable, _, _ = select.select([watcher], [], [], max(0, deadline - time.monotonic()))
                    if readable:
                        os.read(watcher, 65536)
                if os.stat("/proc/" + str(capture.pid) + "/ns/net").st_ino != report["capture_netns_inum"]:
                    raise ValueError("Capture process network namespace differs")

            def membership():
                (cgroup / "cgroup.procs").write_text(str(os.getpid()))
                os.setgroups([])
                os.setgid(identity.pw_gid)
                os.setuid(identity.pw_uid)

            completed = subprocess.run(["/usr/bin/python3", str(root / Path(__file__).name), "--workload", str(root)],
                         stdin=subprocess.DEVNULL, capture_output=True, timeout=6, preexec_fn=membership)
            (root / "workload.log").write_bytes(completed.stdout + completed.stderr)
            if completed.returncode != 0:
                raise ValueError("Bounded benign transport workload failed")
            if process.wait(timeout=15) != 0:
                raise ValueError("Sensor capture failed; inspect sensor.log and final counters")
        if capture is not None and stop_process(capture, signal.SIGINT) != 0:
            raise ValueError("Ethernet capture exited unsuccessfully")
        rows = [json.loads(line) for line in (root / "observations.jsonl").read_text().splitlines()]
        receipt = json.loads((root / "workload.json").read_text())
        capability = audit_records(rows)
        task_evidence = audit_task(rows, receipt)
        if manifest["task_mode"] == "ethernet-http":
            joins = audit_capture(rows, receipt, (root / "interface.pcap").read_bytes(),
                                  (root / "tcpdump.log").read_text(), report["capture_netns_inum"], report["capture_netns_cookie"])
            save(root / "frame_join.json", joins)
            report.update({key: value for key, value in joins.items() if key != "frame_bindings"})
            report["frame_join_sha256"] = digest(root / "frame_join.json")
        report.update(capability, **task_evidence,
                      status="load_attach_and_" + manifest["task_mode"] + "_capability_passed_not_collection_ready",
                      bpf_load_and_attachment_passed=True, transport=manifest["task_mode"],
                      application_receipts={"ethernet-http": 4, "tcp": 16, "udp": 32, "fd-history": 3, "exec-cloexec": 2, "i386-exec": 2}[manifest["task_mode"]])
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        stop_process(capture, signal.SIGINT)
        stop_process(process, signal.SIGTERM)
        if capture_log is not None:
            capture_log.close()
        if watcher >= 0:
            os.close(watcher)
        try:
            cgroup.rmdir()
            report["temporary_cgroup_removed"] = True
        except OSError as error:
            report.update(status="failed_preserved", temporary_cgroup_removed=False,
                          cleanup_error=type(error).__name__ + ": " + str(error))
        save(root / "guest_result.json", report)
        with tarfile.open(root / "evidence.tgz", "x:gz") as archive:
            for name in ("sensor.log", "observations.jsonl", "workload.json", "workload.log", "guest_result.json", "interface.pcap", "tcpdump.log", "frame_join.json", "child_receipt.json", "child_error.json", "pre_exec.json"):
                if (root / name).is_file():
                    archive.add(root / name, arcname=name, recursive=False)
        for name in ("guest_result.json", "evidence.tgz"):
            os.chown(root / name, identity.pw_uid, identity.pw_gid)


def build_i386_probe(attempt):
    toolchain = ROOT.parent / "cohort-expansion-100x100-v18-20261021/i386-toolchain-probe/20261021T153000Z"
    sys.path.insert(0, str(toolchain))
    import audit_toolchain_packages
    import build_i386_controls
    authentication = audit_toolchain_packages.authenticate_packages()
    sysroot = attempt / "sysroot"
    for package in authentication["packages"]:
        subprocess.run(["dpkg-deb", "-x", str(audit_toolchain_packages.STUDY / package["path"]), str(sysroot)], check=True)
    environment = build_i386_controls.toolchain_environment(sysroot)
    source = ROOT / "attribution_i386_control.c"
    binary = attempt / "attribution-i386"
    command = shlex.split(environment["CC"]) + shlex.split(environment["CPPFLAGS"]) + ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source)] + shlex.split(environment["LDFLAGS"]) + ["-o", str(binary)]
    compiled = subprocess.run(command, capture_output=True, text=True, env=environment)
    (attempt / "i386-build.log").write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    contents = binary.read_bytes()
    if contents[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<HH", contents, 16) != (2, 3):
        raise ValueError("Diagnostic is not actual i386 ET_EXEC")
    offset = struct.unpack_from("<I", contents, 28)[0]
    size, count = struct.unpack_from("<HH", contents, 42)
    if {2, 3} & {struct.unpack_from("<I", contents, offset + size * index)[0] for index in range(count)}:
        raise ValueError("Diagnostic has interpreter/dynamic program header")
    save(attempt / "i386-build.json", {"source_sha256": digest(source), "binary_sha256": digest(binary),
         "command": command, "toolchain_authentication": authentication,
         "compiler_version": subprocess.run(["gcc", "--version"], check=True, capture_output=True, text=True).stdout,
         "collection_ready": False})
    with tempfile.TemporaryDirectory() as directory:
        receipt = Path(directory) / "workload.json"
        subprocess.run([str(binary), str(receipt)], check=True, timeout=6, stdin=subprocess.DEVNULL)
        observed = json.loads(receipt.read_text())
        if observed["pointer_bits"] != 32 or observed["messages_received_and_echoed"] != ["HAZIM_I386_A", "HAZIM_I386_B"]:
            raise ValueError("Actual local i386 task failed")
    return binary


def freeze(task_mode="udp"):
    if task_mode not in ("udp", "tcp", "ethernet-http", "fd-history", "exec-cloexec", "i386-exec", "overhead"):
        raise ValueError("Unsupported frozen task mode")
    from export_original_sources import helper_module
    helper = helper_module()
    helper.verify_production()
    version_six = task_mode in ("i386-exec", "overhead")
    build = ABI_BUILD if version_six else BUILD
    sensor_name = "attribution-v6" if version_six else SENSOR_NAME
    sensor_schema = "attribution-sensor-v6" if version_six else SENSOR_SCHEMA
    expected_report = "25b0ea84623f27e76e173483fe7d405e76924ce7c3636cf25f59bcffab0d819b" if version_six else "c3e9c2fc68f61d0dc2a1b0e3366999a18c91295a044cc169e833bc8298dfc0d7"
    result = json.loads((build / "result.json").read_text())
    if digest(build / "result.json") != expected_report:
        raise ValueError("Candidate build report changed")
    for name, expected in result["outputs"].items():
        if digest(build / name) != expected:
            raise ValueError("Candidate output changed")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "attribution-live-capability" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    guest = "/home/csci/Downloads/attribution-live-" + stamp
    sources = {sensor_name: build / sensor_name, "lifecycle.bpf.o": build / "lifecycle.bpf.o",
               Path(__file__).name: Path(__file__)}
    if task_mode == "i386-exec":
        sources["attribution-i386"] = build_i386_probe(attempt)
        sources["attribution_i386_control.c"] = ROOT / "attribution_i386_control.c"
    if task_mode == "overhead":
        from attribution_overhead import ORDER, self_test as overhead_self_test
        overhead_self_test()
        sources["attribution_overhead.py"] = ROOT / "attribution_overhead.py"
    manifest = {"stamp": stamp, "guest_root": guest, "snapshot": "clean-attribution-live-" + stamp,
                "task_mode": task_mode,
                "sensor_name": sensor_name, "sensor_schema": sensor_schema,
                "guest_btf_sha256": GUEST_BTF_SHA256,
                "sensor_build_report_sha256": digest(build / "result.json"),
                "files": {name: digest(path) for name, path in sources.items()}}
    save(attempt / "manifest.json", manifest)
    with tarfile.open(attempt / "payload.tgz", "x:gz") as archive:
        for name, path in sources.items():
            archive.add(path, arcname=name, recursive=False)
        archive.add(attempt / "manifest.json", arcname="manifest.json", recursive=False)
    setup = """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(GUEST)
data=base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest()!=EXPECTED: raise ValueError('Payload changed or existing guest path')
root.mkdir(mode=0o700)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    seen=set()
    for member in archive:
        if not member.isfile() or member.name in seen or Path(member.name).name!=member.name: raise ValueError('Unsafe member')
        seen.add(member.name)
        path=root/member.name
        path.write_bytes(archive.extractfile(member).read())
        path.chmod(0o700 if member.name==SENSOR else 0o600)
print('Benign-only sensor probe staged; no BPF or workload executed')
PY
"""
    setup = setup.replace("GUEST", repr(guest)).replace("SENSOR", repr(sensor_name)).replace("PAYLOAD", repr(base64.b64encode((attempt / "payload.tgz").read_bytes()).decode())).replace("EXPECTED", repr(digest(attempt / "payload.tgz")))
    (attempt / "setup_guest.sh").write_text(setup)
    compile(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0], "generated-setup", "exec")
    subprocess.run(["bash", "-n", str(attempt / "setup_guest.sh")], check=True)
    protocol = {"scope": "Isolated benign-only v5 load/attach and 32 loopback UDP application echoes; no malware, model or production change",
                "udp_evidence": "64 completed sends, 64 completed receives, exact endpoints/lifetimes and 128 marked IP snapshots; not Ethernet ownership",
                "sidecar_capture_boundary": "First exec attempt in dedicated cgroup; child returns require actual parent entry and fork identity; production .18 unchanged",
                "connected_udp_extension": "16 unconnected plus 16 connected echoes via a duplicated descriptor; successful fcntl duplication, both closes and matching file-final/cookie required",
                "frozen_utc": datetime.now(timezone.utc).isoformat(), "sensor_seconds": 8, "workload_timeout_seconds": 6,
                "failure_policy": "Preserve every attempt; never weaken counter/receipt gates; restore original TLS/off on every exit",
                "privilege": "Existing protected authenticated sudo for probe and temporary non-root cgroup only; no policy edits",
                "collection_ready": False, "coverage": "Capability only; not general descriptor/frame/namespace/bypass/overhead coverage",
                "hashes": {name: digest(attempt / name) for name in ("manifest.json", "payload.tgz", "setup_guest.sh")},
                "source_sha256": digest(Path(__file__)), "production_hashes": helper.PINNED}
    protocol["task_mode"] = task_mode
    if task_mode == "tcp":
        protocol.update(scope="Isolated benign-only v5 TCP loopback capability; no malware, model or production change",
                        tcp_evidence="16 exact application echoes; 208 bytes per direction for send/receive; 64 exact marked data snapshots; three application inode/cookie install-final matches and actual connect/accept success")
        del protocol["udp_evidence"]
        del protocol["connected_udp_extension"]
    if task_mode == "ethernet-http":
        protocol.update(scope="Approved isolated guest-to-existing-Sink HTTP Ethernet join gate; four numeric 10.0.0.1:80 requests only; no service/policy/production change",
                        frame_evidence="Exact unique IP bytes and recorder clock bounds within 5ms join every socket snapshot to one untruncated DLT_EN10MB frame in the same actual namespace; tcpdump counters reconcile; residual frames remain unassigned",
                        namespace_evidence="Actual SO_NETNS_COOKIE on every workload socket and a capture-namespace socket must equal packet netns_cookie; actual process namespace inodes must also agree, never compare a cookie to an inode",
                        capture=["/usr/bin/tcpdump", "-i", "enp0s3", "-n", "-s", "0", "-U", "--immediate-mode", "-B", "4096", "-Z", "root", "-w", "interface.pcap"],
                        privilege="Existing protected authenticated sudo for bounded BPF/cgroup and interface capture only; no rmem, service, NSS or other policy changes")
        del protocol["udp_evidence"]
        del protocol["connected_udp_extension"]
    if task_mode == "fd-history":
        protocol.update(scope="Bounded benign native-amd64 forked/shared UDP socket and SCM_RIGHTS history; three exact loopback echoes; no malware, model, Ethernet or production change",
                        descriptor_evidence="Actual parent/child inode and SO_COOKIE receipts; distinct forked files tables; inherited child use/close; retained parent use; successful sendmsg/recvmsg with receive-check AND received fd_install; transferred child use/close; final file after retained parent close; 12 exact marked IP snapshots",
                        limits="One controlled fork/shared-file/SCM_RIGHTS case, not general descriptor reconstruction, CLONE_FILES, mixed ABI, exec CLOEXEC closure, namespace, bypass or overhead coverage")
        del protocol["udp_evidence"]
        del protocol["connected_udp_extension"]
    if task_mode == "exec-cloexec":
        protocol.update(scope="Bounded benign native-amd64 same-PID exec and actual CLOEXEC closure; two exact loopback UDP echoes; no malware, model, Ethernet or production change",
                        descriptor_evidence="Three actual socket inode/cookie identities and F_GETFD results; same-task raw exec plus replacement success; flagged socket filp_close inside exec and matching final before application-resume boundary, without explicit close; actual post-exec EBADF; retained socket inode/cookie identity and use after exec; eight exact marked IP snapshots and post-use close/final matches",
                        limits="One exclusive CLOEXEC socket and two retained descriptors, not alias-wide closure, execveat, non-leader exec, mixed ABI, namespaces, bypass, allocator or overhead certification")
        del protocol["udp_evidence"]
        del protocol["connected_udp_extension"]
    if task_mode == "i386-exec":
        protocol.update(scope="Bounded benign same-task amd64 Python to actual static i386 diagnostic exec and two exact loopback UDP echoes; no malware, model or production change",
                        abi_evidence="Actual same-PID/TID/start exec transition; exactly one v6 kind22 retains actual return11/ABI1 and origin59/ABI0 linked to actual same-task exec-success time; per-event i386 ABI, direct sendto369/recvfrom371 calls with actual FD containment, two measured inode/cookie socket installs/closes/finals and eight exact marked IP snapshots",
                        limits="One native i386 direct-syscall task; not arbitrary mixed-ABI lineage, socketcall decoding, x32, namespaces, bypass, overhead or collection release",
                        diagnostic_build_sha256=digest(attempt / "i386-build.json"))
        del protocol["udp_evidence"]
        del protocol["connected_udp_extension"]
    if task_mode == "overhead":
        protocol.update(scope="Bounded paired benign UDP workload resource diagnostic; no malware/model/production change",
                        sensor_seconds=20, order_instrumented=list(ORDER), exact_echoes_per_run=32,
                        metrics="Actual wait4 CPU user/system and maximum RSS, monotonic workload wall time; three baseline and three instrumented repetitions, AB/BA/AB order",
                        limits="Short Python-plus-echo task, startup/order/cache variability, no kernel-map/global-hook memory/CPU accounting or invented performance budget; not general overhead acceptance")
        del protocol["udp_evidence"]
        del protocol["connected_udp_extension"]
    save(attempt / "protocol.json", protocol)
    print(attempt, flush=True)
    return attempt, manifest


def execute(attempt, manifest):
    from export_original_sources import check_competitors, helper_module, wait_guest
    helper = helper_module()
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        helper.verify_production()
        protocol = json.loads((attempt / "protocol.json").read_text())
        if digest(Path(__file__)) != protocol["source_sha256"]:
            raise ValueError("Live probe driver changed after freeze")
        for name, expected in protocol["hashes"].items():
            if digest(attempt / name) != expected:
                raise ValueError("Frozen probe file changed: " + name)
        check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        if before["guest"]["VMState"] != '"poweroff"' or before["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"' or before["sink"]["VMState"] != '"running"':
            raise ValueError("Expected original powered-off isolated guest and running Sink")
        save(attempt / "initial_vm_state.json", before)
        try:
            with (attempt / "staging.log").open("x") as output:
                with subprocess.Popen(["bash", str(helper.STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", helper.VM,
                   "--guest-user", helper.GUEST_USER, "--baseline-snapshot", helper.BASELINE, "--new-snapshot", manifest["snapshot"],
                   "--schema-version", helper.SCHEMA, "--guest-setup", str(attempt / "setup_guest.sh")],
                   cwd=helper.STUDY, stdout=output, stderr=subprocess.STDOUT, start_new_session=True) as staging:
                    try:
                        returncode = staging.wait(timeout=600)
                        if returncode:
                            raise subprocess.CalledProcessError(returncode, staging.args)
                    except BaseException:
                        try:
                            os.killpg(staging.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            staging.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(staging.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            staging.wait(timeout=15)
                        raise
            save(attempt / "staged_snapshot.json", helper.isolated(helper.VM))
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-live-auth-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                wait_guest(helper, auth, attempt / "guest-login.log")
                protected = manifest["guest_root"] + "/.sudo-password"
                helper.vbox("guestcontrol", helper.VM, "copyto", *auth, password.name, protected)
                helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/bin/chmod", "--wait-stdout", "--wait-stderr",
                            "--timeout", "30000", "--", "600", protected)
                result = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3", "--wait-stdout", "--wait-stderr",
                       "--timeout", "120000", "--", manifest["guest_root"] + "/" + Path(__file__).name,
                       "--guest-probe", manifest["guest_root"], check=False)
                (attempt / "guest-probe.log").write_text(result.stdout + result.stderr)
                for name in ("guest_result.json", "evidence.tgz", "sudo-probe.log"):
                    helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, manifest["guest_root"] + "/" + name, str(attempt / name), check=False)
                if result.returncode or not (attempt / "guest_result.json").is_file():
                    raise ValueError("Live capability failed; preserved guest-probe log and available evidence")
                guest_result = json.loads((attempt / "guest_result.json").read_text())
                if guest_result["status"] != "load_attach_and_" + manifest["task_mode"] + "_capability_passed_not_collection_ready":
                    raise ValueError("Live capability acceptance failed")
                save(attempt / "readiness.json", {"live_capability_passed": True, "complete_live_attribution": False,
                    "collection_ready": False, "guest_result_sha256": digest(attempt / "guest_result.json"),
                    "evidence_sha256": digest(attempt / "evidence.tgz")})
        except BaseException as error:
            save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error), "collection_ready": False})
            raise
        finally:
            if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                helper.vbox("controlvm", helper.VM, "poweroff")
            helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
            final_state = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
            save(attempt / "final_vm_state.json", final_state)
            if (final_state["guest"]["VMState"] != '"poweroff"' or
                    final_state["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"' or
                    final_state["sink"]["VMState"] != '"running"'):
                raise ValueError("Final clean snapshot/power state differs; inspect preserved final state")
            helper.verify_production()


def audit_saved(root, publish=True):
    import copy
    from export_original_sources import helper_module
    helper = helper_module()
    helper.verify_production()
    protocol = json.loads((root / "protocol.json").read_text())
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("task_mode") == "i386-exec" and digest(root / "i386-build.json") != protocol["diagnostic_build_sha256"]:
        raise ValueError("Frozen i386 diagnostic build report changed")
    for name, expected in protocol["hashes"].items():
        if digest(root / name) != expected:
            raise ValueError("Frozen saved input changed: " + name)
    with tarfile.open(root / "payload.tgz") as payload:
        members = payload.getmembers()
        expected_payload = set(manifest["files"]) | {"manifest.json"}
        if len(members) != len(expected_payload) or {member.name for member in members} != expected_payload or any(not member.isfile() or Path(member.name).name != member.name for member in members):
            raise ValueError("Unsafe frozen payload")
        for name, expected in manifest["files"].items():
            if hashlib.sha256(payload.extractfile(name).read()).hexdigest() != expected:
                raise ValueError("Frozen payload member changed")
        if manifest["files"][Path(__file__).name] != protocol["source_sha256"]:
            raise ValueError("Frozen driver identity differs")
    if manifest.get("task_mode") == "overhead":
        from attribution_overhead import audit_saved as audit_overhead
        return audit_overhead(root, publish=publish)
    with tarfile.open(root / "evidence.tgz") as archive:
        members = archive.getmembers()
        expected = {"sensor.log", "observations.jsonl", "workload.json", "workload.log", "guest_result.json"}
        ethernet = manifest.get("task_mode", "udp") == "ethernet-http"
        descriptor_history = manifest.get("task_mode", "udp") == "fd-history"
        exec_cloexec = manifest.get("task_mode", "udp") == "exec-cloexec"
        i386_exec = manifest.get("task_mode", "udp") == "i386-exec"
        if descriptor_history:
            expected.add("child_receipt.json")
        if exec_cloexec:
            expected.add("pre_exec.json")
        if ethernet:
            expected.update(("interface.pcap", "tcpdump.log"))
            if "frame_join.json" in {member.name for member in members}:
                expected.add("frame_join.json")
        if len(members) != len(expected) or {member.name for member in members} != expected or any(not member.isfile() or Path(member.name).name != member.name or member.size > 64 * 1024 * 1024 for member in members):
            raise ValueError("Unsafe evidence archive")
        if archive.extractfile("guest_result.json").read() != (root / "guest_result.json").read_bytes():
            raise ValueError("Archived guest report differs from retrieved report")
        rows = [json.loads(line) for line in archive.extractfile("observations.jsonl")]
        receipt = json.load(archive.extractfile("workload.json"))
        if descriptor_history and json.load(archive.extractfile("child_receipt.json")) != receipt["child"]:
            raise ValueError("Archived child descriptor receipt differs")
        if exec_cloexec and any(receipt.get(key) != value for key, value in json.load(archive.extractfile("pre_exec.json")).items()):
            raise ValueError("Archived pre-exec receipt differs from actual workload receipt")
        if ethernet:
            capture_data = archive.extractfile("interface.pcap").read()
            capture_log = archive.extractfile("tcpdump.log").read().decode()
            saved_joins = json.load(archive.extractfile("frame_join.json")) if "frame_join.json" in expected else None
    original_report = json.loads((root / "guest_result.json").read_text())
    if original_report.get("temporary_cgroup_removed") is not True:
        raise ValueError("Temporary cgroup cleanup is unconfirmed")
    final_state = json.loads((root / "final_vm_state.json").read_text())
    if (final_state["guest"]["VMState"] != '"poweroff"' or
            final_state["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"' or
            final_state["sink"]["VMState"] != '"running"'):
        raise ValueError("Saved cleanup state differs")
    for state in final_state.values():
        if state["nic1"] != '"intnet"' or state["intnet1"] != '"malnet"' or any(state["nic" + str(index)] != '"none"' for index in range(2, 9)):
            raise ValueError("Saved VM isolation differs")
    facts = {**audit_records(rows), **audit_task(rows, receipt)}
    if next(row["schema"] for row in rows if row.get("record") == "session") != manifest.get("sensor_schema", SENSOR_SCHEMA):
        raise ValueError("Captured schema differs from frozen sensor payload")
    capture_guards = 0
    if ethernet:
        joins = audit_capture(rows, receipt, capture_data, capture_log, original_report["capture_netns_inum"], original_report["capture_netns_cookie"])
        if saved_joins is not None and joins != saved_joins:
            raise ValueError("Saved frame join differs from independent recomputation")
        facts.update({key: value for key, value in joins.items() if key != "frame_bindings"})
        for changed_rows, changed_log, namespace in (
                (rows, capture_log, original_report["capture_netns_inum"] + 1),
                (rows, capture_log.replace("0 packets dropped by kernel", "1 packets dropped by kernel"), original_report["capture_netns_inum"]),
                (rows, "", original_report["capture_netns_inum"])):
            try:
                audit_capture(changed_rows, receipt, capture_data, changed_log, namespace, original_report["capture_netns_cookie"])
            except ValueError:
                capture_guards += 1
                continue
            raise AssertionError("Corrupt capture evidence was accepted")
    for kind, field, value in ((4, "result", -1), (2, "operation_begin_ns", 0), (7, "snapshot_hex", "00"), (4, "thread_start_ns", 0)):
        invalid = copy.deepcopy(rows)
        next(row for row in invalid if row.get("kind") == kind)[field] = value
        try:
            audit_task(invalid, receipt)
        except ValueError:
            continue
        raise AssertionError("Corrupt task evidence was accepted: " + field)
    try:
        audit_task([row for row in rows if row.get("kind") != (9 if ethernet or exec_cloexec or i386_exec else 20)], receipt)
    except ValueError:
        pass
    else:
        raise AssertionError("Missing controlled exec/fork evidence was accepted")
    descriptor_guards = fd_history_negative_checks(rows, receipt) if descriptor_history else 0
    exec_guards = exec_cloexec_negative_checks(rows, receipt) if exec_cloexec else 0
    abi_guards = i386_negative_checks(rows, receipt) if i386_exec else 0
    report = {"status": "capability_passed_derived_audit_not_collection_ready", "collection_ready": False,
              "complete_live_attribution": False, "ownership_verified": False, "frame_mapping_verified": False,
              "original_guest_status": original_report["status"], "original_guest_error": original_report.get("error"),
              "validator_sha256": digest(Path(__file__)), "negative_task_guards": 5, "negative_capture_guards": capture_guards,
              "negative_fd_history_guards": descriptor_guards, "negative_exec_cloexec_guards": exec_guards, "facts": facts,
              "negative_i386_guards": abi_guards,
              "inputs": {name: digest(root / name) for name in ("protocol.json", "manifest.json", "payload.tgz", "evidence.tgz", "guest_result.json", "final_vm_state.json")}}
    if publish:
        destination = root / ("validation-derived-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        save(destination, report)
        print(destination, flush=True)
    return report


def http_audit_self_test():
    import copy
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapWriter
    receipt = {"transport": "ethernet-http", "status": "accepted", "pid": 100,
               "endpoint": ["10.0.0.1", 80], "stamp": "synthetic", "netns_inum": 123, "netns_cookie": 321, "transactions": []}
    events = [{"record": "observation", "kind": 9, "pid": 100}]
    frames = []
    for index in range(4):
        beginning = 5000000000 + index * 100000
        marker = "/hazim-attribution-synthetic/" + str(index)
        cookie, inode, file_id, port = index + 10, index + 100, index + 200, index + 40000
        item = {"fd": 5, "inode": inode, "cookie": cookie, "netns_cookie": 321, "local_endpoint": ["10.0.0.10", port],
                "marker": marker, "status": 200, "response_size": 2, "response_sha256": hashlib.sha256(b"OK").hexdigest()}
        receipt["transactions"].append(item)
        common = {"record": "observation", "pid": 100, "tid": 100, "thread_start_ns": 1,
                  "socket_cookie": cookie, "protocol": 6, "local_port": port, "remote_port": 80,
                  "local_address_hex": "0a00000a", "remote_address_hex": "0a000001", "related_pid": 0,
                  "abi": 0, "syscall_id": 42, "arguments": [5, file_id, 0, 0, inode, 0]}
        events.extend([{**common, "kind": 12, "monotonic_ns": beginning},
                       {**common, "kind": 1, "monotonic_ns": beginning + 1},
                       {**common, "kind": 2, "monotonic_ns": beginning + 2, "operation_begin_ns": beginning + 1, "result": 0}])
        for entry_kind, offset, content in ((3, 3, ("GET " + marker + " HTTP/1.1\r\n\r\n").encode()),
                                           (5, 5, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")):
            events.extend([{**common, "kind": entry_kind, "monotonic_ns": beginning + offset},
                           {**common, "kind": entry_kind + 1, "monotonic_ns": beginning + offset + 1,
                            "operation_begin_ns": beginning + offset, "result": len(content)}])
            outgoing = entry_kind == 3
            packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(
                src="10.0.0.10" if outgoing else "10.0.0.1", dst="10.0.0.1" if outgoing else "10.0.0.10") / TCP(
                sport=port if outgoing else 80, dport=80 if outgoing else port) / content
            packet.time = 20 + index / 10000
            frames.append(packet)
            snapshot = bytes(packet)[14:]
            events.append({**common, "kind": 7 if outgoing else 8, "monotonic_ns": beginning + offset,
                           "snapshot_hex": snapshot.hex(), "wire_size": len(snapshot), "captured_size": len(snapshot), "netns_inum": 0, "netns_cookie": 321})
        events.append({**common, "kind": 14, "monotonic_ns": beginning + 10})
    for sequence, row in enumerate(events, 1):
        row["sequence"] = sequence
    rows = events + [{"record": "clock", "phase": phase, "monotonic_ns": monotonic,
                      "realtime_before_ns": monotonic + 15000000000, "realtime_after_ns": monotonic + 15000000100}
                     for phase, monotonic in (("before", 5000000000), ("after", 6000000000))]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "synthetic.pcap"
        with PcapWriter(str(path), linktype=1, sync=True) as writer:
            writer.write(frames)
        data = path.read_bytes()
        with PcapWriter(str(Path(directory) / "duplicate.pcap"), linktype=1, sync=True) as writer:
            writer.write(frames + [frames[0]])
        duplicate = (Path(directory) / "duplicate.pcap").read_bytes()
    log = "8 packets captured\n8 packets received by filter\n0 packets dropped by kernel\n"
    assert audit_task(rows, receipt)["http_application_receipts"] == 4
    assert audit_capture(rows, receipt, data, log, 123, 321)["exact_ethernet_frame_matches"] == 8
    for bad_data, bad_log, namespace in ((data, "", 123), (data, log.replace("0 packets", "1 packets"), 123),
                                          (data, log.replace("8 packets received", "9 packets received"), 123),
                                          (data, log, 124), (duplicate, log, 123)):
        try:
            audit_capture(rows, receipt, bad_data, bad_log, namespace, 321)
        except ValueError:
            continue
        raise AssertionError("Corrupt synthetic capture accepted")
    for field, value in (("status", 500), ("cookie", 0), ("marker", "/changed"), ("response_sha256", "0" * 64), ("response_size", 1)):
        changed = copy.deepcopy(receipt)
        changed["transactions"][0][field] = value
        try:
            audit_task(rows, changed)
        except ValueError:
            continue
        raise AssertionError("Corrupt HTTP application receipt accepted")


def fd_history_audit_self_test():
    shared = {"fd": 4, "inode": 101, "cookie": 201}
    server = {"fd": 3, "inode": 102, "cookie": 202}
    receipt = {"transport": "fd-history", "status": "accepted", "pid": 100, "child_pid": 200,
               "endpoint": ["127.0.0.1", 40000], "client_endpoint": ["127.0.0.1", 40001],
               "server_identity": server, "shared_identity": shared, "control_fd": 5,
               "messages_received_and_echoed": ["HAZIM_INHERIT", "HAZIM_SHARED", "HAZIM_TRANSFER"],
               "child": {"status": "accepted", "pid": 200, "inherited_identity": dict(shared),
                         "transferred_identity": {**shared, "fd": 3}, "received_cloexec": True, "control_fd": 6}}
    common = {"record": "observation", "pid": 100, "tid": 100, "thread_start_ns": 1,
              "related_pid": 0, "abi": 0, "arguments": [4, 301, 10, 0, 101, 0], "socket_cookie": 201}
    events = [{**common, "kind": 9, "monotonic_ns": 1}, {**common, "kind": 12, "monotonic_ns": 10},
              {**common, "kind": 20, "monotonic_ns": 30, "related_pid": 200, "arguments": [2, 200, 10, 20, 0, 0]}]

    def syscall(syscall_id, pid, descriptor, start, end, result=0):
        task = {**common, "pid": pid, "tid": pid, "thread_start_ns": 1 if pid == 100 else 2,
                "syscall_id": syscall_id, "arguments": [descriptor, 0, 0, 0, 0, 0]}
        events.extend([{**task, "kind": 1, "monotonic_ns": start},
                       {**task, "kind": 2, "monotonic_ns": end, "operation_begin_ns": start, "result": result}])

    syscall(56, 100, 0, 29, 32, 200)
    syscall(41, 100, 2, 9, 11, 4)
    events.append({**common, "kind": 2, "pid": 200, "tid": 200, "thread_start_ns": 2, "related_pid": 100,
                   "syscall_id": 56, "monotonic_ns": 31, "operation_begin_ns": 29, "result": 0})
    syscall(3, 200, 4, 70, 71)
    syscall(46, 100, 5, 90, 95, 1)
    syscall(47, 200, 6, 80, 100, 1)
    transferred = {**common, "pid": 200, "tid": 200, "thread_start_ns": 2, "arguments": [3, 301, 20, 0, 101, 0]}
    events.extend([{**transferred, "kind": 15, "monotonic_ns": 85, "result": 0},
                   {**transferred, "kind": 12, "monotonic_ns": 86}])
    syscall(3, 200, 3, 160, 161)
    syscall(257, 200, -100, 165, 166, 3)
    syscall(3, 200, 3, 170, 171)
    syscall(3, 100, 4, 180, 181)
    events.append({**common, "kind": 14, "monotonic_ns": 182})
    for marker, client_pid, beginning in ((b"HAZIM_INHERIT", 200, 40), (b"HAZIM_SHARED", 100, 110), (b"HAZIM_TRANSFER", 200, 130)):
        for kind in (3, 5):
            for peer_pid, cookie, port, remote, offset in ((client_pid, 201, 40001, 40000, 0), (100, 202, 40000, 40001, 2)):
                task = {**common, "pid": peer_pid, "tid": peer_pid, "thread_start_ns": 1 if peer_pid == 100 else 2,
                        "socket_cookie": cookie, "protocol": 17, "local_port": port, "remote_port": remote}
                start = beginning + offset + (0 if kind == 3 else 4)
                if kind == 5 and port == 40001:
                    task["remote_port"] = 0
                    syscall(45, peer_pid, 4 if peer_pid == 100 or beginning == 40 else 3, start - 1, start + 2, len(marker))
                events.extend([{**task, "kind": kind, "monotonic_ns": start},
                               {**task, "kind": kind + 1, "monotonic_ns": start + 1,
                                "operation_begin_ns": start, "result": len(marker)}])
        for kind in (7, 8):
            for source, target in ((40001, 40000), (40000, 40001)):
                body = struct.pack("!BBHHHBBH4s4sHHHH", 0x45, 0, 28 + len(marker), 0, 0, 64, 17, 0,
                                   socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"), source, target, 8 + len(marker), 0) + marker
                local_port = source if kind == 7 else target
                events.append({**common, "kind": kind, "monotonic_ns": beginning + 3, "snapshot_hex": body.hex(),
                               "captured_size": len(body), "wire_size": len(body), "socket_cookie": 201 if local_port == 40001 else 202})
    for sequence, row in enumerate(events, 1):
        row["sequence"] = sequence
    assert audit_task(events, receipt)["scm_rights_install_use_close_verified"]
    assert fd_history_negative_checks(events, receipt) == 10


def self_test():
    i386_audit_self_test()
    fd_history_audit_self_test()
    http_audit_self_test()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        workload(root)
        assert len(json.loads((root / "workload.json").read_text())["messages_received_and_echoed"]) == 32
        tcp_root = root / "tcp"
        tcp_root.mkdir()
        tcp_workload(tcp_root)
        tcp_receipt = json.loads((tcp_root / "workload.json").read_text())
        assert len(tcp_receipt["messages_received_and_echoed"]) == 16
        assert len({tcp_receipt[key]["cookie"] for key in ("listener_identity", "client_identity", "accepted_identity")}) == 3
        history_root = root / "fd-history"
        history_root.mkdir()
        fd_history_workload(history_root)
        history = json.loads((history_root / "workload.json").read_text())
        assert history["shared_identity"]["cookie"] == history["child"]["transferred_identity"]["cookie"]
        assert history["child"]["received_cloexec"] and len(history["messages_received_and_echoed"]) == 3
        exec_root = root / "exec-cloexec"
        exec_root.mkdir()
        save(exec_root / "manifest.json", {"task_mode": "exec-cloexec"})
        subprocess.run([sys.executable, str(Path(__file__).resolve()), "--workload", str(exec_root)], check=True, timeout=6, stdin=subprocess.DEVNULL)
        executed = json.loads((exec_root / "workload.json").read_text())
        assert executed["closed_descriptor_ebadf"] and executed["retained_identity_after_exec"] == executed["retained_identity"]
        assert executed["messages_received_and_echoed"] == ["HAZIM_EXEC_BEFORE", "HAZIM_EXEC_AFTER"]
    event = {"record": "observation", "schema": SENSOR_SCHEMA, "sequence": 1, "socket_cookie": 1, "kind": 3,
             "ownership_verified": False, "frame_link_verified": False}
    final = {"record": "final", "returncode": 0, "counters_available": True, "invalid_records": 0,
             "counters": [1, 0, 0, 0, 0, 0, 0, 0], "events_emitted": 1}
    rows = [{"record": "session", "schema": SENSOR_SCHEMA}, {"record": "attached"}, event, final]
    audit_records(rows)
    for replacement in ({**final, "counters_available": False}, {**final, "counters": [1, 1, 0, 0, 0, 0, 0, 0]},
                        {**final, "events_emitted": 2}, {**final, "returncode": 1}, {**final, "counters": [2, 0, 0, 0, 0, 0, 0, 0]}):
        try:
            audit_records(rows[:-1] + [replacement])
        except ValueError:
            continue
        raise AssertionError("Invalid live evidence accepted")
    print("PASS UDP/TCP/HTTP guards, seventeen synthetic i386/exec-boundary guards, three fork/SCM_RIGHTS echoes, ten descriptor guards and actual exec/CLOEXEC two-echo task; no BPF/VM operation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-probe", action="store_true")
    action.add_argument("--guest-probe", type=Path)
    action.add_argument("--root-probe", type=Path)
    action.add_argument("--workload", type=Path)
    action.add_argument("--exec-cloexec-resume", type=Path)
    action.add_argument("--audit-saved", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--tcp", action="store_true", help="Freeze only the separate bounded TCP capability task")
    mode.add_argument("--ethernet-http", action="store_true", help="Freeze the approved isolated Sink HTTP Ethernet join gate")
    mode.add_argument("--fd-history", action="store_true", help="Freeze the bounded benign fork/shared socket and SCM_RIGHTS capability task")
    mode.add_argument("--exec-cloexec", action="store_true", help="Freeze the bounded benign same-PID exec/CLOEXEC and retained socket task")
    mode.add_argument("--i386-exec", action="store_true", help="Freeze the bounded benign actual amd64-to-i386 exec and UDP task")
    mode.add_argument("--overhead", action="store_true", help="Measure three paired benign UDP baseline/v6 resource checks")
    options = parser.parse_args()
    if (options.tcp or options.ethernet_http or options.fd_history or options.exec_cloexec or options.i386_exec or options.overhead) and not (options.freeze_only or options.execute_benign_probe):
        parser.error("Transport mode requires --freeze-only or --execute-benign-probe")
    if options.self_test:
        self_test()
    elif options.audit_saved:
        audit_saved(options.audit_saved.resolve())
    elif options.workload:
        workload(options.workload.resolve())
    elif options.exec_cloexec_resume:
        exec_cloexec_workload(options.exec_cloexec_resume.resolve(), resumed=True)
    elif options.root_probe:
        root_probe(options.root_probe.resolve())
    elif options.guest_probe:
        root = options.guest_probe.resolve()
        secret = root / ".sudo-password"
        try:
            with secret.open("rb") as password, (root / "sudo-probe.log").open("xb") as output:
                deadline = 110 if json.loads((root / "manifest.json").read_text())["task_mode"] == "overhead" else 45
                result = subprocess.run(["sudo", "-S", "-k", "-p", "", "/usr/bin/python3", str(Path(__file__)),
                                         "--root-probe", str(root)], stdin=password, stdout=output, stderr=subprocess.STDOUT, timeout=deadline)
            if result.returncode:
                print("Authenticated probe failed; see sudo-probe.log", flush=True)
                raise SystemExit(result.returncode)
        finally:
            secret.unlink(missing_ok=True)
    else:
        task_mode = "overhead" if options.overhead else ("i386-exec" if options.i386_exec else ("exec-cloexec" if options.exec_cloexec else ("fd-history" if options.fd_history else ("ethernet-http" if options.ethernet_http else ("tcp" if options.tcp else "udp")))))
        attempt, manifest = freeze(task_mode)
        if options.execute_benign_probe:
            signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
            execute(attempt, manifest)