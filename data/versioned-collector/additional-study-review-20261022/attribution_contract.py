#!/usr/bin/env python3
"""Synthetic design oracle only: no collector attachment or historical attribution."""

import argparse
import ipaddress


SCHEMA = "attribution-design-v1"


def flow(record):
    addresses = [ipaddress.ip_address(record[name]) for name in ("local_ip", "remote_ip")]
    if any(address.version != record["ip_family"] for address in addresses):
        raise ValueError("Address family mismatch")
    ports = [record[name] for name in ("local_port", "remote_port")]
    if any(type(port) is not int or not 0 < port <= 65535 for port in ports):
        raise ValueError("Missing or invalid full endpoint")
    return (record["ip_family"], record["protocol"], str(addresses[0]), ports[0], str(addresses[1]), ports[1])


def classify(packet, sockets):
    if packet.get("schema") != SCHEMA or not packet.get("frame_link_verified"):
        return "unknown"
    if packet.get("protocol") not in {"tcp", "udp"} or not packet.get("socket_cookie"):
        return "unknown"
    moment = packet["monotonic_ns"]
    packet_flow = flow(packet)
    candidates = []
    for socket in sockets:
        if any(socket[field] != packet[field] for field in ("boot_id", "run_id", "netns_cookie", "socket_cookie")):
            continue
        if not socket["open_ns"] <= moment < socket["close_ns"]:
            continue
        if flow(socket) != packet_flow:
            continue
        if socket["peer_evidence"] not in {"connected_socket", "datagram_operation"}:
            continue
        if not socket["peer_begin_ns"] <= moment < socket["peer_end_ns"]:
            continue
        candidates.append(socket)
    if not candidates:
        return "unknown"
    if len(candidates) != 1:
        return "ambiguous_socket_lifetime"
    owners = [owner for owner in candidates[0]["owners"]
              if owner["since_ns"] <= moment < owner["until_ns"]]
    if not owners or any(not owner["identity_verified"] or owner["process_start_ns"] > moment
                         or owner["lineage"] == "unknown" for owner in owners):
        return "unknown"
    states = {owner["lineage"] for owner in owners}
    if not states <= {"target", "non_lineage"}:
        raise ValueError("Unrecognized ownership state")
    if len(states) > 1:
        return "shared_socket"
    return "lineage_socket_associated" if states == {"target"} else "non_lineage_socket_associated"


def self_test():
    packet = {"schema": SCHEMA, "frame_link_verified": True, "boot_id": "boot",
              "run_id": "run", "netns_cookie": 11, "socket_cookie": 101,
              "monotonic_ns": 50, "protocol": "tcp", "ip_family": 4,
              "local_ip": "10.0.0.10", "local_port": 40000,
              "remote_ip": "10.0.0.1", "remote_port": 65010}
    owner = {"pid": 100, "process_start_ns": 5, "identity_verified": True,
             "since_ns": 20, "until_ns": 90, "lineage": "target"}
    socket = {**packet, "open_ns": 10, "close_ns": 100,
              "peer_begin_ns": 10, "peer_end_ns": 100,
              "peer_evidence": "connected_socket", "owners": [owner]}
    checks = [
        ("unique_target", packet, [socket], "lineage_socket_associated"),
        ("no_cookie", {**packet, "socket_cookie": 0}, [socket], "unknown"),
        ("no_frame_link", {**packet, "frame_link_verified": False}, [socket], "unknown"),
        ("legacy_export", {**packet, "schema": ".18"}, [socket], "unknown"),
        ("namespace_collision", packet, [{**socket, "netns_cookie": 12}], "unknown"),
        ("boot_collision", packet, [{**socket, "boot_id": "other"}], "unknown"),
        ("run_collision", packet, [{**socket, "run_id": "other"}], "unknown"),
        ("wrong_port", packet, [{**socket, "remote_port": 65011}], "unknown"),
        ("closed_socket", packet, [{**socket, "close_ns": 50}], "unknown"),
        ("overlapping_lifetimes", packet, [socket, socket], "ambiguous_socket_lifetime"),
        ("unknown_process", packet, [{**socket, "owners": [{**owner, "identity_verified": False}]}], "unknown"),
        ("pid_reuse", packet, [{**socket, "owners": [{**owner, "process_start_ns": 60}]}], "unknown"),
        ("shared_fd", packet, [{**socket, "owners": [owner, {**owner, "pid": 200, "lineage": "non_lineage"}]}], "shared_socket"),
        ("daemon_socket_not_ambient_claim", packet, [{**socket, "owners": [{**owner, "lineage": "non_lineage"}]}], "non_lineage_socket_associated"),
        ("ownership_transfer", packet, [{**socket, "owners": [{**owner, "until_ns": 40}, {**owner, "pid": 200, "since_ns": 40, "lineage": "non_lineage"}]}], "non_lineage_socket_associated"),
        ("unconnected_udp", {**packet, "protocol": "udp"}, [{**socket, "protocol": "udp", "peer_evidence": "datagram_operation"}], "lineage_socket_associated"),
        ("udp_bind_only", {**packet, "protocol": "udp"}, [{**socket, "protocol": "udp", "peer_evidence": "bind_only"}], "unknown"),
        ("stale_udp_peer", {**packet, "protocol": "udp"}, [{**socket, "protocol": "udp", "peer_evidence": "datagram_operation", "peer_end_ns": 50}], "unknown"),
    ]
    ipv6 = {"ip_family": 6, "local_ip": "fd00::10", "remote_ip": "fd00::1"}
    checks.append(("ipv6_normalization", {**packet, **ipv6}, [{**socket, **ipv6, "remote_ip": "fd00:0:0:0:0:0:0:1"}], "lineage_socket_associated"))
    for name, test_packet, test_sockets, expected in checks:
        assert classify(test_packet, test_sockets) == expected, name
    try:
        flow({**packet, "remote_port": 0})
    except ValueError:
        pass
    else:
        raise AssertionError("Wildcard endpoint accepted")
    print(f"PASS: {len(checks)} synthetic ownership cases and invalid endpoint rejection; no live evidence")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", required=True)
    parser.parse_args()
    self_test()


if __name__ == "__main__":
    main()