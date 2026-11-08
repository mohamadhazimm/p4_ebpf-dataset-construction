#!/usr/bin/env python3
"""Run six allowlisted benign attribution controls; never run malware or fit models."""

import argparse
import base64
import csv
import fcntl
import io
import json
import math
import os
import re
import signal
import subprocess
import tarfile
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import analyze_matched45 as existing
import ready_matched45 as ready
from export_original_sources import check_competitors

helper = ready.helper
ROOT = Path(__file__).resolve().parent


def read_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def check_metadata(metadata):
    for key, expected in existing.combined.EXPECTED_SETTINGS.items():
        if metadata.get(key) != expected:
            raise ValueError("Capture setting/quality differs: " + key)
    target, artifact = metadata["target_exec"], metadata["target_artifact"]
    if (metadata["return_code"] != 0 or target["status"] != "observed" or target["match"] != "exact"
            or Path(target["expected_path"]).name != "attribution-control"
            or artifact["e_machine"] != 62 or artifact["linkage"] != "static"
            or artifact["execution_mode"] != "native"
            or metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] != 0):
        raise ValueError("Target exec/native mode/ABI failed")
    if metadata["packet_capture_interface_link_state_before_sample"] != {"operstate": "up", "carrier": 1}:
        raise ValueError("Interface link evidence differs")
    if metadata["packet_capture_rmem_max_before"] != metadata["packet_capture_rmem_max_after_capture"]:
        raise ValueError("Capture buffer restoration failed")


def classify(packet, repeat):
    from scapy.layers.inet import IP, TCP, UDP
    if IP not in packet:
        return "non_ipv4"
    address = packet[IP]
    if address.proto == 6 and TCP in packet:
        transport = packet[TCP]
        endpoints = (address.src, transport.sport, address.dst, transport.dport)
        expected = ("10.0.0.10", 65100 + repeat, "10.0.0.1", 80)
        reverse = (expected[2], expected[3], expected[0], expected[1])
        return "probe_tcp_tuple" if endpoints in (expected, reverse) else "other_tcp_udp"
    if address.proto == 17 and UDP in packet:
        transport = packet[UDP]
        expected = ("10.0.0.10", 65200 + repeat, "10.0.0.1", 65003)
        return "probe_udp_tuple" if (address.src, transport.sport, address.dst, transport.dport) == expected else "other_tcp_udp"
    return "other_ipv4"


def freeze():
    helper.verify_production()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "attribution-pilot" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    binary = attempt / "attribution-control"
    with (attempt / "build.log").open("x") as log:
        subprocess.run(["cc", "-std=c11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
            str(ROOT / "attribution_control.c"), "-o", str(binary)], stdout=log, stderr=subprocess.STDOUT, check=True)
    if ready.elf_header(binary.read_bytes())["mode"] != "native_amd64_static":
        raise ValueError("Control is not a native amd64 static ELF")
    guest = "/home/csci/Downloads/attribution-pilot-" + stamp
    cases = []
    for position, (task, repeat) in enumerate((("null", 1), ("net", 1), ("file", 1), ("file", 2), ("net", 2), ("null", 2)), 1):
        token = task + "_r" + str(repeat)
        cases.append({"position": position, "task": task, "repeat": repeat, "token": token,
            "sample": token + ".zip", "arguments": [task, token, str(repeat)],
            "binary_sha256": ready.digest(binary)})
    with tarfile.open(attempt / "payload.tgz", "w:gz") as archive:
        for case in cases:
            transport = ready.packed_binary("attribution-control", binary.read_bytes())
            case["transport_sha256"] = __import__("hashlib").sha256(transport).hexdigest()
            for name, content in (("samples/" + case["sample"], transport),
                                  ("arguments/" + case["sample"] + ".json", json.dumps(case["arguments"]).encode())):
                member = tarfile.TarInfo(name)
                member.mode, member.size = 0o600, len(content)
                archive.addfile(member, io.BytesIO(content))
    setup = """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,json,subprocess,tarfile
from pathlib import Path
root=Path(GUEST)
data=base64.b64decode(PAYLOAD)
if root.exists() or hashlib.sha256(data).hexdigest()!=EXPECTED:
    raise SystemExit('existing path or payload mismatch')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    seen=set()
    for member in archive:
        path=root/member.name
        if member.name in seen or not member.isfile() or not path.resolve().is_relative_to(root):
            raise SystemExit('unsafe payload member')
        seen.add(member.name)
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(archive.extractfile(member).read())
        path.chmod(0o600)
state={}
for name,command in {'addresses':['/usr/sbin/ip','-j','address','show','dev','enp0s3'],
                     'routes':['/usr/sbin/ip','-j','route'],
                     'services':['/usr/bin/systemctl','list-units','--all','--type=service','--no-pager','--plain']}.items():
    result=subprocess.run(command,capture_output=True,text=True,check=True)
    state[name]=result.stdout
(root/'baseline-state.json').write_text(json.dumps(state,indent=2))
print('ATTRIBUTION_BASELINE_STATE='+json.dumps(state,sort_keys=True))
print('Six benign-only transports staged; no target executed; no service changed')
PY
"""
    setup = setup.replace("GUEST", repr(guest)).replace("PAYLOAD", repr(base64.b64encode((attempt / "payload.tgz").read_bytes()).decode()))
    setup = setup.replace("EXPECTED", repr(ready.digest(attempt / "payload.tgz")))
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "samples.txt").write_text("".join(case["sample"] + "\n" for case in cases))
    subprocess.run(["bash", "-n", str(attempt / "setup_guest.sh")], check=True)
    protocol = {"scope": "Six benign-only attribution captures; no model fit, malware, service change or dataset merge",
        "frozen_utc": datetime.now(timezone.utc).isoformat(), "cases": cases, "guest_root": guest,
        "snapshot": "clean-attribution-v18-" + stamp, "baseline": helper.BASELINE,
        "schema": helper.SCHEMA, "production_hashes": helper.PINNED,
        "settings": {"timeout": 20, "window_sec": 0.5, "iface": "enp0s3", "ebpf": True,
            "fixed_observation": True, "common_launch_wrapper": True, "tcpdump_kib": 65536,
            "drain_ms": 1000, "bpftrace_pages_per_cpu": 16384},
        "predictions": {"null_and_file": "No direct probe TCP/UDP tuples or network syscall IDs",
            "net": "Exact PID/endpoints, one HTTP request token, HTTP200 response and six unique UDP markers in modeled windows",
            "residual": "Count and inventory unmatched traffic; do not infer ownership from co-occurrence"},
        "failures": "Preserve every attempted output; no retry, replacement or quality-gate relaxation",
        "limitations": ["One static amd64 executable, two repeats per task, not independent software families",
            "No general malware/UDP/process-ownership certification", "Residual packets are not all necessarily ambient",
            "No service suppression or new background-controlled dataset release is tested"],
        "source_hashes": {str(path.relative_to(ready.STUDY)): ready.digest(path) for path in (
            Path(__file__), ROOT / "attribution_control.c", Path(helper.__file__), Path(ready.__file__),
            binary, attempt / "payload.tgz", attempt / "setup_guest.sh", attempt / "samples.txt")}}
    ready.save(attempt / "protocol.json", protocol)
    return attempt


def audit(attempt):
    from scapy.all import IP, TCP, UDP, PcapReader
    protocol = ready.load(attempt / "protocol.json")
    for name, expected in protocol["source_hashes"].items():
        if ready.digest(ready.STUDY / name) != expected:
            raise ValueError("Frozen pilot source changed: " + name)
    _, data, _ = existing.combined.frozen.dependencies()
    results = []
    for case in protocol["cases"]:
        sample = attempt / "runs" / case["sample"]
        paths = list(sample.glob("output/run_*/run.json"))
        if len(paths) != 1 or "status=completed" not in (sample / "host_run.txt").read_text().split():
            raise ValueError("Incomplete benign retrieval: " + case["sample"])
        directory = paths[0].parent
        metadata = ready.load(paths[0])
        check_metadata(metadata)
        members = helper.verify_output_archive(sample)
        rows = read_csv(directory / "sample.stdout.log")
        pids = {int(row["pid"]) for row in rows}
        if len(pids) != 1 or not rows or rows[0]["event"] != "start" or rows[0]["value"] != case["token"]:
            raise ValueError("Probe PID/token evidence differs")
        pid = next(iter(pids))
        if not any(int(row["pid"]) == pid and row["event"] == "exec_success" for row in read_csv(directory / "exec_events.csv")):
            raise ValueError("Probe PID not in exec-success evidence")
        if case["task"] == "file" and (directory / "workspace/pilot-file.bin").read_bytes() != (case["token"] + "\n").encode() * 128:
            raise ValueError("File control content differs")
        if case["task"] == "net":
            if not (directory / "workspace/pilot-http-response.bin").read_bytes().startswith((b"HTTP/1.1 200", b"HTTP/1.0 200")):
                raise ValueError("Known-answer HTTP response is not 200")
            for event, protocol_name, local_port, remote_port in (("tcp_connected", "tcp", 65100 + case["repeat"], 80), ("udp_bound", "udp", 65200 + case["repeat"], 65003)):
                selected = [row for row in rows if row["event"] == event]
                if len(selected) != 1 or (selected[0]["protocol"], selected[0]["source_ip"], int(selected[0]["source_port"]), selected[0]["destination_ip"], int(selected[0]["destination_port"])) != (protocol_name, "10.0.0.10", local_port, "10.0.0.1", remote_port):
                    raise ValueError("Probe socket endpoint log differs")
        telemetry = data.p4.load_telemetry_rows(sample)
        names = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
        if len(telemetry) != 40 or len(names) != 169 or len(set(names)) != 169 or not all(math.isfinite(float(window[name])) for window in telemetry for name in names):
            raise ValueError("Finite 40x169 telemetry differs")
        intervals = [(datetime.fromisoformat(window["window_start_utc"].replace("Z", "+00:00")).timestamp(), datetime.fromisoformat(window["window_end_utc"].replace("Z", "+00:00")).timestamp()) for window in telemetry]
        counts, markers, residual_flows, request_count = Counter(), Counter(), Counter(), 0
        start_ns = int(rows[0]["realtime_ns"])
        end_ns = int(rows[-1]["realtime_ns"])
        start_monotonic = int(rows[0]["monotonic_ns"])
        end_monotonic = int(rows[-1]["monotonic_ns"])
        if end_ns < start_ns or end_monotonic < start_monotonic:
            raise ValueError("Probe clock/order evidence differs")
        with PcapReader(str(directory / "packet_capture.pcap")) as capture:
            for packet in capture:
                counts["pcap_records"] += 1
                if not any(start <= float(packet.time) < end for start, end in intervals):
                    continue
                category = classify(packet, case["repeat"])
                counts[category] += 1
                if category == "probe_udp_tuple":
                    markers[bytes(packet[UDP].payload).decode("ascii")] += 1
                    if not start_ns <= int(packet.time * 1000000000) <= end_ns:
                        raise ValueError("UDP marker outside recorded probe execution time")
                if category == "probe_tcp_tuple":
                    request_count += ("GET /attribution-" + case["token"] + " ").encode() in bytes(packet[TCP].payload)
                if category == "other_tcp_udp":
                    transport = packet[TCP] if packet[IP].proto == 6 else packet[UDP]
                    residual_flows[str((packet[IP].proto, packet[IP].src, transport.sport, packet[IP].dst, transport.dport))] += 1
        expected_markers = {"HAZIM_ATTR_" + case["token"] + "_" + str(sequence).zfill(3): 1 for sequence in range(6)}
        if case["task"] == "net":
            if markers != expected_markers or request_count != 1 or not counts["probe_tcp_tuple"]:
                raise ValueError("Known-answer in-window network recovery differs")
        elif counts["probe_tcp_tuple"] or counts["probe_udp_tuple"]:
            raise ValueError("Null/file control unexpectedly has a designated probe tuple")
        statistics = metadata["packet_capture_statistics"]
        if any(statistics[key] != counts["pcap_records"] for key in ("packets_captured", "packets_received_by_filter")):
            raise ValueError("PCAP counters do not reconcile")
        raw_ids = Counter()
        for row in read_csv(directory / "syscall_events.csv"):
            match = re.search(r"\bid=(\d+)\b", row["detail"])
            if int(row["pid"]) == pid and match:
                raw_ids[int(match.group(1))] += 1
        if case["task"] != "net" and any(raw_ids[number] for number in (41, 42, 44, 45, 46, 47)):
            raise ValueError("Null/file control has unexpected recorded network syscalls")
        connect_events = [row for row in read_csv(directory / "ebpf_events.csv")
            if int(row["pid"]) == pid and row["event"] == "connect"
            and re.search(r"\baddr=167772161\b", row["detail"]) and re.search(r"\bport=80\b", row["detail"])]
        if case["task"] == "net" and (raw_ids[42] != 1 or raw_ids[44] != 7 or len(connect_events) != 1):
            raise ValueError("Known TCP/UDP syscall counts or IPv4 connect endpoint differ")
        extracted, _, diagnostic = data.p4.derive_p4_features(directory / "packet_capture.pcap", telemetry, metadata, byte_layer="ethernet", rate_window="nominal")
        comparisons = 0
        if diagnostic["alignment_status"] == "unique":
            for feature in data.p4.P4_FEATURES:
                for statistic, value in data.aggregate([float(window[feature]) for window in telemetry]).items():
                    if not math.isclose(extracted[f"network__p4_{feature}__{statistic}"], value, rel_tol=1e-9, abs_tol=1e-9):
                        raise ValueError("Stored/PCAP P4 summary differs")
                    comparisons += 1
        else:
            raise ValueError("P4 alignment unavailable: " + case["sample"])
        command = ["tshark", "-n", "-r", str(directory / "packet_capture.pcap"), "-Y", 'http.request and http.host == "connectivity-check.ubuntu.com"', "-T", "fields", "-e", "frame.time_epoch"]
        decoded = subprocess.run(command, capture_output=True, text=True, check=True)
        ambient_http = sum(any(start <= float(line) < end for start, end in intervals) for line in decoded.stdout.splitlines() if line)
        results.append({"sample": case["sample"], "task": case["task"], "repeat": case["repeat"], "pid": pid,
            "counts": dict(counts), "in_window_connectivity_http_requests": ambient_http,
            "udp_markers": dict(markers), "http_marker_requests": request_count,
            "execution_realtime_ns": [start_ns, end_ns], "execution_monotonic_ns": [start_monotonic, end_monotonic],
            "connect_event_evidence": connect_events, "residual_in_window_flows": dict(residual_flows),
            "recorded_network_syscall_ids": {str(number): raw_ids[number] for number in (41, 42, 44, 45, 46, 47)},
            "archive_members": members, "finite_cells": 40 * 169, "p4_comparisons": comparisons,
            "source_run_dir": str(directory.relative_to(ready.STUDY)), "metadata_sha256": ready.digest(paths[0]),
            "pcap_sha256": ready.digest(directory / "packet_capture.pcap"), "p4_diagnostic": diagnostic})
    return {"status": "accepted_bounded_attribution_controls", "cases": results,
        "malware_executions": 0, "model_fits": 0, "collection_ready_for_new_dataset": False,
        "limitations": protocol["limitations"]}


def run_logged(command, log_path):
    with log_path.open("x") as log:
        process = subprocess.Popen(command, cwd=ready.STUDY, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            if process.wait():
                raise RuntimeError("Command failed; inspect " + str(log_path))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def execute(attempt):
    helper.verify_production()
    check_competitors()
    protocol = ready.load(attempt / "protocol.json")
    initial = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
    if initial["guest"]["VMState"] != '"poweroff"' or initial["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"' or initial["sink"]["VMState"] != '"running"':
        raise ValueError("Expected powered-off original guest and running isolated Sink")
    ready.save(attempt / "initial_vm_state.json", initial)
    try:
        print("Staging fresh isolated benign-only snapshot", flush=True)
        run_logged(["bash", str(ready.STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
            "--vm", helper.VM, "--guest-user", helper.GUEST_USER, "--baseline-snapshot", helper.BASELINE,
            "--new-snapshot", protocol["snapshot"], "--schema-version", helper.SCHEMA,
            "--guest-setup", str(attempt / "setup_guest.sh")], attempt / "staging.log")
        staged = helper.isolated(helper.VM)
        if staged["CurrentSnapshotName"] != '"' + protocol["snapshot"] + '"':
            raise ValueError("Staged snapshot differs")
        ready.save(attempt / "staged_snapshot.json", staged)
        command = ["bash", str(ready.STUDY / "scripts/vbox_malware_batch.sh"), "--vm", helper.VM,
            "--guest-user", helper.GUEST_USER, "--guest-malware-dir", protocol["guest_root"] + "/samples",
            "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", protocol["snapshot"],
            "--schema-version", helper.SCHEMA, "--guest-arguments-dir", protocol["guest_root"] + "/arguments",
            "--sample-list", str(attempt / "samples.txt"), "--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3",
            "--ebpf", "--fixed-observation", "--common-launch-wrapper"]
        print("Checking six transports without target execution", flush=True)
        run_logged(command + ["--dry-run", "--output-dir", str(attempt / "dry-run")], attempt / "dry-run.log")
        if (attempt / "dry-run.log").read_text().count("Validated sample: ") != 6:
            raise ValueError("Six-case dry-run incomplete")
        print("Collecting six benign controls; no retry or malware", flush=True)
        run_logged(command + ["--output-dir", str(attempt / "runs")], attempt / "collection.log")
        print("Validating markers, tuple/PID evidence, archives and P4 parity", flush=True)
        ready.save(attempt / "validation.json", audit(attempt))
        helper.verify_production()
    except BaseException as error:
        ready.save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error), "malware_executions": 0})
        raise
    finally:
        if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
            helper.vbox("controlvm", helper.VM, "poweroff")
        helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
        final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        ready.save(attempt / "final_vm_state.json", final)
        if final["guest"]["VMState"] != '"poweroff"' or final["guest"]["CurrentSnapshotName"] != '"' + helper.ORIGINAL + '"':
            raise RuntimeError("Guest cleanup failed")
    ready.save(attempt / "status.json", {"stage": "complete", "validation_sha256": ready.digest(attempt / "validation.json"),
        "protocol_sha256": ready.digest(attempt / "protocol.json"), "malware_executions": 0, "model_fits": 0})


def self_test():
    from scapy.all import IP, TCP, UDP, Raw
    assert classify(IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=65101, dport=80), 1) == "probe_tcp_tuple"
    assert classify(IP(src="10.0.0.1", dst="10.0.0.10") / TCP(sport=80, dport=65101), 1) == "probe_tcp_tuple"
    assert classify(IP(src="10.0.0.10", dst="10.0.0.1") / UDP(sport=65201, dport=65003) / Raw(b"test"), 1) == "probe_udp_tuple"
    assert classify(IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=65102, dport=80), 1) == "other_tcp_udp"
    assert classify(IP(src="10.0.0.10", dst="10.0.0.1") / UDP(sport=65201, dport=65004), 1) == "other_tcp_udp"
    saved = next((ROOT / "matched45-readiness/20261022T072823231146Z/gates/20261022T072901422487Z/runs").glob("native_amd64_static-*/output/run_*/run.json"))
    metadata = ready.load(saved)
    metadata["target_exec"]["expected_path"] = "/attribution-control"
    check_metadata(metadata)
    for key, value in (("packet_capture_counter_discrepancy", 1), ("ebpf_lost_event_count", 1), ("packet_capture_dropped_by_kernel", 1)):
        invalid = {**metadata, key: value}
        try:
            check_metadata(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("Positive loss/gap was accepted")
    with tempfile.TemporaryDirectory(prefix="hazim-benign-control-test-") as name:
        directory = Path(name)
        binary = directory / "attribution-control"
        subprocess.run(["cc", "-std=c11", "-static", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "attribution_control.c"), "-o", str(binary)], check=True)
        for task in ("null", "file"):
            result = subprocess.run([str(binary), task, "selftest", "1"], cwd=directory, capture_output=True, text=True, check=True)
            rows = list(csv.DictReader(io.StringIO(result.stdout)))
            assert int(rows[0]["pid"]) > 0 and int(rows[0]["realtime_ns"]) > 0 and int(rows[0]["monotonic_ns"]) > 0
        assert (directory / "pilot-file.bin").read_bytes() == b"selftest\n" * 128
    helper.verify_production()
    print("PASS: exact tuples/mismatch rejection, three negative quality probes, strict static build, real benign null/file outputs/clocks and production hashes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--execute-benign-checks", action="store_true")
    parser.add_argument("--audit", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
        return
    if options.audit:
        result = audit(options.audit.resolve())
        ready.save(options.audit / ("validation-recheck-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json"), result)
        print(json.dumps(result, indent=2))
        return
    with (ready.NATIVE / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        attempt = freeze()
        print("PILOT " + str(attempt), flush=True)
        if options.execute_benign_checks:
            signal.signal(signal.SIGTERM, lambda _signal, _frame: (_ for _ in ()).throw(KeyboardInterrupt()))
            execute(attempt)
        print(json.dumps({"attempt": str(attempt), "executed": options.execute_benign_checks}), flush=True)


if __name__ == "__main__":
    main()