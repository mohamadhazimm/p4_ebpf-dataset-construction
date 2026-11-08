"""Known-answer integrity tests for the installed .19 hybrid collector: event drops, packet drops and leaks.

One benign static amd64 probe (integrity_probe.c) runs 14 bounded cases under the unchanged production batch on a
fresh child of the quiet baseline. Every case does an exact, countable amount of work and the offline validator
compares that receipt with what the collector recorded:
  * event drops: bpftrace lost count, untracked threads, unresolved ABI, CSV-vs-metadata row counts, and the exact
    number of raw getppid/sendto/connect syscalls the probe performed (catches silent loss, not only reported loss);
  * packet drops: independent PCAP record count vs tcpdump received/captured/kernel drops, NIC drop counters, every
    UDP sequence number exactly once, every marked HTTP request/response recovered;
  * leaks: default-deny frame classification (anything not the case's own marked traffic, the .19 capture probes or
    guest/Sink ARP is a leak), cross-run marker residue, and the guest credential absent from all evidence.
Phases: --self-test (local only), --freeze-only (local only), --execute (VM; needs a verbatim approval),
--validate (saved-only). The sample is never executed on the host by this driver.
"""

import argparse
import base64
import collections
import csv
import fcntl
import hashlib
import io
import json
import math
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v19 as c19  # noqa: E402  frozen .19 helpers (SHA pinned below), imported unchanged
import validate_quiet_v2 as vq  # noqa: E402  frozen default-deny frame classifier, imported unchanged

ATTEMPTS = ROOT / "integrity-v19"
PROBE_SOURCE = ROOT / "integrity_probe.c"
PROGRAM = "integrity_probe"
GROUP, GROUP_PORT, MAGIC, MARKER_BYTES = "239.255.42.198", 65003, b"HZSEQ1", 16
GETPPID, SENDTO, CONNECT = 110, 44, 42
FROZEN_HELPERS = {"collect_v19.py": "cf2a2748c36d8000f5a6512c6d5035cff6fefaf25d1f4684abdc4006367dc608",
                  "validate_quiet_v2.py": "46db84e9dd6527c5f292fca8ddf56ea32416ae3c526480cda545fd73402aefb5"}
CONFIG = {"bpftrace_perf_rb_pages": 16384, "common_launch_wrapper": True, "ebpf_status": "active",
          "interface": "enp0s3", "malware_runner_sha256": c19.PINNED["src/malware_runner.py"],
          "observation_mode": "fixed", "p4_network_active_ttl_windows": 3, "packet_capture_buffer_kb_requested": 65536,
          "packet_capture_drain_ms": 1000, "packet_capture_immediate_mode": True, "packet_capture_status": "active",
          "telemetry_schema_version": c19.SCHEMA, "timeout_seconds": 20.0, "window_seconds": 0.5, "windows": 40}
# (workload, arguments, envelope). Envelope = deliberately above the proven rate; it passes if loss is either absent
# or reported and rejected by the quality gate, and fails only on silent loss.
PLAN = [("null", [], False), ("udp", [50000], False), ("syscall", [1000000], False), ("http", [100], False),
        ("threads", [4, 250000], False), ("mixed", [20000, 25], False), ("null", [], False),
        ("syscall", [2000000], True), ("udp", [50000], False), ("http", [100], False),
        ("syscall", [1000000], False), ("threads", [4, 250000], False), ("mixed", [20000, 25], False),
        ("null", [], False)]
require, digest, save, load, stamp = c19.require, c19.digest, c19.save, c19.load, c19.stamp


def expected_counts(workload, arguments):
    """Exact raw syscalls (after target exec, root pid) and own frames the probe must produce."""
    counts = {"getppid": 0, "sendto": 0, "connect": 0, "udp": 0, "http": 0}
    if workload == "syscall":
        counts["getppid"] = arguments[0]
    elif workload == "threads":
        counts["getppid"] = arguments[0] * arguments[1]
    elif workload == "udp":
        counts.update(sendto=arguments[0], udp=arguments[0])
    elif workload == "mixed":
        counts.update(sendto=arguments[0], udp=arguments[0], getppid=arguments[0] * arguments[1])
    elif workload == "http":  # glibc send() on x86_64 is the sendto syscall: one per request
        counts.update(connect=arguments[0], sendto=arguments[0], http=arguments[0])
    return counts


def build_cases(token):
    cases, repeats = [], collections.Counter()
    for position, (workload, arguments, envelope) in enumerate(PLAN, 1):
        repeats[workload, envelope] += 1
        name = "int%02d-%s%s-r%d.zip" % (position, workload, "-envelope" if envelope else "", repeats[workload, envelope])
        marker = "hz%s%02d" % (token, position)
        cases.append({"position": position, "sample": name, "workload": workload, "marker": marker,
                      "arguments": [workload, marker, *map(str, arguments)], "envelope": envelope,
                      "label": "null" if workload == "null" else "benign", "mode": "native_amd64_static",
                      "program": PROGRAM, "expected": expected_counts(workload, arguments)})
    require(len({case["marker"] for case in cases}) == len(cases), "Markers must be unique")
    return cases


def compile_probe(destination):
    output = destination / PROGRAM
    subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-pthread", "-s",
                    "-o", str(output), str(PROBE_SOURCE)], check=True)
    content = output.read_bytes()
    require(content[:4] == b"\x7fELF" and content[4] == 2 and content[16] == 2 and content[18] == 62,
            "Probe is not an amd64 ET_EXEC ELF")
    headers = subprocess.run(["readelf", "-l", str(output)], capture_output=True, text=True, check=True).stdout
    require("INTERP" not in headers and "DYNAMIC" not in headers, "Probe is not fully static")
    return content


def transport(content):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        member = zipfile.ZipInfo(PROGRAM, date_time=(2026, 10, 24, 0, 0, 0))
        member.external_attr = 0o100755 << 16
        archive.writestr(member, content)
    return output.getvalue()


def build_payload(cases, binary):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        def add(name, content, mode):
            member = tarfile.TarInfo(name)
            if content is None:
                member.type, member.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(member)
            else:
                member.size, member.mode = len(content), mode
                archive.addfile(member, io.BytesIO(content))
        add("samples", None, 0)
        add("arguments", None, 0)
        packed = transport(binary)
        for case in cases:
            add("samples/" + case["sample"], packed, 0o600)
            add("arguments/" + case["sample"] + ".json", json.dumps(case["arguments"]).encode(), 0o644)
    return output.getvalue()


def setup_script(guest_root, payload):
    return """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(%r)
data=base64.b64decode(%r)
if root.exists() or hashlib.sha256(data).hexdigest()!=%r:
    raise SystemExit('existing root or changed payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    seen=set()
    for member in archive:
        target=root/member.name
        if member.name in seen or not target.resolve().is_relative_to(root) or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe payload member')
        seen.add(member.name)
        if member.isdir():
            target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:
                stream.write(archive.extractfile(member).read())
            target.chmod(member.mode & 0o777)
print('integrity probe transports staged; no sample executed')
PY
""" % (guest_root, base64.b64encode(payload).decode(), hashlib.sha256(payload).hexdigest())


def check_frozen_helpers():
    for name, expected in FROZEN_HELPERS.items():
        require(digest(ROOT / name) == expected, "Frozen helper changed: " + name)
    c19.verify_production()


def freeze():
    check_frozen_helpers()
    run_id = stamp()
    attempt = ATTEMPTS / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    token = hashlib.sha256(run_id.encode()).hexdigest()[:8]
    cases = build_cases(token)
    binary = compile_probe(attempt)
    payload = build_payload(cases, binary)
    guest_root = "/home/csci/Downloads/integrity-v19-" + run_id
    setup = setup_script(guest_root, payload)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    compile(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0], "setup", "exec")
    (attempt / "payload.tgz").write_bytes(payload)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in cases))
    gcc = subprocess.run(["gcc", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    protocol = {"format": "v19-integrity-tests-v1", "schema": c19.SCHEMA, "production_hashes": c19.PINNED,
        "baseline_snapshot": c19.BASELINE, "new_snapshot": "clean-quiet-v19-integrity-" + run_id,
        "guest_root": guest_root, "cases": cases, "settings": c19.SETTINGS, "config_required": CONFIG,
        "probe": {"source_sha256": digest(PROBE_SOURCE), "binary_sha256": hashlib.sha256(binary).hexdigest(),
                  "compiler": gcc, "flags": "-std=c11 -O2 -static -pthread -s"},
        "frozen_helpers": FROZEN_HELPERS, "driver_sha256": digest(__file__),
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", PROGRAM)},
        "approval": None, "retries": False, "resume": False, "replacement": False, "malware": False,
        "model_fitting": False, "merge_with_any_dataset": False,
        "criteria": {
            "event_drops": "lost==0, no untracked threads, unresolved ABI 0, CSV rows == metadata counters, exact "
                           "raw getppid/sendto/connect counts for the root pid after target exec, thread tids match",
            "packet_drops": "independent PCAP records == received == captured, kernel drops 0, discrepancy 0, NIC "
                            "drop deltas 0, every UDP sequence exactly once, every marked HTTP request + 200 response",
            "leaks": "zero unexplained frames anywhere in the PCAP under default-deny classification; no foreign "
                     "case marker in any evidence file; guest credential absent from all evidence",
            "envelope": "the 2M getppid case passes if loss is absent, or reported AND rejected; silent loss fails"},
        "limitations": ["Benign synthetic workloads on one static amd64 mode; not malware or arbitrary-rate proof",
                        "Frame classification is by endpoint/protocol/marker, not OS-process ownership",
                        "Quiet baseline is quiet-v1 (apt not masked); a background apt burst would show as a leak",
                        "Flood-size captures (>~200k packets) are outside this battery (known runner timeout issue)"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "cases": len(cases), "payload_bytes": len(payload), "vm_steps_authorized": []}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    require(expected_hash and digest(attempt / "protocol.json") == expected_hash, "Explicit frozen protocol hash required")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == "v19-integrity-tests-v1" and protocol["production_hashes"] == c19.PINNED
            and protocol["settings"] == c19.SETTINGS and protocol["baseline_snapshot"] == c19.BASELINE,
            "Frozen contract differs")
    check_frozen_helpers()
    require(digest(PROBE_SOURCE) == protocol["probe"]["source_sha256"], "Probe source changed")
    for name, expected in protocol["files"].items():
        require(digest(attempt / name) == expected, "Frozen file changed: " + name)
    return protocol


def execute(attempt, expected_hash, approval):
    """Preflight -> stage -> dry-run -> one batch -> restore original TLS/off -> offline validation. No retries."""
    require(approval and approval.strip(), "A verbatim user approval is required")
    protocol = verify_plan(attempt, expected_hash)
    module = c19.helper()
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        destination = attempt / "execution"
        destination.mkdir(exist_ok=False)
        save(destination / "authorization.json", {"approval": approval, "protocol_sha256": expected_hash,
             "authorized_utc": datetime.now(timezone.utc).isoformat(), "one_attempt_only": True,
             "steps": ["preflight", "stage", "dry-run", "collect", "restore-original-tls-off"]})
        result = {"protocol_sha256": expected_hash, "status": "failed_preserved", "steps": {}}

        def interrupted(_signal, _frame):
            raise KeyboardInterrupt("Stop owned process group, restore original snapshot, preserve evidence")
        previous = signal.signal(signal.SIGTERM, interrupted)
        touched = False
        try:
            before = c19.preflight(module)
            save(destination / "initial_vm_state.json", before)
            result["steps"]["preflight"] = "passed"
            listing = module.vbox("snapshot", module.VM, "list", "--machinereadable").stdout
            require('"' + protocol["new_snapshot"] + '"' not in listing, "Child already exists; no restage")
            touched = True
            c19.run_logged(["bash", str(c19.STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", module.VM,
                            "--guest-user", module.GUEST_USER, "--baseline-snapshot", c19.BASELINE,
                            "--new-snapshot", protocol["new_snapshot"], "--schema-version", c19.SCHEMA,
                            "--guest-setup", str(attempt / "setup_guest.sh")], destination / "stage.log", 900)
            result["snapshot_uuid"] = c19.snapshot_uuid(module, protocol["new_snapshot"])
            result["steps"]["stage"] = "passed"
            c19.run_logged(c19.batch_command(module, attempt, protocol, True), destination / "dry-run.log", 900)
            result["validated_transports"] = c19.validate_dry_run(destination / "dry-run.log", protocol)
            result["steps"]["dry-run"] = "passed"
            require(not (attempt / "runs").exists(), "Existing output; no retry/resume")
            c19.run_logged(c19.batch_command(module, attempt, protocol), destination / "collect.log", 7200)
            result["steps"]["collect"] = "passed"
            result["status"] = "collected"
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            try:
                if touched:
                    result["final_state"] = c19.restore(module, destination)
                    result["steps"]["restore-original-tls-off"] = "passed"
            except BaseException as error:
                result.update(status="cleanup_failed_requires_user", cleanup_error=type(error).__name__ + ": " + str(error))
                raise
            finally:
                save(destination / "result.json", result)
                signal.signal(signal.SIGTERM, previous)
    print(json.dumps({key: result[key] for key in ("status", "steps")}, indent=2))
    return validate(attempt, expected_hash)


# ----------------------------------------------------------------------------------------------- offline checks
def syscall_counts(run_dir, metadata):
    """Raw syscall ids for the root pid after the exact target exec, plus getppid per thread."""
    target = metadata["target_exec"]["expected_path"]
    root = str(metadata["sample_root_pid"])
    execs = [int(row["timestamp_ns"]) for row in csv.DictReader((run_dir / "exec_events.csv").open())
             if row["event"] == "exec_success" and row["pid"] == root and row["detail"].endswith("filename=" + target)]
    require(len(execs) == 1, "Target exec_success row missing or ambiguous")
    by_id, threads, rows = collections.Counter(), collections.Counter(), 0
    with (run_dir / "syscall_events.csv").open() as stream:
        for row in csv.DictReader(stream):
            rows += 1
            if row["pid"] != root or int(row["timestamp_ns"]) < execs[0]:
                continue
            number = int(row["detail"].split()[0].partition("=")[2])
            by_id[number] += 1
            if number == GETPPID:
                threads[int(row["tid"])] += 1
    return {"csv_rows": rows, "by_id": by_id, "getppid_by_tid": threads}


def event_checks(case, metadata, counts, receipt):
    lost = metadata["ebpf_lost_event_count"]
    diagnostics = metadata["ebpf_event_diagnostics"]
    expected = case["expected"]
    observed = {"getppid": counts["by_id"][GETPPID], "sendto": counts["by_id"][SENDTO],
                "connect": counts["by_id"][CONNECT]}
    shortfall = {name: expected[name] - observed[name] for name in observed}
    checks = {"reported_lost_zero": lost == 0,
              "no_untracked_threads": diagnostics.get("untracked_tid") == {},
              "unresolved_abi_zero": diagnostics.get("raw_syscalls_unresolved_abi") == 0,
              "syscall_csv_matches_metadata": counts["csv_rows"] == metadata["raw_syscall_event_count"],
              "exact_known_answer_counts": all(value == 0 for value in shortfall.values())}
    if case["workload"] == "threads":
        checks["thread_tids_match"] = (receipt is not None and sorted(counts["getppid_by_tid"]) == sorted(receipt["tids"])
                                       and set(counts["getppid_by_tid"].values()) == {int(case["arguments"][3])})
    # Silent loss = fewer events than performed with no loss reported, or more missing than reported lost.
    missing = sum(max(value, 0) for value in shortfall.values())
    silent = missing > 0 and (lost == 0 or missing > lost)
    detected = lost > 0 and metadata["collection_quality_status"] == "rejected" and any(
        reason.startswith("ebpf_events_lost") for reason in metadata["collection_quality_reasons"])
    verdict = "pass" if all(checks.values()) else ("fail_silent_loss" if silent
              else "loss_reported_and_rejected" if detected else "fail")
    return {"verdict": verdict, "checks": checks, "expected": {k: expected[k] for k in observed},
            "observed": observed, "reported_lost": lost, "raw_syscall_rows": counts["csv_rows"]}


def own_traffic(parsed, case):
    """Frame indexes (1-based) that are this case's own marked UDP/HTTP traffic, plus recovered sequence/requests."""
    labels, sequences, requests = {}, collections.Counter(), {}
    prefix = MAGIC + case["marker"].encode()
    if case["expected"]["udp"]:
        for index, packet in enumerate(parsed, 1):
            address = vq.direct_ip(packet)
            if address is None or not isinstance(address.payload, vq.UDP) or address.dst != GROUP:
                continue
            payload = bytes(address.payload.payload)
            if int(address.payload.dport) == GROUP_PORT and address.src == vq.GUEST and payload.startswith(prefix) \
                    and len(payload) == len(MAGIC) + MARKER_BYTES + 8 \
                    and payload[len(prefix):len(MAGIC) + MARKER_BYTES] == b"\0" * (MARKER_BYTES - len(case["marker"])):
                labels[index] = "own_udp"
                sequences[int.from_bytes(payload[-8:], "big")] += 1
    if case["expected"]["http"]:
        flows = collections.defaultdict(list)
        for index, packet in enumerate(parsed, 1):
            key = vq.flow_key(packet)
            if key and (vq.SINK, 80) in key and any(endpoint[0] == vq.GUEST for endpoint in key):
                flows[key].append((index, packet))
        pattern = re.compile(rb"GET /hzint/" + case["marker"].encode() + rb"/(\d+) HTTP/1\.0\r\n")
        for key, members in flows.items():
            try:
                request = vq.tcp_bytes([packet for _index, packet in members], vq.GUEST)
            except ValueError:
                continue
            match = pattern.match(request)
            if not match:
                continue
            try:
                response = vq.tcp_bytes([packet for _index, packet in members], vq.SINK)
            except ValueError:
                response = b""
            number = int(match.group(1))
            requests.setdefault(number, []).append(re.match(rb"HTTP/1\.[01] 200 ", response) is not None)
            for index, _packet in members:
                labels[index] = "own_http"
    return labels, sequences, requests


def packet_checks(case, metadata, parsed, sequences, requests):
    statistics = metadata["packet_capture_statistics"]
    deltas = metadata["packet_capture_interface_counter_deltas"]
    expected = case["expected"]
    checks = {"pcap_records_eq_received_eq_captured":
                  len(parsed) == statistics["packets_captured"] == statistics["packets_received_by_filter"],
              "kernel_drops_zero": statistics["dropped_by_kernel"] == 0,
              "counter_discrepancy_zero": metadata["packet_capture_counter_discrepancy"] == 0,
              "nic_drop_deltas_zero": deltas["rx_dropped"] == 0 and deltas["tx_dropped"] == 0}
    detail = {"pcap_records": len(parsed), "tcpdump": statistics, "nic_deltas": deltas}
    if expected["udp"]:
        missing = [number for number in range(expected["udp"]) if sequences[number] == 0]
        checks["every_udp_sequence_once"] = not missing and set(sequences.values()) == {1} \
            and set(sequences) == set(range(expected["udp"]))
        checks["nic_tx_covers_udp"] = deltas["tx_packets"] >= expected["udp"]
        detail.update(udp_unique=len(sequences), udp_missing=len(missing), udp_duplicates=sum(
            count - 1 for count in sequences.values() if count > 1))
    if expected["http"]:
        checks["every_http_request_once_with_200"] = set(requests) == set(range(expected["http"])) and all(
            replies == [True] for replies in requests.values())
        detail.update(http_requests=len(requests), http_ok=sum(replies == [True] for replies in requests.values()))
    return {"verdict": "pass" if all(checks.values()) else "fail", "checks": checks, "detail": detail}


def leak_ambient(parsed, bounds, metadata, labels):
    probe_flows = [{"phase": phase, "local_port": record["local_port"],
                    "low_ns": record["started_wall_ns"] - 1_000_000_000,
                    "high_ns": record["ended_wall_ns"] + 1_000_000_000}
                   for phase, record in metadata["capture_path_probe"]["probes"].items()]
    rows = vq.classify(parsed, bounds, probe_flows)["frames"]
    for row in rows:
        if row["frame"] in labels:
            row["category"] = labels[row["frame"]]
    unexplained = [row for row in rows if row["category"] == "unexplained"]
    categories = collections.Counter(row["category"].split(":")[0] for row in rows)
    return {"verdict": "pass" if not unexplained else "fail", "categories": dict(categories),
            "unexplained_in_window": sum(row["in_window"] for row in unexplained),
            "unexplained_total": len(unexplained),
            "unexplained_examples": [{key: row[key] for key in row if key != "epoch_ns"} for row in unexplained[:10]]}


def scan_evidence(directories, markers, secret):
    """Map each case directory to the foreign markers and credential hits found in its files and archive members."""
    pattern = re.compile(b"|".join(re.escape(marker.encode()) for marker in markers))
    found = {}
    for owner, directory in directories.items():
        foreign, credential, named = set(), [], []

        def inspect(label, name, content):
            if "password" in name.lower():
                named.append(label)
            foreign.update(match.decode() for match in pattern.findall(content) if match.decode() != owner)
            if secret and secret.encode() in content:
                credential.append(label)
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            label = str(path.relative_to(directory))
            if path.name == "output.tgz":  # compressed: scan every member's decompressed bytes too
                with tarfile.open(path, "r:gz") as archive:
                    for member in archive:
                        if member.isfile():
                            inspect(label + "!" + member.name, Path(member.name).name,
                                    archive.extractfile(member).read())
                        elif "password" in member.name.lower():
                            named.append(label + "!" + member.name)
                continue
            inspect(label, path.name, path.read_bytes())
        found[owner] = {"foreign_markers": sorted(foreign), "credential_files": credential, "password_named_files": named}
    return found


def audit_case(case, sample_dir, tools):
    result = {"sample": case["sample"], "workload": case["workload"], "envelope": case["envelope"]}
    host = dict(line.split("=", 1) for line in (sample_dir / "host_run.txt").read_text().splitlines() if "=" in line)
    result["retrieval"] = host.get("status")
    require(host.get("status") == "completed", "Retrieval not completed: " + str(host.get("status")))
    paths = list((sample_dir / "output").glob("run_*/run.json"))
    require(len(paths) == 1, "Missing or ambiguous run metadata")
    run_dir, metadata = paths[0].parent, load(paths[0])
    for name, value in CONFIG.items():
        require(metadata.get(name) == value, "Collector configuration differs: " + name)
    execution, artifact = metadata["target_exec"], metadata["target_artifact"]
    require(execution["status"] == "observed" and execution["match"] == "exact"
            and Path(execution["expected_path"]).name == PROGRAM, "Target exec not observed exactly")
    require((artifact["execution_mode"], artifact["linkage"], artifact["e_machine"]) == ("native", "static", 62),
            "Target mode/linkage differs")
    require(metadata["packet_capture_interface_link_state_before_sample"] == {"operstate": "up", "carrier": 1},
            "Interface link evidence differs")
    require(metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"],
            "Socket buffer limit not restored")
    result.update(return_code=metadata["return_code"], quality=metadata["collection_quality_status"],
                  quality_reasons=metadata["collection_quality_reasons"], archive_members=c19.audit_archive(sample_dir))
    stdout = (run_dir / "sample.stdout.log").read_text()
    receipt = None
    if case["workload"] == "null":
        require(stdout == "", "Null emitted stdout")
    else:
        receipt = json.loads(stdout)
        require(receipt["marker"] == case["marker"] and receipt["completed"] == receipt["requested"]
                and metadata["return_code"] == 0, "Probe receipt incomplete or nonzero exit")
    result["receipt"] = receipt
    telemetry_text = (run_dir / "telemetry.csv").read_text()
    rows = list(csv.DictReader(io.StringIO(telemetry_text)))
    features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
    require(len(rows) == 40 and len(features) == 169
            and all(math.isfinite(float(row[name])) for row in rows for name in features), "Incomplete/nonfinite 40x169")
    result["events"] = event_checks(case, metadata, syscall_counts(run_dir, metadata), receipt)
    result["events"]["checks"]["ebpf_csv_matches_metadata"] = (
        sum(1 for _row in csv.DictReader((run_dir / "ebpf_events.csv").open())) == metadata["ebpf_event_count"])
    if not result["events"]["checks"]["ebpf_csv_matches_metadata"] and result["events"]["verdict"] == "pass":
        result["events"]["verdict"] = "fail"
    content = (run_dir / "packet_capture.pcap").read_bytes()
    parsed = vq.packets(content)
    bounds = vq.windows(telemetry_text)
    labels, sequences, requests = own_traffic(parsed, case)
    result["packets"] = packet_checks(case, metadata, parsed, sequences, requests)
    result["probe"] = tools[1].audit_probe(metadata, load(run_dir / "capture-path-probe.json"),
                                                            content, telemetry_text)
    result["leak_ambient"] = leak_ambient(parsed, bounds, metadata, labels)
    try:
        data = tools[0]
        telemetry = data.p4.load_telemetry_rows(sample_dir)
        _features, _windows, diagnostics = data.p4.derive_p4_features(
            run_dir / "packet_capture.pcap", telemetry, metadata, byte_layer="ethernet", rate_window="nominal")
        result["window_attribution"] = diagnostics.get("alignment_status")
    except Exception as error:  # informational only: per-window boundary attribution, not a drop
        result["window_attribution"] = "error: " + type(error).__name__
    return result


def validate(attempt, expected_hash):
    protocol = verify_plan(attempt, expected_hash)
    secret = None
    try:
        secret = c19.helper().credentials()
    except Exception:
        pass
    results, tools, corrections = [], c19.validation_tools(), []
    for case in protocol["cases"]:
        corrected = expected_counts(case["workload"], [int(value) for value in case["arguments"][2:]])
        if corrected != case["expected"]:  # never silent: every deviation from the frozen plan is reported
            corrections.append({"sample": case["sample"], "frozen": case["expected"], "used": corrected})
            case = dict(case, expected=corrected)
        try:
            results.append(audit_case(case, attempt / "runs" / case["sample"], tools))
        except Exception as error:
            results.append({"sample": case["sample"], "workload": case["workload"], "envelope": case["envelope"],
                            "technical_error": type(error).__name__ + ": " + str(error)})
    directories = {case["marker"]: attempt / "runs" / case["sample"] for case in protocol["cases"]
                   if (attempt / "runs" / case["sample"]).is_dir()}
    scans = scan_evidence(directories, [case["marker"] for case in protocol["cases"]], secret)
    for case, result in zip(protocol["cases"], results):
        scan = scans.get(case["marker"], {"foreign_markers": ["<no evidence directory>"], "credential_files": [],
                                          "password_named_files": []})
        result["leak_residue"] = {"verdict": "pass" if not scan["foreign_markers"] else "fail",
                                  "foreign_markers": scan["foreign_markers"]}
        result["leak_credential"] = {"short_secret_may_false_positive": bool(secret) and len(secret) < 8,
                                     "verdict": "pass" if secret and not scan["credential_files"]
                                     and not scan["password_named_files"] else ("unchecked" if not secret else "fail"),
                                     "files_with_credential": len(scan["credential_files"]),
                                     "password_named_files": scan["password_named_files"]}
    regular = [row for row in results if not row["envelope"]]
    def ok(rows, key, good=("pass",)):
        return bool(rows) and all(row.get(key, {}).get("verdict") in good for row in rows)
    summary = {"status": "offline_audited", "protocol_sha256": expected_hash, "validator_sha256": digest(__file__),
        "verdicts": {
            "event_drops": ok(regular, "events"),
            "event_envelope_no_silent_loss": ok([row for row in results if row["envelope"]], "events",
                                                ("pass", "loss_reported_and_rejected")),
            "packet_drops": ok(results, "packets"),
            "leak_background_traffic": ok(results, "leak_ambient"),
            "leak_cross_run_residue": ok(results, "leak_residue"),
            "leak_credential": ok(results, "leak_credential"),
            "all_cases_retrieved": all("technical_error" not in row for row in results)},
        "expectation_corrections": corrections, "results": results, "limitations": protocol["limitations"]}
    report = attempt / ("integrity-report-" + stamp() + ".json")
    save(report, summary)
    print(json.dumps({"report": str(report), "verdicts": summary["verdicts"],
                      "expectation_corrections": len(corrections)}, indent=2))
    return summary


# --------------------------------------------------------------------------------------------------- self-test
def synthetic_pcap(frames):
    from scapy.utils import PcapWriter
    output = io.BytesIO()
    writer = PcapWriter(output, linktype=1, sync=True)
    for timestamp, frame in frames:
        frame.time = timestamp
        writer.write(frame)
    return output.getvalue()


def self_test():
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    check_frozen_helpers()
    cases = build_cases("0123abcd")
    require(len(cases) == 14 and sum(case["envelope"] for case in cases) == 1
            and [case["workload"] for case in cases].count("null") == 3, "Plan shape differs")
    require(all(re.fullmatch(r"[A-Za-z0-9._-]+", case["sample"]) for case in cases), "Batch-unsafe sample name")
    with tempfile.TemporaryDirectory() as scratch:
        binary = compile_probe(Path(scratch))
        payload = build_payload(cases, binary)
        setup = setup_script("/home/csci/Downloads/integrity-v19-selftest", payload)
        subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            names = archive.getnames()
            require(len(names) == 2 + 2 * len(cases), "Payload member count differs")
            member = archive.extractfile("samples/" + cases[1]["sample"]).read()
            require(zipfile.ZipFile(io.BytesIO(member)).read(PROGRAM) == binary, "Transport does not hold the probe")
            require(json.loads(archive.extractfile("arguments/" + cases[1]["sample"] + ".json").read())
                    == ["udp", cases[1]["marker"], "50000"], "Arguments differ")
    print("PASS plan/payload: 14 cases, unique markers, static ET_EXEC probe, safe transports, setup syntax")

    # Event checks: exact pass, silent loss, reported-and-rejected loss, thread attribution.
    syscall = next(case for case in cases if case["workload"] == "syscall" and not case["envelope"])
    base = {"ebpf_lost_event_count": 0, "ebpf_event_diagnostics": {"untracked_tid": {}, "raw_syscalls_unresolved_abi": 0},
            "raw_syscall_event_count": 1000010, "collection_quality_status": "accepted", "collection_quality_reasons": []}
    counts = {"csv_rows": 1000010, "by_id": collections.Counter({GETPPID: 1000000}), "getppid_by_tid": {7: 1000000}}
    require(event_checks(syscall, base, counts, None)["verdict"] == "pass", "Exact count not accepted")
    short = dict(counts, by_id=collections.Counter({GETPPID: 999990}))
    require(event_checks(syscall, base, short, None)["verdict"] == "fail_silent_loss", "Silent loss not caught")
    lossy = dict(base, ebpf_lost_event_count=50, collection_quality_status="rejected",
                 collection_quality_reasons=["ebpf_events_lost:50"])
    require(event_checks(syscall, lossy, short, None)["verdict"] == "loss_reported_and_rejected", "Reported loss misjudged")
    require(event_checks(syscall, dict(lossy, ebpf_lost_event_count=5), short, None)["verdict"] == "fail_silent_loss",
            "Loss beyond the reported count not caught")
    require(event_checks(syscall, dict(base, ebpf_event_diagnostics={"untracked_tid": {"9": 3},
            "raw_syscalls_unresolved_abi": 0}), counts, None)["verdict"] == "fail", "Untracked threads not caught")
    threads = next(case for case in cases if case["workload"] == "threads")
    split = {"csv_rows": 1000010, "by_id": collections.Counter({GETPPID: 1000000}),
             "getppid_by_tid": collections.Counter({11: 250000, 12: 250000, 13: 250000, 14: 250000})}
    require(event_checks(threads, base, split, {"tids": [11, 12, 13, 14]})["verdict"] == "pass", "Threads not accepted")
    require(event_checks(threads, base, split, {"tids": [11, 12, 13, 15]})["verdict"] == "fail", "Thread tid mismatch missed")
    print("PASS event checks: exact count, silent loss, reported+rejected loss, loss > reported, untracked tid, thread tids")

    # Packet/leak checks on synthetic frames: sequence gaps/duplicates, HTTP recovery, unexplained frames.
    guest_mac, sink_mac = vq.GUEST_MAC, "08:00:27:00:00:01"
    udp_case = dict(cases[1], expected=dict(cases[1]["expected"], udp=5, sendto=5))
    def datagram(sequence, marker=udp_case["marker"]):
        payload = MAGIC + marker.encode().ljust(MARKER_BYTES, b"\0") + sequence.to_bytes(8, "big")
        return Ether(src=guest_mac, dst="01:00:5e:7f:2a:c6") / IP(src=vq.GUEST, dst=GROUP) / UDP(
            sport=40000, dport=GROUP_PORT) / payload
    frames = [(10.0 + index / 10, datagram(index)) for index in range(5)]
    frames.append((11.0, Ether(src=guest_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=guest_mac, psrc=vq.GUEST,
                                                                           pdst=vq.SINK)))
    parsed = vq.packets(synthetic_pcap(frames))
    labels, sequences, _requests = own_traffic(parsed, udp_case)
    metadata = {"packet_capture_statistics": {"packets_captured": 6, "packets_received_by_filter": 6,
                "dropped_by_kernel": 0}, "packet_capture_counter_discrepancy": 0,
                "packet_capture_interface_counter_deltas": {"rx_dropped": 0, "tx_dropped": 0, "tx_packets": 6}}
    require(packet_checks(udp_case, metadata, parsed, sequences, {})["verdict"] == "pass" and len(labels) == 5,
            "Complete UDP sequence not accepted")
    gap = vq.packets(synthetic_pcap(frames[:2] + frames[3:] + [(12.0, datagram(1))]))
    _labels, gap_sequences, _ = own_traffic(gap, udp_case)
    gap_result = packet_checks(udp_case, metadata, gap, gap_sequences, {})
    require(gap_result["verdict"] == "fail" and gap_result["detail"]["udp_missing"] == 1
            and gap_result["detail"]["udp_duplicates"] == 1, "UDP gap/duplicate not caught")
    received = dict(metadata, packet_capture_statistics={"packets_captured": 6, "packets_received_by_filter": 7,
                                                         "dropped_by_kernel": 0})
    require(packet_checks(udp_case, received, parsed, sequences, {})["verdict"] == "fail", "Counter gap not caught")
    foreign = vq.packets(synthetic_pcap(frames + [(12.0, datagram(5, "hzother000099"))]))
    foreign_labels, _, _ = own_traffic(foreign, udp_case)
    require(len(foreign_labels) == 5, "Another case's marker was counted as own traffic")
    http_case = dict(cases[3], expected=dict(cases[3]["expected"], http=2, connect=2))
    http_frames = []
    for number in range(2):
        port = 50000 + number
        request = b"GET /hzint/" + http_case["marker"].encode() + b"/%d HTTP/1.0\r\nHost: 10.0.0.1\r\n\r\n" % number
        http_frames += [
            (20.0 + number, Ether(src=guest_mac, dst=sink_mac) / IP(src=vq.GUEST, dst=vq.SINK) / TCP(
                sport=port, dport=80, flags="PA", seq=1000, ack=1) / request),
            (20.1 + number, Ether(src=sink_mac, dst=guest_mac) / IP(src=vq.SINK, dst=vq.GUEST) / TCP(
                sport=80, dport=port, flags="PA", seq=1, ack=1000 + len(request)) / b"HTTP/1.1 200 OK\r\n\r\nok")]
    http_parsed = vq.packets(synthetic_pcap(http_frames))
    http_labels, _, requests = own_traffic(http_parsed, http_case)
    http_meta = dict(metadata, packet_capture_statistics={"packets_captured": 4, "packets_received_by_filter": 4,
                                                          "dropped_by_kernel": 0})
    require(len(http_labels) == 4 and packet_checks(http_case, http_meta, http_parsed, {}, requests)["verdict"] == "pass",
            "Marked HTTP not recovered")
    partial = vq.packets(synthetic_pcap(http_frames[:3]))
    _l, _s, missing_reply = own_traffic(partial, http_case)
    require(packet_checks(http_case, dict(http_meta, packet_capture_statistics={"packets_captured": 3,
            "packets_received_by_filter": 3, "dropped_by_kernel": 0}), partial, {}, missing_reply)["verdict"] == "fail",
            "Missing HTTP response not caught")
    probe_meta = {"capture_path_probe": {"probes": {"pre": {"local_port": 1, "started_wall_ns": 0, "ended_wall_ns": 1}}}}
    bounds = [(int(9e9), int(30e9))]
    require(leak_ambient(parsed, bounds, probe_meta, labels)["verdict"] == "pass", "Own traffic + ARP flagged as leak")
    noisy = vq.packets(synthetic_pcap(frames + [(13.0, Ether(src=guest_mac, dst=sink_mac) / IP(
        src=vq.GUEST, dst="91.189.91.39") / TCP(sport=40001, dport=80, flags="S"))]))
    noisy_labels, _, _ = own_traffic(noisy, udp_case)
    noisy_result = leak_ambient(noisy, bounds, probe_meta, noisy_labels)
    require(noisy_result["verdict"] == "fail" and noisy_result["unexplained_total"] == 1, "Background frame not caught")
    print("PASS packet/leak checks: UDP gap+duplicate, counter gap, foreign marker, HTTP request/response, ambient frame")

    with tempfile.TemporaryDirectory() as scratch:
        first, second = Path(scratch) / "a", Path(scratch) / "b"
        first.mkdir()
        second.mkdir()
        (first / "x.log").write_bytes(b"own hzaaaa000001 only")
        (second / "y.pcap").write_bytes(b"\0hzaaaa000001\0 residue and s3cr3t-value")
        scans = scan_evidence({"hzaaaa000001": first, "hzaaaa000002": second}, ["hzaaaa000001", "hzaaaa000002"],
                              "s3cr3t-value")
        require(scans["hzaaaa000001"] == {"foreign_markers": [], "credential_files": [], "password_named_files": []}
                and scans["hzaaaa000002"]["foreign_markers"] == ["hzaaaa000001"]
                and scans["hzaaaa000002"]["credential_files"] == ["y.pcap"], "Residue/credential scan wrong")
    print("PASS residue/credential scan: foreign marker and credential bytes detected, own marker ignored")

    # Saved regression: the default-deny ambient check on the 12 saved .19 benign/null cases must flag only the
    # opening dynamic null that contains the apt burst.
    saved = ROOT / "v19-small-collection/20261024T091843893614Z"
    flagged = []
    for case in load(saved / "protocol.json")["cases"]:
        if case["label"] == "malware":
            continue
        run_dir = list((saved / "runs" / case["sample"] / "output").glob("run_*/run.json"))[0].parent
        metadata = load(run_dir / "run.json")
        parsed = vq.packets((run_dir / "packet_capture.pcap").read_bytes())
        verdict = leak_ambient(parsed, vq.windows((run_dir / "telemetry.csv").read_text()), metadata, {})
        if verdict["verdict"] != "pass":
            flagged.append((case["sample"], verdict["unexplained_total"]))
    require([name for name, _count in flagged] == ["null-native_amd64_dynamic-r1.zip"], "Saved regression differs: %r" % flagged)
    print("PASS saved .19 regression: 11/12 benign/null clean, apt-burst null flagged (%d unexplained frames)" % flagged[0][1])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--freeze-only", action="store_true")
    group.add_argument("--execute", action="store_true")
    group.add_argument("--validate", action="store_true")
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    elif arguments.freeze_only:
        freeze()
    elif arguments.execute:
        execute(arguments.attempt.resolve(), arguments.protocol_sha256, arguments.approval)
    else:
        validate(arguments.attempt.resolve(), arguments.protocol_sha256)


if __name__ == "__main__":
    main()
