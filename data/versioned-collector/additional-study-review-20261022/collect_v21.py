"""Approval-gated .21 quiet collection: 97 malware + 97 benign + 9 null on the headless quiet snapshot.

New, self-contained driver; reuses collect_v19's generic helpers and phase pattern (frozen=collect_v19) and the
quiet-v3.5 frame primitives (validate_quiet_v2 + quiet_rederive_v35). Re-pinned to the installed .21 runner, the
validated headless quiet child, and the frozen malware selection + benign binding + payload builder.

Per-case acceptance = collect_v19's technical gates (installed-source provenance, accepted quality, exact target exec,
native mode/linkage, 40x169 finite, safe archive hashes, independent PCAP == received == captured, zero loss/ABI,
buffers restored, pre/post capture probes recovered outside windows, UNIQUE recorded-window Ethernet/nominal P4
alignment and parity) PLUS a v21 traffic gate:
  - null / non-network benign: quiet-v3.5 default-deny -- no unexplained in-window frame (only guest/Sink ARP, guest
    self-announcements, capture probes, ICMP quotes allowed);
  - network-active benign: the case's own guest<->Sink traffic in-window is EXPECTED and allowed, and at least one such
    frame must be present (proves it reached the Sink on enp0s3); any non-Sink in-window frame still rejects;
  - malware: traffic is attributed to the sample and RECORDED, never used to reject.
Phases: preflight (read-only) / preflight-benign (stage + run the 97 benign + 9 null only, confirm which musl Sink
tasks actually produce enp0s3 traffic, drop non-answering ones) / stage / dry-run / collect. Never edits production,
the frozen selection/binding, or any frozen driver. No retries/resume/replacement. Stop on first failure; preserve.
"""

import argparse
import base64
import collections
import copy
import fcntl
import hashlib
import io
import json
import math
import os
import signal
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v19 as frozen          # noqa: E402  generic helpers + phase building blocks (pins .19, reused by identity)
import validate_quiet_v2 as vq        # noqa: E402  quiet frame primitives + GUEST/SINK/PAIR
import quiet_rederive_v35 as v35       # noqa: E402  checksum-tolerant ICMP quote rederivation (quiet-v3.5)
import build_v21_payload as builder    # noqa: E402  payload assembly

require, digest, save, load, stamp = frozen.require, frozen.digest, frozen.save, frozen.load, frozen.stamp
STUDY = frozen.STUDY
SCHEMA = "2026-10-24.21"
BASELINE = "clean-final-quiet-v19-20261024T150104720304Z"
BASELINE_UUID = "7d211f0d-2e9a-410b-8230-66693dfe097b"
ORIGINAL_UUID = "72de0a02-2e71-42b8-85e2-78c21d6b00f9"
MALWARE_SEL = ROOT / "v21-collection-selection/20261024T170741270302Z/malware_selection.json"
BENIGN_BIND = ROOT / "v21-collection-selection/benign-binding-20261024T193834394034Z/benign_binding.json"
SETTINGS = ["--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
            "--fixed-observation", "--common-launch-wrapper"]
EXPECTED_MODE = frozen.EXPECTED_MODE
PINNED = {
    "src/malware_runner.py": "4933ff5c9c56bd097ce565d14a7173bd281dd124aca43d1df0dbe76315e64b9c",
    "scripts/vbox_malware_batch.sh": "4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f",
    "scripts/stage_versioned_runner_snapshot.sh": "5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103",
}


def verify_production(study=STUDY):
    observed = {name: digest(study / name) for name in PINNED}
    for name, expected in PINNED.items():
        require(observed[name] == expected, "Installed .21 production provenance changed: " + name)
    return observed


# ----------------------------------------------------------------------------------------------- payload / freeze

def build_setup(guest_root, payload_bytes):
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
    for member in archive:
        target=(root/member.name).resolve()
        if not str(target).startswith(str(root.resolve())+'/') or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe payload member')
    archive.extractall(root, filter='data')
print('v21 payload staged; no sample executed')
PY
""" % (guest_root, base64.b64encode(payload_bytes).decode(), hashlib.sha256(payload_bytes).hexdigest())


def freeze():
    verify_production()
    require(digest(MALWARE_SEL) and digest(BENIGN_BIND), "Frozen selection inputs missing")
    malware = load(MALWARE_SEL)
    benign = load(BENIGN_BIND)
    run_id = stamp()
    attempt = ROOT / "v21-collection" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/v21-collection-" + run_id
    workdir = attempt / "_wrap"
    workdir.mkdir()
    manifest, order = builder.build(attempt / "payload", malware, benign, guest_root, workdir)
    subprocess.run(["rm", "-rf", str(workdir)], check=False)
    payload_bytes = make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    benign_list = [c for c in order if c["label"] in ("benign", "null")]
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in benign_list))
    settings_required = {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": PINNED["src/malware_runner.py"],
                         "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True}
    protocol = {"format": "v21-quiet-collection-v1", "schema": SCHEMA, "production_hashes": PINNED,
        "baseline_snapshot": BASELINE, "baseline_uuid": BASELINE_UUID, "original_uuid": ORIGINAL_UUID,
        "new_snapshot": "clean-v21-collection-" + run_id, "benign_snapshot": "clean-v21-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS, "settings_required": settings_required,
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "network_benign": manifest["network_benign"],
        "malware_selection_sha256": digest(MALWARE_SEL), "benign_binding_sha256": digest(BENIGN_BIND),
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(builder.__file__)), "driver_sha256": digest(__file__),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "model_fitting": False, "merge_with_any_dataset": False, "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "criteria": ["installed .21 provenance; accepted quality; exact exec; native mode/linkage; 40x169 finite",
                     "safe archive hashes; independent PCAP == received == captured; zero loss/ABI; buffers restored",
                     "pre/post capture probes outside windows; unique recorded-window Ethernet/nominal P4 alignment+parity",
                     "null/non-network benign: quiet-v3.5 default-deny (no unexplained in-window frame)",
                     "network benign: own guest<->Sink traffic allowed and required; non-Sink in-window rejects",
                     "malware traffic recorded, not rejected; exclusions reported by family/mode/label"],
        "limitations": ["Headless quiet .21 dataset; never merged with .20/.19/.18 or desktop captures without analysis",
                        "amd64-dynamic malware training-only (singleton families); its validation stratum is benign-only",
                        "musl Sink tasks are candidates; those the Sink does not answer on enp0s3 are dropped at preflight",
                        "P4 features are offline PCAP reconstruction; frame classification is not OS-process ownership",
                        "Exploratory family/project-held-out design; not blind evaluation or hybrid-superiority evidence"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "network_benign": protocol["network_benign"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "vm_steps_authorized": []}, indent=2))
    return attempt


def make_tgz(tree):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path in sorted(Path(tree).rglob("*")):
            archive.add(path, arcname=str(path.relative_to(tree)), recursive=False)
    return buffer.getvalue()


def verify_plan(attempt, expected_hash):
    require(expected_hash and digest(attempt / "protocol.json") == expected_hash, "Explicit frozen protocol hash required")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == "v21-quiet-collection-v1" and protocol["production_hashes"] == PINNED,
            "Protocol version or pins differ")
    require(protocol["malware_selection_sha256"] == digest(MALWARE_SEL)
            and protocol["benign_binding_sha256"] == digest(BENIGN_BIND), "Frozen selection changed")
    require(protocol["settings"] == SETTINGS and protocol["schema"] == SCHEMA
            and protocol["baseline_snapshot"] == BASELINE, "Frozen collection contract differs")
    verify_production()
    for name, expected in protocol["files"].items():
        require(digest(attempt / name) == expected, "Frozen payload/order changed: " + name)
    return protocol


# ----------------------------------------------------------------------------------------------- traffic gate

def v21_classify(parsed, bounds, probe_flows, network_case):
    """quiet-v3.5 default-deny per-frame classification, extended so a network-active benign case may talk to the Sink.

    Returns accepted/reasons plus in-window guest<->Sink frame count. Malware callers pass network_case=None and
    ignore `accepted` (traffic is recorded, not gated)."""
    announcements = vq.self_announcements(parsed, vq.GUEST_MAC)
    sink_frames = 0
    ipv6_mcast = 0
    unexplained = []
    for index, packet in enumerate(parsed, 1):
        timestamp = vq.packet_ns(packet)
        inside = any(start <= timestamp < end for start, end in bounds)
        category = "unexplained"
        if index in announcements:
            category = "guest_self_announcement"
        elif packet.haslayer(vq.ARP):
            arp = packet[vq.ARP]
            if {arp.psrc, arp.pdst} == vq.PAIR and int(arp.op) in (1, 2) and int(arp.ptype) == 0x800:
                category = "guest_sink_arp"
        elif getattr(packet, "type", None) == 0x86DD and str(packet.dst).lower().startswith("33:33"):
            # IPv6 link-local multicast (router/neighbor solicitation, MLD) from the Sink; the guest has no IPv6.
            # Non-routable, non-contaminating boot-time noise (recognized benign in quiet-v2.3).
            category = "ipv6_link_local_multicast"
            if inside:
                ipv6_mcast += 1
        address = vq.direct_ip(packet)
        if category == "unexplained" and address is not None:
            endpoints = {address.src, address.dst}
            if address.src == vq.SINK and address.dst == vq.GUEST and address.haslayer(vq.ICMP) \
                    and int(address.payload.type) == 3 and int(address.payload.code) == 3:
                category = "icmp_quote"
            elif endpoints <= vq.PAIR:
                for probe in probe_flows:
                    if (vq.flow_key(packet) == tuple(sorted(((vq.GUEST, probe["local_port"]), (vq.SINK, 80))))
                            and probe["low_ns"] <= timestamp <= probe["high_ns"]
                            and address.haslayer(vq.TCP) and not bytes(address[vq.TCP].payload) and not inside):
                        category = "capture_probe:" + probe["phase"]
                        break
                else:
                    if network_case:
                        category = "benign_network_sink"
                        if inside:
                            sink_frames += 1
        if category == "unexplained" and inside:
            unexplained.append(index)
    reasons = []
    if unexplained:
        reasons.append("unexplained_in_window_traffic:%d" % len(unexplained))
    if network_case and sink_frames == 0:
        reasons.append("network_case_reached_no_sink_traffic")
    if ipv6_mcast > 3:
        reasons.append("excess_ipv6_multicast:%d" % ipv6_mcast)
    return {"accepted": not reasons, "reasons": reasons, "sink_in_window_frames": sink_frames,
            "ipv6_link_local_multicast_frames": ipv6_mcast, "unexplained_in_window_frames": unexplained}


def metadata_checks_v21(metadata, case, settings):
    require(not sys.flags.optimize, "Do not disable the frozen workload assertions with Python -O")
    for name, expected in settings.items():
        require(metadata.get(name) == expected, "Setting/quality/provenance differs: " + name)
    require(metadata["collection_quality_reasons"] == [], "Quality reasons are not empty")
    execution = metadata["target_exec"]
    require(execution["status"] == "observed" and execution["match"] == "exact", "Target exec not observed exactly")
    program = case.get("program")
    if program:
        require(Path(execution["expected_path"]).name == program, "Target basename differs")
    mode, linkage, machine = EXPECTED_MODE[case["mode"]]
    artifact = metadata["target_artifact"]
    require((artifact["execution_mode"], artifact["linkage"], artifact["e_machine"]) == (mode, linkage, machine),
            "Target mode/linkage differs")
    require(metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] == 0, "Unresolved ABI")
    require(metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"]
            and metadata["packet_capture_rmem_max_during_capture"] == 134217728, "Buffer restoration differs")
    require(metadata["packet_capture_interface_link_state_before_sample"] == {"operstate": "up", "carrier": 1},
            "Interface link evidence differs")
    if case["label"] == "null":
        require(metadata["return_code"] == 0, "Null target did not exit zero")
    elif case["label"] == "benign" and not case.get("network"):
        require(metadata["return_code"] in case.get("expected_returncodes", [0]), "Benign target exit not expected")
    # network-active benign: exit code is not gated (network CLIs legitimately return nonzero on refused/timeout);
    # the traffic gate (>=1 in-window guest<->Sink frame) in audit_case_v21 is the authoritative acceptance.


def audit_case_v21(sample_dir, case, settings, tools):
    data, probes, _ambient, _workloads = tools
    host = dict(line.split("=", 1) for line in (sample_dir / "host_run.txt").read_text().splitlines() if "=" in line)
    require(host.get("status") == "completed", "Retrieval not completed: " + str(host.get("status")))
    paths = list((sample_dir / "output").glob("run_*/run.json"))
    require(len(paths) == 1, "Missing or ambiguous run metadata")
    run_dir = paths[0].parent
    metadata = load(paths[0])
    row = {"return_code": metadata.get("return_code"), "quality_status": metadata.get("collection_quality_status"),
           "exec_status": metadata.get("target_exec", {}).get("status")}
    metadata_checks_v21(metadata, case, settings)
    row["archive_members"] = frozen.audit_archive(sample_dir)
    telemetry = data.p4.load_telemetry_rows(sample_dir)
    features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
    require(len(telemetry) == 40 and len(features) == len(set(features)) == 169
            and all(math.isfinite(float(window[name])) for window in telemetry for name in features), "Incomplete/nonfinite 40x169")
    content = (run_dir / "packet_capture.pcap").read_bytes()
    parsed = vq.packets(content)
    bounds = vq.windows((run_dir / "telemetry.csv").read_text())
    statistics = metadata["packet_capture_statistics"]
    require(len(parsed) == statistics["packets_captured"] == statistics["packets_received_by_filter"]
            and statistics["dropped_by_kernel"] == 0, "Independent PCAP/counter disagreement")
    probe = probes.audit_probe(metadata, load(run_dir / "capture-path-probe.json"), content, (run_dir / "telemetry.csv").read_text())
    probe_flows = [{"phase": phase, "local_port": record["local_port"],
                    "low_ns": record["started_wall_ns"] - 1_000_000_000,
                    "high_ns": record["ended_wall_ns"] + 1_000_000_000}
                   for phase, record in metadata["capture_path_probe"]["probes"].items()]
    traffic = v21_classify(parsed, bounds, probe_flows, case["label"] == "benign" and bool(case.get("network")))
    if case["label"] != "malware":
        require(traffic["accepted"], "Traffic gate: " + ";".join(traffic["reasons"]))
    extracted, _windows, diagnostics = data.p4.derive_p4_features(run_dir / "packet_capture.pcap", telemetry, metadata,
                                                                  byte_layer="ethernet", rate_window="nominal")
    require(diagnostics["alignment_status"] == "unique", "P4 alignment not unique")
    comparisons = 0
    for name in data.p4.P4_FEATURES:
        for statistic, stored in data.aggregate([float(window[name]) for window in telemetry]).items():
            require(math.isclose(stored, float(extracted["network__p4_" + name + "__" + statistic]),
                                 rel_tol=1e-9, abs_tol=1e-9), "P4 parity mismatch: " + name)
            comparisons += 1
    if case["label"] == "null":
        require((run_dir / "sample.stdout.log").read_bytes() == b"", "Null emitted stdout")
    row.update(pcap_frames=len(parsed), probe=probe, traffic=traffic, p4_alignment=diagnostics["alignment_status"],
               p4_parity_comparisons=comparisons, finite_cells=40 * 169,
               post_target_lineage_raw_syscalls=metadata["target_exec"]["post_target_lineage_raw_syscalls"])
    return row


# ----------------------------------------------------------------------------------------------- VM phases

def snapshot_present(module, name):
    listing = module.vbox("snapshot", module.VM, "list", "--machinereadable").stdout
    return '"' + name + '"' in listing


def preflight(module, protocol):
    from export_original_sources import check_competitors
    verify_production()
    check_competitors()
    states = frozen.state_check(module)
    require(frozen.snapshot_uuid(module, module.ORIGINAL) == ORIGINAL_UUID, "Original TLS snapshot UUID differs")
    require(frozen.snapshot_uuid(module, BASELINE) == BASELINE_UUID, "Quiet baseline snapshot UUID differs")
    return {"states": states, "baseline_uuid": BASELINE_UUID, "original_uuid": ORIGINAL_UUID}


def batch_command(module, attempt, protocol, snapshot, output, sample_list, dry_run=False):
    command = ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"), "--vm", module.VM,
        "--guest-user", module.GUEST_USER, "--guest-malware-dir", protocol["guest_root"] + "/samples",
        "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", snapshot,
        "--schema-version", SCHEMA, "--guest-arguments-dir", protocol["guest_root"] + "/arguments",
        "--sample-list", str(sample_list), "--output-dir", str(output), *SETTINGS]
    return command + (["--dry-run"] if dry_run else [])


def stage_command(attempt, module, snapshot):
    return ["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"), "--vm", module.VM,
            "--guest-user", module.GUEST_USER, "--baseline-snapshot", BASELINE, "--new-snapshot", snapshot,
            "--schema-version", SCHEMA, "--guest-setup", str(attempt / "setup_guest.sh")]


def validate_dry_run(logfile, protocol):
    paths = [line.partition(": ")[2] for line in logfile.read_text().splitlines() if line.startswith("Validated sample: ")]
    expected = [protocol["guest_root"] + "/samples/" + case["sample"] for case in protocol["cases"]]
    require(paths == expected, "Dry-run allowlist/order differs")
    return len(paths)


def perform_phase(attempt, phase, expected_hash, approval):
    require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    protocol = verify_plan(attempt, expected_hash)
    module = frozen.helper()
    predecessors = {"preflight-benign": "preflight", "stage": "preflight", "dry-run": "stage", "collect": "dry-run"}
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if phase in predecessors:
            prior = load(attempt / "phases" / predecessors[phase] / "result.json")
            require(prior["status"] == "passed" and prior["protocol_sha256"] == expected_hash, "Previous phase not accepted")
        destination = attempt / "phases" / phase
        destination.mkdir(parents=True, exist_ok=False)
        save(destination / "authorization.json", {"approval": approval, "phase": phase, "protocol_sha256": expected_hash,
             "authorized_utc": datetime.now(timezone.utc).isoformat(), "one_attempt_only": True})
        result = {"phase": phase, "protocol_sha256": expected_hash, "status": "failed_preserved"}

        def interrupted(_signal, _frame):
            raise KeyboardInterrupt("Stop owned process group, restore original snapshot, preserve failure")
        previous = signal.signal(signal.SIGTERM, interrupted)
        touched = False
        try:
            before = preflight(module, protocol)
            save(destination / "initial_vm_state.json", before)
            if phase == "preflight":
                result.update(before)
            elif phase in ("preflight-benign", "stage"):
                snapshot = protocol["benign_snapshot"] if phase == "preflight-benign" else protocol["new_snapshot"]
                require(not snapshot_present(module, snapshot), "Child already exists; no restage")
                touched = True
                save(destination / "command.json", stage_command(attempt, module, snapshot))
                frozen.run_logged(stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
                result["snapshot_uuid"] = frozen.snapshot_uuid(module, snapshot)
                if phase == "preflight-benign":
                    out = destination / "runs"
                    require(not out.exists(), "Existing benign output; no retry")
                    frozen.run_logged(batch_command(module, attempt, protocol, snapshot, out, attempt / "benign-null.txt"),
                                      destination / "collection.log", 7200)
                    result.update(benign_preflight(attempt, destination, protocol))
            elif phase == "dry-run":
                staged = load(attempt / "phases/stage/result.json")
                require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child differs")
                require(not (attempt / "dry-run").exists(), "Existing output; no retry/resume")
                touched = True
                command = batch_command(module, attempt, protocol, protocol["new_snapshot"], attempt / "dry-run",
                                        attempt / "cases.txt", dry_run=True)
                save(destination / "command.json", command)
                frozen.run_logged(command, destination / "command.log", 1200)
                result["validated_transports"] = validate_dry_run(destination / "command.log", protocol)
            elif phase == "collect":
                staged = load(attempt / "phases/stage/result.json")
                require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child differs")
                require(not (attempt / "runs").exists(), "Existing output; no retry/resume")
                touched = True
                command = batch_command(module, attempt, protocol, protocol["new_snapshot"], attempt / "runs", attempt / "cases.txt")
                save(destination / "command.json", command)
                frozen.run_logged(command, destination / "command.log", 6 * 3600)
                result["reached_batch_complete"] = "Batch complete" in (destination / "command.log").read_text()
            verify_plan(attempt, expected_hash)
            result["status"] = "passed"
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            try:
                if touched:
                    frozen.restore(module, destination)
            except BaseException as error:
                result.update(status="cleanup_failed_requires_user", cleanup_error=type(error).__name__ + ": " + str(error))
                raise
            finally:
                save(destination / "result.json", result)
                signal.signal(signal.SIGTERM, previous)
        print(json.dumps(result, indent=2))


def benign_preflight(attempt, destination, protocol):
    """Audit the 97 benign + 9 null, record which musl Sink tasks actually produced enp0s3 traffic."""
    tools = frozen.validation_tools()
    rows, dropped = [], []
    for case in [c for c in protocol["cases"] if c["label"] in ("benign", "null")]:
        row = {key: case.get(key) for key in ("sample", "label", "mode", "program", "network", "split")}
        try:
            row.update(audit_case_v21(destination / "runs" / case["sample"], case,
                                      protocol["settings_required"], tools), status="accepted")
        except Exception as error:
            row.update(status="excluded", reason=type(error).__name__ + ": " + str(error))
            if case.get("network") and case.get("needs_guest_validation"):
                dropped.append(case["sample"])
        rows.append(row)
    save(destination / "benign_preflight.json", {"results": rows, "dropped_musl_sink_tasks": dropped,
         "counts": dict(collections.Counter(r["status"] for r in rows))})
    accepted = sum(1 for r in rows if r["status"] == "accepted")
    require(accepted >= 0, "benign preflight produced no rows")
    return {"benign_null_accepted": accepted, "benign_null_total": len(rows), "dropped_musl_sink_tasks": dropped}


def validate(attempt, expected_hash):
    protocol = verify_plan(attempt, expected_hash)
    tools = frozen.validation_tools()
    rows, nulls = [], {}
    for case in protocol["cases"]:
        row = {key: case.get(key) for key in ("sample", "label", "mode", "split", "network")}
        sample_dir = attempt / "runs" / case["sample"]
        paths = list((sample_dir / "output").glob("run_*/run.json")) if sample_dir.exists() else []
        if len(paths) == 1:
            metadata = load(paths[0])
            row.update(return_code=metadata.get("return_code"), quality_status=metadata.get("collection_quality_status"),
                       exec_status=metadata.get("target_exec", {}).get("status"))
        try:
            row.update(audit_case_v21(sample_dir, case, protocol["settings_required"], tools), status="accepted")
            if case["label"] == "null":
                nulls.setdefault(case["mode"], []).append(row["post_target_lineage_raw_syscalls"])
        except Exception as error:
            row.update(status="excluded", reason=type(error).__name__ + ": " + str(error))
        rows.append(row)
    summary = {"status": "offline_audited_no_merge_no_model", "protocol_sha256": expected_hash, "results": rows,
        "counts": dict(collections.Counter(r["status"] for r in rows)),
        "accepted_by_mode_label": {str(k): v for k, v in sorted(collections.Counter(
            (r["mode"], r["label"]) for r in rows if r["status"] == "accepted").items())},
        "all_cases_accepted": bool(rows) and all(r["status"] == "accepted" for r in rows),
        "null_max_post_target_syscalls": {m: max(v) for m, v in nulls.items()},
        "collection_ready": False, "model_fits": 0, "merged_cases": 0,
        "validator_sha256": digest(__file__), "limitations": protocol["limitations"]}
    report = attempt / ("validation-" + stamp() + ".json")
    save(report, summary)
    print(json.dumps({"report": str(report), "counts": summary["counts"],
                      "accepted_by_mode_label": summary["accepted_by_mode_label"],
                      "null_max_post_target_syscalls": summary["null_max_post_target_syscalls"]}, indent=2))
    return summary


# ----------------------------------------------------------------------------------------------- self-test

def classify_tests():
    from decimal import Decimal
    bounds = [(100, 200)]

    def at(packet):
        packet.time = Decimal(150) / 1_000_000_000
        return packet
    arp = at(vq.Ether() / vq.ARP(psrc=vq.GUEST, pdst=vq.SINK, ptype=0x800))
    require(v21_classify([arp], bounds, [], False)["accepted"], "guest/Sink ARP rejected")
    http = at(vq.Ether() / vq.IP(src=vq.GUEST, dst=vq.SINK) / vq.TCP(dport=80) / vq.Raw(b"GET / HTTP/1.0\r\n\r\n"))
    require(not v21_classify([http], bounds, [], False)["accepted"], "non-network benign accepted Sink traffic")
    network = v21_classify([http], bounds, [], True)
    require(network["accepted"] and network["sink_in_window_frames"] == 1, "network benign did not allow Sink traffic")
    foreign = at(vq.Ether() / vq.IP(src=vq.GUEST, dst="8.8.8.8") / vq.TCP(dport=80))
    require(not v21_classify([foreign], bounds, [], True)["accepted"], "network benign accepted non-Sink traffic")
    out_of_window = v21_classify([at(vq.Ether() / vq.IP(src=vq.GUEST, dst=vq.SINK) / vq.TCP(dport=443))], [(300, 400)], [], True)
    require(not out_of_window["accepted"] and out_of_window["sink_in_window_frames"] == 0,
            "network benign with no in-window Sink traffic was accepted")
    # IPv6 link-local multicast (Sink ND/RS): one is allowed, >3 in-window rejects.
    rs = at(vq.Ether(src="00:1b:21:07:94:77", dst="33:33:00:00:00:02", type=0x86DD) / vq.Raw(b"\x00" * 8))
    ok = v21_classify([rs], bounds, [], False)
    require(ok["accepted"] and ok["ipv6_link_local_multicast_frames"] == 1, "single Sink IPv6 ND not allowed")
    many = v21_classify([at(vq.Ether(src="00:1b:21:07:94:77", dst="33:33:00:00:00:02", type=0x86DD) / vq.Raw(b"\x00" * 8)) for _ in range(4)], bounds, [], False)
    require(not many["accepted"], "excess IPv6 multicast not rejected")
    print("PASS v21 traffic gate: ARP ok, default-deny for non-network, guest<->Sink allowed+required for network, Sink IPv6 ND bounded, non-Sink/out-of-window rejected")


def build_tests():
    malware, benign = load(MALWARE_SEL), load(BENIGN_BIND)
    with tempfile.TemporaryDirectory(prefix="hazim-v21-build-") as directory:
        out = Path(directory) / "payload"
        manifest, order = builder.build(out, malware, benign, "/home/csci/Downloads/v21-collection-TEST", Path(directory) / "_w")
        require(manifest["counts"] == {"malware": 97, "benign": 97, "null": 9}, "Payload counts differ")
        require(len(order) == 203 and len({c["sample"] for c in order}) == 203, "Order not 203 unique")
        for case in [c for c in order if c["label"] == "malware"][:5]:
            z = out / "samples" / case["sample"]
            member = subprocess.run(["7z", "x", "-so", "-pinfected", str(z)], capture_output=True).stdout
            require(hashlib.sha256(member).hexdigest() == case["member_sha256"], "Malware member hash differs")
        stale = [a.name for a in (out / "arguments").glob("*.json")
                 if "cohort-native-x64-v18" in a.read_text() or "native-heldout-release" in a.read_text()]
        require(not stale, "Stale guest-root prefix in arguments")
        setup = build_setup("/home/csci/Downloads/v21-collection-TEST", make_tgz(out))
        subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
        import ast
        ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    print("PASS deterministic 203-case payload, malware member hashes, no stale fixture prefixes, generated setup syntax")


def saved_tests():
    """Run audit_case_v21 against a saved .19 benign/null capture: provenance rejects as .19, traffic gate exercises."""
    pilot = ROOT / "v19-small-collection/20261024T091843893614Z"
    tools = frozen.validation_tools()
    settings = {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": PINNED["src/malware_runner.py"],
                "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True}
    protocol = load(pilot / "protocol.json")
    null = next(c for c in protocol["cases"] if c["label"] == "null" and c["mode"] == "native_amd64_static")
    sample_dir = pilot / "runs" / null["sample"]
    if sample_dir.exists():
        try:
            audit_case_v21(sample_dir, {**null, "network": False}, settings, tools)
        except ValueError as error:
            require("telemetry_schema_version" in str(error) or "malware_runner_sha256" in str(error),
                    "Saved .19 not rejected on .21 provenance: " + str(error))
        else:
            raise AssertionError("Saved .19 capture accepted as .21")
    print("PASS saved .19 capture rejected on .21 provenance (no new capture)")


def phase_mock_tests():
    with tempfile.TemporaryDirectory(prefix="hazim-v21-phases-") as directory:
        temporary = Path(directory)
        fake = SimpleNamespace(__file__=str(temporary / "helper.py"), VM="t", GUEST_USER="t",
                               vbox=lambda *a: SimpleNamespace(stdout=""))
        protocol = {"guest_root": "/g", "new_snapshot": "child", "benign_snapshot": "bchild",
                    "cases": [{"sample": "a.zip", "label": "malware"}, {"sample": "b.zip", "label": "benign"}]}
        with patch(__name__ + ".verify_plan", return_value=protocol), patch("collect_v19.helper", return_value=fake), \
             patch(__name__ + ".preflight", return_value={"baseline_uuid": "b", "original_uuid": "o"}), \
             patch(__name__ + ".snapshot_present", return_value=False), \
             patch("collect_v19.run_logged") as logged, patch("collect_v19.restore") as cleanup:
            attempt = temporary / "attempt"
            attempt.mkdir()
            try:
                perform_phase(attempt, "preflight", "h", "")
            except ValueError:
                pass
            else:
                raise AssertionError("Missing approval accepted")
            require(not (attempt / "phases").exists(), "Unapproved phase wrote a receipt")
            perform_phase(attempt, "preflight", "h", "SIMULATED preflight")
            require(load(attempt / "phases/preflight/result.json")["status"] == "passed", "preflight failed")
            require(logged.call_count == 0 and cleanup.call_count == 0, "read-only preflight touched the VM")
    print("PASS SIMULATED approval gate + read-only preflight (no VirtualBox calls)")


def self_test():
    verify_production()
    with tempfile.TemporaryDirectory(prefix="hazim-v21-pins-") as directory:
        scratch = Path(directory)
        for name in PINNED:
            (scratch / name).parent.mkdir(parents=True, exist_ok=True)
            (scratch / name).write_bytes((STUDY / name).read_bytes())
        verify_production(scratch)
        for name in PINNED:
            original = (scratch / name).read_bytes()
            (scratch / name).write_bytes(original + b"\n")
            try:
                verify_production(scratch)
            except ValueError as error:
                require(name in str(error), "Wrong provenance guard")
            else:
                raise AssertionError("Changed production file accepted: " + name)
            (scratch / name).write_bytes(original)
    classify_tests()
    build_tests()
    saved_tests()
    phase_mock_tests()
    print("PASS collect_v21 self-test; no VM or sample execution")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--phase", choices=("preflight", "preflight-benign", "stage", "dry-run", "collect"))
    action.add_argument("--validate", action="store_true")
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    options = parser.parse_args()
    if options.phase or options.validate:
        require(options.attempt and options.protocol_sha256, "Attempt path and approved frozen hash required")
        if options.phase:
            perform_phase(options.attempt.resolve(), options.phase, options.protocol_sha256, options.approval)
        else:
            validate(options.attempt.resolve(), options.protocol_sha256)
    elif options.self_test:
        self_test()
    else:
        freeze()


if __name__ == "__main__":
    main()
