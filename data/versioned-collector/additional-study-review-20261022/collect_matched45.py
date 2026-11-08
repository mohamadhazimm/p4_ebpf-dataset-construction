#!/usr/bin/env python3
"""One authorized capture of the frozen matched extension; no retry or training."""

import argparse
import csv
import fcntl
import json
import math
import os
import signal
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import audit_matched45_readiness as audit
import ready_matched45 as ready
from export_original_sources import check_competitors


RELEASE = ready.ROOT / "matched45-readiness/20261022T072823231146Z"
GATE = RELEASE / "gates/20261022T072901422487Z"
EXPECTED_READY = "ec335f085853d1f0b6482ea9299f2db7127e6b66e7ed82e7bec891a38bea8e33"
EXPECTED_SNAPSHOT = "a3af439c-ad5f-403c-a7fe-df2676c17999"
HELPER = ready.helper


def now():
    return datetime.now(timezone.utc).isoformat()


def status(run, stage, **extra):
    temporary = run / "status.tmp"
    temporary.write_text(json.dumps({"stage": stage, "updated_utc": now(), **extra}, indent=2) + "\n")
    temporary.replace(run / "status.json")


def preflight():
    if ready.digest(GATE / "readiness.json") != EXPECTED_READY:
        raise ValueError("Accepted readiness changed")
    report = audit.audit(GATE)
    accepted = ready.load(GATE / "readiness.json")
    if accepted["snapshot_uuid"].strip('"') != EXPECTED_SNAPSHOT:
        raise ValueError("Accepted snapshot UUID differs")
    snapshot = HELPER.vbox("snapshot", HELPER.VM, "list", "--machinereadable")
    entries = dict(line.split("=", 1) for line in snapshot.stdout.splitlines() if "=" in line)
    names = [key for key, value in entries.items() if key.startswith("SnapshotName") and value.strip('"') == accepted["snapshot"]]
    if len(names) != 1 or entries.get(names[0].replace("SnapshotName", "SnapshotUUID"), "").strip('"') != EXPECTED_SNAPSHOT:
        raise ValueError("Accepted snapshot is not available with its pinned UUID")
    states = {"guest": HELPER.isolated(HELPER.VM), "sink": HELPER.isolated("Sink")}
    if (states["guest"]["VMState"] != '"poweroff"'
            or states["guest"]["CurrentSnapshotName"] != '"' + HELPER.ORIGINAL + '"'
            or states["sink"]["VMState"] != '"running"'):
        raise ValueError("Require clean original powered-off guest and running isolated Sink")
    check_competitors()
    if (RELEASE / "collection").exists():
        raise ValueError("Collection directory already exists; no implicit resume/retry")
    return accepted, states, report


def batch_command(run, accepted):
    manifest = ready.load(RELEASE / "manifest.json")
    return ["bash", str(ready.STUDY / "scripts/vbox_malware_batch.sh"),
        "--vm", HELPER.VM, "--guest-user", HELPER.GUEST_USER,
        "--guest-malware-dir", manifest["guest_root"] + "/samples",
        "--guest-runner", "/home/csci/Downloads/malware_runner.py",
        "--snapshot", accepted["snapshot"], "--schema-version", HELPER.SCHEMA,
        "--guest-arguments-dir", manifest["guest_root"] + "/arguments",
        "--sample-list", str(RELEASE / "all-cases.txt"), "--output-dir", str(run / "runs"),
        "--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
        "--fixed-observation", "--common-launch-wrapper"]


def capture(command, run):
    with (run / "collection.log").open("x") as log:
        child = subprocess.Popen(command, cwd=ready.STUDY, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1, start_new_session=True)
        try:
            for line in child.stdout:
                print(line, end="", flush=True)
                log.write(line)
                log.flush()
            return child.wait()
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            child.stdout.close()


def restore_guest(run):
    if HELPER.vm_info(HELPER.VM)["VMState"] != '"poweroff"':
        HELPER.vbox("controlvm", HELPER.VM, "poweroff")
    HELPER.vbox("snapshot", HELPER.VM, "restore", HELPER.ORIGINAL)
    states = {"guest": HELPER.isolated(HELPER.VM), "sink": HELPER.isolated("Sink")}
    ready.save(run / "final_vm_state.json", states)
    if states["guest"]["VMState"] != '"poweroff"' or states["guest"]["CurrentSnapshotName"] != '"' + HELPER.ORIGINAL + '"':
        raise RuntimeError("Cleanup did not restore the clean powered-off guest")


def validate_retrieval(run):
    from scapy.utils import RawPcapReader
    manifest = ready.load(RELEASE / "manifest.json")
    totals, rows = Counter(), []
    for case in ready.load(RELEASE / "case_order.json"):
        sample = run / "runs" / case["sample"]
        host_path = sample / "host_run.txt"
        host = dict(line.split("=", 1) for line in host_path.read_text().splitlines() if "=" in line) if host_path.exists() else {}
        row = {"sample": case["sample"], "label": case["label"], "mode": case["mode"],
            "split": case["split"], "retrieval_status": host.get("status", "missing"), "quality_status": "unavailable"}
        rows.append(row)
        totals["retrieval_" + row["retrieval_status"]] += 1
        paths = list(sample.glob("output/run_*/run.json"))
        if not paths:
            continue
        if len(paths) != 1:
            raise ValueError("Ambiguous output metadata: " + case["sample"])
        metadata = ready.load(paths[0])
        for key, expected in manifest["settings_required"].items():
            if key not in {"collection_quality_status", "ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel"} and metadata.get(key) != expected:
                raise ValueError("Pinned collection setting differs: " + case["sample"] + ":" + key)
        totals["archive_members"] += HELPER.verify_output_archive(sample)
        features = [name for values in metadata["telemetry_feature_groups"].values() for name in values]
        with (paths[0].parent / "telemetry.csv").open(newline="") as stream:
            telemetry = list(csv.DictReader(stream))
        if len(telemetry) != 40 or len(features) != 169 or len(set(features)) != 169 or not all(math.isfinite(float(window[name])) for window in telemetry for name in features):
            raise ValueError("Incomplete or nonfinite telemetry: " + case["sample"])
        totals["finite_cells"] += 40 * 169
        with RawPcapReader(str(paths[0].parent / "packet_capture.pcap")) as reader:
            count = sum(1 for _packet in reader)
        if count != metadata["packet_capture_statistics"].get("packets_captured"):
            raise ValueError("PCAP file/captured-count disagreement: " + case["sample"])
        totals["pcap_records"] += count
        row.update(quality_status=metadata.get("collection_quality_status", "unavailable"),
            target_exec_status=metadata.get("target_exec", {}).get("status", "unavailable"),
            return_code=metadata.get("return_code"), ebpf_lost_events=metadata.get("ebpf_lost_event_count"),
            packet_discrepancy=metadata.get("packet_capture_counter_discrepancy"),
            pcap_kernel_drops=metadata.get("packet_capture_dropped_by_kernel"))
        totals["quality_" + row["quality_status"]] += 1
        if row["quality_status"] == "accepted":
            for key in ("ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel"):
                if metadata.get(key) != 0:
                    raise ValueError("Accepted quality contradicts loss evidence")
            if metadata["packet_capture_statistics"].get("packets_received_by_filter") != count:
                raise ValueError("Accepted quality contradicts packet counters")
    return {"status": "retrieval_audited_no_merge_or_model", "totals": dict(totals), "cases": rows,
        "model_fits": 0, "merged_cases": 0, "limits": [
            "Retrieval and sensor quality do not establish target execution or malicious activation",
            "Rejected, missing and exec-unobserved cases must not silently enter a model",
            "Per-run target/mode/ABI, null and unique recorded-window Ethernet/nominal P4 parity gates remain required before merging",
            "Low activity is retained; consumed validation remains exploratory"]}


def execute(accepted, states, report):
    paths = [Path(__file__), Path(audit.__file__), Path(ready.__file__), Path(ready.workloads.__file__),
        RELEASE / "protocol.json", RELEASE / "preregistration.json", RELEASE / "case_order.json",
        RELEASE / "all-cases.txt", GATE / "readiness.json", Path(HELPER.__file__)]
    hashes = {str(path.relative_to(ready.STUDY)): ready.digest(path) for path in paths}
    run = RELEASE / "collection"
    run.mkdir(exist_ok=False)
    command = batch_command(run, accepted)
    ready.save(run / "launch_manifest.json", {"started_utc": now(), "pid": os.getpid(),
        "authorization": "User explicitly requested starting the approved matched45 collection",
        "cases": 96, "study_malware": 45, "study_benign": 45, "null_controls": 6,
        "snapshot": accepted["snapshot"], "snapshot_uuid": EXPECTED_SNAPSHOT,
        "frozen_hashes": hashes, "production_hashes": HELPER.PINNED,
        "readiness_report": report, "initial_vm_state": states, "command": command,
        "automatic_retry": False, "resume": False, "replacement": False,
        "model_training": False, "merge_enabled": False})
    def stop(_signal, _frame):
        raise KeyboardInterrupt("Collection interrupted; stop batch and clean guest")
    signal.signal(signal.SIGTERM, stop)
    try:
        status(run, "capturing", planned_cases=96)
        try:
            returncode = capture(command, run)
        finally:
            restore_guest(run)
        if returncode:
            raise RuntimeError("Pinned batch returned " + str(returncode) + "; preserve all failures, no retry")
        status(run, "validating_retrieval", planned_cases=96)
        HELPER.verify_production()
        for name, expected in hashes.items():
            if ready.digest(ready.STUDY / name) != expected:
                raise ValueError("Frozen workflow input changed: " + name)
        ready.save(run / "retrieval_validation.json", validate_retrieval(run))
        status(run, "capture_complete_retrieval_audited", model_fits=0, merged_cases=0,
            next_gate="Review exclusions and target/mode/ABI/null/P4 alignment/parity before any merge")
    except BaseException as error:
        status(run, "stopped_requires_review", error=type(error).__name__ + ": " + str(error),
            no_automatic_retry=True, model_fits=0, merged_cases=0)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    with (ready.NATIVE / "readiness.lock").open("r") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        accepted, states, report = preflight()
        print(json.dumps({"launch_checks": "passed", "planned_cases": 96, "snapshot": accepted["snapshot"],
            "mode": "capture_only_no_retry_no_merge_no_model"}), flush=True)
        if args.execute:
            execute(accepted, states, report)


if __name__ == "__main__":
    main()