"""Approval-gated matched-cohort (revision5-matched) quiet collection: 105 malware + 105 benign + 9 null.

Confound-controlled redo of the quiet collection: diverse families (cap 10/family, new MalwareBazaar families),
family/project-held-out split, and ACTIVITY-MATCHED benign (host-preflighted so benign syscall volume overlaps the
malware per-mode bands). New self-contained driver; re-pinned to the installed .21 runner and the validated headless
quiet child, same batch/stager/SETTINGS as collect_v21, and reuses collect_v21's already-tested generic machinery
(provenance check, payload setup, per-case technical audit, v21 traffic gate, batch/stage commands, benign preflight)
plus collect_v19's generic helpers. Only the inputs (revision5 selection + benign binding + fixtures), attempt root,
guest root, snapshot names and protocol format differ. No retries/resume/replacement; stop on first failure; preserve.

Phases: preflight (read-only) / preflight-benign (stage + run the 105 benign + 9 null only; confirm Sink tasks reach
enp0s3, drop non-answering) / stage / dry-run / collect. Per-case acceptance = collect_v21's technical gates + v21
traffic gate. Never edits production, the frozen selections, or any frozen driver.
"""

import argparse
import collections
import fcntl
import io
import json
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
import collect_v21 as v21                 # noqa: E402  generic phase/audit/traffic-gate machinery (pins .21)
import build_revision5_payload as builder  # noqa: E402  revision5 payload assembly

frozen = v21.frozen                        # collect_v19 generic helpers
require, digest, save, load, stamp = frozen.require, frozen.digest, frozen.save, frozen.load, frozen.stamp
STUDY = frozen.STUDY
SCHEMA, BASELINE, BASELINE_UUID, ORIGINAL_UUID = v21.SCHEMA, v21.BASELINE, v21.BASELINE_UUID, v21.ORIGINAL_UUID
SETTINGS, PINNED = v21.SETTINGS, v21.PINNED
FORMAT = "revision5-matched-collection-v1"
MALWARE_SEL = STUDY / "data/malware/revision5-diverse/matched-selection/malware_selection.json"
BENIGN_SEL = STUDY / "data/benign/revision5-matched/benign_selection.json"
INVENTORY = STUDY / "data/benign/revision5-matched/benign_inventory.json"
INPUTS = {"malware_selection_sha256": MALWARE_SEL, "benign_selection_sha256": BENIGN_SEL,
          "benign_inventory_sha256": INVENTORY}


# ----------------------------------------------------------------------------------------------- payload / freeze

def freeze():
    v21.verify_production()
    for path in (MALWARE_SEL, BENIGN_SEL, INVENTORY):
        require(digest(path), "Frozen selection input missing: " + path.name)
    malware = load(MALWARE_SEL)
    benign = load(BENIGN_SEL)
    invmap = {r["sha256"]: r["locator"] for r in load(INVENTORY)}
    run_id = stamp()
    attempt = ROOT / "revision5-collection" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/revision5-matched-" + run_id
    workdir = attempt / "_wrap"
    workdir.mkdir()
    manifest, order = builder.build(attempt / "payload", malware, benign, invmap, guest_root, workdir)
    subprocess.run(["rm", "-rf", str(workdir)], check=False)
    require(manifest["counts"] == {"malware": 105, "benign": 105, "null": 9}, "Payload counts are not 105/105/9")
    payload_bytes = v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    benign_list = [c for c in order if c["label"] in ("benign", "null")]
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in benign_list))
    settings_required = {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": PINNED["src/malware_runner.py"],
                         "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True}
    protocol = {"format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED,
        "baseline_snapshot": BASELINE, "baseline_uuid": BASELINE_UUID, "original_uuid": ORIGINAL_UUID,
        "new_snapshot": "clean-rev5-collection-" + run_id, "benign_snapshot": "clean-rev5-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS, "settings_required": settings_required,
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "network_benign": manifest["network_benign"],
        "malware_selection_sha256": digest(MALWARE_SEL), "benign_selection_sha256": digest(BENIGN_SEL),
        "benign_inventory_sha256": digest(INVENTORY), "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(builder.__file__)), "workloads_sha256": digest(ROOT / "benign_workloads.py"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "criteria": ["installed .21 provenance; accepted quality; exact exec; native mode/linkage; 40x169 finite",
                     "safe archive hashes; independent PCAP == received == captured; zero loss/ABI; buffers restored",
                     "pre/post capture probes outside windows; unique recorded-window Ethernet/nominal P4 alignment+parity",
                     "null/non-network benign: quiet-v3.5 default-deny (no unexplained in-window frame)",
                     "network benign: own guest<->Sink traffic allowed and required; non-Sink in-window rejects",
                     "malware traffic recorded, not rejected; exclusions reported by family/mode/label"],
        "design": ["Matched cohort: mode-matched (native amd64 static/dynamic, i386 static for both labels),",
                   "activity-matched benign (host-preflighted to overlap malware per-mode syscall bands),",
                   "family-held-out malware + project-held-out benign; cap 10/family; new MB families included.",
                   "Purpose: remove the artifact/activity/return-code confounds so a measured hybrid-vs-host result",
                   "reflects behavior, not collection metadata. Exploratory; validation consumed once scored."],
        "limitations": ["Headless quiet .21-runner dataset; never merged with other captures without compatibility analysis",
                        "amd64-dynamic malware is training-only (singleton families); its validation stratum is benign-only",
                        "benign activity is a host-strace sizing proxy for malware's .21 bands; confirmed only at collect",
                        "musl Sink tasks are candidates; those the Sink does not answer on enp0s3 are dropped at preflight",
                        "P4 features are offline PCAP reconstruction; frame classification is not OS-process ownership"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_mode_label": protocol["by_mode_label"],
                      "network_benign": protocol["network_benign"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "vm_steps_authorized": []}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    require(expected_hash and digest(attempt / "protocol.json") == expected_hash, "Explicit frozen protocol hash required")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == FORMAT and protocol["production_hashes"] == PINNED, "Protocol version or pins differ")
    for field, path in INPUTS.items():
        require(protocol[field] == digest(path), "Frozen selection changed: " + path.name)
    require(protocol["settings"] == SETTINGS and protocol["schema"] == SCHEMA
            and protocol["baseline_snapshot"] == BASELINE, "Frozen collection contract differs")
    v21.verify_production()
    for name, expected in protocol["files"].items():
        require(digest(attempt / name) == expected, "Frozen payload/order changed: " + name)
    return protocol


# ----------------------------------------------------------------------------------------------- VM phases

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
            before = v21.preflight(module, protocol)
            save(destination / "initial_vm_state.json", before)
            if phase == "preflight":
                result.update(before)
            elif phase in ("preflight-benign", "stage"):
                snapshot = protocol["benign_snapshot"] if phase == "preflight-benign" else protocol["new_snapshot"]
                require(not v21.snapshot_present(module, snapshot), "Child already exists; no restage")
                touched = True
                save(destination / "command.json", v21.stage_command(attempt, module, snapshot))
                frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
                result["snapshot_uuid"] = frozen.snapshot_uuid(module, snapshot)
                if phase == "preflight-benign":
                    out = destination / "runs"
                    require(not out.exists(), "Existing benign output; no retry")
                    frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, out, attempt / "benign-null.txt"),
                                      destination / "collection.log", 7200)
                    result.update(v21.benign_preflight(attempt, destination, protocol))
            elif phase == "dry-run":
                staged = load(attempt / "phases/stage/result.json")
                require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child differs")
                require(not (attempt / "dry-run").exists(), "Existing output; no retry/resume")
                touched = True
                command = v21.batch_command(module, attempt, protocol, protocol["new_snapshot"], attempt / "dry-run",
                                            attempt / "cases.txt", dry_run=True)
                save(destination / "command.json", command)
                frozen.run_logged(command, destination / "command.log", 1200)
                result["validated_transports"] = v21.validate_dry_run(destination / "command.log", protocol)
            elif phase == "collect":
                staged = load(attempt / "phases/stage/result.json")
                require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child differs")
                require(not (attempt / "runs").exists(), "Existing output; no retry/resume")
                touched = True
                command = v21.batch_command(module, attempt, protocol, protocol["new_snapshot"], attempt / "runs", attempt / "cases.txt")
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
            row.update(v21.audit_case_v21(sample_dir, case, protocol["settings_required"], tools), status="accepted")
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

def build_tests():
    malware, benign = load(MALWARE_SEL), load(BENIGN_SEL)
    invmap = {r["sha256"]: r["locator"] for r in load(INVENTORY)}
    with tempfile.TemporaryDirectory(prefix="hazim-rev5-build-") as directory:
        out = Path(directory) / "payload"
        manifest, order = builder.build(out, malware, benign, invmap, "/home/csci/Downloads/revision5-matched-TEST",
                                        Path(directory) / "_w")
        require(manifest["counts"] == {"malware": 105, "benign": 105, "null": 9}, "Payload counts differ")
        require(len(order) == 219 and len({c["sample"] for c in order}) == 219, "Order not 219 unique")
        for case in [c for c in order if c["label"] == "malware"][:5]:
            member = subprocess.run(["7z", "x", "-so", "-pinfected", str(out / "samples" / case["sample"])],
                                    capture_output=True).stdout
            require(__import__("hashlib").sha256(member).hexdigest() == case["member_sha256"], "Malware member hash differs")
        stale = [a.name for a in (out / "arguments").glob("*.json") if "revision5-matched-TEST" not in a.read_text()
                 and ("/home/csci/Downloads/" in a.read_text())]
        require(not stale, "Unexpected guest-root prefix in arguments: " + ",".join(stale))
        require({c["mode"] for c in order} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "Unmapped mode label in order")
        setup = v21.build_setup("/home/csci/Downloads/revision5-matched-TEST", v21.make_tgz(out))
        subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    print("PASS deterministic 219-case payload (105/105/9), malware member hashes, native mode labels, setup syntax")


def phase_mock_tests():
    with tempfile.TemporaryDirectory(prefix="hazim-rev5-phases-") as directory:
        temporary = Path(directory)
        fake = SimpleNamespace(__file__=str(temporary / "helper.py"), VM="t", GUEST_USER="t",
                               vbox=lambda *a: SimpleNamespace(stdout=""))
        protocol = {"guest_root": "/g", "new_snapshot": "child", "benign_snapshot": "bchild",
                    "cases": [{"sample": "a.zip", "label": "malware"}, {"sample": "b.zip", "label": "benign"}]}
        with patch(__name__ + ".verify_plan", return_value=protocol), patch("collect_v19.helper", return_value=fake), \
             patch("collect_v21.preflight", return_value={"baseline_uuid": "b", "original_uuid": "o"}), \
             patch("collect_v21.snapshot_present", return_value=False), \
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
    v21.verify_production()
    v21.classify_tests()
    build_tests()
    phase_mock_tests()
    print("PASS collect_revision5 self-test; no VM or sample execution")


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
