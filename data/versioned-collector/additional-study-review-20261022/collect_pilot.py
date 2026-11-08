"""Observation-length pilot driver: 5 malware + 5 long benign + 3 null, each observed for 5 minutes (600 windows).

Purpose: measure whether a 5-minute observation reveals host/network/hybrid signal that the 20-second observation
truncates. This is a 13-case feasibility probe, NOT a cohort for modelling. It reuses collect_v21's already-tested
phase machinery (preflight / stage / dry-run / collect, snapshot/restore, batch/stage commands, benign preflight) by
overriding three module globals: SETTINGS (--timeout 300), SCHEMA (.22), PINNED (the .22 runner). The .22 runner is
.21 plus a bounded-memory fail-closed guard (build_runner_v22.py) so a sample that spikes over 5 minutes cannot
exhaust the 6 GiB guest. Malware/null transports are reused verbatim from the frozen revision5 payload; benign are the
long workloads (benign_workloads_long). No retries/resume/replacement; stop on first failure; restore original TLS/off
on any mutating exit. The per-case audit is lighter than the .21 cohort audit (clean-capture essentials at 600 windows);
P4 reconstruction and the 20s/1/2/3/5-min prefix scoring are a separate offline analysis.

Local freeze and --self-test pin the .22 runner by its collector-v22 FILE and never touch src/, so they are
non-destructive. The VM phases (stage/collect) additionally require .22 installed at src/malware_runner.py (the pinned
batch stages and hash-checks src/), which is an explicit install step at the VM checkpoint, preserving .21 first.
"""

import collections
import csv
import json
import math
import signal
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21                 # noqa: E402  generic phase machinery (globals overridden below)
import build_pilot_payload as builder     # noqa: E402  pilot payload assembly
import benign_workloads_long as bwl       # noqa: E402  the 5 long workloads

frozen = v21.frozen
require, digest, save, load, stamp = frozen.require, frozen.digest, frozen.save, frozen.load, frozen.stamp
STUDY = frozen.STUDY

# ---- pilot overrides of collect_v21's globals (picked up by stage_command/batch_command/verify_production/preflight)
PILOT_SCHEMA = "2026-11-05.22"
V22_FILE = "data/versioned-collector/additional-study-review-20261022/collector-v22/malware_runner.py"
V22_SHA = digest(STUDY / V22_FILE)
PILOT_SETTINGS = ["--timeout", "300", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
                  "--fixed-observation", "--common-launch-wrapper"]
PILOT_PINNED = {
    V22_FILE: V22_SHA,
    "scripts/vbox_malware_batch.sh": v21.PINNED["scripts/vbox_malware_batch.sh"],
    "scripts/stage_versioned_runner_snapshot.sh": v21.PINNED["scripts/stage_versioned_runner_snapshot.sh"],
}
v21.SCHEMA = PILOT_SCHEMA
v21.SETTINGS = PILOT_SETTINGS
v21.PINNED = PILOT_PINNED

SCHEMA, BASELINE = v21.SCHEMA, v21.BASELINE
BASELINE_UUID, ORIGINAL_UUID = v21.BASELINE_UUID, v21.ORIGINAL_UUID
SETTINGS, PINNED = v21.SETTINGS, v21.PINNED
FORMAT = "observation-length-pilot-v1"
EXPECTED_WINDOWS = 600  # 300 s / 0.5 s


def require_v22_installed():
    """VM phases stage and hash-check src/malware_runner.py, so .22 must be installed there (install step preserves
    .21 first). Local freeze/self-test do not call this."""
    require(digest(STUDY / "src/malware_runner.py") == V22_SHA,
            "src/malware_runner.py is not the .22 runner (%s expected). Install collector-v22 into src/ (preserve .21 "
            "first) before the VM phases." % V22_SHA[:12])


# ------------------------------------------------------------------------------------------------- payload / freeze

def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "pilot-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/pilot5min-" + run_id
    manifest, order = builder.build(attempt / "payload", guest_root)
    require(manifest["counts"] == {"malware": 5, "benign": 5, "null": 3}, "Payload counts are not 5/5/3")
    payload_bytes = v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    benign_list = [c for c in order if c["label"] in ("benign", "null")]
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in benign_list))

    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": BASELINE_UUID, "original_uuid": ORIGINAL_UUID,
        "new_snapshot": "clean-pilot5min-" + run_id, "benign_snapshot": "clean-pilot5min-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "network_benign": sum(1 for c in order if c["label"] == "benign" and c.get("network")),
        "benign_binaries": manifest["benign_binaries"], "expected_windows": EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(builder.__file__)), "workloads_sha256": digest(ROOT / "benign_workloads_long.py"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Observation-length feasibility: do host/network/hybrid signals grow from 20 s to 5 min, and for",
                    "which sensor? Scored on prefixes (first 40/120/240/360/600 windows) of the same captures; the",
                    "first 40 windows reproduce the 20 s protocol. 13-case probe, not a cohort or model."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec",
                     "(malware/benign); telemetry 600x169 finite; safe archive hashes; nulls quiet for the full 5 min"],
        "limitations": [".22 (bounded-memory fail-closed) headless-quiet dataset; never merged with .21/.20/.19 or any",
                        "other captures without a compatibility analysis. CatStorm/Chaos excluded (would overflow at 5",
                        "min). Benign re-tasked to long workloads (openssl speed / sqlite CTE / rsync bwlimit / curl &",
                        "wget throttled) sized to exceed 5 min on the fast host so a slower guest stays active throughout;",
                        "the 300 s fixed observation truncates the tail symmetrically with the malware. Feasibility only."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_mode_label": protocol["by_mode_label"],
                      "network_benign": protocol["network_benign"], "runner_v22_sha256": V22_SHA[:12],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA,
                      "vm_steps_authorized": []}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    require(expected_hash and digest(attempt / "protocol.json") == expected_hash, "Explicit frozen protocol hash required")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == FORMAT and protocol["production_hashes"] == PINNED, "Protocol version or pins differ")
    require(protocol["settings"] == SETTINGS and protocol["schema"] == SCHEMA
            and protocol["baseline_snapshot"] == BASELINE and protocol["runner_v22_sha256"] == V22_SHA,
            "Frozen pilot contract differs")
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner changed since freeze")
    for name, expected in protocol["files"].items():
        require(digest(attempt / name) == expected, "Frozen payload/order changed: " + name)
    return protocol


# ----------------------------------------------------------------------------------------------------- VM phases

def perform_phase(attempt, phase, expected_hash, approval):
    require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    protocol = verify_plan(attempt, expected_hash)
    module = frozen.helper()
    predecessors = {"preflight-benign": "preflight", "stage": "preflight", "dry-run": "stage", "collect": "dry-run"}
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
            require_v22_installed()
            snapshot = protocol["benign_snapshot"] if phase == "preflight-benign" else protocol["new_snapshot"]
            require(not v21.snapshot_present(module, snapshot), "Child already exists; no restage")
            touched = True
            save(destination / "command.json", v21.stage_command(attempt, module, snapshot))
            frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
            result["snapshot_uuid"] = frozen.snapshot_uuid(module, snapshot)
            if phase == "preflight-benign":
                out = destination / "runs"
                require(not out.exists(), "Existing benign output; no retry")
                n_bn = sum(1 for c in protocol["cases"] if c["label"] in ("benign", "null"))
                frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, out, attempt / "benign-null.txt"),
                                  destination / "collection.log", n_bn * 500 + 7200)  # ~500 s/case + 2 h margin
                result["benign_audit"] = [pilot_audit(out / c["sample"], c, protocol)
                                          for c in protocol["cases"] if c["label"] in ("benign", "null")]
        elif phase == "dry-run":
            require_v22_installed()
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
            require_v22_installed()
            staged = load(attempt / "phases/stage/result.json")
            require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child differs")
            require(not (attempt / "runs").exists(), "Existing output; no retry/resume")
            touched = True
            command = v21.batch_command(module, attempt, protocol, protocol["new_snapshot"], attempt / "runs", attempt / "cases.txt")
            save(destination / "command.json", command)
            frozen.run_logged(command, destination / "command.log", len(protocol["cases"]) * 500 + 7200)  # ~500 s/case (300 s obs + overhead) + 2 h margin
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


# ------------------------------------------------------------------------------------------------- per-case audit

def pilot_audit(sample_dir, case, protocol):
    """Clean-capture essentials at 600 windows. Lighter than the .21 cohort audit; P4 parity is left to the offline
    prefix analysis. Raises on any failure (the caller records accepted/excluded)."""
    paths = list((sample_dir / "output").glob("run_*/run.json")) if sample_dir.exists() else []
    require(len(paths) == 1, "Missing or ambiguous run.json")
    run_dir = paths[0].parent
    m = load(paths[0])
    req = protocol["settings_required"]
    require(m.get("telemetry_schema_version") == req["telemetry_schema_version"], "Schema differs")
    require(m.get("malware_runner_sha256") == req["malware_runner_sha256"], "Runner hash differs")
    require(m.get("collection_quality_status") == "accepted",
            "Quality rejected: " + ",".join(m.get("collection_quality_reasons") or []))
    require((m.get("ebpf_events_overflow") or 0) == 0, "eBPF events overflow")
    exec_status = (m.get("target_exec") or {}).get("status")
    if case["label"] != "null":
        require(exec_status == "observed", "Target exec not observed")
    telemetry = list(csv.DictReader((run_dir / "telemetry.csv").open()))
    features = [name for group in m["telemetry_feature_groups"].values() for name in group]
    require(len(telemetry) == protocol["expected_windows"] and len(features) == len(set(features)) == 169
            and all(math.isfinite(float(w[name])) for w in telemetry for name in features),
            "Incomplete/nonfinite %dx169" % protocol["expected_windows"])
    frozen.audit_archive(run_dir.parents[1])  # safe archive member hashes
    return {"sample": case["sample"], "label": case["label"], "mode": case["mode"],
            "network": case.get("network"), "family": case.get("family"), "program": case.get("program"),
            "return_code": m.get("return_code"), "exec_status": exec_status,
            "post_target_lineage_raw_syscalls": (m.get("target_exec") or {}).get("post_target_lineage_raw_syscalls"),
            "windows": len(telemetry)}


def validate(attempt, expected_hash):
    protocol = verify_plan(attempt, expected_hash)
    rows = []
    for case in protocol["cases"]:
        try:
            row = pilot_audit(attempt / "runs" / case["sample"], case, protocol)
            row["status"] = "accepted"
        except Exception as error:
            row = {"sample": case["sample"], "label": case["label"], "mode": case["mode"],
                   "status": "excluded", "reason": type(error).__name__ + ": " + str(error)}
        rows.append(row)
    nulls = {r["mode"]: r["post_target_lineage_raw_syscalls"] for r in rows
             if r["label"] == "null" and r["status"] == "accepted"}
    summary = {"status": "offline_audited_no_merge_no_model", "protocol_sha256": expected_hash, "results": rows,
               "counts": dict(collections.Counter(r["status"] for r in rows)),
               "accepted_by_mode_label": {str(k): v for k, v in sorted(collections.Counter(
                   (r["mode"], r["label"]) for r in rows if r["status"] == "accepted").items())},
               "null_post_target_syscalls": nulls, "collection_ready": False, "model_fits": 0, "merged_cases": 0,
               "validator_sha256": digest(__file__), "limitations": protocol["limitations"]}
    report = attempt / ("validation-" + stamp() + ".json")
    save(report, summary)
    print(json.dumps({"report": str(report), "counts": summary["counts"],
                      "accepted_by_mode_label": summary["accepted_by_mode_label"],
                      "null_post_target_syscalls": nulls}, indent=2))
    return summary


# ----------------------------------------------------------------------------------------------------- self-test

def build_tests():
    with tempfile.TemporaryDirectory(prefix="hazim-pilot-build-") as directory:
        out = Path(directory) / "payload"
        manifest, order = builder.build(out, "/home/csci/Downloads/pilot5min-TEST")
        require(manifest["counts"] == {"malware": 5, "benign": 5, "null": 3}, "Payload counts differ")
        require(len(order) == 13 and len({c["sample"] for c in order}) == 13, "Order not 13 unique")
        require({c["mode"] for c in order} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "Unmapped mode label in order")
        # malware member hash matches the frozen revision5 member (reused verbatim)
        for case in [c for c in order if c["label"] == "malware"]:
            member = subprocess.run(["7z", "x", "-so", "-pinfected", str(out / "samples" / case["sample"])],
                                    capture_output=True).stdout
            require(__import__("hashlib").sha256(member).hexdigest() == case["expected_member_sha256"],
                    "Malware member hash differs from revision5: " + case["sample"])
        # benign arguments carry the pilot guest-root, no stale prefix
        stale = [a.name for a in (out / "arguments").glob("*-pilot.zip.json")
                 if "/home/csci/Downloads/" in a.read_text() and "pilot5min-TEST" not in a.read_text()]
        require(not stale, "Stale guest-root in benign arguments: " + ",".join(stale))
        setup = v21.build_setup("/home/csci/Downloads/pilot5min-TEST", v21.make_tgz(out))
        subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    print("PASS deterministic 13-case payload (5/5/3), malware member hashes == revision5, native modes, setup syntax")


def settings_tests():
    require(SETTINGS[:2] == ["--timeout", "300"], "Pilot timeout is not 300 s")
    require(SCHEMA == "2026-11-05.22" and PINNED[V22_FILE] == V22_SHA, "Pilot pins .22 incorrectly")
    # batch/stage commands carry the pilot schema and 300 s timeout
    fake = SimpleNamespace(VM="t", GUEST_USER="t")
    proto = {"guest_root": "/g"}
    bc = v21.batch_command(fake, Path("/a"), proto, "snap", Path("/o"), Path("/l"))
    require("--schema-version" in bc and bc[bc.index("--schema-version") + 1] == "2026-11-05.22", "batch schema wrong")
    require("--timeout" in bc and bc[bc.index("--timeout") + 1] == "300", "batch timeout wrong")
    sc = v21.stage_command(Path("/a"), fake, "snap")
    require(sc[sc.index("--schema-version") + 1] == "2026-11-05.22", "stage schema wrong")
    print("PASS pilot overrides: 300 s / schema .22 / .22 pin flow into stage+batch commands")


def phase_mock_tests():
    with tempfile.TemporaryDirectory(prefix="hazim-pilot-phases-") as directory:
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


def selftest_v22_not_required_locally():
    # Freeze/self-test must not depend on src/ being .22 (install is a VM-checkpoint step).
    require(V22_SHA and len(V22_SHA) == 64, "collector-v22 runner hash unavailable")
    print("PASS local freeze pins the collector-v22 FILE; src/ untouched (src_is_v22=%s)"
          % (digest(STUDY / "src/malware_runner.py") == V22_SHA))


def self_test():
    settings_tests()
    selftest_v22_not_required_locally()
    build_tests()
    phase_mock_tests()
    print("PASS collect_pilot self-test; no VM or sample execution")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Observation-length pilot (5 min / 600 windows)")
    parser.add_argument("--freeze-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--phase", choices=["preflight", "preflight-benign", "stage", "dry-run", "collect"])
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--attempt")
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.freeze_only:
        freeze()
    elif args.validate:
        validate(Path(args.attempt).resolve(), args.protocol_sha256)
    elif args.phase:
        # Absolute so the staged setup script / sample list resolve regardless of the batch/stager working dir.
        perform_phase(Path(args.attempt).resolve(), args.phase, args.protocol_sha256, args.approval)
    else:
        parser.error("choose --self-test, --freeze-only, --phase, or --validate")


if __name__ == "__main__":
    main()
