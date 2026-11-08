"""One benign attempt: the unchanged V3 harness plus per-case capture-path probes (V4)."""

import argparse
import json
import signal
from datetime import datetime, timezone
from pathlib import Path

import check_performance_v4 as version
import run_performance_v3 as previous


ROOT = Path(__file__).resolve().parent
identity = version.identity
performance = version.performance
gate = version.gate
PINS = {
    "performance_v4.py": "44ed0debb6349253999bd3e71a71f4ee6ac4783c0cd39239d5995034b10c5306",
    "check_performance_v4.py": "c6a0860d8f850ed544d8672f5e59dc2d2c65fda3031ab2461a0791bbef017942",
    "PERFORMANCE_PROTOCOL_V4.md": "4543c26f81c15c2c9548bae01999dcf302890d595618c2143d90d3621b79c3e3",
}


def verify_inputs():
    hashes = previous.verify_inputs()
    for name, expected in PINS.items():
        path = ROOT / name
        if identity.digest(path) != expected:
            raise ValueError("Frozen V4 source changed: " + name)
        hashes[str(path)] = expected
    return hashes


def preflight():
    verify_inputs()
    return previous.preflight()


def freeze(launch_approval=None):
    hashes = verify_inputs()
    driver = version.load_driver()
    attempt, manifest = driver["freeze"]()
    path = attempt / "protocol.json"
    protocol = json.loads(path.read_text())
    for name in (Path(__file__).name, "audit_performance_v4.py"):
        hashes[str(ROOT / name)] = identity.digest(ROOT / name)
    protocol["source_hashes"].update(hashes)
    protocol.update(
        approval='User chose "V4 per-case probes (Recommended)" on 2026-10-24 over quiet-policy V1 bracketing and per-case restore',
        launch_approval=launch_approval, fresh_attempts_authorized=1 if launch_approval else 0,
        recorder_seconds=22, acknowledgement_seconds=12, diagnostic_28s_lifetime_imported=False,
        helper_transactions=0, capture_path_probes_per_sensor_case=2,
        capture_path_probe_target="%s:%d" % performance.TARGET,
        original_quality_function_unchanged=True, strict_quality_gate_unchanged=False,
        no_traffic_reason_superseded_by_probe_recovery=True,
        timing_boundary_unchanged=True, task_source_unchanged=True, automatic_retry_authorized=False,
        malware_launch_authorized=False, fitting_authorized=False, final_collection_release_authorized=False,
    )
    path.write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    return attempt, manifest, driver


def self_test():
    verify_inputs()
    version.self_test()
    driver = version.load_driver()
    if driver["__file__"] != version.__file__ or driver["integration"].SCHEMA != performance.SCHEMA:
        raise ValueError("Host/guest V4 binding differs")
    print("PASS separately bound V4 host launcher; V3 pins, tasks, timing and limits retained; no VM operation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--check-only", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    parser.add_argument("--approval", help="verbatim user launch approval, required with --execute-benign-checks")
    options = parser.parse_args()
    if options.check_only:
        preflight()
        print("PASS read-only production/competitor/original-TLS/off/internal-only/Sink preflight")
        return
    if options.execute_benign_checks and not options.approval:
        parser.error("--execute-benign-checks requires --approval")
    self_test()
    if options.self_test:
        return
    if options.execute_benign_checks:
        preflight()
    attempt, manifest, driver = freeze(options.approval if options.execute_benign_checks else None)
    if options.execute_benign_checks:
        receipt = {"requested_at": datetime.now(timezone.utc).isoformat(), "attempt": str(attempt),
                   "protocol_sha256": identity.digest(attempt / "protocol.json"), "approval": options.approval,
                   "capture_path_probes_per_sensor_case": 2, "automatic_retry_authorized": False}
        claim = attempt.parent / "one-attempt-authorization.json"
        with claim.open("x") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        driver["execute"](attempt, manifest)


if __name__ == "__main__":
    main()
