"""One newly requested benign attempt using the unchanged strict V3 harness."""

import argparse
import json
import signal
from datetime import datetime, timezone
from pathlib import Path

import check_performance_v3 as version


ROOT = Path(__file__).resolve().parent
identity = version.identity
performance = version.performance
gate = version.gate
PINS = {
    "performance_v3.py": "73acfd00f9f8e28132dcfe8ba92c03fc9e359d5bcaff9e9654001182031634ef",
    "check_performance_v3.py": "d09e5ad186d44961a4149b6515da2ac1b719500d86356c5b7d2cfa367f21a5b4",
    "PERFORMANCE_PROTOCOL_V3.md": "44c71996f1b42a1ffc6446a521b072cc5472117d93f02b9c84d577df53a9bca1",
}


def verify_inputs():
    hashes = version.frozen.verify_inputs()
    for name, expected in PINS.items():
        path = ROOT / name
        if identity.digest(path) != expected:
            raise ValueError("Frozen V3 repair changed: " + name)
        hashes[str(path)] = expected
    return hashes


def preflight():
    from export_original_sources import check_competitors, helper_module
    verify_inputs()
    helper = helper_module()
    helper.verify_production()
    check_competitors()
    state = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
    if not (state["guest"]["VMState"].strip('"') == "poweroff"
            and state["guest"]["CurrentSnapshotName"].strip('"') == helper.ORIGINAL
            and state["sink"]["VMState"].strip('"') == "running"):
        raise ValueError("Need original TLS/off and isolated Sink/running")
    return state


def freeze():
    hashes = verify_inputs()
    driver = version.load_driver()
    attempt, manifest = driver["freeze"]()
    path = attempt / "protocol.json"
    protocol = json.loads(path.read_text())
    for name in (Path(__file__).name, "audit_performance_v3.py", "PERFORMANCE_V3_ATTEMPT_PROTOCOL.md"):
        hashes[str(ROOT / name)] = identity.digest(ROOT / name)
    protocol["source_hashes"].update(hashes)
    protocol.update(
        approval='User requested "can you get accepted performance measurement sand final release-specific checks please ?"; one benign attempt only, unchanged strict gate',
        fresh_attempts_authorized=1, recorder_seconds=22, acknowledgement_seconds=12,
        diagnostic_28s_lifetime_imported=False, helper_transactions=0,
        timing_boundary_unchanged=True, task_source_unchanged=True,
        strict_quality_gate_unchanged=True, automatic_retry_authorized=False,
        malware_launch_authorized=False, fitting_authorized=False,
        final_collection_release_authorized=False,
    )
    path.write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    return attempt, manifest, driver


def self_test():
    verify_inputs()
    version.self_test()
    driver = version.load_driver()
    if driver["__file__"] != version.__file__ or driver["integration"].SCHEMA != performance.SCHEMA:
        raise ValueError("Host/guest V3 binding differs")
    print("PASS separately bound V3 host launcher; original strict gates/tasks/limits retained; no VM operation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--check-only", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    options = parser.parse_args()
    if options.check_only:
        preflight()
        print("PASS read-only production/competitor/original-TLS/off/internal-only/Sink preflight")
        return
    self_test()
    if options.self_test:
        return
    if options.execute_benign_checks:
        preflight()
    attempt, manifest, driver = freeze()
    if options.execute_benign_checks:
        receipt = {"requested_at": datetime.now(timezone.utc).isoformat(), "attempt": str(attempt),
                   "protocol_sha256": identity.digest(attempt / "protocol.json"),
                   "strict_quality_gate_unchanged": True, "automatic_retry_authorized": False}
        claim = attempt.parent / "one-attempt-authorization.json"
        with claim.open("x") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        driver["execute"](attempt, manifest)


if __name__ == "__main__":
    main()