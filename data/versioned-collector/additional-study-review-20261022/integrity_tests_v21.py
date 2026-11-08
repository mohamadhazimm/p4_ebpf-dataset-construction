"""Known-answer integrity battery for the installed .21 runner on the validated headless quiet snapshot.

Thin layer over frozen integrity_tests_v20.py (same 15 cases, probe, drop/leak/flood checks and quiet-v3.5
classifier), re-pinned to .21. Tightened for the .21 microsecond fix: window bounds must lie exactly (0 us) on the
sample_started_wall_us + k * 500000 us grid, the recorded start string must equal that anchor, and offline window
attribution must be unique in every case.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import integrity_tests_v20 as v20  # noqa: E402  frozen .20 battery layer

c19, v19i = v20.c19, v20.v19i
V20_DRIVER_SHA256 = "206bed8cfdb289d0f6f95b41895fe86d84e90e92283b4bc1fcb3c4af27b5d799"
RUNNER21 = "4933ff5c9c56bd097ce565d14a7173bd281dd124aca43d1df0dbe76315e64b9c"
SCHEMA21 = "2026-10-24.21"
FORMAT = "v21-integrity-tests-v1"
ATTEMPTS = ROOT / "integrity-v21"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
frozen_v20_checks = v20.v20_checks


def install():
    c19.require(c19.digest(v20.__file__) == V20_DRIVER_SHA256, "Frozen .20 integrity driver changed")
    v20.RUNNER20, v20.SCHEMA20 = RUNNER21, SCHEMA21
    v20.PINNED20 = {**v20.PINNED20, "src/malware_runner.py": RUNNER21}
    v20.CONFIG20 = {**v20.CONFIG20, "telemetry_schema_version": SCHEMA21, "malware_runner_sha256": RUNNER21}
    v20.FORMAT, v20.ATTEMPTS, v20.GRID_TOLERANCE = FORMAT, ATTEMPTS, timedelta(0)
    v20.v20_checks = v21_checks
    v20.install()


def v21_checks(case, sample_dir):
    result = frozen_v20_checks(case, sample_dir)
    paths = list((sample_dir / "output").glob("run_*/run.json"))
    if len(paths) == 1:
        metadata = c19.load(paths[0])
        anchor = metadata.get("sample_started_wall_us")
        exact = isinstance(anchor, int) and metadata["sample_started_at_utc"] == (EPOCH + timedelta(microseconds=anchor)).isoformat()
        result["checks"]["microsecond_anchor_recorded"] = exact
        result["sample_started_wall_us"] = anchor
        if not exact:
            result["verdict"] = "fail"
    return result


def freeze():
    install()
    v19i.check_frozen_helpers()
    run_id = c19.stamp()
    attempt = ATTEMPTS / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    cases = v19i.build_cases(hashlib.sha256(run_id.encode()).hexdigest()[:8])
    binary = v19i.compile_probe(attempt)
    payload = v19i.build_payload(cases, binary)
    guest_root = "/home/csci/Downloads/integrity-v21-" + run_id
    setup = v19i.setup_script(guest_root, payload)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    compile(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0], "setup", "exec")
    (attempt / "payload.tgz").write_bytes(payload)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in cases))
    gcc = subprocess.run(["gcc", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    protocol = {"format": FORMAT, "schema": SCHEMA21, "production_hashes": v20.PINNED20,
        "baseline_snapshot": v20.BASELINE20, "baseline_uuid": v20.BASELINE20_UUID,
        "new_snapshot": "clean-quiet-v21-integrity-" + run_id, "guest_root": guest_root, "cases": cases,
        "settings": c19.SETTINGS, "config_required": v20.CONFIG20,
        "probe": {"source_sha256": c19.digest(v19i.PROBE_SOURCE), "binary_sha256": hashlib.sha256(binary).hexdigest(),
                  "compiler": gcc, "flags": "-std=c11 -O2 -static -pthread -s"},
        "frozen_helpers": {**v19i.FROZEN_HELPERS, "integrity_tests_v19.py": v20.V19I_SHA256,
                           "quiet_rederive_v35.py": v20.QUIET_SHA256, "integrity_tests_v20.py": V20_DRIVER_SHA256},
        "driver_sha256": c19.digest(__file__),
        "files": {name: c19.digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", v19i.PROGRAM)},
        "approval": None, "retries": False, "resume": False, "replacement": False, "malware": False,
        "model_fitting": False, "merge_with_any_dataset": False,
        "criteria": {"as_v20": "event/packet/flood/leak/v20-fix verdicts as in integrity_tests_v20.py",
                     "v21": "window bounds exactly (0 us) on sample_started_wall_us + k*500000 us; recorded start string "
                            "equals the anchor; unique offline window attribution in all 15 cases"},
        "limitations": ["Benign synthetic workloads on one static amd64 mode; not malware or arbitrary-rate proof",
                        "Frame classification is by endpoint/protocol/marker, not OS-process ownership",
                        "Headless quiet guest; .21 captures stay separate from .20/.19/.18/desktop data",
                        "In-kernel syscall aggregation is not part of .21: bursts above ~1M events still lose events"]}
    c19.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": c19.digest(attempt / "protocol.json"),
                      "cases": len(cases), "vm_steps_authorized": []}, indent=2))
    return attempt


def self_test():
    install()
    c19.require(v20.v20_checks is v21_checks and v20.GRID_TOLERANCE == timedelta(0) and c19.PINNED["src/malware_runner.py"] == RUNNER21
                and c19.SCHEMA == SCHEMA21 and v20.CONFIG20["telemetry_schema_version"] == SCHEMA21, "Re-pinning failed")
    meta = {"sample_started_at_utc": (EPOCH + timedelta(microseconds=1792848528669581)).isoformat(), "window_seconds": 0.5}
    rows = [{"window_start_utc": (EPOCH + timedelta(microseconds=1792848528669581 + k * 500000)).isoformat(),
             "window_end_utc": (EPOCH + timedelta(microseconds=1792848528669581 + (k + 1) * 500000)).isoformat()} for k in range(40)]
    c19.require(v20.grid_check(meta, rows)["ok"], "Exact grid rejected")
    rows[3]["window_end_utc"] = (EPOCH + timedelta(microseconds=1792848528669581 + 4 * 500000 + 1)).isoformat()
    c19.require(not v20.grid_check(meta, rows)["ok"], "1 us off-grid bound accepted at 0 us tolerance")
    print("PASS .21 re-pinning, 0 us grid tolerance (exact accepted, 1 us rejected)")


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
        install()
        v20.execute(arguments.attempt.resolve(), arguments.protocol_sha256, arguments.approval)
    else:
        install()
        v20.validate(arguments.attempt.resolve(), arguments.protocol_sha256)


if __name__ == "__main__":
    main()
