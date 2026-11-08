"""Benign-only 5-min collection of the remaining 62 paper benign tasks (+3 null): completes the paper's 105 benign
at 5 min when combined with benign-bursty-5min. NO malware. Reuses collect_pilot's phase machinery and
collect_benign_bursty's behaviour check unchanged.

  1. collect_benign_rest.py --self-test / --freeze-only
  2. --phase preflight (read-only) -> --phase stage -> --phase dry-run -> --phase collect
  3. --validate, then --behavior-check, then the combined re-score.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_pilot as cp                       # noqa: E402
import collect_benign_bursty as cb               # noqa: E402  behaviour check (sets cp.FORMAT, overridden below)
import build_benign_rest_payload as benx         # noqa: E402

cp.FORMAT = "observation-length-benign-rest-v1"
FORMAT = cp.FORMAT
require, digest, save, stamp = cp.require, cp.digest, cp.save, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE


def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "benign-rest-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/benrest5min-" + run_id
    manifest, order = benx.build(attempt / "payload", guest_root)
    require(manifest["counts"] == {"benign": 62, "null": 3} and manifest["by_kind"] == {"short": 62, "null": 3},
            "rest payload counts out of range")
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    import subprocess
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in order))
    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-benrest5min-" + run_id, "benign_snapshot": "clean-benrest5min-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_kind": manifest["by_kind"],
        "by_mode_label": manifest["by_mode_label"], "by_project": manifest["by_project"],
        "network_benign": sum(1 for c in order if c["label"] == "benign" and c.get("network")),
        "short_tasks": manifest["short_tasks"], "fixtures_copied": manifest["fixtures_copied"],
        "expected_windows": cp.EXPECTED_WINDOWS, "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(benx.__file__)), "bursty_builder_sha256": digest(Path(cb.benx.__file__)),
        "revision5_payload_manifest_sha256": digest(benx.REV5_PAYLOAD / "payload_manifest.json"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "pairs_with": "benign-bursty-5min/20261107T071120390917Z (the other 43 short tasks + 15 sparse jobs) and the "
                      "already-collected 5-min malware (scale/topup/finish)",
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Complete the paper's 105 benign tasks at 5 min (the bursty run has 43): the whole remainder,",
                    "nothing chosen by outcome. More short-task runs per project so the benign side is 105 short +",
                    "15 sparse + the capped busy programs, 26 projects."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec;",
                     "telemetry 600x169 finite; safe archive hashes; nulls quiet; behaviour check (return code and",
                     "activity timing as designed)."],
        "limitations": [".22 bounded-memory headless-quiet dataset; never merged with .21/.20/.19 or other captures.",
                        "Short tasks are the paper's 20 s benign tasks re-run at 5 min (same programs, new runs)."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_kind": protocol["by_kind"],
                      "by_mode_label": protocol["by_mode_label"], "network_benign": protocol["network_benign"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


def self_test():
    cp.settings_tests()
    import tempfile
    from collections import Counter
    with tempfile.TemporaryDirectory(prefix="hazim-benrest-build-") as d:
        manifest, order = benx.build(Path(d) / "payload", "/home/csci/Downloads/benrest5min-TEST")
        require(manifest["counts"] == {"benign": 62, "null": 3}, "counts wrong")
        require(len(order) == len({c["sample"] for c in order}), "duplicate samples")
        require(Counter(c.get("kind", "null") for c in order) == {"short": 62, "null": 3}, "kinds wrong")
        for c in order:
            cb.expectation(c)
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "benrest5min-TEST" not in a.read_text()]
        require(not stale, "stale guest-root: " + ",".join(stale))
    cp.phase_mock_tests()
    print("PASS collect_benign_rest self-test (62 short + 3 null, expectations defined, root checks, mocks)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Benign-only 5-min collection of the remaining 62 paper benign tasks")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--phase", choices=["preflight", "preflight-benign", "stage", "dry-run", "collect"])
    p.add_argument("--validate", action="store_true")
    p.add_argument("--behavior-check", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.validate:
        cp.validate(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.behavior_check:
        cb.behavior_check(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.phase:
        cp.perform_phase(Path(a.attempt).resolve(), a.phase, a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only, --phase, --validate or --behavior-check")


if __name__ == "__main__":
    main()
