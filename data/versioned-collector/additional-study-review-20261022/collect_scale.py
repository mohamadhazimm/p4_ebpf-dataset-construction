"""Scaled observation-length cohort driver: ~50 malware + ~50 long benign + 3 null, each observed 5 min (600 windows).

Scale-up of the 10-case pilot (which showed malware do 70-93% of their behaviour, and >90% of their network, after the
20 s mark). Reuses the pilot driver's tested phase machinery (collect_pilot.perform_phase / validate / pilot_audit /
verify_plan) unchanged; only the payload (build_scale_payload) and the protocol FORMAT differ. Same .22 runner, 300 s
settings, quiet baseline, per-phase approval, stop-first-failure, restore-on-mutating-exit. No merge with any other
dataset. collect_pilot is left untouched.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_pilot as cp                 # noqa: E402  phase machinery + .22 pins + 300 s settings
import build_scale_payload as scale_builder  # noqa: E402

cp.FORMAT = "observation-length-scale-v1"  # make verify_plan/perform_phase/validate accept the scaled protocol
FORMAT = cp.FORMAT
require, digest, save, stamp = cp.require, cp.digest, cp.save, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE


def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "scale-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/scale5min-" + run_id
    manifest, order = scale_builder.build(attempt / "payload", guest_root)
    require(manifest["counts"]["null"] == 3 and manifest["counts"]["malware"] >= 40
            and manifest["counts"]["benign"] >= 40, "Scaled payload counts out of range")
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    import subprocess
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    benign_list = [c for c in order if c["label"] in ("benign", "null")]
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in benign_list))

    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-scale5min-" + run_id, "benign_snapshot": "clean-scale5min-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "network_benign": sum(1 for c in order if c["label"] == "benign" and c.get("network")),
        "benign_binaries": manifest["benign_binaries"], "expected_windows": cp.EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(scale_builder.__file__)),
        "workloads_sha256": digest(ROOT / "benign_workloads_long.py"),
        "malware_selection_sha256": digest(ROOT / "scale_malware_selection.json"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Scaled observation-length cohort: does the host/network/hybrid signal grow from 20 s to 5 min across",
                    "~50 diverse malware (27 families) and ~50 sustained benign? Scored on prefixes (40/120/240/360/600",
                    "windows) of the same captures. Follows the 10-case pilot where malware did 70-93% of host activity",
                    "and >90% of network after the 20 s mark."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec",
                     "(malware/benign); telemetry 600x169 finite; safe archive hashes; nulls quiet for the full 5 min"],
        "limitations": [".22 (bounded-memory fail-closed) headless-quiet dataset; never merged with .21/.20/.19 or any",
                        "other captures without a compatibility analysis. CatStorm/Chaos excluded (overflow at 5 min).",
                        "Benign are variants of 5 validated long workloads (rsync/wget/ping/openssl/sqlite), weighted to",
                        "the host/network-busy ones; they are not 50 distinct programs. Mode mix differs across labels",
                        "(benign rsync-heavy = amd64_dynamic); the primary analysis is within-run (prefix), robust to",
                        "that. Feasibility/observation-length probe, not a detector-training cohort."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_mode_label": protocol["by_mode_label"],
                      "network_benign": protocol["network_benign"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


def self_test():
    # Reuse the pilot driver's override + phase-mock checks, plus a scaled build.
    cp.settings_tests()
    import tempfile
    with tempfile.TemporaryDirectory(prefix="hazim-scale-build-") as d:
        manifest, order = scale_builder.build(Path(d) / "payload", "/home/csci/Downloads/scale5min-TEST")
        require(manifest["counts"]["null"] == 3 and manifest["counts"]["malware"] == 50
                and manifest["counts"]["benign"] == 50, "Scaled counts wrong")
        require(len(order) == 103 and len({c["sample"] for c in order}) == 103, "Order not 103 unique")
        require({c["mode"] for c in order} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "Unmapped mode label")
        import subprocess
        for case in [c for c in order if c["label"] == "malware"][:6]:
            member = subprocess.run(["7z", "x", "-so", "-pinfected", str((Path(d) / "payload/samples" / case["sample"]))],
                                    capture_output=True).stdout
            require(__import__("hashlib").sha256(member).hexdigest() == case["expected_member_sha256"],
                    "Malware member hash differs from revision5: " + case["sample"])
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "scale5min-TEST" not in a.read_text()]
        require(not stale, "Stale guest-root in arguments: " + ",".join(stale))
    cp.phase_mock_tests()  # note: this patches cp internals; FORMAT is irrelevant there (verify_plan is mocked)
    print("PASS collect_scale self-test (counts 50/50/3, member hashes, modes, overrides, phase mocks)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Scaled observation-length cohort (5 min / 600 windows)")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--phase", choices=["preflight", "preflight-benign", "stage", "dry-run", "collect"])
    p.add_argument("--validate", action="store_true")
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
    elif a.phase:
        cp.perform_phase(Path(a.attempt).resolve(), a.phase, a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only, --phase, or --validate")


if __name__ == "__main__":
    main()
