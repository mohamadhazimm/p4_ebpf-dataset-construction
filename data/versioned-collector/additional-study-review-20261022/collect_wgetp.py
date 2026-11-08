"""Benign-only driver for the PACED-wget i386 follow-up (300 s / 600 windows): 5 paced wget variants + 3 null, NO malware.

Applies the benign-expanded lesson (curl-i386 overflowed the 4M cap; wget-i386-600k hit the post-processing deadline):
wget --wait paces the GET list so each variant stays under the cap AND stays network-active the full 300 s (no idle
tail). These are MORE variants in the existing 'wget' held-out group (not a new program); curl stays out. Scored at
analysis time against the same already-collected 5-min malware. Reuses collect_pilot's phase machinery unchanged.

  1. collect_wgetp.py --self-test / --freeze-only
  2. --phase preflight (read-only) -> --phase preflight-benign -> --phase stage -> --phase dry-run -> --phase collect
  3. --validate, then re-score the wget group with the paced variants added.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_pilot as cp                       # noqa: E402  phase machinery + .22 pins + 300 s settings
import build_wgetp_payload as benx               # noqa: E402

cp.FORMAT = "observation-length-wgetp-v1"
FORMAT = cp.FORMAT
require, digest, save, stamp = cp.require, cp.digest, cp.save, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE


def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "wgetp-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/wgetp5min-" + run_id
    manifest, order = benx.build(attempt / "payload", guest_root)
    require(manifest["counts"]["null"] == 3 and manifest["counts"].get("malware", 0) == 0
            and manifest["counts"]["benign"] == 5, "wgetp payload counts out of range")
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
        "new_snapshot": "clean-wgetp5min-" + run_id, "benign_snapshot": "clean-wgetp5min-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "by_group": manifest["by_group"],
        "network_benign": sum(1 for c in order if c["label"] == "benign" and c.get("network")),
        "benign_binaries": manifest["benign_binaries"], "expected_windows": cp.EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(benx.__file__)),
        "workloads_expanded_sha256": digest(ROOT / "benign_workloads_expanded.py"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "pairs_with_malware": "scale-5min/20261105T224558731619Z + topup-5min/20261106T073625330426Z + "
                              "topup-5min-finish/20261106T155820346732Z (already-collected 5-min malware)",
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Paced-wget i386 follow-up: 5 wget --wait variants (~0.5-10 req/s, each active ~285 s of the 300 s",
                    "window) that apply the benign-expanded overflow/deadline lesson. More variants inside the existing",
                    "'wget' held-out group (not a new program); curl stays out (curl 7.81 has no request-rate knob).",
                    "Scored at analysis with the already-collected 5-min malware on prefixes (40/120/240/360/600 win)."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow (the point of --wait);",
                     "exact target exec; telemetry 600x169 finite; safe archive hashes; nulls quiet; each paced wget",
                     "reaches the Sink across the full window (confirmed in the benign-only preflight)."],
        "limitations": [".22 bounded-memory headless-quiet dataset; never merged with .21/.20/.19 or other captures.",
                        "These are wget-group VARIANTS, not a new held-out program; the 8-program combined cohort is",
                        "unchanged in program count. curl-i386 remains unrecoverable (no request-rate knob in 7.81)."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_group": protocol["by_group"],
                      "by_mode_label": protocol["by_mode_label"], "network_benign": protocol["network_benign"],
                      "waits": [b["params"] for b in manifest["benign_binaries"].values()],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


def self_test():
    cp.settings_tests()
    import tempfile
    from collections import Counter
    with tempfile.TemporaryDirectory(prefix="hazim-wgetp-build-") as d:
        manifest, order = benx.build(Path(d) / "payload", "/home/csci/Downloads/wgetp5min-TEST")
        require(manifest["counts"]["null"] == 3 and manifest["counts"]["benign"] == 5
                and manifest["counts"].get("malware", 0) == 0, "counts wrong")
        require(len(order) == len({c["sample"] for c in order}), "duplicate samples")
        require({c["mode"] for c in order} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "unmapped mode")
        groups = Counter(c["program"] for c in order if c["label"] == "benign")
        require(set(groups) == {"wget"}, "unexpected benign group: " + str(dict(groups)))
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "wgetp5min-TEST" not in a.read_text()]
        require(not stale, "stale guest-root: " + ",".join(stale))
    cp.phase_mock_tests()
    print("PASS collect_wgetp self-test (5 paced wget + 3 null, group 'wget' only, member/root checks, mocks)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Benign-only paced-wget 5-min collection (300 s / 600 windows)")
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
