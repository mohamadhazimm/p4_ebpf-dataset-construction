"""Benign-only driver for the expanded 5-min benign cohort (300 s / 600 windows).

Collects ~45 expanded benign variants (benign_workloads_expanded: hostgen/lowrate/top/vmstat/free/find/sort/wget/curl)
+ 3 null -- NO malware. The ~100 malware are already collected (scale+topup+finish) on the same .22/300 s/quiet
baseline and are paired with this benign at analysis time (family/program-held-out 70/30; rsync trimmed to ~10). This
fixes the 3-benign-program collapse (now 11 held-out groups, network-active + i386 coverage).

Reuses collect_pilot's tested phase machinery (perform_phase / validate / pilot_audit / verify_plan) unchanged; only the
payload (build_benign_expanded_payload) and the protocol FORMAT differ. Same .22 runner, 300 s settings, quiet baseline,
per-phase approval, stop-first-failure, restore-on-mutating-exit. No merge with any other dataset. collect_pilot /
collect_scale / collect_topup are left untouched.

SEQUENCE (heavy steps AFTER the malware collect frees the disk):
  1. benign_workloads_expanded.py --verify   (size find/sort to ~320 s; confirm lowrate under the 4 M cap)
  2. collect_benign_expanded.py --freeze-only (builds full fixtures + freezes the attempt)
  3. --phase preflight (read-only) -> --phase preflight-benign (all cases; confirms Sink-answered traffic, no overflow)
     -> --phase stage -> --phase dry-run -> --phase collect        (each needs its own --approval)
  4. --validate, then the combined held-out analysis with the existing malware.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_pilot as cp                       # noqa: E402  phase machinery + .22 pins + 300 s settings
import build_benign_expanded_payload as benx     # noqa: E402

cp.FORMAT = "observation-length-benign-expanded-v1"   # make verify_plan/perform_phase/validate accept this protocol
FORMAT = cp.FORMAT
require, digest, save, stamp = cp.require, cp.digest, cp.save, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE


def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "benign-expanded-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/benx5min-" + run_id
    manifest, order = benx.build(attempt / "payload", guest_root)
    require(manifest["counts"]["null"] == 3 and manifest["counts"].get("malware", 0) == 0
            and manifest["counts"]["benign"] >= 30, "Benign-expanded payload counts out of range")
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    import subprocess
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in order))  # every case is benign/null

    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-benx5min-" + run_id, "benign_snapshot": "clean-benx5min-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "by_group": manifest["by_group"],
        "network_benign": sum(1 for c in order if c["label"] == "benign" and c.get("network")),
        "benign_binaries": manifest["benign_binaries"], "expected_windows": cp.EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(benx.__file__)),
        "workloads_sha256": digest(ROOT / "benign_workloads_expanded.py"),
        "hostgen_src_sha256": digest(ROOT / "benign_host_gen.c"),
        "hostgen_bin_sha256": digest(STUDY / benx.be.BIN["hostgen"][1]),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "pairs_with_malware": "scale-5min/20261105T224558731619Z + topup-5min/20261106T073625330426Z + "
                              "topup-5min-finish/20261106T155820346732Z (already-collected 5-min malware)",
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Benign-only 5-min run adding 8 new benign groups (procps top/vmstat/free, findutils find, coreutils",
                    "sort, i386 wget/curl, host generator, network generator) to fix the 3-benign-program held-out",
                    "collapse. Paired at analysis with the already-collected ~100 5-min malware; scored on prefixes",
                    "(40/120/240/360/600 windows = 20 s/1/2/3/5 min) of the same captures."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec;",
                     "telemetry 600x169 finite; safe archive hashes; nulls quiet for the full 5 min; network benign",
                     "reach the Sink (confirmed in the benign-only preflight)."],
        "limitations": [".22 bounded-memory headless-quiet dataset; never merged with .21/.20/.19 or other captures",
                        "without a compatibility analysis. hostgen and lowrate are ONE self-written binary each (5",
                        "modes = variants, one held-out group each), not independent programs. find/sort fixture sizes",
                        "set by --verify. amd64_dynamic benign stays rsync-only (already collected); this run is",
                        "amd64_static + i386_static to match the malware mode mix."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_group": protocol["by_group"],
                      "by_mode_label": protocol["by_mode_label"], "network_benign": protocol["network_benign"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


def self_test():
    cp.settings_tests()
    import tempfile
    from collections import Counter
    # tiny, distinct-under-naming grid so no heavy fixtures are built
    benx.be.FIND_COUNTS[:] = [1000, 2000]
    benx.be.SORT_MBS[:] = [1, 2]
    benx.be.WGET_URLS[:] = [1000, 2000]
    benx.be.CURL_URLS[:] = [1000, 2000]
    benx.be.TOP_DELAYS[:] = [1, 2]
    benx.be.VMSTAT_DELAYS[:] = [1, 2]
    benx.be.FREE_DELAYS[:] = [1, 2]
    benx.be.GEN_TREE_FILES = 20
    with tempfile.TemporaryDirectory(prefix="hazim-benx-build-") as d:
        manifest, order = benx.build(Path(d) / "payload", "/home/csci/Downloads/benx5min-TEST")
        require(manifest["counts"]["null"] == 3 and manifest["counts"].get("malware", 0) == 0, "counts wrong")
        require(len(order) == len({c["sample"] for c in order}), "duplicate samples")
        require({c["mode"] for c in order} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "unmapped mode")
        groups = Counter(c["program"] for c in order if c["label"] == "benign")
        require(set(groups) >= {"hostgen", "lowrate", "top", "vmstat", "free", "wget", "curl"},
                "missing a benign group: " + str(dict(groups)))
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "benx5min-TEST" not in a.read_text()]
        require(not stale, "stale guest-root: " + ",".join(stale))
    cp.phase_mock_tests()
    print("PASS collect_benign_expanded self-test (benign+null only, 9 groups present, no malware, member/root checks, mocks)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Benign-only expanded 5-min collection (300 s / 600 windows)")
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
