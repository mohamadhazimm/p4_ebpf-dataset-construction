"""Top-up driver for the full 5-min observation-length cohort.

Collects the 62 revision5 malware NOT in the 87-case scale run (disjoint by member sha, CatStorm excluded) + all 68
fixed host-active benign variants (rsync/wget/ping; openssl/sqlite dropped because they idle the host sensor) + 3 null,
each observed 5 min (600 windows). Combined with the 42 malware + 3 null already accepted in
scale-5min/20261105T224558731619Z, this completes the ~104-malware (all revision5 except CatStorm) 5-min cohort.

Reuses collect_pilot's tested phase machinery (perform_phase / validate / pilot_audit / verify_plan) unchanged; only the
payload (build_topup_payload) and the protocol FORMAT differ. Same .22 runner, 300 s settings, quiet baseline, per-phase
approval, stop-first-failure, restore-on-mutating-exit. The subprocess caps now scale with case count (collect ~20.5 h,
benign preflight ~12 h for 133/71 cases) -- the fix for the 8 h cap that stopped the scale run at 87/103. No merge with
any other dataset. collect_pilot / collect_scale are left untouched.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_pilot as cp                 # noqa: E402  phase machinery + .22 pins + 300 s settings
import build_topup_payload as topup_builder  # noqa: E402

cp.FORMAT = "observation-length-topup-v1"  # make verify_plan/perform_phase/validate accept the top-up protocol
FORMAT = cp.FORMAT
require, digest, save, stamp = cp.require, cp.digest, cp.save, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE


def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "topup-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/topup5min-" + run_id
    manifest, order = topup_builder.build(attempt / "payload", guest_root)
    require(manifest["counts"]["null"] == 3 and manifest["counts"]["malware"] >= 40
            and manifest["counts"]["benign"] >= 40, "Top-up payload counts out of range")
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
        "new_snapshot": "clean-topup5min-" + run_id, "benign_snapshot": "clean-topup5min-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "network_benign": sum(1 for c in order if c["label"] == "benign" and c.get("network")),
        "benign_binaries": manifest["benign_binaries"], "expected_windows": cp.EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(topup_builder.__file__)),
        "scale_builder_sha256": digest(ROOT / "build_scale_payload.py"),
        "workloads_sha256": digest(ROOT / "benign_workloads_long.py"),
        "malware_selection_sha256": digest(ROOT / "topup_malware_selection.json"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "reuses_prior_attempt": "scale-5min/20261105T224558731619Z (42 accepted malware + 3 null already collected)",
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Top-up to complete the full 5-min cohort: the 62 revision5 malware NOT in the scale run (disjoint,",
                    "CatStorm excluded) + all 68 fixed host-active benign (rsync/wget/ping) + 3 null. With the 42 malware",
                    "+ 3 null already accepted, the full cohort is all revision5 malware except CatStorm (~104) at 5 min,",
                    "scored on prefixes (40/120/240/360/600 windows = 20 s/1/2/3/5 min) of the same captures."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec",
                     "(malware/benign); telemetry 600x169 finite; safe archive hashes; nulls quiet for the full 5 min"],
        "limitations": [".22 (bounded-memory fail-closed) headless-quiet dataset; never merged with .21/.20/.19 or any",
                        "other captures without a compatibility analysis. CatStorm excluded (heavy flood: overflow +",
                        "multi-GB PCAP at 5 min). Benign are 3 host-active families (rsync disk I/O = amd64_dynamic,",
                        "wget network = amd64_static, ping network-light = i386_static); openssl/sqlite DROPPED (they",
                        "burn CPU silently and idle the host sensor). This gives a benign/malware MODE skew (benign",
                        "rsync-heavy amd64_dynamic vs malware amd64_static-heavy) and only 3 benign program families vs",
                        "the paper's 24 -- the price of the 5 min consistency. The primary analysis is within-run",
                        "(prefix), robust to the mode skew. Floods stay separate network-strong evidence (CIC + Kaiten).",
                        "The 42 malware + 3 null reused from scale-5min/20261105T224558731619Z are the same .22/300 s",
                        "collector/quiet baseline, so the cohort spans two attempts as the paper's 240-row set already",
                        "does."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_mode_label": protocol["by_mode_label"],
                      "network_benign": protocol["network_benign"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


def self_test():
    cp.settings_tests()
    import tempfile
    with tempfile.TemporaryDirectory(prefix="hazim-topup-build-") as d:
        manifest, order = topup_builder.build(Path(d) / "payload", "/home/csci/Downloads/topup5min-TEST")
        require(manifest["counts"]["null"] == 3 and manifest["counts"]["malware"] == 62
                and manifest["counts"]["benign"] == 68, "Top-up counts wrong")
        require(len(order) == 133 and len({c["sample"] for c in order}) == 133, "Order not 133 unique")
        require({c["mode"] for c in order} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "Unmapped mode label")
        # top-up malware are disjoint from the 42 already collected
        import glob
        scale = ROOT / "scale-5min/20261105T224558731619Z"
        sproto = json.load(open(scale / "protocol.json")); smeta = {c["sample"]: c for c in sproto["cases"]}
        done = set()
        for rj in glob.glob(str(scale / "runs/*/output/run_*/run.json")):
            sname = rj.split("/runs/")[1].split("/")[0]; sc = smeta.get(sname); rjd = json.load(open(rj))
            if sc and sc["label"] == "malware" and rjd.get("collection_quality_status") == "accepted":
                done.add(sc.get("expected_member_sha256") or sc["sample"].replace(".zip", ""))
        topup_shas = {c["expected_member_sha256"] for c in order if c["label"] == "malware"}
        require(not (topup_shas & done), "Top-up malware overlaps the 42 already collected")
        import subprocess
        for case in [c for c in order if c["label"] == "malware"][:6]:
            member = subprocess.run(["7z", "x", "-so", "-pinfected", str((Path(d) / "payload/samples" / case["sample"]))],
                                    capture_output=True).stdout
            require(__import__("hashlib").sha256(member).hexdigest() == case["expected_member_sha256"],
                    "Malware member hash differs from revision5: " + case["sample"])
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "topup5min-TEST" not in a.read_text()]
        require(not stale, "Stale guest-root in arguments: " + ",".join(stale))
    cp.phase_mock_tests()
    print("PASS collect_topup self-test (62/68/3, 133 unique, disjoint from the 42, member hashes, modes, overrides, mocks)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Top-up collection to complete the full 5-min cohort (300 s / 600 windows)")
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
