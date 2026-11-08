"""Finish driver: collect ONLY the 47 top-up cases the interrupted run never reached.

The top-up attempt topup-5min/20261106T073625330426Z was interrupted by a session end at 86/133 runs
(42 malware + 41 benign + 3 null; 38 malware + 41 benign + 3 null accepted). Its frozen protocol is
resume:False, so this completes it WITHOUT retrying anything already attempted: it collects exactly the
47 never-attempted cases (20 malware + 27 benign; the 3 null were in the first 86 and are not re-run).

It builds the SAME verified 133-case payload as the top-up (build_topup_payload, so every transport is
byte-identical and the malware member hashes are the already-verified revision5 members), then restricts
the RUN SET -- attempt/cases.txt, benign-null.txt and protocol["cases"] -- to the 47 uncollected samples
(by name, read from the top-up attempt's runs/). Staging the full payload is harmless (the batch runs only
the listed 47). Everything else -- .22 runner, 300 s settings, quiet baseline, per-phase approval,
stop-first-failure, restore-on-mutating-exit, the collect_pilot phase machinery -- is unchanged.

Combined cohort after this run: 42 malware + 3 null (scale-5min/20261105T224558731619Z) + 38 accepted
malware + 41 benign (topup-5min/20261106T073625330426Z) + up to 20 malware + 27 benign here = all 104
revision5 malware except CatStorm, at 5 min, plus the 68 fixed host-active benign and 3 null. No merge
with any other dataset. collect_topup / collect_pilot / collect_scale are left untouched.
"""

import glob
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_topup as ct              # noqa: E402  imports collect_pilot(as cp) + build_topup_payload; sets cp.FORMAT
cp = ct.cp
topup_builder = ct.topup_builder

cp.FORMAT = "observation-length-topup-finish-v1"  # override so verify_plan/perform_phase/validate accept this protocol
FORMAT = cp.FORMAT
require, digest, save, stamp = cp.require, cp.digest, cp.save, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE

TOPUP_ATTEMPT = ROOT / "topup-5min" / "20261106T073625330426Z"
SCALE_ATTEMPT = ROOT / "scale-5min" / "20261105T224558731619Z"


def collected_names(attempt):
    """Sample names that already have a run.json in the given attempt (attempted; never retried here)."""
    done = set()
    for p in glob.glob(str(attempt / "runs" / "*" / "output" / "run_*" / "run.json")):
        done.add(p.split("/runs/")[1].split("/")[0])
    return done


def accepted_malware_shas(attempt):
    """expected_member_sha256 of malware runs accepted in the given attempt (for disjointness checks)."""
    proto = json.load((attempt / "protocol.json").open())
    meta = {c["sample"]: c for c in proto["cases"]}
    shas = set()
    for p in glob.glob(str(attempt / "runs" / "*" / "output" / "run_*" / "run.json")):
        name = p.split("/runs/")[1].split("/")[0]
        case = meta.get(name)
        rj = json.load(open(p))
        if case and case["label"] == "malware" and rj.get("collection_quality_status") == "accepted":
            shas.add(case.get("expected_member_sha256") or name.replace(".zip", ""))
    return shas


def _restrict(attempt_payload_dir, guest_root):
    """Build the full 133-case payload, then return (order, finish, counts, by_mode_label) where finish is the
    47 never-attempted cases from the top-up run."""
    done = collected_names(TOPUP_ATTEMPT)
    require(len(done) == 86, "Top-up attempt does not have the expected 86 collected runs (got %d)" % len(done))
    manifest, order = topup_builder.build(attempt_payload_dir, guest_root)   # verbatim top-up transports
    all_names = {c["sample"] for c in order}
    require(done <= all_names, "Collected names are not a subset of the built payload")
    finish = [c for c in order if c["sample"] not in done]
    for i, c in enumerate(finish, 1):
        c["position"] = i
    counts = dict(Counter(c["label"] for c in finish))
    require(len(finish) == 47 and counts.get("malware") == 20 and counts.get("benign") == 27
            and counts.get("null", 0) == 0, "Finish set is not 20 malware + 27 benign + 0 null (got %r)" % counts)
    by_mode_label = {str(k): v for k, v in sorted(Counter((c["mode"], c["label"]) for c in finish).items())}
    return manifest, order, finish, counts, by_mode_label


def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "topup-5min-finish" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/topupfinish5min-" + run_id
    manifest, order, finish, counts, by_mode_label = _restrict(attempt / "payload", guest_root)

    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    import subprocess
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in finish))
    benign_list = [c for c in finish if c["label"] in ("benign", "null")]
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in benign_list))

    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-topupfinish-" + run_id, "benign_snapshot": "clean-topupfinish-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": finish, "counts": counts, "by_mode_label": by_mode_label,
        "network_benign": sum(1 for c in finish if c["label"] == "benign" and c.get("network")),
        "benign_binaries": manifest["benign_binaries"], "expected_windows": cp.EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(topup_builder.__file__)),
        "scale_builder_sha256": digest(ROOT / "build_scale_payload.py"),
        "workloads_sha256": digest(ROOT / "benign_workloads_long.py"),
        "malware_selection_sha256": digest(ROOT / "topup_malware_selection.json"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "finishes_attempt": "topup-5min/20261106T073625330426Z",
        "collected_in_topup": sorted(collected_names(TOPUP_ATTEMPT)),
        "reuses_prior_attempts": ["scale-5min/20261105T224558731619Z (42 accepted malware + 3 null)",
                                  "topup-5min/20261106T073625330426Z (38 accepted malware + 41 benign + 3 null; 86/133 reached)"],
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Finish the top-up: collect ONLY the 47 cases (20 malware + 27 benign) the interrupted run never",
                    "reached. No retry of anything already attempted (resume:False on the top-up means the never-run tail",
                    "is a fresh, disjoint set). Same .22 runner / 300 s / quiet baseline. With scale + top-up this gives",
                    "the full ~104-malware (all revision5 except CatStorm) + 68 benign + 3 null 5-min cohort, scored on",
                    "prefixes (40/120/240/360/600 windows = 20 s/1/2/3/5 min) of the same captures."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec",
                     "(malware/benign); telemetry 600x169 finite; safe archive hashes"],
        "limitations": [".22 (bounded-memory fail-closed) headless-quiet dataset; never merged with .21/.20/.19 or any",
                        "other captures without a compatibility analysis. The full payload (133) is staged but only the",
                        "47 uncollected cases are run (same verified transports as the top-up). CatStorm excluded. Benign",
                        "are the 3 host-active families (rsync/wget/ping); the 27 benign here are the uncollected tail of",
                        "those 68 variants. The cohort spans three attempts (scale + top-up + this finish), all the same",
                        ".22/300 s collector + quiet baseline, as the paper's 240-row set already spans attempts. Floods",
                        "stay separate network-strong evidence (CIC + Kaiten)."]}
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
    with tempfile.TemporaryDirectory(prefix="hazim-topupfinish-build-") as d:
        manifest, order, finish, counts, by_mode_label = _restrict(Path(d) / "payload",
                                                                    "/home/csci/Downloads/topupfinish5min-TEST")
        require(len(order) == 133 and len({c["sample"] for c in order}) == 133, "Full build not 133 unique")
        require(len(finish) == 47 and len({c["sample"] for c in finish}) == 47, "Finish not 47 unique")
        require(counts == {"malware": 20, "benign": 27}, "Finish counts wrong: %r" % counts)
        require({c["mode"] for c in finish} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "Unmapped mode label")
        # the 20 finish malware are disjoint from everything already attempted (scale 42 + topup 42)
        finish_shas = {c["expected_member_sha256"] for c in finish if c["label"] == "malware"}
        prior = accepted_malware_shas(SCALE_ATTEMPT) | accepted_malware_shas(TOPUP_ATTEMPT)
        require(not (finish_shas & prior), "Finish malware overlaps already-accepted malware")
        # finish samples are exactly the top-up cases with no run.json
        done = collected_names(TOPUP_ATTEMPT)
        require(not ({c["sample"] for c in finish} & done), "Finish set overlaps collected top-up runs")
        # member hashes of the finish malware match the frozen revision5 members
        import subprocess
        for case in [c for c in finish if c["label"] == "malware"][:6]:
            member = subprocess.run(["7z", "x", "-so", "-pinfected", str((Path(d) / "payload/samples" / case["sample"]))],
                                    capture_output=True).stdout
            require(__import__("hashlib").sha256(member).hexdigest() == case["expected_member_sha256"],
                    "Malware member hash differs from revision5: " + case["sample"])
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "topupfinish5min-TEST" not in a.read_text()]
        require(not stale, "Stale guest-root in arguments: " + ",".join(stale))
    cp.phase_mock_tests()
    print("PASS collect_topup_finish self-test (47 = 20 malware + 27 benign, disjoint from scale+topup, "
          "member hashes, modes, overrides, mocks)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Finish the top-up: collect the 47 uncollected cases (300 s / 600 windows)")
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
