"""Quiet-v3.4: quiet-v3.3 with hung boots replaced instead of failing the ten-boot check (user decision).

Evidence: quiet-ambient-v3-3/20261024T144721455938Z boots 1-5 accepted, boot 6 hung (Guest Control silent for 75 s,
trace = start record only, VBox.log stops after the initramfs vboxguest load); quiet-v3.1 boot 3 showed the same.
Saved desktop-guest batch logs show the same hang in 44 of 4,606 Guest Control waits (0.96%), always unrecovered past
45 s, which the batch handles by restarting the VM. The user chose "Replace hung boots (Recommended)".
Rule: a boot is HUNG only if Guest Control never answered within 75 s AND, after power-off, its trace holds nothing
but the VirtualBox start record (zero frames). A hung boot is recorded and replaced by a fresh boot, at most 2 per run;
a third hang, any other failure, or any boot with frames that breaks a rule stops the run as before. Ten accepted boots
with distinct boot IDs are still required. Everything else is inherited from frozen quiet_ambient_v33.py.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v33 as v33  # noqa: E402

v32, v31, v3, v23, base, frozen, traffic = v33.v32, v33.v31, v33.v3, v33.v23, v33.base, v33.frozen, v33.traffic
V33_SHA256 = "0de4d9ce66dfb869bb9e254e3e2d837d801bf0fe8e7d937e8f40ed3cc7f5f543"
FORMAT = "quiet-v3.4-multiboot-v1"
MAX_HUNG = 2
HANG_MESSAGE = "Guest Control did not answer within %d s of power-on" % v32.READINESS_SECONDS


def classify_hung(module, directory, error):
    """Return a hung-boot record, or None if this failure is anything other than a frameless readiness hang."""
    if not isinstance(error, ValueError) or str(error) != HANG_MESSAGE:
        return None
    module.vbox("controlvm", module.VM, "poweroff", check=False)  # the hung guest is still running
    module.vbox("modifyvm", module.VM, "--nictrace1", "off")
    pcap = directory / "boot.pcap"
    if not pcap.is_file():
        return None
    records = v23.trace_records(pcap.read_bytes())
    if len(records) != 1 or records[0][1] != 4 or records[0][3] != b"\0" * 4:
        return None
    readiness = frozen.load(directory / "startup-readiness.json")
    probes = [event for event in readiness["events"] if event["operation"] == "guestcontrol"]
    return {"status": "hung", "directory": directory.name, "frames": 0, "guestcontrol_probes": len(probes),
            "probe_returncodes": sorted({event["returncode"] for event in probes}, key=str),
            "pcap_sha256": frozen.digest(pcap)}


def multiboot(module, attempt, protocol, destination, auth):
    configured = frozen.load(attempt / "phases/configure/result.json")
    frozen.require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == configured["snapshot_uuid"],
                   "Quiet child UUID differs")
    results, ids, hung, position = [], set(), [], 0
    while len(results) < base.BOOT_COUNT:
        position += 1
        try:
            result = base.boot_once(module, protocol, destination, position, auth)
            frozen.require(result["boot_id"] not in ids, "Repeated boot ID; not an independent boot")
        except Exception as error:
            record = classify_hung(module, destination / ("boot-%02d" % position), error)
            if record is None or len(hung) >= MAX_HUNG:
                frozen.save(destination / "failed-prefix.json", {
                    "accepted": [{"position": index, "boot_id": row["boot_id"]} for index, row in enumerate(results, 1)],
                    "hung": hung, "failure": {"position": position, "hung": record,
                                              "technical_error": type(error).__name__ + ": " + str(error)}})
                raise
            hung.append({"position": position, **record})
            frozen.save(destination / ("hung-boot-%02d.json" % position), hung[-1])  # save() never overwrites
            continue
        ids.add(result["boot_id"])
        results.append(result)
    return {"boot_count": len(results), "boot_ids": sorted(ids), "all_boots_accepted": True, "hung_boots": hung,
            "positions_used": position, "collection_ready": False,
            "next_gate": "Separately approved installed-.19 staging, dry-run and benign batch"}


def check_frozen():
    v33.check_frozen()
    frozen.require(frozen.digest(v33.__file__) == V33_SHA256, "Frozen quiet-v3.3 driver changed")


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["max_hung_boots"] == MAX_HUNG
                   and len(protocol["control_paths"]) == base.BOOT_COUNT + MAX_HUNG
                   and protocol["capture_seconds"] == v32.CAPTURE_SECONDS
                   and protocol["readiness_seconds"] == v32.READINESS_SECONDS
                   and protocol["ipv4_wait_seconds"] == v33.IPV4_WAIT_SECONDS
                   and protocol["production_hashes"] == frozen.PINNED, "Protocol contract differs")
    check_frozen()
    frozen.verify_production()
    for name, checksum in protocol["source_hashes"].items():
        frozen.require(frozen.digest(name) == checksum, "Frozen source changed: " + name)
    for name, checksum in protocol["files"].items():
        frozen.require(frozen.digest(attempt / name) == checksum, "Frozen prepared artifact changed: " + name)
    return protocol


def freeze():
    import ast
    check_frozen()
    frozen.verify_production()
    network = v31.network
    attempt = ROOT / "quiet-ambient-v3-4" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, v33.__file__, v32.__file__, v31.__file__, v3.__file__, v23.__file__, v23.v22.__file__,
                 v23.v21.__file__, base.__file__, network.__file__, traffic.__file__, v3.POLICY, base.POLICY,
                 ROOT / "quiet_ambient.py", ROOT / "capture_liveness_v4.py", ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT,
        "derived_from": {"quiet_ambient_v33.py": V33_SHA256, "user_decision": "Replace hung boots (Recommended)",
                         "change": "frameless readiness hangs are recorded and replaced, at most 2 per run",
                         "evidence": ["quiet-ambient-v3-3/20261024T144721455938Z boots 1-5 accepted, boot 6 hung",
                                      "desktop batch logs: 44/4,606 Guest Control waits >= 158 s"],
                         "superseded_attempts": ["quiet-ambient-v2/20261024T110014475263Z",
                                                 "quiet-ambient-v2-1/20261024T132922140215Z",
                                                 "quiet-ambient-v2-2/20261024T133443341773Z",
                                                 "quiet-ambient-v2-3/20261024T134126526695Z",
                                                 "quiet-ambient-v3/20261024T135729274511Z",
                                                 "quiet-ambient-v3-1/20261024T140349202097Z",
                                                 "quiet-ambient-v3-2/20261024T141226860839Z",
                                                 "quiet-ambient-v3-3/20261024T144721455938Z"]},
        "policy": {"file": "quiet_guest_v3.sh", "sha256": frozen.digest(v3.POLICY), "default_target": "multi-user.target",
                   "snapd_masked_required": sorted(v3.SNAPD_REQUIRED), "headless_required_units": v3.HEADLESS_REQUIRED},
        "boot_count": base.BOOT_COUNT, "max_hung_boots": MAX_HUNG, "capture_seconds": v32.CAPTURE_SECONDS,
        "readiness_seconds": v32.READINESS_SECONDS, "ipv4_wait_seconds": v33.IPV4_WAIT_SECONDS,
        "production_hashes": frozen.PINNED, "baseline": frozen.BASELINE, "baseline_uuid": base.BASELINE_UUID,
        "original_uuid": base.ORIGINAL_UUID, "original_trace": v23.v21.ORIGINAL_TRACE,
        "new_snapshot": "clean-final-quiet-v19-" + attempt.name,
        "staged_snapshot": "clean-final-quiet-v19-payload-" + attempt.name,
        "guest_mac": traffic.GUEST_MAC, "control_paths": ["/hazim-final/boot/" + attempt.name + "/" + str(index)
                                                       for index in range(1, base.BOOT_COUNT + MAX_HUNG + 1)],
        "source_hashes": sources, "files": files, "approval": None, "vm_steps_authorized": [],
        "collection_ready": False, "retries": "hung boots only (frameless + Guest Control silent 75 s), max 2",
        "model_fits": 0, "merge_with_v18": False, "merge_with_desktop_v19": False, "future_batch_cases": plan["cases"],
        "phases": ["preflight", "configure", "multiboot", "stage", "dry-run", "benign"],
        "allowances": ["VirtualBox 4-byte trace start record (record 1 only)",
                       "<=3 guest IPv4 conflict probes within 1 s, before the first announcement",
                       "<=3 guest announcements at 1.5-3.0 s spacing",
                       "<=3 Sink IPv6 router solicitations from the MAC answering ARP for 10.0.0.1"],
        "criteria": ["Policy receipt: quiet-v3, multi-user.target default, snapd + quiet-v2 units masked and inactive",
                     "Ten accepted traced 90 s boots with distinct boot IDs; at most 2 frameless hung boots replaced; "
                     "every frame of every accepted boot is the start record, a bounded link-up frame, guest/Sink ARP or "
                     "the HTTP control",
                     "Every case in the later benign batch must independently pass the strict validator",
                     "Cleanup restores the original snapshot and trace off/none"],
        "limitations": ["Headless guest differs from the desktop guest used for all earlier captures; keep data separate",
                        "Hypervisor NIC tracing has no independent drop counter; not a completeness proof",
                        "Ten ninety-second boots do not exercise every later timer",
                        "Boot-hang cause unknown (about 1% of desktop boots; 2 of about 20 headless boots so far)",
                        "No VM phase, batch, malware, fit or merge is authorized by preparation"]}
    frozen.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": frozen.digest(attempt / "protocol.json"),
                      "vm_steps_authorized": [], "collection_ready": False}, indent=2))
    return attempt


def install():
    v33.install()
    check_frozen()
    base.multiboot, base.verify_plan = multiboot, verify_plan


def self_test():
    import struct
    import tempfile
    from types import SimpleNamespace
    from unittest.mock import patch
    header = (ROOT / "quiet-ambient-v3-3/20261024T144721455938Z/phases/multiboot/boot-06/boot.pcap").read_bytes()
    frozen.require(len(v23.trace_records(header)) == 1, "Saved hung-boot trace is not start-record-only")
    with_frames = (ROOT / "quiet-ambient-v3-3/20261024T144721455938Z/phases/multiboot/boot-01/boot.pcap").read_bytes()

    def run(script):
        calls = []
        module = SimpleNamespace(VM="VM", vbox=lambda *a, check=True, timeout=None: calls.append(a) or SimpleNamespace(returncode=0))
        outcomes = iter(script)
        with tempfile.TemporaryDirectory() as directory:
            attempt = Path(directory)
            (attempt / "phases/configure").mkdir(parents=True)
            frozen.save(attempt / "phases/configure/result.json", {"snapshot_uuid": "child"})

            def fake_boot(_module, _protocol, destination, position, _auth):
                kind = next(outcomes)
                folder = destination / ("boot-%02d" % position)
                folder.mkdir()
                frozen.save(folder / "startup-readiness.json", {"events": [{"operation": "guestcontrol", "returncode": 1}]})
                if kind == "ok":
                    return {"boot_id": "id-%d" % position}
                (folder / "boot.pcap").write_bytes(header if kind == "hung" else with_frames)
                raise ValueError(HANG_MESSAGE if kind in ("hung", "hung_with_frames") else "Boot positive control failed")
            with patch.object(frozen, "snapshot_uuid", return_value="child"), patch.object(base, "boot_once", side_effect=fake_boot):
                try:
                    result = multiboot(module, attempt, {"new_snapshot": "child"}, attempt, [])
                    return "accepted", result, calls
                except ValueError as error:
                    return "failed:" + str(error), json.loads((attempt / "failed-prefix.json").read_text()), calls
    outcome, result, calls = run(["ok", "hung"] + ["ok"] * 9)
    frozen.require(outcome == "accepted" and result["boot_count"] == 10 and len(result["hung_boots"]) == 1
                   and result["positions_used"] == 11 and ("controlvm", "VM", "poweroff") in calls
                   and ("modifyvm", "VM", "--nictrace1", "off") in calls, "One hung boot not replaced: %r" % (result,))
    outcome, result, _ = run(["hung", "ok", "hung"] + ["ok"] * 9)
    frozen.require(outcome == "accepted" and len(result["hung_boots"]) == 2, "Two hung boots not tolerated")
    outcome, result, _ = run(["hung", "hung", "hung"])
    frozen.require(outcome.startswith("failed") and len(result["hung"]) == 2, "Third hung boot accepted")
    outcome, result, _ = run(["ok", "hung_with_frames"])
    frozen.require(outcome.startswith("failed") and result["failure"]["hung"] is None, "Hang with frames was replaced")
    outcome, result, _ = run(["ok", "other"])
    frozen.require(outcome.startswith("failed") and result["failure"]["hung"] is None, "Non-hang failure was replaced")
    print("PASS hung-boot rule: 1 and 2 hung boots replaced, 3rd fails, hang-with-frames and other failures still fail")
    v33.self_test()
    install()
    frozen.require(base.multiboot is multiboot and base.boot_once is v33.boot_once, "Inherited machinery not routed through v3.4")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--audit-batch", action="store_true")
    action.add_argument("--phase", choices=("preflight", *base.PREDECESSOR))
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    options = parser.parse_args()
    if options.self_test:
        self_test()
        return
    if options.freeze_only:
        freeze()
        return
    install()
    frozen.require(options.attempt is not None, "Frozen attempt required")
    attempt = options.attempt.resolve()
    if options.audit_batch:
        base.audit_batch(attempt, verify_plan(attempt, options.protocol_sha256))
    else:
        base.perform_phase(attempt, options.phase, options.protocol_sha256, options.approval)


if __name__ == "__main__":
    main()
