"""Quiet-v3: quiet-v2.3 with the headless + snapd-off guest policy chosen by the user.

The quiet-v2.3 ten-boot check (quiet-ambient-v2-3/20261024T134126526695Z, boot-01) found two boot-time sources the
quiet-v2 policy does not cover: snapd contacting `api.snapcraft.io` (DNS + TLS) despite `refresh --hold=forever`, and a
desktop-session WS-Discovery probe with IGMP joins. The user chose "Headless guest + snapd off". quiet_guest_v3.sh keeps
every quiet-v2 measure, masks the snapd service/socket/seeding/repair units, sets multi-user.target as the default and
fails closed unless VirtualBox Guest Additions and NetworkManager are still pulled in by multi-user.target.
Everything else (trace reader, cleanup, absence check, boot audit, bounded link-up allowances, batch validator) is
inherited unchanged from frozen quiet_ambient_v23.py.
"""

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v23 as v23  # noqa: E402

v22, v21, base, frozen, network, traffic = v23.v22, v23.v21, v23.base, v23.frozen, v23.network, v23.traffic
V23_SHA256 = "84b39069a0074a3e980a9dd3f5ba723be27243a46d770072ae76f132ab82411b"
FORMAT = "quiet-v3-multiboot-v1"
POLICY = ROOT / "quiet_guest_v3.sh"
SNAPD_REQUIRED = {"snapd.service", "snapd.socket"}
HEADLESS_REQUIRED = ["virtualbox-guest-utils.service", "NetworkManager.service"]


def check_receipt(receipt):
    frozen.require(receipt["policy"] == "quiet-v3", "Policy receipt differs")
    frozen.require(receipt["default_target"] == "multi-user.target", "Headless default target not confirmed")
    frozen.require(receipt["headless_required_units"] == HEADLESS_REQUIRED, "Headless guard units differ")
    snapd = set(receipt["snapd_masked_units"])
    frozen.require(SNAPD_REQUIRED <= snapd, "snapd service/socket not masked")
    for unit in snapd | set(receipt["masked_units"]):
        state = receipt["units"][unit]
        frozen.require(state["enabled"] == "masked" and state["active"] != "active", "Unit not masked/inactive: " + unit)
    frozen.require(all(value == "0" for value in receipt["apt_periodic_effective"].values()), "APT periodic not all zero")


def configure(module, attempt, protocol, destination, auth, password_file):
    """quiet-v2.2 configure, applying quiet_guest_v3.sh and checking its receipt; every other step is identical."""
    from quiet_ambient import Guest
    listing = module.vbox("snapshot", module.VM, "list", "--machinereadable").stdout
    frozen.require('"' + protocol["new_snapshot"] + '"' not in listing, "Quiet child already exists; no retry")
    guest = Guest(module, destination)
    guest.boot(frozen.BASELINE, "configure-boot", auth)
    guest_root = "/home/" + module.GUEST_USER + "/hazim-quiet-v3-" + attempt.name
    guest.stage_credential(auth, password_file, guest_root)
    module.vbox("guestcontrol", module.VM, "copyto", *auth, str(POLICY), guest_root + "/quiet_guest_v3.sh")
    response = guest.run(auth, "/bin/bash", "-c",
                         "sudo -S -p '' /bin/bash %s/quiet_guest_v3.sh < %s/.auth" % (guest_root, guest_root), timeout=300)
    (destination / "policy.log").write_text(response.stdout + response.stderr)
    frozen.require(response.returncode == 0, "Quiet-v3 policy failed; preserve failure, no retry")
    receipt = json.loads(response.stdout.strip().splitlines()[-1])
    check_receipt(receipt)
    frozen.save(destination / "policy-receipt.json", receipt)
    frozen.require(guest.run(auth, "/bin/rm", "-rf", "--", guest_root).returncode == 0, "Setup removal failed")
    frozen.require(v22.confirmed_absent(guest, auth, guest_root), "Setup/credential still present or absence not confirmed")
    frozen.require(guest.run(auth, "/bin/sync").returncode == 0, "Guest sync failed")
    frozen.require(guest.poweroff(graceful=True) == "graceful", "Graceful shutdown failed; no snapshot created")
    module.vbox("snapshot", module.VM, "take", protocol["new_snapshot"], "--description",
                "Quiet-v3 (headless, snapd masked) child of " + base.BASELINE_UUID + "; policy receipt "
                + frozen.digest(destination / "policy-receipt.json"))
    return {"snapshot_uuid": frozen.snapshot_uuid(module, protocol["new_snapshot"]),
            "policy_receipt_sha256": frozen.digest(destination / "policy-receipt.json")}


def check_frozen():
    v23.check_frozen()
    frozen.require(frozen.digest(v23.__file__) == V23_SHA256, "Frozen quiet-v2.3 driver changed")


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["capture_seconds"] == base.CAPTURE_SECONDS
                   and protocol["production_hashes"] == frozen.PINNED, "Protocol contract differs")
    check_frozen()
    frozen.verify_production()
    for name, checksum in protocol["source_hashes"].items():
        frozen.require(frozen.digest(name) == checksum, "Frozen source changed: " + name)
    for name, checksum in protocol["files"].items():
        frozen.require(frozen.digest(attempt / name) == checksum, "Frozen prepared artifact changed: " + name)
    return protocol


def freeze():
    check_frozen()
    frozen.verify_production()
    attempt = ROOT / "quiet-ambient-v3" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, v23.__file__, v22.__file__, v21.__file__, base.__file__, network.__file__, traffic.__file__,
                 POLICY, base.POLICY, ROOT / "quiet_ambient.py", ROOT / "capture_liveness_v4.py",
                 ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT,
        "derived_from": {"quiet_ambient_v23.py": V23_SHA256, "user_decision": "Headless guest + snapd off (Recommended)",
                         "evidence": "quiet-ambient-v2-3/20261024T134126526695Z/phases/multiboot/boot-01",
                         "superseded_attempts": ["quiet-ambient-v2/20261024T110014475263Z",
                                                 "quiet-ambient-v2-1/20261024T132922140215Z",
                                                 "quiet-ambient-v2-2/20261024T133443341773Z",
                                                 "quiet-ambient-v2-3/20261024T134126526695Z"]},
        "policy": {"file": "quiet_guest_v3.sh", "sha256": frozen.digest(POLICY), "default_target": "multi-user.target",
                   "snapd_masked_required": sorted(SNAPD_REQUIRED), "headless_required_units": HEADLESS_REQUIRED},
        "boot_count": base.BOOT_COUNT, "capture_seconds": base.CAPTURE_SECONDS, "production_hashes": frozen.PINNED,
        "baseline": frozen.BASELINE, "baseline_uuid": base.BASELINE_UUID, "original_uuid": base.ORIGINAL_UUID,
        "original_trace": v21.ORIGINAL_TRACE,
        "new_snapshot": "clean-final-quiet-v19-" + attempt.name,
        "staged_snapshot": "clean-final-quiet-v19-payload-" + attempt.name,
        "guest_mac": traffic.GUEST_MAC, "control_paths": ["/hazim-final/boot/" + attempt.name + "/" + str(index)
                                                       for index in range(1, base.BOOT_COUNT + 1)],
        "source_hashes": sources, "files": files, "approval": None, "vm_steps_authorized": [],
        "collection_ready": False, "retries": False, "model_fits": 0, "merge_with_v18": False,
        "merge_with_desktop_v19": False, "future_batch_cases": plan["cases"],
        "phases": ["preflight", "configure", "multiboot", "stage", "dry-run", "benign"],
        "allowances": ["VirtualBox 4-byte trace start record (record 1 only)",
                       "<=3 guest IPv4 conflict probes within 1 s, before the first announcement",
                       "<=3 guest announcements at 1.8-2.2 s spacing",
                       "<=3 Sink IPv6 router solicitations from the MAC answering ARP for 10.0.0.1"],
        "criteria": ["Policy receipt: quiet-v3, multi-user.target default, snapd + quiet-v2 units masked and inactive, "
                     "Guest Additions and NetworkManager pulled in by multi-user.target",
                     "Setup/credential directory absence positively confirmed by the guest before the snapshot",
                     "Ten traced 60 s boots, distinct boot IDs; every frame is the start record, a bounded link-up frame, "
                     "guest/Sink ARP or the marked HTTP control; anything else rejects",
                     "Every case in the later benign batch must independently pass the strict validator",
                     "Cleanup restores the original snapshot and trace off/none"],
        "limitations": ["Headless guest differs from the desktop guest used for all earlier captures; keep data separate",
                        "Hypervisor NIC tracing has no independent drop counter; not a completeness proof",
                        "Ten sixty-second boots do not exercise every later timer",
                        "No VM phase, batch, malware, fit or merge is authorized by preparation"]}
    frozen.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": frozen.digest(attempt / "protocol.json"),
                      "vm_steps_authorized": [], "collection_ready": False}, indent=2))
    return attempt


def install():
    v23.install()
    check_frozen()
    base.configure, base.verify_plan = configure, verify_plan


def self_test():
    import copy
    import inspect
    subprocess.run(["bash", "-n", str(POLICY)], check=True)
    policy = POLICY.read_text()
    ast.parse(policy.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    good = {"policy": "quiet-v3", "default_target": "multi-user.target", "headless_required_units": HEADLESS_REQUIRED,
            "snapd_masked_units": ["snapd.service", "snapd.socket", "snapd.seeded.service"],
            "masked_units": ["apt-daily.timer"], "apt_periodic_effective": {"APT::Periodic::Enable": "0"},
            "units": {unit: {"enabled": "masked", "active": "inactive"}
                      for unit in ("snapd.service", "snapd.socket", "snapd.seeded.service", "apt-daily.timer")}}
    check_receipt(good)
    bad_cases = {"graphical default": ("default_target", "graphical.target"),
                 "policy v2": ("policy", "quiet-v2"),
                 "snapd socket not masked": ("snapd_masked_units", ["snapd.service"]),
                 "apt periodic on": ("apt_periodic_effective", {"APT::Periodic::Enable": "1"})}
    for name, (key, value) in bad_cases.items():
        receipt = copy.deepcopy(good)
        receipt[key] = value
        try:
            check_receipt(receipt)
            raise AssertionError("Bad receipt accepted: " + name)
        except ValueError:
            pass
    active = copy.deepcopy(good)
    active["units"]["snapd.service"]["active"] = "active"
    try:
        check_receipt(active)
        raise AssertionError("Active snapd accepted")
    except ValueError:
        pass
    # configure must differ from the frozen v2.2 configure only in the policy file/name and the receipt check.
    frozen.require(base.configure is not configure, "Self-test must compare against the inherited configure")
    drop = lambda text: [line.strip() for line in text.replace("'", '"').splitlines()
                         if line.strip() and not line.strip().startswith(('"""', "#", "def configure"))]
    differing = sorted(set(drop(inspect.getsource(v22.configure))) ^ set(drop(inspect.getsource(configure))))
    allowed = ("guest_root = ", "module.vbox(\"guestcontrol\"", "\"sudo -S -p", "frozen.require(response.returncode == 0",
               "frozen.require(receipt[\"policy\"]", "check_receipt(receipt)", "\"Quiet-v2 child of", "\"Quiet-v3 (headless",
               "+ frozen.digest(destination", "frozen.require(confirmed_absent(guest, auth, guest_root)",
               "frozen.require(v22.confirmed_absent(guest, auth, guest_root)")
    frozen.require(all(line.startswith(allowed) for line in differing), "configure differs unexpectedly: %r" % differing)
    print("PASS quiet-v3 policy syntax; receipt checks (good + 5 bad); configure differs only in policy/receipt lines")
    v23.self_test()
    install()
    frozen.require(base.configure is configure and base.audit_boot is v23.audit_boot and traffic.classify is v23.classify,
                   "Inherited phase machinery not routed through v3")


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
