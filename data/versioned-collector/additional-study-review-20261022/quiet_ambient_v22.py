"""Quiet-v2.2: quiet-v2.1 plus a guest-absence check that does not depend on VBoxManage exit-code mapping.

Cause of the quiet-v2.1 configure stop (attempt quiet-ambient-v2-1/20261024T132922140215Z): after deleting the setup
directory, quiet-v2 required `VBoxManage guestcontrol run /usr/bin/test -e DIR` to return exactly 1. VBoxManage does
not pass a guest process's nonzero exit status through: its `run` exit table reports a normal nonzero guest exit as
16 and a signal as 18 (a saved SIGSEGV probe in cohort-100x100-v18-20261021/.../compatible-static came back as 18),
while VBoxManage's own failures return 1. So `== 1` rejects a correctly deleted directory, and the quiet-v1 form
`!= 0` would also accept a Guest Control failure. The replacement asks the guest `test ! -e DIR` and requires 0, which
is only returned when the guest process ran and confirmed the path is absent.

Everything else is inherited unchanged from frozen quiet_ambient_v21.py (which itself wraps frozen quiet_ambient_v2.py).
"""

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v21 as v21  # noqa: E402

base, frozen, network, traffic = v21.base, v21.frozen, v21.network, v21.traffic
V21_SHA256 = "5e5c379cc41f5e5be121e05d5f51a65c313044b8809a84f94a86ff1cacbf4390"
FORMAT = "quiet-v2.2-multiboot-v1"


def confirmed_absent(guest, auth, path):
    """True only if the guest process ran and `test ! -e PATH` exited 0."""
    return guest.run(auth, "/usr/bin/test", "!", "-e", path).returncode == 0


def configure(module, attempt, protocol, destination, auth, password_file):
    """quiet_ambient_v2.configure with the absence check replaced; every other step is identical."""
    from quiet_ambient import Guest
    listing = module.vbox("snapshot", module.VM, "list", "--machinereadable").stdout
    frozen.require('"' + protocol["new_snapshot"] + '"' not in listing, "Quiet child already exists; no retry")
    guest = Guest(module, destination)
    guest.boot(frozen.BASELINE, "configure-boot", auth)
    guest_root = "/home/" + module.GUEST_USER + "/hazim-quiet-v2-" + attempt.name
    guest.stage_credential(auth, password_file, guest_root)
    module.vbox("guestcontrol", module.VM, "copyto", *auth, str(base.POLICY), guest_root + "/quiet_guest_v2.sh")
    response = guest.run(auth, "/bin/bash", "-c",
                         "sudo -S -p '' /bin/bash %s/quiet_guest_v2.sh < %s/.auth" % (guest_root, guest_root), timeout=300)
    (destination / "policy.log").write_text(response.stdout + response.stderr)
    frozen.require(response.returncode == 0, "Quiet-v2 policy failed; preserve failure, no retry")
    receipt = json.loads(response.stdout.strip().splitlines()[-1])
    frozen.require(receipt["policy"] == "quiet-v2", "Policy receipt differs")
    frozen.save(destination / "policy-receipt.json", receipt)
    frozen.require(guest.run(auth, "/bin/rm", "-rf", "--", guest_root).returncode == 0, "Setup removal failed")
    frozen.require(confirmed_absent(guest, auth, guest_root), "Setup/credential still present or absence not confirmed")
    frozen.require(guest.run(auth, "/bin/sync").returncode == 0, "Guest sync failed")
    frozen.require(guest.poweroff(graceful=True) == "graceful", "Graceful shutdown failed; no snapshot created")
    module.vbox("snapshot", module.VM, "take", protocol["new_snapshot"], "--description",
                "Quiet-v2 child of " + base.BASELINE_UUID + "; policy receipt " + frozen.digest(destination / "policy-receipt.json"))
    return {"snapshot_uuid": frozen.snapshot_uuid(module, protocol["new_snapshot"]),
            "policy_receipt_sha256": frozen.digest(destination / "policy-receipt.json")}


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["capture_seconds"] == base.CAPTURE_SECONDS
                   and protocol["production_hashes"] == frozen.PINNED, "Protocol contract differs")
    frozen.require(frozen.digest(base.__file__) == v21.BASE_SHA256 and frozen.digest(v21.__file__) == V21_SHA256,
                   "Frozen quiet-v2 or quiet-v2.1 driver changed")
    frozen.verify_production()
    for name, checksum in protocol["source_hashes"].items():
        frozen.require(frozen.digest(name) == checksum, "Frozen source changed: " + name)
    for name, checksum in protocol["files"].items():
        frozen.require(frozen.digest(attempt / name) == checksum, "Frozen prepared artifact changed: " + name)
    return protocol


def freeze():
    frozen.require(frozen.digest(base.__file__) == v21.BASE_SHA256 and frozen.digest(v21.__file__) == V21_SHA256,
                   "Frozen quiet-v2 or quiet-v2.1 driver changed")
    frozen.verify_production()
    attempt = ROOT / "quiet-ambient-v2-2" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, v21.__file__, base.__file__, network.__file__, traffic.__file__, base.POLICY,
                 ROOT / "quiet_ambient.py", ROOT / "capture_liveness_v4.py", ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT,
        "derived_from": {"quiet_ambient_v21.py": V21_SHA256, "quiet_ambient_v2.py": v21.BASE_SHA256,
                         "superseded_attempts": ["quiet-ambient-v2/20261024T110014475263Z",
                                                 "quiet-ambient-v2-1/20261024T132922140215Z"],
                         "change": "absence check `test ! -e DIR` == 0 instead of `test -e DIR` == 1"},
        "boot_count": base.BOOT_COUNT, "capture_seconds": base.CAPTURE_SECONDS, "production_hashes": frozen.PINNED,
        "baseline": frozen.BASELINE, "baseline_uuid": base.BASELINE_UUID, "original_uuid": base.ORIGINAL_UUID,
        "original_trace": v21.ORIGINAL_TRACE,
        "new_snapshot": "clean-final-quiet-v19-" + attempt.name,
        "staged_snapshot": "clean-final-quiet-v19-payload-" + attempt.name,
        "guest_mac": traffic.GUEST_MAC, "control_paths": ["/hazim-final/boot/" + attempt.name + "/" + str(index)
                                                       for index in range(1, base.BOOT_COUNT + 1)],
        "source_hashes": sources, "files": files, "approval": None, "vm_steps_authorized": [],
        "collection_ready": False, "retries": False, "model_fits": 0, "merge_with_v18": False,
        "future_batch_cases": plan["cases"],
        "phases": ["preflight", "configure", "multiboot", "stage", "dry-run", "benign"],
        "criteria": ["Setup/credential directory absence positively confirmed by the guest before the snapshot",
                     "Trace enabled (confirmed from the NIC 1 line) before power-on; stop sixty seconds after power-on",
                     "Ten distinct boot IDs, each restored from the same policy child",
                     "One bounded numeric-Sink HTTP200 control per boot; exact saved response equals PCAP",
                     "All boot frames classified by strict allowlist; unexplained frames reject",
                     "Every case in the later benign batch must independently pass the strict validator",
                     "Cleanup restores the original snapshot and trace off/none without writing a literal file name"],
        "limitations": ["Hypervisor NIC tracing has no independent drop counter; not a completeness proof",
                        "Ten sixty-second boots do not exercise every later timer",
                        "Network controls repeat one diagnostic source; no independent software diversity claim",
                        "No VM phase, batch, malware, fit or merge is authorized by preparation"]}
    frozen.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": frozen.digest(attempt / "protocol.json"),
                      "vm_steps_authorized": [], "collection_ready": False}, indent=2))
    return attempt


def install():
    v21.install()
    frozen.require(frozen.digest(v21.__file__) == V21_SHA256, "Frozen quiet-v2.1 driver changed")
    base.configure, base.verify_plan = configure, verify_plan


def self_test():
    # The absence check against VBoxManage's real exit-code behaviour: 0 = guest confirmed absent; 16 = guest test
    # exited nonzero (path present); 1 = VBoxManage itself failed. Only 0 may count as absent.
    for code, expected in ((0, True), (16, False), (1, False), (18, False)):
        guest = SimpleNamespace(run=lambda auth, *command, code=code: SimpleNamespace(returncode=code, command=command))
        frozen.require(confirmed_absent(guest, [], "/home/csci/x") is expected, "Absence mapping wrong for %d" % code)
    seen = []
    guest = SimpleNamespace(run=lambda auth, *command: seen.append(command) or SimpleNamespace(returncode=0))
    confirmed_absent(guest, [], "/home/csci/x")
    frozen.require(seen == [("/usr/bin/test", "!", "-e", "/home/csci/x")], "Absence command differs")
    # The replacement must differ from the frozen configure only in that check.
    import inspect
    frozen.require(base.configure is not configure, "Self-test must compare against the frozen configure")
    original = inspect.getsource(base.configure).replace("'", '"')
    replaced = inspect.getsource(configure).replace("'", '"')
    drop = lambda text: [line.strip() for line in text.splitlines()
                         if line.strip() and not line.strip().startswith(('"""', "#", "def configure"))]
    differing = sorted(set(drop(original)) ^ set(drop(replaced)))
    frozen.require(differing == sorted([
        'frozen.require(guest.run(auth, "/usr/bin/test", "-e", guest_root).returncode == 1, "Setup/credential still present")',
        'frozen.require(confirmed_absent(guest, auth, guest_root), "Setup/credential still present or absence not confirmed")',
        'module.vbox("guestcontrol", module.VM, "copyto", *auth, str(POLICY), guest_root + "/quiet_guest_v2.sh")',
        'module.vbox("guestcontrol", module.VM, "copyto", *auth, str(base.POLICY), guest_root + "/quiet_guest_v2.sh")',
        '"Quiet-v2 child of " + BASELINE_UUID + "; policy receipt " + frozen.digest(destination / "policy-receipt.json"))',
        '"Quiet-v2 child of " + base.BASELINE_UUID + "; policy receipt " + frozen.digest(destination / "policy-receipt.json"))']),
        "configure differs from frozen quiet-v2 beyond the absence check: %r" % differing)
    print("PASS absence check: 0 only confirms absence (16/1/18 fail closed); configure differs only in that check")
    v21.self_test()
    install()
    frozen.require(base.configure is configure and base.verify_plan is verify_plan and base.cleanup is v21.cleanup,
                   "Inherited phase machinery not routed through v2.2")


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
