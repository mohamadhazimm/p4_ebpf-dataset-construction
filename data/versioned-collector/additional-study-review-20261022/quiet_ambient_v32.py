"""Quiet-v3.2: quiet-v3.1 with boot readiness that tolerates a slow headless boot.

Evidence (quiet-ambient-v3-1/20261024T140349202097Z): boots 1 and 2 were accepted with only the start record, three
conflict probes, three announcements, four guest/Sink ARP frames and the 12-frame HTTP control. Boot 3 never reached
guest userspace before the readiness probes gave up: in VBox.log the guest kernel driver loaded at 5.6 s (as in boot 2)
but the shared-folder module that boot 2 loaded at 12.2 s never appeared, the trace holds only the start record, and
the frozen readiness probed at about 0, 15 and 30 s. Without a desktop login the LoggedInUsers wake-up never fires, so
the probe schedule is fixed and short. This version probes Guest Control every 5 s up to 75 s after power-on and traces
each boot for 90 s instead of 60 s; every traffic rule is unchanged. A boot that is still unreachable at 75 s fails.
"""

import argparse
import inspect
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v31 as v31  # noqa: E402

v3, v23, base, frozen, traffic = v31.v3, v31.v23, v31.base, v31.frozen, v31.traffic
V31_SHA256 = "fea761098072ba28a34318227c88b6a943baf2afa32dc5ef3c62673401e438b4"
FORMAT = "quiet-v3.2-multiboot-v1"
CAPTURE_SECONDS = 90
READINESS_SECONDS = 75
PROBE_PERIOD_SECONDS = 5


def wait_boot_guest(module, auth, directory, deadline_ns):
    """Power on, then probe Guest Control with /bin/true every 5 s until it answers or the deadline passes."""
    receipt = {"events": [], "deadline_ns": deadline_ns, "status": "rejected", "probe_period_seconds": PROBE_PERIOD_SECONDS}
    try:
        response = module.vbox("startvm", module.VM, "--type", "headless", check=False, timeout=5)
        receipt["events"].append({"operation": "startvm", "returncode": response.returncode, "ended_ns": time.monotonic_ns()})
        frozen.require(response.returncode == 0, "Boot power-on failed")
        while True:
            started = time.monotonic_ns()
            remaining = (deadline_ns - started) / 1_000_000_000
            frozen.require(remaining > 0, "Guest Control did not answer within %d s of power-on" % READINESS_SECONDS)
            budget = min(PROBE_PERIOD_SECONDS, remaining)
            try:
                code = module.vbox("guestcontrol", module.VM, "run", *auth, "--exe", "/bin/true", "--wait-stdout",
                                   "--wait-stderr", "--timeout", "5000", "--", check=False, timeout=budget).returncode
            except subprocess.TimeoutExpired:
                code = None
            receipt["events"].append({"operation": "guestcontrol", "returncode": code, "ended_ns": time.monotonic_ns(),
                                      "budget_seconds": budget})
            if code == 0:
                receipt["status"] = "accepted_authenticated_probe"
                return
            pause = PROBE_PERIOD_SECONDS - (time.monotonic_ns() - started) / 1_000_000_000
            if pause > 0:
                time.sleep(min(pause, max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)))
    finally:
        frozen.save(directory / "startup-readiness.json", receipt)


def boot_once(module, protocol, destination, index, auth):
    """quiet-v2 boot_once with the readiness/control deadline at 75 s and the trace length at 90 s."""
    from quiet_ambient import Guest

    directory = destination / ("boot-%02d" % index)
    directory.mkdir()
    module.vbox("snapshot", module.VM, "restore", protocol["new_snapshot"])
    module.isolated(module.VM)
    module.vbox("modifyvm", module.VM, "--nictracefile1", str(directory / "boot.pcap"), "--nictrace1", "on")
    trace = {"enabled_before_start": base.trace_state(module.vm_info(module.VM)) == {
        "nictrace1": "on", "nictracefile1": str(directory / "boot.pcap")}}
    frozen.require(trace["enabled_before_start"], "NIC trace configuration was not confirmed")
    finished = threading.Event()
    failures = []

    def stop_trace():
        try:
            trace["stop_requested_ns"] = time.monotonic_ns()
            stopped = module.vbox("controlvm", module.VM, "nictrace1", "off", check=False)
            trace["stop_returncode"] = stopped.returncode
            trace["stop_ended_ns"] = time.monotonic_ns()
        except Exception as error:
            failures.append(type(error).__name__ + ": " + str(error))
        finally:
            finished.set()

    trace["power_requested_ns"] = time.monotonic_ns()
    timer = threading.Timer(CAPTURE_SECONDS, stop_trace)
    timer.start()
    readiness_deadline = trace["power_requested_ns"] + READINESS_SECONDS * 1_000_000_000
    try:
        wait_boot_guest(module, auth, directory, readiness_deadline)
        frozen.require(time.monotonic_ns() < readiness_deadline, "No time for bounded positive control inside boot capture")
        guest = Guest(module, destination)
        response = guest.run(auth, "/usr/bin/python3", "-c", base.control_script(protocol["control_paths"][index - 1]),
                             timeout=10)
        (directory / "control.log").write_text(response.stdout + response.stderr)
        frozen.require(response.returncode == 0, "Boot positive control failed")
        frozen.save(directory / "control.json", json.loads(response.stdout.strip()))
        frozen.require(finished.wait(timeout=CAPTURE_SECONDS), "Boot trace stop did not finish")
        frozen.require(not failures and trace.get("stop_returncode") == 0, "Trace stop failed: " + str(failures))
    finally:
        timer.cancel()
        timer.join(timeout=6)
        frozen.require(not timer.is_alive(), "Trace stop thread did not finish; cleanup required")
        frozen.save(directory / "trace.json", trace)
    module.vbox("controlvm", module.VM, "poweroff")
    module.vbox("modifyvm", module.VM, "--nictrace1", "off")
    result = base.audit_boot(directory, protocol["control_paths"][index - 1])
    frozen.save(directory / "audit.json", result)
    return result


def check_frozen():
    v31.check_frozen()
    frozen.require(frozen.digest(v31.__file__) == V31_SHA256, "Frozen quiet-v3.1 driver changed")


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["capture_seconds"] == CAPTURE_SECONDS and protocol["readiness_seconds"] == READINESS_SECONDS
                   and protocol["production_hashes"] == frozen.PINNED, "Protocol contract differs")
    check_frozen()
    frozen.verify_production()
    for name, checksum in protocol["source_hashes"].items():
        frozen.require(frozen.digest(name) == checksum, "Frozen source changed: " + name)
    for name, checksum in protocol["files"].items():
        frozen.require(frozen.digest(attempt / name) == checksum, "Frozen prepared artifact changed: " + name)
    return protocol


def _freeze():
    import ast
    frozen.verify_production()
    network = v31.network
    attempt = ROOT / "quiet-ambient-v3-2" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, v31.__file__, v3.__file__, v23.__file__, v23.v22.__file__, v23.v21.__file__, base.__file__,
                 network.__file__, traffic.__file__, v3.POLICY, base.POLICY, ROOT / "quiet_ambient.py",
                 ROOT / "capture_liveness_v4.py", ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT,
        "derived_from": {"quiet_ambient_v31.py": V31_SHA256,
                         "change": "Guest Control probed every 5 s up to 75 s; trace 90 s (was ~0/15/30 s probes, 60 s)",
                         "evidence": "quiet-ambient-v3-1/20261024T140349202097Z: boots 1-2 accepted, boot 3 stalled before userspace",
                         "superseded_attempts": ["quiet-ambient-v2/20261024T110014475263Z",
                                                 "quiet-ambient-v2-1/20261024T132922140215Z",
                                                 "quiet-ambient-v2-2/20261024T133443341773Z",
                                                 "quiet-ambient-v2-3/20261024T134126526695Z",
                                                 "quiet-ambient-v3/20261024T135729274511Z",
                                                 "quiet-ambient-v3-1/20261024T140349202097Z"]},
        "policy": {"file": "quiet_guest_v3.sh", "sha256": frozen.digest(v3.POLICY), "default_target": "multi-user.target",
                   "snapd_masked_required": sorted(v3.SNAPD_REQUIRED), "headless_required_units": v3.HEADLESS_REQUIRED},
        "boot_count": base.BOOT_COUNT, "capture_seconds": CAPTURE_SECONDS, "readiness_seconds": READINESS_SECONDS,
        "production_hashes": frozen.PINNED, "baseline": frozen.BASELINE, "baseline_uuid": base.BASELINE_UUID,
        "original_uuid": base.ORIGINAL_UUID, "original_trace": v23.v21.ORIGINAL_TRACE,
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
                       "<=3 guest announcements at 1.5-3.0 s spacing",
                       "<=3 Sink IPv6 router solicitations from the MAC answering ARP for 10.0.0.1"],
        "criteria": ["Policy receipt: quiet-v3, multi-user.target default, snapd + quiet-v2 units masked and inactive",
                     "Ten traced 90 s boots, distinct boot IDs, Guest Control reachable within 75 s; every frame is the "
                     "start record, a bounded link-up frame, guest/Sink ARP or the marked HTTP control",
                     "Every case in the later benign batch must independently pass the strict validator",
                     "Cleanup restores the original snapshot and trace off/none"],
        "limitations": ["Headless guest differs from the desktop guest used for all earlier captures; keep data separate",
                        "Hypervisor NIC tracing has no independent drop counter; not a completeness proof",
                        "Ten ninety-second boots do not exercise every later timer",
                        "The boot-3 stall cause is unknown (no guest console log); slow boots are tolerated up to 75 s",
                        "No VM phase, batch, malware, fit or merge is authorized by preparation"]}
    frozen.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": frozen.digest(attempt / "protocol.json"),
                      "vm_steps_authorized": [], "collection_ready": False}, indent=2))
    return attempt


def install():
    v31.install()
    check_frozen()
    base.CAPTURE_SECONDS = CAPTURE_SECONDS  # read at call time by the inherited audit_boot and multiboot
    base.wait_boot_guest, base.boot_once, base.verify_plan = wait_boot_guest, boot_once, verify_plan


def self_test():
    from types import SimpleNamespace
    # boot_once differs from the frozen quiet-v2 version only in its deadline/trace-length lines.
    frozen.require(base.boot_once is not boot_once, "Self-test must compare against the frozen boot_once")
    drop = lambda text: [line.strip() for line in text.replace("'", '"').splitlines()
                         if line.strip() and not line.strip().startswith(('"""', "#", "def boot_once"))]
    differing = sorted(set(drop(inspect.getsource(base.boot_once))) ^ set(drop(inspect.getsource(boot_once))))
    allowed = ("timer = threading.Timer(", "wait_boot_guest(module, auth, directory", "frozen.require(time.monotonic_ns() <",
               "readiness_deadline = ", "trace = {\"enabled_before_start\": ", "response = guest.run(auth, \"/usr/bin/python3\"",
               "timeout=10)", "\"No time for bounded positive control", "result = audit_boot(", "result = base.audit_boot(",
               "frozen.require(finished.wait(timeout=CAPTURE_SECONDS)")
    frozen.require(all(line.startswith(allowed) for line in differing), "boot_once differs unexpectedly: %r" % differing)
    print("PASS boot_once differs from frozen quiet-v2 only in deadline/trace-length/namespace lines")

    def simulated(ready_after_s, deadline_s):
        clock = {"t": 0.0}
        calls = []

        def vbox(*arguments, check=True, timeout=None):
            calls.append(arguments[0])
            clock["t"] += 0.05 if arguments[0] == "startvm" else min(timeout or 5, 1.0)
            return SimpleNamespace(returncode=0 if arguments[0] == "startvm" or clock["t"] >= ready_after_s else 1)
        module = SimpleNamespace(VM="VM", vbox=vbox)
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(time, "monotonic_ns", side_effect=lambda: int(clock["t"] * 1e9)), \
                patch.object(time, "sleep", side_effect=lambda seconds: clock.__setitem__("t", clock["t"] + seconds)):
            try:
                wait_boot_guest(module, [], Path(directory), int(deadline_s * 1e9))
                outcome = "accepted"
            except ValueError:
                outcome = "rejected"
            receipt = json.loads((Path(directory) / "startup-readiness.json").read_text())
        return outcome, receipt, calls
    outcome, receipt, calls = simulated(40.0, READINESS_SECONDS)
    frozen.require(outcome == "accepted" and receipt["status"] == "accepted_authenticated_probe"
                   and calls.count("guestcontrol") in range(8, 11), "Slow 40 s boot not accepted: %r" % (calls,))
    outcome, receipt, calls = simulated(80.0, READINESS_SECONDS)
    frozen.require(outcome == "rejected" and receipt["status"] == "rejected", "Unreachable guest accepted")
    outcome, _receipt, calls = simulated(5.0, READINESS_SECONDS)
    frozen.require(outcome == "accepted" and calls.count("guestcontrol") <= 2, "Fast boot needed too many probes")
    print("PASS readiness: 40 s boot accepted with 5 s probing, 80 s boot rejected at 75 s, fast boot in <=2 probes")
    v31.self_test()  # inherited chain at the frozen 60 s length, then installs v3.1
    install()
    frozen.require(base.CAPTURE_SECONDS == 90 and base.boot_once is boot_once and base.wait_boot_guest is wait_boot_guest
                   and v23.link_up_labels is v31.link_up_labels, "Inherited phase machinery not routed through v3.2")


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
        check_frozen()
        _freeze()
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
