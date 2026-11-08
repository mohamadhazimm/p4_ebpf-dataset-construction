"""Quiet-v2.1: the frozen quiet-v2 multiboot driver with a NIC trace-state reader that works on VirtualBox 7.2.

Verified cause of the quiet-v2 preflight stop: VBoxManage 7.2 machine-readable `showvminfo` has format strings for
`nic%d`, `macaddress%d`, `cableconnected%d`, `nictype%d`, `nicspeed%d` but none for `nictrace%d`/`nictracefile%d`
(checked in the binary's strings). Those keys therefore never appear, on or off, so quiet-v2 could neither pass its
preflight nor confirm tracing before each boot. The only trace output is the human-readable NIC line
`... Trace: %s (file: %ls), Type: ...`.

This version imports the frozen quiet_ambient_v2.py unchanged (SHA pinned) and replaces exactly three things:
  * the helper's vm_info() for the guest gains `nictrace1`/`nictracefile1` derived from that human-readable line
    (fail closed on any format/MAC/version disagreement), so the unchanged preflight/boot/cleanup checks apply;
  * cleanup never writes back a literal `none` file: it restores the original snapshot, sets only `--nictrace1 off`
    if tracing is still on, and fails closed if the trace file setting is not the original `none`;
  * protocol format/attempt directory are new; every quiet-v2 phase, gate and approval rule is otherwise inherited.
"""

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v2 as base  # noqa: E402

frozen, network, traffic = base.frozen, base.network, base.traffic
BASE_SHA256 = "e1ca6adf2980bd3eb7c51b56e624cfed64331268846ca0cb61d95c5e1922bcc6"
FORMAT = "quiet-v2.1-multiboot-v1"
VBOX_MAJOR_MINOR = "7.2."
TRACE_LINE = re.compile(r"^NIC 1:\s+MAC: (?P<mac>[0-9A-F]{12}), Attachment: .*, Cable connected: (?:on|off), "
                        r"Trace: (?P<state>on|off) \(file: (?P<file>[^()]*)\), Type: [^,]+, Reported speed: ")
ORIGINAL_TRACE = {"nictrace1": "off", "nictracefile1": "none"}


def human_showvminfo(name):
    environment = {**os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}
    return subprocess.run(["VBoxManage", "showvminfo", name], capture_output=True, text=True, check=True,
                          timeout=60, env=environment).stdout


def parse_trace(text):
    lines = [line for line in text.splitlines() if line.startswith("NIC 1:")]
    frozen.require(len(lines) == 1, "Expected exactly one human-readable NIC 1 line")
    match = TRACE_LINE.match(lines[0])
    frozen.require(match is not None, "NIC 1 line is not in the pinned VBoxManage 7.2 format")
    return {"nictrace1": match["state"], "nictracefile1": match["file"], "mac": match["mac"]}


def with_trace(info, text):
    """Add derived trace keys to one machine-readable info dict; disagreement or missing identity fails closed."""
    derived = parse_trace(text)
    frozen.require(info.get("macaddress1", "").strip('"') == derived["mac"], "Human/machine NIC 1 MAC disagree")
    for key in ("nictrace1", "nictracefile1"):
        if key in info:  # a future VBoxManage that prints the key must agree with the human line
            frozen.require(info[key].strip('"') == derived[key], "Machine/human trace state disagree: " + key)
        info[key] = '"%s"' % derived[key]
    info["nictrace_source"] = '"human-readable NIC 1 line"'
    return info


def runtime_helper(reader=human_showvminfo):
    module = base_runtime_helper()
    version = subprocess.run(["VBoxManage", "--version"], capture_output=True, text=True, check=True,
                             timeout=30).stdout.strip()
    frozen.require(version.startswith(VBOX_MAJOR_MINOR), "Trace parser is pinned to VBoxManage 7.2: " + version)
    return wrap_module(module, reader)


def wrap_module(module, reader):
    machine = module.vm_info

    def vm_info(name):
        info = machine(name)
        return with_trace(info, reader(name)) if name == module.VM else info

    module.vm_info = vm_info  # isolated() resolves vm_info through the module globals, so it is covered too
    return module


def cleanup(module, destination, original_trace):
    frozen.require(original_trace == ORIGINAL_TRACE, "Only the measured original trace state off/none is supported")
    errors = []
    try:
        if module.vm_info(module.VM)["VMState"] != '"poweroff"':
            module.vbox("controlvm", module.VM, "poweroff")
        module.vbox("snapshot", module.VM, "restore", module.ORIGINAL)
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
    try:
        if base.trace_state(module.vm_info(module.VM))["nictrace1"] != "off":
            module.vbox("modifyvm", module.VM, "--nictrace1", "off")  # never write a literal 'none' file back
        states = frozen.state_check(module)
        frozen.require(frozen.snapshot_uuid(module, module.ORIGINAL) == base.ORIGINAL_UUID, "Cleanup snapshot UUID differs")
        frozen.require(base.trace_state(states["guest"]) == original_trace,
                       "NIC trace configuration not restored to off/none; user action required (no literal write-back)")
        frozen.save(destination / "final_vm_state.json", states)
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
    frozen.require(not errors, "Cleanup failed; user action required: " + "; ".join(errors))


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["capture_seconds"] == base.CAPTURE_SECONDS
                   and protocol["production_hashes"] == frozen.PINNED, "Protocol contract differs")
    frozen.require(frozen.digest(base.__file__) == BASE_SHA256, "Frozen quiet-v2 driver changed")
    frozen.verify_production()
    for name, checksum in protocol["source_hashes"].items():
        frozen.require(frozen.digest(name) == checksum, "Frozen source changed: " + name)
    for name, checksum in protocol["files"].items():
        frozen.require(frozen.digest(attempt / name) == checksum, "Frozen prepared artifact changed: " + name)
    return protocol


def freeze():
    frozen.require(frozen.digest(base.__file__) == BASE_SHA256, "Frozen quiet-v2 driver changed")
    frozen.verify_production()
    attempt = ROOT / "quiet-ambient-v2-1" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, base.__file__, network.__file__, traffic.__file__, base.POLICY, ROOT / "quiet_ambient.py",
                 ROOT / "capture_liveness_v4.py", ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT, "derived_from": {"driver": "quiet_ambient_v2.py", "sha256": BASE_SHA256,
                "superseded_attempt": "quiet-ambient-v2/20261024T110014475263Z",
                "change": "NIC trace state read from the human-readable NIC 1 line; no literal 'none' write-back"},
        "boot_count": base.BOOT_COUNT, "capture_seconds": base.CAPTURE_SECONDS, "production_hashes": frozen.PINNED,
        "baseline": frozen.BASELINE, "baseline_uuid": base.BASELINE_UUID, "original_uuid": base.ORIGINAL_UUID,
        "original_trace": ORIGINAL_TRACE,
        "new_snapshot": "clean-final-quiet-v19-" + attempt.name,
        "staged_snapshot": "clean-final-quiet-v19-payload-" + attempt.name,
        "guest_mac": traffic.GUEST_MAC, "control_paths": ["/hazim-final/boot/" + attempt.name + "/" + str(index)
                                                       for index in range(1, base.BOOT_COUNT + 1)],
        "source_hashes": sources, "files": files, "approval": None, "vm_steps_authorized": [],
        "collection_ready": False, "retries": False, "model_fits": 0, "merge_with_v18": False,
        "future_batch_cases": plan["cases"],
        "phases": ["preflight", "configure", "multiboot", "stage", "dry-run", "benign"],
        "criteria": ["Trace enabled (confirmed from the NIC 1 line) before power-on; stop sixty seconds after power-on",
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


base_runtime_helper = base.runtime_helper


def install():
    """Route the inherited quiet-v2 phase machinery through the v2.1 replacements."""
    frozen.require(frozen.digest(base.__file__) == BASE_SHA256, "Frozen quiet-v2 driver changed")
    base.runtime_helper, base.cleanup, base.verify_plan = runtime_helper, cleanup, verify_plan


OBSERVED_OFF = ("NIC 1:                       MAC: 001B210AEE09, Attachment: Internal Network 'malnet', "
                "Cable connected: on, Trace: off (file: none), Type: 82540EM, Reported speed: 0 Mbps, Boot priority: 0, "
                "Promisc Policy: deny, Bandwidth group: none\nNIC 2:                       disabled\n")


def self_test():
    # Parser: the actual line observed on this host, the on form, and fail-closed variants.
    frozen.require(parse_trace(OBSERVED_OFF) == {"nictrace1": "off", "nictracefile1": "none", "mac": "001B210AEE09"},
                   "Observed off line misparsed")
    on = OBSERVED_OFF.replace("Trace: off (file: none)", "Trace: on (file: /tmp/x/boot-01/boot.pcap)")
    frozen.require(parse_trace(on)["nictrace1"] == "on" and parse_trace(on)["nictracefile1"] == "/tmp/x/boot-01/boot.pcap",
                   "On line misparsed")
    for bad in ("", OBSERVED_OFF + OBSERVED_OFF, OBSERVED_OFF.replace("Trace: off", "Trace: maybe"),
                OBSERVED_OFF.replace("Trace:", "Ablaufverfolgung:"), OBSERVED_OFF.replace(", Type:", "; Type:")):
        try:
            parse_trace(bad)
            raise AssertionError("Malformed NIC line accepted")
        except ValueError:
            pass
    machine = {"VMState": '"poweroff"', "macaddress1": '"001B210AEE09"', "nic1": '"intnet"'}
    frozen.require(base.trace_state(with_trace(dict(machine), OBSERVED_OFF)) == ORIGINAL_TRACE,
                   "Unchanged quiet-v2 trace_state does not read derived keys")
    for disagreement in ({**machine, "macaddress1": '"001B210AEE10"'}, {**machine, "nictrace1": '"on"'}):
        try:
            with_trace(dict(disagreement), OBSERVED_OFF)
            raise AssertionError("Human/machine disagreement accepted")
        except ValueError:
            pass
    print("PASS trace parser: observed off/none line, on line, 5 malformed variants and 2 disagreements fail closed")

    # Wrapper + inherited preflight check + v2.1 cleanup against a simulated VM (no VBoxManage call).
    def simulated(restored_file="none", tracing_after_restore="off"):
        state = {"trace": "on", "file": "/tmp/x/boot.pcap", "vm": '"running"'}
        calls = []

        def vbox(*arguments, check=True, timeout=None):
            calls.append(arguments)
            if arguments[:2] == ("snapshot", "VM") and arguments[2] == "restore":
                state.update(trace=tracing_after_restore, file=restored_file, vm='"poweroff"')
            elif arguments[0] == "controlvm" and arguments[2] == "poweroff":
                state["vm"] = '"poweroff"'
            elif arguments[0] == "modifyvm" and arguments[2] == "--nictrace1":
                state["trace"] = arguments[3]
            return SimpleNamespace(returncode=0, stdout="")

        module = SimpleNamespace(VM="VM", ORIGINAL="clean-tls-paired-2026-10-19", vbox=vbox)
        module.vm_info = lambda name: {"VMState": state["vm"], "macaddress1": '"001B210AEE09"'}
        reader = lambda name: OBSERVED_OFF.replace("Trace: off (file: none)",
                                                   "Trace: %s (file: %s)" % (state["trace"], state["file"]))
        return wrap_module(module, reader), calls
    from unittest.mock import patch
    with tempfile.TemporaryDirectory() as directory, \
            patch.object(frozen, "state_check", side_effect=lambda module: {"guest": module.vm_info(module.VM)}), \
            patch.object(frozen, "snapshot_uuid", return_value=base.ORIGINAL_UUID):
        module, calls = simulated()
        cleanup(module, Path(directory), ORIGINAL_TRACE)
        frozen.require(("snapshot", "VM", "restore", module.ORIGINAL) in calls
                       and not any("--nictracefile1" in call for call in calls), "Cleanup wrote a trace file name")
        module, calls = simulated(tracing_after_restore="on")
        (Path(directory) / "b").mkdir()
        cleanup(module, Path(directory) / "b", ORIGINAL_TRACE)
        frozen.require(("modifyvm", "VM", "--nictrace1", "off") in calls
                       and not any("--nictracefile1" in call for call in calls), "Cleanup did not turn tracing off only")
        module, calls = simulated(restored_file="/tmp/x/boot.pcap")
        (Path(directory) / "c").mkdir()
        try:
            cleanup(module, Path(directory) / "c", ORIGINAL_TRACE)
            raise AssertionError("Unrestored trace file accepted")
        except ValueError as error:
            frozen.require("user action" in str(error) and not any("--nictracefile1" in call for call in calls),
                           "Unrestored trace file not failed closed")
    print("PASS cleanup: restore-only, trace-off-only and fail-closed unrestored file; never writes --nictracefile1")
    install()
    frozen.require(base.cleanup is cleanup and base.verify_plan is verify_plan and base.runtime_helper is runtime_helper,
                   "Inherited phase machinery not routed through v2.1")
    base.self_test()


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
