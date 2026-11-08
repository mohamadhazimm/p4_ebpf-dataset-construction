"""Quiet-v3.3: quiet-v3.2 with a guest-side IPv4 readiness wait before each boot's HTTP control.

Evidence (quiet-ambient-v3-2/20261024T141226860839Z): boots 1-9 were accepted (only the start record, conflict probes,
announcements, guest/Sink ARP, the HTTP control and once a Sink router solicitation; nine distinct boot IDs). In boot 10
Guest Control answered at 16.1 s, during NetworkManager's RFC 5227 conflict probing (16.15-16.25 s); the control started
at 16.2 s, its ARP request and first SYN left with source address 0.0.0.0, the retransmissions from 10.0.0.10 went
unanswered within the control's 3 s connect timeout, and the boot failed "Boot positive control failed". This is a
Guest-Control-before-IPv4 race, not background traffic. Before the control, this version runs a guest command that
polls `ip -4 -j addr show dev enp0s3` (netlink only; no packets) until 10.0.0.10 is configured, up to 25 s, and records
the wait. Everything else is inherited from frozen quiet_ambient_v32.py.
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
import quiet_ambient_v32 as v32  # noqa: E402

v31, v3, v23, base, frozen, traffic = v32.v31, v32.v3, v32.v23, v32.base, v32.frozen, v32.traffic
V32_SHA256 = "b691a90dc8a0a9d7594c101328f255dc0bcc87c91e7443af6441010a3fd92ba1"
FORMAT = "quiet-v3.3-multiboot-v1"
IPV4_WAIT_SECONDS = 25
IPV4_WAIT_SCRIPT = """import json,subprocess,time
started=time.monotonic()
while True:
    shown=json.loads(subprocess.run(['/usr/sbin/ip','-4','-j','addr','show','dev','enp0s3'],capture_output=True,text=True,check=True).stdout or '[]')
    local=[a for link in shown for a in link.get('addr_info',[]) if a.get('local')=='10.0.0.10' and not a.get('tentative') and not a.get('dadfailed')]
    if local:
        print(json.dumps({'ipv4_ready':True,'waited_seconds':round(time.monotonic()-started,3)}))
        break
    if time.monotonic()-started>%d:
        print(json.dumps({'ipv4_ready':False,'waited_seconds':round(time.monotonic()-started,3)}))
        raise SystemExit(1)
    time.sleep(0.2)
""" % IPV4_WAIT_SECONDS


def boot_once(module, protocol, destination, index, auth):
    """quiet-v3.2 boot_once with the guest IPv4 readiness wait inserted before the HTTP control."""
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
    timer = threading.Timer(v32.CAPTURE_SECONDS, stop_trace)
    timer.start()
    readiness_deadline = trace["power_requested_ns"] + v32.READINESS_SECONDS * 1_000_000_000
    try:
        v32.wait_boot_guest(module, auth, directory, readiness_deadline)
        guest = Guest(module, destination)
        ready = guest.run(auth, "/usr/bin/python3", "-c", IPV4_WAIT_SCRIPT, timeout=IPV4_WAIT_SECONDS + 5)
        (directory / "ipv4-ready.log").write_text(ready.stdout + ready.stderr)
        frozen.require(ready.returncode == 0, "Guest IPv4 address not configured within %d s" % IPV4_WAIT_SECONDS)
        frozen.save(directory / "ipv4-ready.json", json.loads(ready.stdout.strip().splitlines()[-1]))
        frozen.require(time.monotonic_ns() < readiness_deadline, "No time for bounded positive control inside boot capture")
        response = guest.run(auth, "/usr/bin/python3", "-c", base.control_script(protocol["control_paths"][index - 1]),
                             timeout=10)
        (directory / "control.log").write_text(response.stdout + response.stderr)
        frozen.require(response.returncode == 0, "Boot positive control failed")
        frozen.save(directory / "control.json", json.loads(response.stdout.strip()))
        frozen.require(finished.wait(timeout=v32.CAPTURE_SECONDS), "Boot trace stop did not finish")
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
    v32.check_frozen()
    frozen.require(frozen.digest(v32.__file__) == V32_SHA256, "Frozen quiet-v3.2 driver changed")


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["capture_seconds"] == v32.CAPTURE_SECONDS
                   and protocol["readiness_seconds"] == v32.READINESS_SECONDS
                   and protocol["ipv4_wait_seconds"] == IPV4_WAIT_SECONDS
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
    attempt = ROOT / "quiet-ambient-v3-3" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, v32.__file__, v31.__file__, v3.__file__, v23.__file__, v23.v22.__file__, v23.v21.__file__,
                 base.__file__, network.__file__, traffic.__file__, v3.POLICY, base.POLICY, ROOT / "quiet_ambient.py",
                 ROOT / "capture_liveness_v4.py", ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT,
        "derived_from": {"quiet_ambient_v32.py": V32_SHA256,
                         "change": "guest IPv4 readiness wait (ip -4 -j addr, up to 25 s) before each boot's HTTP control",
                         "evidence": "quiet-ambient-v3-2/20261024T141226860839Z: boots 1-9 accepted; boot 10 control raced IPv4 DAD",
                         "superseded_attempts": ["quiet-ambient-v2/20261024T110014475263Z",
                                                 "quiet-ambient-v2-1/20261024T132922140215Z",
                                                 "quiet-ambient-v2-2/20261024T133443341773Z",
                                                 "quiet-ambient-v2-3/20261024T134126526695Z",
                                                 "quiet-ambient-v3/20261024T135729274511Z",
                                                 "quiet-ambient-v3-1/20261024T140349202097Z",
                                                 "quiet-ambient-v3-2/20261024T141226860839Z"]},
        "policy": {"file": "quiet_guest_v3.sh", "sha256": frozen.digest(v3.POLICY), "default_target": "multi-user.target",
                   "snapd_masked_required": sorted(v3.SNAPD_REQUIRED), "headless_required_units": v3.HEADLESS_REQUIRED},
        "boot_count": base.BOOT_COUNT, "capture_seconds": v32.CAPTURE_SECONDS, "readiness_seconds": v32.READINESS_SECONDS,
        "ipv4_wait_seconds": IPV4_WAIT_SECONDS,
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
                     "Ten traced 90 s boots, distinct boot IDs, Guest Control within 75 s and guest IPv4 configured within "
                     "25 s more; every frame is the start record, a bounded link-up frame, guest/Sink ARP or the HTTP control",
                     "Every case in the later benign batch must independently pass the strict validator",
                     "Cleanup restores the original snapshot and trace off/none"],
        "limitations": ["Headless guest differs from the desktop guest used for all earlier captures; keep data separate",
                        "Hypervisor NIC tracing has no independent drop counter; not a completeness proof",
                        "Ten ninety-second boots do not exercise every later timer",
                        "The production .19 batch has no IPv4 readiness wait; the .20 candidate adds one in the runner",
                        "No VM phase, batch, malware, fit or merge is authorized by preparation"]}
    frozen.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": frozen.digest(attempt / "protocol.json"),
                      "vm_steps_authorized": [], "collection_ready": False}, indent=2))
    return attempt


def install():
    v32.install()
    check_frozen()
    base.boot_once, base.verify_plan = boot_once, verify_plan


def self_test():
    import ast
    ast.parse(IPV4_WAIT_SCRIPT)
    added = {'ready = guest.run(auth, "/usr/bin/python3", "-c", IPV4_WAIT_SCRIPT, timeout=IPV4_WAIT_SECONDS + 5)',
             '(directory / "ipv4-ready.log").write_text(ready.stdout + ready.stderr)',
             'frozen.require(ready.returncode == 0, "Guest IPv4 address not configured within %d s" % IPV4_WAIT_SECONDS)',
             'frozen.save(directory / "ipv4-ready.json", json.loads(ready.stdout.strip().splitlines()[-1]))',
             'guest = Guest(module, destination)'}
    drop = lambda text: [line.strip() for line in text.replace("'", '"').splitlines()
                         if line.strip() and not line.strip().startswith(('"""', "#", "def boot_once"))]
    old, new = drop(inspect.getsource(v32.boot_once)), drop(inspect.getsource(boot_once))
    renamed = {line.replace("v32.", "") for line in new}
    frozen.require(set(old) - renamed == set() and renamed - set(old) <= {line.replace("v32.", "") for line in added},
                   "boot_once differs unexpectedly: %r" % sorted((set(old) ^ renamed)))
    # The wait script against fake `ip` output: tentative/absent keep waiting, configured returns.
    namespace = {}
    shown = [[{"addr_info": []}], [{"addr_info": [{"local": "10.0.0.10", "tentative": True}]}],
             [{"addr_info": [{"local": "10.0.0.10"}]}]]
    calls = iter(shown)
    from unittest.mock import patch
    fake = lambda *a, **k: subprocess.CompletedProcess(a, 0, json.dumps(next(calls)), "")
    with patch.object(subprocess, "run", side_effect=fake), patch.object(time, "sleep"):
        import contextlib, io
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(IPV4_WAIT_SCRIPT, "wait", "exec"), namespace)
    frozen.require(json.loads(output.getvalue())["ipv4_ready"] is True, "Wait script did not accept a configured address")
    print("PASS boot_once differs from frozen v3.2 only by the IPv4 wait; wait skips absent/tentative, accepts configured")
    v32.self_test()
    install()
    frozen.require(base.boot_once is boot_once and base.wait_boot_guest is v32.wait_boot_guest and base.CAPTURE_SECONDS == 90,
                   "Inherited phase machinery not routed through v3.3")


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
