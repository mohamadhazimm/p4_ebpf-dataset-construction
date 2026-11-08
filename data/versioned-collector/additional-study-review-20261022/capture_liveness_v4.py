#!/usr/bin/env python3
"""Approved bounded startup correction; preserve the measured V3 lifecycle."""

import argparse
import ast
import copy
import json
import signal
import subprocess
import time
from pathlib import Path

import capture_liveness_v3 as lifecycle


ROOT = Path(__file__).resolve().parent
checks = lifecycle.checks
driver = lifecycle.driver
integration = lifecycle.previous
SCHEMA = "2026-10-23.24-capture-liveness-startup-diagnostic"
Session = lifecycle.Session
STARTUP_SECONDS = 120
PINS = {"capture_liveness_v3.py": "403b21b5249ef0c2a3104b5271109a18e28a8e137b885f10fe669d21d842da71",
        "CAPTURE_LIVENESS_PROTOCOL_V3.md": "9544f2b790666b7c3abe81d010a21b815814fe5403f9c08546c7e89e872bed87",
        "audit_capture_liveness_v3_launch.py": "504464b3e1db6aefeaba562943a3177280884aa4ccc8bd4415547202c1bc5af0"}
for name, expected in PINS.items():
    checks.require(checks.digest(ROOT / name) == expected, "Measured V3 input changed: " + name)


def wait_guest(helper, auth, log_path):
    started = time.monotonic_ns()
    deadline = started + STARTUP_SECONDS * checks.SECOND
    receipt = {"status": "rejected", "started_ns": started, "deadline_ns": deadline,
               "events": [], "scope": "Startup only; no diagnostic control or helper transaction"}

    def run(command, operation, maximum, log):
        requested = time.monotonic_ns()
        budget_ns = min(int(maximum * checks.SECOND), deadline - requested)
        checks.require(budget_ns > 0, "Startup absolute deadline exhausted")
        budget = budget_ns / checks.SECOND
        try:
            response = subprocess.run(command, capture_output=True, text=True, timeout=budget, check=False)
        except subprocess.TimeoutExpired:
            receipt["events"].append({"operation": operation + "_timeout", "requested_ns": requested,
                                      "ended_ns": time.monotonic_ns(), "timeout_budget_ns": budget_ns})
            raise
        log.write(response.stdout + response.stderr)
        log.flush()
        ended = time.monotonic_ns()
        receipt["events"].append({"operation": operation, "requested_ns": requested,
                                  "ended_ns": ended, "returncode": response.returncode,
                                  "timeout_budget_ns": budget_ns})
        checks.require(ended <= deadline, "Startup command exceeded absolute deadline")
        return response.returncode

    try:
        with log_path.open("x") as log:
            checks.require(run(["VBoxManage", "startvm", helper.VM, "--type", "headless"],
                               "startvm", STARTUP_SECONDS, log) == 0, "Guest startup failed")
            for probe in range(3):
                budget = min(5.0, checks.remaining(deadline, clock=time.monotonic_ns))
                try:
                    ready = run(["VBoxManage", "guestcontrol", helper.VM, "run", *auth, "--exe", "/bin/true",
                                 "--wait-stdout", "--wait-stderr", "--timeout", str(max(1, int(budget * 1000))), "--"],
                                "guestcontrol_true", budget, log) == 0
                except subprocess.TimeoutExpired:
                    ready = False
                if ready:
                    receipt["status"] = "accepted_guestcontrol_probe"
                    receipt["ended_ns"] = time.monotonic_ns()
                    audit_startup(receipt)
                    return
                checks.require(probe < 2, "Guest Control failed three bounded startup probes")
                event_budget = checks.remaining(deadline, clock=time.monotonic_ns) - 5.0
                if event_budget > 0:
                    try:
                        run(["VBoxManage", "guestproperty", "wait", helper.VM,
                             "/VirtualBox/GuestInfo/OS/LoggedInUsers", "--timeout",
                             str(max(1, int(event_budget * 1000))), "--fail-on-timeout"],
                            "login_notification", event_budget, log)
                    except subprocess.TimeoutExpired:
                        pass
    except BaseException as error:
        receipt["error_type"] = type(error).__name__
        raise
    finally:
        receipt["ended_ns"] = time.monotonic_ns()
        integration.save(log_path.with_name("startup-readiness.json"), receipt)


def audit_startup(receipt):
    checks.require(receipt["status"] == "accepted_guestcontrol_probe" and "error_type" not in receipt,
                   "Startup was not independently accepted")
    start, deadline = receipt["started_ns"], receipt["deadline_ns"]
    checks.require(deadline == start + STARTUP_SECONDS * checks.SECOND and start <= receipt["ended_ns"] <= deadline,
                   "Startup absolute deadline differs")
    events = receipt["events"]
    checks.require(events and events[0]["operation"] == "startvm" and events[0]["returncode"] == 0 and
                   events[-1]["operation"] == "guestcontrol_true" and events[-1]["returncode"] == 0,
                   "No successful final Guest Control probe")
    probes = [event for event in events if event["operation"].startswith("guestcontrol_true")]
    checks.require(1 <= len(probes) <= 3, "Startup probe count differs")
    previous_end = start
    for event in events:
        checks.require(previous_end <= event["requested_ns"] <= event["ended_ns"] <= receipt["ended_ns"],
                       "Startup command clocks differ")
        checks.require(0 < event["timeout_budget_ns"] <= deadline - event["requested_ns"],
                       "Startup command resets deadline")
        if event["operation"].startswith("guestcontrol_true"):
            checks.require(event["timeout_budget_ns"] <= 5 * checks.SECOND, "Startup probe timeout exceeds five seconds")
        previous_end = event["ended_ns"]
    checks.require(events[-1]["ended_ns"] - events[-1]["requested_ns"] <= 5 * checks.SECOND,
                   "Successful Guest Control probe exceeded five seconds")
    return {"status": receipt["status"], "probes": len(probes), "elapsed_ns": receipt["ended_ns"] - start}


def audit_saved(attempt):
    result = lifecycle.audit_saved(attempt)
    result["startup"] = audit_startup(json.loads((attempt / "startup-readiness.json").read_text()))
    result["startup_receipt_sha256"] = checks.digest(attempt / "startup-readiness.json")
    result["v4_auditor_sha256"] = checks.digest(__file__)
    return result


def generate(base):
    tree = ast.parse(lifecycle.generate(base))
    sites = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "capture_liveness_v3":
                    alias.name = "capture_liveness_v4"
                    sites += 1
    checks.require(sites == 1, "V3 generated import anchor differs")
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


def contract():
    result = lifecycle.contract()
    result.update(protocol_schema="2026-10-23.capture-liveness-proposal.v4",
                  startup_change="Successful authenticated /bin/true required; notification alone never accepts; absolute120s, at most3 probes, each at most5s",
                  fresh_attempts_authorized=1)
    for name in (*PINS, "CAPTURE_LIVENESS_PROTOCOL_V4.md"):
        result["source_pins"][name] = checks.digest(ROOT / name)
    for name in ("protocol.json", "failure.json", "final_vm_state.json", "launch-audit-20261023T111521144771Z.json"):
        path = ROOT / "capture-liveness-v3-readiness/20261023T111107169124Z" / name
        result["source_pins"][str(path.relative_to(ROOT))] = checks.digest(path)
    return result


def execute(attempt, manifest):
    signal.signal(signal.SIGTERM, integration.interrupted)
    path = ROOT / "check_integrated_attribution.py"
    driver.pinned(path, "55f556320f6ac4121338b57d8a28e6bc39ed9a811916a0e3c0624d24342017af")
    original = ast.parse(path.read_text())
    node = next(item for item in original.body if isinstance(item, ast.FunctionDef) and item.name == "execute")
    imports = 0
    deadlines = 0
    for child in ast.walk(node):
        if isinstance(child, ast.ImportFrom) and child.module == "export_original_sources":
            checks.require([alias.name for alias in child.names] == ["check_competitors", "helper_module", "wait_guest"],
                           "Original execution imports differ")
            child.names = child.names[:2]
            imports += 1
        if isinstance(child, ast.Constant) and child.value == "360000":
            child.value = "720000"
            deadlines += 1
    checks.require(imports == deadlines == 1, "Execution derivation anchors differ")
    namespace = dict(driver.__dict__)
    namespace["wait_guest"] = wait_guest
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(path), "exec"), namespace)
    namespace["execute"](attempt, manifest)


def startup_self_test():
    import tempfile
    from types import SimpleNamespace
    from unittest.mock import patch

    for scenario in ("ready_without_event", "timeout_then_ready", "notification_timeout_then_ready", "event_not_readiness", "all_failed",
                     "probe_timeout", "interrupt", "late_success"):
        now = [checks.SECOND]
        probes = []
        commands = []

        def run(command, **options):
            commands.append(command)
            checks.require(0 < options["timeout"] <= STARTUP_SECONDS, "Unbounded startup subprocess")
            if "guestcontrol" in command:
                probes.append(command)
                checks.require(options["timeout"] <= 5, "Probe exceeds five seconds")
                if scenario == "probe_timeout":
                    now[0] += int(options["timeout"] * checks.SECOND)
                    raise subprocess.TimeoutExpired("synthetic", options["timeout"])
                if scenario == "interrupt":
                    raise KeyboardInterrupt()
                now[0] += int((STARTUP_SECONDS + 1 if scenario == "late_success" else 0.01) * checks.SECOND)
                successful = scenario in ("ready_without_event", "late_success") or (
                    scenario in ("timeout_then_ready", "notification_timeout_then_ready") and len(probes) == 2)
                return SimpleNamespace(returncode=0 if successful else 1, stdout="", stderr="")
            if "guestproperty" in command:
                now[0] += int((options["timeout"] if scenario in ("timeout_then_ready", "notification_timeout_then_ready") else 0.01) * checks.SECOND)
                if scenario == "notification_timeout_then_ready":
                    raise subprocess.TimeoutExpired("synthetic", options["timeout"])
                return SimpleNamespace(returncode=1 if scenario == "timeout_then_ready" else 0, stdout="", stderr="")
            now[0] += 10000000
            return SimpleNamespace(returncode=0, stdout="started\n", stderr="")

        with tempfile.TemporaryDirectory(prefix="hazim-startup-v4-") as directory:
            log = Path(directory) / "guest-login.log"
            try:
                with patch.object(time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(subprocess, "run", side_effect=run):
                    wait_guest(SimpleNamespace(VM="synthetic-only"), ["--username", "synthetic", "--passwordfile", "/private/auth"], log)
            except (ValueError, TimeoutError, subprocess.TimeoutExpired, KeyboardInterrupt):
                checks.require(scenario not in ("ready_without_event", "timeout_then_ready", "notification_timeout_then_ready"), "Available Guest Control rejected")
            else:
                checks.require(scenario in ("ready_without_event", "timeout_then_ready", "notification_timeout_then_ready"), "Unusable/late Guest Control accepted")
            receipt = json.loads(log.with_name("startup-readiness.json").read_text())
            checks.require((receipt["status"] == "accepted_guestcontrol_probe") ==
                           (scenario in ("ready_without_event", "timeout_then_ready", "notification_timeout_then_ready")), "Startup receipt status differs")
            checks.require(len(probes) <= 3 and "/private/auth" not in json.dumps(receipt), "Probe budget or credential privacy differs")
            if scenario == "ready_without_event":
                checks.require(not any("guestproperty" in command for command in commands), "Unnecessary event wait after ready probe")
                accepted = receipt
    for corruption in ("deadline", "missing_probe", "failed_probe", "late_probe", "reset_budget", "order"):
        changed = copy.deepcopy(accepted)
        if corruption == "deadline":
            changed["deadline_ns"] += 1
        elif corruption == "missing_probe":
            changed["events"] = changed["events"][:1]
        elif corruption == "failed_probe":
            changed["events"][-1]["returncode"] = 1
        elif corruption == "late_probe":
            changed["events"][-1]["ended_ns"] = changed["deadline_ns"] + 1
        elif corruption == "reset_budget":
            changed["events"][-1]["timeout_budget_ns"] = STARTUP_SECONDS * checks.SECOND
        else:
            changed["events"].reverse()
        try:
            audit_startup(changed)
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupted startup receipt accepted: " + corruption)
    with tempfile.TemporaryDirectory(prefix="hazim-startup-real-clock-") as directory:
        log = Path(directory) / "guest-login.log"
        with patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
            wait_guest(SimpleNamespace(VM="synthetic-only"), [], log)
        audit_startup(json.loads(log.with_name("startup-readiness.json").read_text()))
    print("PASS bounded startup: already-ready without event, timeout then ready, event-only rejection, three-probe rejection, timeout/interruption publication, late-success rejection and credential privacy")
    print("PASS six independent startup receipt deadline/probe/order/budget corruption guards and real advancing-clock budget check")


checks.SCHEMA = integration.SCHEMA = SCHEMA
checks.contract = contract
integration.generate = generate
integration.__file__ = __file__
driver.__file__ = __file__
freeze_tree = copy.deepcopy(lifecycle.freeze_tree)
for node in ast.walk(freeze_tree):
    if isinstance(node, ast.Tuple) and any(isinstance(item, ast.Constant) and item.value == "CAPTURE_LIVENESS_PROTOCOL_V2.md"
                                         for item in node.elts):
        node.elts.extend([ast.Constant(value="capture_liveness_v3.py"), ast.Constant(value="audit_capture_liveness_v3_launch.py"),
                  ast.Constant(value="CAPTURE_LIVENESS_PROTOCOL_V4.md")])
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value == "capture-liveness-v3-readiness":
            node.value = "capture-liveness-v4-readiness"
        elif node.value.startswith("User selected Approve Versioned Fix"):
            node.value = "User selected Approve Versioned Startup Fix And One Benign Diagnostic: one fresh six-control launch; all existing limits unchanged; no benchmark, malware, fitting, padding or policy change"
exec(compile(ast.fix_missing_locations(freeze_tree), __file__, "exec"), driver.__dict__)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--startup-self-test", action="store_true")
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--guest", type=Path)
    action.add_argument("--broker", type=Path)
    action.add_argument("--audit-saved", type=Path)
    options = parser.parse_args()
    if options.broker:
        integration.broker(options.broker)
    elif options.guest:
        signal.signal(signal.SIGTERM, integration.interrupted)
        raise SystemExit(0 if driver.guest(options.guest) else 2)
    elif options.startup_self_test:
        startup_self_test()
    elif options.audit_saved:
        from datetime import datetime, timezone
        result = audit_saved(options.audit_saved)
        output = options.audit_saved / ("audit-v4-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        integration.save(output, result)
        print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "output": str(output),
                          "collection_ready": False}, indent=2))
    elif options.self_test:
        startup_self_test()
        lifecycle.self_test()
    else:
        startup_self_test()
        attempt, manifest = driver.freeze()
        if options.execute_benign_checks:
            execute(attempt, manifest)