#!/usr/bin/env python3
"""Approved V3 lifecycle correction derived from immutable measured V2 modules."""

import argparse
import ast
import inspect
import json
import signal
import subprocess
import tarfile
import time
from pathlib import Path

import capture_liveness as checks


ROOT = Path(__file__).resolve().parent
PINS = {"capture_liveness.py": "bde94fe9f894282bdbb2837756b09de6998b8f6c099be8b7d50294f13bd72686",
        "integrated_liveness.py": "927c11ad69f7a508769a7b26029719d3293882e470a84e1930974651da828436",
        "audit_capture_liveness.py": "a68c44db6b701728beded356944cadd3e46b569d70a79f1a22a4c97219861f6f",
        "check_capture_liveness.py": "a5620cdd6beae6ec579d1a483385055652ca6b41ad387cd1dbe1748446996dd6"}
for filename, expected in PINS.items():
    checks.require(checks.digest(ROOT / filename) == expected, "Measured V2 module changed: " + filename)

import integrated_liveness as previous
import audit_capture_liveness as auditor
import check_capture_liveness as driver


SCHEMA = "2026-10-23.23-capture-liveness-lifecycle-diagnostic"
OriginalSession = previous.Session
original_generate = previous.generate
original_contract = checks.contract
original_audit_case = auditor.audit_case
original_self_test = driver.self_test
require = checks.require


class Session(OriginalSession):
    def __init__(self, args):
        super().__init__(args)
        self.receipts = {}
        self.lifecycle_error = None

    def send_finish(self):
        if "finish_request_ns" in self.receipts:
            return
        self.receipts["finish_request_ns"] = time.monotonic_ns()
        self.process.stdin.write(b"FINISH\n")
        self.process.stdin.flush()

    def observation_end(self, monotonic_ns, observation_start_ns=None):
        self.receipts["observation_end_ns"] = monotonic_ns
        self.receipts["observation_start_ns"] = observation_start_ns
        try:
            self.send_finish()
        except BaseException as error:
            self.lifecycle_error = "FINISH send failed: " + repr(error)
        try:
            previous.save(self.run_dir / "liveness-finish-request.json", dict(self.receipts))
        except BaseException as error:
            self.lifecycle_error = "Early receipt publication failed: " + repr(error)

    def stop(self):
        if self.process is None or self.result is not None:
            self.password = b""
            if self.log is not None:
                self.log.close()
            return
        try:
            self.send_finish()
            budget = checks.remaining(self.receipts["finish_request_ns"] + 15 * checks.SECOND, clock=time.monotonic_ns)
            self.result = previous.identity.read_message(self.process, budget)
            self.receipts["finish_ack_ns"] = time.monotonic_ns()
            require(self.receipts["finish_ack_ns"] <= self.receipts["finish_request_ns"] + 15 * checks.SECOND,
                    "Diagnostic finish acknowledgement deadline")
            require(self.process.wait(timeout=3) == 0, "Diagnostic broker exit failed")
        except BaseException as error:
            self.result = {"status": "rejected", "error": type(error).__name__ + ": " + str(error)}
            self.process.stdin.close()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                previous.stop_process(self.process)
        finally:
            self.log.close()
            for name in ("attribution-gate", "exec-ready"):
                (self.run_dir / name).unlink(missing_ok=True)

    def quality(self, metadata, status, reasons):
        self.stop()
        if self.result is None:
            self.result = {"status": "rejected", "error": "Diagnostic session did not start"}
        available = {**self.receipts, **self.result.get("lifecycle", {}),
                     "observation_start_ns": metadata["sample_started_monotonic_ns"],
                     "original_observation_end_ns": metadata["observation_ended_monotonic_ns"],
                     "broker_status": self.result["status"], "error": getattr(self, "lifecycle_error", None)}
        try:
            previous.save(self.run_dir / "liveness-attempt.json", available)
        except BaseException as error:
            self.lifecycle_error = "Raw lifecycle publication failed: " + repr(error)
        result = super().quality(metadata, status, reasons)
        if getattr(self, "lifecycle_error", None):
            return "rejected", [*result[1], "capture_liveness_failed:" + self.lifecycle_error]
        return result


def generate(base):
    tree = ast.parse(original_generate(base))
    sites = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "integrated_liveness":
                    alias.name = "capture_liveness_v3"
                    alias.asname = "integrated_liveness"
        if isinstance(node, ast.Call) and ast.unparse(node.func) == "attribution.observation_end":
            node.args.append(ast.Name(id="sample_started_ns", ctx=ast.Load()))
            sites += 1
    require(sites == 1, "Actual end callback anchor differs")
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


def contract():
    result = original_contract()
    result.update(protocol_schema="2026-10-23.capture-liveness-proposal.v3", implementation_authorized=True,
                  diagnostic_execution_authorized=True, diagnostic_timing_proposal_approved=True,
                  lifecycle_change="Immediate end-to-FINISH send; unchanged original teardown; remaining fifteen-second ack budget; raw clocks before validation")
    path = ROOT / "CAPTURE_LIVENESS_PROTOCOL_V3.md"
    result["source_pins"][path.name] = checks.digest(path)
    for name in ("protocol.json", "guest_result.json", "evidence.tgz", "partial-audit-20261023T102947067164Z.json"):
        preserved = ROOT / "capture-liveness-readiness/20261023T102537476340Z" / name
        result["source_pins"][str(preserved.relative_to(ROOT))] = checks.digest(preserved)
    return result


def audit_case(read, prefix, manifest, case):
    result = original_audit_case(read, prefix, manifest, case)
    early = json.loads(read(prefix + "/liveness-finish-request.json"))
    raw = json.loads(read(prefix + "/liveness-attempt.json"))
    final = json.loads(read(prefix + "/liveness-lifecycle.json"))
    require(all(early[name] == final[name] == raw[name] for name in early), "Early/raw/final lifecycle receipts differ")
    require(all(raw[name] == value for name, value in final.items()) and raw["error"] is None and
            raw["broker_status"] == "accepted", "Raw lifecycle not independently accepted")
    require(raw["finish_request_ns"] <= json.loads(read(prefix + "/attribution-result.json"))["finish_arrival_ns"],
            "FINISH arrival precedes request")
    return result


def audit_saved(attempt):
    result = auditor.audit(attempt)
    manifest = json.loads((attempt / "manifest.json").read_text())
    report = json.loads((attempt / "guest_result.json").read_text())
    require(result["cases"] == report["cases"], "Guest/independently audited case facts differ")
    with tarfile.open(attempt / "evidence.tgz", "r:gz") as archive:
        previous_ack = 0
        clocks = []
        for case in result["cases"]:
            prefix = case["prefix"]
            raw = json.load(archive.extractfile(prefix + "/liveness-attempt.json"))
            diagnostics = json.load(archive.extractfile(prefix + "/packet_capture_diagnostics.json"))
            stops = [event["monotonic_ns"] for event in diagnostics["lifecycle_events"] if event["event"] == "stop_requested"]
            require(len(stops) == 1 and raw["finish_request_ns"] <= stops[0], "FINISH not before original PCAP teardown")
            require(previous_ack < raw["ready_ns"], "Actual six-case execution ordering differs")
            previous_ack = raw["finish_ack_ns"]
            clocks.append({"case": case["case"], "actual_end_to_finish_ns": raw["finish_request_ns"] - raw["observation_end_ns"],
                           "finish_to_ack_ns": raw["finish_ack_ns"] - raw["finish_request_ns"]})
        result["member_sha256"] = {item.name: __import__("hashlib").sha256(archive.extractfile(item).read()).hexdigest()
                                   for item in archive.getmembers()}
        first = result["cases"][0]
        prefix = first["prefix"]
        frozen = {item.name: archive.extractfile(item).read() for item in archive.getmembers()}
        for filename, field in (("liveness-finish-request.json", "observation_end_ns"),
                                ("liveness-attempt.json", "finish_ack_ns")):
            name = prefix + "/" + filename
            changed = json.loads(frozen[name])
            changed[field] += 1
            try:
                audit_case(lambda path: json.dumps(changed).encode() if path == name else frozen[path],
                           prefix, manifest, manifest["cases"][0])
            except ValueError:
                pass
            else:
                raise AssertionError("Altered early/raw receipt accepted")
    state = json.loads((attempt / "final_vm_state.json").read_text())
    for kind in ("guest", "sink"):
        require(state[kind]["nic1"] == '"intnet"' and state[kind]["intnet1"] == '"malnet"' and
                all(state[kind]["nic" + str(number)] == '"none"' for number in range(2, 9)), "Saved isolation differs")
    result.update(lifecycle_clocks=clocks, raw_clock_corruption_guards=2, v3_auditor_sha256=checks.digest(__file__))
    return result


def self_test():
    import tempfile
    from unittest.mock import MagicMock, patch
    original_self_test()
    for condition in ("original", "full"):
        with tempfile.TemporaryDirectory(prefix="hazim-lifecycle-v3-") as directory:
            session = Session.__new__(Session)
            session.process = MagicMock()
            session.process.wait.return_value = 0
            session.result = None
            session.log = MagicMock()
            session.password = b""
            session.run_dir = Path(directory)
            session.receipts = {"ready_ns": checks.SECOND}
            with patch.object(time, "monotonic_ns", return_value=21 * checks.SECOND):
                session.observation_end(21 * checks.SECOND, checks.SECOND)
            session.process.stdin.write.assert_called_once_with(b"FINISH\n")
            require((session.run_dir / "liveness-finish-request.json").is_file(), "Early receipt not published")
            with patch.object(time, "monotonic_ns", return_value=26 * checks.SECOND), \
                    patch.object(previous.identity, "read_message", return_value={"status": "accepted"}) as reader:
                session.stop()
            require(reader.call_args.args[1] == 10 and session.receipts["finish_request_ns"] == 21 * checks.SECOND,
                    "Five-second original teardown reset request/ack budget")
            session.process.stdin.write.assert_called_once_with(b"FINISH\n")
            session.config = {"condition": condition, "helper_transactions": 0}
            status, _reasons = session.quality({"sample_started_monotonic_ns": checks.SECOND,
                                               "observation_ended_monotonic_ns": 21 * checks.SECOND}, "accepted", [])
            require(status == "rejected" and (session.run_dir / "liveness-attempt.json").is_file(),
                    "Invalid lifecycle accepted or rejected-case raw clocks lost")
    for failure in ("send", "publication"):
        with tempfile.TemporaryDirectory(prefix="hazim-lifecycle-failure-") as directory:
            session = Session.__new__(Session)
            session.process = MagicMock()
            session.process.wait.return_value = 0
            session.result = None
            session.log = MagicMock()
            session.password = b""
            session.run_dir = Path(directory)
            session.receipts = {"ready_ns": checks.SECOND}
            if failure == "send":
                session.process.stdin.write.side_effect = BrokenPipeError("injected send failure")
            original_save = previous.save
            with patch.object(time, "monotonic_ns", return_value=21 * checks.SECOND), \
                    patch.object(previous, "save", side_effect=OSError("injected publication failure")
                                 if failure == "publication" else original_save):
                session.observation_end(21 * checks.SECOND, checks.SECOND)
            require(getattr(session, "lifecycle_error", None), "Injected failure was not retained")
            with patch.object(time, "monotonic_ns", return_value=26 * checks.SECOND), \
                    patch.object(previous.identity, "read_message", side_effect=TimeoutError("injected ack failure")):
                session.stop()
            require(session.result["status"] == "rejected" and session.log.close.called,
                    "Send/publication failure bypassed stop cleanup")
            session.config = {"condition": "original", "helper_transactions": 0}
            status, _reasons = session.quality({"sample_started_monotonic_ns": checks.SECOND,
                                               "observation_ended_monotonic_ns": 21 * checks.SECOND}, "accepted", [])
            require(status == "rejected" and (session.run_dir / "liveness-attempt.json").is_file(),
                    "Failed send/publication case lost final raw receipt or was promoted")
    print("PASS original/full immediate FINISH, five-second simulated original teardown, no duplicate request, shrinking ack budget and failed-validation clock publication")
    print("PASS injected FINISH-send/acknowledgement/publication failures retain rejection and still close resources")


checks.SCHEMA = previous.SCHEMA = SCHEMA
checks.contract = contract
previous.Session = Session
previous.generate = generate
previous.__file__ = __file__
auditor.audit_case = driver.audit_case = audit_case
driver.self_test = self_test
driver.__file__ = __file__
freeze_tree = ast.parse(inspect.getsource(driver.freeze))
for node in ast.walk(freeze_tree):
    if isinstance(node, ast.Tuple) and any(isinstance(item, ast.Constant) and
                                         item.value == "CAPTURE_LIVENESS_PROTOCOL_V2.md" for item in node.elts):
        node.elts.extend([ast.Constant(value="check_capture_liveness.py"),
                          ast.Constant(value="CAPTURE_LIVENESS_PROTOCOL_V3.md")])
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value == "capture-liveness-readiness":
            node.value = "capture-liveness-v3-readiness"
        elif node.value.startswith("User selected Approve V2 Implementation"):
            node.value = "User selected Approve Versioned Fix And Benign Diagnostic: one fresh V3 six-control attempt, unchanged limits, no benchmark retry, malware, fitting, padding or policy change"
exec(compile(ast.fix_missing_locations(freeze_tree), __file__, "exec"), driver.__dict__)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--guest", type=Path)
    action.add_argument("--broker", type=Path)
    action.add_argument("--audit-saved", type=Path)
    options = parser.parse_args()
    if options.broker:
        previous.broker(options.broker)
    elif options.guest:
        signal.signal(signal.SIGTERM, previous.interrupted)
        raise SystemExit(0 if driver.guest(options.guest) else 2)
    elif options.audit_saved:
        result = audit_saved(options.audit_saved)
        from datetime import datetime, timezone
        output = options.audit_saved / ("audit-v3-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        previous.save(output, result)
        print(json.dumps({"status": result["status"], "output": str(output), "collection_ready": False}, indent=2))
    elif options.self_test:
        self_test()
    else:
        attempt, manifest = driver.freeze()
        if options.execute_benign_checks:
            driver.execute(attempt, manifest)