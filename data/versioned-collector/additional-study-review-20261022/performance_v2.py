"""Separately versioned performance lifecycle; unchanged measured task boundary."""

import argparse
import ast
import json
import os
import signal
import subprocess
import time
from pathlib import Path

import scoped_performance as previous


ROOT = Path(__file__).resolve().parent
SCHEMA = "2026-10-23.25-performance-lifecycle-harness"
SECOND = 1_000_000_000
identity = previous.identity


class Session(previous.Session):
    def __init__(self, args):
        super().__init__(args)
        self.receipts = {}
        self.lifecycle_error = None

    def prepare(self, run_dir, sample):
        original_file = previous.__file__
        previous.__file__ = __file__
        try:
            return super().prepare(run_dir, sample)
        finally:
            previous.__file__ = original_file

    def send_finish(self):
        if self.process is not None and self.result is None and "finish_request_ns" not in self.receipts:
            self.receipts["finish_request_ns"] = time.monotonic_ns()
            self.process.stdin.write(b"FINISH\n")
            self.process.stdin.flush()

    def observation_end(self, actual_end, observation_start):
        self.receipts.update(observation_end_ns=actual_end, observation_start_ns=observation_start)
        try:
            self.send_finish()
            identity.save(self.run_dir / "performance-finish-request.json", self.receipts)
        except BaseException as error:
            self.lifecycle_error = repr(error)

    def stop(self):
        if self.process is None or self.result is not None:
            self.password = b""
            if self.log is not None:
                self.log.close()
            return
        try:
            self.send_finish()
            remaining = (self.receipts["finish_request_ns"] + 12 * SECOND - time.monotonic_ns()) / SECOND
            if remaining <= 0:
                raise TimeoutError("Original performance acknowledgement deadline exhausted")
            self.result = identity.read_message(self.process, remaining)
            self.receipts["finish_ack_ns"] = time.monotonic_ns()
            if self.receipts["finish_ack_ns"] > self.receipts["finish_request_ns"] + 12 * SECOND:
                raise TimeoutError("Original performance acknowledgement exceeded twelve seconds")
            if self.process.wait(timeout=5) != 0:
                raise ValueError("Performance broker exited unsuccessfully")
            if self.lifecycle_error is not None:
                raise ValueError(self.lifecycle_error)
        except BaseException as error:
            self.lifecycle_error = repr(error)
            self.result = {"status": "rejected", "error": self.lifecycle_error}
            self.process.stdin.close()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=8)
        finally:
            self.log.close()
            for name in ("attribution-gate", "exec-ready"):
                (self.run_dir / name).unlink(missing_ok=True)
            identity.save(self.run_dir / "performance-lifecycle.json",
                          {**self.receipts, "error": self.lifecycle_error, "broker_status": self.result["status"]})


def generate(base):
    tree = ast.parse(previous.generate(base))
    callbacks = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "scoped_performance":
                    alias.name = "performance_v2"
        elif isinstance(node, ast.Name) and node.id == "scoped_performance":
            node.id = "performance_v2"
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "TELEMETRY_SCHEMA_VERSION" for target in node.targets):
            node.value = ast.Constant(SCHEMA)
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    for parent in ast.walk(main):
        for field, children in ast.iter_fields(parent):
            if not isinstance(children, list):
                continue
            replacement = []
            for statement in children:
                if (isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "observation_ended_ns" for target in statement.targets)
                        and isinstance(statement.value, ast.Call) and ast.unparse(statement.value.func) == "min"):
                    replacement.extend(ast.parse("attribution.observation_end(observation_ended_ns, sample_started_ns)").body)
                    callbacks += 1
                replacement.append(statement)
            setattr(parent, field, replacement)
    if callbacks != 1:
        raise ValueError("Original actual-end/clamp callback anchor differs")
    generated = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    compile(generated, "performance-v2-runner", "exec")
    return generated


launch = previous.launch
write_task_usage = previous.write_task_usage
original_sensors_enabled = previous.original_sensors_enabled
broker = previous.broker


def self_test(base=None):
    import tempfile
    from unittest.mock import MagicMock, patch
    base = Path(base) if base is not None else ROOT.parents[2] / "src/malware_runner.py"
    previous.self_test(base)
    generated = generate(base)
    before = {node.name: ast.dump(node) for node in ast.parse(base.read_text()).body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    after = {node.name: ast.dump(node) for node in ast.parse(generated).body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    assert before == after
    for condition in ("baseline", "original", "full"):
        with tempfile.TemporaryDirectory(prefix="hazim-performance-v2-") as directory:
            session = Session.__new__(Session)
            session.process = MagicMock()
            session.process.wait.return_value = 0
            session.log = MagicMock()
            session.result = None
            session.receipts = {}
            session.lifecycle_error = None
            session.password = b""
            session.run_dir = Path(directory)
            with patch.object(time, "monotonic_ns", return_value=21 * SECOND):
                session.observation_end(21 * SECOND, SECOND)
            session.process.stdin.write.assert_called_once_with(b"FINISH\n")
            with patch.object(time, "monotonic_ns", return_value=26 * SECOND), patch.object(identity, "read_message", return_value={"status": "accepted"}) as read:
                session.stop()
            assert read.call_args.args[1] == 7
            assert json.loads((session.run_dir / "performance-lifecycle.json").read_text())["error"] is None
            session.process.stdin.write.assert_called_once_with(b"FINISH\n")
    for failure in ("send", "ack", "late_ack", "publication", "expired"):
        with tempfile.TemporaryDirectory(prefix="hazim-performance-failure-") as directory:
            session = Session.__new__(Session)
            session.process = MagicMock()
            session.process.wait.return_value = 0
            session.log = MagicMock()
            session.result = None
            session.receipts = {}
            session.lifecycle_error = None
            session.password = b""
            session.run_dir = Path(directory)
            if failure == "send":
                session.process.stdin.write.side_effect = BrokenPipeError("injected send failure")
            with patch.object(time, "monotonic_ns", return_value=21 * SECOND):
                if failure == "publication":
                    with patch.object(identity, "save", side_effect=OSError("injected publication failure")):
                        session.observation_end(21 * SECOND, SECOND)
                else:
                    session.observation_end(21 * SECOND, SECOND)
            clocks = [26 * SECOND, 34 * SECOND] if failure == "late_ack" else [34 * SECOND, 34 * SECOND] if failure == "expired" else [26 * SECOND, 26 * SECOND]
            with patch.object(time, "monotonic_ns", side_effect=clocks), patch.object(identity, "read_message", return_value={"status": "accepted"}, side_effect=TimeoutError("injected ACK failure") if failure == "ack" else None):
                session.stop()
            assert session.result["status"] == "rejected"
            assert json.loads((session.run_dir / "performance-lifecycle.json").read_text())["error"]
            session.process.stdin.write.assert_called_once_with(b"FINISH\n")
            session.process.stdin.close.assert_called_once()
            session.log.close.assert_called_once()
    print("PASS unchanged helpers/task boundary and three-condition immediate single FINISH with original remaining12s acknowledgement budget")
    print("PASS send/ACK/late-ACK/publication/expired-budget failures preserve rejection, single send, raw evidence and closed resources")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--broker", type=Path)
    options = parser.parse_args()
    if options.broker:
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        broker(options.broker)
    else:
        self_test()