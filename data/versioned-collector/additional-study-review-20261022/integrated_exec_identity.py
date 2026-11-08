#!/usr/bin/env python3
"""Versioned exec-inode integration derived from the frozen benign candidate."""

import argparse
import ast
import hashlib
import json
import os
import select
import signal
import subprocess
import tempfile
from pathlib import Path

import exec_identity


SCHEMA = "2026-10-23.20-exec-identity-candidate"
FROZEN_INTEGRATION_SHA256 = "51731965c773ed03438b089b10e5a73c9ec4554c89fd010b55080c4617042a21"


def start_trace(run_dir, target_pid, request):
    readiness = os.open(run_dir / "exec-ready", os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not select.select([readiness], [], [], 5)[0] or os.read(readiness, 64) != b"READY\n":
            raise ValueError("Existing Bash did not reach its pre-target gate")
    finally:
        os.close(readiness)
    private = tempfile.TemporaryDirectory(prefix="hazim-exec-", dir="/run")
    directory = Path(private.name)
    output = directory / "result.json"
    trace_request = directory / "request.json"
    trace_request.write_text(json.dumps({"pid": target_pid, "sha256": request["sample_sha256"],
        "allowed_sha256": [request["sample_sha256"]], "seconds": 28, "output": str(output)}))
    trace_request.chmod(0o600)
    log = (run_dir / "exec-identity.log").open("xb")
    process = subprocess.Popen(["/usr/bin/python3", str(Path(exec_identity.__file__).resolve()), "--watch", str(trace_request)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log, start_new_session=True)
    handle = {"private": private, "output": output, "process": process, "log": log}
    try:
        response = read_message(process, 5)
        if response["pid"] != target_pid:
            raise ValueError("Exec observer attached to another task")
    except BaseException:
        stop_trace(handle)
        raise
    return handle


def finish_trace(handle, run_dir, result, request, target_pid):
    if handle is None or handle["process"].wait(timeout=6) != 0:
        raise ValueError("Exec observer failed; preserve its report")
    report = json.loads(handle["output"].read_text())
    events = [json.loads(line) for line in (run_dir / "attribution.jsonl").read_text().splitlines()]
    result["executable_identity"] = exec_identity.validate_receipts(report, target_pid, request["sample_sha256"], events)


def stop_trace(handle):
    if handle is None:
        return
    process = handle["process"]
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
    handle["log"].close()
    if handle["output"].is_file():
        with (Path(handle["log"].name).parent / "exec-identity.json").open("x") as stream:
            stream.write(handle["output"].read_text())
    handle["private"].cleanup()


def load_frozen():
    original = Path(__file__).with_name("integrated_attribution.py")
    if hashlib.sha256(original.read_bytes()).hexdigest() != FROZEN_INTEGRATION_SHA256:
        raise ValueError("Frozen integration changed")
    tree = ast.parse(original.read_text())
    tree.body = [node for node in tree.body if not isinstance(node, ast.If)]
    broker = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "broker")
    broker.body[:0] = ast.parse("identity = None").body
    capture = next(node for node in broker.body if isinstance(node, ast.Try))
    replacement = []
    sites = []
    for statement in capture.body:
        text = ast.unparse(statement)
        if text.startswith("signal.signal(signal.SIGALRM,"):
            replacement.extend(ast.parse("identity = start_trace(run_dir, target_pid, request)").body)
            sites.append("attach")
        replacement.append(statement)
        if isinstance(statement, ast.If) and ast.unparse(statement.test) == "process.wait(timeout=10) != 0":
            replacement.extend(ast.parse("finish_trace(identity, run_dir, result, request, target_pid)").body)
            sites.append("finish")
    if sites != ["attach", "finish"]:
        raise ValueError("Frozen broker lifecycle sites differ: " + repr(sites))
    capture.body = replacement
    capture.finalbody[:0] = ast.parse("stop_trace(identity)").body
    capture.finalbody.extend(ast.parse("for evidence_name in ('exec-identity.json', 'exec-identity.log'):\n    if (run_dir / evidence_name).is_file():\n        os.chown(run_dir / evidence_name, *owner)").body)
    namespace = {"__file__": __file__, "__name__": "frozen_exec_integration",
                 "start_trace": start_trace, "finish_trace": finish_trace, "stop_trace": stop_trace}
    exec(compile(ast.fix_missing_locations(tree), str(original), "exec"), namespace)
    namespace["SCHEMA"] = SCHEMA
    return namespace


FROZEN = load_frozen()
digest = FROZEN["digest"]
save = FROZEN["save"]
read_message = FROZEN["read_message"]
audit_records = FROZEN["audit_records"]
BASE_SHA256 = FROZEN["BASE_SHA256"]
broker = FROZEN["broker"]


class Session(FROZEN["Session"]):
    def prepare(self, run_dir, sample):
        super().prepare(run_dir, sample)
        os.mkfifo(self.run_dir / "exec-ready", 0o600)

    def wrap(self, command):
        super().wrap(command)
        return ["/bin/bash", "-c",
                'printf "READY\\n" > "$2" || exit 125; IFS= read -r ready < "$1" || exit 125; test "$ready" = GO || exit 125; shift 2; exec "$@"',
                "sample-launch", str(self.run_dir / "attribution-gate"), str(self.run_dir / "exec-ready"), *command[4:]]

    def stop(self):
        try:
            return super().stop()
        finally:
            if self.run_dir is not None:
                (self.run_dir / "exec-ready").unlink(missing_ok=True)

    def quality(self, metadata, status, reasons):
        status, reasons = super().quality(metadata, status, reasons)
        if status != "accepted":
            return status, reasons
        try:
            report = json.loads((self.run_dir / "exec-identity.json").read_text())
            rows = [json.loads(line) for line in (self.run_dir / "attribution.jsonl").read_text().splitlines()]
            facts = exec_identity.validate_receipts(report, metadata["sample_root_pid"], digest(metadata["sample"]), rows)
            if facts != metadata["attribution"]["executable_identity"]:
                raise ValueError("Broker exec identity differs")
            metadata["executable_identity"] = {**facts, "evidence_sha256": digest(self.run_dir / "exec-identity.json"),
                "attestor_sha256": digest(exec_identity.__file__)}
        except (ValueError, KeyError, OSError) as error:
            return "rejected", [*reasons, "executable_identity_failed:" + str(error)]
        return status, reasons


def generate(base):
    tree = ast.parse(FROZEN["generate_base"](base))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "integrated_attribution":
                    alias.name = "integrated_exec_identity"
        elif isinstance(node, ast.Name) and node.id == "integrated_attribution":
            node.id = "integrated_exec_identity"
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


FROZEN["generate_base"] = FROZEN["generate"]
FROZEN["generate"] = generate


def self_test(base):
    FROZEN["self_test"](base)
    exec_identity.self_test()
    assert SCHEMA in generate(base) and "import integrated_exec_identity" in generate(base)
    print("PASS frozen broker derivation, exec identity attachment before release and preserved feature/helper ASTs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--broker", type=Path)
    action.add_argument("--self-test", type=Path)
    options = parser.parse_args()
    broker(options.broker) if options.broker else self_test(options.self_test)