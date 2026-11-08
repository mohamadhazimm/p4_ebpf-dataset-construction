#!/usr/bin/env python3
"""Freeze and execute a separately versioned benign exec-inode integration gate."""

import argparse
import ast
import hashlib
import json
from pathlib import Path

import exec_identity
import integrated_exec_identity as integration


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
FROZEN_DRIVER_SHA256 = "55f556320f6ac4121338b57d8a28e6bc39ed9a811916a0e3c0624d24342017af"


def load_frozen():
    source = ROOT / "check_integrated_attribution.py"
    if hashlib.sha256(source.read_bytes()).hexdigest() != FROZEN_DRIVER_SHA256:
        raise ValueError("Frozen integrated guest driver changed")
    tree = ast.parse(source.read_text())
    tree.body = [node for node in tree.body if not isinstance(node, ast.If)]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "integrated_attribution":
                    alias.name = "integrated_exec_identity"
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            replacements = {"integrated-collector-readiness": "exec-identity-readiness",
                "clean-integrated-": "clean-exec-identity-", "/home/csci/Downloads/integrated-": "/home/csci/Downloads/exec-identity-"}
            node.value = replacements.get(node.value, node.value)
    freeze_function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "freeze")
    payload = next(node for node in freeze_function.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "payload" for target in node.targets))
    for key in payload.value.keys:
        if isinstance(key, ast.Constant) and key.value == "integrated_attribution.py":
            key.value = "integrated_exec_identity.py"
    for name, expression in (("integrated_attribution.py", "ROOT / 'integrated_attribution.py'"),
                             ("exec_identity.py", "ROOT / 'exec_identity.py'"),
                             ("check_integrated_attribution.py", "ROOT / 'check_integrated_attribution.py'")):
        payload.value.keys.append(ast.Constant(name))
        payload.value.values.append(ast.parse(expression, mode="eval").body)
    namespace = {"__file__": __file__, "__name__": "frozen_identity_guest_driver"}
    exec(compile(ast.fix_missing_locations(tree), str(source), "exec"), namespace)
    return namespace


FROZEN = load_frozen()


def audit_run(directory, manifest, case):
    facts = FROZEN["audit_run_base"](directory, manifest, case)
    metadata = json.loads((directory / "run.json").read_text())
    report = json.loads((directory / "exec-identity.json").read_text())
    events = [json.loads(line) for line in (directory / "attribution.jsonl").read_text().splitlines()]
    identity = exec_identity.validate_receipts(report, metadata["sample_root_pid"], facts["target_sha256"], events)
    expected = {**identity, "evidence_sha256": integration.digest(directory / "exec-identity.json"),
                "attestor_sha256": manifest["files"]["exec_identity.py"]}
    if metadata.get("executable_identity") != expected:
        raise ValueError("Actual executable identity differs from collector metadata")
    return {**facts, "executed_inode": expected}


FROZEN["audit_run_base"] = FROZEN["audit_run"]
FROZEN["audit_run"] = audit_run
runner_command = FROZEN["runner_command"]
guest = FROZEN["guest"]
freeze = FROZEN["freeze"]
execute = FROZEN["execute"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--guest", type=Path)
    options = parser.parse_args()
    if options.guest:
        raise SystemExit(0 if guest(options.guest.resolve()) else 2)
    elif options.self_test:
        integration.self_test(STUDY / "src/malware_runner.py")
        print("PASS frozen driver derivation and explicit exec-inode receipt audit")
    else:
        attempt, manifest = freeze()
        if options.execute_benign_checks:
            import signal
            signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
            execute(attempt, manifest)