#!/usr/bin/env python3
"""Audit saved exec-inode evidence without guest, workload or model operations."""

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import check_exec_identity
import exec_identity
import integrated_exec_identity as integration


ROOT = Path(__file__).resolve().parent
FROZEN_AUDITOR_SHA256 = "28fe48360059cdef24dcaf768f0d1bbb6ac16df526d37a28b1e5d0f310437bae"
REJECTED = set()


def load_frozen():
    source = ROOT / "audit_integrated_attribution.py"
    if hashlib.sha256(source.read_bytes()).hexdigest() != FROZEN_AUDITOR_SHA256:
        raise ValueError("Frozen integrated auditor changed")
    tree = ast.parse(source.read_text())
    tree.body = [node for node in tree.body if not isinstance(node, ast.If)
                 and not (isinstance(node, ast.Import) and any(alias.name in
                          ("check_integrated_attribution", "integrated_attribution") for alias in node.names))]
    replacements = {
        "integrated_attribution.py": "integrated_exec_identity.py",
        "accepted_saved_integrated_benign_capture_audit": "accepted_saved_exec_inode_benign_capture_audit",
        "validation-derived-": "identity-validation-derived-",
        "Four bounded benign diagnostics only; no general exec-inode/hash, ownership, namespace/bypass/allocator, rate/performance or study allocation release; no .18 merge":
            "Four bounded native x86 benign images attested at exec stops; no library/interpreter, non-leader exec, general ownership/namespace/bypass/allocator, rate/performance or study allocation release; no .18 merge",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = replacements.get(node.value, node.value)
    namespace = {"__file__": __file__, "__name__": "frozen_exec_identity_auditor",
                 "driver": SimpleNamespace(**check_exec_identity.FROZEN), "integration": integration}
    exec(compile(ast.fix_missing_locations(tree), str(source), "exec"), namespace)
    return namespace


FROZEN = load_frozen()


def validate_capture(directory, manifest, case):
    facts = FROZEN["validate_capture_base"](directory, manifest, case)
    metadata = json.loads((directory / "run.json").read_text())
    original = json.loads((directory / "exec-identity.json").read_text())
    original_events = [json.loads(line) for line in (directory / "attribution.jsonl").read_text().splitlines()]
    for kind in ("hash", "inode", "namespace", "duplicate", "task_start", "clock_order", "missing_kernel_exec", "live_task"):
        report = copy.deepcopy(original)
        events = copy.deepcopy(original_events)
        receipt = report["exec_receipts"][0]
        if kind == "hash":
            receipt["image"]["sha256"] = "0" * 64
        elif kind == "inode":
            receipt["image"]["inode"] = 0
        elif kind == "namespace":
            receipt["namespaces"]["net"] += 1
        elif kind == "duplicate":
            report["exec_receipts"].append(copy.deepcopy(receipt))
        elif kind == "task_start":
            receipt["start_ticks"] += 1
        elif kind == "clock_order":
            receipt["stop_observed_ns"] = 0
        elif kind == "missing_kernel_exec":
            events = [row for row in events if row.get("kind") != 9]
        else:
            report["live_tasks"] = [receipt["pid"]]
        try:
            exec_identity.validate_receipts(report, metadata["sample_root_pid"], facts["target_sha256"], events)
        except ValueError:
            REJECTED.add(kind)
        else:
            raise AssertionError("Altered exec receipt accepted: " + kind)
    return facts


FROZEN["validate_capture_base"] = FROZEN["validate_capture"]
FROZEN["validate_capture"] = validate_capture


def audit(attempt):
    REJECTED.clear()
    report = FROZEN["audit"](attempt)
    report["exec_receipt_negative_guards"] = sorted(REJECTED)
    report["frozen_auditor_sha256"] = FROZEN_AUDITOR_SHA256
    report["executed_inodes_verified"] = sum(row["executed_inode"]["exec_count"] for row in report["results"])
    output = attempt / ("identity-validation-complete-" + FROZEN["datetime"].now(FROZEN["timezone"].utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    integration.save(output, report)
    print(output)
    print(json.dumps({key: report[key] for key in ("executed_inodes_verified", "exec_receipt_negative_guards")}))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    audit(parser.parse_args().attempt.resolve())