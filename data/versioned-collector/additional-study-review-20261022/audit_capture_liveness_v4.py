"""Saved-only V4 audit with exact JSON case-fact comparison."""

import argparse
import ast
import copy
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path

import capture_liveness_v4 as measured


PINS = {
    "capture_liveness_v4.py": "78dc41fc820c918051c9b386ffe18cf072e4b47c714a2158e2b2e9873bab1545",
    "CAPTURE_LIVENESS_PROTOCOL_V4.md": "a8e4bb19b27afd3adac8a5faeb7a523e6b64d991c95130e3af11a63f1f8bd1b8",
}


def same_case_facts(actual, saved):
    return json.loads(json.dumps(actual)) == saved


def self_test():
    actual = [{"case": "full-quiet", "v6": {"kinds": {1: 19, 2: 18}, "observations": 39,
                                                "error_loss_counters": {1: 0, 2: 0}}}]
    saved = json.loads(json.dumps(actual))
    measured.checks.require(same_case_facts(actual, saved), "JSON integer-key round trip rejected")
    for corruption in ("kind", "loss", "observations", "scalar_type", "missing", "case"):
        changed = copy.deepcopy(saved)
        if corruption == "kind":
            changed[0]["v6"]["kinds"]["1"] += 1
        elif corruption == "loss":
            changed[0]["v6"]["error_loss_counters"]["1"] = 1
        elif corruption == "observations":
            changed[0]["v6"]["observations"] += 1
        elif corruption == "scalar_type":
            changed[0]["v6"]["observations"] = "39"
        elif corruption == "missing":
            del changed[0]["v6"]["kinds"]["2"]
        else:
            changed[0]["case"] = "full-pre"
        measured.checks.require(not same_case_facts(actual, changed), "Altered case facts accepted: " + corruption)
    print("PASS exact JSON key round trip and six changed sensor/case/type/missing-field guards")


def audit(attempt):
    for name, digest in PINS.items():
        measured.checks.require(measured.checks.digest(measured.ROOT / name) == digest, "Measured V4 source changed: " + name)
    tree = ast.parse(inspect.getsource(measured.lifecycle.audit_saved))
    original = ast.parse('result["cases"] == report["cases"]', mode="eval").body
    replacements = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args and ast.dump(node.args[0]) == ast.dump(original):
            node.args[0] = ast.Call(func=ast.Name(id="same_case_facts", ctx=ast.Load()),
                                    args=[original.left, original.comparators[0]], keywords=[])
            replacements += 1
    measured.checks.require(replacements == 1, "Frozen case comparison anchor differs")
    namespace = dict(vars(measured.lifecycle))
    namespace["same_case_facts"] = same_case_facts
    exec(compile(ast.fix_missing_locations(tree), "<saved-only-v4-json-audit>", "exec"), namespace)
    result = namespace["audit_saved"](attempt)
    startup_path = attempt / "startup-readiness.json"
    result.update(startup=measured.audit_startup(json.loads(startup_path.read_text())),
                  startup_receipt_sha256=measured.checks.digest(startup_path),
                  saved_only_auditor_sha256=measured.checks.digest(__file__),
                  case_comparison="Exact JSON representation; integer dictionary keys round-trip to strings only",
                  case_comparison_corruption_guards=6)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    self_test()
    if options.attempt:
        attempt = options.attempt.resolve()
        result = audit(attempt)
        output = attempt / ("audit-v4-derived-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        measured.integration.save(output, result)
        print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "output": str(output),
                          "collection_ready": False, "performance_accepted": False}, indent=2))