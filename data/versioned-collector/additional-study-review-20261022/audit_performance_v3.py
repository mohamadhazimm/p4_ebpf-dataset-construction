"""Saved-only V3 audit retaining the independently implemented V2 evidence gates."""

import argparse
import ast
import datetime
import inspect
import json
from pathlib import Path

import audit_performance_v2 as frozen
import run_performance_v3 as version


FROZEN_SHA256 = "272ddebf33498433d125dee4ec174887a588538993e2e50e05f6109576d81327"


def audit(attempt):
    if version.identity.digest(frozen.__file__) != FROZEN_SHA256:
        raise ValueError("Frozen independent V2 auditor changed")
    protocol = json.loads((attempt / "protocol.json").read_text())
    frozen.require(protocol["schema"] == version.performance.SCHEMA
                   and protocol["strict_quality_gate_unchanged"]
                   and not protocol["automatic_retry_authorized"]
                   and not protocol["malware_launch_authorized"], "V3 authorization/schema differs")
    tree = ast.parse(inspect.getsource(frozen.audit))
    namespace = {**vars(frozen), "version": version}
    exec(compile(tree, "<independent-v3-saved-audit>", "exec"), namespace)
    result = namespace["audit"](attempt)
    result["auditor_sha256"] = version.identity.digest(__file__)
    result["inherited_auditor_sha256"] = FROZEN_SHA256
    return result


def self_test():
    frozen.require(version.identity.digest(frozen.__file__) == FROZEN_SHA256, "Frozen auditor changed")
    frozen.self_test()
    rows = [{**case, "usage": {"wall_ns": 100, "user_seconds": .1, "system_seconds": .01},
             "recorder_usage": {"peak_rss_kib": 1024}} for case in version.gate.plan()]
    limits = version.gate.approved_contract()["performance_limits"]
    frozen.require(frozen.summary(rows, limits)["performance_accepted"], "Complete local fixture rejected")
    print("PASS independent V3 version binding and inherited incomplete/lifecycle/performance guards; SIMULATED only")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    self_test()
    if options.attempt:
        attempt = options.attempt.resolve()
        result = audit(attempt)
        output = attempt / ("audit-v3-derived-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        version.identity.save(output, result)
        print(output)
        print(json.dumps({key: result[key] for key in ("status", "performance_accepted", "collection_ready", "actual_cases", "accepted_measurements", "first_failing_pair")}, indent=2))