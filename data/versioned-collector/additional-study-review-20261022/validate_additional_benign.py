#!/usr/bin/env python3
"""Preserve the first host task protocol and correct only xmlwf output handling."""

import argparse
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path

import additional_benign_workloads as original
from validate_remediation_workloads import digest, expect, save


ROOT = original.ROOT
PREVIOUS = ROOT / "additional-benign-workloads/20261023T064923411538Z"


def xml_error(stdout, stderr):
    diagnostic = stdout + stderr
    return b"invalid.xml:" in diagnostic and b"mismatched tag" in diagnostic


def adapted_task():
    source = inspect.getsource(original.task)
    old = 'expect(bool(command(["invalid.xml"], 2).stderr), "Malformed XML diagnostic absent")'
    new = 'malformed = command(["invalid.xml"], 2)\n        expect(xml_error(malformed.stdout, malformed.stderr), "Malformed XML diagnostic differs")'
    expect(source.count(old) == 1, "Frozen xmlwf correction boundary changed")
    source = source.replace(old, new)
    old_receipt = 'expect(result.returncode == expected_return, "Unexpected task return: " + str(receipts[-1]))'
    expect(source.count(old_receipt) == 1, "Frozen command receipt boundary changed")
    source = source.replace(old_receipt, 'save(work / ("command-%02d.json" % number), receipts[-1])\n        ' + old_receipt)
    namespace = dict(vars(original), xml_error=xml_error)
    exec(compile(source, "additional-benign-validated-task-v2", "exec"), namespace)
    return namespace["task"], source


def run():
    protocol_path = PREVIOUS / "protocol.json"
    result_path = PREVIOUS / "result.json"
    protocol = json.loads(protocol_path.read_text())
    previous = json.loads(result_path.read_text())
    for name, expected in protocol["input_hashes"].items():
        expect(digest(Path(name)) == expected, "Frozen original workload input changed: " + name)
    rows = {(row["unit"], row["mode"]): row for row in protocol["executables"]}
    expect(len(rows) == 24 and len(previous["results"]) == 24, "Unexpected original task population")
    target_task, source = adapted_task()
    attempt = ROOT / "additional-benign-workloads" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    payload = attempt / "validated_task.py"
    with payload.open("x") as output:
        output.write(source)
    inputs = dict(protocol["input_hashes"])
    inputs.update({str(protocol_path): digest(protocol_path), str(result_path): digest(result_path), str(Path(__file__)): digest(Path(__file__)), str(payload): digest(payload)})
    save(attempt / "protocol.json", {"schema": "additional-benign-host-tasks-v2", "input_hashes": inputs,
         "executables": list(rows.values()), "original_attempt": str(PREVIOUS),
         "correction": "xmlwf syntax diagnostics may use stdout; require exact fixture name and mismatched-tag text, valid exit0 and invalid exit2",
         "reuse": "rehash all original accepted case inputs, outputs and actual stdout/stderr receipts; rerun only the two previously failed xmlwf checks",
         "generated_task_source": str(payload), "source_namespace": str(Path(original.__file__)),
         "collection_ready": False, "vm_operations": 0, "model_fits": 0, "roles_or_quotas_assigned": False})
    report = {"status": "running", "results": [], "collection_ready": False, "guest_validated": False,
              "target_variants_executed_this_attempt": 0, "reused_accepted_variants": 0}
    seen = set()
    try:
        for result in previous["results"]:
            identity = (result["unit"], result["mode"])
            expect(identity in rows and identity not in seen, "Duplicate or unexpected original case")
            seen.add(identity)
            row = rows[identity]
            expect(digest(Path(row["path"])) == row["sha256"], "Target bytes changed")
            if result["status"] == "accepted":
                work = PREVIOUS / (row["project"] + "-" + row["mode"])
                expect(result["executable_sha256"] == row["sha256"], "Original accepted identity differs")
                for name, expected in dict(result["inputs"], **result["outputs"]).items():
                    expect(digest(work / name) == expected, "Original accepted task artifact changed")
                for index, receipt in enumerate(result["receipts"]):
                    expect(receipt["returncode"] == receipt["expected_returncode"], "Original command was not accepted")
                    expect(digest(work / ("stdout-%02d.bin" % index)) == receipt["stdout_sha256"], "Original stdout receipt changed")
                    expect(digest(work / ("stderr-%02d.bin" % index)) == receipt["stderr_sha256"], "Original stderr receipt changed")
                report["results"].append(dict(result, reused_from=str(work)))
                report["reused_accepted_variants"] += 1
            else:
                expect(row["project"] == "expat" and result["error"] == "ValueError: Malformed XML diagnostic absent", "Unexpected failed task needs independent review")
                work = attempt / (row["project"] + "-" + row["mode"])
                report["results"].append(target_task(row, work))
                report["target_variants_executed_this_attempt"] += 1
            print("ACCEPTED", row["unit"], row["mode"], flush=True)
        expect(len(seen) == 24 and report["reused_accepted_variants"] == 22 and report["target_variants_executed_this_attempt"] == 2, "Task reuse/execution boundary differs")
        expect(all(digest(Path(name)) == expected for name, expected in inputs.items()), "Frozen input changed")
        report["status"] = "accepted_host_tasks_guest_pending"
    except Exception as error:
        report.update(status="failed_preserved", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        save(attempt / "result.json", report)
        print(attempt, flush=True)


def self_test():
    original.self_test()
    expect(xml_error(b"invalid.xml:1:17: mismatched tag\n", b""), "Actual stdout diagnostic rejected")
    expect(xml_error(b"", b"invalid.xml:1:17: mismatched tag\n"), "Stderr diagnostic rejected")
    expect(not xml_error(b"valid.xml:1:17: mismatched tag", b""), "Wrong fixture accepted")
    expect(not xml_error(b"invalid.xml: permission denied", b""), "Unrelated failure accepted")
    adapted_task()
    print("PASS exact xmlwf fixture/diagnostic guards and bounded source adaptation; no workload")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--run", action="store_true")
    options = parser.parse_args()
    self_test() if options.self_test else run()