#!/usr/bin/env python3
"""Prospective benchmark-only decision oracle, not a guest or raw-evidence auditor."""

import argparse
import ast
import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
PRODUCTION_SHA256 = "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49"
NO_TRAFFIC = "packet_capture_interface_no_traffic"
CONTROL_ORDER = ("original-pre", "full-pre", "full-post", "original-post")
BODY_SHA256 = "f0a3eec2709682107edae2372e8984e15bd3b2b7e3de9878ba76cd69cc556ce0"
COUNTERS = ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_dropped", "tx_dropped")
PROFILE = {"observation_seconds": 20, "window_seconds": 0.5, "interface": "enp0s3",
           "packet_buffer_kib": 65536, "packet_drain_ms": 1000, "immediate_mode": True,
           "perf_pages": 16384, "capture_filter": None}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum, "Missing, boolean or invalid integer evidence")
    return value


def sha256(value):
    require(type(value) is str and len(value) == 64 and
            all(character in "0123456789abcdef" for character in value), "Invalid SHA-256 evidence identity")
    return value


@lru_cache(maxsize=1)
def original_quality():
    source = STUDY / "src/malware_runner.py"
    require(digest(source) == PRODUCTION_SHA256, "Frozen production source changed")
    tree = ast.parse(source.read_text())
    definitions = [node for node in tree.body if
                   isinstance(node, ast.FunctionDef) and node.name == "assess_collection_quality" or
                   isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                   target.id == "INTERFACE_DOWN_OPERSTATES" for target in node.targets)]
    require(len(definitions) == 2, "Original quality definition anchors differ")
    namespace = {}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["assess_collection_quality"]


def validate_capture(facts):
    context = facts["context"]
    uuid.UUID(context["boot_id"])
    uuid.UUID(context["snapshot_uuid"])
    uuid.UUID(context["attempt_id"])
    sha256(context["attempt_manifest_sha256"])
    integer(context["network_namespace"], 1)
    require(context["base_runner_sha256"] == PRODUCTION_SHA256 and context["capture_profile"] == PROFILE,
            "Capture source/profile differs")
    require(all(type(context["capture_profile"][name]) is type(value) for name, value in PROFILE.items()),
        "Capture profile value types differ")
    started = integer(facts["started_ns"], 1)
    ended = integer(facts["ended_ns"], started + 1)
    require(integer(facts["case_started_ns"], 1) < started < ended < integer(facts["case_finished_ns"], 1),
        "Observation is not inside the complete case envelope")
    require(facts["packet_capture_status"] == facts["ebpf_status"] == "active", "Inactive sensor")
    statistics = facts["packet_statistics"]
    records = integer(facts["independent_pcap_records"])
    require(integer(statistics["packets_received_by_filter"]) ==
            integer(statistics["packets_captured"]) == records, "PCAP record/counter gap")
    for value in (statistics["dropped_by_kernel"], facts["ebpf_lost_event_count"],
                  facts["raw_syscalls_unresolved_abi"]):
        require(integer(value) == 0, "Observed sensor loss or unresolved ABI")
    require(integer(facts["rmem_before"], 1) == integer(facts["rmem_after"], 1) and
            facts["buffer_restore_error"] is None, "Buffer restoration differs")
    before, after = facts["interface_before"], facts["interface_after"]
    for link in (before, after):
        require(link["operstate"] == "up" and integer(link["carrier"]) == 1, "Missing/down link evidence")
        require(facts["case_started_ns"] <= integer(before["monotonic_ns"]) <= started < ended <=
            integer(after["monotonic_ns"]) <= facts["case_finished_ns"],
            "Interface receipts do not cover observation")
    deltas = {name: integer(after[name]) - integer(before[name]) for name in COUNTERS}
    require(all(value >= 0 for value in deltas.values()) and
            deltas["rx_dropped"] == deltas["tx_dropped"] == 0, "NIC reset/drop")
    status, reasons = original_quality()(True, "active", 0, True, "active", 0,
                                        packet_capture_statistics=statistics,
                                        interface_counter_deltas=deltas,
                                        interface_link_state={"operstate": before["operstate"], "carrier": before["carrier"]})
    require(facts["original_quality"] == {"status": status, "reasons": reasons},
            "Original quality result was changed or does not reproduce")
    return status, reasons, deltas


def evaluate(case, controls):
    """Consume independently audited facts; never establish raw provenance or performance acceptance."""
    result = {"status": "rejected", "benchmark_capture_eligible": False,
              "performance_accepted": False, "collection_ready": False,
              "evidence_scope": "Decision-oracle output only; raw audit and future guest integration required"}
    try:
        require(case["scope"] == "benign_scoped_performance" and case["task"] in ("file", "network") and
                case["condition"] in ("original", "full"), "Outside benchmark-only instrumented scope")
        status, reasons, deltas = validate_capture(case)
        quiet = status == "rejected" and reasons == [NO_TRAFFIC]
        require(status == "accepted" and not reasons or quiet, "Other quality rejection remains blocking")
        if quiet:
            require(all(value == 0 for value in deltas.values()), "Quiet interface bytes/counters disagree")
        require([control["id"] for control in controls] == list(CONTROL_ORDER), "Missing/reordered/extra controls")
        require(len({control["evidence_sha256"] for control in controls}) == 4, "Reused control evidence")
        require(len({control["transaction"]["request_sha256"] for control in controls}) == 4, "Reused control transaction")
        require(all(earlier["case_finished_ns"] < later["case_started_ns"]
                for earlier, later in zip(controls, controls[1:])), "Control raw clock order differs")
        for control in controls:
            sha256(control["evidence_sha256"])
            control_status, control_reasons, _deltas = validate_capture(control)
            require(control_status == "accepted" and not control_reasons and
                    control["independent_pcap_records"] > 0, "Positive control was not recovered")
            require(control["context"] == case["context"], "Control boot/namespace/capture profile differs")
            require(control["condition"] == control["id"].split("-")[0], "Control condition differs")
            if control["id"].endswith("pre"):
                require(control["case_finished_ns"] < case["case_started_ns"], "Pre-control overlaps benchmark setup")
            else:
                require(case["case_finished_ns"] < control["case_started_ns"], "Post-control overlaps benchmark teardown")
            transaction = control["transaction"]
            sha256(transaction["request_sha256"])
            require(control["case_started_ns"] <= integer(transaction["started_ns"], 1) <
                    integer(transaction["ended_ns"], 1) <= control["started_ns"] and
                    transaction["ended_ns"] - transaction["started_ns"] <= 2_000_000_000,
                    "Helper escaped its separate control or original two-second bound")
            require(integer(control["helper_transactions"]) == 1 and
                    transaction["helper_outside_target_cgroup"] is True and
                    transaction["application_and_pcap_recovery"] is True and
                    transaction["destination"] == ["10.0.0.1", 80] and
                    integer(transaction["http_status"]) == 200 and
                    integer(transaction["body_bytes"]) == 258 and transaction["body_sha256"] == BODY_SHA256,
                    "Exact bounded internal positive-control proof differs")
        require(integer(case["intentional_helper_transactions"]) == 0, "Measured case contains helper traffic")
        result.update(status="quiet_with_bracketing_controls_not_completeness_proof" if quiet else
                      "original_quality_accepted_with_bracketing_controls",
                      benchmark_capture_eligible=True, original_quality=copy.deepcopy(case["original_quality"]))
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        result["reason"] = str(error)
    return result


def synthetic_fixture():
    context = {"boot_id": "00000000-0000-4000-8000-000000000001", "network_namespace": 4026531833,
               "snapshot_uuid": "00000000-0000-4000-8000-000000000002",
               "attempt_id": "00000000-0000-4000-8000-000000000003",
               "attempt_manifest_sha256": hashlib.sha256(b"SYNTHETIC manifest").hexdigest(),
               "base_runner_sha256": PRODUCTION_SHA256, "capture_profile": copy.deepcopy(PROFILE)}
    case = {"scope": "benign_scoped_performance", "task": "file", "condition": "original", "context": context,
            "started_ns": 100, "ended_ns": 200, "case_started_ns": 95, "case_finished_ns": 205,
            "packet_capture_status": "active", "ebpf_status": "active",
            "packet_statistics": {"packets_received_by_filter": 0, "packets_captured": 0, "dropped_by_kernel": 0},
            "independent_pcap_records": 0, "ebpf_lost_event_count": 0, "raw_syscalls_unresolved_abi": 0,
            "rmem_before": 4194304, "rmem_after": 4194304, "buffer_restore_error": None,
            "original_quality": {"status": "rejected", "reasons": [NO_TRAFFIC]},
            "intentional_helper_transactions": 0}
    for field, timestamp in (("interface_before", 99), ("interface_after", 201)):
        case[field] = {"operstate": "up", "carrier": 1, "monotonic_ns": timestamp,
                       **{name: 100 for name in COUNTERS}}
    controls = []
    for index, name in enumerate(CONTROL_ORDER):
        control = copy.deepcopy(case)
        started = (10 + index * 20) if name.endswith("pre") else (300 + index * 20)
        control.update(id=name, condition=name.split("-")[0], started_ns=started, ended_ns=started + 5,
                       case_started_ns=started - 3, case_finished_ns=started + 7,
                       evidence_sha256=hashlib.sha256(name.encode()).hexdigest(), independent_pcap_records=2,
                       helper_transactions=1, original_quality={"status": "accepted", "reasons": []},
                       packet_statistics={"packets_received_by_filter": 2, "packets_captured": 2, "dropped_by_kernel": 0},
                       transaction={"helper_outside_target_cgroup": True, "application_and_pcap_recovery": True,
                                    "started_ns": started - 2, "ended_ns": started - 1,
                                    "destination": ["10.0.0.1", 80], "http_status": 200, "body_bytes": 258,
                                    "body_sha256": BODY_SHA256, "request_sha256": hashlib.sha256(name.encode()).hexdigest()})
        control["interface_before"]["monotonic_ns"] = started - 1
        control["interface_after"].update(monotonic_ns=started + 6, rx_packets=101, tx_packets=101, rx_bytes=101, tx_bytes=101)
        controls.append(control)
    return case, controls


def self_test():
    case, controls = synthetic_fixture()
    original_inputs = copy.deepcopy((case, controls))
    accepted = evaluate(case, controls)
    require(accepted["benchmark_capture_eligible"] and accepted["original_quality"]["status"] == "rejected" and
            not accepted["performance_accepted"] and not accepted["collection_ready"], "Quiet predicate/provenance changed")
    require((case, controls) == original_inputs, "Policy mutated original facts")
    guards = {
        "missing_controls": lambda changed, bracket: bracket.clear(),
        "foreign_boot": lambda changed, bracket: bracket[0]["context"].update(boot_id="00000000-0000-4000-8000-000000000002"),
        "foreign_namespace": lambda changed, bracket: bracket[1]["context"].update(network_namespace=1),
        "different_profile": lambda changed, bracket: bracket[0]["context"]["capture_profile"].update(packet_buffer_kib=64),
        "late_pre": lambda changed, bracket: changed.update(started_ns=10),
        "early_post": lambda changed, bracket: changed.update(ended_ns=400),
        "unrecovered_http": lambda changed, bracket: bracket[0]["transaction"].update(application_and_pcap_recovery=False),
        "helper_in_target": lambda changed, bracket: bracket[0]["transaction"].update(helper_outside_target_cgroup=False),
        "unexpected_destination": lambda changed, bracket: bracket[0]["transaction"].update(destination=["10.0.0.2", 80]),
        "positive_ebpf_loss": lambda changed, bracket: changed.update(ebpf_lost_event_count=1),
        "packet_gap": lambda changed, bracket: changed["packet_statistics"].update(packets_received_by_filter=1),
        "missing_abi": lambda changed, bracket: changed.pop("raw_syscalls_unresolved_abi"),
        "missing_link": lambda changed, bracket: changed.pop("interface_after"),
        "buffer_restore": lambda changed, bracket: changed.update(rmem_after=134217728),
        "nic_drop": lambda changed, bracket: changed["interface_after"].update(rx_dropped=101),
        "quiet_byte_drift": lambda changed, bracket: changed["interface_after"].update(rx_bytes=101),
        "quality_relabel": lambda changed, bracket: changed.update(original_quality={"status": "accepted", "reasons": []}),
        "helper_padding": lambda changed, bracket: changed.update(intentional_helper_transactions=1),
        "collection_scope": lambda changed, bracket: changed.update(scope="malware_collection"),
        "bool_counter": lambda changed, bracket: changed.update(independent_pcap_records=False),
        "duplicate_control": lambda changed, bracket: bracket.__setitem__(1, copy.deepcopy(bracket[0])),
        "foreign_attempt": lambda changed, bracket: bracket[0]["context"].update(attempt_id="00000000-0000-4000-8000-000000000004"),
        "foreign_snapshot": lambda changed, bracket: bracket[0]["context"].update(snapshot_uuid="00000000-0000-4000-8000-000000000004"),
        "foreign_manifest": lambda changed, bracket: bracket[0]["context"].update(attempt_manifest_sha256="a" * 64),
        "control_clock_order": lambda changed, bracket: bracket[0].update(case_finished_ns=30),
        "setup_overlap": lambda changed, bracket: changed.update(case_started_ns=26),
        "teardown_overlap": lambda changed, bracket: changed.update(case_finished_ns=340),
        "helper_outside_control": lambda changed, bracket: bracket[0]["transaction"].update(started_ns=1),
        "invalid_request_identity": lambda changed, bracket: bracket[0]["transaction"].update(request_sha256="not-a-digest"),
        "profile_bool": lambda changed, bracket: changed["context"]["capture_profile"].update(immediate_mode=1),
        "changed_http_body": lambda changed, bracket: bracket[0]["transaction"].update(body_sha256="a" * 64),
        "extra_transaction": lambda changed, bracket: bracket[0].update(helper_transactions=2),
    }
    for name, corrupt in guards.items():
        changed, bracket = copy.deepcopy(case), copy.deepcopy(controls)
        corrupt(changed, bracket)
        require(not evaluate(changed, bracket)["benchmark_capture_eligible"], "Corruption accepted: " + name)
    active = copy.deepcopy(case)
    active.update(independent_pcap_records=1, original_quality={"status": "accepted", "reasons": []},
                  packet_statistics={"packets_received_by_filter": 1, "packets_captured": 1, "dropped_by_kernel": 0})
    active["interface_after"].update(rx_packets=101, rx_bytes=101)
    require(evaluate(active, controls)["benchmark_capture_eligible"], "Original accepted capture rejected")
    for condition in ("original", "full"):
        for task in ("file", "network"):
            changed = {**case, "condition": condition, "task": task}
            require(evaluate(changed, controls)["benchmark_capture_eligible"], "Declared benchmark scope differs")
    print("PASS SYNTHETIC decision oracle: preserved original quiet rejection, normal capture, four scoped combinations, " +
          str(len(guards)) + " fail-closed guards; no empirical capture/performance/release acceptance")
    return list(guards)


def specification(guards):
    pins = {"run_performance_v3.py": "d135febab6234fa2c8efc6166a0b133c73c6b0fcc004057c01b15c92d647f1c6",
            "performance_v3.py": "73acfd00f9f8e28132dcfe8ba92c03fc9e359d5bcaff9e9654001182031634ef",
            "audit_performance_v3.py": "b46625318d1d85bda0cc599319c03f224608ddf169144a50b58c80f2903b25c7",
            "PERFORMANCE_V3_ATTEMPT_PROTOCOL.md": "2d3c7ab2e160d9d67bcb1876a26b5d4c9c5794a69b711d96d10844013883b37e"}
    for name, expected in pins.items():
        require(digest(ROOT / name) == expected, "Measured V3 input changed: " + name)
    return {"schema": "2026-10-23.benchmark-quiet-policy.v1", "status": "local_policy_not_guest_integrated",
            "authorization": {"user_request": "okay let's go with your thoughts and instincts",
                              "policy_development": True, "quality_amendment_effective": False,
                              "vm_execution": False, "fresh_performance_attempts": 0, "full_collection": False},
            "benchmark_cases": 84, "scored_cases": 60, "separate_positive_controls": 4, "maximum_total_captures": 88,
            "control_order": {"pre": list(CONTROL_ORDER[:2]), "post": list(CONTROL_ORDER[2:])},
            "profile": PROFILE, "benchmark_recorder_seconds": 22, "benchmark_ack_seconds": 12,
            "separate_diagnostic_recorder_seconds": 28,
            "limits": {"median_wall_ratio_max": 1.10, "every_pair_wall_ratio_max": 1.25,
                       "median_task_cpu_ratio_max": 1.15, "recorder_rss_mib_max": 256},
            "original_quality_preserved": True, "quiet_interval_completeness_proven": False,
            "raw_control_auditor_implemented": False, "guest_adapter_implemented": False,
            "performance_accepted": False, "collection_ready": False, "existing_417_assignments_unchanged": True,
            "synthetic_negative_guards": guards,
            "source_hashes": {**{str(ROOT / name): value for name, value in pins.items()},
                              str(STUDY / "src/malware_runner.py"): PRODUCTION_SHA256,
                              str(Path(__file__).resolve()): digest(__file__),
                              str(ROOT / "BENCHMARK_QUIET_POLICY_V1.md"): digest(ROOT / "BENCHMARK_QUIET_POLICY_V1.md")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write-contract", action="store_true")
    options = parser.parse_args()
    require(options.self_test or options.write_contract, "Choose --self-test or --write-contract; no launch CLI exists")
    guards = self_test()
    if options.write_contract:
        contract = specification(guards)
        destination = ROOT / "benchmark-quiet-policy-proposals" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        destination.mkdir(parents=True, exist_ok=False)
        with (destination / "contract.json").open("x") as stream:
            json.dump(contract, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(destination)
        print("Local policy only: no raw control audit, guest adapter, VM launch or accepted performance result")


if __name__ == "__main__":
    main()