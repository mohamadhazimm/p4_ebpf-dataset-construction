"""Independently audit complete or stopped saved V2 performance evidence."""

import argparse
import copy
import csv
import datetime
import hashlib
import io
import json
import math
import statistics
from pathlib import Path

import check_performance_v2 as version
import audit_scoped_performance as original


require = original.require


def lifecycle(early, final, metadata):
    for key, value in early.items():
        require(final.get(key) == value, "Early/final lifecycle receipts differ")
    start, ended, finish, ack = (final[key] for key in
                                 ("observation_start_ns", "observation_end_ns", "finish_request_ns", "finish_ack_ns"))
    require(all(type(value) is int for value in (start, ended, finish, ack)), "Lifecycle clock type differs")
    require(start == metadata["sample_started_monotonic_ns"] and ended >= metadata["observation_ended_monotonic_ns"]
            and 20_000_000_000 <= ended - start, "Actual/model observation clocks differ")
    require(ended <= finish <= ack <= finish + 12_000_000_000
            and final["error"] is None and final["broker_status"] == "accepted", "Original12s FINISH/ACK or broker failure")
    return {"actual_end_ns": ended, "finish_delay_ns": finish - ended, "ack_interval_ns": ack - finish}


def summary(rows, limits):
    require(len(rows) == 84 and sum(not row["warmup"] for row in rows) == 60, "Incomplete benchmark cannot supply accepted medians")
    groups = []
    failures = []
    for abi in ("amd64", "i386"):
        for task in ("file", "network"):
            selected = [row for row in rows if row["abi"] == abi and row["task"] == task and not row["warmup"]]
            conditions = {name: sorted((row for row in selected if row["condition"] == name), key=lambda row: row["repeat"])
                          for name in ("baseline", "original", "full")}
            require(all([row["repeat"] for row in values] == list(range(5)) for values in conditions.values()), "Missing or repeated scored case")
            original_rows, full = conditions["original"], conditions["full"]
            wall = statistics.median(row["usage"]["wall_ns"] for row in full) / statistics.median(row["usage"]["wall_ns"] for row in original_rows)
            cpu = lambda row: row["usage"]["user_seconds"] + row["usage"]["system_seconds"]
            denominator = statistics.median(cpu(row) for row in original_rows)
            require(denominator > 0, "Nonpositive original task CPU denominator")
            cpu_ratio = statistics.median(cpu(row) for row in full) / denominator
            pairs = [actual["usage"]["wall_ns"] / reference["usage"]["wall_ns"] for actual, reference in zip(full, original_rows)]
            rss = max(row["recorder_usage"]["peak_rss_kib"] for row in full) / 1024
            checks = {"wall_median": wall <= limits["full_vs_original_task_wall_median_ratio_max"],
                      "wall_pairs": max(pairs) <= limits["full_vs_original_task_wall_any_pair_ratio_max"],
                      "cpu_median": cpu_ratio <= limits["full_vs_original_task_cpu_median_ratio_max"],
                      "rss": rss <= limits["recorder_rss_mib_max"]}
            groups.append({"abi": abi, "task": task, "wall_median_ratio": wall, "cpu_median_ratio": cpu_ratio,
                           "wall_pair_ratios": pairs, "recorder_peak_rss_mib": rss, "checks": checks})
            failures.extend(abi + ":" + task + ":" + name for name, passed in checks.items() if not passed)
    return {"groups": groups, "failures": failures, "performance_accepted": not failures}


def self_test():
    metadata = {"sample_started_monotonic_ns": 1, "observation_ended_monotonic_ns": 20_000_000_001}
    receipt = {"observation_start_ns": 1, "observation_end_ns": 20_000_000_002,
               "finish_request_ns": 20_000_000_003, "finish_ack_ns": 21_000_000_000,
               "error": None, "broker_status": "accepted"}
    lifecycle(receipt, receipt, metadata)
    guards = []
    for key, value in (("finish_ack_ns", 33_000_000_004), ("finish_request_ns", 20_000_000_000),
                       ("observation_start_ns", 2), ("broker_status", "rejected"), ("error", "lost")):
        changed = {**receipt, key: value}
        try:
            lifecycle(changed, changed, metadata)
        except ValueError:
            guards.append(key)
        else:
            raise AssertionError("Corrupt lifecycle accepted: " + key)
    rows = [{**case, "usage": {"wall_ns": 100, "user_seconds": .1, "system_seconds": .01},
             "recorder_usage": {"peak_rss_kib": 1024}} for case in version.gate.plan()]
    limits = version.gate.approved_contract()["performance_limits"]
    require(summary(rows, limits)["performance_accepted"], "Synthetic in-budget performance rejected")
    changed = copy.deepcopy(rows)
    next(row for row in changed if row["condition"] == "full" and not row["warmup"])["usage"]["wall_ns"] = 126
    require(not summary(changed, limits)["performance_accepted"], "Any-pair budget corruption accepted")
    try:
        summary(rows[:-1], limits)
    except ValueError:
        guards.append("incomplete_design")
    else:
        raise AssertionError("Incomplete design promoted")
    print("PASS independent lifecycle corruption, any-pair budget and incomplete-design guards")
    return guards + ["wall_pair_budget"]


def audit(attempt):
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(protocol["recorder_seconds"] == 22 and protocol["acknowledgement_seconds"] == 12
            and protocol["helper_transactions"] == 0 and not protocol["diagnostic_28s_lifetime_imported"], "Benchmark protocol changed")
    for field in ("files", "source_hashes"):
        for name, expected in protocol[field].items():
            path = attempt / name if field == "files" else Path(name)
            require(version.identity.digest(path) == expected, "Frozen source/transport differs: " + name)
    payload = original.members(attempt / "payload.tgz", 256 * 1024 * 1024)
    manifest = json.loads((attempt / "manifest.json").read_text())
    require(json.loads(payload["manifest.json"]) == manifest and manifest["cases"] == version.gate.plan(), "Manifest/order differs")
    for name, expected in manifest["files"].items():
        require(hashlib.sha256(payload[name]).hexdigest() == expected, "Payload member differs: " + name)
    contract = json.loads(payload["contract.json"])
    require(contract == version.gate.approved_contract(), "Approved exact contract differs")
    evidence = original.members(attempt / "evidence.tgz", 2 * 1024 * 1024 * 1024)
    require(evidence["guest_result.json"] == (attempt / "guest_result.json").read_bytes(), "Guest/archive report differs")
    guest = json.loads(evidence["guest_result.json"])
    require(not guest["collection_ready"] and guest["malware_executions"] == 0, "Unexpected readiness or workload scope")
    accepted = guest["status"] == "accepted_bounded_performance"
    directories = sorted(name.rsplit("/", 1)[0] for name in evidence if name.endswith("/run.json"))
    require(0 < len(directories) <= 84 and len(guest["measurements"]) <= len(directories), "Unexpected run/measurement count")
    rows, cases = [], []
    cells = packets = 0
    first_failing_pair = None
    for index, directory in enumerate(directories):
        case = manifest["cases"][index]
        require(directory.split("/")[0] == "output-" + case["mode"], "Execution is not the frozen prefix")
        entry = lambda name: evidence[directory + "/" + name]
        metadata = json.loads(entry("run.json"))
        require(metadata["telemetry_schema_version"] == version.performance.SCHEMA
                and metadata["malware_runner_sha256"] == manifest["files"]["integrated_runner.py"], "Actual runner provenance differs")
        completed = index < len(guest["measurements"])
        require(completed or (not accepted and index == len(directories) - 1), "Unmeasured case is not the failed final case")
        pcaps = [content for name, content in evidence.items() if name.startswith(directory + "/") and name.endswith(".pcap")]
        require(len(pcaps) == (0 if case["condition"] == "baseline" else 1), "Unexpected actual PCAP count")
        captured = original.packet_count(pcaps[0]) if pcaps else None
        packets += captured or 0
        raw = {"case": case, "quality_status": metadata["collection_quality_status"],
               "quality_reasons": metadata["collection_quality_reasons"], "pcap_records": captured,
               "accepted_measurement": completed}
        if not completed:
            require(guest.get("error") and not accepted, "Failed final case lacks preserved failure")
            for name in ("task-usage.json", "performance-finish-request.json", "performance-lifecycle.json", "attribution-result.json"):
                if directory + "/" + name in evidence:
                    raw[name] = json.loads(entry(name))
            if "task-usage.json" in raw and metadata["return_code"] == 0:
                original.validate_usage(raw["task-usage.json"], metadata["sample_root_pid"])
            if directory + "/sample.stdout.log" in evidence and entry("sample.stdout.log").strip():
                raw["application_receipt"] = json.loads(entry("sample.stdout.log"))
                require(raw["application_receipt"]["pid"] == metadata["sample_root_pid"], "Failed-case application PID differs")
            if case["task"] == "file" and directory + "/workspace/roundtrip.bin" in evidence:
                require(entry("workspace/roundtrip.bin") == bytes((offset * 37 + 11) % 251 for offset in range(65536)) * 256, "Failed-case owned file bytes differ")
            if case["condition"] != "baseline" and directory + "/telemetry.csv" in evidence:
                features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
                telemetry = list(csv.DictReader(io.StringIO(entry("telemetry.csv").decode())))
                require(len(features) == len(set(features)) == 169 and len(telemetry) == 40, "Failed-case telemetry contract differs")
                for row in telemetry:
                    for name in features:
                        require(math.isfinite(float(row[name])), "Failed-case nonfinite feature")
                        cells += 1
            cases.append(raw)
            continue
        require(metadata["return_code"] == 0, "Accepted task exit differs")
        receipt = json.loads(entry("sample.stdout.log"))
        require(receipt == {"status": "accepted", "task": case["task"], "pid": metadata["sample_root_pid"],
                           "pointer_bits": 32 if case["abi"] == "i386" else 64,
                           "file_bytes": 16777216 if case["task"] == "file" else 0,
                           "actual_udp_echoes": 64 if case["task"] == "network" else 0}, "Actual task/ABI receipt differs")
        usage = json.loads(entry("task-usage.json"))
        original.validate_usage(usage, receipt["pid"])
        if case["task"] == "file":
            require(entry("workspace/roundtrip.bin") == bytes((offset * 37 + 11) % 251 for offset in range(65536)) * 256, "Owned16MiB bytes differ")
        require(not original.quality_findings(metadata, case, captured), "Accepted measurement has a quality rejection")
        if case["condition"] != "baseline":
            require(metadata["raw_syscalls_unresolved_abi"] == 0 if "raw_syscalls_unresolved_abi" in metadata else metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] == 0, "Unresolved event ABI")
            require(metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"], "Buffer not restored")
            require(metadata["packet_capture_interface_link_state_before_sample"]["carrier"] in (1, "1"), "Interface carrier not up")
            features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
            telemetry = list(csv.DictReader(io.StringIO(entry("telemetry.csv").decode())))
            require(len(features) == len(set(features)) == 169 and len(telemetry) == 40, "Feature contract differs")
            for row in telemetry:
                for name in features:
                    require(math.isfinite(float(row[name])), "Nonfinite feature")
                    cells += 1
        clocks = lifecycle(json.loads(entry("performance-finish-request.json")), json.loads(entry("performance-lifecycle.json")), metadata)
        if case["condition"] != "baseline":
            diagnostics = json.loads(entry("packet_capture_diagnostics.json"))
            stops = [event for event in diagnostics["lifecycle_events"] if event["event"] == "stop_requested"]
            require(len(stops) == 1 and json.loads(entry("performance-lifecycle.json"))["finish_request_ns"] <= stops[0]["monotonic_ns"], "FINISH did not precede original PCAP shutdown")
        recorder = None
        if case["condition"] == "full":
            records = [json.loads(line) for line in entry("attribution.jsonl").decode().splitlines()]
            version.identity.audit_records(records)
            version.identity.exec_identity.validate_receipts(json.loads(entry("exec-identity.json")), receipt["pid"], manifest["files"][case["binary"]], records)
            recorder = json.loads(entry("recorder-usage.json"))
            original.validate_usage(recorder, recorder["pid"])
            require(metadata["attribution"]["temporary_cgroup_removed"], "Full cgroup remains")
        else:
            require(metadata["benchmark_cgroup"]["temporary_cgroup_removed"], "Baseline/original cgroup remains")
        row = {**case, "usage": usage, "recorder_usage": recorder}
        saved = guest["measurements"][index]
        require(all(saved[key] == value for key, value in row.items()), "Independent case/usage differs from guest report")
        rows.append(row)
        if not case["warmup"]:
            pair = [item for item in rows if all(item[key] == case[key] for key in ("abi", "task", "repeat")) and item["condition"] in ("original", "full")]
            if len(pair) == 2:
                ratio = next(item for item in pair if item["condition"] == "full")["usage"]["wall_ns"] / next(item for item in pair if item["condition"] == "original")["usage"]["wall_ns"]
                if ratio > contract["performance_limits"]["full_vs_original_task_wall_any_pair_ratio_max"]:
                    require(first_failing_pair is None and index == len(directories) - 1 and not accepted, "Execution continued after failing wall pair")
                    require(guest["first_failing_wall_pair_ratio"] == ratio, "Reported failing pair differs")
                    first_failing_pair = {"case": case, "ratio": ratio}
        cases.append({**raw, "usage": usage, "lifecycle": clocks})
    require(len(rows) == len(guest["measurements"]), "Missing accepted measurement")
    metrics = summary(rows, contract["performance_limits"]) if len(rows) == 84 else {"performance_accepted": False, "groups": [], "failures": ["incomplete_design"]}
    require(accepted == metrics["performance_accepted"], "Guest acceptance differs from independently audited budgets/completeness")
    if not accepted:
        require(guest.get("error") or metrics["failures"], "Missing preserved failure")
    state = json.loads((attempt / "final_vm_state.json").read_text())
    require(state["guest"]["VMState"].strip('"') == "poweroff" and state["guest"]["CurrentSnapshotName"].strip('"') == "clean-tls-paired-2026-10-19"
            and state["sink"]["VMState"].strip('"') == "running", "Saved cleanup differs")
    for machine in state.values():
        require(machine["nic1"].strip('"') == "intnet" and machine["intnet1"].strip('"') == "malnet"
                and all(machine["nic" + str(index)].strip('"') == "none" for index in range(2, 9)), "Saved isolation differs")
    import capture_liveness_v4
    startup = capture_liveness_v4.audit_startup(json.loads((attempt / "startup-readiness.json").read_text()))
    return {"status": "accepted_bounded_performance_independently_audited" if accepted else "stopped_prefix_audited_not_performance_accepted",
            "collection_ready": False, "performance_accepted": accepted, "malware_executions": 0,
            "safe_evidence_members": len(evidence), "instrumented_finite_cells": cells, "pcap_records": packets,
            "actual_cases": len(cases), "accepted_measurements": len(rows), "cases": cases,
            "first_failing_pair": first_failing_pair, "metrics": metrics, "startup": startup,
            "negative_guards": self_test(), "input_hashes": {name: version.identity.digest(attempt / name) for name in
            ("protocol.json", "manifest.json", "payload.tgz", "guest_result.json", "evidence.tgz", "startup-readiness.json", "final_vm_state.json")},
            "limitations": "Bounded engineering tasks only. A stopped prefix supplies no accepted performance medians. Baseline sensor-quality rejection is preserved. No continuous completeness, arbitrary workload, detector or collection-release inference."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    self_test()
    if options.attempt:
        attempt = options.attempt.resolve()
        result = audit(attempt)
        result["auditor_sha256"] = version.identity.digest(__file__)
        output = attempt / ("audit-derived-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
        version.identity.save(output, result)
        print(output)
        print(json.dumps({key: result[key] for key in ("status", "performance_accepted", "collection_ready", "actual_cases", "accepted_measurements", "first_failing_pair")}, indent=2))