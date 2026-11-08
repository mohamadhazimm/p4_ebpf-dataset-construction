#!/usr/bin/env python3
"""Re-audit immutable integrated benign evidence without guest or model operations."""

import argparse
import copy
import hashlib
import json
import math
import struct
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import check_integrated_attribution as driver
import integrated_attribution as integration


def unpack(archive_path, destination):
    hashes = {}
    with tarfile.open(archive_path) as archive:
        members = archive.getmembers()
        driver.expect(len(members) <= 200 and sum(member.size for member in members) <= 32 * 1024 * 1024, "Evidence bounds exceeded")
        for member in members:
            name = PurePosixPath(member.name)
            driver.expect(member.isfile() and not name.is_absolute() and ".." not in name.parts
                          and member.name not in hashes and member.size <= 16 * 1024 * 1024, "Unsafe or duplicate archive member")
            driver.expect(not any(part.startswith(".") for part in name.parts), "Unexpected private evidence member")
            content = archive.extractfile(member).read()
            driver.expect(len(content) == member.size, "Archive member truncated")
            path = destination / member.name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(content)
            path.chmod(0o600)
            hashes[member.name] = hashlib.sha256(content).hexdigest()
    return hashes


def validate_capture(directory, manifest, case):
    facts = driver.audit_run(directory, manifest, case)
    metadata = json.loads((directory / "run.json").read_text())
    target = (directory.parent.parent / case["binary"]).read_bytes()
    executable_type, machine = struct.unpack_from("<HH", target, 16)
    expected_machine = 3 if case["mode"] == "i386-hash" else 62
    driver.expect(target.startswith(b"\x7fELF") and executable_type == 2 and machine == expected_machine, "Actual target ELF mode differs")
    artifact = metadata["target_artifact"]
    driver.expect(artifact["e_machine"] == expected_machine and artifact["linkage"] == "static"
                  and artifact["execution_mode"] == ("native_compat" if expected_machine == 3 else "native"), "Recorded target mode differs")
    driver.expect(metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] == 0
                  and metadata["packet_capture_interface_link_state_before_sample"] == {"operstate": "up", "carrier": 1}, "ABI or link evidence differs")
    result = json.loads((directory / "attribution-result.json").read_text())
    driver.expect(result["observations_sha256"] == integration.digest(directory / "attribution.jsonl")
                  and result["sample_sha256"] == manifest["files"][case["binary"]]
                  and result["sensor_sha256"] == manifest["files"]["attribution-v6"]
                  and result["object_sha256"] == manifest["files"]["lifecycle.bpf.o"], "Attribution evidence hashes differ")
    driver.expect(metadata["attribution"]["module_sha256"] == manifest["files"]["integrated_attribution.py"], "Integrated module hash differs")
    driver.expect(all(metadata["attribution"][key] == value for key, value in result.items()), "Archived broker result differs from metadata")
    rows = [json.loads(line) for line in (directory / "attribution.jsonl").read_text().splitlines()]
    clocks = {row["phase"]: row["monotonic_ns"] for row in rows if row.get("record") == "clock"}
    driver.expect(clocks["before"] <= metadata["sample_started_monotonic_ns"] < metadata["observation_ended_monotonic_ns"] <= clocks["after"], "Observation clock boundaries differ")
    return facts


def audit(attempt):
    protocol = json.loads((attempt / "protocol.json").read_text())
    for name, expected in protocol["files"].items():
        driver.expect(integration.digest(attempt / name) == expected, "Frozen input changed: " + name)
    for name, expected in protocol["source_hashes"].items():
        driver.expect(integration.digest(name) == expected, "Frozen source changed: " + name)
    manifest = json.loads((attempt / "manifest.json").read_text())
    guest_report = json.loads((attempt / "guest_result.json").read_text())
    driver.expect(guest_report["status"] == "accepted_four_integrated_benign_captures_not_collection_release"
                  and len(guest_report["results"]) == 4, "Guest report not accepted")
    sys.path.insert(0, str(driver.STUDY.parent.parent / "p4_ebpf"))
    import analyze_p4_pcap_ablation as p4
    results = []
    with tempfile.TemporaryDirectory(prefix="hazim-integrated-audit-") as temporary:
        root = Path(temporary)
        payload = root / "payload"
        evidence = root / "evidence"
        payload_hashes = unpack(attempt / "payload.tgz", payload)
        driver.expect(payload_hashes == {**manifest["files"], "manifest.json": integration.digest(attempt / "manifest.json")}, "Frozen payload members differ")
        evidence_hashes = unpack(attempt / "evidence.tgz", evidence)
        driver.expect(evidence_hashes["guest_result.json"] == integration.digest(attempt / "guest_result.json"), "Retrieved and archived guest reports differ")
        for binary in ("attribution-control", "xxhsum"):
            (evidence / binary).write_bytes((payload / binary).read_bytes())
        for case, saved in zip(manifest["cases"], guest_report["results"]):
            directories = list((evidence / ("output-" + case["mode"])).iterdir())
            driver.expect(len(directories) == 1 and directories[0].is_dir(), "Unexpected capture directories")
            directory = directories[0]
            facts = validate_capture(directory, manifest, case)
            facts["run_directory"] = saved["run_directory"]
            driver.expect(json.loads(json.dumps(facts)) == saved, "Host and guest audit facts differ")
            metadata = json.loads((directory / "run.json").read_text())
            telemetry = p4.load_telemetry_rows(directory)
            _, reconstructed, alignment = p4.derive_p4_features(directory / "packet_capture.pcap", telemetry, metadata,
                                                               byte_layer="ethernet", rate_window="nominal")
            comparisons = 0
            if alignment["alignment_status"] == "unique":
                driver.expect(len(reconstructed) == len(telemetry), "Reconstructed window count differs")
                for stored, rebuilt in zip(telemetry, reconstructed):
                    for feature in p4.P4_FEATURES:
                        driver.expect(math.isclose(float(stored[feature]), rebuilt[feature], rel_tol=1e-9, abs_tol=1e-9), "Stored/P4 window value differs")
                        comparisons += 1
            results.append({**facts, "p4_alignment": alignment, "p4_window_comparisons": comparisons})
        guards = []
        metadata_path = directory / "run.json"
        original = metadata_path.read_bytes()
        for kind in ("old_sensor_loss", "missing_exec", "wrong_target_mode", "wrong_observation_hash"):
            changed = copy.deepcopy(metadata)
            if kind == "old_sensor_loss":
                changed["ebpf_lost_event_count"] = 1
            elif kind == "missing_exec":
                changed["target_exec"]["status"] = "not_observed"
            elif kind == "wrong_target_mode":
                changed["target_artifact"]["e_machine"] = 62
            else:
                changed["attribution"]["observations_sha256"] = "0" * 64
            metadata_path.write_text(json.dumps(changed))
            try:
                validate_capture(directory, manifest, case)
            except ValueError:
                guards.append(kind)
            else:
                raise AssertionError("Corrupted capture accepted: " + kind)
            finally:
                metadata_path.write_bytes(original)
    final = json.loads((attempt / "final_vm_state.json").read_text())
    driver.expect(final["guest"]["VMState"] == '"poweroff"'
                  and final["guest"]["CurrentSnapshotUUID"] == '"72de0a02-2e71-42b8-85e2-78c21d6b00f9"'
                  and final["sink"]["VMState"] == '"running"', "Saved VM cleanup differs")
    for state in final.values():
        driver.expect(state["nic1"] == '"intnet"' and state["intnet1"] == '"malnet"'
                      and all(state["nic%d" % index] == '"none"' for index in range(2, 9)), "Saved VM isolation differs")
    inputs = {name: integration.digest(attempt / name) for name in ("protocol.json", "manifest.json", "payload.tgz", "guest_result.json", "evidence.tgz", "final_vm_state.json", "staged_snapshot.json")}
    report = {"status": "accepted_saved_integrated_benign_capture_audit", "collection_ready": False,
              "inputs": inputs, "auditor_sha256": integration.digest(__file__), "archive_members": len(evidence_hashes),
              "member_sha256": evidence_hashes, "results": results, "negative_guards": guards,
              "feature_cells": sum(row["feature_cells"] for row in results),
              "pcap_records": sum(row["pcap_records"] for row in results),
              "p4_window_comparisons": sum(row["p4_window_comparisons"] for row in results),
              "p4_extractor_sha256": integration.digest(p4.__file__),
              "limitations": "Four bounded benign diagnostics only; no general exec-inode/hash, ownership, namespace/bypass/allocator, rate/performance or study allocation release; no .18 merge"}
    output = attempt / ("validation-derived-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    integration.save(output, report)
    print(output)
    print(json.dumps({key: report[key] for key in ("status", "archive_members", "feature_cells", "pcap_records", "p4_window_comparisons", "negative_guards")}))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", type=Path)
    audit(parser.parse_args().attempt.resolve())