import ast
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import sys

import validate_zero_probe as shared


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
RETRY = json.loads((ROOT / "fallback_retry_manifest.json").read_text())
OUTPUT = ROOT / RETRY["output_directory"] / RETRY["sample"]


if __name__ == "__main__":
    experiment = json.loads((ROOT / "experiment_manifest.json").read_text())
    baseline = json.loads((ROOT / "probe_results.json").read_text())
    assert shared.sha256(STUDY / "src/malware_runner.py") == RETRY["runner_sha256"]
    assert shared.sha256(STUDY / "scripts/vbox_malware_batch.sh") == RETRY["batch_sha256"]
    assert shared.sha256(ROOT / "zero_feature_probe.sh") == RETRY["workload_sha256"]
    metadata_path, = (OUTPUT / "output").glob("*/run.json")
    run = metadata_path.parent
    metadata = json.loads(metadata_path.read_text())
    fields, windows = shared.read_csv(run / "telemetry.csv")
    feature_names = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
    assert metadata["telemetry_schema_version"] == RETRY["runner_schema"]
    assert metadata["malware_runner_sha256"] == RETRY["runner_sha256"]
    assert metadata["status"] == "completed" and metadata["return_code"] == 0
    assert metadata["ebpf_status"] == metadata["packet_capture_status"] == "active"
    assert metadata["packet_capture_dropped_by_kernel"] == 0
    assert len(windows) == 40 and len(fields) == 176 and len(feature_names) == 169
    assert fields == metadata["telemetry_fields"]
    assert all(row[name] not in (None, "") and math.isfinite(float(row[name]))
               for row in windows for name in feature_names)
    archive_files, archive_errors = shared.archive_parity(OUTPUT)
    assert archive_files > 0 and not archive_errors

    feature_sums = {name: sum(float(row[name]) for row in windows)
                    for name in experiment["target_zero_features"]}
    before = baseline["target_feature_sums"]
    changes = {name: {"v3_sum": before[name], "v4_sum": feature_sums[name],
                      "delta": feature_sums[name] - before[name]}
               for name in experiment["target_zero_features"]}
    changed = sorted(name for name, value in feature_sums.items() if value > 0)
    still_zero = sorted(name for name, value in feature_sums.items() if value == 0)

    _, raw_rows = shared.read_csv(run / "syscall_events.csv")
    raw_syscall_counts = Counter()
    syscall_numbers = {"execveat": 322, "openat2": 437, "pwrite64": 18,
                       "renameat": 264, "renameat2": 316, "unlinkat": 263}
    for row in raw_rows:
        try:
            number = int(row["detail"].partition("id=")[2])
        except ValueError:
            continue
        for name, syscall_number in syscall_numbers.items():
            if number == syscall_number:
                raw_syscall_counts[name] += 1
    _, named_rows = shared.read_csv(run / "ebpf_events.csv")
    named_counts = Counter(row["event"] for row in named_rows)
    diagnostics = metadata.get("ebpf_event_diagnostics", {}).get("raw_syscall_feature_fallbacks", {})
    entry_comparison = {
        name: {"raw_syscall_rows": raw_syscall_counts[name],
               "named_event_rows": named_counts[name],
               "v4_feature_sum": feature_sums[f"ebpf_{name}_count"],
               "fallback_count": diagnostics.get(name, 0)}
        for name in syscall_numbers
    }
    probe_output = ast.literal_eval((run / "sample.stdout.log").read_text().strip().splitlines()[-1])
    packet_counts = {
        "icmp": shared.frame_count(run / "packet_capture.pcap", "icmp"),
        "ipv6": shared.frame_count(run / "packet_capture.pcap", "ipv6"),
        "igmp": shared.frame_count(run / "packet_capture.pcap", "ip.proto == 2"),
        "large_frames_ge_1200": shared.frame_count(run / "packet_capture.pcap", "frame.len >= 1200"),
        "tcp_urgent": shared.frame_count(run / "packet_capture.pcap", "tcp.flags.urg == 1"),
    }
    assert all(entry["raw_syscall_rows"] > 0 and entry["v4_feature_sum"] > 0
               for entry in entry_comparison.values())
    assert feature_sums["host_execveat_event_count"] > 0
    assert feature_sums["host_rename_total"] > 0 and feature_sums["host_unlink_total"] > 0
    assert feature_sums["host_unique_rename_paths"] > 0 and feature_sums["host_unique_unlink_paths"] > 0
    assert still_zero == ["net_ipv6_packets"]

    report = {
        "retry_manifest": RETRY,
        "run_metadata": {key: metadata.get(key) for key in
                         ("status", "return_code", "telemetry_schema_version", "malware_runner_sha256",
                          "ebpf_status", "packet_capture_status", "packet_capture_dropped_by_kernel",
                          "ebpf_event_count", "raw_syscall_event_count")},
        "checks": {"telemetry_complete": True, "archive_hash_parity": True,
                   "raw_syscall_counters_reconciled": True, "host action/path features_nonzero": True},
        "archive_regular_files_hash_matched": archive_files,
        "window_count": len(windows), "feature_count": len(feature_names),
        "target_feature_changes_v3_to_v4": changes,
        "features_nonzero_v4": changed,
        "features_still_zero_v4": still_zero,
        "syscall_entry_counter_comparison": entry_comparison,
        "raw_syscall_feature_fallbacks": diagnostics,
        "script_operations": probe_output["results"],
        "pcap_dissector_frame_counts": packet_counts,
        "limitations": ["This is one benign synthetic run, not malware or classifier evidence.",
                        "The only remaining targeted zero is IPv6; the probe reported ENETUNREACH.",
                        "Raw-syscall fallback counts calls but cannot recover missing path strings.",
                        "Fallback mappings are limited to known x86-64/i386 process ELF ABIs; unknown ABIs retain named-event counts.",
                        "No reported PCAP drops does not prove zero unreported eBPF loss."],
        "artifacts_sha256": {name: shared.sha256(run / name) for name in
                             ("run.json", "telemetry.csv", "ebpf_events.csv", "syscall_events.csv",
                              "packet_capture.pcap", "sample.stdout.log")},
        "validator_sha256": shared.sha256(Path(__file__)),
    }
    (ROOT / "probe_fallback_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"features_nonzero": changed, "features_still_zero": still_zero,
                      "syscall_entry_counter_comparison": entry_comparison,
                      "pcap_dissector_frame_counts": packet_counts}, indent=2))