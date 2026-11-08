"""Read-only data-quality audit of every recorded sample run in the study (no VM, no execution).

For each host_run.txt under data/ it reports retrieval outcome and, where metadata exists, the
"dropping" (packet drops, counter gaps, lost/untracked eBPF events, short or nonfinite telemetry),
"slipping" (telemetry window timing drift, early-stop observations) and "leaking" (byte markers of
known background services inside the PCAP) indicators, plus target-exec outcome. Older schemas lack
fields, so missing evidence is reported as unavailable, never as clean. Writes a new timestamped
report directory and never modifies a run.
"""

import collections
import csv
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT.parents[1]
LEAK_MARKERS = {
    "networkmanager_connectivity": b"connectivity-check",
    "apt_package_download": b"APT-HTTP",
    "ntp_dns": b"\x03ntp\x06ubuntu\x03com",
    "ntp_bootstrap_dns": b"ntp-bootstrap",
    "mdns_local": b"\x05local\x00",
    "cups_ipp": b"_ipp",
    "reverse_dns": b"\x07in-addr\x04arpa",
}
IDENTIFIERS = {"run_id", "label", "window_id", "window_start_utc", "window_end_utc", "window_seconds",
               "record_type", "sample_artifact", "sample_name", "collection_quality_status",
               "collection_quality_reasons", "ebpf_status"}
HEX64 = re.compile(r"^[0-9a-f]{64}\.(zip|triage|elf)$")


def experiment_of(path):
    parts = path.relative_to(DATA).parts
    return parts[1] if parts[0] == "versioned-collector" else parts[0] + "/" + parts[1]


def label_of(path, sample):
    text = str(path).lower()
    if sample.startswith("null"):
        return "null"
    if HEX64.match(sample):
        return "malware"
    if "hybrid_scenarios" in text:
        return "scenario"
    if "benign" in text or sample.startswith(("benign", "native_", "amd64-", "i386-", "curl")):
        return "benign"
    if "malware" in text:
        return "malware"
    return "other"


def log_counts(path):
    result = {}
    if path.is_file():
        text = path.read_text(errors="replace")
        for key, pattern in (("captured", r"(\d+) packets captured"), ("received", r"(\d+) packets received by filter"),
                             ("dropped", r"(\d+) packets dropped by kernel")):
            found = re.findall(pattern, text)
            if found:
                result[key] = int(found[-1])
    return result


def ebpf_log_lost(path):
    if not path.is_file():
        return None
    text = path.read_text(errors="replace")
    total = re.findall(r"Total lost event count:\s*(\d+)", text)
    if total:
        return int(total[-1])
    return sum(int(value) for value in re.findall(r"Lost (\d+) events", text))


def telemetry_check(path, features, window_seconds):
    if not path.is_file():
        return {"rows": 0, "nonfinite": None, "max_window_drift_ms": None}
    with path.open(newline="", errors="replace") as stream:
        rows = list(csv.DictReader(stream))
    columns = features or [name for name in (rows[0].keys() if rows else []) if name not in IDENTIFIERS]
    nonfinite = 0
    for row in rows:
        for name in columns:
            try:
                if not math.isfinite(float(row.get(name, "nan"))):
                    nonfinite += 1
            except ValueError:
                nonfinite += 1
    drift = None
    if rows and window_seconds and "window_seconds" in rows[0]:
        values = []
        for row in rows[:-1]:  # the final window may legitimately be truncated by observation end
            try:
                values.append(abs(float(row["window_seconds"]) - window_seconds) * 1000)
            except ValueError:
                pass
        drift = round(max(values), 3) if values else None
    return {"rows": len(rows), "nonfinite": nonfinite, "max_window_drift_ms": drift}


def last_line(path):
    if not path.is_file():
        return ""
    lines = [line.strip() for line in path.read_text(errors="replace").splitlines() if line.strip()]
    return lines[-1][:200] if lines else ""


def audit_run(host_path):
    sample_dir = host_path.parent
    host = dict(line.split("=", 1) for line in host_path.read_text(errors="replace").splitlines() if "=" in line)
    row = {"experiment": experiment_of(host_path), "sample": sample_dir.name,
           "label": label_of(host_path, sample_dir.name), "host_status": host.get("status", "missing"),
           "path": str(sample_dir.relative_to(DATA))}
    runs = list((sample_dir / "output").glob("*/run.json"))
    row["run_json_count"] = len(runs)
    run_dir = runs[0].parent if len(runs) == 1 else (next((sample_dir / "output").glob("*/"), None))
    metadata = {}
    if len(runs) == 1:
        try:
            metadata = json.loads(runs[0].read_text())
        except (ValueError, OSError):
            row["metadata_error"] = "unreadable run.json"
    row["schema"] = metadata.get("telemetry_schema_version", "unversioned" if metadata else "")
    # The recorded sample name is the extracted member (often a provider name), not the hash-named
    # archive directory, so a name comparison is not an integrity check and is deliberately omitted.
    row["return_code"] = metadata.get("return_code")
    row["process_status"] = metadata.get("status")
    row["observation_mode"] = metadata.get("observation_mode", "adaptive_or_unrecorded")
    row["quality_status"] = metadata.get("collection_quality_status", "unrecorded" if metadata else "")
    row["quality_reasons"] = ";".join(metadata.get("collection_quality_reasons", []) or [])
    statistics = metadata.get("packet_capture_statistics") or {}
    fallback = log_counts(run_dir / "packet_capture.log") if run_dir else {}
    captured = statistics.get("packets_captured", fallback.get("captured"))
    received = statistics.get("packets_received_by_filter", fallback.get("received"))
    dropped = metadata.get("packet_capture_dropped_by_kernel", fallback.get("dropped"))
    row.update(pcap_captured=captured, pcap_received=received, pcap_kernel_drops=dropped,
               pcap_counter_gap=(received - captured - dropped) if None not in (captured, received, dropped) else None)
    lost = metadata.get("ebpf_lost_event_count")
    row["ebpf_lost"] = lost if lost is not None else (ebpf_log_lost(run_dir / "ebpf_collector.log") if run_dir else None)
    row["ebpf_status"] = metadata.get("ebpf_status")
    row["pcap_status"] = metadata.get("packet_capture_status")
    diagnostics = metadata.get("ebpf_event_diagnostics") or {}
    parsed = sum((diagnostics.get("parsed") or {}).values())
    untracked = sum((diagnostics.get("untracked_tid") or {}).values())
    row["ebpf_untracked_fraction"] = round(untracked / parsed, 4) if parsed else None
    row["unresolved_abi"] = diagnostics.get("raw_syscalls_unresolved_abi")
    execution = metadata.get("target_exec")
    row["target_exec"] = (execution or {}).get("status", "unrecorded" if metadata else "")
    row["exec_errno"] = ";".join(str(item.get("errno")) for item in (execution or {}).get("root_exec_failures", []) or [])
    windows, window_seconds, timeout = metadata.get("windows"), metadata.get("window_seconds"), metadata.get("timeout_seconds")
    row["windows"] = windows
    row["expected_windows"] = round(timeout / window_seconds) if timeout and window_seconds else None
    features = [name for group in (metadata.get("telemetry_feature_groups") or {}).values() for name in group]
    row.update(telemetry_check(run_dir / "telemetry.csv", features, window_seconds) if run_dir else
               {"rows": 0, "nonfinite": None, "max_window_drift_ms": None})
    if "packet_capture_rmem_max_before" in metadata:
        row["rmem_restored"] = metadata.get("packet_capture_rmem_max_before") == metadata.get("packet_capture_rmem_max_after_capture")
    link = metadata.get("packet_capture_interface_link_state_before_sample")
    row["link_carrier"] = (link or {}).get("carrier")
    probe = metadata.get("capture_path_probe")
    row["probe_status"] = (probe or {}).get("status")
    pcap = run_dir / "packet_capture.pcap" if run_dir else None
    row["pcap_bytes"] = pcap.stat().st_size if pcap and pcap.is_file() else None
    if pcap and pcap.is_file():
        content = pcap.read_bytes()
        for name, marker in LEAK_MARKERS.items():
            row["leak_" + name] = marker in content
    if row["host_status"] != "completed":
        row["runner_log_last_line"] = last_line(sample_dir / "runner.log")
        row["archive_log_last_line"] = last_line(sample_dir / "archive.log")
        row["copy_log_last_line"] = last_line(sample_dir / "copy.log")
        row["output_tgz_bytes"] = (sample_dir / "output.tgz").stat().st_size if (sample_dir / "output.tgz").is_file() else None
    return row


def findings(row):
    """Classify one run into dropping / slipping / leaking / execution / retrieval findings."""
    out = []
    if row["host_status"] != "completed":
        out.append("retrieval:" + row["host_status"])
        return out
    if row["run_json_count"] != 1:
        out.append("retrieval:missing_or_ambiguous_run_json")
        return out
    if row.get("quality_status") == "rejected":
        out.append("quality_rejected")
    if (row.get("pcap_kernel_drops") or 0) > 0:
        out.append("dropping:pcap_kernel_drops")
    if row.get("pcap_counter_gap") not in (None, 0):
        out.append("dropping:pcap_counter_gap")
    if (row.get("ebpf_lost") or 0) > 0:
        out.append("dropping:ebpf_lost_events")
    if (row.get("ebpf_untracked_fraction") or 0) > 0:
        out.append("dropping:ebpf_untracked_thread_events")
    if row.get("unresolved_abi"):
        out.append("dropping:unresolved_abi")
    if row.get("nonfinite"):
        out.append("dropping:nonfinite_telemetry")
    if row.get("expected_windows") and row.get("rows", 0) < row["expected_windows"]:
        out.append("slipping:observation_shorter_than_requested")
    if (row.get("max_window_drift_ms") or 0) > 50:
        out.append("slipping:window_drift_over_50ms")
    if row.get("rmem_restored") is False:
        out.append("environment:rmem_not_restored")
    if row.get("link_carrier") in (0, "0"):
        out.append("environment:link_down")
    if row.get("probe_status") not in (None, "recovered"):
        out.append("capture_probe_not_recovered")
    if row.get("target_exec") not in ("observed", "unrecorded", ""):
        out.append("execution:target_exec_" + str(row["target_exec"]))
    if any(row.get("leak_" + name) for name in LEAK_MARKERS):
        out.append("leaking:background_service_traffic")
    return out


def main():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = ROOT / "historical-run-audit" / stamp
    output.mkdir(parents=True)
    rows = []
    for host_path in sorted(DATA.rglob("host_run.txt")):
        try:
            row = audit_run(host_path)
        except Exception as error:  # an unreadable run is a finding, never a crash
            row = {"experiment": experiment_of(host_path), "sample": host_path.parent.name, "label": "?",
                   "host_status": "audit_error", "audit_error": type(error).__name__ + ": " + str(error)[:160],
                   "path": str(host_path.parent.relative_to(DATA)), "run_json_count": 0}
        row["findings"] = ";".join(findings(row)) if row.get("host_status") != "audit_error" else "audit_error"
        rows.append(row)
    fields = sorted({key for row in rows for key in row}, key=lambda k: (k not in ("experiment", "sample", "label", "host_status", "findings"), k))
    with (output / "runs.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    summary = {"runs": len(rows), "by_host_status": collections.Counter(row["host_status"] for row in rows),
               "by_schema": collections.Counter(row.get("schema") or "none" for row in rows),
               "finding_counts": collections.Counter(item for row in rows for item in row["findings"].split(";") if item),
               "finding_counts_by_schema": {}, "leak_marker_counts_by_schema": {}, "retrieval_failure_hints": collections.Counter()}
    for schema in sorted(summary["by_schema"]):
        subset = [row for row in rows if (row.get("schema") or "none") == schema]
        summary["finding_counts_by_schema"][schema] = dict(collections.Counter(
            item for row in subset for item in row["findings"].split(";") if item))
        summary["leak_marker_counts_by_schema"][schema] = {name: sum(1 for row in subset if row.get("leak_" + name)) for name in LEAK_MARKERS}
    for row in rows:
        if row["host_status"] not in ("completed", "audit_error"):
            hint = row.get("runner_log_last_line") or ("(empty runner.log)" if row["host_status"] == "runner_failed" else row.get("archive_log_last_line") or row.get("copy_log_last_line") or "(no log)")
            summary["retrieval_failure_hints"][row["host_status"] + " | " + re.sub(r"[0-9a-f]{16,}", "<hash>", hint)[:140]] += 1
    (output / "summary.json").open("x").write(json.dumps(summary, indent=2, sort_keys=True, default=dict) + "\n")
    print(output)
    print(json.dumps({key: summary[key] for key in ("runs", "by_host_status", "finding_counts")}, indent=1, default=dict))


if __name__ == "__main__":
    main()
