#!/usr/bin/env python3
"""DERIVED, READ-ONLY implementation audit of archived runs (independent audit 2026-10-20).

Reads frozen scale-100x100 (.14) and benign-ELF-100 (.14) outputs; never writes into them.
Output: run_audit.csv and run_audit_summary.json next to this script.
Exploratory/diagnostic only; no model is trained here.
"""
from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLLECTOR = HERE.parent
SCALE = COLLECTOR / "scale-100x100-v14-20261020T072500Z"
ELF = COLLECTOR / "benign-elf-100-v14-20261020T140000Z"
EXEC_IDS_X86_64 = {"id=59", "id=322"}
LAUNCHER_COMMS = {"python3", "bash"}
csv.field_size_limit(sys.maxsize)


def read_names(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def scale_family_maps() -> tuple[dict[str, str], dict[str, str]]:
    selection = json.loads((SCALE / "selection.json").read_text())
    malware = {row["sample"]: row["family"] for row in selection["malware"]}
    benign = {row["sample"]: row["family"] for row in selection["benign"]}
    for name in ("continuation_selection.json", "completion_selection.json"):
        replacement = json.loads((SCALE / name).read_text())
        malware.pop(replacement["replaced_sample"]["sample"])
        malware[replacement["replacement_sample"]["sample"]] = replacement["replacement_sample"]["family"]
    return malware, benign


def p4_alignment() -> dict[str, str]:
    path = SCALE / "modeling/p4_29x29/p4_alignment_audit.csv"
    with path.open() as handle:
        return {row["sample_artifact"]: row["status"] for row in csv.DictReader(handle)}


def oof_samples() -> set[str]:
    path = SCALE / "modeling/p4_29x29/oof_predictions.csv"
    with path.open() as handle:
        return {row["sample_artifact"] for row in csv.DictReader(handle)}


def audit_run(run_dir: Path) -> dict:
    meta = json.loads((run_dir / "run.json").read_text())
    root = int(meta["sample_root_pid"])
    start = int(meta["sample_started_monotonic_ns"])
    end = meta.get("observation_ended_monotonic_ns")
    raw_root_exec: list[tuple[int, str]] = []
    raw_root_rows: list[tuple[int, str]] = []
    raw_all: list[tuple[int, str]] = []
    raw_total = 0
    raw_pids: set[int] = set()
    with (run_dir / "syscall_events.csv").open(newline="") as handle:
        for row in csv.DictReader(handle):
            raw_total += 1
            pid = int(row["pid"])
            raw_pids.add(pid)
            ts = int(row["timestamp_ns"])
            raw_all.append((ts, row["detail"]))
            if pid == root:
                raw_root_rows.append((ts, row["comm"]))
                if row["detail"] in EXEC_IDS_X86_64:
                    raw_root_exec.append((ts, row["comm"]))
    named_total = 0
    named_counts: Counter = Counter()
    root_named_exec: list[tuple[int, str, str]] = []
    exit_ts: dict[int, list[int]] = defaultdict(list)
    last_ts_by_pid: dict[int, int] = {}
    windows: set[int] = set()
    first_ts = None
    last_ts = None
    tids: set[int] = set()
    with (run_dir / "ebpf_events.csv").open(newline="") as handle:
        for row in csv.DictReader(handle):
            named_total += 1
            event = row["event"]
            named_counts[event] += 1
            pid, tid, ts = int(row["pid"]), int(row["tid"]), int(row["timestamp_ns"])
            tids.add(tid)
            windows.add(int(row["window_id"]))
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
            last_ts_by_pid[pid] = max(last_ts_by_pid.get(pid, ts), ts)
            if event == "exit" and pid == tid:
                exit_ts[pid].append(ts)
            if pid == root and event in {"execve", "execveat"}:
                root_named_exec.append((ts, row["comm"], row["detail"]))
    boundary = raw_root_exec[1][0] if len(raw_root_exec) >= 2 else None
    comm_after = ""
    if boundary is not None:
        after = [comm for ts, comm in raw_root_rows if ts > boundary]
        comm_after = after[0] if after else ""
    post = [detail for ts, detail in raw_all if boundary is not None and ts > boundary]
    post_last = max((ts for ts, _ in raw_all if boundary is not None and ts > boundary), default=None)
    if not comm_after:
        exec_outcome = "no_post_exec_root_syscalls"
    elif comm_after in LAUNCHER_COMMS:
        exec_outcome = "launcher_comm_persisted"
    else:
        exec_outcome = "target_comm_observed"
    root_exit = min(exit_ts[root]) if exit_ts.get(root) else None
    # PID reuse heuristic: a PID with >1 leader exit, or named events after its first leader exit.
    reuse = sorted(
        pid for pid, stamps in exit_ts.items()
        if len(stamps) > 1 or last_ts_by_pid.get(pid, 0) > min(stamps) + 1_000_000
    )
    diag = meta.get("ebpf_event_diagnostics") or {}
    stats = meta.get("packet_capture_statistics") or {}
    return {
        "run_dir": str(run_dir.relative_to(COLLECTOR)),
        "run_id": meta.get("run_id", ""),
        "started_at_utc": meta.get("started_at_utc", ""),
        "return_code": meta.get("return_code"),
        "quality": meta.get("collection_quality_status"),
        "artifact_type": meta.get("sample_artifact_type"),
        "n_watch_paths": len(meta.get("filesystem_watch_paths") or []),
        "observation_mode": meta.get("observation_mode"),
        "timeout_seconds": meta.get("timeout_seconds"),
        "observation_s": (int(end) - start) / 1e9 if end else "",
        "root_raw_exec_count": len(raw_root_exec),
        "root_raw_exec_comms": "|".join(comm for _, comm in raw_root_exec),
        "comm_after_boundary": comm_after,
        "exec_success_inferred": bool(comm_after) and comm_after not in LAUNCHER_COMMS,
        "exec_outcome": exec_outcome,
        "post_exec_raw_syscalls": len(post),
        "post_exec_distinct_syscall_ids": len(set(post)),
        "post_exec_last_s": (post_last - start) / 1e9 if post_last else "",
        "root_named_exec_count": len(root_named_exec),
        "root_named_exec_before_or_at_boundary": sum(1 for ts, _, _ in root_named_exec if boundary and ts <= boundary + 1_000_000),
        "named_execve_total": named_counts.get("execve", 0),
        "fallback_execve": (diag.get("raw_syscall_feature_fallbacks") or {}).get("execve", 0),
        "fallback_total": sum((diag.get("raw_syscall_feature_fallbacks") or {}).values()),
        "root_exit_s": (root_exit - start) / 1e9 if root_exit else "",
        "last_event_s": (last_ts - start) / 1e9 if last_ts else "",
        "events_before_start": int(first_ts is not None and first_ts < start),
        "active_windows": len(windows),
        "named_events": named_total,
        "raw_syscalls": raw_total,
        "distinct_pids": len(raw_pids),
        "distinct_tids_named": len(tids),
        "fork_events": named_counts.get("fork", 0),
        "dup2_events": named_counts.get("dup2", 0),
        "connect_events": named_counts.get("connect", 0),
        "pid_reuse_suspects": len(reuse),
        "pcap_packets_captured": stats.get("packets_captured", ""),
        "ebpf_lost": meta.get("ebpf_lost_event_count"),
    }


def main() -> int:
    malware_fam, benign_fam = scale_family_maps()
    alignment = p4_alignment()
    modeled = oof_samples()
    rows = []
    for cohort, names, fam in (
        ("malware", read_names(SCALE / "manifests/malware-100-completion.txt"), malware_fam),
        ("benign_script", read_names(SCALE / "manifests/benign-100.txt"), benign_fam),
    ):
        sub = "malware" if cohort == "malware" else "benign"
        for sample in names:
            runs = sorted((SCALE / "runs" / sub / sample / "output").glob("run_*/run.json"))
            if len(runs) != 1:
                raise SystemExit(f"{cohort}/{sample}: expected one run.json, found {len(runs)}")
            row = {"cohort": cohort, "sample": sample, "group": fam[sample],
                   "p4_alignment": alignment.get(sample, ""), "in_183_model": sample in modeled}
            row.update(audit_run(runs[0].parent))
            rows.append(row)
    for run_json in sorted((ELF / "runs/benign-elf").glob("profile-*/*/output/run_*/run.json")):
        tool = run_json.parents[2].name
        profile = run_json.parents[3].name
        row = {"cohort": "benign_elf", "sample": f"{profile}/{tool}", "group": tool,
               "p4_alignment": "", "in_183_model": False}
        row.update(audit_run(run_json.parent))
        rows.append(row)
    if Counter(r["cohort"] for r in rows) != Counter({"malware": 100, "benign_script": 100, "benign_elf": 100}):
        raise SystemExit(f"unexpected cohort counts {Counter(r['cohort'] for r in rows)}")
    with (HERE / "run_audit.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    def med(values):
        values = [float(v) for v in values if v != "" and v is not None]
        return round(statistics.median(values), 4) if values else None

    summary: dict = {"derived": True, "exploratory": True, "inputs": [str(SCALE), str(ELF)], "cohorts": {}}
    for cohort in ("malware", "benign_script", "benign_elf"):
        sub = [r for r in rows if r["cohort"] == cohort]
        acc = [r for r in sub if r["quality"] == "accepted"]
        summary["cohorts"][cohort] = {
            "runs": len(sub),
            "accepted": len(acc),
            "groups": len({r["group"] for r in sub}),
            "in_183_model": sum(r["in_183_model"] for r in sub),
            "p4_alignment": dict(Counter(r["p4_alignment"] for r in sub)),
            "return_codes": dict(Counter(str(r["return_code"]) for r in acc)),
            "root_raw_exec_count": dict(Counter(r["root_raw_exec_count"] for r in acc)),
            "exec_success_inferred": dict(Counter(r["exec_success_inferred"] for r in acc)),
            "comm_after_boundary_launcher": sorted(r["sample"] for r in acc if not r["exec_success_inferred"]),
            "exec_outcome": dict(Counter(r["exec_outcome"] for r in acc)),
            "post_exec_raw_syscalls_lt_50": sum(1 for r in acc if r["post_exec_raw_syscalls"] < 50),
            "post_exec_raw_syscalls_lt_50_in_183": sum(1 for r in acc if r["post_exec_raw_syscalls"] < 50 and r["in_183_model"]),
            "median_post_exec_raw_syscalls": med(r["post_exec_raw_syscalls"] for r in acc),
            "median_post_exec_distinct_ids": med(r["post_exec_distinct_syscall_ids"] for r in acc),
            "post_exec_activity_after_1s": sum(1 for r in acc if r["post_exec_last_s"] != "" and float(r["post_exec_last_s"]) > 1),
            "post_exec_activity_after_5s": sum(1 for r in acc if r["post_exec_last_s"] != "" and float(r["post_exec_last_s"]) > 5),
            "root_named_exec_count": dict(Counter(r["root_named_exec_count"] for r in acc)),
            "runs_with_fallback_execve": sum(1 for r in acc if r["fallback_execve"]),
            "watch_paths": dict(Counter(r["n_watch_paths"] for r in acc)),
            "observation_mode": dict(Counter(str(r["observation_mode"]) for r in acc)),
            "median_observation_s": med(r["observation_s"] for r in acc),
            "median_root_exit_s": med(r["root_exit_s"] for r in acc),
            "root_exit_missing": sum(1 for r in acc if r["root_exit_s"] == ""),
            "root_exit_lt_1s": sum(1 for r in acc if r["root_exit_s"] != "" and float(r["root_exit_s"]) < 1),
            "median_last_event_s": med(r["last_event_s"] for r in acc),
            "median_active_windows": med(r["active_windows"] for r in acc),
            "median_named_events": med(r["named_events"] for r in acc),
            "median_raw_syscalls": med(r["raw_syscalls"] for r in acc),
            "median_distinct_pids": med(r["distinct_pids"] for r in acc),
            "median_fork_events": med(r["fork_events"] for r in acc),
            "median_dup2_events": med(r["dup2_events"] for r in acc),
            "runs_with_connect": sum(1 for r in acc if r["connect_events"]),
            "median_pcap_packets": med(r["pcap_packets_captured"] for r in acc),
            "runs_events_before_start": sum(r["events_before_start"] for r in acc),
            "runs_pid_reuse_suspect": sum(1 for r in acc if r["pid_reuse_suspects"]),
            "started_min": min(r["started_at_utc"] for r in sub),
            "started_max": max(r["started_at_utc"] for r in sub),
        }
    (HERE / "run_audit_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
