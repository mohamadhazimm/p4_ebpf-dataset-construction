#!/usr/bin/env python3
"""Read-only: estimate raw-syscall fallback counts lost to the /proc ABI race in .14 cohorts.

Expected fallback per (window, pid, syscall) = max(raw - named, 0), with raw IDs mapped by the
x86_64 table (native i386 malware is skipped). Lost = expected - recorded fallback in run.json.
"""
import collections
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VC = ROOT.parent
# x86_64 table copied from src/malware_runner.py SYSCALL_NAMES_BY_ABI (schema .17); the host lacks
# the runner's watchdog/psutil imports.
X86_64 = {
    1: "write", 3: "close", 9: "mmap", 10: "mprotect", 18: "pwrite64",
    20: "writev", 33: "dup2", 41: "socket", 42: "connect", 43: "accept",
    44: "sendto", 45: "recvfrom", 49: "bind", 50: "listen", 59: "execve",
    62: "kill", 101: "ptrace", 257: "openat", 263: "unlinkat",
    264: "renameat", 288: "accept4", 292: "dup3", 316: "renameat2",
    322: "execveat", 437: "openat2",
}
COHORTS = {
    "scale100-malware": VC / "scale-100x100-v14-20261020T072500Z/runs/malware",
    "scale100-benign": VC / "scale-100x100-v14-20261020T072500Z/runs/benign",
    "benign-elf-100": VC / "benign-elf-100-v14-20261020T140000Z/runs/benign-elf",
}
ELF = {row["sample"]: row for row in csv.DictReader(
    open(VC / "independent-audit-derived-20261020/elf_header_linkage.csv"))}

report = {"method": __doc__.strip(), "cohorts": {}}
for cohort, base in COHORTS.items():
    runs = []
    for run_json in sorted(base.rglob("run.json")):
        run_dir = run_json.parent
        sample = run_dir.parent.parent.name
        if ELF.get(sample, {}).get("machine") == "EM_386":
            continue
        meta = json.loads(run_json.read_text())
        if meta.get("collection_quality_status") != "accepted":
            continue
        windows = int(meta.get("window_count") or 0) or None
        raw = collections.Counter()
        for row in csv.DictReader(open(run_dir / "syscall_events.csv")):
            name = X86_64.get(int(row["detail"].partition("=")[2]))
            if name:
                raw[(row["window_id"], row["pid"], name)] += 1
        named = collections.Counter()
        for row in csv.DictReader(open(run_dir / "ebpf_events.csv")):
            named[(row["window_id"], row["pid"], row["event"])] += 1
        expected = collections.Counter()
        for (window, pid, name), count in raw.items():
            expected[name] += max(count - named[(window, pid, name)], 0)
        recorded = collections.Counter(meta["ebpf_event_diagnostics"].get("raw_syscall_feature_fallbacks", {}))
        lost = {name: expected[name] - recorded[name] for name in expected if expected[name] != recorded[name]}
        telemetry = list(csv.DictReader(open(run_dir / "telemetry.csv")))
        feature_total = {name: sum(float(r[f"ebpf_{name}_count"]) for r in telemetry)
                         for name in lost if f"ebpf_{name}_count" in telemetry[0]}
        runs.append({"sample": sample, "lost": lost, "feature_total": feature_total,
                     "expected_total": sum(expected.values()), "recorded_total": sum(recorded.values())})
    lost_total = collections.Counter()
    for run in runs:
        lost_total.update(run["lost"])
    report["cohorts"][cohort] = {
        "runs": len(runs),
        "runs_with_lost_fallback": sum(bool(r["lost"]) for r in runs),
        "runs_with_negative_lost": sum(any(v < 0 for v in r["lost"].values()) for r in runs),
        "lost_by_syscall": dict(lost_total),
        "max_lost_in_run": max((sum(r["lost"].values()) for r in runs), default=0),
        "expected_fallback_total": sum(r["expected_total"] for r in runs),
        "recorded_fallback_total": sum(r["recorded_total"] for r in runs),
        "runs_detail": [r for r in runs if r["lost"]],
    }
    print(cohort, {k: v for k, v in report["cohorts"][cohort].items() if k != "runs_detail"})
(ROOT / "historical_abi_fallback_audit.json").write_text(json.dumps(report, indent=2) + "\n")
