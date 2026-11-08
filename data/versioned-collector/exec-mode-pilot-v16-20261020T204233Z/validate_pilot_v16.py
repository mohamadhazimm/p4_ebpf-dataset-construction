#!/usr/bin/env python3
"""Read-only validation of the Phase B (schema .16) benign execution-mode pilot.

Structural invariants (provenance, sensors, telemetry, archive) are hard errors.
Preregistered predictions P1-P8 are evaluated with the frozen rules in
preregistration.json and reported as pass/fail; they are not tuned here.
"""
import csv
import hashlib
import json
import math
import statistics
import sys
import tarfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = json.loads((ROOT / "experiment_manifest.json").read_text())
PHASE_B = MANIFEST["phase_b"]
PREREG_PATH = ROOT / "preregistration.json"
CASES = {case["sample"]: case for case in json.loads((ROOT / "cases.json").read_text())["cases"]}
RUN_ROOT = ROOT / PHASE_B["output"]
EXPECTED_ROWS = int(PHASE_B["timeout_s"] / 0.5)
EXEC_EVENTS = {"exec_success", "exec_return"}
RUNNABLE_MODES = {"amd64-dynamic", "amd64-static", "i386-static", "armel-static", "mipsel-static", "arm64-static"}
QEMU_BY_MACHINE = {40: "qemu-arm", 8: "qemu-mipsel", 183: "qemu-aarch64"}
SINK_ADDR = "addr=167772161 port=80"  # 10.0.0.1:80


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_csv(path):
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def detail_value(detail, key):
    for part in detail.split():
        if part.startswith(key + "="):
            return part.split("=", 1)[1]
    return None


errors = []
runs = {}
if sha(PREREG_PATH.read_bytes()) != PHASE_B["preregistration_sha256"]:
    errors.append("preregistration.json hash differs from the frozen manifest value")

for sample, case in CASES.items():
    sample_dir = RUN_ROOT / sample
    problems = []

    def check(condition, message):
        if not condition:
            problems.append(message)

    host_file = sample_dir / "host_run.txt"
    host = dict(line.split("=", 1) for line in host_file.read_text().split() if "=" in line) if host_file.exists() else {}
    run_dirs = sorted((sample_dir / "output").glob("run_*")) if (sample_dir / "output").exists() else []
    check(host.get("status") == "completed", f"retrieval {host.get('status')}")
    check(len(run_dirs) == 1, f"{len(run_dirs)} run directories")
    if problems:
        runs[sample] = {"case": case, "problems": problems}
        errors += [f"{sample}: {p}" for p in problems]
        continue
    run_dir = run_dirs[0]
    meta = json.loads((run_dir / "run.json").read_text())
    root_pid = meta["sample_root_pid"]

    check(meta["telemetry_schema_version"] == PHASE_B["schema"], "schema mismatch")
    check(meta["malware_runner_sha256"] == PHASE_B["runner_sha256"], "runner hash mismatch")
    check(meta["ebpf_status"] == "active", "eBPF inactive")
    check("target_exec" in meta and "target_artifact" in meta, "target_exec/target_artifact missing")

    telemetry = read_csv(run_dir / "telemetry.csv")
    features = [name for group in meta["telemetry_feature_groups"].values() for name in group]
    check(len(features) == 169, f"feature count {len(features)}")
    check(len(telemetry) == EXPECTED_ROWS, f"telemetry rows {len(telemetry)}")
    check(all(math.isfinite(float(row[name])) for row in telemetry for name in features), "non-finite features")

    events = read_csv(run_dir / "ebpf_events.csv")
    exec_rows = read_csv(run_dir / "exec_events.csv")
    check(not ({row["event"] for row in events} & EXEC_EVENTS), "exec diagnostics leaked into ebpf_events.csv")
    check(exec_rows and {row["event"] for row in exec_rows} <= EXEC_EVENTS, "exec_events.csv content")

    archived = 0
    with tarfile.open(sample_dir / "output.tgz") as archive:
        for member in archive.getmembers():
            name = Path(member.name)
            check(not name.is_absolute() and ".." not in name.parts, f"unsafe member {member.name}")
            if member.isfile():
                archived += 1
                extracted = sample_dir / "output" / name
                check(extracted.is_file() and sha(archive.extractfile(member).read()) == sha(extracted.read_bytes()),
                      f"archive mismatch {member.name}")

    # Workload-specific evidence used by P5/P6 and the net/i386 diagnostics.
    root_events = [row for row in events if int(row["pid"]) == root_pid]
    # ebpf_events.csv is already restricted to the sample lineage; nc runs as a child of the root.
    connects = [row for row in events if row["event"] == "connect"]
    sink_connects = sum(1 for row in connects if SINK_ADDR in row["detail"])
    thread_exec = None
    if case["workload"] == "thread-exec":
        sh_execs = [row for row in exec_rows if row["event"] == "exec_success" and int(row["pid"]) == root_pid
                    and detail_value(row["detail"], "filename") == "/bin/sh"]
        old_pids = [int(detail_value(row["detail"], "old_pid")) for row in sh_execs]
        after = int(sh_execs[0]["timestamp_ns"]) if sh_execs else None
        opens_after = sum(1 for row in root_events if row["event"] == "openat" and "ka_thread_exec.txt" in row["detail"]
                          and after is not None and int(row["timestamp_ns"]) > after)
        thread_exec = {"sh_exec_count": len(sh_execs), "old_pids": old_pids,
                       "old_pid_differs": any(pid != root_pid for pid in old_pids),
                       "openat_after_sh_exec": opens_after}
    leader_exit = None
    if case["workload"] == "leader-exit":
        leader_exits = [row for row in root_events if row["event"] == "exit" and int(row["tid"]) == root_pid]
        live = [detail_value(row["detail"], "live") for row in leader_exits]
        first_live = next((int(row["timestamp_ns"]) for row, value in zip(leader_exits, live)
                           if value is not None and int(value) > 0), None)
        worker_opens = sum(1 for row in root_events if row["event"] == "openat" and "ka_leader_exit.txt" in row["detail"]
                           and int(row["tid"]) != root_pid and first_live is not None
                           and int(row["timestamp_ns"]) > first_live)
        leader_exit = {"leader_exit_live_values": live, "worker_openat_after_leader_exit": worker_opens}

    workspace = run_dir / "workspace"
    net_body = workspace / "bb_net_workload.html"
    runs[sample] = {
        "case": {k: case[k] for k in ("mode", "workload", "repeat", "member")},
        "problems": problems,
        "process_status": meta["status"],
        "return_code": meta["return_code"],
        "quality": meta["collection_quality_status"],
        "quality_reasons": meta.get("collection_quality_reasons"),
        "ebpf_lost": meta.get("ebpf_lost_event_count"),
        "pcap_drops": meta.get("packet_capture_dropped_by_kernel"),
        "pcap_discrepancy": meta.get("packet_capture_counter_discrepancy"),
        "target_exec": meta["target_exec"],
        "target_artifact": meta["target_artifact"],
        "named_vs_raw": meta["ebpf_event_diagnostics"].get("named_vs_raw_syscalls"),
        "ebpf_event_count": meta.get("ebpf_event_count"),
        "raw_syscall_event_count": meta.get("raw_syscall_event_count"),
        "lineage_connects": len(connects),
        "lineage_sink_connects": sink_connects,
        "net_body_bytes": net_body.stat().st_size if net_body.exists() else None,
        "archive_files": archived,
        "thread_exec": thread_exec,
        "leader_exit": leader_exit,
    }
    errors += [f"{sample}: {p}" for p in problems]

# ---- Preregistered tiers -------------------------------------------------
valid = {s: r for s, r in runs.items() if "target_exec" in r}


def stratum(run):
    art = run["target_artifact"]
    return (art.get("e_machine"), art.get("linkage"))


def accepted(run):
    return run["quality"] == "accepted" and run["ebpf_lost"] == 0 and run["pcap_drops"] == 0 \
        and run["pcap_discrepancy"] == 0


nulls = defaultdict(dict)
for s, r in valid.items():
    if r["case"]["workload"] == "null" and accepted(r):
        nulls[stratum(r)][s] = r["target_exec"].get("post_target_lineage_raw_syscalls") or 0


def floor_for(sample, run):
    key = stratum(run)
    pool = nulls.get(key)
    used = key
    if not pool:
        used = (key[0], "static")
        pool = nulls.get(used, {})
    values = [v for s, v in pool.items() if s != sample]
    return (max(values) if values else None), used, len(values)


for s, r in valid.items():
    floor, used, n = floor_for(s, r)
    post = r["target_exec"].get("post_target_lineage_raw_syscalls")
    if r["target_exec"]["status"] != "observed":
        tier = "not_launched"
    elif floor is None:
        tier = "undetermined_no_floor"
    else:
        tier = "progressed" if (post or 0) > floor + max(25, 0.25 * floor) else "launched_no_progress"
    r["tier"] = {"tier": tier, "floor": floor, "margin": None if floor is None else max(25, 0.25 * floor),
                 "floor_stratum": list(used), "floor_n": n, "post_target_lineage_raw_syscalls": post}


def by(mode=None, workload=None):
    return {s: r for s, r in valid.items()
            if (mode is None or r["case"]["mode"] in ([mode] if isinstance(mode, str) else mode))
            and (workload is None or r["case"]["workload"] in ([workload] if isinstance(workload, str) else workload))}


def verdict(failures, n):
    return {"status": "pass" if not failures and n else "fail", "n": n, "failures": failures}


preds = {}
sel = by(RUNNABLE_MODES, "null")
preds["P1_null_runs"] = verdict([f"{s}: {r['tier']['tier']}" for s, r in sel.items()
                                 if accepted(r) and r["tier"]["tier"] != "launched_no_progress"], len(sel))
sel = by(RUNNABLE_MODES, ["file", "net"])
preds["P2_workload_runs"] = verdict([f"{s}: {r['tier']['tier']} post={r['tier']['post_target_lineage_raw_syscalls']} "
                                     f"floor={r['tier']['floor']}" for s, r in sel.items()
                                     if accepted(r) and r["tier"]["tier"] != "progressed"], len(sel))
sel = by("armel-dynamic")
fails = []
for s, r in sel.items():
    art, te = r["target_artifact"], r["target_exec"]
    if art.get("execution_mode") != "binfmt_emulated":
        fails.append(f"{s}: execution_mode {art.get('execution_mode')}")
    if art.get("interpreter_present") is not False:
        fails.append(f"{s}: interpreter_present {art.get('interpreter_present')}")
    if te["status"] != "observed" or te["match"] != "exact":
        fails.append(f"{s}: target {te['status']}/{te['match']}")
    if r["tier"]["tier"] != "launched_no_progress":
        fails.append(f"{s}: tier {r['tier']['tier']}")
preds["P3_unrunnable_emulated_dynamic"] = verdict(fails, len(sel))
sel = by("amd64-truncated")
fails = []
for s, r in sel.items():
    errnos = [f.get("errno") for f in r["target_exec"]["root_exec_failures"]]
    if r["tier"]["tier"] != "not_launched":
        fails.append(f"{s}: tier {r['tier']['tier']}")
    if 8 not in errnos:
        fails.append(f"{s}: errnos {errnos}")
preds["P4_invalid_elf"] = verdict(fails, len(sel))
sel = by(workload="thread-exec")
fails = []
for s, r in sel.items():
    t = r["thread_exec"]
    if r["target_exec"]["status"] != "observed":
        fails.append(f"{s}: target {r['target_exec']['status']}")
    if not t["old_pid_differs"]:
        fails.append(f"{s}: /bin/sh exec old_pids {t['old_pids']}")
    if t["openat_after_sh_exec"] < 200:
        fails.append(f"{s}: openat after sh exec {t['openat_after_sh_exec']}")
preds["P5_thread_exec"] = verdict(fails, len(sel))
sel = by(workload="leader-exit")
fails = [f"{s}: live={r['leader_exit']['leader_exit_live_values']} worker_openat="
         f"{r['leader_exit']['worker_openat_after_leader_exit']}"
         for s, r in sel.items() if r["leader_exit"]["worker_openat_after_leader_exit"] < 200]
preds["P6_leader_exit"] = verdict(fails, len(sel))
sel = {s: r for s, r in valid.items() if r["target_artifact"].get("execution_mode") == "binfmt_emulated"}
fails = []
for s, r in sel.items():
    art, te = r["target_artifact"], r["target_exec"]
    if te["match"] != "exact":
        fails.append(f"{s}: match {te['match']}")
    want = QEMU_BY_MACHINE.get(art.get("e_machine"))
    if want is None or art.get("binfmt_handler") != want:
        fails.append(f"{s}: handler {art.get('binfmt_handler')} machine {art.get('e_machine')}")
preds["P7_emulated_filename"] = verdict(fails, len(sel))
preds["P8_sensor_quality"] = verdict([f"{s}: quality={r['quality']} lost={r['ebpf_lost']} drops={r['pcap_drops']} "
                                      f"disc={r['pcap_discrepancy']}" for s, r in valid.items() if not accepted(r)],
                                     len(valid))

# ---- Descriptive diagnostics (not preregistered) -------------------------
profiles = defaultdict(list)
for r in valid.values():
    profiles[(r["case"]["mode"], r["case"]["workload"])].append(r["tier"]["post_target_lineage_raw_syscalls"] or 0)
profile_table = {f"{m}/{w}": {"n": len(v), "min": min(v), "median": statistics.median(v), "max": max(v)}
                 for (m, w), v in sorted(profiles.items())}
net_runs = by(workload="net")
diagnostics = {
    "post_target_lineage_by_mode_workload": profile_table,
    "net_runs_with_sink_connect": {s: r["lineage_sink_connects"] for s, r in net_runs.items()},
    "net_body_bytes": {s: r["net_body_bytes"] for s, r in net_runs.items()},
    "i386_connect_decoded": {s: r["lineage_sink_connects"] for s, r in by("i386-static", "net").items()},
    "named_vs_raw_by_run": {s: r["named_vs_raw"] for s, r in valid.items()},
    "process_status_counts": {k: sum(1 for r in valid.values() if r["process_status"] == k)
                              for k in sorted({r["process_status"] for r in valid.values()})},
}

report = {
    "schema": PHASE_B["schema"], "runner_sha256": PHASE_B["runner_sha256"],
    "preregistration_sha256": PHASE_B["preregistration_sha256"],
    "structural_status": "accepted" if not errors else "rejected", "structural_errors": errors,
    "predictions": preds, "diagnostics": diagnostics, "runs": runs,
}
(ROOT / "pilot_v16_validation.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
print(json.dumps({"structural_status": report["structural_status"], "structural_errors": errors[:20],
                  "predictions": {k: (v["status"], v["n"], v["failures"][:6]) for k, v in preds.items()},
                  "profiles": profile_table,
                  "net_sink_connects": diagnostics["net_runs_with_sink_connect"],
                  "process_status": diagnostics["process_status_counts"]}, indent=1))
sys.exit(0 if not errors else 1)
