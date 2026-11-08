"""Benign-only 5-min collection of the two missing benign SHAPES (300 s / 600 windows): 43 short tasks that run and
exit + 15 sparse periodic jobs + 3 null. NO malware. See build_benign_bursty_payload.py for the why.

Reuses collect_pilot's phase machinery unchanged (.22 pins, 300 s settings, approval-gated phases, restore on exit).
Adds --behavior-check: the 5-min audit (collect_pilot.pilot_audit) checks capture quality, exec, 600 finite windows and
archive hashes, but NOT whether the program did what it was meant to do -- that is how the benign-expanded top
(segfault, rc -11) and lowrate (usage error, rc 2) runs were counted as accepted. The behaviour check compares each
run's return code and activity timing with its design and lists every mismatch.

  1. collect_benign_bursty.py --self-test / --freeze-only
  2. --phase preflight (read-only) -> --phase stage -> --phase dry-run -> --phase collect
  3. --validate, then --behavior-check, then the combined re-score (host-gap-check-20261107/).
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_pilot as cp                       # noqa: E402  phase machinery + .22 pins + 300 s settings
import build_benign_bursty_payload as benx       # noqa: E402

cp.FORMAT = "observation-length-benign-bursty-v1"
FORMAT = cp.FORMAT
require, digest, save, stamp = cp.require, cp.digest, cp.save, cp.stamp
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SETTINGS, PINNED, SCHEMA, BASELINE = cp.SETTINGS, cp.PINNED, cp.SCHEMA, cp.BASELINE


def freeze():
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed; run build_runner_v22.py")
    run_id = stamp()
    attempt = ROOT / "benign-bursty-5min" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/benburst5min-" + run_id
    manifest, order = benx.build(attempt / "payload", guest_root)
    require(manifest["counts"] == {"benign": 58, "null": 3}
            and manifest["by_kind"] == {"short": 43, "sparse": 15, "null": 3}, "bursty payload counts out of range")
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    import subprocess
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in order))

    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-benburst5min-" + run_id, "benign_snapshot": "clean-benburst5min-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_kind": manifest["by_kind"],
        "by_mode_label": manifest["by_mode_label"], "by_project": manifest["by_project"],
        "network_benign": sum(1 for c in order if c["label"] == "benign" and c.get("network")),
        "short_tasks": manifest["short_tasks"], "sparse_jobs": manifest["sparse_jobs"],
        "fixtures_copied": manifest["fixtures_copied"], "expected_windows": cp.EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(benx.__file__)),
        "workloads_expanded_sha256": digest(ROOT / "benign_workloads_expanded.py"),
        "revision5_payload_manifest_sha256": digest(benx.REV5_PAYLOAD / "payload_manifest.json"),
        "driver_sha256": digest(__file__), "approval": None, "vm_steps_authorized": [], "retries": False,
        "resume": False, "replacement": False, "model_fitting": False, "merge_with_any_dataset": False,
        "collection_ready": False,
        "pairs_with_malware": "scale-5min/20261105T224558731619Z + topup-5min/20261106T073625330426Z + "
                              "topup-5min-finish/20261106T155820346732Z (already-collected 5-min malware)",
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Break the 5-min lifetime shortcut (one feature, 'windows with any system calls', BA 0.81-0.84):",
                    "add benign that run briefly and exit (43 of the paper's own validated tasks, 24 projects) and",
                    "benign that wake only every 5-30 s (15 periodic jobs), the two activity shapes most of the 5-min",
                    "malware show and the 5-min benign never did. Scored with the already-collected 5-min malware."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec;",
                     "telemetry 600x169 finite; safe archive hashes; nulls quiet; PLUS the behaviour check (return",
                     "code and activity timing match each job's design); mismatches are reported, not hidden."],
        "limitations": [".22 bounded-memory headless-quiet dataset; never merged with .21/.20/.19 or other captures.",
                        "Short tasks are the paper's 20 s benign tasks re-run at 5 min (same programs, new runs).",
                        "Sparse jobs are variants of existing groups (procps, inetutils ping, wget) plus lowrate_gen",
                        "for 60 s; top is excluded (segfaults in this guest)."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_kind": protocol["by_kind"],
                      "by_mode_label": protocol["by_mode_label"], "network_benign": protocol["network_benign"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


# --------------------------------------------------------------------------------------------- behaviour check
def expectation(case):
    """What each job was designed to do (return code set, activity-timing bounds). None = report only."""
    if case["label"] == "null":
        return {"rc": {0}, "max_last_active": 5}
    if case["kind"] == "short":
        rc = set(case["expected_returncodes"]) if case.get("expected_returncodes") and not case.get("network") else None
        return {"rc": rc, "min_active": 1, "max_last_active": 60}          # finishes early (<= ~30 s)
    prog = case["program"]
    if prog in ("vmstat", "free", "ping"):
        return {"rc": {-15}, "min_active": 5, "max_active": 120, "min_last_active": 500}
    if prog == "wget":
        return {"rc": {-15, 0, 4, 8}, "min_active": 5, "max_active": 200, "min_last_active": 500}
    if prog == "lowrate":
        return {"rc": {0}, "min_active": 3, "max_last_active": 140}          # 60 s of polls, then exits
    raise KeyError(prog)


def behavior_check(attempt, expected_hash):
    protocol = cp.verify_plan(Path(attempt), expected_hash)
    rows, bad = [], []
    for case in protocol["cases"]:
        runs = sorted((Path(attempt) / "runs" / case["sample"] / "output").glob("run_*/run.json"))
        if len(runs) != 1:
            rows.append({"sample": case["sample"], "status": "missing"}); bad.append(case["sample"]); continue
        m = json.load(open(runs[0]))
        tel = list(csv.DictReader(open(runs[0].with_name("telemetry.csv"))))
        host = [float(t["host_total_syscalls_total"]) for t in tel]
        net = [float(t["net_pkts_total_delta"]) for t in tel]
        iface = [float(t["net_packets_sent"]) + float(t["net_packets_recv"]) for t in tel]
        active = [i for i, v in enumerate(host) if v]
        row = {"sample": case["sample"], "kind": case.get("kind", "null"), "program": case.get("program"),
               "rc": m.get("return_code"), "quality": m.get("collection_quality_status"),
               "host_active_windows": len(active), "last_active_window": max(active) if active else -1,
               "p4_active_windows": sum(1 for v in net if v), "iface_packets": int(sum(iface)),
               "post_target_syscalls": (m.get("target_exec") or {}).get("post_target_lineage_raw_syscalls")}
        e, why = expectation(case), []
        if e.get("rc") is not None and row["rc"] not in e["rc"]:
            why.append("rc %s not in %s" % (row["rc"], sorted(e["rc"])))
        if row["host_active_windows"] < e.get("min_active", 0):
            why.append("active %d < %d" % (row["host_active_windows"], e["min_active"]))
        if row["host_active_windows"] > e.get("max_active", 10 ** 9):
            why.append("active %d > %d" % (row["host_active_windows"], e["max_active"]))
        if row["last_active_window"] > e.get("max_last_active", 10 ** 9):
            why.append("last active %d > %d" % (row["last_active_window"], e["max_last_active"]))
        if row["last_active_window"] < e.get("min_last_active", -1):
            why.append("last active %d < %d" % (row["last_active_window"], e["min_last_active"]))
        if case.get("network") and row["iface_packets"] == 0:
            why.append("network job sent/received no packets")
        row["behavior"] = "as_designed" if not why else "mismatch: " + "; ".join(why)
        if why:
            bad.append(case["sample"])
        rows.append(row)
    report = {"protocol_sha256": expected_hash, "rows": rows, "mismatches": bad,
              "counts": {"as_designed": sum(1 for r in rows if r.get("behavior") == "as_designed"),
                         "mismatch": len(bad)}, "checker_sha256": digest(__file__)}
    out = Path(attempt) / ("behavior-" + stamp() + ".json")
    save(out, report)
    for r in rows:
        print("  %-62s %-6s rc=%-4s active=%3s last=%3s p4=%3s pkts=%-6s %s" % (
            r["sample"][:62], r.get("kind", ""), r.get("rc"), r.get("host_active_windows"),
            r.get("last_active_window"), r.get("p4_active_windows"), r.get("iface_packets"), r.get("behavior", r.get("status"))))
    print(json.dumps({"report": str(out), **report["counts"]}, indent=2))
    return report


def self_test():
    cp.settings_tests()
    import tempfile
    from collections import Counter
    with tempfile.TemporaryDirectory(prefix="hazim-benburst-build-") as d:
        manifest, order = benx.build(Path(d) / "payload", "/home/csci/Downloads/benburst5min-TEST")
        require(manifest["counts"] == {"benign": 58, "null": 3}, "counts wrong")
        require(len(order) == len({c["sample"] for c in order}), "duplicate samples")
        require({c["mode"] for c in order} <= {"native_amd64_static", "native_amd64_dynamic", "native_i386_static"},
                "unmapped mode")
        kinds = Counter(c.get("kind", "null") for c in order)
        require(kinds == {"short": 43, "sparse": 15, "null": 3}, "kinds wrong: " + str(dict(kinds)))
        for c in order:                                  # every case has a behaviour expectation
            expectation(c)
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "benburst5min-TEST" not in a.read_text()]
        require(not stale, "stale guest-root: " + ",".join(stale))
    cp.phase_mock_tests()
    print("PASS collect_benign_bursty self-test (43 short + 15 sparse + 3 null, expectations defined, root checks, mocks)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Benign-only bursty/short 5-min collection (300 s / 600 windows)")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--phase", choices=["preflight", "preflight-benign", "stage", "dry-run", "collect"])
    p.add_argument("--validate", action="store_true")
    p.add_argument("--behavior-check", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.validate:
        cp.validate(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.behavior_check:
        behavior_check(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.phase:
        cp.perform_phase(Path(a.attempt).resolve(), a.phase, a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only, --phase, --validate or --behavior-check")


if __name__ == "__main__":
    main()
