"""Known-answer integrity battery for the installed .20 runner on the validated headless quiet snapshot.

Reuses frozen integrity_tests_v19.py unchanged (its probe, payload, per-case drop/leak audit and residue/credential
scan), re-pointed at .20, the headless quiet child and the quiet-v3.5 classifier (default-deny + bounded link-up
allowances + checksum-tolerant ICMP quotes). Adds one envelope case (250,000-packet UDP burst) and checks each .20 fix:
  * window_start_utc/window_end_utc lie on the sample-start + k*0.5 s grid (2 us tolerance);
  * offline recorded-window P4 reconstruction is unique for every case (it failed in 3 of 14 under .19);
  * the byte-level decoder accounted for every in-window packet (fast + scapy fallback == telemetry packets);
  * the interface IPv4 readiness wait reported ready; no post-processing error; run.json present for every case.
Phases: --self-test (local), --freeze-only (local), --execute (VM, verbatim approval), --validate (saved-only).
"""

import argparse
import hashlib
import json
import math
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v19 as c19  # noqa: E402  frozen helpers; production pins re-pointed below
import integrity_tests_v19 as v19i  # noqa: E402  frozen battery, imported unchanged
import quiet_rederive_v35 as quiet  # noqa: E402  quiet-v3.5 classifier chain

V19I_SHA256 = "1b10393b9a4f047d0733104f55209890e32059b1f59e0a997afff1cd45133d17"
QUIET_SHA256 = "40af1743a0a4152d0df066406090f4871dd7241abf29f9d3a88ba48b728b5202"
RUNNER20 = "80211b3d75f6c541eb3be5d8586dad7227d99b394a59f12c3080902bd060a5ab"
SCHEMA20 = "2026-10-24.20"
BASELINE20 = "clean-final-quiet-v19-20261024T150104720304Z"
BASELINE20_UUID = "7d211f0d-2e9a-410b-8230-66693dfe097b"
PINNED20 = {**c19.PINNED, "src/malware_runner.py": RUNNER20}
CONFIG20 = {**v19i.CONFIG, "telemetry_schema_version": SCHEMA20, "malware_runner_sha256": RUNNER20}
PLAN20 = [*v19i.PLAN, ("udp", [250000], True)]
ATTEMPTS = ROOT / "integrity-v20"
FORMAT = "v20-integrity-tests-v1"
GRID_TOLERANCE = timedelta(microseconds=2)


def install():
    """Point the frozen helpers at .20, the headless quiet child and the quiet-v3.5 classifier."""
    for name, expected in {"integrity_tests_v19.py": V19I_SHA256, "quiet_rederive_v35.py": QUIET_SHA256}.items():
        c19.require(c19.digest(ROOT / name) == expected, "Frozen helper changed: " + name)
    quiet.install()  # validate_quiet_v2.classify -> quiet-v3.5 classify (used by v19i.leak_ambient)
    c19.PINNED, c19.SCHEMA, c19.BASELINE = PINNED20, SCHEMA20, BASELINE20
    v19i.CONFIG, v19i.PLAN, v19i.ATTEMPTS = CONFIG20, PLAN20, ATTEMPTS
    v19i.verify_plan, v19i.validate = verify_plan, validate  # v19i.execute resolves these at call time


def freeze():
    install()
    v19i.check_frozen_helpers()
    run_id = c19.stamp()
    attempt = ATTEMPTS / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    cases = v19i.build_cases(hashlib.sha256(run_id.encode()).hexdigest()[:8])
    binary = v19i.compile_probe(attempt)
    payload = v19i.build_payload(cases, binary)
    guest_root = "/home/csci/Downloads/integrity-v20-" + run_id
    setup = v19i.setup_script(guest_root, payload)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    compile(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0], "setup", "exec")
    (attempt / "payload.tgz").write_bytes(payload)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in cases))
    gcc = subprocess.run(["gcc", "--version"], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    protocol = {"format": FORMAT, "schema": SCHEMA20, "production_hashes": PINNED20,
        "baseline_snapshot": BASELINE20, "baseline_uuid": BASELINE20_UUID,
        "new_snapshot": "clean-quiet-v20-integrity-" + run_id, "guest_root": guest_root, "cases": cases,
        "settings": c19.SETTINGS, "config_required": CONFIG20,
        "probe": {"source_sha256": c19.digest(v19i.PROBE_SOURCE), "binary_sha256": hashlib.sha256(binary).hexdigest(),
                  "compiler": gcc, "flags": "-std=c11 -O2 -static -pthread -s"},
        "frozen_helpers": {**v19i.FROZEN_HELPERS, "integrity_tests_v19.py": V19I_SHA256, "quiet_rederive_v35.py": QUIET_SHA256},
        "driver_sha256": c19.digest(__file__),
        "files": {name: c19.digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", v19i.PROGRAM)},
        "approval": None, "retries": False, "resume": False, "replacement": False, "malware": False,
        "model_fitting": False, "merge_with_any_dataset": False,
        "added_case": "int15 udp 250000 envelope: flood test of the .20 fast PCAP path (added beyond the approved 14)",
        "criteria": {
            "event_drops": "regular cases: lost 0, no untracked tid, unresolved ABI 0, CSV == metadata, exact known-answer counts",
            "packet_drops": "regular cases: PCAP == received == captured, kernel drops 0, discrepancy 0, NIC drops 0, every "
                            "UDP sequence once, every HTTP request + 200",
            "leaks": "zero unexplained frames under quiet-v3.5 classification; no foreign marker; credential absent",
            "envelopes": "2M getppid: loss absent or reported+rejected; 250k UDP flood: run.json present, packets exact or "
                         "loss reported+rejected; never silent",
            "v20_fixes": "grid window bounds; unique offline window attribution in every case; decoder fast+fallback == "
                         "telemetry packets; IPv4 ready; no postprocessing error"},
        "limitations": ["Benign synthetic workloads on one static amd64 mode; not malware or arbitrary-rate proof",
                        "Frame classification is by endpoint/protocol/marker, not OS-process ownership",
                        "Headless quiet guest; .20 captures stay separate from .19/.18/desktop data",
                        "In-kernel syscall aggregation is not part of .20: bursts above ~1M events still lose events"]}
    c19.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": c19.digest(attempt / "protocol.json"),
                      "cases": len(cases), "vm_steps_authorized": []}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    c19.require(expected_hash and c19.digest(attempt / "protocol.json") == expected_hash, "Explicit frozen protocol hash required")
    protocol = c19.load(attempt / "protocol.json")
    c19.require(protocol["format"] == FORMAT and protocol["production_hashes"] == PINNED20
                and protocol["settings"] == c19.SETTINGS and protocol["baseline_snapshot"] == BASELINE20
                and protocol["config_required"] == CONFIG20, "Frozen .20 contract differs")
    v19i.check_frozen_helpers()  # frozen helper hashes + c19.verify_production against PINNED20
    c19.require(c19.digest(v19i.PROBE_SOURCE) == protocol["probe"]["source_sha256"], "Probe source changed")
    for name, expected in protocol["files"].items():
        c19.require(c19.digest(attempt / name) == expected, "Frozen file changed: " + name)
    return protocol


def execute(attempt, expected_hash, approval):
    install()
    protocol = verify_plan(attempt, expected_hash)
    module = c19.helper()
    c19.require(c19.snapshot_uuid(module, BASELINE20) == protocol["baseline_uuid"], "Quiet child UUID differs")
    return v19i.execute(attempt, expected_hash, approval)


def grid_check(metadata, rows):
    start = datetime.fromisoformat(metadata["sample_started_at_utc"])
    width = timedelta(seconds=float(metadata["window_seconds"]))
    worst = timedelta(0)
    for index, row in enumerate(rows):
        expected_start = start + index * width
        for actual, expected in ((datetime.fromisoformat(row["window_start_utc"]), expected_start),
                                 (datetime.fromisoformat(row["window_end_utc"]), expected_start + width)):
            worst = max(worst, abs(actual - expected))
    return {"ok": worst <= GRID_TOLERANCE, "max_offset_us": worst / timedelta(microseconds=1)}


def v20_checks(case, sample_dir):
    import csv
    paths = list((sample_dir / "output").glob("run_*/run.json"))
    if len(paths) != 1:
        return {"verdict": "fail", "checks": {"run_json_present": False}}
    run_dir, metadata = paths[0].parent, c19.load(paths[0])
    rows = list(csv.DictReader((run_dir / "telemetry.csv").open()))
    grid = grid_check(metadata, rows)
    decoder = metadata.get("packet_window_decoder") or {}
    in_window = sum(int(row["net_packets_captured"]) for row in rows)
    ipv4 = metadata.get("packet_capture_interface_ipv4_ready") or {}
    checks = {"run_json_present": True, "grid_window_bounds": grid["ok"],
              "decoder_accounts_for_every_packet": decoder.get("fast", 0) + decoder.get("scapy_fallback", 0) == in_window,
              "ipv4_ready": ipv4.get("ready") is True,
              "no_postprocessing_error": "postprocessing_error" not in metadata
                                         and not any(str(r).startswith("postprocessing") for r in metadata["collection_quality_reasons"])}
    started = datetime.fromisoformat(metadata["started_at_utc"])
    finished = datetime.fromisoformat(metadata["finished_at_utc"])
    return {"verdict": "pass" if all(checks.values()) else "fail", "checks": checks, "grid_max_offset_us": grid["max_offset_us"],
            "decoder": decoder, "in_window_packets": in_window, "ipv4_ready": ipv4,
            "runner_seconds_start_to_run_json": round((finished - started).total_seconds(), 1)}


def validate(attempt, expected_hash):
    install()
    protocol = verify_plan(attempt, expected_hash)
    secret = None
    try:
        secret = c19.helper().credentials()
    except Exception:
        pass
    results, tools = [], c19.validation_tools()
    for case in protocol["cases"]:
        sample_dir = attempt / "runs" / case["sample"]
        try:
            row = v19i.audit_case(case, sample_dir, tools)
        except Exception as error:
            row = {"sample": case["sample"], "workload": case["workload"], "envelope": case["envelope"],
                   "technical_error": type(error).__name__ + ": " + str(error)}
        host = sample_dir / "host_run.txt"
        row["retrieval"] = dict(line.split("=", 1) for line in host.read_text().splitlines() if "=" in line).get("status") \
            if host.exists() else None
        row["v20"] = v20_checks(case, sample_dir) if sample_dir.is_dir() else {"verdict": "fail", "checks": {}}
        results.append(row)
    directories = {case["marker"]: attempt / "runs" / case["sample"] for case in protocol["cases"]
                   if (attempt / "runs" / case["sample"]).is_dir()}
    scans = v19i.scan_evidence(directories, [case["marker"] for case in protocol["cases"]], secret)
    for case, row in zip(protocol["cases"], results):
        scan = scans.get(case["marker"], {"foreign_markers": ["<no evidence directory>"], "credential_files": [],
                                          "password_named_files": []})
        row["leak_residue"] = {"verdict": "pass" if not scan["foreign_markers"] else "fail", "foreign_markers": scan["foreign_markers"]}
        row["leak_credential"] = {"verdict": "pass" if secret and not scan["credential_files"] and not scan["password_named_files"]
                                  else ("unchecked" if not secret else "fail"),
                                  "files_with_credential": len(scan["credential_files"])}
    summary = {"status": "offline_audited", "protocol_sha256": expected_hash, "validator_sha256": c19.digest(__file__),
               "verdicts": verdicts(results), "results": results, "limitations": protocol["limitations"]}
    report = attempt / ("integrity-report-" + c19.stamp() + ".json")
    c19.save(report, summary)
    print(json.dumps({"report": str(report), "verdicts": summary["verdicts"]}, indent=2))
    return summary


def verdicts(results):
    regular = [row for row in results if not row.get("envelope")]
    envelope = [row for row in results if row.get("envelope")]
    good = lambda rows, key, allowed=("pass",): bool(rows) and all(row.get(key, {}).get("verdict") in allowed for row in rows)
    flood = [row for row in envelope if row.get("workload") == "udp"]
    flood_ok = bool(flood) and all(row.get("retrieval") == "completed" and row.get("v20", {}).get("checks", {}).get("run_json_present")
                                   and (row.get("packets", {}).get("verdict") == "pass"
                                        or (row.get("quality") == "rejected" and row.get("quality_reasons")))
                                   for row in flood)
    return {"event_drops": good(regular, "events"),
            "event_envelope_no_silent_loss": good([r for r in envelope if r.get("workload") == "syscall"], "events",
                                                  ("pass", "loss_reported_and_rejected")),
            "packet_drops": good(regular, "packets"),
            "flood_envelope_completed_without_silent_loss": flood_ok,
            "leak_background_traffic": good(results, "leak_ambient"),
            "leak_cross_run_residue": good(results, "leak_residue"),
            "leak_credential": good(results, "leak_credential"),
            "window_attribution_unique_every_case": all(row.get("window_attribution") == "unique" for row in results),
            "v20_fixes": good(results, "v20"),
            "all_cases_retrieved": all("technical_error" not in row and row.get("retrieval") == "completed" for row in results)}


def self_test():
    install()
    cases = v19i.build_cases("0123abcd")
    c19.require(len(cases) == 15 and sum(case["envelope"] for case in cases) == 2
                and cases[-1]["sample"] == "int15-udp-envelope-r1.zip" and cases[-1]["expected"]["udp"] == 250000,
                "Plan shape differs")
    meta = {"sample_started_at_utc": "2026-10-24T12:00:00.123456+00:00", "window_seconds": 0.5}
    start = datetime.fromisoformat(meta["sample_started_at_utc"])
    rows = [{"window_start_utc": (start + timedelta(seconds=0.5 * k)).isoformat(),
             "window_end_utc": (start + timedelta(seconds=0.5 * (k + 1), microseconds=1)).isoformat()} for k in range(40)]
    c19.require(grid_check(meta, rows)["ok"], "Grid within 1 us rejected")
    rows[7]["window_end_utc"] = (start + timedelta(seconds=4.0, microseconds=812)).isoformat()  # a .19-style late wake-up
    c19.require(not grid_check(meta, rows)["ok"], "Late .19-style boundary accepted")
    flood_pass = {"envelope": True, "workload": "udp", "retrieval": "completed", "quality": "accepted",
                  "packets": {"verdict": "pass"}, "v20": {"verdict": "pass", "checks": {"run_json_present": True}}}
    c19.require(verdicts([flood_pass])["flood_envelope_completed_without_silent_loss"], "Clean flood not accepted")
    rejected = dict(flood_pass, packets={"verdict": "fail"}, quality="rejected", quality_reasons=["packet_capture_kernel_drops:9"])
    c19.require(verdicts([rejected])["flood_envelope_completed_without_silent_loss"], "Reported flood loss not accepted")
    silent = dict(flood_pass, packets={"verdict": "fail"}, quality="accepted", quality_reasons=[])
    c19.require(not verdicts([silent])["flood_envelope_completed_without_silent_loss"], "Silent flood loss accepted")
    missing = dict(flood_pass, retrieval="runner_failed", v20={"verdict": "fail", "checks": {"run_json_present": False}})
    c19.require(not verdicts([missing])["flood_envelope_completed_without_silent_loss"], "runner_failed flood accepted")
    print("PASS plan (15 cases, 2 envelopes), grid check (1 us ok, .19-style 812 us rejected), flood envelope verdicts")
    # Leak check through the quiet-v3.5 classifier on a saved .19 integrity UDP case (its own traffic is relabelled).
    saved = ROOT / "integrity-v19/20261024T115441494604Z"
    case = next(c for c in c19.load(saved / "protocol.json")["cases"] if c["sample"] == "int02-udp-r1.zip")
    run_dir = next((saved / "runs" / case["sample"] / "output").glob("run_*/run.json")).parent
    parsed = v19i.vq.packets((run_dir / "packet_capture.pcap").read_bytes())
    labels, sequences, _ = v19i.own_traffic(parsed, case)
    leak = v19i.leak_ambient(parsed, v19i.vq.windows((run_dir / "telemetry.csv").read_text()), c19.load(run_dir / "run.json"), labels)
    c19.require(v19i.vq.classify is quiet.classify and leak["verdict"] == "pass" and leak["categories"].get("own_udp") == 50000,
                "Quiet classifier leak check differs: %r" % leak["categories"])
    print("PASS leak check runs through quiet-v3.5 classify:", leak["categories"])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--freeze-only", action="store_true")
    group.add_argument("--execute", action="store_true")
    group.add_argument("--validate", action="store_true")
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    elif arguments.freeze_only:
        freeze()
    elif arguments.execute:
        execute(arguments.attempt.resolve(), arguments.protocol_sha256, arguments.approval)
    else:
        validate(arguments.attempt.resolve(), arguments.protocol_sha256)


if __name__ == "__main__":
    main()
