"""Sensor-visibility test, step 2: the 5 Tsunami bots with our collector inside the guest (as in A of step 1) but
the sample itself in a neutral folder.

Step 1 (collect_visibility.py, attempt runs/20261115T194338586321Z) showed that the five Tsunami bots quit without
traffic when our collector runs in the guest and connect within a second when nothing of ours does. B removed two
things at once: our processes, and the telling folder the sample runs from (/tmp/malware-lab/extracted/...). This
step changes only the second: the production batch's work folder becomes /tmp/<random hex> (batch option
--guest-work-dir), so the sample's own file path and working folder carry no telling name. Everything visible in the
process list stays as in A: python3 running /home/csci/Downloads/malware_runner.py, sudo, bpftrace, tcpdump writing
/tmp/.malware-pcap-<id>.pcap.

Reading: they connect now -> they reacted to their own path. They still quit -> they react to what they see running
(our programs or their command lines). Same lab, Sink check, 60-s settings and .22 collector as step 1; cases: the
null, the positive control and the five Tsunami. Phases: preflight -> sink-check -> stage -> dry-run -> collect,
then --validate and --analyze. Step 1's driver is imported unchanged.

    python3 collect_visibility_v2.py --self-test | --freeze-only
    python3 collect_visibility_v2.py --phase PHASE --attempt DIR --protocol-sha256 SHA --approval TEXT
"""
import argparse
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import collect_visibility as v1             # noqa: E402  step 1, unchanged (sets the 60-s settings and .22 pins)

cp, builder = v1.cp, v1.builder
FORMAT = "sensor-visibility-neutral-workdir-v1"
cp.FORMAT = FORMAT
require, digest, save, load, stamp = v1.require, v1.digest, v1.save, v1.load, v1.stamp
STEP1 = HERE / "runs/20261115T194338586321Z"
STEP1_PROTOCOL = "e24cabb63d53ea38895178ab860e7e8af1ac4600d238d528a44847c3d447420d"
TSUNAMI = [m for m in builder.MALWARE if m[2] == "Tsunami"]

_batch_command = cp.v21.batch_command


def batch_command(module, attempt, protocol, snapshot, output, sample_list, dry_run=False):
    """The production batch command with the neutral work folder of this step."""
    command = _batch_command(module, attempt, protocol, snapshot, output, sample_list, dry_run=dry_run)
    work = protocol.get("guest_work_dir")
    require(work and work.startswith("/tmp/") and "malware" not in work, "neutral guest work folder missing")
    return command[:2] + ["--guest-work-dir", work] + command[2:]


cp.v21.batch_command = batch_command          # used by the pilot's dry-run and collect phases


def freeze():
    require(digest(v1.STUDY / v1.V22_FILE) == v1.V22_SHA, "collector-v22 runner missing/changed")
    run_id = stamp()
    attempt = HERE / "runs" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/d-" + run_id
    work = "/tmp/" + secrets.token_hex(4)
    saved, builder.MALWARE = builder.MALWARE, TSUNAMI
    try:
        manifest, order = builder.build(attempt / "payload")
    finally:
        builder.MALWARE = saved
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    protocol = {
        "format": FORMAT, "schema": cp.SCHEMA, "production_hashes": cp.PINNED, "runner_v22_sha256": v1.V22_SHA,
        "baseline_snapshot": cp.BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-vis2-" + run_id, "benign_snapshot": "clean-vis2-unused-" + run_id,
        "guest_root": guest_root, "guest_work_dir": work, "settings": v1.VIS_SETTINGS,
        "settings_required": {"telemetry_schema_version": cp.SCHEMA, "malware_runner_sha256": v1.V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "members": manifest["members"], "expected_windows": 120,
        "b_seconds": v1.B_SECONDS, "start_sh_sha256": digest(HERE / "start.sh"),
        "sink_required": {"inetsim_http": "10.0.0.1:80", "dns": "10.0.0.1:53", "dnsmasq_answers": "10.0.0.1",
                          "sinkhole": "off"},
        "step1": {"attempt": str(STEP1), "protocol_sha256": STEP1_PROTOCOL},
        "payload_sha256": digest(attempt / "payload.tgz"), "builder_sha256": digest(Path(builder.__file__)),
        "driver_sha256": digest(Path(__file__)), "step1_driver_sha256": digest(Path(v1.__file__)),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "model_fitting": False, "merge_with_any_dataset": False, "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt")},
        "limitations": ["5 samples of one family; one run each.",
                        "Only the sample's own location changes; our processes and their command lines (which",
                        "contain 'malware') stay visible, so 'still quits' does not separate names from command lines.",
                        ".22 captures of 60 s; never merged with the dataset or any other collection."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "guest_work_dir": work, "new_snapshot": protocol["new_snapshot"],
                      "src_is_v22": digest(v1.STUDY / "src/malware_runner.py") == v1.V22_SHA}, indent=2))
    return attempt


def analyze(attempt, expected_hash):
    protocol = v1.verify_plan(attempt, expected_hash)
    step1 = load(STEP1 / "analysis.json")
    before = {r["sample"]: r for r in step1["rows"]}
    rows = []
    for case in protocol["cases"]:
        now = v1.a_summary(attempt, case)
        old = before.get(case["sample"], {})
        rows.append({"sample": case["sample"], "family": case.get("family", case.get("program")), "neutral_workdir": now,
                     "step1_A": old.get("A"), "step1_B": old.get("B")})
    out = {"protocol_sha256": expected_hash, "guest_work_dir": protocol["guest_work_dir"], "rows": rows}
    save(attempt / "analysis.json", out)
    print("%-12s %-10s | neutral folder: rc %-4s flows %-4s /proc reads %-5s | step 1 A flows %-4s | step 1 B flows %s" % (
        "sample", "family", "", "", "", "", ""))
    for r in rows:
        n, a, b = r["neutral_workdir"], r["step1_A"] or {}, r["step1_B"] or {}
        print("%-12s %-10s | neutral folder: rc %-4s flows %-4s /proc reads %-5s | step 1 A flows %-4s | step 1 B flows %s" % (
            r["sample"][:12], (r["family"] or "")[:10], n.get("return_code"), n.get("flows"), n.get("process_list_reads"),
            a.get("flows"), b.get("flows")))


def self_test():
    from types import SimpleNamespace
    with tempfile.TemporaryDirectory(prefix="hz-vis2-test-") as tmp:
        tmp = Path(tmp)
        saved, builder.MALWARE = builder.MALWARE, TSUNAMI
        try:
            manifest, order = builder.build(tmp / "payload")
        finally:
            builder.MALWARE = saved
        require(manifest["counts"] == {"null": 1, "benign": 1, "malware": 5}, "counts %s" % manifest["counts"])
        require({c.get("family") for c in order if c["label"] == "malware"} == {"Tsunami"}, "Tsunami only")
        fake = SimpleNamespace(VM="Ubuntu-Clean-24.04", GUEST_USER="csci")
        cmd = cp.v21.batch_command(fake, tmp, {"guest_root": "/g", "guest_work_dir": "/tmp/0a1b2c3d"}, "s", tmp / "o",
                                   tmp / "c.txt", dry_run=True)
        require(cmd[2:4] == ["--guest-work-dir", "/tmp/0a1b2c3d"] and cmd[-1] == "--dry-run"
                and cmd[cmd.index("--timeout") + 1] == "60", "batch command %s" % cmd)
        try:
            cp.v21.batch_command(fake, tmp, {"guest_root": "/g", "guest_work_dir": "/tmp/malware-lab"}, "s", tmp, tmp)
            raise AssertionError("telling work folder accepted")
        except ValueError:
            pass
        require(cp.FORMAT == FORMAT and v1.load(STEP1 / "analysis.json")["protocol_sha256"] == STEP1_PROTOCOL, "step 1 link")
    print("PASS collect_visibility_v2 self-test (5 Tsunami + null + control, neutral --guest-work-dir in the batch "
          "command, telling folder refused, 60-s settings, step 1 linked)")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--phase", choices=["preflight", "sink-check", "stage", "dry-run", "collect"])
    p.add_argument("--validate", action="store_true")
    p.add_argument("--analyze", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.analyze:
        analyze(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.validate:
        v1.verify_plan(Path(a.attempt).resolve(), a.protocol_sha256)
        cp.validate(Path(a.attempt).resolve(), a.protocol_sha256)
    elif a.phase == "sink-check":
        v1.sink_check(Path(a.attempt).resolve(), a.protocol_sha256, a.approval)
    elif a.phase:
        attempt = Path(a.attempt).resolve()
        v1.verify_plan(attempt, a.protocol_sha256)
        if a.phase == "collect":
            require(load(attempt / "phases/sink-check/result.json")["status"] == "passed", "sink-check not accepted")
        cp.perform_phase(attempt, a.phase, a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only, --phase, --validate or --analyze")


if __name__ == "__main__":
    main()
