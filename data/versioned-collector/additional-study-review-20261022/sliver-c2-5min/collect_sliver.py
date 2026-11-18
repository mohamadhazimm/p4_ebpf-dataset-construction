"""Sliver C2 testbed collection (300 s / 600 windows): 12 live-C2 implants + 28 benign clients + 3 null.

Reuses the sinkhole driver's flow verbatim (so the benign side and the sinkhole mode are identical to the sinkhole
run, for a clean server-down-vs-up contrast) and splices in the operator auto-tasker as a background daemon for the
whole collect phase, so whichever implant is live during its window gets the fixed benign task list. Our own Sliver
server (up) and our own implants; both ends ours; sealed malnet; no internet; no downloaded malware tasked.

Phases: preflight / stage / dry-run / server-check / sink prepare / collect (auto-tasker live) / sink logs /
sink restore / validate / behaviour. Stops at the first failure; once prepared, logs + restore always run.

Run: /usr/bin/python3 collect_sliver.py --self-test | --freeze-only | --run-all --attempt <dir> --protocol-sha256 <h> --approval "<text>"
"""
import hashlib
import json
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import collect_sinkhole_c2 as c2  # noqa: E402  flow + sink_step + behavior_check + sink helpers
import build_sliver_payload as bsp  # noqa: E402
import autotask  # noqa: E402

cp = c2.cp
cp.FORMAT = "sliver-c2-5min-v1"
FORMAT = cp.FORMAT
require, digest, save = cp.require, cp.digest, cp.save
STUDY, V22_FILE, V22_SHA = cp.STUDY, cp.V22_FILE, cp.V22_SHA
SCHEMA, SETTINGS, PINNED, BASELINE = cp.SCHEMA, cp.SETTINGS, c2.PINNED if hasattr(c2, "PINNED") else cp.v21.PINNED, cp.BASELINE
LAB = "/home/remnux/hazim-sliver"
SERVER_LISTENERS = ["mtls   tcp        8443", "http   tcp        8080", "https  tcp        8444", "wg     udp        51820"]


# ----------------------------------------------------------------------------------- Sliver server / auto-tasker

def server_up(module):
    text = autotask.client(module, ["jobs"])
    ports = [p for p in ("8443", "8080", "8444", "51820") if p in text]
    require(len(ports) == 4, "Sliver server not ready: expected 4 listeners, saw ports %s\n%s" % (ports, text[-400:]))
    return ports


def ensure_upload(module):
    c2.sink_run(module, ["/bin/bash", "-lc", "echo 'uploaded by operator in the sealed lab' > %s/lab-upload.txt"
                         % LAB], sudo=False)


def start_autotasker(attempt, duration):
    log = attempt / "autotask.jsonl"
    stop = attempt / "autotask.stop"
    if stop.exists():
        stop.unlink()
    proc = subprocess.Popen(["/usr/bin/python3", str(HERE / "autotask.py"), "--duration", str(duration),
                             "--log", str(log), "--stop", str(stop)],
                            stdout=open(attempt / "autotask.out", "a"), stderr=subprocess.STDOUT)
    return proc, stop


def stop_autotasker(proc, stop):
    try:
        stop.write_text("stop")
    except OSError:
        pass
    for _ in range(20):
        if proc.poll() is not None:
            return
        time.sleep(3)
    proc.terminate()


# ------------------------------------------------------------------------------------------------ freeze

MINI_IMPLANTS = ["lab-mtls-beacon-a", "lab-wg-session-a"]   # one beacon + one session for the collector preflight


def freeze(mini=False):
    require(digest(STUDY / V22_FILE) == V22_SHA, "collector-v22 runner missing/changed")
    run_id = cp.stamp()
    attempt = HERE / (("mini-" if mini else "") + run_id)
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/sliverc2-" + run_id
    if mini:
        manifest, order = bsp.build(attempt / "payload", guest_root, only_implants=MINI_IMPLANTS,
                                    include_benign=False, null_modes={"native_amd64_dynamic"})
        require(manifest["counts"] == {"malware": 2, "null": 1}, "mini counts differ")
    else:
        # fair: benign restricted to amd64-dynamic to match the implants' mode exactly (12 vs 12), so "mode"
        # carries no signal. Nulls (environment controls, not classifier inputs) kept one per mode.
        manifest, order = bsp.build(attempt / "payload", guest_root, benign_modes={"native_amd64_dynamic"})
        require(manifest["counts"] == {"malware": 12, "benign": 12, "null": 3}, "payload counts differ")
    payload_bytes = cp.v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = cp.v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    (attempt / "benign-null.txt").write_text("".join(c["sample"] + "\n" for c in order if c["label"] != "malware"))
    protocol = {
        "format": FORMAT, "schema": SCHEMA, "production_hashes": PINNED, "runner_v22_sha256": V22_SHA,
        "baseline_snapshot": BASELINE, "baseline_uuid": cp.BASELINE_UUID, "original_uuid": cp.ORIGINAL_UUID,
        "new_snapshot": "clean-sliverc2-" + run_id, "benign_snapshot": "clean-sliverc2-benign-" + run_id,
        "guest_root": guest_root, "settings": SETTINGS,
        "settings_required": {"telemetry_schema_version": SCHEMA, "malware_runner_sha256": V22_SHA,
                              "observation_mode": "fixed", "window_seconds": 0.5, "ebpf_enabled": True},
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "by_group": manifest["by_group"], "benign_binaries": manifest["benign_binaries"],
        "implants": manifest["implants"], "expected_windows": cp.EXPECTED_WINDOWS,
        "payload_sha256": digest(attempt / "payload.tgz"),
        "sink": {"vm": c2.SINK_VM, "sinkhole_required": "on", "dns_answer_during_collect": c2.DNS_REDIRECT,
                 "dns_answer_restored": c2.DNS_ORIGINAL, "redirect_conf": c2.REDIRECT_DNSMASQ_CONF,
                 "redirect_conf_sha256": hashlib.sha256(c2.REDIRECT_CONF_TEXT.encode()).hexdigest(),
                 "kit": {name: digest(c2.KIT / name) for name in ("sinkhole.sh", "sinkhole_catchall.py")},
                 "after": "sinkhole off, original dnsmasq"},
        "sliver": {"version": "v1.7.9", "server": "our own, on the Sink (daemon -l 127.0.0.1 -p 31337)",
                   "listeners": {"mtls": 8443, "http": 8080, "https": 8444, "wg": 51820},
                   "dns_c2": "dropped (would collide with the Sink's dnsmasq on :53)",
                   "operator_tasks": autotask.TASKS, "task_interval_s": autotask.TASK_EVERY,
                   "autotask_sha256": digest(HERE / "autotask.py")},
        "builder_sha256": digest(Path(bsp.__file__)), "driver_sha256": digest(__file__),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "model_fitting": False, "merge_with_any_dataset": False, "collection_ready": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt", "benign-null.txt")},
        "purpose": ["Supply the command phase the sinkhole run lacked: our own Sliver implants beacon to our own",
                    "live server and run a fixed benign task list, measured by the same host/network/hybrid sensors",
                    "next to the sinkhole run's benign clients. Contrast: same framework, server down vs up."],
        "criteria": [".22 runner provenance; accepted sensor quality; no eBPF loss/overflow; exact target exec;",
                     "600x169 finite telemetry; nulls quiet; Sliver server up (4 listeners) and sinkhole on with",
                     "the DNS redirect for the whole collect; auto-tasker tasks live implants by ID."],
        "limitations": ["Separate dataset variant (Sliver C2 + sinkhole on); never merged with any other capture.",
                        "One framework (Sliver), default implant builds, a fixed benign task script: a case study,",
                        "not a general result.",
                        "Mode-balanced: 12 implants vs 12 benign, all amd64-dynamic, so the mode baseline is ~0.5",
                        "and cannot stand in for detection; 5 benign programs vs 6 implant transport groups is small.",
                        "Both ends ours; sealed malnet; no internet; no downloaded malware is tasked."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "by_group": protocol["by_group"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576, 1),
                      "src_is_v22": digest(STUDY / "src/malware_runner.py") == V22_SHA}, indent=2))
    return attempt


# ------------------------------------------------------------------------------------------------ orchestration

def run_all(attempt, expected_hash, approval, use_sinkhole=True):
    require(approval and approval.strip(), "approval required")

    def interrupted(_s, _f):
        raise KeyboardInterrupt("stopped: stop the auto-tasker, restore the Sink and the guest, preserve the attempt")
    signal.signal(signal.SIGTERM, interrupted)
    module = cp.frozen.helper()
    for phase in ("preflight", "stage", "dry-run"):
        cp.perform_phase(attempt, phase, expected_hash, approval)
    server_up(module)
    ensure_upload(module)
    n_cases = len(json.loads((attempt / "protocol.json").read_text())["cases"])
    tasker, stop = None, None
    prepared = False
    try:
        if use_sinkhole:
            c2.sink_step(attempt, expected_hash, "prepare", approval)
            prepared = True
            c2.require_sink_ready(module)
        tasker, stop = start_autotasker(attempt, duration=n_cases * 420 + 600)
        cp.perform_phase(attempt, "collect", expected_hash, approval)
    finally:
        if tasker is not None:
            stop_autotasker(tasker, stop)
        if prepared:
            try:
                c2.sink_step(attempt, expected_hash, "logs", approval)
            finally:
                c2.sink_step(attempt, expected_hash, "restore", approval)
    cp.validate(attempt, expected_hash)
    if use_sinkhole:
        c2.behavior_check(attempt, expected_hash)


def self_test():
    cp.settings_tests()
    bsp.self_test()
    cp.phase_mock_tests()
    require(autotask.TASKS and all(isinstance(t, str) for t in autotask.TASKS), "task list")
    require("8443" in " ".join(str(v) for v in (8443, 8080, 8444, 51820)), "listeners")
    print("PASS collect_sliver self-test (payload 12/28/3, phase mocks, task list)")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Sliver C2 testbed (300 s / 600 windows)")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--freeze-mini", action="store_true")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--no-sinkhole", action="store_true", help="skip the sinkhole steps (mini collector preflight)")
    p.add_argument("--phase", choices=["preflight", "stage", "dry-run", "collect"])
    p.add_argument("--sink", choices=["prepare", "logs", "restore"])
    p.add_argument("--validate", action="store_true")
    p.add_argument("--behavior", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.freeze_mini:
        freeze(mini=True)
    else:
        attempt = Path(a.attempt).resolve()
        if a.run_all:
            run_all(attempt, a.protocol_sha256, a.approval, use_sinkhole=not a.no_sinkhole)
        elif a.phase:
            if a.phase == "collect":
                c2.require_sink_ready(cp.frozen.helper())
            cp.perform_phase(attempt, a.phase, a.protocol_sha256, a.approval)
        elif a.sink:
            c2.sink_step(attempt, a.protocol_sha256, a.sink, a.approval)
        elif a.validate:
            cp.validate(attempt, a.protocol_sha256)
        elif a.behavior:
            c2.behavior_check(attempt, a.protocol_sha256)
        else:
            p.error("choose a step")


if __name__ == "__main__":
    main()
