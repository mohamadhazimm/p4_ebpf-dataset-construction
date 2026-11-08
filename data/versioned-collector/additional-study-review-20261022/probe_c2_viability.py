"""Host-evasive C2/beaconing VIABILITY PROBE (not a classifier cohort).

Runs the quarantined C2/beaconing samples (Sliver/CobaltStrike/Meterpreter/Winnti/Merlin) through the SAME installed
`.21` collector, in the isolated quiet guest against the INetSim Sink, and MEASURES per sample: host activity
(post_target_lineage_raw_syscalls) vs network flow (in-window net packets + PCAP captured) vs target-exec status.
The question it answers is behavioral, not classification: do these implants run HOST-QUIET and NETWORK-PRESENT
(the signature where P4 could add value), or do they exit silent on both channels (useless), or loud on host (host
already catches)? Per-mode null controls give the host-quiet floor.

Reuses collect_v21's tested VM safety primitives (isolation/competitor checks, snapshot/restore, staging, production
batch) and build_v21_payload's assembly; adds only a C2-only payload (18 samples + 9 nulls, zero benign) and a RAW
saved-only measurement (NO acceptance gate, NO traffic gate, NO 40-window pin -- measurements are kept even from
crashed/silent samples). Malware stays quarantined until the batch stages it into the isolated child; nothing is run
on the host. Every VM phase needs explicit per-phase approval (preflight -> stage -> dry-run -> collect), same gates
as collect_v21. This is a viability probe; it does not build or score any model and merges with no dataset.
"""

import argparse
import collections
import csv
import fcntl
import hashlib
import json
import signal
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21          # noqa: E402  tested VM-safety primitives + command builders
import build_v21_payload as builder  # noqa: E402  payload assembly (AES-zip reuse / raw-ELF wrap / nulls / interleave)
import collect_v19 as frozen       # noqa: E402  generic helpers (helper/run_logged/restore/snapshot_uuid)

STUDY = frozen.STUDY
SCHEMA, BASELINE, BASELINE_UUID, ORIGINAL_UUID = v21.SCHEMA, v21.BASELINE, v21.BASELINE_UUID, v21.ORIGINAL_UUID
SETTINGS, PINNED = v21.SETTINGS, v21.PINNED
require, digest, save, load, stamp = frozen.require, frozen.digest, frozen.save, frozen.load, frozen.stamp

C2_INCOMING = STUDY / "data/malware/revision5-diverse/c2-incoming"
TRIAGE_C2 = STUDY / "data/malware/revision5-diverse/triage-c2"
MODES = ["native_amd64_dynamic", "native_amd64_static", "native_i386_static"]

# member_sha256 -> family (from the MalwareBazaar get_siginfo census + Triage; all Triage = Sliver). 18 samples.
FAMILY = {
    "0188b0eba4b01c4fb838df9d1d76c76d7f1dc22897e25161975b606c134c1027": "Sliver",
    "fc4803bb4c3b92b0a15e94d83034256b3deaa5e00b85fcbe1882fd241dd6a679": "Sliver",
    "4835ecb171fc4a20ce1d90a94edf959cbbf88afcfac7a82b7c894ca3d70b8c45": "Sliver",
    "f9562324cb3c4ca0abced209c10fa733846367ecbfcd7db5ee7c54b0bfba41b3": "Sliver",
    "2d996c6d8e922b1587cdd510bf8e9d8d4a23af31d0c11a0cd723dc93ac22ed45": "Sliver",
    "4852ca68af9e9f770466656f563d4805ac591f39bf71004e3e7911fdf922f6a4": "Sliver",
    "6227013fa448c2115f1cbbe43b690b9090ff15c670c4b4a6ef70545a66d21e8d": "Sliver",
    "179f63c5547dd283d85574e16b2d9e0343753fe700ccffdf5fd6e54138c024de": "Sliver",
    "54b667fbf881692bc20caf560d92f7477e83a1a16dda6d2309b1d5bcc402bcab": "CobaltStrike",
    "6d450659d857f16d7df7572f8e6cd3f066eac0f2b2b7f90ef4e077097ccba65f": "CobaltStrike",
    "30222fa4feaffc3708c73018ddb7aed0c5c5b3b5c8ec4ccb5463045ea9ff8d99": "CobaltStrike",
    "1eb91af4713f2151d4ade415d45fba925853b6d8a0eac90a75c69ee2b24088d2": "CobaltStrike",
    "42405d1848e283c80a03b7e6e59044e9bcddcdac2c4c0302c8be0edb67a4084e": "Meterpreter",
    "7c2e806cf61299e07ecff6b2d8dbdbc07b8d7e3b00518d1ebb869db3b3668382": "Meterpreter",
    "846afc3a59b00718b3c0c406d3f443e7252794569f31c98d7bb5e6928067d4a5": "Meterpreter",
    "9410c3cc736efec4335145fec5f69e17accb5931c384675744dc84d66410397c": "Meterpreter",
    "0fca9dae54a7a55f0805a864e9d2911d727a6e274f4ddc9b5673078130e0f9e1": "Winnti",
    "6d58d77705bc436461376bfaf7399405e2e3e46570e12409fa84f029b03ece0f": "Merlin",
}


def inspect_elf(data, strict_linkage=True):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    elf_class, enc = data[4], data[5]
    endian = "<" if enc == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 18)[0]
    if elf_class == 2:
        phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
    else:
        phoff = struct.unpack_from(endian + "I", data, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
    pts = [struct.unpack_from(endian + "I", data, phoff + i * phentsize)[0] for i in range(phnum)]
    if strict_linkage and 2 in pts and 3 not in pts:
        return "unsupported:static-pie"
    dynamic = 2 in pts or 3 in pts
    if machine == 62 and elf_class == 2:
        return "native_amd64_dynamic" if dynamic else "native_amd64_static"
    if machine == 3 and elf_class == 1 and not dynamic:
        return "native_i386_static"
    return f"unsupported:machine{machine}"


def extract_member(path):
    done = subprocess.run(["7z", "x", "-so", "-pinfected", str(path)], capture_output=True, timeout=180)
    require(done.returncode == 0, "7z extract failed: " + path.name)
    return done.stdout


def generate_selection():
    """Scan quarantine, verify member hash + strict native mode, build the C2 selection + null-only binding."""
    cases = []
    for z in sorted(C2_INCOMING.glob("*.zip")):
        member = extract_member(z)
        sha = hashlib.sha256(member).hexdigest()
        require(sha == z.stem, "MB member hash != archive name: " + z.name)
        mode = inspect_elf(member)
        require(mode.startswith("native"), "unsupported mode %s %s" % (mode, sha))
        require(sha in FAMILY, "unmapped family for " + sha)
        cases.append({"member_sha256": sha, "source_path": str(z.relative_to(STUDY)), "transport_ready": True,
                      "mode": mode, "family": FAMILY[sha], "split": "probe"})
    for f in sorted(TRIAGE_C2.iterdir()):
        if not f.is_file() or f.suffix == ".jsonl":
            continue
        data = f.read_bytes()
        if data[:4] != b"\x7fELF":
            continue
        sha = hashlib.sha256(data).hexdigest()
        mode = inspect_elf(data)
        require(mode.startswith("native"), "unsupported triage mode %s %s" % (mode, sha))
        require(sha in FAMILY, "unmapped family for triage " + sha)
        cases.append({"member_sha256": sha, "source_path": str(f.relative_to(STUDY)), "transport_ready": False,
                      "mode": mode, "family": FAMILY[sha], "split": "probe"})
    require(len(cases) == len(FAMILY), "expected %d C2 cases, got %d" % (len(FAMILY), len(cases)))
    require(len({c["member_sha256"] for c in cases}) == len(cases), "duplicate member hash")
    nulls = [{"mode": m, "spot": s} for m in MODES for s in ("start", "middle", "end")]
    return {"cases": cases}, {"cases": [], "nulls": nulls}


def freeze():
    v21.verify_production()
    run_id = stamp()
    attempt = ROOT / "c2-viability" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/c2-probe-" + run_id
    c2_sel, null_bind = generate_selection()
    save(attempt / "c2_selection.json", c2_sel)
    save(attempt / "null_binding.json", null_bind)
    workdir = attempt / "_wrap"
    workdir.mkdir()
    manifest, order = builder.build(attempt / "payload", c2_sel, null_bind, guest_root, workdir)
    subprocess.run(["rm", "-rf", str(workdir)], check=False)
    payload_bytes = v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    by_family = dict(collections.Counter((c["family"], c["mode"]) for c in order if c["label"] == "malware"))
    protocol = {
        "format": "c2-viability-probe-v1", "schema": SCHEMA, "production_hashes": PINNED,
        "purpose": "behavioral viability probe: measure host-activity vs network-flow per C2 sample against the "
                   "isolated Sink; NOT a classifier cohort, NO acceptance/traffic gate, NO model, NO merge",
        "baseline_snapshot": BASELINE, "baseline_uuid": BASELINE_UUID, "original_uuid": ORIGINAL_UUID,
        "new_snapshot": "clean-c2probe-" + run_id, "guest_root": guest_root, "settings": SETTINGS,
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "c2_by_family_mode": {f"{k}": n for k, n in sorted(by_family.items())},
        "c2_selection_sha256": digest(attempt / "c2_selection.json"),
        "null_binding_sha256": digest(attempt / "null_binding.json"),
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(builder.__file__)), "driver_sha256": digest(__file__),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt")},
        "limitations": [
            "C2 implants need a live controller; against the isolated INetSim Sink they may beacon-and-retry (ideal), "
            "exit silent on both channels (useless), or mis-resolve their hardcoded C2. Behaviour is per-sample.",
            "20s observation captures the initial beacon/handshake, not multi-interval cadence; a follow-up could "
            "extend the window if initial beacons look promising.",
            "Family labels are acquisition tags (some Triage Sliver are multi-tagged); Winnti/Merlin are singletons.",
            "This measures viability only; it is not a classifier cohort, not an evaluation, and merges no dataset."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "c2_by_family_mode": protocol["c2_by_family_mode"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "new_snapshot": protocol["new_snapshot"]}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    require(expected_hash and digest(attempt / "protocol.json") == expected_hash, "Explicit frozen protocol hash required")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == "c2-viability-probe-v1" and protocol["production_hashes"] == PINNED,
            "Protocol version or pins differ")
    require(protocol["settings"] == SETTINGS and protocol["schema"] == SCHEMA
            and protocol["baseline_snapshot"] == BASELINE, "Frozen probe contract differs")
    v21.verify_production()
    for name, expected in protocol["files"].items():
        require(digest(attempt / name) == expected, "Frozen payload/order changed: " + name)
    return protocol


def perform_phase(attempt, phase, expected_hash, approval):
    require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    protocol = verify_plan(attempt, expected_hash)
    module = frozen.helper()
    predecessors = {"stage": "preflight", "dry-run": "stage", "collect": "dry-run"}
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if phase in predecessors:
            prior = load(attempt / "phases" / predecessors[phase] / "result.json")
            require(prior["status"] == "passed" and prior["protocol_sha256"] == expected_hash, "Previous phase not accepted")
        destination = attempt / "phases" / phase
        destination.mkdir(parents=True, exist_ok=False)
        save(destination / "authorization.json", {"approval": approval, "phase": phase, "protocol_sha256": expected_hash,
             "authorized_utc": datetime.now(timezone.utc).isoformat(), "one_attempt_only": True})
        result = {"phase": phase, "protocol_sha256": expected_hash, "status": "failed_preserved"}

        def interrupted(_s, _f):
            raise KeyboardInterrupt("Stop owned process group, restore original snapshot, preserve failure")
        previous = signal.signal(signal.SIGTERM, interrupted)
        touched = False
        try:
            before = v21.preflight(module, protocol)
            save(destination / "initial_vm_state.json", before)
            if phase == "preflight":
                result.update(before)
            elif phase == "stage":
                snapshot = protocol["new_snapshot"]
                require(not v21.snapshot_present(module, snapshot), "Child already exists; no restage")
                touched = True
                save(destination / "command.json", v21.stage_command(attempt, module, snapshot))
                frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
                result["snapshot_uuid"] = frozen.snapshot_uuid(module, snapshot)
            elif phase == "dry-run":
                staged = load(attempt / "phases/stage/result.json")
                require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child differs")
                require(not (attempt / "dry-run").exists(), "Existing output; no retry/resume")
                touched = True
                command = v21.batch_command(module, attempt, protocol, protocol["new_snapshot"], attempt / "dry-run",
                                            attempt / "cases.txt", dry_run=True)
                save(destination / "command.json", command)
                frozen.run_logged(command, destination / "command.log", 1200)
                result["validated_transports"] = v21.validate_dry_run(destination / "command.log", protocol)
            elif phase == "collect":
                staged = load(attempt / "phases/stage/result.json")
                require(frozen.snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child differs")
                require(not (attempt / "runs").exists(), "Existing output; no retry/resume")
                touched = True
                command = v21.batch_command(module, attempt, protocol, protocol["new_snapshot"], attempt / "runs", attempt / "cases.txt")
                save(destination / "command.json", command)
                frozen.run_logged(command, destination / "command.log", 6 * 3600)
                result["reached_batch_complete"] = "Batch complete" in (destination / "command.log").read_text()
            else:
                require(False, "unknown phase: " + phase)
            verify_plan(attempt, expected_hash)
            result["status"] = "passed"
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            try:
                if touched:
                    frozen.restore(module, destination)
            except BaseException as error:
                result.update(status="cleanup_failed_requires_user", cleanup_error=type(error).__name__ + ": " + str(error))
                raise
            finally:
                save(destination / "result.json", result)
                signal.signal(signal.SIGTERM, previous)
        print(json.dumps(result, indent=2))


def sum_inwindow_net_packets(sample_dir):
    """Sum per-window network packet counts from telemetry.csv (in-window traffic), tolerant of column naming."""
    tele = next(sample_dir.glob("output/run_*/telemetry.csv"), None)
    if tele is None:
        return None
    rows = list(csv.DictReader(tele.open()))
    if not rows:
        return 0
    cols = [c for c in rows[0] if "net" in c.lower() and "packet" in c.lower()]
    if not cols:
        return None
    total = 0
    for r in rows:
        for c in cols:
            try:
                total += int(float(r[c]))
            except (ValueError, TypeError):
                pass
    return total


def measure(attempt):
    """Saved-only: per-case host activity vs network flow vs exec status; classify viability tiers. No gate, no model."""
    protocol = load(attempt / "protocol.json")
    rows = []
    for case in protocol["cases"]:
        d = attempt / "runs" / case["sample"]
        row = {"sample": case["sample"], "label": case["label"], "family": case.get("family", ""),
               "mode": case.get("mode", ""), "spot": case.get("spot", "")}
        rj = next(d.glob("output/run_*/run.json"), None)
        if rj is None:
            row["status"] = "no_run_json"
            rows.append(row)
            continue
        m = json.loads(rj.read_text())
        te = m.get("target_exec", {}) or {}
        pkt = m.get("packet_capture_statistics", {}) or {}
        row.update(status="retrieved",
                   exec_observed=te.get("status") == "observed",
                   return_code=m.get("return_code"),
                   host_syscalls=te.get("post_target_lineage_raw_syscalls"),
                   pcap_captured=pkt.get("packets_captured", pkt.get("captured")),
                   inwindow_net=sum_inwindow_net_packets(d),
                   quality=m.get("collection_quality_status"))
        rows.append(row)
    # host-quiet floor from this probe's own nulls, per mode (+ margin).
    floor = {}
    for m in MODES:
        hv = [r["host_syscalls"] for r in rows if r["label"] == "null" and r["mode"] == m
              and isinstance(r.get("host_syscalls"), int)]
        floor[m] = (max(hv) if hv else 20) + 25
    tiers = collections.Counter()
    for r in rows:
        if r["label"] != "malware":
            r["tier"] = "null" if r["label"] == "null" else "benign"
            continue
        if r.get("status") != "retrieved" or not r.get("exec_observed") or not isinstance(r.get("host_syscalls"), int):
            r["tier"] = "no_exec_or_data"
        else:
            quiet = r["host_syscalls"] <= floor.get(r["mode"], 45)
            net = (r.get("inwindow_net") or 0) > 0
            r["tier"] = ("host_evasive_network" if quiet and net else
                         "silent_both" if quiet and not net else
                         "host_loud_network" if (not quiet) and net else "host_loud")
        tiers[r["tier"]] += 1
    out = {"attempt": str(attempt), "host_quiet_floor_by_mode": floor,
           "malware_tier_counts": dict(tiers),
           "verdict_note": "host_evasive_network = the P4-can-add class (host-quiet + network-present). "
                           "silent_both = useless vs the Sink. host_loud* = host already catches.",
           "cases": rows}
    dest = attempt / "measurement"
    dest.mkdir(exist_ok=True)
    save(dest / ("viability-" + stamp() + ".json"), out)
    print(json.dumps({"malware_tier_counts": dict(tiers), "host_quiet_floor_by_mode": floor}, indent=2))
    print("\n%-7s %-13s %-22s %-10s %-9s %-9s %s" % ("label", "family", "mode", "host_sysc", "inwin_net", "rc", "tier"))
    for r in rows:
        print("%-7s %-13s %-22s %-10s %-9s %-9s %s" % (
            r["label"], str(r.get("family"))[:13], r.get("mode", "").replace("native_", ""),
            r.get("host_syscalls"), r.get("inwindow_net"), r.get("return_code"), r.get("tier")))
    return out


def self_test():
    c2_sel, null_bind = generate_selection()
    assert len(c2_sel["cases"]) == 18, len(c2_sel["cases"])
    bymode = collections.Counter(c["mode"] for c in c2_sel["cases"])
    assert bymode["native_amd64_static"] == 9 and bymode["native_amd64_dynamic"] == 4 and bymode["native_i386_static"] == 5, bymode
    assert all(c["mode"].startswith("native") for c in c2_sel["cases"])
    assert len(null_bind["nulls"]) == 9 and null_bind["cases"] == []
    # payload assembly via the real builder into a temp dir
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        manifest, order = builder.build(td / "payload", c2_sel, null_bind, "/home/csci/Downloads/c2-probe-test", td / "_w")
        assert manifest["counts"].get("malware") == 18 and manifest["counts"].get("null") == 9, manifest["counts"]
        assert manifest["counts"].get("benign", 0) == 0
        assert len(order) == 27
        for c in order:
            assert (td / "payload/samples" / c["sample"]).is_file()
        # the 10/18 that are raw-ELF (triage=4) + MB are all present; verify one MB member hash round-trips
        mbzip = td / "payload/samples" / (c2_sel["cases"][0]["member_sha256"] + ".zip")
        assert hashlib.sha256(extract_member(mbzip)).hexdigest() == c2_sel["cases"][0]["member_sha256"]
    # measure() on a synthetic runs tree
    with tempfile.TemporaryDirectory() as td:
        att = Path(td)
        save(att / "protocol.json", {"format": "c2-viability-probe-v1", "cases": [
            {"sample": "A.zip", "label": "null", "mode": "native_amd64_static", "spot": "start"},
            {"sample": "B.zip", "label": "malware", "mode": "native_amd64_static", "family": "Sliver"},
            {"sample": "C.zip", "label": "malware", "mode": "native_amd64_static", "family": "CobaltStrike"},
            {"sample": "D.zip", "label": "malware", "mode": "native_amd64_static", "family": "Meterpreter"}]})

        def synth(name, host, net, exec_ok=True):
            rd = att / "runs" / name / "output" / "run_0"
            rd.mkdir(parents=True)
            (rd / "run.json").write_text(json.dumps({
                "target_exec": {"status": "observed" if exec_ok else "not_observed",
                                "post_target_lineage_raw_syscalls": host},
                "return_code": 0, "packet_capture_statistics": {"packets_captured": net}}))
            with (rd / "telemetry.csv").open("w", newline="") as h:
                w = csv.writer(h)
                w.writerow(["window", "net_packets_total"])
                w.writerow([0, net])
        synth("A.zip", 20, 0)                 # null floor 20 -> quiet threshold 45
        synth("B.zip", 25, 12)                # quiet + network  -> host_evasive_network
        synth("C.zip", 25, 0)                 # quiet + no net    -> silent_both
        synth("D.zip", 5000, 30)              # loud + network    -> host_loud_network
        out = measure(att)
        t = out["malware_tier_counts"]
        assert t.get("host_evasive_network") == 1 and t.get("silent_both") == 1 and t.get("host_loud_network") == 1, t
    # verify_plan rejects a tampered hash
    try:
        verify_plan(att, "deadbeef")
        raise AssertionError("verify_plan accepted a bad hash")
    except Exception as e:
        assert "protocol hash" in str(e) or "protocol.json" in str(e), e
    print("self-test OK: selection 9/4/5, payload 18+9, measure tiers, verify_plan guard")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--phase", choices=["preflight", "stage", "dry-run", "collect"])
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    p.add_argument("--measure", action="store_true")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.measure:
        measure(Path(a.attempt))
    elif a.phase:
        perform_phase(Path(a.attempt), a.phase, a.protocol_sha256, a.approval)
    else:
        p.error("one of --self-test / --freeze-only / --phase / --measure required")


if __name__ == "__main__":
    main()
