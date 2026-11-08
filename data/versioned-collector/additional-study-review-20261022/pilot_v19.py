"""Benign-only pilot of the DRAFT .19 collector on the quiet snapshot, through the real batch script.

The pinned stage/batch scripts are copied byte-identically into a shadow root whose src/malware_runner.py is the
.19 draft, so the real src/ stays .18 until this pilot passes. Cases (18): all six matched45 nulls, nine matched45
benign programs (three per native mode) and three runs of the attribution-control network task (one HTTP GET and six
UDP datagrams to the internal Sink). Every transport is copied byte-identically from an already validated payload.

Prospective acceptance, per case: retrieval completed, .19 schema/hash, quality accepted, exact target exec, exit 0,
40x169 finite features, safe archive hashes, PCAP records == tcpdump counters, zero sensor loss/gaps/unresolved ABI,
pre/post probes independently recovered from raw PCAP, zero frames from the disabled ambient sources, and P4 unique
alignment with stored/reconstructed parity (or, for a capture with no in-window frames, all-zero stored P4).
Network cases must contain their marked HTTP GET and UDP datagrams inside the feature windows. Any other in-window
frame in a non-network case is reported, never assumed ambient or sample-caused.
"""

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import io
import json
import math
import os
import shutil
import subprocess
import sys
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
V19 = ROOT / "collector-v19/malware_runner.py"
V19_SHA256 = "bef85019b580dbb3f135756aa9e9b7eb67447a0edb1cd92be7d630fed06f1ad2"
V18_SHA256 = "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49"
SCHEMA = "2026-10-24.19"
QUIET_SNAPSHOT = "clean-quiet-ambient-20261024T080813430717Z"
ENV_FILE = STUDY.parents[1] / ".env"
SCRIPTS = {"scripts/vbox_malware_batch.sh": "4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f",
           "scripts/stage_versioned_runner_snapshot.sh": "5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103"}
MATCHED = ROOT / "matched45-readiness/20261022T072823231146Z"
ATTRIBUTION = ROOT / "attribution-pilot/20261022T101347764368Z"
LEGACY = STUDY / "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/readiness/20261021T104951987641Z"
BENIGN = ["native_amd64_dynamic-coreutils-nice.zip", "native_amd64_dynamic-coreutils-nohup.zip",
          "native_amd64_dynamic-coreutils-chown.zip", "native_amd64_static-coreutils-printf.zip",
          "native_amd64_static-coreutils-sum.zip", "native_amd64_static-sqlite3-lemon.zip",
          "native_i386_static-xz-utils-xzdec.zip", "native_i386_static-sharutils-uuencode.zip",
          "native_i386_static-e2fsprogs-uuidgen.zip"]
ORDER = ["null-native_amd64_dynamic-r1.zip", "null-native_amd64_static-r1.zip", "null-native_i386_static-r1.zip",
         "net_r1.zip", BENIGN[0], BENIGN[3], BENIGN[6], BENIGN[2], BENIGN[4], "net_r2.zip", BENIGN[7], BENIGN[1],
         BENIGN[5], BENIGN[8], "net_r3.zip",
         "null-native_amd64_dynamic-r2.zip", "null-native_amd64_static-r2.zip", "null-native_i386_static-r2.zip"]
EXPECTED_MODE = {"native_amd64_dynamic": ("native", "dynamic", 62), "native_amd64_static": ("native", "static", 62),
                 "native_i386_static": ("native_compat", "static", 3)}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cases():
    manifest = json.loads((MATCHED / "manifest.json").read_text())
    by_sample = {case["sample"]: case for case in manifest["cases"]}
    result = []
    for sample in ORDER:
        if sample.startswith("net_r"):
            repeat = sample[5]
            result.append({"sample": sample, "label": "network_control", "mode": "native_amd64_static",
                           "arguments": ["net", "net_r" + repeat, repeat], "source": "attribution_control",
                           "transport_sha256": "8087ad0cb8c8d34a42fc5ebad55a11e0b8ca8dd7c1235f97dc46afd4419881b2"})
        else:
            case = by_sample[sample]
            require(case["label"] in ("benign", "null"), "Pilot may contain only benign/null cases")
            result.append({"sample": sample, "label": case["label"], "mode": case["mode"],
                           "arguments": case["collection_arguments"], "source": "matched45",
                           "case_id": case.get("case_id"), "transport_sha256": case["transport_sha256"]})
    return manifest["guest_root"], result


def build_payload(selected):
    """Benign-only payload: only selected samples/arguments/fixtures are read from the source archives."""
    wanted = {"samples/" + case["sample"]: case for case in selected if case["source"] == "matched45"}
    fixture_prefixes = tuple("fixtures/" + case["case_id"] + "/" for case in selected
                             if case["source"] == "matched45" and case["label"] == "benign")
    members, data = {}, {}
    with tarfile.open(MATCHED / "payload.tgz", "r:gz") as archive:
        for member in archive:
            if member.name in wanted or (member.name.startswith(fixture_prefixes) and (member.isfile() or member.isdir())) \
                    or any(member.name == prefix.rstrip("/") for prefix in fixture_prefixes):
                require(member.isfile() or member.isdir(), "Unsafe payload member")
                members[member.name] = member
                data[member.name] = archive.extractfile(member).read() if member.isfile() else None
    for name, case in wanted.items():
        require(hashlib.sha256(data[name]).hexdigest() == case["transport_sha256"], "Matched45 transport differs: " + name)
    with tarfile.open(ATTRIBUTION / "payload.tgz", "r:gz") as archive:
        control = archive.extractfile("samples/net_r1.zip").read()
    require(hashlib.sha256(control).hexdigest() == "8087ad0cb8c8d34a42fc5ebad55a11e0b8ca8dd7c1235f97dc46afd4419881b2",
            "Attribution control transport differs")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        def add(name, content, mode=0o644, directory=False):
            member = tarfile.TarInfo(name)
            member.mtime = 0
            if directory:
                member.type, member.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(member)
            else:
                member.size, member.mode = len(content), mode
                archive.addfile(member, io.BytesIO(content))
        for name in sorted(members):
            if name.startswith("fixtures/"):
                add(name, data[name], members[name].mode & 0o777, directory=members[name].isdir())
        for case in selected:
            content = control if case["source"] == "attribution_control" else data["samples/" + case["sample"]]
            add("samples/" + case["sample"], content, 0o600)
            add("arguments/" + case["sample"] + ".json", json.dumps(case["arguments"]).encode())
    return output.getvalue()


def setup_script(guest_root, payload):
    return """#!/usr/bin/env bash
set -euo pipefail
/usr/bin/python3 - <<'PY'
import base64,hashlib,io,tarfile
from pathlib import Path
root=Path(%r)
data=base64.b64decode(%r)
if root.exists() or hashlib.sha256(data).hexdigest()!=%r:
    raise SystemExit('existing root or changed payload')
root.mkdir(parents=True)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
    for member in archive:
        target=root/member.name
        if not target.resolve().is_relative_to(root) or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe payload member')
        if member.isdir():
            target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
            target.chmod(member.mode & 0o777)
print('18 benign/null pilot transports staged; no target executed')
PY
""" % (guest_root, base64.b64encode(payload).decode(), hashlib.sha256(payload).hexdigest())


def freeze():
    require(digest(V19) == V19_SHA256, ".19 draft changed")
    require(digest(STUDY / "src/malware_runner.py") == V18_SHA256, "Real src runner is not the expected .18")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "v19-pilot" / stamp
    for name, expected in SCRIPTS.items():
        require(digest(STUDY / name) == expected, "Pinned script changed: " + name)
        target = attempt / "shadow" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(STUDY / name, target)
        require(digest(target) == expected, "Shadow script copy differs: " + name)
    (attempt / "shadow/src").mkdir()
    shutil.copy2(V19, attempt / "shadow/src/malware_runner.py")
    guest_root, selected = cases()
    payload = build_payload(selected)
    (attempt / "payload.tgz").write_bytes(payload)
    (attempt / "setup_guest.sh").write_text(setup_script(guest_root, payload))
    subprocess.run(["bash", "-n", str(attempt / "setup_guest.sh")], check=True)
    (attempt / "pilot-cases.txt").write_text("".join(case["sample"] + "\n" for case in selected))
    snapshot = "clean-quiet-v19-pilot-" + stamp
    protocol = {"schema": SCHEMA, "runner_sha256": V19_SHA256, "baseline_snapshot": QUIET_SNAPSHOT,
                "new_snapshot": snapshot, "guest_root": guest_root, "cases": selected,
                "settings": ["--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
                             "--fixed-observation", "--common-launch-wrapper"],
                "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "pilot-cases.txt")},
                "source_hashes": {str(path): digest(path) for path in
                                  (Path(__file__), V19, ROOT / "audit_performance_v4.py", ROOT / "quiet_ambient.py",
                                   attempt / "shadow/scripts/vbox_malware_batch.sh",
                                   attempt / "shadow/scripts/stage_versioned_runner_snapshot.sh")},
                "approval": None, "malware_executions": 0, "real_src_runner_unchanged": True,
                "retries": "None; preserve every failure", "criteria": __doc__.split("Prospective acceptance, per case: ")[1]}
    save(attempt / "protocol.json", protocol)
    return attempt, protocol


def helper():
    sys.path.insert(0, str(ROOT))
    from export_original_sources import check_competitors, helper_module
    return helper_module(), check_competitors


def state_ok(module, state):
    return (state["guest"]["VMState"] == '"poweroff"' and state["guest"]["CurrentSnapshotName"] == '"' + module.ORIGINAL + '"'
            and state["sink"]["VMState"] == '"running"')


def preflight():
    module, check_competitors = helper()
    module.verify_production()  # real src/ and pinned scripts remain .18-era until promotion
    check_competitors()
    state = {"guest": module.isolated(module.VM), "sink": module.isolated("Sink")}
    require(state_ok(module, state), "Need original TLS/off and isolated Sink/running")
    snapshots = module.vbox("snapshot", module.VM, "list", "--machinereadable").stdout
    require('"%s"' % QUIET_SNAPSHOT in snapshots, "Quiet snapshot missing")
    return module, state


def execute(attempt, approval):
    module, _check = helper()
    protocol = json.loads((attempt / "protocol.json").read_text())
    protocol["approval"] = approval
    (attempt / "protocol.json").write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    shadow = attempt / "shadow/scripts"
    environment = {**os.environ, "ENV_FILE": str(ENV_FILE)}
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _module, before = preflight()
        save(attempt / "initial_vm_state.json", before)
        for name, expected in protocol["files"].items():
            require(digest(attempt / name) == expected, "Frozen pilot file changed: " + name)
        try:
            with (attempt / "staging.log").open("x") as log:
                subprocess.run(["bash", str(shadow / "stage_versioned_runner_snapshot.sh"), "--vm", module.VM,
                                "--guest-user", module.GUEST_USER, "--baseline-snapshot", QUIET_SNAPSHOT,
                                "--new-snapshot", protocol["new_snapshot"], "--schema-version", SCHEMA,
                                "--guest-setup", str(attempt / "setup_guest.sh")], cwd=STUDY, env=environment,
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=900)
            batch = ["bash", str(shadow / "vbox_malware_batch.sh"), "--vm", module.VM, "--guest-user", module.GUEST_USER,
                     "--guest-malware-dir", protocol["guest_root"] + "/samples",
                     "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", protocol["new_snapshot"],
                     "--schema-version", SCHEMA, "--guest-arguments-dir", protocol["guest_root"] + "/arguments",
                     "--sample-list", str(attempt / "pilot-cases.txt"), *protocol["settings"]]
            with (attempt / "dry-run.log").open("x") as log:
                subprocess.run(batch + ["--output-dir", str(attempt / "dry-run"), "--dry-run"], cwd=STUDY, env=environment,
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1800)
            with (attempt / "collection.log").open("x") as log:
                subprocess.run(batch + ["--output-dir", str(attempt / "runs")], cwd=STUDY, env=environment,
                               stdout=log, stderr=subprocess.STDOUT, check=True, timeout=7200)
        except BaseException as error:
            save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error)})
            raise
        finally:
            if module.vm_info(module.VM)["VMState"] != '"poweroff"':
                module.vbox("controlvm", module.VM, "poweroff")
            module.vbox("snapshot", module.VM, "restore", module.ORIGINAL)
            final = {"guest": module.isolated(module.VM), "sink": module.isolated("Sink")}
            save(attempt / "final_vm_state.json", final)
            require(state_ok(module, final), "Cleanup differs")
            module.verify_production()


def validate(attempt):
    sys.path.insert(0, str(ROOT))
    import audit_performance_v4 as probes
    import quiet_ambient
    module, _check = helper()
    data = load_module("pilot_feature_utilities", LEGACY / "prepare_model_data.py")
    protocol = json.loads((attempt / "protocol.json").read_text())
    results, nulls, failures = [], {}, []
    for case in protocol["cases"]:
        row = {"sample": case["sample"], "label": case["label"], "mode": case["mode"], "findings": []}
        try:
            sample_dir = attempt / "runs" / case["sample"]
            require("status=completed" in (sample_dir / "host_run.txt").read_text(), "Retrieval not completed")
            paths = list((sample_dir / "output").glob("*/run.json"))
            require(len(paths) == 1, "Ambiguous run metadata")
            run_dir = paths[0].parent
            metadata = json.loads(paths[0].read_text())
            require(metadata["telemetry_schema_version"] == SCHEMA and metadata["malware_runner_sha256"] == V19_SHA256,
                    "Runner provenance differs")
            require(metadata["collection_quality_status"] == "accepted" and metadata["collection_quality_reasons"] == [],
                    "Quality not accepted: " + ";".join(metadata["collection_quality_reasons"]))
            require(metadata["return_code"] == 0, "Target exit differs")
            execution = metadata["target_exec"]
            require(execution["status"] == "observed" and execution["match"] == "exact", "Target exec not exact")
            mode, linkage, machine = EXPECTED_MODE[case["mode"]]
            artifact = metadata["target_artifact"]
            require(artifact["execution_mode"] == mode and artifact["linkage"] == linkage and artifact["e_machine"] == machine,
                    "Target mode/linkage differs")
            telemetry = data.p4.load_telemetry_rows(sample_dir)
            features = [name for values in metadata["telemetry_feature_groups"].values() for name in values]
            require(len(telemetry) == 40 and len(features) == len(set(features)) == 169
                    and all(math.isfinite(float(window[name])) for window in telemetry for name in features), "Telemetry incomplete")
            row["archive_members"] = module.verify_output_archive(sample_dir)
            pcap = (run_dir / "packet_capture.pcap").read_bytes()
            statistics = metadata["packet_capture_statistics"]
            records = sum(1 for _ in probes.frames(pcap))
            require(records == statistics["packets_captured"] == statistics["packets_received_by_filter"]
                    and all(metadata[name] == 0 for name in ("ebpf_lost_event_count", "packet_capture_counter_discrepancy",
                                                             "packet_capture_dropped_by_kernel"))
                    and metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] == 0, "Sensor loss/counter evidence")
            telemetry_text = (run_dir / "telemetry.csv").read_text()
            probe = probes.audit_probe(metadata, json.loads((run_dir / "capture-path-probe.json").read_text()), pcap, telemetry_text)
            row.update(pcap_frames=records, in_window_frames=probe["in_window_frames"], probe=probe)
            ambient = quiet_ambient.summarize(run_dir / "packet_capture.pcap")
            row["ambient_disabled_source_frames"] = ambient["disabled_source_frames"]
            row["other_frames_by_source"] = ambient["remaining_by_source"]
            require(all(count == 0 for count in ambient["disabled_source_frames"].values()), "Disabled ambient source present")
            extracted, _windows, diagnostics = data.p4.derive_p4_features(run_dir / "packet_capture.pcap", telemetry, metadata,
                                                                          byte_layer="ethernet", rate_window="nominal")
            row["p4_alignment"] = diagnostics["alignment_status"]
            comparisons = 0
            if diagnostics["alignment_status"] == "unique":
                for name in data.p4.P4_FEATURES:
                    for statistic, stored in data.aggregate([float(window[name]) for window in telemetry]).items():
                        require(math.isclose(stored, float(extracted["network__p4_" + name + "__" + statistic]),
                                             rel_tol=1e-9, abs_tol=1e-9), "P4 parity mismatch: " + name)
                        comparisons += 1
            else:
                require(probe["in_window_frames"] == 0 and all(float(window[name]) == 0 for window in telemetry
                                                               for name in data.p4.P4_FEATURES),
                        "P4 alignment not unique for a capture with in-window traffic")
            row["p4_parity_comparisons"] = comparisons
            if case["label"] == "network_control":
                marker = "/attribution-" + case["arguments"][1]
                parsed = quiet_ambient.frames(run_dir / "packet_capture.pcap")
                rows = list(__import__("csv").DictReader(io.StringIO(telemetry_text)))
                start, end = probes.utc_ns(rows[0]["window_start_utc"]), probes.utc_ns(rows[-1]["window_end_utc"])
                inside = [frame for frame in parsed if start <= int(frame["epoch"] * 1e9) < end]
                http = [frame for frame in inside if frame["http_uri"] == marker]
                udp = subprocess.run(["tshark", "-r", str(run_dir / "packet_capture.pcap"), "-Y",
                                      "udp.dstport == 65003 && ip.dst == 10.0.0.1 && !icmp", "-T", "fields", "-e", "frame.time_epoch"],
                                     capture_output=True, text=True, check=True).stdout.split()
                udp_inside = [value for value in udp if start <= int(float(value) * 1e9) < end]
                row.update(marked_http_in_window=len(http), udp_65003_in_window=len(udp_inside))
                require(http and len(udp_inside) == 6, "Network control traffic not inside the feature windows")
            if case["label"] == "null":
                nulls.setdefault(case["mode"], []).append(execution["post_target_lineage_raw_syscalls"])
            row["post_target_lineage_raw_syscalls"] = execution["post_target_lineage_raw_syscalls"]
            row["status"] = "accepted"
        except (ValueError, KeyError, FileNotFoundError, StopIteration) as error:
            row["status"] = "rejected"
            row["findings"].append(type(error).__name__ + ": " + str(error))
            failures.append(case["sample"])
        results.append(row)
    summary = {"accepted": not failures, "cases": len(results), "rejected": failures,
               "quiet_non_network_cases": sum(1 for row in results if row["label"] != "network_control"
                                              and row.get("in_window_frames") == 0),
               "null_max_post_target_syscalls": {mode: max(values) for mode, values in nulls.items()},
               "results": results, "validator_sha256": digest(__file__)}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    save(attempt / ("validation-" + stamp + ".json"), summary)
    print(json.dumps({key: summary[key] for key in ("accepted", "cases", "rejected", "quiet_non_network_cases",
                                                    "null_max_post_target_syscalls")}, indent=2))
    return summary


def self_test():
    _guest_root, selected = cases()
    require(len(selected) == 18 and len({case["sample"] for case in selected}) == 18, "Pilot case count differs")
    require(Counter(case["label"] for case in selected) == {"null": 6, "benign": 9, "network_control": 3}, "Pilot mix differs")
    require(Counter(case["mode"] for case in selected if case["label"] == "benign") ==
            {"native_amd64_dynamic": 3, "native_amd64_static": 3, "native_i386_static": 3}, "Benign mode balance differs")
    payload = build_payload(selected)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        names = archive.getnames()
    require(sorted(name for name in names if name.startswith("samples/")) == sorted("samples/" + case["sample"] for case in selected),
            "Payload samples differ from the benign/null pilot selection")
    require(not any(len(Path(name).stem) == 64 for name in names), "Payload contains a malware-hash transport")
    print("PASS benign-only 18-case pilot selection (6 null, 9 benign 3/3/3 per mode, 3 network), byte-verified transports, "
          "payload %d bytes; no VM operation" % len(payload))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--check-only", action="store_true")
    action.add_argument("--execute", action="store_true")
    action.add_argument("--validate", type=Path)
    parser.add_argument("--approval")
    options = parser.parse_args()
    if options.validate:
        validate(options.validate.resolve())
        return
    self_test()
    if options.self_test:
        return
    if options.check_only:
        preflight()
        print("PASS read-only preflight: real src .18, pinned scripts, no competitor, original TLS/off, Sink, quiet snapshot")
        return
    if options.execute and not options.approval:
        parser.error("--execute requires --approval")
    attempt, _protocol = freeze()
    print(attempt)
    if options.execute:
        execute(attempt, options.approval)
        validate(attempt)


if __name__ == "__main__":
    main()
