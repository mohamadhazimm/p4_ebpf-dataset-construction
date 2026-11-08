"""Approval-gated small collection using the installed .19 runner; never execute samples on the host."""

import argparse
import ast
import base64
import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import math
import os
import random
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
SCHEMA = "2026-10-24.19"
BASELINE = "clean-quiet-ambient-20261024T080813430717Z"
MATCHED = ROOT / "matched45-readiness/20261022T072823231146Z"
MANIFEST_SHA256 = "43d913c154f442bcec9879dfc06398e8814d54110ff7f61fcad7fdb77a96799a"
PAYLOAD_SHA256 = "3f0f46698f32f258ef8fb895b3e3d05aa2a886bbd9b1967cfeeb458cc1a6a6e3"
BENIGN_PROGRAMS = ("ginstall", "nice", "printf", "lesskey", "echo", "xzdec")
EXPECTED_MODE = {"native_amd64_dynamic": ("native", "dynamic", 62),
                 "native_amd64_static": ("native", "static", 62),
                 "native_i386_static": ("native_compat", "static", 3)}
SETTINGS = ["--timeout", "20", "--window-sec", "0.5", "--iface", "enp0s3", "--ebpf",
            "--fixed-observation", "--common-launch-wrapper"]
PINNED = {
    "src/malware_runner.py": "37e5a156774663214ba231825c5174c048d5468747b0a213624153426af60b0a",
    "scripts/vbox_malware_batch.sh": "4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f",
    "scripts/stage_versioned_runner_snapshot.sh": "5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def verify_production(study=STUDY):
    observed = {name: digest(study / name) for name in PINNED}
    for name, expected in PINNED.items():
        require(observed[name] == expected, "Installed .19 production provenance changed: " + name)
    return observed


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def load(path):
    return json.loads(Path(path).read_text())


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def select_cases(manifest):
    cases = manifest["cases"]
    benign = [case for case in cases if case["label"] == "benign" and case["program"] in BENIGN_PROGRAMS]
    require(len(benign) == 6, "Need the six frozen output-verifiable benign programs")
    generator = random.Random(42)
    ordered = sorted((case for case in cases if case["label"] == "null" and case["repeat"] == 1),
                     key=lambda case: case["mode"])
    slots = Counter((case["mode"], case["split"]) for case in benign)
    for (mode, split), count in sorted(slots.items()):
        candidates = [case for case in cases if case["label"] == "malware"
                      and (case["mode"], case["split"]) == (mode, split)]
        groups = sorted({case["group_id"] for case in candidates})
        queues = {group: sorted((case for case in candidates if case["group_id"] == group),
                                key=lambda case: case["sha256"]) for group in groups}
        malware = []
        while len(malware) < count:
            require(any(queues.values()), "Insufficient malware in the matched slot")
            for group in groups:
                if queues[group] and len(malware) < count:
                    malware.append(queues[group].pop(0))
        controls = sorted((case for case in benign if (case["mode"], case["split"]) == (mode, split)),
                          key=lambda case: case["sample"])
        for control, target in zip(controls, malware):
            pair = [control, target]
            generator.shuffle(pair)
            ordered.extend(pair)
    ordered.extend(sorted((case for case in cases if case["label"] == "null" and case["repeat"] == 2),
                          key=lambda case: case["mode"]))
    ordered = copy.deepcopy(ordered)
    require(len(ordered) == 18 and len({case["sample"] for case in ordered}) == 18, "Expected 18 unique transports")
    require(Counter(case["label"] for case in ordered) == {"malware": 6, "benign": 6, "null": 6}, "Case budget differs")
    for label in ("malware", "benign", "null"):
        require(Counter(case["mode"] for case in ordered if case["label"] == label) ==
                {mode: 2 for mode in EXPECTED_MODE}, "Per-mode budget differs")
    for position, case in enumerate(ordered, 1):
        require(re.fullmatch(r"[A-Za-z0-9._-]+", case["sample"]), "Unsafe transport basename")
        require(case.get("group_id") not in {"malware_signature::DDoSAgent", "benign_project::util-linux"},
                "Globally excluded group")
        if case["label"] == "malware":
            require(case["split"] == case["inherited_role"], "Inherited role changed")
        case["position"] = position
    return ordered


def safe_member(member):
    path = Path(member.name)
    require(not path.is_absolute() and ".." not in path.parts and member.name not in ("", ".")
            and (member.isfile() or member.isdir()) and member.size <= 64 * 1024 * 1024,
            "Unsafe or oversized payload member: " + member.name)


def build_payload(selected, source=MATCHED / "payload.tgz"):
    require(digest(source) == PAYLOAD_SHA256, "Frozen matched45 payload changed")
    samples = {"samples/" + case["sample"]: case for case in selected}
    fixtures = {"fixtures/" + case["case_id"]: case for case in selected if case["label"] == "benign"}
    members = {}
    with tarfile.open(source, "r:gz") as archive:
        seen = set()
        for member in archive:
            safe_member(member)
            require(member.name not in seen, "Duplicate source payload member")
            seen.add(member.name)
            if member.name in samples or any(member.name == prefix or member.name.startswith(prefix + "/")
                                             for prefix in fixtures):
                content = archive.extractfile(member).read() if member.isfile() else None
                members[member.name] = (member, content)
    for name, case in samples.items():
        require(name in members and members[name][1] is not None, "Missing selected transport")
        require(hashlib.sha256(members[name][1]).hexdigest() == case["transport_sha256"], "Changed transport: " + name)
    for prefix, case in fixtures.items():
        observed = {name[len(prefix) + 1:]: hashlib.sha256(content).hexdigest()
                    for name, (_member, content) in members.items()
                    if name.startswith(prefix + "/") and content is not None}
        require(observed == case["fixture_hashes"], "Frozen fixture identities differ: " + prefix)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, (original, content) in sorted(members.items()):
            member = tarfile.TarInfo(name)
            member.mode = 0o600 if name in samples else original.mode & 0o777
            if content is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        for case in selected:
            content = json.dumps(case["collection_arguments"]).encode()
            member = tarfile.TarInfo("arguments/" + case["sample"] + ".json")
            member.size, member.mode = len(content), 0o644
            archive.addfile(member, io.BytesIO(content))
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
    seen=set()
    for member in archive:
        target=root/member.name
        if member.name in seen or not target.resolve().is_relative_to(root) or not (member.isfile() or member.isdir()):
            raise SystemExit('unsafe payload member')
        seen.add(member.name)
        if member.isdir():
            target.mkdir(parents=True,exist_ok=True)
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb') as stream:
                stream.write(archive.extractfile(member).read())
            target.chmod(member.mode & 0o777)
print('18 frozen transports staged; no sample executed')
PY
""" % (guest_root, base64.b64encode(payload).decode(), hashlib.sha256(payload).hexdigest())


def helper():
    sys.path.insert(0, str(ROOT))
    from export_original_sources import helper_module
    return helper_module()


def validation_tools():
    sys.path.insert(0, str(ROOT))
    import audit_performance_v4
    import matched45_workloads
    import quiet_ambient
    legacy = STUDY / "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/readiness/20261021T104951987641Z/prepare_model_data.py"
    spec = importlib.util.spec_from_file_location("v19_collection_features", legacy)
    data = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(data)
    return data, audit_performance_v4, quiet_ambient, matched45_workloads


def source_hashes():
    module = helper()
    data, probes, ambient, workloads = validation_tools()
    workspace = STUDY.parents[1]
    paths = {Path(__file__), Path(module.__file__), Path(data.__file__), Path(probes.__file__),
             Path(ambient.__file__), Path(workloads.__file__), MATCHED / "manifest.json",
             MATCHED / "payload.tgz", ROOT / "HANDOFF_COLLECTOR_V19.md"}
    for imported in list(sys.modules.values()):
        filename = getattr(imported, "__file__", None)
        if filename and Path(filename).suffix == ".py" and Path(filename).resolve().is_relative_to(workspace):
            paths.add(Path(filename).resolve())
    return {str(path): digest(path) for path in sorted(paths)}


def freeze():
    verify_production()
    require(digest(MATCHED / "manifest.json") == MANIFEST_SHA256, "Frozen matched45 manifest changed")
    source = load(MATCHED / "manifest.json")
    selected = select_cases(source)
    payload = build_payload(selected)
    setup = setup_script(source["guest_root"], payload)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    run_id = stamp()
    attempt = ROOT / "v19-small-collection" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    (attempt / "payload.tgz").write_bytes(payload)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in selected))
    protocol = {"format": "v19-small-collection-v1", "schema": SCHEMA, "production_hashes": PINNED,
        "baseline_snapshot": BASELINE, "new_snapshot": "clean-quiet-v19-small-" + run_id,
        "guest_root": source["guest_root"], "cases": selected, "settings": SETTINGS,
        "settings_required": {**source["settings_required"], "telemetry_schema_version": SCHEMA,
                              "malware_runner_sha256": PINNED["src/malware_runner.py"]},
        "selection": "Six archive-verifiable benign tasks; family/hash round-robin malware in matched mode/role slots; seed42 pair order",
        "counts": {"malware": 6, "benign": 6, "null": 6}, "seed": 42,
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "model_fitting": False, "merge_with_v18": False, "collection_ready": False,
        "criteria": ["retrieved; installed .19 hash/schema; accepted quality; exact exec; mode/linkage",
                     "40x169 finite; safe archive hashes; independent PCAP == received == captured; zero loss/ABI",
                     "independent pre/post probes outside windows; zero disabled-source frames",
                     "unique recorded-window Ethernet/nominal P4 alignment and parity; report all exclusions",
                     "benign/null exit0 and substantive saved outputs; malware exit0 is not required"],
        "limitations": ["Small engineering collection; inherited evaluation is consumed/exploratory",
                        "No general completeness, malicious activation or hybrid-superiority claim",
                        "Quiet .19 data remain separate from all .18 datasets; low activity retained"],
        "source_hashes": source_hashes(),
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt")}}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "vm_steps_authorized": []}, indent=2))
    return attempt


def verify_plan(attempt, expected_hash):
    require(expected_hash and digest(attempt / "protocol.json") == expected_hash, "Explicit frozen protocol hash required")
    protocol = load(attempt / "protocol.json")
    require(protocol["format"] == "v19-small-collection-v1" and protocol["production_hashes"] == PINNED,
            "Protocol version or pins differ")
    require(protocol["cases"] == select_cases(load(MATCHED / "manifest.json")), "Case identities or order differ")
    require(protocol["settings"] == SETTINGS and protocol["schema"] == SCHEMA
            and protocol["baseline_snapshot"] == BASELINE, "Frozen collection contract differs")
    verify_production()
    for name, expected in protocol["source_hashes"].items():
        require(digest(name) == expected, "Frozen source changed: " + name)
    for name, expected in protocol["files"].items():
        require(digest(attempt / name) == expected, "Frozen payload/order changed: " + name)
    return protocol


def snapshot_uuid(module, name):
    entries = dict(line.split("=", 1) for line in module.vbox("snapshot", module.VM, "list", "--machinereadable").stdout.splitlines()
                   if "=" in line)
    keys = [key for key, value in entries.items() if key.startswith("SnapshotName") and value.strip('"') == name]
    require(len(keys) == 1, "Missing or ambiguous snapshot: " + name)
    return entries[keys[0].replace("SnapshotName", "SnapshotUUID")].strip('"')


def state_check(module):
    states = {"guest": module.isolated(module.VM), "sink": module.isolated("Sink")}
    require(states["guest"]["VMState"] == '"poweroff"'
            and states["guest"]["CurrentSnapshotName"] == '"' + module.ORIGINAL + '"'
            and states["sink"]["VMState"] == '"running"', "Need original TLS/off and isolated running Sink")
    return states


def preflight(module):
    from export_original_sources import check_competitors
    verify_production()
    check_competitors()
    states = state_check(module)
    original_uuid = snapshot_uuid(module, module.ORIGINAL)
    require(original_uuid == "72de0a02-2e71-42b8-85e2-78c21d6b00f9", "Original TLS snapshot UUID differs")
    return {"states": states, "baseline_uuid": snapshot_uuid(module, BASELINE), "original_uuid": original_uuid}


def restore(module, destination):
    if module.vm_info(module.VM)["VMState"] != '"poweroff"':
        module.vbox("controlvm", module.VM, "poweroff")
    module.vbox("snapshot", module.VM, "restore", module.ORIGINAL)
    states = state_check(module)
    save(destination / "final_vm_state.json", states)
    return states


def batch_command(module, attempt, protocol, dry_run=False):
    command = ["bash", str(STUDY / "scripts/vbox_malware_batch.sh"), "--vm", module.VM,
        "--guest-user", module.GUEST_USER, "--guest-malware-dir", protocol["guest_root"] + "/samples",
        "--guest-runner", "/home/csci/Downloads/malware_runner.py", "--snapshot", protocol["new_snapshot"],
        "--schema-version", SCHEMA, "--guest-arguments-dir", protocol["guest_root"] + "/arguments",
        "--sample-list", str(attempt / "cases.txt"), "--output-dir", str(attempt / ("dry-run" if dry_run else "runs")),
        *SETTINGS]
    return command + (["--dry-run"] if dry_run else [])


def run_logged(command, logfile, timeout):
    environment = {**os.environ, "ENV_FILE": str(STUDY.parents[1] / ".env")}
    with logfile.open("x") as log:
        child = subprocess.Popen(command, cwd=STUDY, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            returncode = child.wait(timeout=timeout)
            require(returncode == 0, "Phase command returned " + str(returncode) + "; no retry")
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()


def validate_dry_run(logfile, protocol):
    paths = [line.partition(": ")[2] for line in logfile.read_text().splitlines()
             if line.startswith("Validated sample: ")]
    expected = [protocol["guest_root"] + "/samples/" + case["sample"] for case in protocol["cases"]]
    require(paths == expected, "Dry-run allowlist/order differs")
    return len(paths)


def perform_phase(attempt, phase, expected_hash, approval):
    require(approval and approval.strip(), "A verbatim user approval is required for this VM phase")
    protocol = verify_plan(attempt, expected_hash)
    module = helper()
    predecessors = {"stage": "preflight", "dry-run": "stage", "collect": "dry-run"}
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if phase in predecessors:
            prior = load(attempt / "phases" / predecessors[phase] / "result.json")
            require(prior["status"] == "passed" and prior["protocol_sha256"] == expected_hash, "Previous phase not accepted")
        destination = attempt / "phases" / phase
        destination.mkdir(parents=True, exist_ok=False)
        save(destination / "authorization.json", {"approval": approval, "phase": phase,
             "protocol_sha256": expected_hash, "authorized_utc": datetime.now(timezone.utc).isoformat(),
             "cleanup_authorized": phase != "preflight", "one_attempt_only": True})
        result = {"phase": phase, "protocol_sha256": expected_hash, "status": "failed_preserved"}
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt("Stop owned process group, restore original snapshot, preserve failure")
        previous_handler = signal.signal(signal.SIGTERM, interrupted)
        touched = False
        try:
            before = preflight(module)
            save(destination / "initial_vm_state.json", before)
            if phase == "preflight":
                result.update(before)
            else:
                approved = load(attempt / "phases/preflight/result.json")
                require(before["baseline_uuid"] == approved["baseline_uuid"]
                        and before["original_uuid"] == approved["original_uuid"], "Clean snapshot identity changed")
                if phase == "stage":
                    listing = module.vbox("snapshot", module.VM, "list", "--machinereadable").stdout
                    require('"' + protocol["new_snapshot"] + '"' not in listing, "New child already exists; no restage")
                    command = ["bash", str(STUDY / "scripts/stage_versioned_runner_snapshot.sh"),
                        "--vm", module.VM, "--guest-user", module.GUEST_USER,
                        "--baseline-snapshot", BASELINE, "--new-snapshot", protocol["new_snapshot"],
                        "--schema-version", SCHEMA, "--guest-setup", str(attempt / "setup_guest.sh")]
                else:
                    staged = load(attempt / "phases/stage/result.json")
                    require(snapshot_uuid(module, protocol["new_snapshot"]) == staged["snapshot_uuid"], "Staged child identity differs")
                    require(not (attempt / ("dry-run" if phase == "dry-run" else "runs")).exists(), "Existing output; no retry/resume")
                    command = batch_command(module, attempt, protocol, phase == "dry-run")
                save(destination / "command.json", command)
                touched = True
                run_logged(command, destination / "command.log", 900 if phase == "stage" else 5400)
                if phase == "stage":
                    result["snapshot_uuid"] = snapshot_uuid(module, protocol["new_snapshot"])
                elif phase == "dry-run":
                    result["validated_transports"] = validate_dry_run(destination / "command.log", protocol)
            verify_plan(attempt, expected_hash)
            result["status"] = "passed"
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            try:
                if touched:
                    restore(module, destination)
            except BaseException as error:
                result.update(status="cleanup_failed_requires_user", cleanup_error=type(error).__name__ + ": " + str(error))
                raise
            finally:
                save(destination / "result.json", result)
                signal.signal(signal.SIGTERM, previous_handler)
        print(json.dumps(result, indent=2))


def metadata_checks(metadata, case, settings):
    require(not sys.flags.optimize, "Do not disable the frozen workload assertions with Python -O")
    for name, expected in settings.items():
        require(metadata.get(name) == expected, "Setting/quality/provenance differs: " + name)
    require(metadata["collection_quality_reasons"] == [], "Quality reasons are not empty")
    execution = metadata["target_exec"]
    require(execution["status"] == "observed" and execution["match"] == "exact", "Target exec not observed exactly")
    program = case.get("program")
    if program:
        require(Path(execution["expected_path"]).name == program, "Target basename differs")
    mode, linkage, machine = EXPECTED_MODE[case["mode"]]
    artifact = metadata["target_artifact"]
    require((artifact["execution_mode"], artifact["linkage"], artifact["e_machine"]) == (mode, linkage, machine),
            "Target mode/linkage differs")
    require(metadata["ebpf_event_diagnostics"]["raw_syscalls_unresolved_abi"] == 0, "Unresolved ABI")
    require(metadata["packet_capture_rmem_max_before"] == metadata["packet_capture_rmem_max_after_capture"]
            and metadata["packet_capture_rmem_max_during_capture"] == 134217728, "Buffer restoration differs")
    require(metadata["packet_capture_interface_link_state_before_sample"] == {"operstate": "up", "carrier": 1},
            "Interface link evidence differs")
    if case["label"] != "malware":
        require(metadata["return_code"] == 0, "Benign/null target did not exit zero")


def audit_archive(sample_dir):
    output = (sample_dir / "output").resolve()
    seen, regular, total = set(), set(), 0
    with tarfile.open(sample_dir / "output.tgz", "r:gz") as archive:
        for member in archive:
            target = (output / member.name).resolve()
            require(not Path(member.name).is_absolute() and ".." not in Path(member.name).parts
                    and target.is_relative_to(output) and member.name not in seen
                    and (member.isfile() or member.isdir()), "Unsafe/duplicate evidence member")
            seen.add(member.name)
            if member.isdir():
                continue
            regular.add(target)
            total += member.size
            require(member.size <= 512 * 1024 * 1024 and total <= 2 * 1024 * 1024 * 1024, "Evidence exceeds size bounds")
            checksum = hashlib.sha256()
            with archive.extractfile(member) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    checksum.update(block)
            require(target.is_file() and not target.is_symlink() and checksum.hexdigest() == digest(target),
                    "Evidence archive/host hash differs")
            require(target.stat().st_mode & 0o777 == member.mode & 0o777, "Evidence file mode differs")
    require(total > 0, "Empty evidence archive")
    require({path.resolve() for path in output.rglob("*") if path.is_file()} == regular,
            "Host evidence file is absent from the archive")
    return len(regular)


def audit_case(sample_dir, case, settings, module, tools):
    data, probes, ambient, workloads = tools
    host = dict(line.split("=", 1) for line in (sample_dir / "host_run.txt").read_text().splitlines() if "=" in line)
    require(host.get("status") == "completed", "Retrieval not completed: " + str(host.get("status")))
    paths = list((sample_dir / "output").glob("run_*/run.json"))
    require(len(paths) == 1, "Missing or ambiguous run metadata")
    run_dir = paths[0].parent
    metadata = load(paths[0])
    row = {"return_code": metadata.get("return_code"), "quality_status": metadata.get("collection_quality_status"),
           "exec_status": metadata.get("target_exec", {}).get("status")}
    metadata_checks(metadata, case, settings)
    row["archive_members"] = audit_archive(sample_dir)
    telemetry = data.p4.load_telemetry_rows(sample_dir)
    features = [name for group in metadata["telemetry_feature_groups"].values() for name in group]
    require(len(telemetry) == 40 and len(features) == len(set(features)) == 169
            and all(math.isfinite(float(window[name])) for window in telemetry for name in features), "Incomplete/nonfinite 40x169")
    pcap = (run_dir / "packet_capture.pcap").read_bytes()
    records = sum(1 for _frame in probes.frames(pcap))
    statistics = metadata["packet_capture_statistics"]
    require(records == statistics["packets_captured"] == statistics["packets_received_by_filter"]
            and statistics["dropped_by_kernel"] == 0, "Independent PCAP/counter disagreement")
    probe = probes.audit_probe(metadata, load(run_dir / "capture-path-probe.json"), pcap,
                               (run_dir / "telemetry.csv").read_text())
    traffic = ambient.summarize(run_dir / "packet_capture.pcap")
    require(all(count == 0 for count in traffic["disabled_source_frames"].values()), "Disabled ambient source present")
    extracted, _windows, diagnostics = data.p4.derive_p4_features(run_dir / "packet_capture.pcap", telemetry, metadata,
                                                                byte_layer="ethernet", rate_window="nominal")
    require(diagnostics["alignment_status"] == "unique", "P4 alignment not unique")
    comparisons = 0
    for name in data.p4.P4_FEATURES:
        for statistic, stored in data.aggregate([float(window[name]) for window in telemetry]).items():
            require(math.isclose(stored, float(extracted["network__p4_" + name + "__" + statistic]),
                                 rel_tol=1e-9, abs_tol=1e-9), "P4 parity mismatch: " + name)
            comparisons += 1
    if case["label"] == "benign":
        result = subprocess.CompletedProcess([], metadata["return_code"],
            (run_dir / "sample.stdout.log").read_text(), (run_dir / "sample.stderr.log").read_text())
        workloads.check_result(case, result, run_dir / "workspace", run_dir / "unused-fixtures")
    elif case["label"] == "null":
        require((run_dir / "sample.stdout.log").read_bytes() == b"", "Null emitted stdout")
    row.update(pcap_frames=records, in_window_frames=probe["in_window_frames"], probe=probe,
               ambient_disabled_source_frames=traffic["disabled_source_frames"],
               remaining_by_source=traffic["remaining_by_source"], p4_alignment=diagnostics["alignment_status"],
               p4_parity_comparisons=comparisons, finite_cells=40 * 169,
               post_target_lineage_raw_syscalls=metadata["target_exec"]["post_target_lineage_raw_syscalls"])
    return row


def validate(attempt, expected_hash):
    protocol = verify_plan(attempt, expected_hash)
    module, tools = helper(), validation_tools()
    rows, nulls = [], {}
    for case in protocol["cases"]:
        row = {key: case[key] for key in ("sample", "label", "mode", "split", "sha256")}
        sample_dir = attempt / "runs" / case["sample"]
        paths = list((sample_dir / "output").glob("run_*/run.json"))
        if len(paths) == 1:
            metadata = load(paths[0])
            row.update(return_code=metadata.get("return_code"), quality_status=metadata.get("collection_quality_status"),
                       quality_reasons=metadata.get("collection_quality_reasons"),
                       exec_status=metadata.get("target_exec", {}).get("status"))
        try:
            row.update(audit_case(sample_dir, case, protocol["settings_required"], module, tools), status="accepted")
            if case["label"] == "null":
                nulls.setdefault(case["mode"], []).append(row["post_target_lineage_raw_syscalls"])
        except Exception as error:
            row.update(status="excluded", reason=type(error).__name__ + ": " + str(error))
        rows.append(row)
    summary = {"status": "offline_audited_no_merge_no_model", "protocol_sha256": expected_hash, "results": rows,
        "counts": dict(Counter(row["status"] for row in rows)), "collection_ready": False,
        "all_cases_accepted": all(row["status"] == "accepted" for row in rows),
        "null_max_post_target_syscalls": {mode: max(values) for mode, values in nulls.items()},
        "model_fits": 0, "merged_cases": 0, "validator_sha256": digest(__file__),
        "limitations": protocol["limitations"]}
    report = attempt / ("validation-" + stamp() + ".json")
    save(report, summary)
    print(json.dumps({"report": str(report), "counts": summary["counts"],
                      "null_max_post_target_syscalls": summary["null_max_post_target_syscalls"]}, indent=2))
    return summary


def phase_tests():
    with tempfile.TemporaryDirectory(prefix="hazim-v19-phases-") as directory:
        temporary = Path(directory)
        fake_helper = SimpleNamespace(__file__=str(temporary / "helper.py"), VM="test", GUEST_USER="test",
            vbox=lambda *arguments: SimpleNamespace(stdout=""))
        protocol = {"guest_root": "/guest", "new_snapshot": "test-child",
                    "cases": [{"sample": "first.zip"}, {"sample": "second.zip"}]}
        before = {"baseline_uuid": "baseline", "original_uuid": "original"}
        expected = ["/guest/samples/first.zip", "/guest/samples/second.zip"]
        def write_log(logfile, paths):
            logfile.write_text("".join("Validated sample: " + path + "\n" for path in paths))
        def fake_run(_command, logfile, _timeout):
            write_log(logfile, expected)
        logfile = temporary / "dry-run.log"
        write_log(logfile, expected)
        require(validate_dry_run(logfile, protocol) == 2, "Dry-run positive control failed")
        for paths in (expected[:1], expected[::-1], expected + expected[:1],
                      ["/wrong/samples/first.zip", expected[1]]):
            write_log(logfile, paths)
            try:
                validate_dry_run(logfile, protocol)
            except ValueError:
                pass
            else:
                raise AssertionError("Invalid dry-run history accepted")
        with patch(__name__ + ".verify_plan", return_value=protocol), patch(__name__ + ".helper", return_value=fake_helper), \
             patch(__name__ + ".preflight", return_value=before), patch(__name__ + ".snapshot_uuid", return_value="child"), \
             patch(__name__ + ".run_logged", side_effect=fake_run) as logged, patch(__name__ + ".restore") as cleanup:
            attempt = temporary / "attempt"
            attempt.mkdir()
            try:
                perform_phase(attempt, "preflight", "test-hash", "")
            except ValueError:
                pass
            else:
                raise AssertionError("Approval missing but phase accepted")
            require(not (attempt / "phases").exists(), "Unapproved phase wrote a receipt")
            for phase in ("preflight", "stage", "dry-run", "collect"):
                perform_phase(attempt, phase, "test-hash", "SIMULATED explicit " + phase + " approval with cleanup")
                require(load(attempt / "phases" / phase / "result.json")["status"] == "passed", "Simulated phase failed")
            require(logged.call_count == 3 and cleanup.call_count == 3, "Mutating phases did not clean up exactly once")
            require("--dry-run" in logged.call_args_list[1].args[0]
                    and "--dry-run" not in logged.call_args_list[2].args[0]
                    and all("--resume" not in call.args[0] for call in logged.call_args_list), "Batch phase routing differs")
            try:
                perform_phase(attempt, "collect", "test-hash", "SIMULATED retry")
            except FileExistsError:
                pass
            else:
                raise AssertionError("A second collection attempt was accepted")
            failed = temporary / "failed"
            failed.mkdir()
            perform_phase(failed, "preflight", "test-hash", "SIMULATED preflight")
            logged.side_effect = KeyboardInterrupt("SIMULATED command interruption")
            try:
                perform_phase(failed, "stage", "test-hash", "SIMULATED stage and restore")
            except KeyboardInterrupt:
                pass
            else:
                raise AssertionError("Interrupted stage was accepted")
            require(cleanup.call_count == 4 and load(failed / "phases/stage/result.json")["status"] == "failed_preserved",
                    "Interrupted phase cleanup/publication failed")
            try:
                perform_phase(failed, "dry-run", "test-hash", "SIMULATED dry-run")
            except ValueError:
                pass
            else:
                raise AssertionError("Failed predecessor did not stop dry-run")
    print("PASS SIMULATED approvals, phase order, dry-run identity/order guards, no retry/resume, interruption cleanup; no VirtualBox calls")


def saved_tests(selected, manifest):
    pilot = ROOT / "v19-pilot/20261024T083321478831Z"
    require(digest(pilot / "validation-20261024T084742214380Z.json") ==
            "2736e50f2d86bece461848479890c8f270bd534eefde8e5ebc2216071f96cd74", "Saved pilot acceptance changed")
    tools, module = validation_tools(), helper()
    settings = {**manifest["settings_required"], "telemetry_schema_version": SCHEMA,
                "malware_runner_sha256": PINNED["src/malware_runner.py"]}
    covered = []
    for case in selected:
        sample_dir = pilot / "runs" / case["sample"]
        if not sample_dir.exists():
            continue
        metadata = load(next(sample_dir.glob("output/*/run.json")))
        try:
            metadata_checks(metadata, case, settings)
        except ValueError as error:
            require("malware_runner_sha256" in str(error), "Unexpected saved draft provenance failure")
        else:
            raise AssertionError("Saved draft .19 accepted as installed .19")
        draft = {**settings, "malware_runner_sha256": "bef85019b580dbb3f135756aa9e9b7eb67447a0edb1cd92be7d630fed06f1ad2"}
        result = audit_case(sample_dir, case, draft, module, tools)
        require(result["p4_parity_comparisons"] == 145, "Saved parity comparison count differs")
        mutations = [("collection_quality_status", "rejected"), ("ebpf_lost_event_count", 1),
                     ("packet_capture_counter_discrepancy", 1), ("return_code", 2)]
        for field, value in mutations:
            altered = copy.deepcopy(metadata)
            altered[field] = value
            try:
                metadata_checks(altered, case, draft)
            except ValueError:
                pass
            else:
                raise AssertionError("Changed evidence accepted: " + field)
        altered = copy.deepcopy(metadata)
        altered["return_code"] = 2
        metadata_checks(altered, {**case, "label": "malware"}, draft)
        covered.append(case["sample"])
    require(len(covered) == 9, "Expected six saved nulls and three selected benign regression cases")
    print("PASS nine SAVED draft .19 audits, 1305 P4 parity comparisons, provenance/loss/quality/exit guards; no new captures")


def self_test():
    verify_production()
    with tempfile.TemporaryDirectory(prefix="hazim-v19-pins-") as directory:
        scratch = Path(directory)
        for name in PINNED:
            target = scratch / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((STUDY / name).read_bytes())
        verify_production(scratch)
        for name in PINNED:
            target = scratch / name
            original = target.read_bytes()
            target.write_bytes(original + b"\n")
            try:
                verify_production(scratch)
            except ValueError as error:
                require(name in str(error), "Wrong provenance guard fired")
            else:
                raise AssertionError("Changed production file was accepted: " + name)
            target.write_bytes(original)
    require(digest(MATCHED / "manifest.json") == MANIFEST_SHA256, "Frozen identity manifest changed")
    manifest = load(MATCHED / "manifest.json")
    selected = select_cases(manifest)
    reversed_manifest = {**manifest, "cases": list(reversed(manifest["cases"]))}
    require(selected == select_cases(reversed_manifest), "Selection depends on source row order")
    payload = build_payload(selected)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        require(sorted(name for name in archive.getnames() if name.startswith("samples/")) ==
                sorted("samples/" + case["sample"] for case in selected), "Payload sample allowlist differs")
        for case in selected:
            require(json.load(archive.extractfile("arguments/" + case["sample"] + ".json")) ==
                    case["collection_arguments"], "Arguments changed")
    setup = setup_script(manifest["guest_root"], payload)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    phase_tests()
    saved_tests(selected, manifest)
    print("PASS installed .19 pins and all three corruption guards; no VM or sample execution")
    print("PASS deterministic 18-case selection, exact opaque transports/fixtures/arguments and generated setup syntax")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--verify-local", action="store_true")
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--phase", choices=("preflight", "stage", "dry-run", "collect"))
    action.add_argument("--validate", action="store_true")
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    options = parser.parse_args()
    if options.phase or options.validate:
        require(options.attempt and options.protocol_sha256, "Attempt path and approved frozen hash required")
        if options.phase:
            perform_phase(options.attempt.resolve(), options.phase, options.protocol_sha256, options.approval)
        else:
            validate(options.attempt.resolve(), options.protocol_sha256)
    elif options.self_test:
        self_test()
    elif options.freeze_only:
        freeze()
    else:
        print(json.dumps(verify_production(), indent=2))


if __name__ == "__main__":
    main()