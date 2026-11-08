#!/usr/bin/env python3
"""Freeze and run the prospectively approved, benign-only performance gate."""

import argparse
import ast
import copy
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import integrated_exec_identity as identity
import scoped_performance as performance


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
CORRECTION = ROOT / "release-proposals/20261023T081218460447Z/source-correction.json"
CORRECTION_SHA256 = "3b5a3a78f8d47de7de31c04a534e46555e5b4a9a409e81c28df69929b7ef75eb"


def plan():
    rows = []
    for abi in ("amd64", "i386"):
        for task in ("file", "network"):
            for repeat in range(-2, 5):
                conditions = ("baseline", "original", "full") if repeat % 2 == 0 else ("full", "original", "baseline")
                for condition in conditions:
                    rows.append({"mode": "case-%03d" % len(rows), "abi": abi, "task": task,
                                 "condition": condition, "repeat": repeat, "warmup": repeat < 0,
                                 "binary": "performance-" + abi})
    if len(rows) != 84 or sum(not row["warmup"] for row in rows) != 60:
        raise ValueError("Prospective case design differs")
    return rows


def approved_contract():
    if identity.digest(CORRECTION) != CORRECTION_SHA256:
        raise ValueError("Approved source correction changed")
    corrected = json.loads(CORRECTION.read_text())
    for name, expected in corrected["input_hashes"].items():
        if identity.digest(name) != expected:
            raise ValueError("Changed approved source-review input: " + name)
    earlier = json.loads(Path(corrected["previous_contract"]).read_text())
    return {"schema": "approved-source-corrected-engineering-contract-v1", "source_correction": str(CORRECTION),
            "source_correction_sha256": CORRECTION_SHA256, "pairs": corrected["pairs"],
            "performance_limits": earlier["performance_limits"], "roles_effective": True,
            "approval": "Explicit Approve Engineering Pilot Scope; Approve These Prospective Limits; Approve Frozen Source Correction answers in this session",
            "collection_ready": False, "malware_launch_authorized": False, "model_fitting_authorized": False,
            "old_capture_merge_authorized": False, "existing_417_assignments_unchanged": True,
            "source_lineage_independence_certified": False}


def build_tasks(attempt):
    import freeze_scoped_contract as source_review
    toolchain = ROOT.parent / "cohort-expansion-100x100-v18-20261021/i386-toolchain-probe/20261021T153000Z"
    sys.path.insert(0, str(toolchain))
    import audit_toolchain_packages
    import build_i386_controls
    authentication = audit_toolchain_packages.authenticate_packages()
    sysroot = attempt / "sysroot"
    for package in authentication["packages"]:
        subprocess.run(["dpkg-deb", "-x", str(audit_toolchain_packages.STUDY / package["path"]), str(sysroot)], check=True)
    environment = build_i386_controls.toolchain_environment(sysroot)
    source = ROOT / "scoped_performance_task.c"
    binaries = {}
    commands = []
    for abi in ("amd64", "i386"):
        binary = attempt / ("performance-" + abi)
        command = (["gcc", "-static"] if abi == "amd64" else shlex.split(environment["CC"]) + shlex.split(environment["CPPFLAGS"]))
        command += ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source)]
        if abi == "i386":
            command += shlex.split(environment["LDFLAGS"])
        command += ["-o", str(binary)]
        built = subprocess.run(command, capture_output=True, text=True, env=environment if abi == "i386" else None)
        (attempt / (abi + "-build.log")).write_text(built.stdout + built.stderr)
        built.check_returncode()
        facts = source_review.executable_regions(binary.read_bytes())
        if not facts["strict_static"] or (facts["elf_class"], facts["machine"]) != ((1, 3) if abi == "i386" else (2, 62)):
            raise ValueError("Performance task ELF mode differs")
        with tempfile.TemporaryDirectory() as directory:
            for task in ("file", "network"):
                observed = subprocess.run([str(binary), task], cwd=directory, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=6, check=True)
                receipt = json.loads(observed.stdout)
                if receipt["status"] != "accepted" or receipt["pointer_bits"] != (32 if abi == "i386" else 64):
                    raise ValueError("Actual local task or ABI failed")
        commands.append(command)
        binaries[abi] = binary
    identity.save(attempt / "performance-build.json", {"source_sha256": identity.digest(source), "commands": commands,
                  "authentication": authentication, "binaries": {name: identity.digest(path) for name, path in binaries.items()}})
    return binaries


def load_driver():
    import check_exec_identity as previous
    original = ROOT / "check_integrated_attribution.py"
    if identity.digest(original) != previous.FROZEN_DRIVER_SHA256:
        raise ValueError("Frozen guest/staging driver changed")
    tree = ast.parse(original.read_text())
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ("freeze", "execute", "runner_command")]
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            substitutions = {"integrated-collector-readiness": "scoped-performance", "clean-integrated-": "clean-performance-",
                             "/home/csci/Downloads/integrated-": "/home/csci/Downloads/performance-", "360000": "3600000",
                             "Four benign integrated captures only; no malware/full collection, role allocation or fitting": "Approved benign performance only: two warmups and five counterbalanced repetitions per ABI/file-network task across baseline/original/full; stop at first scored pair above1.25; no malware, collection release or fitting"}
            if isinstance(node.value, str):
                node.value = substitutions.get(node.value, node.value).replace('("attribution-control","xxhsum","attribution-v6")', '("attribution-control","xxhsum","attribution-v6","performance-amd64","performance-i386")')
    freeze = next(node for node in tree.body if node.name == "freeze")
    payload = next(node for node in freeze.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "payload" for target in node.targets))
    position = freeze.body.index(payload)
    freeze.body[position:position] = ast.parse("binaries = build_tasks(attempt)\nintegration.save(attempt / 'contract.json', approved_contract())").body
    for key, expression in (("scoped_performance.py", "ROOT / 'scoped_performance.py'"),
                            ("integrated_exec_identity.py", "ROOT / 'integrated_exec_identity.py'"),
                            ("exec_identity.py", "ROOT / 'exec_identity.py'"),
                            ("scoped_performance_task.c", "ROOT / 'scoped_performance_task.c'"),
                            ("performance-amd64", "binaries['amd64']"), ("performance-i386", "binaries['i386']"),
                            ("contract.json", "attempt / 'contract.json'")):
        payload.value.keys.append(ast.Constant(key))
        payload.value.values.append(ast.parse(expression, mode="eval").body)
    manifest = next(node for node in freeze.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "manifest" for target in node.targets))
    for index, key in enumerate(manifest.value.keys):
        if isinstance(key, ast.Constant) and key.value == "cases":
            manifest.value.values[index] = ast.parse("plan()", mode="eval").body
    manifest.value.keys.append(ast.Constant("source_correction_sha256"))
    manifest.value.values.append(ast.Name(id="CORRECTION_SHA256", ctx=ast.Load()))
    namespace = {**previous.FROZEN, "__file__": __file__, "integration": types_namespace(),
                 "build_tasks": build_tasks, "approved_contract": approved_contract, "plan": plan,
                 "CORRECTION_SHA256": CORRECTION_SHA256}
    exec(compile(ast.fix_missing_locations(tree), str(original), "exec"), namespace)
    return namespace


def types_namespace():
    from types import SimpleNamespace
    return SimpleNamespace(**{**vars(identity), "generate": performance.generate, "self_test": performance.self_test,
                              "SCHEMA": performance.SCHEMA, "__file__": str(ROOT / "integrated_attribution.py")})


def runner_command(root, case):
    return ["/usr/bin/python3", str(root / "integrated_runner.py"), str(root / case["binary"]),
            "--allow-execution", "--output-dir", str(root / ("output-" + case["mode"])),
            "--sample-args-file", str(root / (case["mode"] + "-args.json")), "--timeout", "20", "--window-sec", "0.5",
            "--iface", "enp0s3", "--fixed-observation", "--common-launch-wrapper",
            "--packet-capture-password-file", str(root / ".pcap-auth"), "--ebpf-password-file", str(root / ".ebpf-auth")]


def audit_run(directory, manifest, case):
    metadata = json.loads((directory / "run.json").read_text())
    usage = json.loads((directory / "task-usage.json").read_text())
    receipt = json.loads((directory / "sample.stdout.log").read_text())
    if metadata["telemetry_schema_version"] != performance.SCHEMA or metadata["malware_runner_sha256"] != manifest["files"]["integrated_runner.py"] or metadata["return_code"] != 0:
        raise ValueError("Measured runner provenance or exit differs")
    if receipt != {"status": "accepted", "task": case["task"], "pid": metadata["sample_root_pid"],
                   "pointer_bits": 32 if case["abi"] == "i386" else 64, "file_bytes": 16777216 if case["task"] == "file" else 0,
                   "actual_udp_echoes": 64 if case["task"] == "network" else 0} or usage["pid"] != receipt["pid"]:
        raise ValueError("Actual task result or measured PID differs")
    if case["task"] == "file":
        data = (directory / "workspace/roundtrip.bin").read_bytes()
        expected = bytes((offset * 37 + 11) % 251 for offset in range(65536)) * 256
        if data != expected:
            raise ValueError("Archived actual owned-file bytes differ")
    if case["condition"] != "baseline":
        if metadata["collection_quality_status"] != "accepted" or metadata["ebpf_status"] != "active" or metadata["packet_capture_status"] != "active" or metadata["target_exec"]["match"] != "exact" or metadata["target_exec"]["status"] != "observed":
            raise ValueError("Original sensors, quality or exact target exec failed")
        for key in ("ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel"):
            if metadata[key] != 0:
                raise ValueError("Positive sensor loss or packet-counter discrepancy")
    if case["condition"] == "full":
        rows = [json.loads(line) for line in (directory / "attribution.jsonl").read_text().splitlines()]
        identity.audit_records(rows)
        identity.exec_identity.validate_receipts(json.loads((directory / "exec-identity.json").read_text()), receipt["pid"],
                                                manifest["files"][case["binary"]], rows)
        recorder = json.loads((directory / "recorder-usage.json").read_text())
        if recorder["returncode"] != 0 or not metadata["attribution"]["temporary_cgroup_removed"]:
            raise ValueError("Recorder failure or cgroup cleanup missing")
    else:
        recorder = None
        if not metadata["benchmark_cgroup"]["temporary_cgroup_removed"]:
            raise ValueError("Original/baseline cgroup cleanup missing")
    return {**case, "usage": usage, "recorder_usage": recorder, "run_directory": str(directory)}


def guest(root):
    manifest = json.loads((root / "manifest.json").read_text())
    contract = json.loads((root / "contract.json").read_text())
    report = {"status": "failed_preserved", "collection_ready": False, "malware_executions": 0, "measurements": []}
    try:
        for name, expected in manifest["files"].items():
            if identity.digest(root / name) != expected:
                raise ValueError("Frozen benchmark payload changed")
        for case in manifest["cases"]:
            config = {field: str(root / name) for field, name in (("sensor", "attribution-v6"), ("object", "lifecycle.bpf.o"))}
            config.update({field + "_sha256": identity.digest(path) for field, path in list(config.items())})
            config.update(guest_btf_sha256=manifest["guest_btf_sha256"], performance_condition=case["condition"])
            config_path = root / (case["mode"] + "-config.json")
            identity.save(config_path, config)
            for name in (".pcap-auth", ".ebpf-auth"):
                (root / name).write_bytes((root / ".sudo-password").read_bytes())
                (root / name).chmod(0o600)
            identity.save(root / (case["mode"] + "-args.json"), [case["task"]])
            command = runner_command(root, case)
            if case["condition"] == "baseline":
                index = command.index("--iface")
                del command[index:index + 2]
            with (root / (case["mode"] + "-runner.log")).open("x") as log:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    env={**os.environ, "HAZIM_ATTRIBUTION_CONFIG": str(config_path), "HAZIM_PERFORMANCE_CONDITION": case["condition"]}, start_new_session=True)
                try:
                    if process.wait(timeout=80) != 0:
                        raise ValueError("Benchmark runner failed: " + case["mode"])
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=15)
            directories = list((root / ("output-" + case["mode"])).iterdir())
            if len(directories) != 1:
                raise ValueError("Unexpected benchmark run count")
            row = audit_run(directories[0], manifest, case)
            report["measurements"].append(row)
            print("PASS", case["mode"], case["abi"], case["task"], case["condition"], "warmup" if case["warmup"] else "scored", row["usage"]["wall_ns"], flush=True)
            if not case["warmup"]:
                pair = [item for item in report["measurements"] if all(item[key] == case[key] for key in ("abi", "task", "repeat")) and item["condition"] in ("original", "full")]
                if len(pair) == 2:
                    original = next(item for item in pair if item["condition"] == "original")
                    full = next(item for item in pair if item["condition"] == "full")
                    ratio = full["usage"]["wall_ns"] / original["usage"]["wall_ns"]
                    if ratio > contract["performance_limits"]["full_vs_original_task_wall_any_pair_ratio_max"]:
                        report.update(status="performance_budget_failed_preserved", first_failing_wall_pair_ratio=ratio,
                                      stop_rule="Prospectively stop on first scored pair exceeding approved1.25 any-pair limit; no retries or post-result budget changes")
                        raise ValueError("Approved per-pair performance limit exceeded: " + str(ratio))
        report.update(performance.summarize(report["measurements"], contract["performance_limits"]))
    except BaseException as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        for name in (".pcap-auth", ".ebpf-auth", ".sudo-password"):
            (root / name).unlink(missing_ok=True)
        identity.save(root / "guest_result.json", report)
        with tarfile.open(root / "evidence.tgz", "x:gz") as archive:
            for path in sorted(root.rglob("*")):
                relative = path.relative_to(root)
                if path.is_file() and (path.name == "guest_result.json" or path.name.endswith("-runner.log") or relative.parts[0].startswith("output-")):
                    if path.is_symlink():
                        raise ValueError("Benchmark evidence symlink")
                    archive.add(path, arcname=str(relative), recursive=False)
    return report["status"] == "accepted_bounded_performance"


DRIVER = None if "--guest" in sys.argv else load_driver()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--freeze-only", action="store_true")
    group.add_argument("--execute-benign-checks", action="store_true")
    group.add_argument("--guest", type=Path)
    options = parser.parse_args()
    if options.guest:
        raise SystemExit(0 if guest(options.guest.resolve()) else 2)
    else:
        attempt, manifest = DRIVER["freeze"]()
        if options.execute_benign_checks:
            signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
            DRIVER["execute"](attempt, manifest)