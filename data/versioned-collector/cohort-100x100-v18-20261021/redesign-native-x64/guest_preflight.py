#!/usr/bin/env python3
"""Run only the hash-allowlisted benign workload profiles in the isolated guest."""

from __future__ import annotations

import bz2
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2)


def check_outputs(case, work, stdout):
    errors = []
    for pattern in case["output_globs"]:
        if not any(path.is_file() and path.stat().st_size for path in work.glob(pattern)):
            errors.append("missing_output:" + pattern)
    if case["require_stdout"] and not stdout.stat().st_size:
        errors.append("missing_stdout")
    program = case["program"]
    if program in {"cp", "rcp", "rsync"}:
        name = {"cp": "copied.txt", "rcp": "rcp-copy.txt", "rsync": "rsync-copy.txt"}[program]
        source = Path(case["arguments"][0 if program != "rsync" else 1])
        if not (work / name).is_file() or digest(work / name) != digest(source):
            errors.append("copy_content_mismatch")
    if program == "jq" and stdout.read_text().strip() != "3":
        errors.append("jq_result_mismatch")
    if program == "whois" and "Domain Name: EXAMPLE.INVALID" not in stdout.read_text():
        errors.append("whois_result_mismatch")
    if program == "patch" and (not (work / "patched.txt").is_file() or (work / "patched.txt").read_bytes() != b"alpha\nBETA\ngamma\n"):
        errors.append("patch_content_mismatch")
    if program in {"unzip", "unzipsfx"}:
        extracted = work / ("unzipped" if program == "unzip" else "unzipped-sfx") / "input.txt"
        source = Path(case["guest_sample"]).parents[1] / "workspace" / "input.txt"
        if not extracted.is_file() or digest(extracted) != digest(source):
            errors.append("unzip_content_mismatch")
    if program == "bzip2recover":
        shared = Path(case["arguments"][0]).parent
        recovered = sorted(shared.glob("rec*payload.bz2"))
        if not recovered or b"".join(bz2.decompress(path.read_bytes()) for path in recovered) != (shared / "input.txt").read_bytes():
            errors.append("bzip2_recovered_content_mismatch")
    return errors


def main():
    root = Path(sys.argv[1]).resolve()
    config = json.loads((root / "workloads.json").read_text())
    if str(root) != config["guest_root"] or len(config["cases"]) != 100:
        raise ValueError("unexpected guest root or benign allowlist size")
    seed = root / "workspace-seed"
    for name, expected in config["fixtures_sha256"].items():
        if digest(root / name) != expected:
            raise ValueError("fixture hash mismatch: " + name)
    outputs = root / "preflight"
    outputs.mkdir(exist_ok=True)
    network_ready = False
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        route = subprocess.run(["/usr/sbin/ip", "-j", "route", "get", "10.0.0.1"], capture_output=True, text=True)
        if route.returncode == 0 and any(row.get("dev") == "enp0s3" for row in json.loads(route.stdout)):
            try:
                with socket.create_connection(("10.0.0.1", 80), timeout=1):
                    network_ready = True
                    break
            except OSError:
                pass
        threading.Event().wait(0.2)
    if not network_ready:
        (root / "guest_preflight.json").write_text(json.dumps({"status": "network_not_ready", "accepted": 0, "cases": []}))
        raise RuntimeError("internal Sink route/service not ready")
    for port in (65014, 65015):
        deadline = time.monotonic() + 30
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("common loopback fixture not ready")
                threading.Event().wait(0.2)
    diagnostics = {"nsswitch": Path("/etc/nsswitch.conf").read_text(), "nss_calls": []}
    for database in ("protocols", "services", "passwd"):
        for policy in ("default", "files"):
            command = [str(root / "nss-diagnostic"), database] + (["files"] if policy == "files" else [])
            check = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3)
            diagnostics["nss_calls"].append({"database": database, "policy": policy, "returncode": check.returncode,
                                             "stdout": check.stdout, "stderr": check.stderr})
    sudo_check = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/true"], capture_output=True, text=True)
    diagnostics["sudo_noninteractive_available"] = sudo_check.returncode == 0
    results = []
    for case in config["cases"]:
        target = Path(case["guest_sample"])
        if target.parent != root / "samples" or target.name != case["program"] or digest(target) != case["staged_sha256"]:
            raise ValueError("refusing non-allowlisted benign target")
        shared = root / "workspace"
        shutil.rmtree(shared, ignore_errors=True)
        shutil.copytree(seed, shared)
        case_dir = outputs / case["program"]
        if case_dir.exists():
            raise ValueError("refusing to overwrite guest preflight: " + case["program"])
        case_dir.mkdir()
        result = {"program": case["program"], "sha256": digest(target), "errors": [], "exec_started": False}
        if case["mode"] == "dynamic":
            loader = subprocess.run(["/lib64/ld-linux-x86-64.so.2", "--list", str(target)], capture_output=True, text=True)
            result["loader_returncode"] = loader.returncode
            (case_dir / "loader.txt").write_text(loader.stdout + loader.stderr)
            if loader.returncode:
                result["errors"].append("guest_loader_failed")
        stdout_path = case_dir / "stdout.log"
        fixture_events = root / "fixture-service-events.jsonl"
        prior_events = fixture_events.read_text().splitlines() if fixture_events.exists() else []
        started = time.monotonic()
        with stdout_path.open("wb") as stdout, (case_dir / "stderr.log").open("wb") as stderr:
            try:
                process = subprocess.Popen([str(target), *case["arguments"]], cwd=case_dir,
                                           stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                           start_new_session=True, env={**os.environ, "TERM": "dumb", "GIT_CONFIG_NOSYSTEM": "1"})
                result["exec_started"] = True
                try:
                    if case["foreground_service"]:
                        port = 65012 if case["program"] == "inetd" else 65013
                        deadline = time.monotonic() + 3
                        listening = False
                        while process.poll() is None and time.monotonic() < deadline:
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                                    listening = True
                                    break
                            except OSError:
                                threading.Event().wait(0.05)
                        result["listening_on_loopback"] = listening
                        if not listening:
                            result["errors"].append("foreground_service_not_listening")
                        stop(process)
                    else:
                        process.wait(timeout=case["preflight_timeout_seconds"])
                except subprocess.TimeoutExpired:
                    result["errors"].append("workload_timeout")
                    stop(process)
                finally:
                    stop(process)
                result["returncode"] = process.returncode
                if not case["foreground_service"] and process.returncode not in case["expected_returncodes"]:
                    result["errors"].append("unexpected_returncode")
            except OSError as error:
                result["errors"].append("exec_failed:" + type(error).__name__ + ":" + str(error.errno))
        result["duration_seconds"] = time.monotonic() - started
        if case["program"] in {"ftp", "whois"}:
            deadline = time.monotonic() + 2
            connected = False
            while time.monotonic() < deadline:
                events = fixture_events.read_text().splitlines()[len(prior_events):] if fixture_events.exists() else []
                connected = any(json.loads(line)["protocol"] == case["program"] for line in events)
                if connected:
                    break
                threading.Event().wait(0.05)
            result["fixture_connection_observed"] = connected
            if not connected:
                result["errors"].append("fixture_connection_missing")
        result["errors"].extend(check_outputs(case, case_dir, stdout_path))
        result["status"] = "accepted" if not result["errors"] else "rejected"
        result["stderr_tail"] = (case_dir / "stderr.log").read_text(errors="replace")[-1000:]
        results.append(result)
        (root / "guest_preflight.json").write_text(json.dumps({
            "status": "incomplete", "benign_only": True, "cases": results,
            "accepted": sum(row["status"] == "accepted" for row in results)}, indent=2) + "\n")
    shutil.rmtree(root / "workspace", ignore_errors=True)
    shutil.copytree(seed, root / "workspace")
    report = {"status": "accepted" if all(row["status"] == "accepted" for row in results) else "rejected",
              "benign_only": True, "sensor_activation_measured": False, "cases": results,
              "accepted": sum(row["status"] == "accepted" for row in results), "diagnostics": diagnostics}
    (root / "guest_preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "accepted": report["accepted"], "total": len(results),
                      "rejected": [{"program": row["program"], "errors": row["errors"], "returncode": row.get("returncode"), "stderr": row["stderr_tail"]}
                                   for row in results if row["errors"]]}, indent=2))


if __name__ == "__main__":
    main()