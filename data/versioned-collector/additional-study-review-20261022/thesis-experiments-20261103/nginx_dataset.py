"""Recollect every dataset execution against the current Sink (E6: the nginx-served dataset).

    /usr/bin/python3 nginx_dataset.py build
    /usr/bin/python3 nginx_dataset.py run <attempt> --approval "<verbatim>"

Stages the same 240 samples and arguments that produced the released dataset (resolved from their original
collections), with no background workload, and runs them once. Whatever server is answering on the Sink at
run time is what the runs see, so the Sink is set to nginx (web) + INetSim (other services) + dnsmasq before
running. Reuses the VM machinery of collect_v21/collect_v19 and the run resolution of vm_batches.
"""
import argparse
import fcntl
import hashlib
import glob
import json
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vm-batches-20261031"))
import collect_v21 as v21        # noqa: E402
import collect_v19 as frozen     # noqa: E402
import vm_batches as vb          # noqa: E402  (run_dir, sha256, _IP, DATASET, POOL)

save, stamp, require = frozen.save, frozen.stamp, frozen.require
import csv


def build():
    v21.verify_production()
    rows = list(csv.DictReader(open(vb.DATASET)))
    pool = json.loads(vb.POOL.read_text())
    require(len(rows) == len(pool) == 240, "dataset/pool size")
    run_id = stamp()
    attempt = HERE / "nginx-dataset" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/nginx-ds-" + run_id
    payload = attempt / "payload"
    (payload / "samples").mkdir(parents=True)
    (payload / "arguments").mkdir()
    cases, fixtures = [], set()
    for row, entry in zip(rows, pool):
        root, name, original = vb.run_dir(entry["sample"])
        old_root = json.loads((root / "protocol.json").read_text())["guest_root"]
        src = root / "payload" / "samples" / name
        argv = json.loads((root / "payload" / "arguments" / (name + ".json")).read_text())
        new_argv = [a.replace(old_root, guest_root) for a in argv]
        for a in argv:
            if old_root + "/fixtures/" in a:
                fixtures.add((root, a[a.index(old_root) + len(old_root) + 1:].split("'")[0].split('"')[0]))
        for a in new_argv:
            for ip in vb._IP.findall(a):
                require(ip == vb.SINK or ip.startswith("10.0."), "non-lab address in " + name)
        shutil.copyfile(src, payload / "samples" / name)
        (payload / "arguments" / (name + ".json")).write_text(json.dumps(new_argv))
        cases.append({"sample": name, "label": row["label"], "category": row["category"],
                      "execution_id": row["execution_id"], "split": row["split"], "cv_group": row["cv_group"],
                      "mode": row["mode"], "sample_sha256": vb.sha256(src), "original_run": str(original.relative_to(ROOT))})
    for root, rel in sorted(fixtures):
        src = root / "payload" / rel
        require(src.exists(), "missing fixture " + str(src))
        dst = payload / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, symlinks=False, dirs_exist_ok=True)
        else:
            shutil.copyfile(src, dst)
    data = v21.make_tgz(payload)
    (attempt / "payload.tgz").write_bytes(data)
    setup = v21.build_setup(guest_root, data)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    # dataset order == pool order == row order; keep it
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in cases))
    save(attempt / "protocol.json", {"format": "nginx-dataset-v1", "kind": "nginx_dataset", "schema": v21.SCHEMA,
         "guest_root": guest_root, "new_snapshot": "clean-nginx-ds-" + run_id, "baseline": v21.BASELINE,
         "baseline_uuid": v21.BASELINE_UUID, "original_uuid": v21.ORIGINAL_UUID, "settings": v21.SETTINGS,
         "payload_sha256": hashlib.sha256(data).hexdigest(), "driver_sha256": vb.sha256(__file__),
         "cases": cases, "approval": None})
    print(json.dumps({"attempt": str(attempt), "cases": len(cases), "payload_mb": round(len(data) / 1e6, 1)}))


def run(attempt, approval):
    require(approval and approval.strip(), "verbatim approval required")
    attempt = Path(attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(vb.sha256(attempt / "payload.tgz") == protocol["payload_sha256"], "payload changed since build")
    v21.verify_production()
    destination = attempt / "run"
    destination.mkdir()
    save(destination / "authorization.json", {"approval": approval, "authorized_utc": datetime.now(timezone.utc).isoformat()})
    module = frozen.helper()
    snapshot = protocol["new_snapshot"]

    def interrupted(_s, _f):
        raise KeyboardInterrupt("stop + restore original")
    previous = signal.signal(signal.SIGTERM, interrupted)
    touched = False
    try:
        with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            save(destination / "initial_vm_state.json", v21.preflight(module, protocol))
            require(not v21.snapshot_present(module, snapshot), "child snapshot already exists")
            touched = True
            frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / "dry-run",
                                                attempt / "cases.txt", dry_run=True), destination / "dry-run.log", 1800)
            validated = v21.validate_dry_run(destination / "dry-run.log", protocol)
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / "runs", attempt / "cases.txt"),
                              destination / "collection.log", 8 * 3600)
            reached = "Batch complete" in (destination / "collection.log").read_text()
            save(destination / "result.json", {"status": "passed", "dry_run_validated": validated, "reached_batch_complete": reached})
            print(json.dumps({"attempt": str(attempt), "dry_run_validated": validated, "reached_batch_complete": reached}))
    except BaseException as error:
        save(destination / "result.json", {"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error)})
        raise
    finally:
        try:
            if touched:
                frozen.restore(module, destination)
        finally:
            signal.signal(signal.SIGTERM, previous)


def continue_run(attempt, approval):
    """Run the cases with no retrieved run.json, from the same payload and child snapshot, into
    runs-continuation/ (for recovery after a host crash). No sample is rerun that already completed."""
    require(approval and approval.strip(), "verbatim approval required")
    attempt = Path(attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(vb.sha256(attempt / "payload.tgz") == protocol["payload_sha256"], "payload changed since build")
    require(not (attempt / "run" / "result.json").exists(), "attempt finished; nothing to continue")
    missing = [c for c in protocol["cases"] if not glob.glob(str(attempt / "runs" / c["sample"] / "output" / "run_*" / "run.json"))]
    require(missing, "no missing cases")
    v21.verify_production()
    index = 1
    while (attempt / ("run-continuation" if index == 1 else "run-continuation-%d" % index)).exists():
        index += 1
    suffix = "" if index == 1 else "-%d" % index
    destination = attempt / ("run-continuation" + suffix)
    destination.mkdir()
    (attempt / "cases-continuation.txt").write_text("".join(c["sample"] + "\n" for c in missing))
    save(destination / "authorization.json", {"approval": approval, "authorized_utc": datetime.now(timezone.utc).isoformat(),
                                              "cases": len(missing)})
    module = frozen.helper()
    snapshot = protocol["new_snapshot"]

    def interrupted(_s, _f):
        raise KeyboardInterrupt("stop + restore original")
    previous = signal.signal(signal.SIGTERM, interrupted)
    touched = False
    try:
        with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            save(destination / "initial_vm_state.json", v21.preflight(module, protocol))
            require(v21.snapshot_present(module, snapshot), "child snapshot missing")
            touched = True
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / ("dry-run-continuation" + suffix),
                                                attempt / "cases-continuation.txt", dry_run=True), destination / "dry-run.log", 1800)
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / "runs-continuation",
                                                attempt / "cases-continuation.txt"), destination / "collection.log", 8 * 3600)
            reached = "Batch complete" in (destination / "collection.log").read_text()
            save(destination / "result.json", {"status": "passed", "reached_batch_complete": reached, "continued": len(missing)})
            print(json.dumps({"attempt": str(attempt), "continued": len(missing), "reached_batch_complete": reached}))
    except BaseException as error:
        save(destination / "result.json", {"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error)})
        raise
    finally:
        try:
            if touched:
                frozen.restore(module, destination)
        finally:
            signal.signal(signal.SIGTERM, previous)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("build")
    for name in ("run", "continue"):
        r = sub.add_parser(name)
        r.add_argument("attempt")
        r.add_argument("--approval", required=True)
    a = ap.parse_args()
    if a.command == "build":
        build()
    elif a.command == "run":
        run(a.attempt, a.approval)
    else:
        continue_run(a.attempt, a.approval)


if __name__ == "__main__":
    main()
