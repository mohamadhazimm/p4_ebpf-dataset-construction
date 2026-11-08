"""Build and run the two VM batches of PROTOCOL.md through the paper's collector.

    python3 vm_batches.py build python|background      # no VM: freeze payload, setup, case list, protocol
    python3 vm_batches.py run <attempt> --approval "<verbatim>"   # stage, dry run, collect, restore

Reuses the tested primitives of collect_v21 (production pins, quiet baseline, stage and batch commands)
and collect_v19 (VM helper, logged phases, restore of the original snapshot). Each run boots the staged
child snapshot fresh; the batch restores it around every case. No retries, no replacements.

python:     16 benign Python workloads, launched like Slowloris/GoldenEye (flood_gen pyexec).
background: the 54 Table IV test executions and the 36 attack-batch executions, rerun from their original
            sample files and arguments while a benign background workload (started at boot by the guest
            user's @reboot crontab entry) sends marked traffic to the Sink.
"""
import argparse
import csv
import fcntl
import glob
import hashlib
import json
import random
import re
import shutil
import signal
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21        # noqa: E402
import collect_v19 as frozen     # noqa: E402

save, stamp, require = frozen.save, frozen.stamp, frozen.require
DATASET = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
POOL = ROOT / "paper-check-20261028/independent_pool.json"
FLOOD_GEN = ROOT / "flood_gen"
FLOOD_GEN_SHA = "1bc8630d60d7330b7089879cb2a684d2bbc59b8f47e980c1b7ff92155fefdd6d"
WORKLOADS = HERE / "python_workloads"
BG_SCRIPT = HERE / "background" / "bg_workload.py"
SINK = "10.0.0.1"
ORDER_SEED = 20261031
RUN_ROOTS = [ROOT / "revision5-collection/20261025T100025568989Z", ROOT / "realtools-collect/20261026T165642798242Z",
             ROOT / "flood21-collect/20261026T154421063760Z", ROOT / "flood21-collect/20261026T150016786262Z",
             ROOT / "flood21-collect/20261026T151240756153Z"]
NETWORK_WORKLOADS = ["py_http_poll", "py_http_threadpool", "py_http_multiproc", "py_http_keepalive",
                     "py_http_upload", "py_http_longpoll", "py_dns_resolver", "py_http_crawl"]
LOCAL_WORKLOADS = ["py_json_transform", "py_gzip_roundtrip", "py_sqlite_load", "py_hash_tree",
                   "py_csv_stats", "py_multiproc_compute", "py_thread_fileio", "py_subprocess_pipeline"]
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_payload_tgz(attempt, guest_root, extra_setup=""):
    data = v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(data)
    setup = v21.build_setup(guest_root, data) + extra_setup
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    return data


# ---------------------------------------------------------------- batch P: benign Python workloads

def build_python(attempt, guest_root):
    require(sha256(FLOOD_GEN) == FLOOD_GEN_SHA, "flood_gen changed")
    payload = attempt / "payload"
    (payload / "samples").mkdir(parents=True)
    (payload / "arguments").mkdir()
    gen = FLOOD_GEN.read_bytes()
    cases = []
    for name in NETWORK_WORKLOADS + LOCAL_WORKLOADS:
        script = WORKLOADS / (name + ".py")
        network = name in NETWORK_WORKLOADS
        argv = ["pyexec", script.name] + ([SINK] if network else [])
        with zipfile.ZipFile(payload / "samples" / (name + ".zip"), "w") as z:
            z.writestr("flood_gen", gen)
            z.writestr(script.name, script.read_bytes())
        (payload / "arguments" / (name + ".zip.json")).write_text(json.dumps(argv))
        cases.append({"sample": name + ".zip", "label": "benign", "category": "python_benign",
                      "network": network, "argv": argv, "script_sha256": sha256(script)})
    random.Random(ORDER_SEED).shuffle(cases)
    return cases, ""


# ---------------------------------------------------------------- batch B: background workload

def run_dir(sample):
    for root in RUN_ROOTS:
        for name in (sample, sample + ".zip"):
            found = glob.glob(str(root / "runs" / name / "output" / "run_*"))
            if found:
                return root, name, Path(found[0])
    raise FileNotFoundError(sample)


def build_background(attempt, guest_root):
    rows = list(csv.DictReader(open(DATASET)))
    pool = json.loads(POOL.read_text())
    require(len(rows) == len(pool) == 240, "dataset/pool size")
    payload = attempt / "payload"
    for sub in ("samples", "arguments", "bg"):
        (payload / sub).mkdir(parents=True)
    cases, fixtures = [], set()
    for row, entry in zip(rows, pool):
        if not (row["split"] == "test" or row["category"] in ("network_attack", "network_benign", "null")):
            continue
        root, name, original_run = run_dir(entry["sample"])
        old_root = json.loads((root / "protocol.json").read_text())["guest_root"]
        src = root / "payload" / "samples" / name
        argv = json.loads((root / "payload" / "arguments" / (name + ".json")).read_text())
        new_argv = [a.replace(old_root, guest_root) for a in argv]
        for a in argv:
            if old_root + "/fixtures/" in a:
                fixtures.add((root, a[a.index(old_root) + len(old_root) + 1:].split("'")[0].split('"')[0]))
        for a in new_argv:
            for ip in _IP.findall(a):
                require(ip == SINK or ip.startswith("10.0."), "non-lab address in " + name)
        shutil.copyfile(src, payload / "samples" / name)
        (payload / "arguments" / (name + ".json")).write_text(json.dumps(new_argv))
        cases.append({"sample": name, "label": "malicious" if row["label"] == "1" else "benign",
                      "category": row["category"], "execution_id": row["execution_id"], "split": row["split"],
                      "cv_group": row["cv_group"], "mode": row["mode"], "source_attempt": root.name,
                      "original_run": str(original_run.relative_to(ROOT)), "sample_sha256": sha256(src),
                      "argv": new_argv})
    require(len(cases) == 90, "expected 90 background cases, got %d" % len(cases))
    for root, rel in sorted(fixtures):
        src = root / "payload" / rel
        require(src.exists(), "missing fixture " + str(src))
        dst = payload / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, symlinks=False, dirs_exist_ok=True)
        else:
            shutil.copyfile(src, dst)
    shutil.copyfile(BG_SCRIPT, payload / "bg" / BG_SCRIPT.name)
    random.Random(ORDER_SEED).shuffle(cases)
    bg = guest_root + "/bg/" + BG_SCRIPT.name
    log = guest_root + "/bg/bg.log"
    extra = """
systemctl is-enabled cron.service >/dev/null && systemctl is-active cron.service >/dev/null || { echo 'cron not enabled/active'; exit 1; }
tmp=$(mktemp)
crontab -l 2>/dev/null > "$tmp" || true
echo '@reboot /usr/bin/python3 %s %s >/dev/null 2>&1 # vm-batches-background' >> "$tmp"
crontab "$tmp"; rm -f "$tmp"
crontab -l | grep -q 'vm-batches-background' || { echo 'crontab entry missing'; exit 1; }
echo 'background workload installed for the next boots'
""" % (bg, log)
    return cases, extra


# ---------------------------------------------------------------- build / run

def build(kind):
    v21.verify_production()
    run_id = stamp()
    attempt = HERE / kind / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/vmb-%s-%s" % (kind, run_id)
    cases, extra = (build_python if kind == "python" else build_background)(attempt, guest_root)
    data = write_payload_tgz(attempt, guest_root, extra)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in cases))
    protocol = {"format": "vm-batches-20261031-v1", "kind": kind, "schema": v21.SCHEMA, "guest_root": guest_root,
                "new_snapshot": "clean-vmb-%s-%s" % (kind, run_id), "baseline": v21.BASELINE,
                "baseline_uuid": v21.BASELINE_UUID, "original_uuid": v21.ORIGINAL_UUID, "settings": v21.SETTINGS,
                "pins": v21.PINNED, "payload_sha256": hashlib.sha256(data).hexdigest(),
                "protocol_md_sha256": sha256(HERE / "PROTOCOL.md"), "driver_sha256": sha256(__file__),
                "order_seed": ORDER_SEED, "cases": cases, "approval": None}
    if kind == "background":
        protocol["background_script_sha256"] = sha256(BG_SCRIPT)
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "cases": len(cases), "payload_mb": round(len(data) / 1e6, 1)}))
    return attempt


def run(attempt, approval):
    require(approval and approval.strip(), "verbatim approval required")
    attempt = Path(attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(sha256(attempt / "payload.tgz") == protocol["payload_sha256"], "payload changed since build")
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
                              destination / "collection.log", 4 * 3600)
            reached = "Batch complete" in (destination / "collection.log").read_text()
            save(destination / "result.json", {"status": "passed", "dry_run_validated": validated,
                                                "reached_batch_complete": reached})
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("kind", choices=["python", "background"])
    r = sub.add_parser("run")
    r.add_argument("attempt")
    r.add_argument("--approval", required=True)
    args = parser.parse_args()
    if args.command == "build":
        build(args.kind)
    else:
        run(args.attempt, args.approval)


if __name__ == "__main__":
    main()
