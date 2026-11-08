#!/usr/bin/env python3
"""Overnight LID-DS batch: process a downloaded Proton bundle, evaluate all scenarios together with the
already processed ones, write the report, record the bundle's hash and delete it (user's storage rule).

Scenario archives stored uncompressed are read in place; compressed ones are extracted one at a time,
processed and deleted. Scenarios already processed are skipped.

    python3 -I run_lidds_overnight.py DOWNLOADED_ZIP
"""
import hashlib, json, resource, shutil, subprocess, sys, time, zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = Path("/home/ali/Desktop/Hazim/external-datasets/lidds2021")
DONE = [HERE / "runs/20261105T213222Z/prepared"]
PY = ["/usr/bin/python3", "-I"]
JOBS = "8"                 # leaves the CPUs the other session's VM collection needs
WORKER_MEMORY = 12 << 30   # per extraction process; a runaway trace raises MemoryError (recorded, not fatal)


def capped():
    resource.setrlimit(resource.RLIMIT_AS, (WORKER_MEMORY, WORKER_MEMORY))


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 24), b""):
            h.update(block)
    return h.hexdigest()


def main():
    source = Path(sys.argv[1])
    DATA.mkdir(exist_ok=True)
    bundle = DATA / "proton-batch2.zip"
    shutil.move(str(source), bundle)
    run = HERE / "runs" / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-batch2")
    run.mkdir(parents=True)
    done = set()
    for d in DONE:
        done |= {r["scenario"] for r in json.load(open(d / "recordings.json"))}
    members = zipfile.ZipFile(bundle).infolist()
    new = [m for m in members if m.filename not in done]
    log("bundle %s: %d members, new %s" % (bundle, len(members), [m.filename for m in new]))
    digest = sha256(bundle)
    prepared = []
    if all(m.compress_type == zipfile.ZIP_STORED for m in new):
        out = run / "prepared"
        subprocess.run(PY + [str(HERE / "prepare_lidds.py"), str(bundle), str(out), "--jobs", JOBS,
                             "--skip", *sorted(done)], check=True, preexec_fn=capped)
        prepared.append(out)
    else:
        outer = zipfile.ZipFile(bundle)
        for m in new:
            target = DATA / m.filename
            log("extracting compressed %s" % m.filename)
            with outer.open(m) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 24)
            out = run / ("prepared-" + m.filename[:-4])
            subprocess.run(PY + [str(HERE / "prepare_lidds.py"), str(target), str(out), "--jobs", JOBS], check=True, preexec_fn=capped)
            target.unlink()
            prepared.append(out)
    log("prepared: %s" % [str(p) for p in prepared])
    subprocess.run(PY + [str(HERE / "evaluate_lidds.py"), *map(str, DONE + prepared), "--out", str(run)], check=True)
    evaluation = sorted(run.glob("evaluation-*"))[-1]
    subprocess.run(PY + [str(HERE / "report_lidds.py"), str(evaluation), *map(str, DONE + prepared)], check=True)
    (run / "deleted_raw_files.json").write_text(json.dumps(
        {"bundle": bundle.name, "sha256": digest, "bytes": bundle.stat().st_size,
         "members": [[m.filename, m.file_size, m.compress_type] for m in members]}, indent=1))
    bundle.unlink()
    log("done; bundle deleted; report %s" % (evaluation / "REPORT.md"))


if __name__ == "__main__":
    main()
