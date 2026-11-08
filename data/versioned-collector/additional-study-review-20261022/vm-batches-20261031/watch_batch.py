"""Poll a VM-batch attempt; print one line per problem run, a progress line every 10 good runs, and the end.

    python3 -u watch_batch.py <attempt> [--runs=runs] [--rundir=run] [--cases=<case list file>]
                                        [--quiet-below=N] [--no-bg-check]

A problem is a run without a retrieved run.json, a rejected capture, an unobserved target exec, or (for
background batches) no marked background traffic in the feature windows.
"""
import glob
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import assess  # noqa: E402


def option(key, default):
    return next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--%s=" % key)), default)


attempt = Path(sys.argv[1]).resolve()
runs_dir, run_dir, case_list = option("runs", "runs"), option("rundir", "run"), option("cases", "")
quiet_below = int(option("quiet-below", "0"))
protocol = json.loads((attempt / "protocol.json").read_text())
check_bg = protocol["kind"].startswith("background") and "--no-bg-check" not in sys.argv
cases = protocol["cases"]
if case_list:
    wanted = set((attempt / case_list).read_text().split())
    cases = [c for c in cases if c["sample"] in wanted]
seen, ok, problems = set(), 0, 0
while True:
    finished = (attempt / run_dir / "result.json").exists()
    for case in cases:
        sample = case["sample"]
        if sample in seen:
            continue
        host = attempt / runs_dir / sample / "host_run.txt"
        runs = glob.glob(str(attempt / runs_dir / sample / "output" / "run_*" / "run.json"))
        if not runs:
            if host.exists() and "status=" in host.read_text():
                status = next(l for l in host.read_text().splitlines() if l.startswith("status="))
            elif finished and (attempt / runs_dir / sample).exists():
                status = "no status"
            else:
                continue  # not started or still running
            seen.add(sample)
            problems += 1
            print("PROBLEM %s (%s): no run.json, %s" % (sample[:40], case["category"], status), flush=True)
            continue
        try:
            meta = json.loads(Path(runs[0]).read_text())
        except json.JSONDecodeError:
            continue  # being written
        seen.add(sample)
        issues = []
        if meta.get("collection_quality_status") != "accepted":
            issues.append("quality %s %s" % (meta.get("collection_quality_status"), meta.get("collection_quality_reasons")))
        if (meta.get("target_exec") or {}).get("status") != "observed":
            issues.append("exec %s" % (meta.get("target_exec") or {}).get("status"))
        if check_bg:
            d = Path(runs[0]).parent
            if assess.bg_requests_in_window(d / "packet_capture.pcap", int(meta["sample_started_wall_us"]), 0.5) == 0:
                issues.append("no background traffic in window")
        if issues:
            problems += 1
            print("PROBLEM %s (%s): %s" % (sample[:40], case["category"], "; ".join(issues)), flush=True)
        else:
            ok += 1
            if ok % 10 == 0 and ok > quiet_below:
                print("progress: %d of %d retrieved, %d fine, %d problems" % (len(seen), len(cases), ok, problems), flush=True)
    if finished:
        result = json.loads((attempt / run_dir / "result.json").read_text())
        print("BATCH ENDED: %s | %d of %d retrieved, %d fine, %d problems" % (json.dumps(result), len(seen), len(cases), ok, problems), flush=True)
        break
    time.sleep(20)
