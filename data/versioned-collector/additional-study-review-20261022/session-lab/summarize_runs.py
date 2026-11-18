#!/usr/bin/env python3
"""Technical summary of session-lab attempts (offline): sessions run, accepted / rejected / failed and why,
Sink capture counters, clock drift, monitor health, flow attribution, per kind; and the session phases' results.

  /usr/bin/python3 summarize_runs.py <attempt> [<attempt> ...] [--json out.json]
"""
import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab  # noqa: E402


def status_of(sdir):
    if (sdir / "checks-recheck.json").is_file():
        return "accepted" if lab.load(sdir / "checks-recheck.json")["recheck"]["accepted"] else "rejected"
    if (sdir / "failure.json").is_file():
        return "failed"
    if not (sdir / "result.json").is_file():
        return "missing"
    return lab.load(sdir / "result.json").get("status", "failed")


def summarize(attempt):
    protocol = lab.load(attempt / "protocol.json")
    reports = {}
    if (attempt / "analysis.json").is_file():
        reports = {r["sid"]: r for r in lab.load(attempt / "analysis.json")["sessions"]}
    out = {"attempt": attempt.name, "plan": protocol.get("plan"), "planned": len(protocol["sessions"]),
           "by_status": Counter(), "by_kind_status": defaultdict(Counter), "reasons": [], "packets": [],
           "drift_ms": [], "jitter_ms": [], "flows": Counter(), "minutes": []}
    for s in protocol["sessions"]:
        sdir = attempt / "sessions" / s["sid"]
        if not sdir.is_dir():
            continue
        st = status_of(sdir)
        out["by_status"][st] += 1
        out["by_kind_status"][s["kind"]][st] += 1
        rec = lab.load(sdir / "result.json") if (sdir / "result.json").is_file() else {}
        if st != "accepted":
            why = rec.get("checks", {}).get("reasons") or [lab.load(sdir / "failure.json")["error"]] \
                if (sdir / "failure.json").is_file() or rec.get("checks") else ["?"]
            out["reasons"].append((s["sid"], s["kind"], s["name"], st, why))
        c = rec.get("capture", {}).get("counters", {})
        if c:
            out["packets"].append(c.get("received", 0))
        if rec.get("started_utc") and rec.get("finished_utc"):
            from datetime import datetime
            a, b = datetime.fromisoformat(rec["started_utc"]), datetime.fromisoformat(rec["finished_utc"])
            out["minutes"].append((b - a).total_seconds() / 60)
        r = reports.get(s["sid"], {})
        if r.get("clocks", {}).get("drift_ms") is not None:
            out["drift_ms"].append(r["clocks"]["drift_ms"])
            out["jitter_ms"].append(max(r["clocks"].get("jitter_start_ms", 0), r["clocks"].get("jitter_end_ms", 0)))
        for k, v in (r.get("flows") or {}).items():
            out["flows"][k] += v
    phases = {}
    for d in sorted((attempt / "phases").glob("*")):
        res = sorted(d.glob("result*.json"))
        phases[d.name] = [lab.load(x).get("status") for x in res]
    out["phases"] = phases
    for k in ("packets", "drift_ms", "jitter_ms", "minutes"):
        v = out[k]
        out[k] = {"n": len(v), "min": min(v), "median": statistics.median(v), "max": max(v)} if v else None
    out["by_status"] = dict(out["by_status"])
    out["by_kind_status"] = {k: dict(v) for k, v in out["by_kind_status"].items()}
    out["flows"] = dict(out["flows"])
    total = sum(out["flows"].values())
    out["flows_attributed_share"] = round(1 - out["flows"].get("nobody", 0) / total, 4) if total else None
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("attempts", nargs="+")
    p.add_argument("--json")
    a = p.parse_args()
    res = [summarize(Path(x).resolve()) for x in a.attempts]
    for r in res:
        print("== %s (%s): %d of %d planned sessions run; %s" % (r["attempt"], r["plan"], sum(r["by_status"].values()),
                                                                 r["planned"], r["by_status"]))
        print("   by kind:", r["by_kind_status"])
        print("   phases:", r["phases"])
        print("   minutes per session:", r["minutes"], " Sink packets:", r["packets"])
        print("   clock drift ms:", r["drift_ms"], " probe jitter ms:", r["jitter_ms"])
        print("   guest flows by owner:", r["flows"], " attributed share:", r["flows_attributed_share"])
        for x in r["reasons"]:
            print("   not accepted:", x)
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=1, default=str))


if __name__ == "__main__":
    main()
