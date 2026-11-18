"""Command phase of the Sliver testbed run, measured around each tasking (offline).

autotask.py logs a tasking when the Sliver client call returns: a session has already run the tasks by then, a
beacon runs them at its next check-in (every 5 s). So host calls and packets are compared in the windows from
10 s before to 5 s after each logged tasking against the implant's other windows. The first 20 s (start-up of the
implant) are left out of both.

    /usr/bin/python3 command_phase.py ATTEMPT
"""
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sinkhole-c2-5min"))
import analyze_sinkhole_c2 as A  # noqa: E402  frozen; loader only

BEFORE, AFTER, SKIP_S = 10.0, 5.0, 20.0


def main():
    attempt = Path(sys.argv[1]).resolve()
    host, net = A.tc.signals()
    _, rows = A.load_runs(attempt, host, net)
    log = [json.loads(l) for l in open(attempt / "autotask.jsonl") if l.strip()]
    hi, ni = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    per, pooled = {}, {"host_around": [], "host_other": [], "net_around": [], "net_other": []}
    for r in rows:
        if r["label"] != "malware":
            continue
        name = r["case"]["sample"].removesuffix(".zip")
        t0, t1 = r["start"].timestamp(), r["end"].timestamp()
        ev = [e for e in log if e.get("name") == name and t0 <= e.get("t", 0) < t1]
        around = set()
        for e in ev:
            lo = max(0, int((e["t"] - BEFORE - t0) / 0.5))
            hi_w = min(600, int((e["t"] + AFTER - t0) / 0.5) + 1)
            around.update(range(lo, hi_w))
        keep = set(range(int(SKIP_S / 0.5), 600))
        other = sorted(keep - around)
        a = sorted(around & keep)
        H, N = r["H"][:, hi], r["N"][:, ni]
        per[name] = {"kind": r["case"]["family"], "taskings": len(ev),
                     "windows_around": len(a), "windows_other": len(other),
                     "host_calls_per_window_around": round(float(H[a].mean()), 1) if a else None,
                     "host_calls_per_window_other": round(float(H[other].mean()), 1) if other else None,
                     "packets_per_window_around": round(float(N[a].mean()), 2) if a else None,
                     "packets_per_window_other": round(float(N[other].mean()), 2) if other else None}
        if a and other:
            pooled["host_around"].extend(H[a]); pooled["host_other"].extend(H[other])
            pooled["net_around"].extend(N[a]); pooled["net_other"].extend(N[other])
    res = {"attempt": str(attempt), "window_s": [-BEFORE, AFTER], "startup_left_out_s": SKIP_S, "per_implant": per,
           "pooled_mean_per_window": {k: round(float(np.mean(v)), 2) for k, v in pooled.items() if v}}
    (attempt / "analysis" / "command_phase_around.json").write_text(json.dumps(res, indent=1))
    print(json.dumps(res["pooled_mean_per_window"]))
    for k, v in per.items():
        print(k, v["taskings"], v["host_calls_per_window_around"], v["host_calls_per_window_other"],
              v["packets_per_window_around"], v["packets_per_window_other"])


if __name__ == "__main__":
    main()
