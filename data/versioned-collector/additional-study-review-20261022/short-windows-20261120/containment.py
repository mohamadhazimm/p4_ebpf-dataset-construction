#!/usr/bin/env python3
"""Share of each dataset flood's traffic sent after a block, by window length and alarm delay. Offline, from the
15 attack runs' own captures (the release dataset's network_attack rows).

    /usr/bin/python3 containment.py OUT.json

Model (PC1.md parts 11E and 12: every flood alarms on its first window with traffic, at every window length; a host
block drops everything the host sends from then on):
  block time  = end of the first window that holds the attack's first frame + D, where D is the alarm delay after
                the window's end (PC1 measured a median 213 ms in 12A and about 270 ms in 11E/11F: about 107 ms for
                the window to reach the collector, about 160 ms of stacked-forest scoring, 3-5 ms for the write; with
                part 13K's overlapped loop at 0.25 s, about 300 ms for the stacked detector and 226 ms for the network
                detector);
  aligned     windows start at the run's anchor (sample start), as in the dataset replays;
  window 0    as aligned, but the block always comes D after window 0 ends (PC1.md 12B's assumption). It differs
              only at 0.1 s, for the two GoldenEye runs: their first frame comes 0.18-0.20 s after the anchor, so
              window 0 holds none of their traffic;
  any phase   live windows run on their own clock: the first window ends a uniform time in (0, W] after the
              attack's first frame (mean over 100 phases);
  blocked     frames from the host (IPv4 source 10.0.0.10) in the run's 20 s at or after the block time, over all
              its frames in the 20 s; mean over the 15 runs, and per attack type.

The first version (2026-11-20 03:59) computed "aligned" with the window-0 rule, while README.md's table used the
first window with traffic; both are now in the output.
"""
import json
import math
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "committee-eval-20261113"))
import common as C  # noqa: E402
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/features")
import switch_model as sm  # noqa: E402

HOST = bytes([10, 0, 0, 10])
WINDOWS = (0.5, 0.25, 0.1)
DELAYS = (0.0, 0.05, 0.1, 0.213, 0.226, 0.27, 0.30)


def host_times(pcap, anchor_us):
    """Seconds from the anchor of the host's IPv4 frames in the 20 s."""
    out = []
    for time_us, _ts, frame in sm.read_pcap(str(pcap)):
        rel = time_us - anchor_us
        if not 0 <= rel < 20_000_000 or len(frame) < 34:
            continue
        if ((frame[12] << 8) | frame[13]) == 0x0800 and frame[26:30] == HOST:
            out.append(rel / 1e6)
    return np.asarray(out)


def main():
    rows, _, _ = C.load()
    dirs = C.run_dirs(rows)
    runs = []
    for r, d in zip(rows, dirs):
        if r["category"] != "network_attack":
            continue
        run = C.output_dir(d)
        meta = json.load(open(run / "run.json"))
        t = host_times(run / "packet_capture.pcap", int(meta["sample_started_wall_us"]))
        runs.append({"execution_id": r["execution_id"], "attack_type": r["attack_type"], "t": t})
    rng = np.random.default_rng(20261120)
    phases = rng.uniform(0, 1, 100)
    out = {"runs": {}, "aligned": {}, "window0": {}, "any_phase": {}, "by_type_aligned": {}}
    for x in runs:
        t = x["t"]
        out["runs"][x["execution_id"]] = {"attack_type": x["attack_type"], "host_frames": int(len(t)),
                                          "first_s": float(t.min()), "last_s": float(t.max()),
                                          "median_s": float(np.median(t))}
    for W in WINDOWS:
        for D in DELAYS:
            key = "W=%.2f D=%.3f" % (W, D)
            al = [float((x["t"] >= (math.floor(x["t"].min() / W) + 1) * W + D).mean()) for x in runs]
            w0 = [float((x["t"] >= W + D).mean()) for x in runs]
            ph = [float(np.mean([(x["t"] >= x["t"].min() + (1 - p) * W + D).mean() for p in phases])) for x in runs]
            out["aligned"][key] = {"mean": float(np.mean(al)), "per_run": dict(zip([x["execution_id"] for x in runs], al))}
            out["window0"][key] = {"mean": float(np.mean(w0)), "per_run": dict(zip([x["execution_id"] for x in runs], w0))}
            out["any_phase"][key] = {"mean": float(np.mean(ph))}
            types = sorted({x["attack_type"] for x in runs})
            out["by_type_aligned"][key] = {ty: float(np.mean([a for a, x in zip(al, runs) if x["attack_type"] == ty]))
                                           for ty in types}
    json.dump(out, open(sys.argv[1], "w"), indent=1)
    print("runs:", ", ".join("%s %d frames %.2f-%.2f s" % (k, v["host_frames"], v["first_s"], v["last_s"])
                             for k, v in out["runs"].items()))
    print("\nmean share of the floods' host frames blocked (aligned windows | window 0 | any phase)")
    print("%-8s" % "D \\ W" + "".join("%22s" % ("%.2f s" % W) for W in WINDOWS))
    for D in DELAYS:
        print("%-8s" % ("%d ms" % round(D * 1000)) + "".join(
            "%22s" % ("%.0f%% | %.0f%% | %.0f%%" % (100 * out["aligned"]["W=%.2f D=%.3f" % (W, D)]["mean"],
                                                  100 * out["window0"]["W=%.2f D=%.3f" % (W, D)]["mean"],
                                                  100 * out["any_phase"]["W=%.2f D=%.3f" % (W, D)]["mean"]))
            for W in WINDOWS))
    print("\nby attack type, aligned, D = 270 ms and D = 50 ms")
    for D in (0.27, 0.05):
        for W in WINDOWS:
            print("  D %3d ms W %.2f s: " % (round(D * 1000), W) + ", ".join(
                "%s %.0f%%" % (ty, 100 * v) for ty, v in out["by_type_aligned"]["W=%.2f D=%.3f" % (W, D)].items()))


if __name__ == "__main__":
    main()
