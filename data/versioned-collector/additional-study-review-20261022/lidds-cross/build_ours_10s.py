#!/usr/bin/env python3
"""The 240 dataset rows as 10-s observations (the first 20 of the 40 windows of 0.5 s), so that they have
the same shape as the LID-DS 2021 rows (lidds-external/prepare_lidds.py: 20 windows of 0.5 s).

    /usr/bin/python3 build_ours_10s.py OUTDIR

For each of the 240 rows of the release's dataset/features.csv (run lookup and event parsing from
../switch-exact-1s/build_rows.py):
  gate    the run's raw data at 0.5 s x 40 give the published row (network: release switch_model.py on
          packet_capture.pcap; host: release host_model.py on syscall_events.csv, launch prologue included);
  10 s    the same window lists cut to the first 20 windows and summarized again (mean/max/sum/std/active);
          checked to equal a direct 20-window computation;
  hosts   as collected (launch prologue included, like the dataset) and prologue-free (without the root
          process's calls before its second exec success, 178 calls per run).
Outputs: features_10s_ascollected.csv, features_10s_prologuefree.csv (features.csv layout, metadata
columns unchanged, syscall_count left as published), build.json (gates, hashes).
"""
import csv
import glob
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "switch-exact-1s"))
import build_rows as br  # noqa: E402

hm, sm, pc, REL = br.hm, br.sm, br.pc, br.REL


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(a, b):
    return abs(a - b) / max(1.0, abs(b))


def main():
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    rows = list(csv.DictReader(open(REL / "dataset/features.csv", newline="")))
    pool = json.load(open(br.POOL))
    fields = list(rows[0])
    host_cols = [c for c in fields if c.startswith("host_")]
    net_cols = [c for c in fields if c.startswith("net_")]
    assert len(host_cols) == 90 and len(net_cols) == 145
    rep = {"gate_net_max_rel": 0.0, "gate_host_max_rel": 0.0, "cut_vs_direct_max_rel": 0.0, "prologue_calls": {}}
    variants = {"ascollected": [], "prologuefree": []}
    for i, row in enumerate(rows):
        rj = glob.glob(str(br.run_dir(i, row, pool) / "output" / "run_*" / "run.json"))
        if len(rj) != 1:
            sys.exit("row %d: expected one run.json" % i)
        run = Path(rj[0]).parent
        meta = json.load(open(rj[0]))
        anchor = int(meta["sample_started_wall_us"])
        pcap = str(run / "packet_capture.pcap")
        net40 = sm.window_features(pcap, anchor, 0.5, 40)
        events, prologue = br.host_events(run, meta)
        host40 = hm.window_features(events, windows=40)
        gn = max(rel(v, float(row[c])) for c, v in pc.five(net40, sm.FEATURES).items())
        gh = max(rel(v, float(row[c])) for c, v in pc.five(host40, hm.FEATURES).items())
        rep["gate_net_max_rel"] = max(rep["gate_net_max_rel"], gn)
        rep["gate_host_max_rel"] = max(rep["gate_host_max_rel"], gh)
        if gn > 1e-9 or gh > 1e-9:
            sys.exit("row %d (%s): raw run does not reproduce the published row (net %.2e, host %.2e)"
                     % (i, row["execution_id"], gn, gh))
        free_events = [e for e, m in zip(events, prologue) if not m]
        hosts = {"ascollected": host40[:20], "prologuefree": hm.window_features(free_events, windows=40)[:20]}
        net10 = pc.five(net40[:20], sm.FEATURES)
        # cutting 40 windows to 20 must equal computing 20 windows directly
        direct = {**pc.five(sm.window_features(pcap, anchor, 0.5, 20), sm.FEATURES),
                  **pc.five(hm.window_features(free_events, windows=20), hm.FEATURES)}
        cut = {**net10, **pc.five(hosts["prologuefree"], hm.FEATURES)}
        d = max(rel(cut[k], direct[k]) for k in direct)
        rep["cut_vs_direct_max_rel"] = max(rep["cut_vs_direct_max_rel"], d)
        if d > 1e-12:
            sys.exit("row %d: 20 of 40 windows differs from 20 windows (%.2e)" % (i, d))
        n = sum(prologue)
        rep["prologue_calls"][n] = rep["prologue_calls"].get(n, 0) + 1
        for name, hw in hosts.items():
            r = dict(row)
            r.update(net10)
            r.update(pc.five(hw, hm.FEATURES))
            variants[name].append(r)
        print("[build] %3d %-60s prologue %d" % (i, row["execution_id"], n), flush=True)
    for name, lst in variants.items():
        path = out / ("features_10s_%s.csv" % name)
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
            w.writeheader()
            for r in lst:
                w.writerow({k: (repr(v) if isinstance(v, float) else v) for k, v in r.items()})
        rep["sha256_" + path.name] = sha256(path)
    rep.update({"features_csv_sha256": sha256(REL / "dataset/features.csv"),
                "host_model_sha256": sha256(REL / "features/host_model.py"),
                "switch_model_sha256": sha256(REL / "features/switch_model.py"),
                "build_rows_sha256": sha256(HERE.parent / "switch-exact-1s/build_rows.py"),
                "builder_sha256": sha256(Path(__file__))})
    json.dump(rep, open(out / "build.json", "w"), indent=1)
    print("[build] gates: network %.1e, host %.1e; 20-of-40 vs direct %.1e; prologue calls %s"
          % (rep["gate_net_max_rel"], rep["gate_host_max_rel"], rep["cut_vs_direct_max_rel"], rep["prologue_calls"]))


if __name__ == "__main__":
    main()
