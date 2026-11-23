#!/usr/bin/env python3
"""The 240 dataset rows with 0.25-s and 0.1-s windows instead of 0.5 s, rebuilt from the raw runs with the
release's own feature code (features/switch_model.py, host_model.py, summary.py), unchanged. Offline.

    /usr/bin/python3 build_short.py OUTDIR [--jobs 12]

The observation stays the same 20 s from the same anchors: 0.25 s x 80 and 0.1 s x 200 windows end where
0.5 s x 40 end. Per run (the rows of the release's dataset/features.csv, in file order):

  gate     0.5 s x 40 must give the published row:
             - the window of every saved system-call event, recomputed from its timestamp on the runner's
               grid ((timestamp_ns - sample_started_monotonic_ns) // window_ns, src/malware_runner.py),
               equals the saved window_id;
             - the rebuilt per-window values equal the run's telemetry.csv in every window
               (committee-eval-20261113/cache/windows.npz);
             - the five summaries equal the published 145 network and 90 host columns.
  build    W = 0.25 s and 0.1 s:
             network   switch_model.window_features(pcap, sample_started_wall_us, W, 20 s / W, TTL 3 windows);
                       the switch's TTL is 3 windows at any window length too (p4_ebpf exact_model.TTL);
             host      host_model.window_features on (window at W, pid, syscall) of every saved call, in the
                       saved order ("as collected", with the launch prologue, like the published rows), and
                       without the root's calls before its second exec success ("prologue-free", as in
                       launcher-ablation-05s).
  nesting  at W, every 0.5-s window is the sum of its 0.5/W windows for the additive features (packets and
           bytes in each direction, SYN, ACK, RST, host calls): same anchors, same grid.

Outputs (OUTDIR):
  features_<ms>ms_<host>.csv     features.csv layout, metadata unchanged; ms in 500, 250, 100; host in
                                 ascollected, prologuefree (500 ms as collected = the published row)
  windows_<ms>ms.npz             N (240, n, 29), H (240, n, 18), Hpf (240, n, 18) in the features.csv signal
                                 order, with the signal names and execution ids
  dataset_windows_<ms>ms_<host>.csv.gz   the per-window table in p4_ebpf live_test/streaming's format
  build.json                     gates, checks, per-run facts, hashes
"""
import argparse
import csv
import glob
import gzip
import hashlib
import io
import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np

REL = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
HERE = Path(__file__).resolve().parent
COMMITTEE = HERE.parent / "committee-eval-20261113"
sys.path.insert(0, str(REL / "features"))
import host_model as hm  # noqa: E402
import summary as su  # noqa: E402
import switch_model as sm  # noqa: E402
sys.path.insert(0, str(COMMITTEE))
import common as C  # noqa: E402

OBSERVATION_NS = 20_000_000_000
WINDOWS = {500: 40, 250: 80, 100: 200}          # window length in ms -> windows in the 20 s
ADDITIVE_NET = ("net_pkts_total_delta", "net_bytes_total_delta", "net_pkts_ab_delta", "net_bytes_ab_delta",
                "net_pkts_ba_delta", "net_bytes_ba_delta", "net_syn_delta", "net_ack_delta", "net_rst_delta")
ADDITIVE_HOST = ("host_total_syscalls_total",)
GATE_REL = 1e-9

ROWS, HOST_COLS, NET_COLS = C.load()
HOST_SIGNALS, NET_SIGNALS = C.signals(HOST_COLS), C.signals(NET_COLS)
assert sorted(HOST_SIGNALS) == sorted(hm.FEATURES) and sorted(NET_SIGNALS) == sorted(sm.FEATURES)
RUN_DIRS = C.run_dirs(ROWS)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_calls(run, meta):
    """Saved system calls in file order: timestamp, saved window, pid, syscall id, launch-prologue flag."""
    root = int(meta["sample_root_pid"])
    with open(run / "exec_events.csv", newline="") as f:
        succ = [int(e["timestamp_ns"]) for e in csv.DictReader(f)
                if e["event"] == "exec_success" and int(e["pid"]) == root]
    cut = succ[1] if len(succ) >= 2 else None
    ts, wid, pid, sid = [], [], [], []
    with open(run / "syscall_events.csv", newline="") as f:
        reader = csv.reader(f)
        head = next(reader)
        it, iw, ip, ie, idt = (head.index(k) for k in ("timestamp_ns", "window_id", "pid", "event", "detail"))
        for row in reader:
            if row[ie] != "syscall":
                continue
            try:
                s = int(row[idt].split("id=")[1].split()[0])
            except (IndexError, ValueError):
                continue
            ts.append(int(row[it]))
            wid.append(int(row[iw]))
            pid.append(int(row[ip]))
            sid.append(s)
    ts = np.asarray(ts, dtype=np.int64)
    pid = np.asarray(pid, dtype=np.int64)
    prologue = (pid == root) & (ts < cut) if cut is not None else np.zeros(len(ts), dtype=bool)
    return ts, np.asarray(wid, dtype=np.int64), pid, np.asarray(sid, dtype=np.int64), prologue, cut is not None


def host_windows(win, pid, sid, n, keep=None):
    if keep is not None:
        win, pid, sid = win[keep], pid[keep], sid[keep]
    rows = hm.window_features(zip(win.tolist(), pid.tolist(), sid.tolist()), windows=n)
    return np.asarray([[r[s] for s in HOST_SIGNALS] for r in rows], dtype=float), rows


def net_windows(pcap, anchor_us, ms):
    rows = sm.window_features(str(pcap), anchor_us, ms / 1000.0, WINDOWS[ms], 3)
    return np.asarray([[r[s] for s in NET_SIGNALS] for r in rows], dtype=float), rows


def rel_diff(a, b):
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    return float(np.max(np.abs(a - b) / np.maximum(1.0, np.abs(b)))) if a.size else 0.0


def one(i):
    t0 = time.time()
    row, base = ROWS[i], RUN_DIRS[i]
    hits = glob.glob(str(base / "output" / "run_*" / "run.json"))
    assert len(hits) == 1, base
    run = Path(hits[0]).parent
    meta = json.load(open(hits[0]))
    anchor_us = int(meta["sample_started_wall_us"])
    start_ns = int(meta["sample_started_monotonic_ns"])
    observed = int(meta["observation_ended_monotonic_ns"]) - start_ns
    ts, wid, pid, sid, prologue, has_cut = read_calls(run, meta)
    rel = ts - start_ns
    facts = {"run_dir": str(run), "run_id": meta["run_id"], "anchor_us": anchor_us, "start_ns": start_ns,
             "observation_ns": observed, "calls": int(len(ts)), "prologue_calls": int(prologue.sum()),
             "second_exec_found": bool(has_cut),
             "calls_before_start": int((rel < 0).sum()), "calls_after_20s": int((rel >= OBSERVATION_NS).sum()),
             "window_id_mismatch": int((rel // 500_000_000 != wid).sum())}
    out = {"i": i, "facts": facts, "N": {}, "H": {}, "Hpf": {}, "summ": {}}
    pcap = run / "packet_capture.pcap"
    for ms, n in WINDOWS.items():
        win = rel // (ms * 1_000_000)
        H, hrows = host_windows(win, pid, sid, n)
        Hpf, hrows_pf = host_windows(win, pid, sid, n, keep=~prologue)
        N, nrows = net_windows(pcap, anchor_us, ms)
        out["N"][ms], out["H"][ms], out["Hpf"][ms] = N, H, Hpf
        out["summ"][ms] = {"ascollected": {**su.summarize(hrows, hm.FEATURES), **su.summarize(nrows, sm.FEATURES)},
                           "prologuefree": {**su.summarize(hrows_pf, hm.FEATURES), **su.summarize(nrows, sm.FEATURES)}}
    # gates at 0.5 s: the published row
    pub = out["summ"][500]["ascollected"]
    facts["gate_net_rel"] = rel_diff([pub[c] for c in NET_COLS], [float(row[c]) for c in NET_COLS])
    facts["gate_host_rel"] = rel_diff([pub[c] for c in HOST_COLS], [float(row[c]) for c in HOST_COLS])
    # nesting of the shorter windows in the 0.5-s windows
    nest = {}
    for ms in (250, 100):
        r = 500 // ms
        ni = [NET_SIGNALS.index(s) for s in ADDITIVE_NET]
        hi = [HOST_SIGNALS.index(s) for s in ADDITIVE_HOST]
        nest[ms] = {
            "net": float(np.max(np.abs(out["N"][ms][:, ni].reshape(40, r, -1).sum(1) - out["N"][500][:, ni]))),
            "host": float(np.max(np.abs(out["H"][ms][:, hi].reshape(40, r, -1).sum(1) - out["H"][500][:, hi]))),
            "host_pf": float(np.max(np.abs(out["Hpf"][ms][:, hi].reshape(40, r, -1).sum(1) - out["Hpf"][500][:, hi]))),
        }
    facts["nesting_max_abs"] = nest
    facts["seconds"] = round(time.time() - t0, 2)
    return out


def write_features(path, per_run, variant, ms):
    fields = list(ROWS[0])
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for row, res in zip(ROWS, per_run):
            r = dict(row)
            r.update({c: repr(float(res["summ"][ms][variant][c])) for c in HOST_COLS + NET_COLS})
            w.writerow(r)


def write_windows_gz(path, H, N):
    meta = ["execution_id", "label", "category", "cv_group", "split", "window"]
    with open(path, "wb") as raw, io.TextIOWrapper(gzip.GzipFile(filename="", mode="wb", compresslevel=9,
                                                                 fileobj=raw, mtime=0), newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(meta + HOST_SIGNALS + NET_SIGNALS)
        for i, r in enumerate(ROWS):
            for k in range(H.shape[1]):
                w.writerow([r["execution_id"], r["label"], r["category"], r["cv_group"], r["split"], k]
                           + [repr(float(x)) for x in H[i, k]] + [repr(float(x)) for x in N[i, k]])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("outdir")
    ap.add_argument("--jobs", type=int, default=12)
    args = ap.parse_args()
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=False)
    t0 = time.time()
    # big runs first, so the pool is not left waiting on one at the end
    order = sorted(range(len(ROWS)), key=lambda i: -float(ROWS[i]["syscall_count"] or 0))
    per_run = [None] * len(ROWS)
    with Pool(args.jobs) as pool:
        for res in pool.imap_unordered(one, order):
            per_run[res["i"]] = res
            f = res["facts"]
            print("[build] %3d %-66s calls %8d prologue %3d  %5.1fs  gate net %.1e host %.1e" % (
                res["i"], ROWS[res["i"]]["execution_id"][:66], f["calls"], f["prologue_calls"], f["seconds"],
                f["gate_net_rel"], f["gate_host_rel"]), flush=True)
    facts = [r["facts"] for r in per_run]
    # window-by-window gate against the telemetry of the collection
    tel = np.load(COMMITTEE / "cache" / "windows.npz", allow_pickle=False)
    assert list(tel["host_signals"]) == HOST_SIGNALS and list(tel["net_signals"]) == NET_SIGNALS
    N05 = np.stack([r["N"][500] for r in per_run])
    H05 = np.stack([r["H"][500] for r in per_run])
    report = {
        "gate": {
            "window_id_mismatches": sum(f["window_id_mismatch"] for f in facts),
            "calls_before_start": sum(f["calls_before_start"] for f in facts),
            "calls_after_20s": sum(f["calls_after_20s"] for f in facts),
            "observation_ns": sorted({f["observation_ns"] for f in facts}),
            "summary_net_max_rel": max(f["gate_net_rel"] for f in facts),
            "summary_host_max_rel": max(f["gate_host_rel"] for f in facts),
            "telemetry_net_max_rel": rel_diff(N05, tel["N"]),
            "telemetry_host_max_rel": rel_diff(H05, tel["H"]),
        },
        "nesting_max_abs": {str(ms): {k: max(f["nesting_max_abs"][ms][k] for f in facts) for k in ("net", "host", "host_pf")}
                            for ms in (250, 100)},
        "prologue_calls": {},
        "second_exec_missing": [ROWS[i]["execution_id"] for i, f in enumerate(facts) if not f["second_exec_found"]],
        "runs": {ROWS[i]["execution_id"]: f for i, f in enumerate(facts)},
    }
    for f in facts:
        report["prologue_calls"][str(f["prologue_calls"])] = report["prologue_calls"].get(str(f["prologue_calls"]), 0) + 1
    g = report["gate"]
    ok = (g["window_id_mismatches"] == 0 and g["calls_before_start"] == 0 and g["calls_after_20s"] == 0
          and g["summary_net_max_rel"] <= GATE_REL and g["summary_host_max_rel"] <= GATE_REL
          and g["telemetry_net_max_rel"] <= GATE_REL and g["telemetry_host_max_rel"] <= GATE_REL
          and all(v == 0.0 for d in report["nesting_max_abs"].values() for v in d.values()))
    report["gate"]["passed"] = bool(ok)
    hashes = {}
    for ms in WINDOWS:
        for variant in ("ascollected", "prologuefree"):
            p = out / ("features_%dms_%s.csv" % (ms, variant))
            write_features(p, per_run, variant, ms)
            hashes[p.name] = sha256(p)
        N = np.stack([r["N"][ms] for r in per_run])
        H = np.stack([r["H"][ms] for r in per_run])
        Hpf = np.stack([r["Hpf"][ms] for r in per_run])
        p = out / ("windows_%dms.npz" % ms)
        np.savez_compressed(p, N=N, H=H, Hpf=Hpf, host_signals=np.asarray(HOST_SIGNALS),
                            net_signals=np.asarray(NET_SIGNALS),
                            execution_ids=np.asarray([r["execution_id"] for r in ROWS]))
        hashes[p.name] = sha256(p)
        if ms != 500:
            for variant, HH in (("ascollected", H), ("prologuefree", Hpf)):
                p = out / ("dataset_windows_%dms_%s.csv.gz" % (ms, variant))
                write_windows_gz(p, HH, N)
                hashes[p.name] = sha256(p)
    report["outputs_sha256"] = hashes
    report["inputs_sha256"] = {
        "features.csv": sha256(REL / "dataset/features.csv"),
        "switch_model.py": sha256(REL / "features/switch_model.py"),
        "host_model.py": sha256(REL / "features/host_model.py"),
        "summary.py": sha256(REL / "features/summary.py"),
        "committee common.py": sha256(COMMITTEE / "common.py"),
        "cache/windows.npz": sha256(COMMITTEE / "cache" / "windows.npz"),
        "build_short.py": sha256(Path(__file__)),
    }
    report["seconds"] = round(time.time() - t0, 1)
    json.dump(report, open(out / "build.json", "w"), indent=1)
    print("[build] gate %s: window_id mismatches %d; calls outside 0-20 s %d/%d; observation %s ns; summaries net "
          "%.1e host %.1e; telemetry net %.1e host %.1e; nesting %s; prologue calls %s; %.0f s" % (
              "PASSED" if ok else "FAILED", g["window_id_mismatches"], g["calls_before_start"], g["calls_after_20s"],
              g["observation_ns"], g["summary_net_max_rel"], g["summary_host_max_rel"], g["telemetry_net_max_rel"],
              g["telemetry_host_max_rel"], report["nesting_max_abs"], report["prologue_calls"], report["seconds"]))
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
