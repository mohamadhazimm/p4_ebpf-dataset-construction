"""Vectorised version of the release's features/host_model.py, for the evasion simulations. Offline.

host_windows(w, p, s) returns the 18 window features of host_model.window_features for events
(window, pid, syscall id) given in call order; main() checks both agree on all 240 executions.

    /usr/bin/python3 fasthost.py      # builds ../cache/events/<row>.npz and checks
"""
import csv
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/features")
import common as C  # noqa: E402
import host_model as HM  # noqa: E402

EVENTS = C.CACHE / "events"
SIG8 = ["unique_syscalls", "entropy", "top_syscall_freq", "avg_run_length", "max_run_length",
        "rare_syscall_ratio", "first50_unique", "first100_unique"]


def load_events(i, run_dir=None):
    """(w, p, s, root_pid, prologue_mask) of one execution, cached."""
    f = EVENTS / ("%d.npz" % i)
    if f.exists():
        z = np.load(f)
        return z["w"], z["p"], z["s"], int(z["root"]), z["prologue"]
    out = C.output_dir(run_dir)
    meta = json.loads((out / "run.json").read_text())
    root = int(meta["sample_root_pid"])
    succ = [int(e["timestamp_ns"]) for e in csv.DictReader(open(out / "exec_events.csv"))
            if e["event"] == "exec_success" and int(e["pid"]) == root]
    cut = succ[1] if len(succ) >= 2 else None
    w, p, s, pro = [], [], [], []
    for r in csv.DictReader(open(out / "syscall_events.csv")):
        if r["event"] != "syscall":
            continue
        try:
            sid = int(r["detail"].split("id=")[1].split()[0])
        except (IndexError, ValueError):
            continue
        w.append(int(r["window_id"])); p.append(int(r["pid"])); s.append(sid)
        pro.append(cut is not None and int(r["pid"]) == root and int(r["timestamp_ns"]) < cut)
    EVENTS.mkdir(parents=True, exist_ok=True)
    arr = dict(w=np.asarray(w, np.int32), p=np.asarray(p, np.int64), s=np.asarray(s, np.int32),
               root=np.asarray(root), prologue=np.asarray(pro, bool))
    np.savez_compressed(f, **arr)
    return arr["w"], arr["p"], arr["s"], root, arr["prologue"]


def group_structure(w, p, order=None):
    """Sort events by (window, pid, order); group ids, starts, ranks in the sorted order."""
    n = len(w)
    order = np.arange(n) if order is None else order
    key = w.astype(np.int64) * (1 << 40) + (p.astype(np.int64) & ((1 << 40) - 1))
    idx = np.lexsort((order, key))
    k = key[idx]
    new = np.empty(n, bool)
    if n:
        new[0] = True
        new[1:] = k[1:] != k[:-1]
    gid = np.cumsum(new) - 1
    gstart = np.flatnonzero(new)
    rank = np.arange(n) - gstart[gid] if n else np.zeros(0, int)
    return idx, gid, gstart, rank


def host_windows(w, p, s, order=None, windows=40):
    """(windows, 18) host features in host_model.FEATURES order."""
    m = (w >= 0) & (w < windows)
    w, p, s = w[m], p[m], s[m]
    order = None if order is None else order[m]
    out = np.zeros((windows, len(HM.FEATURES)))
    n = len(w)
    if n == 0:
        return out
    idx, gid, gstart, rank = group_structure(w, p, order)
    s, w = s[idx], w[idx]
    G = len(gstart)
    total = np.diff(np.append(gstart, n)).astype(float)
    run_start = np.ones(n, bool)
    run_start[1:] = (gid[1:] != gid[:-1]) | (s[1:] != s[:-1])
    runs = np.bincount(gid, weights=run_start, minlength=G)
    rid = np.cumsum(run_start) - 1
    run_len = np.bincount(rid)
    max_run = np.zeros(G); np.maximum.at(max_run, gid[run_start], run_len)
    valid = (s >= 0) & (s < HM.MAX_SYSCALL_ID)
    hk = gid[valid].astype(np.int64) * HM.MAX_SYSCALL_ID + s[valid]
    uk, cnt = np.unique(hk, return_counts=True)
    hg = uk // HM.MAX_SYSCALL_ID
    unique = np.bincount(hg, minlength=G).astype(float)
    prob = cnt / total[hg]
    ent = np.zeros(G); np.add.at(ent, hg, -prob * np.log2(prob))
    top = np.zeros(G); np.maximum.at(top, hg, cnt)
    sing = np.bincount(hg, weights=(cnt == 1).astype(float), minlength=G)
    firsts = []
    for N in (50, 100):
        mk = rank < N
        fk = gid[mk].astype(np.int64) * (1 << 21) + (s[mk].astype(np.int64) + (1 << 20))
        u = np.unique(fk)
        firsts.append(np.bincount(u // (1 << 21), minlength=G).astype(float))
    sig = {"total_syscalls": total, "unique_syscalls": unique, "entropy": ent, "top_syscall_freq": top / total,
           "avg_run_length": total / runs, "max_run_length": max_run, "transition_count": runs - 1,
           "rare_syscall_ratio": sing / total, "first50_unique": firsts[0], "first100_unique": firsts[1]}
    gw = w[gstart]
    nproc = np.bincount(gw, minlength=windows).astype(float)
    col = {f: i for i, f in enumerate(HM.FEATURES)}
    for name in ("total_syscalls", "transition_count"):
        out[:, col["host_%s_total" % name]] = np.bincount(gw, weights=sig[name], minlength=windows)
    for name in SIG8:
        sm = np.bincount(gw, weights=sig[name], minlength=windows)
        out[:, col["host_%s_mean" % name]] = np.divide(sm, nproc, out=np.zeros(windows), where=nproc > 0)
        mx = np.zeros(windows); np.maximum.at(mx, gw, sig[name])
        out[:, col["host_%s_max" % name]] = mx
    return out


def to_columns(win, host_cols):
    """Five summaries of the 18 window features, in the dataset's host column order."""
    sigs = C.signals(host_cols)
    order = [HM.FEATURES.index(s) for s in sigs]
    return C.summarize(win[None, :, order])[0]


def _check(i_dir):
    i, d = i_dir
    w, p, s, root, pro = load_events(i, d)
    fast = host_windows(w, p, s)
    if len(w) <= 300_000:  # the pure-Python model on the smaller runs (the large ones are checked by the gate below)
        slow = np.asarray([[r[f] for f in HM.FEATURES] for r in HM.window_features(list(zip(w, p, s)), 40)])
        d1 = float(np.max(np.abs(fast - slow) / np.maximum(1, np.abs(slow))))
    else:
        d1 = None
    return i, d1, fast


def main():
    rows, hc, nc = C.load()
    with Pool(8) as pool:
        res = sorted(pool.map(_check, list(enumerate(C.run_dirs(rows))), chunksize=2), key=lambda t: t[0])
    worst = max(r[1] for r in res if r[1] is not None)
    X = np.asarray([to_columns(r[2], hc) for r in res])
    Xref = C.matrix(rows, hc)
    gate = float(np.max(np.abs(X - Xref) / np.maximum(1, np.abs(Xref))))
    print("fast vs host_model.py (runs <= 300k events): %.2e; fast vs published host columns (all 240): %.2e"
          % (worst, gate))
    assert worst < 1e-9 and gate < 1e-9


if __name__ == "__main__":
    main()
