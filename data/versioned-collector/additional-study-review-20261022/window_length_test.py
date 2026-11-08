"""Window-length test: does reading the sensors every 1, 2, 5 or 10 s instead of every 0.5 s lose detection?

Recomputes the paper's per-window features from each 5-minute run's raw data at several window lengths:
- host: the 18 window features of features/host_model.py, from the run's syscall_events.csv (every recorded system
  call, in recorded order, with the 0.5 s window it fell in). A W-second window is W/0.5 consecutive 0.5 s windows, on
  the same grid that starts at sample start, so re-binning is exact.
- network: the 29 window features of features/switch_model.py, from the run's packet capture, with the window length
  W, nominal rates (packets / W) and an active-flow TTL counted in windows (3, as in the dataset; 5 as a check, the
  live collector's default).
Each execution is summarized over the first T seconds (summary.py: mean, max, sum, std, non-zero windows), giving
90 host + 145 network columns at every (W, T), like the dataset.

Checks before any scoring: at W = 0.5 s the recomputed windows must equal the runner's stored telemetry (host 18 and
network 29 columns) in every window of every run.

Scoring: grouped cross-validation, whole malware families and whole benign programs held out
(StratifiedGroupKFold(5)), RF300 class-balanced, threshold 0.5, ten fold assignments (seeds 42 and 0-8). Detectors:
host (90), network (145), hybrid (both, concatenated). Offline; no VM, no model promotion, no dataset merge.

    /usr/bin/python3 window_length_test.py extract ATTEMPT OUTDIR [--jobs N]
    /usr/bin/python3 window_length_test.py score OUTDIR [--jobs N]
"""

import argparse
import csv
import glob
import hashlib
import json
import os
import sys
import time
from multiprocessing import Pool

import numpy as np

RELEASE = "/home/ali/Desktop/Hazim/p4-ebpf-malware-detection"
sys.path.insert(0, RELEASE + "/features")
import host_model  # noqa: E402
import summary  # noqa: E402
import switch_model  # noqa: E402

BASE_WINDOW = 0.5
OBSERVATION = 300.0
BASE_WINDOWS = 600
WINDOWS = [0.5, 1.0, 2.0, 5.0, 10.0]
PREFIXES = [20.0, 60.0, 120.0, 180.0, 300.0]
TTLS = {10.0: [3, 5]}           # extra TTL check at 10 s; every other W uses 3
SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8]
TOL = 1e-9


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_cases(attempt):
    proto = json.load(open(os.path.join(attempt, "protocol.json")))
    meta = {c["sample"]: c for c in proto["cases"]}
    cases, skipped = [], []
    for rj in sorted(glob.glob(os.path.join(attempt, "runs/*/output/run_*/run.json"))):
        sample = rj.split("/runs/")[1].split("/")[0]
        c = meta.get(sample)
        if c is None:
            skipped.append((sample, "not in protocol"))
            continue
        d = json.load(open(rj))
        if d.get("collection_quality_status") != "accepted":
            skipped.append((sample, "quality %s" % d.get("collection_quality_status")))
            continue
        if (d.get("target_exec") or {}).get("status") != "observed":
            skipped.append((sample, "target exec not observed"))
            continue
        cases.append({"sample": sample, "run_dir": os.path.dirname(rj), "label": c["label"],
                      "family": c.get("family"), "program": c.get("program"), "mode": c.get("mode"),
                      "start_us": int(d["sample_started_wall_us"])})
    return cases, skipped


def read_events(path):
    """(window_id, pid, syscall_id) of every recorded system call, in file order."""
    events = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row["event"] != "syscall":
                continue
            detail = row["detail"]
            if not detail.startswith("id="):
                raise ValueError("unexpected detail %r in %s" % (detail, path))
            events.append((int(row["window_id"]), int(row["pid"]), int(detail[3:])))
    return events


def matrix(windows, features):
    return np.array([[float(w[f]) for f in features] for w in windows])


def extract_case(case):
    run = case["run_dir"]
    pcap = os.path.join(run, "packet_capture.pcap")
    events = read_events(os.path.join(run, "syscall_events.csv"))
    stored = list(csv.DictReader(open(os.path.join(run, "telemetry.csv"))))
    out = {"sample": case["sample"], "n_events": len(events),
           "pcap_sha256": sha256(pcap), "events_sha256": sha256(os.path.join(run, "syscall_events.csv"))}
    if len(stored) != BASE_WINDOWS:
        out["error"] = "telemetry has %d windows" % len(stored)
        return out, None

    # Check at 0.5 s against the runner's stored per-window features.
    host05 = matrix(host_model.window_features(events, BASE_WINDOWS), host_model.FEATURES)
    net05 = matrix(switch_model.window_features(pcap, case["start_us"], BASE_WINDOW, BASE_WINDOWS),
                   switch_model.FEATURES)
    host_st = matrix(stored, host_model.FEATURES)
    net_st = matrix(stored, switch_model.FEATURES)
    dh = np.abs(host05 - host_st) / np.maximum(1.0, np.abs(host_st))
    dn = np.abs(net05 - net_st) / np.maximum(1.0, np.abs(net_st))
    out["host_max_rel_diff"] = float(dh.max())
    out["net_max_rel_diff"] = float(dn.max())
    out["host_cells_off"] = int((dh > TOL).sum())
    out["net_cells_off"] = int((dn > TOL).sum())

    mats = {}
    for w in WINDOWS:
        k = int(round(w / BASE_WINDOW))
        n = int(round(OBSERVATION / w))
        if w == BASE_WINDOW:
            host = host05
        else:
            host = matrix(host_model.window_features([(win // k, pid, sid) for win, pid, sid in events], n),
                          host_model.FEATURES)
        for ttl in TTLS.get(w, [3]):
            if w == BASE_WINDOW and ttl == 3:
                net = net05
            else:
                net = matrix(switch_model.window_features(pcap, case["start_us"], w, n, active_ttl_windows=ttl),
                             switch_model.FEATURES)
            mats["%g_ttl%d" % (w, ttl)] = (host, net)
    # Host check at every W: the system-call total over 300 s does not depend on the window length.
    tot = host_model.FEATURES.index("host_total_syscalls_total")
    out["host_total_by_window"] = {key: float(h[:, tot].sum()) for key, (h, _) in mats.items()}
    pk = switch_model.FEATURES
    out["net_packets_by_window"] = {key: float(nm[:, pk.index("net_pkts_ab_delta")].sum()
                                               + nm[:, pk.index("net_pkts_ba_delta")].sum())
                                    for key, (_, nm) in mats.items()} if "net_pkts_ab_delta" in pk else None
    return out, mats


def cmd_extract(args):
    attempt = os.path.abspath(args.attempt)
    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=False)
    cases, skipped = load_cases(attempt)
    t0 = time.time()
    with Pool(args.jobs) as pool:
        results = pool.map(extract_case, cases, chunksize=1)
    checks, store = [], {}
    for case, (info, mats) in zip(cases, results):
        checks.append(info)
        if mats is None:
            continue
        for key, (h, n) in mats.items():
            store.setdefault(key, {})[case["sample"]] = (h, n)
    keep = [c for c, (info, mats) in zip(cases, results) if mats is not None]
    arrays = {}
    for key, per in store.items():
        arrays["host_" + key] = np.stack([per[c["sample"]][0] for c in keep])
        arrays["net_" + key] = np.stack([per[c["sample"]][1] for c in keep])
    np.savez_compressed(os.path.join(outdir, "windows.npz"), **arrays)
    meta = {"attempt": attempt, "script_sha256": sha256(__file__),
            "feature_code_sha256": {m: sha256(os.path.join(RELEASE, "features", m + ".py"))
                                    for m in ("host_model", "switch_model", "summary")},
            "windows": WINDOWS, "ttls": {str(k): v for k, v in TTLS.items()}, "prefixes": PREFIXES,
            "host_features": host_model.FEATURES, "net_features": switch_model.FEATURES,
            "cases": [{k: c[k] for k in ("sample", "label", "family", "program", "mode")} for c in keep],
            "skipped": skipped, "checks": checks, "seconds": round(time.time() - t0, 1)}
    json.dump(meta, open(os.path.join(outdir, "extract.json"), "w"), indent=1)
    off_h = sum(c.get("host_cells_off", 0) for c in checks)
    off_n = sum(c.get("net_cells_off", 0) for c in checks)
    print("cases %d (skipped %d); 0.5 s check: host cells off %d, network cells off %d; %.0f s"
          % (len(keep), len(skipped), off_h, off_n, time.time() - t0))


def summarize_matrix(mat, features, n):
    windows = [dict(zip(features, row)) for row in mat[:n]]
    s = summary.summarize(windows, features)
    return [s["%s__%s" % (f, st)] for f in features for st in summary.STATISTICS]


def score_one(job):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import balanced_accuracy_score, roc_auc_score
    from sklearn.model_selection import StratifiedGroupKFold
    name, X, y, groups, seed = job
    oof = np.zeros(len(y))
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(X, y, groups):
        clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42, n_jobs=1)
        clf.fit(X[tr], y[tr])
        oof[te] = clf.predict_proba(X[te])[:, 1]
    pred = (oof >= 0.5).astype(int)
    return name, seed, {"ba": float(balanced_accuracy_score(y, pred)), "auc": float(roc_auc_score(y, oof)),
                        "tp": int(((pred == 1) & (y == 1)).sum()), "fp": int(((pred == 1) & (y == 0)).sum()),
                        "tn": int(((pred == 0) & (y == 0)).sum()), "fn": int(((pred == 0) & (y == 1)).sum())}


def cmd_score(args):
    outdir = os.path.abspath(args.outdir)
    meta = json.load(open(os.path.join(outdir, "extract.json")))
    arr = np.load(os.path.join(outdir, "windows.npz"))
    keep = [i for i, c in enumerate(meta["cases"]) if c["label"] in ("malware", "benign")]
    cases = [meta["cases"][i] for i in keep]       # null runs are checked at extraction, not classified
    arr = {k: v[keep] for k, v in arr.items()}
    y = np.array([1 if c["label"] == "malware" else 0 for c in cases])
    groups = np.array([("fam:" + c["family"]) if c["label"] == "malware" else ("prog:" + c["program"])
                       for c in cases])
    hf, nf = meta["host_features"], meta["net_features"]
    jobs = []
    for key in sorted({k[5:] for k in arr if k.startswith("host_")}):
        w = float(key.split("_ttl")[0])
        H, N = arr["host_" + key], arr["net_" + key]
        for t in PREFIXES:
            n = int(round(t / w))
            Xh = np.array([summarize_matrix(H[i], hf, n) for i in range(len(cases))])
            Xn = np.array([summarize_matrix(N[i], nf, n) for i in range(len(cases))])
            Xy = np.concatenate([Xh, Xn], 1)
            for det, X in (("host", Xh), ("network", Xn), ("hybrid", Xy)):
                for seed in SEEDS:
                    jobs.append(("%s|%g|%s" % (key, t, det), X, y, groups, seed))
    with Pool(args.jobs) as pool:
        res = pool.map(score_one, jobs, chunksize=4)
    table = {}
    for name, seed, r in res:
        table.setdefault(name, {})[seed] = r
    rows = []
    for name, per in table.items():
        key, t, det = name.split("|")
        w, ttl = key.split("_ttl")
        ba = np.array([per[s]["ba"] for s in SEEDS]); auc = np.array([per[s]["auc"] for s in SEEDS])
        rows.append({"window": float(w), "ttl": int(ttl), "observation": float(t), "detector": det,
                     "windows": int(round(float(t) / float(w))),
                     "ba_mean": ba.mean(), "ba_sd": ba.std(ddof=1), "auc_mean": auc.mean(),
                     "auc_sd": auc.std(ddof=1), "seed42": per[42], "per_seed": per})
    rows.sort(key=lambda r: (r["ttl"], r["observation"], r["window"], r["detector"]))
    out = {"n_malware": int(y.sum()), "n_benign": int((1 - y).sum()), "n_groups": len(set(groups)),
           "seeds": SEEDS, "rows": rows}
    json.dump(out, open(os.path.join(outdir, "scores.json"), "w"), indent=1, default=float)
    print("malware %d, benign %d, groups %d" % (y.sum(), (1 - y).sum(), len(set(groups))))
    for r in rows:
        print("W=%-4g ttl=%d T=%-4g n=%-3d %-8s BA %.3f+-%.3f  AUC %.3f+-%.3f"
              % (r["window"], r["ttl"], r["observation"], r["windows"], r["detector"],
                 r["ba_mean"], r["ba_sd"], r["auc_mean"], r["auc_sd"]))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract"); e.add_argument("attempt"); e.add_argument("outdir")
    e.add_argument("--jobs", type=int, default=4)
    s = sub.add_parser("score"); s.add_argument("outdir"); s.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args()
    {"extract": cmd_extract, "score": cmd_score}[args.cmd](args)


if __name__ == "__main__":
    main()
