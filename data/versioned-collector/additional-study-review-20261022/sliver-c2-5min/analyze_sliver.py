"""Sliver testbed analysis (offline; no VM, no merge, no model promotion). Complements the frozen sinkhole analysis,
which is applied unchanged to the same attempt for within-run detection (analyze_sinkhole_c2.py ATTEMPT).

  1 Command phase: per implant, the operator's taskings (autotask.jsonl) inside its observation, and host system
    calls / switch packets in the 2 s after each tasking against the implant's windows without a tasking.
  2 Transports: the same implant code over HTTP, HTTPS, mutual TLS and WireGuard: what each view measures.
  3 Published detectors: trained on the release dataset (240 rows, 20 s), applied to each run's first 40 windows;
    also trained without the benign projects whose binaries the testbed's benign clients use.
  4 Server down vs up: detectors trained on the sinkhole run (real C2 samples, server unreachable) applied to the
    testbed's implants (server up, tasked).

    nice -n 19 /usr/bin/python3 analyze_sliver.py ATTEMPT_DIR
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
PROJ = HERE.parent
sys.path.insert(0, str(PROJ / "sinkhole-c2-5min"))
import analyze_sinkhole_c2 as A  # noqa: E402  frozen; only its loader is used
import importlib.util  # noqa: E402
# the frozen analysis puts the release's evaluation/common.py on the path; load the committee loader by file
_spec = importlib.util.spec_from_file_location("committee_common", PROJ / "committee-eval-20261113" / "common.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)

SINKHOLE = PROJ / "sinkhole-c2-5min/20261113T084625506148Z"
TESTBED_BENIGN_PROJECTS = {"curl", "wget", "git", "openssl", "rsync"}
AFTER_TASK_WINDOWS = 4  # 2 s


def five(W, sig_names, columns, k):
    """Summaries of the first k windows, column by column in the release's column order."""
    idx = {s: i for i, s in enumerate(sig_names)}
    out = []
    for c in columns:
        s, st = c.rsplit("__", 1)
        v = W[:k, idx[s]]
        out.append({"mean": v.mean(), "max": v.max(), "sum": v.sum(), "std": v.std(),
                    "active_windows": float((v != 0).sum())}[st])
    return np.asarray(out)


def command_phase(attempt, rows, host, net):
    log = [json.loads(l) for l in open(attempt / "autotask.jsonl")] if (attempt / "autotask.jsonl").exists() else []
    hi, ni = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    per, pooled = {}, {"host_after": [], "host_other": [], "net_after": [], "net_other": []}
    for r in rows:
        if r["label"] != "malware":
            continue
        name = r["case"]["sample"].removesuffix(".zip")
        t0, t1 = r["start"].timestamp(), r["end"].timestamp()
        ev = [e for e in log if e.get("name") == name and t0 <= e["t"] < t1]
        after = set()
        for e in ev:
            w = int((e["t"] - t0) / 0.5)
            after.update(range(w, min(600, w + AFTER_TASK_WINDOWS)))
        other = sorted(set(range(600)) - after)
        a, o = sorted(after), other
        H, N = r["H"][:, hi], r["N"][:, ni]
        rec = {"family": r["case"]["family"], "taskings": len(ev), "taskings_ok": sum(bool(e.get("result_ok")) for e in ev),
               "first_tasking_s": round(min(e["t"] for e in ev) - t0, 1) if ev else None,
               "host_calls_per_window_after": round(float(H[a].mean()), 1) if a else None,
               "host_calls_per_window_other": round(float(H[o].mean()), 1),
               "packets_per_window_after": round(float(N[a].mean()), 2) if a else None,
               "packets_per_window_other": round(float(N[o].mean()), 2)}
        per[name] = rec
        if a:
            pooled["host_after"].extend(H[a]); pooled["host_other"].extend(H[o])
            pooled["net_after"].extend(N[a]); pooled["net_other"].extend(N[o])
    summary = {k: round(float(np.mean(v)), 2) if v else None for k, v in pooled.items()}
    return {"per_implant": per, "pooled_mean_per_window": summary, "taskings_total": len(log)}


def transports(rows, host, net):
    hi = host.index("host_total_syscalls_total")
    pk, by, fl = (net.index(s) for s in ("net_pkts_total_delta", "net_bytes_total_delta", "net_flow_count_seen"))
    groups = defaultdict(list)
    for r in rows:
        if r["label"] == "malware":
            groups[r["case"]["family"]].append(r)
    out = {}
    for fam, rs in sorted(groups.items()):
        rec = {}
        for k, lab in ((40, "20s"), (600, "5min")):
            packets = [r["N"][:k, pk].sum() for r in rs]
            bytes_ = [r["N"][:k, by].sum() for r in rs]
            rec[lab] = {"packets": [int(x) for x in packets], "bytes": [int(x) for x in bytes_],
                        "mean_packet_bytes": [round(b / p, 1) if p else 0 for b, p in zip(bytes_, packets)],
                        "max_flows_per_window": [int(r["N"][:k, fl].max()) for r in rs],
                        "host_calls": [int(r["H"][:k, hi].sum()) for r in rs]}
        out[fam] = rec
    return out


def published(rows, host, net):
    """Release detectors trained on features.csv (20 s) and applied to the first 40 windows of every run."""
    drows, hc, nc = C.load()
    Xh_d, Xn_d, y_d = C.matrix(drows, hc), C.matrix(drows, nc), C.labels(drows)
    g_d = C.groups_published(drows)
    scored = [r for r in rows if r["label"] in ("malware", "benign", "null")]
    Xh_t = np.asarray([five(r["H"], host, hc, 40) for r in scored])
    Xn_t = np.asarray([five(r["N"], net, nc, 40) for r in scored])
    y_t = np.asarray([int(r["label"] == "malware") for r in scored])
    Xh, Xn = np.vstack([Xh_d, Xh_t]), np.vstack([Xn_d, Xn_t])
    y = np.concatenate([y_d, y_t]); g = np.concatenate([g_d, ["testbed"] * len(scored)])
    te = np.arange(len(drows), len(y))
    keep_all = np.arange(len(drows))
    keep_cut = np.asarray([i for i, r in enumerate(drows) if r["project"] not in TESTBED_BENIGN_PROJECTS])
    out = {}
    for name, tr in (("trained_on_all_240", keep_all), ("without_testbed_benign_projects", keep_cut)):
        P = C.fit_predict(Xh, Xn, y, g, tr, te)
        res = {"training_rows": int(len(tr)), "per_detector": {}}
        for d, p in P.items():
            flag = p >= 0.5
            res["per_detector"][d] = {
                "implants_flagged": int(flag[y_t == 1].sum()), "implants": int((y_t == 1).sum()),
                "benign_flagged": int(flag[(y_t == 0) & np.array([r["label"] == "benign" for r in scored])].sum()),
                "benign": int(sum(r["label"] == "benign" for r in scored)),
                "nulls_flagged": int(flag[np.array([r["label"] == "null" for r in scored])].sum()),
                "by_run": {r["case"]["sample"].removesuffix(".zip"): round(float(x), 3) for r, x in zip(scored, p)}}
        out[name] = res
    return out


def server_down_vs_up(rows, host, net):
    """Train on the sinkhole run (server unreachable), score the testbed's runs (server up, tasked)."""
    _, sk = A.load_runs(SINKHOLE, host, net)
    train = [r for r in sk if r["label"] in ("malware", "benign")]
    test = [r for r in rows if r["label"] in ("malware", "benign")]
    drows, hc, nc = C.load()
    out = {}
    for k, lab in ((40, "20s"), (600, "5min")):
        Xh = np.asarray([five(r["H"], host, hc, k) for r in train + test])
        Xn = np.asarray([five(r["N"], net, nc, k) for r in train + test])
        y = np.asarray([int(r["label"] == "malware") for r in train + test])
        g = np.asarray([r["group"] for r in train] + ["testbed"] * len(test))
        tr, te = np.arange(len(train)), np.arange(len(train), len(train) + len(test))
        P = C.fit_predict(Xh, Xn, y, g, tr, te)
        yt = y[te]
        out[lab] = {d: {"implants_flagged": int((p[yt == 1] >= .5).sum()), "implants": int((yt == 1).sum()),
                        "benign_flagged": int((p[yt == 0] >= .5).sum()), "benign": int((yt == 0).sum())}
                    for d, p in P.items()}
    out["note"] = ("benign clients of the testbed are the sinkhole run's amd64-dynamic tasks re-run, so their false "
                   "alarms here are not a transfer measurement; implant recall is")
    return out


def main():
    attempt = Path(sys.argv[1]).resolve()
    host, net = A.tc.signals()
    protocol, rows = A.load_runs(attempt, host, net)
    res = {"attempt": str(attempt), "accepted": {lab: sum(r["label"] == lab for r in rows)
                                                 for lab in ("malware", "benign", "null")}}
    res["command_phase"] = command_phase(attempt, rows, host, net)
    res["transports"] = transports(rows, host, net)
    res["published_detectors"] = published(rows, host, net)
    res["server_down_vs_up"] = server_down_vs_up(rows, host, net)
    out = attempt / "analysis"
    out.mkdir(exist_ok=True)
    (out / "sliver_results.json").write_text(json.dumps(res, indent=1, default=str))
    print(json.dumps({k: res[k] for k in ("accepted",)}, indent=1))
    print("command phase (pooled mean per window):", res["command_phase"]["pooled_mean_per_window"])
    for name, v in res["published_detectors"].items():
        print(name, {d: "%d/%d implants, %d/%d benign" % (x["implants_flagged"], x["implants"], x["benign_flagged"], x["benign"])
                     for d, x in v["per_detector"].items()})
    for lab in ("20s", "5min"):
        print("server down -> up", lab, {d: "%d/%d implants" % (x["implants_flagged"], x["implants"])
                                         for d, x in res["server_down_vs_up"][lab].items()})


if __name__ == "__main__":
    main()
