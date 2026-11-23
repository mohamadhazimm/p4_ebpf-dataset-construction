#!/usr/bin/env python3
"""PC1.md part 12B, rerun on the lab workstation (2026-11-20).

PC1's study_windows.py (archive live_test/committee_replay/pc1_20261119_part12.tar.xz, part12_20261119/src/) trained
and scored the network detector on the 110 captures with traffic only. All 43 benign runs among them send in their
first window, so the forests learned that an empty first window is malicious: every attack run whose first window is
empty alarmed at window 0 (p = 1.000) before it had sent anything. Three variants, per window length:

  as12b    12B itself: the 110 runs, leave one group out over their 42 groups. PC1's code is copied verbatim (load,
           summarize, host_bins, the fold loop, the alarm and the share), so it must reproduce study.json.
  traffic  12B's probabilities, with an alarm allowed only from a run's first window with traffic.
  all240   the population the live detector trains on (live_test/streaming/dataset_windows*.csv.gz): all 240 runs,
           the 130 without TCP/UDP traffic all-zero in every window (as in those tables), leave one group out over
           the release's 73 cv_groups. The 110 runs' containment is computed as in 12B; the silent runs have no
           host frames to block.

    rerun_12b.py PC1_WINDOWS_DIR P4_EBPF_DIR RELEASE_DIR OUT_DIR [--jobs N]

PC1_WINDOWS_DIR is part12_20261119/windows of the archive (windows_<ws>.csv.gz, study.json). The forest is the
release's evaluation/common.py random_forest() (500 trees, balanced, seed 42, one thread); the folds run in
parallel processes, which changes no result (each forest is seeded and trained on the same rows in the same order).
"""
import argparse
import csv
import gzip
import io
import json
import multiprocessing
import struct
import sys
import tarfile
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

SIZES = [0.1, 0.25, 0.5]                               # PC1's constants, unchanged
PREFIX_TIMES = [0.5, 1, 2, 3, 5, 8, 10, 15, 20]
PROCESSING_S = 0.05
HOST = bytes([10, 0, 0, 10])
BIN_S = 0.01
FLOODS_SHOWN = ["syn_fan_40k", "goldeneye_p10", "udp_sink_60k", "syn_sink_40k"]     # 12B's per-flood line

common = None                                           # the release's evaluation/common.py, imported in main()


def load(path):
    """PC1's load(), verbatim."""
    runs, order = {}, []
    with gzip.open(path, "rt") as f:
        r = csv.reader(f)
        h = next(r)
        feats = h[5:]
        for row in r:
            eid = row[0]
            if eid not in runs:
                runs[eid] = dict(label=int(row[1]), category=row[2], group=row[3], w={})
                order.append(eid)
            runs[eid]["w"][int(row[4])] = [float(x) for x in row[5:]]
    K = max(len(v["w"]) for v in runs.values())
    W = np.asarray([[runs[e]["w"][k] for k in range(K)] for e in order])
    return order, W, np.asarray([runs[e]["label"] for e in order]), np.asarray([runs[e]["group"] for e in order]), \
        [runs[e]["category"] for e in order], feats


def summarize(W, k):
    """PC1's summarize() (stream_verdicts.summarize), verbatim."""
    W = W[:, :k]
    return np.stack([W.mean(1), W.max(1), W.sum(1), W.std(1), (W != 0).sum(1).astype(float)], axis=2).reshape(len(W), -1)


def host_bins(repo):
    """PC1's host_bins(), verbatim but for the repository path."""
    out = {}
    items = [(r, open(repo / "live_test/captures/cohort" / r["capture"], "rb").read)
             for r in csv.DictReader(open(repo / "live_test/captures/cohort/manifest.csv"))]
    tar = tarfile.open(repo / "live_test/captures/cohort-extra.tar.gz", "r:gz")
    extra = list(csv.DictReader(io.TextIOWrapper(tar.extractfile("cohort-extra/manifest.csv"))))
    for r in extra:
        items.append((r, (lambda m: (lambda: tar.extractfile(m).read()))("cohort-extra/" + r["capture"])))
    for r, read in items:
        data = read()
        ns = struct.unpack("<I", data[:4])[0] == 0xa1b23c4d
        anchor = int(r["anchor_us"]) / 1e6
        bins = np.zeros(int(round(20.0 / BIN_S)) + 1)
        off = 24
        while off + 16 <= len(data):
            ts, tu, il, _ = struct.unpack("<IIII", data[off:off + 16])
            fr = data[off + 16:off + 16 + il]
            off += 16 + il
            if len(fr) >= 34 and fr[12:14] == b"\x08\x00" and fr[26:30] == HOST:
                t = ts + tu / (1e9 if ns else 1e6) - anchor
                if 0 <= t < 20.0:
                    bins[int(t / BIN_S)] += 1
        out[r["execution_id"]] = bins
    return out


# the fold loop of PC1's main(), one group per call (run in a process pool)
_G = {}


def _fold(grp):
    W, y, g, pref, K = _G["W"], _G["y"], _G["g"], _G["pref"], _G["K"]
    test, train = g == grp, g != grp
    Xtr = np.vstack([summarize(W[train], k) for k in pref])
    ytr = np.tile(y[train], len(pref))
    forest = common.random_forest().fit(Xtr, ytr)
    rows = {}
    for i in np.where(test)[0]:
        Xk = np.vstack([summarize(W[i:i + 1], k) for k in range(1, K + 1)])
        rows[int(i)] = forest.predict_proba(Xk)[:, 1]
    return rows


def _init(release_eval):
    global common
    sys.path.insert(0, release_eval)
    import common as c  # noqa: E402
    common = c


def probabilities(W, y, g, ws, jobs, release_eval):
    K = W.shape[1]
    pref = sorted(set([1, 2, 3] + [int(round(t / ws)) for t in PREFIX_TIMES]))
    pref = [k for k in pref if 1 <= k <= K]
    _G.update(W=W, y=y, g=g, pref=pref, K=K)
    P = np.full((len(y), K), np.nan)
    with multiprocessing.get_context("fork").Pool(jobs, initializer=_init, initargs=(release_eval,)) as pool:
        for rows in pool.imap_unordered(_fold, sorted(set(g))):
            for i, p in rows.items():
                P[i] = p
    assert not np.isnan(P).any()
    return P, pref


def first_traffic(Wi):
    """The run's first window with any traffic (any non-zero network feature), or None."""
    nz = np.where((Wi != 0).any(axis=1))[0]
    return int(nz[0]) if len(nz) else None


def evaluate(ids, W, y, cats, P, ws, bins, traffic_only=False):
    """PC1's per-run alarm and share (t_alarm = (k + 1) * ws, block PROCESSING_S later, share of the host's frames
    from that 10 ms bin on), with traffic_only allowing an alarm only from the run's first window with traffic."""
    K = W.shape[1]
    final = P[:, -1]
    pred = final >= 0.5
    runs = []
    for i, eid in enumerate(ids):
        ft = first_traffic(W[i])
        start = (ft if ft is not None else K) if traffic_only else 0
        k_alarm = next((k for k in range(start, K) if P[i, k] >= 0.5), None)
        t_alarm = None if k_alarm is None else (k_alarm + 1) * ws
        b = bins.get(eid)
        share = None
        if b is not None and b.sum() > 0:
            t_block = None if t_alarm is None else t_alarm + PROCESSING_S
            share = 0.0 if t_block is None else float(b[int(round(t_block / BIN_S)):].sum() / b.sum())
        runs.append(dict(execution_id=eid, label=int(y[i]), category=cats[i], first_traffic_window=ft,
                         alarm_window=k_alarm, first_alarm_s=t_alarm,
                         alarm_before_traffic=(k_alarm is not None and (ft is None or k_alarm < ft)),
                         blocked_share=None if share is None else round(share, 4), p_final=round(float(final[i]), 4)))
    return runs, pred


def summary(runs, y, final, pred, subset=None):
    sel = [i for i, r in enumerate(runs) if subset is None or r["execution_id"] in subset]
    ys, fs, ps = y[sel], final[sel], pred[sel]
    rr = [runs[i] for i in sel]
    att = [r for r in rr if r["label"] == 1]
    ben = [r for r in rr if r["label"] == 0]
    t_att = [r["first_alarm_s"] for r in att if r["first_alarm_s"] is not None]

    def mean_share(cat):
        v = [r["blocked_share"] for r in att if r["category"] == cat and r["blocked_share"] is not None]
        return round(float(np.mean(v)), 4) if v else None
    tpr, tnr = float(ps[ys == 1].mean()), float((~ps[ys == 0]).mean())
    return dict(runs=len(rr), balanced_accuracy=round((tpr + tnr) / 2, 4), tpr=round(tpr, 4), tnr=round(tnr, 4),
                auc=round(float(roc_auc_score(ys, fs)), 4),
                attacks=len(att), attacks_alarmed=sum(1 for r in att if r["first_alarm_s"] is not None),
                benign=len(ben), benign_alarmed=sum(1 for r in ben if r["first_alarm_s"] is not None),
                first_alarm_median_s=float(np.median(t_att)) if t_att else None,
                alarmed_before_traffic=dict(attacks=sum(1 for r in att if r["alarm_before_traffic"]),
                                            benign=sum(1 for r in ben if r["alarm_before_traffic"])),
                floods_blocked_mean=mean_share("network_attack"), malware_blocked_mean=mean_share("malware"),
                floods_shown={r["execution_id"]: r["blocked_share"] for r in att if r["execution_id"] in FLOODS_SHOWN})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pc1_windows")
    ap.add_argument("p4_ebpf")
    ap.add_argument("release")
    ap.add_argument("out")
    ap.add_argument("--jobs", type=int, default=16)
    a = ap.parse_args()
    wdir, repo, rel, out = Path(a.pc1_windows), Path(a.p4_ebpf), Path(a.release), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    release_eval = str(rel / "evaluation")
    _init(release_eval)
    study = json.loads((wdir / "study.json").read_text())
    relrows = list(csv.DictReader(open(rel / "dataset/features.csv")))
    t0 = time.time()
    bins = host_bins(repo)
    print("host bins: %d captures (%.0f s)" % (len(bins), time.time() - t0), flush=True)
    result = dict(processing_s=PROCESSING_S, inputs={}, sizes={})
    for ws in SIZES:
        path = wdir / ("windows_%s.csv.gz" % ws)
        result["inputs"][str(ws)] = path.name
        ids, W, y, g, cats, feats = load(path)
        K = W.shape[1]
        # as12b: PC1's study
        t0 = time.time()
        P, pref = probabilities(W, y, g, ws, a.jobs, release_eval)
        ref = {r["execution_id"]: r for r in study["sizes"][str(ws)]["runs"]}
        dp = max(abs(round(float(P[i, k]), 4) - ref[e]["p"][k]) for i, e in enumerate(ids) for k in range(K))
        runs, pred = evaluate(ids, W, y, cats, P, ws, bins)
        same_alarm = sum(1 for r in runs if r["first_alarm_s"] == ref[r["execution_id"]]["first_alarm_s"])
        same_share = sum(1 for r in runs if r["blocked_share"] == ref[r["execution_id"]]["blocked_share"])
        s12 = summary(runs, y, P[:, -1], pred)
        trf_runs, trf_pred = evaluate(ids, W, y, cats, P, ws, bins, traffic_only=True)
        strf = summary(trf_runs, y, P[:, -1], trf_pred)
        print("ws %.2f as12b: %d runs, %d groups, %.0f s; max |p - study.json| %.4g; first alarm equal %d/%d, share equal "
              "%d/%d" % (ws, len(ids), len(set(g)), time.time() - t0, dp, same_alarm, len(ids), same_share, len(ids)),
              flush=True)
        # all240: the 110 runs plus the 130 without traffic (all-zero windows), the release's labels and groups
        pos = {e: i for i, e in enumerate(ids)}
        meta = {r["execution_id"]: r for r in relrows}
        for e in ids:
            assert meta[e]["cv_group"] == g[pos[e]] and int(meta[e]["label"]) == y[pos[e]], e
        ids2 = [r["execution_id"] for r in relrows]
        W2 = np.zeros((len(ids2), K, W.shape[2]))
        for j, e in enumerate(ids2):
            if e in pos:
                W2[j] = W[pos[e]]
        y2 = np.asarray([int(meta[e]["label"]) for e in ids2])
        g2 = np.asarray([meta[e]["cv_group"] for e in ids2])
        cats2 = [meta[e]["category"] for e in ids2]
        t0 = time.time()
        P2, _ = probabilities(W2, y2, g2, ws, a.jobs, release_eval)
        runs2, pred2 = evaluate(ids2, W2, y2, cats2, P2, ws, bins)
        s240_110 = summary(runs2, y2, P2[:, -1], pred2, subset=set(ids))
        s240 = summary(runs2, y2, P2[:, -1], pred2)
        trf2, trfp2 = evaluate(ids2, W2, y2, cats2, P2, ws, bins, traffic_only=True)
        s240_trf = summary(trf2, y2, P2[:, -1], trfp2, subset=set(ids))
        zero_p = [float(P2[j, k]) for j, e in enumerate(ids2) for k in range(K) if not (W2[j, :k + 1] != 0).any()]
        print("ws %.2f all240: %d runs, %d groups, %.0f s; p on an empty prefix: median %.3f, max %.3f" % (
            ws, len(ids2), len(set(g2)), time.time() - t0, float(np.median(zero_p)), max(zero_p)), flush=True)
        result["sizes"][str(ws)] = dict(
            windows=K, prefixes=pref,
            reproduction=dict(max_abs_p_diff_vs_study_json=dp, first_alarm_equal=same_alarm, share_equal=same_share,
                              runs=len(ids), study_json_floods_and_malware=dict(
                                  floods=round(float(np.mean([ref[e]["blocked_share"] for e in ids
                                                              if ref[e]["category"] == "network_attack"])), 4),
                                  malware=round(float(np.mean([ref[e]["blocked_share"] for e in ids
                                                               if ref[e]["category"] == "malware"])), 4))),
            as12b=s12, traffic_only_alarms=strf, all240_on_the_110=s240_110, all240=s240,
            all240_traffic_only_on_the_110=s240_trf,
            all240_empty_prefix_p=dict(median=round(float(np.median(zero_p)), 4), max=round(max(zero_p), 4),
                                       n=len(zero_p)),
            runs=dict(as12b=runs, traffic_only=trf_runs, all240=runs2))
    (out / "rerun_12b.json").write_text(json.dumps(result, indent=1) + "\n")
    hdr = ("| Window | Variant | Run-level BA (AUC) | Attacks alarmed | Benign alarmed | First alarm (median) | "
           "Alarmed before any traffic | Floods blocked (mean) | Malware blocked (mean) |")
    lines = [hdr, "|" + "---|" * 9]
    for ws in reversed(SIZES):
        s = result["sizes"][str(ws)]
        for name, key in (("12B (110 runs)", "as12b"), ("12B, alarms only on traffic", "traffic_only_alarms"),
                          ("trained on all 240, the 110", "all240_on_the_110"), ("trained on all 240, all 240", "all240")):
            v = s[key]
            lines.append("| %.2f s | %s | %.3f (%.3f) | %d/%d | %d/%d | %s | %d | %s | %s |" % (
                ws, name, v["balanced_accuracy"], v["auc"], v["attacks_alarmed"], v["attacks"], v["benign_alarmed"],
                v["benign"], "%.2f s" % v["first_alarm_median_s"] if v["first_alarm_median_s"] is not None else "-",
                v["alarmed_before_traffic"]["attacks"] + v["alarmed_before_traffic"]["benign"],
                "%.0f%%" % (100 * v["floods_blocked_mean"]) if v["floods_blocked_mean"] is not None else "-",
                "%.0f%%" % (100 * v["malware_blocked_mean"]) if v["malware_blocked_mean"] is not None else "-"))
    (out / "rerun_12b.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
