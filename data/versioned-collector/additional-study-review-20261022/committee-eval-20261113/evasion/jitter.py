"""Randomized-timing evasion (committee item 8, addendum to evasion.py). Offline, read-only on the data.

Only the packet timing of malicious executions (malware and network attacks) is changed; host features and
benign rows stay as recorded. Detectors are trained on unmodified data with the Table V protocol (ten fold
assignments, grouped 5-fold), exactly as evasion.py does (same model code: compute_oof._fit_stream_models /
_predict_stream); the malicious test rows of each fold are scored with their re-timed network features.

Packets considered: the IPv4 TCP/UDP frames of the run's capture inside its 20-s observation
[sample_started_wall_us, +20 s) - the packets the switch model counts. Each re-timing gives new whole-microsecond
offsets; the packets are then fed in time order (stable sort: ties keep capture order) through the release's
switch model exactly as evasion.slowed_network does (FlowTable(0.5 s, TTL 3), Ethernet frame bytes, nominal
rates, window = offset // 0.5 s from the same anchor, timestamp (start + offset) / 1e6).

  jitter|J        every packet delayed by U(0, J) s, then re-sorted; packets pushed past the observation end
                  are dropped (counted)                                                    J = 0.1, 0.5, 2, 5
  jitterflow|J    sensitivity: the same delays, but each bidirectional flow keeps its packet order (its delayed
                  times are sorted and given to its packets in capture order), so no reply precedes its request
  expgap          the same packets in the same order, re-timed with exponential inter-packet gaps scaled to span
                  the observation (N+1 gaps, i.e. a Poisson process conditioned on N arrivals in 20 s): the count
                  is kept, nothing is dropped
Three random draws per variant (fixed seeds, below); recall is reported per draw and as their mean.

Checks before any result:
  * identity re-timing reproduces the dataset's 145 network columns of every malicious row and is bit-identical to
    evasion.slowed_network(i, 1); re-timing by off * s is bit-identical to evasion.slowed_network(i, s), s in RATE_S
  * the unmodified out-of-fold probabilities equal cache/cv_published_k40.npz, and the unmodified and slowed (rate)
    recalls equal results/evasion.json

    /usr/bin/python3 evasion/jitter.py [--jobs 10]
"""
import argparse
import hashlib
import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402
import evasion as E  # noqa: E402  (sets the release features/ path, provides slowed_network)
from compute_oof import _fit_stream_models, _predict_stream  # noqa: E402

SM = E.SM
OBS_US, WIN_US = 20_000_000, 500_000
JS = [0.1, 0.5, 2, 5]
DRAWS = [0, 1, 2]
RATE_S = [2, 5, 10, 50]          # evasion.py's slowing factors, used as a check of this path
BASE_SEED = 20261115
EXP_CODE = 999_999
D = {}


def draw_rng(i, code, draw):
    """Fixed, independent random stream per (row, variant, draw)."""
    return np.random.default_rng([BASE_SEED, int(i), int(code), int(draw)])


def packets(i):
    """Start (us since epoch) and the IPv4 TCP/UDP packets of row i inside the observation, in capture order."""
    out = C.output_dir(D["dirs"][i])
    start = int(json.loads((out / "run.json").read_text())["sample_started_wall_us"])
    off, pk, ln, keys = [], [], [], []
    for time_us, ts, frame in SM.read_pcap(out / "packet_capture.pcap"):
        o = time_us - start
        if o < 0 or o >= OBS_US:
            continue
        p = SM.parse_flow_packet(frame)
        if p is None:
            continue
        off.append(o); pk.append(p); ln.append(len(frame))
        source, destination, protocol, ports, _ = p
        keys.append((protocol, *sorted(((source, ports[0]), (destination, ports[1])))))
    off = np.asarray(off, np.int64)
    # a few captures hold timestamps up to ~0.1 ms out of order (never across a window boundary); the release
    # model and evasion.slowed_network process packets in capture order, so order-preserving re-timings do too
    w = off // WIN_US
    assert (np.diff(w) >= 0).all(), "packet order crosses a window boundary: row %d" % i
    return start, off, pk, np.asarray(ln, np.int64), keys


def features(start, new_off, keep, pk, ln, order=None):
    """145 network columns from re-timed packets, the same way as evasion.slowed_network.

    order: processing order; None = capture order (identity, slowing, expgap: order-preserving re-timings),
    else the stable time sort of the jittered packets."""
    order = np.arange(len(new_off)) if order is None else order
    table = SM.FlowTable(0.5, 3)
    res, cur = [], 0
    for j in order:
        if not keep[j]:
            continue
        o = int(new_off[j])
        wdx = o // WIN_US
        while cur < wdx:
            res.append(table.read_window(cur)); cur += 1
        table.update(wdx, (start + o) / 1e6, *pk[j], int(ln[j]))
    while cur < 40:
        res.append(table.read_window(cur)); cur += 1
    arr = np.asarray([[r[f] for f in SM.FEATURES] for r in res])
    cols = [SM.FEATURES.index(s) for s in C.signals(D["net_cols"])]
    return C.summarize(arr[None][:, :, cols])[0]


def flow_order_times(new_off, keys):
    """Give each flow's sorted delayed times to its packets in capture order (packets are in capture order)."""
    out = np.empty_like(new_off)
    members = {}
    for j, k in enumerate(keys):
        members.setdefault(k, []).append(j)
    for idx in members.values():
        idx = np.asarray(idx)
        out[idx] = np.sort(new_off[idx])
    return out


def row_job(i):
    t0 = time.time()
    start, off, pk, ln, keys = packets(i)
    n = len(off)
    ref = C.matrix([D["rows"][i]], D["net_cols"])[0]
    every = np.ones(n, bool)
    ident = features(start, off, every, pk, ln)
    d = np.diff(off)
    chk = {"n_packets": n, "timestamp_inversions": int((d < 0).sum()),
           "max_inversion_us": int(-d.min()) if n > 1 and (d < 0).any() else 0,
           "identity_max_abs_diff_vs_dataset": float(np.abs(ident - ref).max()),
           "identity_allclose_dataset": bool(np.allclose(ident, ref, rtol=1e-12, atol=1e-12)),
           "identity_equals_slowed_1": bool(np.array_equal(ident, E.slowed_network(i, 1))),
           "rate_equals_slowed": {}}
    feats, drops = {}, {}
    for s in RATE_S:
        f = features(start, off * s, off * s < OBS_US, pk, ln)
        chk["rate_equals_slowed"][str(s)] = bool(np.array_equal(f, E.slowed_network(i, s)))
        feats["rate|%d" % s] = f
    for draw in DRAWS:
        for J in JS:
            cj, cf = "jitter|%g|d%d" % (J, draw), "jitterflow|%g|d%d" % (J, draw)
            if not n:
                feats[cj] = feats[cf] = ident
                drops[cj] = 0
                continue
            rng = draw_rng(i, int(round(J * 1000)), draw)
            delay = rng.integers(0, int(round(J * 1e6)), size=n, dtype=np.int64)  # U(0, J), whole microseconds
            jit = off + delay
            keep = jit < OBS_US
            feats[cj] = features(start, jit, keep, pk, ln, np.argsort(jit, kind="stable"))
            flo = flow_order_times(jit, keys)
            feats[cf] = features(start, flo, flo < OBS_US, pk, ln, np.argsort(flo, kind="stable"))
            drops[cj] = int((~keep).sum())
            assert int((flo >= OBS_US).sum()) == drops[cj]  # same delayed times per flow, so the same count
        ce = "expgap|d%d" % draw
        if not n:
            feats[ce] = ident
            drops[ce] = 0
            continue
        rng = draw_rng(i, EXP_CODE, draw)
        gaps = rng.exponential(1.0, n + 1)
        cs = np.cumsum(gaps)
        t = np.floor(cs[:n] / cs[n] * OBS_US).astype(np.int64)
        t = np.minimum(t, OBS_US - 1)  # guard against a rounded 1.0 (probability ~0)
        assert (np.diff(t) >= 0).all()
        feats[ce] = features(start, t, every, pk, ln)
        drops[ce] = 0
    chk["seconds"] = round(time.time() - t0, 1)
    return int(i), feats, drops, chk


def cv_job(seed):
    """Table V fold assignment `seed`: unmodified OOF for every row, and every perturbed config for malicious rows."""
    y, g, Xh, Xn, pert = D["y"], D["g"], D["Xh"], D["Xn"], D["perturbed"]
    cfgs = sorted(pert)
    mal = np.flatnonzero(y == 1)
    oof = {d: np.zeros(len(y)) for d in C.DETECTORS}
    res = {cfg: {} for cfg in cfgs}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        models = _fit_stream_models(Xh, Xn, y, g, tr)
        te_m = np.intersect1d(te, mal)
        blocks_h = [Xh[te]] + [Xh[te_m]] * len(cfgs)
        blocks_n = [Xn[te]] + [np.stack([pert[cfg][int(i)] for i in te_m]) for cfg in cfgs]
        P = _predict_stream(models, np.vstack(blocks_h), np.vstack(blocks_n))
        for d in C.DETECTORS:
            oof[d][te] = P[d][:len(te)]
        base = len(te)
        for b, cfg in enumerate(cfgs):
            for j, i in enumerate(te_m):
                res[cfg][int(i)] = {d: float(P[d][base + b * len(te_m) + j]) for d in C.DETECTORS}
    return seed, oof, res


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def recall_of(cv, cfg, members):
    """Share of (assignment, row) pairs flagged at 0.5, per detector, over the given malicious rows."""
    out = {}
    for d in C.DETECTORS:
        v = [cv[s][cfg][int(i)][d] >= 0.5 for s in C.FOLD_SEEDS for i in members]
        out[d] = float(np.mean(v)) if v else None
    return out


def r3(x):
    return None if x is None else round(float(x), 3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=10)
    a = ap.parse_args()
    jobs = min(10, a.jobs)
    t_start = time.time()
    rows, hc, nc = C.load()
    y = C.labels(rows)
    dirs = C.run_dirs(rows)
    cats = np.asarray([r["category"] for r in rows])
    atype = np.asarray([r["attack_type"] for r in rows])
    E.D.update(rows=rows, host_cols=hc, net_cols=nc, dirs=dirs)  # for evasion.slowed_network (checks)
    D.update(rows=rows, net_cols=nc, dirs=dirs)
    mal = np.flatnonzero(y == 1)
    assert set(cats[mal]) == {"malware", "network_attack"}

    # ------------------------------------------------------------------ features (largest captures first)
    order = sorted(mal, key=lambda i: -(C.output_dir(dirs[i]) / "packet_capture.pcap").stat().st_size)
    with Pool(jobs) as pool:
        out = pool.map(row_job, [int(i) for i in order], chunksize=1)
    perturbed, drops, checks = {}, {}, {}
    for i, feats, dr, chk in out:
        for cfg, f in feats.items():
            perturbed.setdefault(cfg, {})[i] = f
        for cfg, k in dr.items():
            drops.setdefault(cfg, {})[i] = k
        checks[i] = chk
    n_pk = {i: checks[i]["n_packets"] for i in checks}
    Xh, Xn = C.matrix(rows, hc), C.matrix(rows, nc)
    col = nc.index("net_pkts_total_delta__sum")
    chk_feat = {
        "malicious_rows": int(len(mal)),
        "rows_with_packets": int(sum(1 for i in mal if n_pk[int(i)] > 0)),
        "packets_equal_dataset_net_pkts_total_delta_sum": bool(all(n_pk[int(i)] == int(Xn[i, col]) for i in mal)),
        "rows_with_timestamp_inversions": {rows[int(i)]["execution_id"]: [checks[int(i)]["timestamp_inversions"],
                                                                          checks[int(i)]["max_inversion_us"]]
                                           for i in mal if checks[int(i)]["timestamp_inversions"]},
        "identity_allclose_dataset_rtol1e-12": int(sum(checks[int(i)]["identity_allclose_dataset"] for i in mal)),
        "identity_max_abs_diff_vs_dataset": max(checks[int(i)]["identity_max_abs_diff_vs_dataset"] for i in mal),
        "identity_bit_identical_to_slowed_network_1": int(sum(checks[int(i)]["identity_equals_slowed_1"] for i in mal)),
        "rate_bit_identical_to_slowed_network": {str(s): int(sum(checks[int(i)]["rate_equals_slowed"][str(s)] for i in mal))
                                                for s in RATE_S},
    }
    assert chk_feat["packets_equal_dataset_net_pkts_total_delta_sum"]
    assert chk_feat["identity_allclose_dataset_rtol1e-12"] == len(mal)
    assert chk_feat["identity_bit_identical_to_slowed_network_1"] == len(mal)
    assert all(v == len(mal) for v in chk_feat["rate_bit_identical_to_slowed_network"].values())
    print("features done: %d rows, %.0f s" % (len(out), time.time() - t_start), flush=True)

    # ------------------------------------------------------------------ scoring (Table V protocol)
    D.update(y=y, g=C.groups_published(rows), Xh=Xh, Xn=Xn, perturbed=perturbed)
    with Pool(min(jobs, len(C.FOLD_SEEDS))) as pool:
        res = pool.map(cv_job, C.FOLD_SEEDS, chunksize=1)
    oof = {s: o for s, o, _ in res}
    cv = {s: r for s, _, r in res}
    cache = np.load(C.CACHE / "cv_published_k40.npz")
    maxdiff = max(float(np.abs(np.stack([oof[s][d] for s in C.FOLD_SEEDS]) - cache[d]).max()) for d in C.DETECTORS)
    for s in C.FOLD_SEEDS:  # unmodified malicious rows, as scored in the perturbation loop
        cv[s]["__unmodified__"] = {int(i): {d: float(oof[s][d][i]) for d in C.DETECTORS} for i in mal}

    groups = {"malware": mal[cats[mal] == "malware"], "network_attack": mal[cats[mal] == "network_attack"]}
    by_type = {t: mal[atype[mal] == t] for t in ("syn_flood", "udp_flood", "slowloris", "goldeneye")}
    ref_json = json.loads((C.HERE / "results" / "evasion.json").read_text())
    unmod = {c: {d: r3(v) for d, v in recall_of(cv, "__unmodified__", m).items()} for c, m in groups.items()}
    rates = {"rate|%d" % s: {c: {d: r3(v) for d, v in recall_of(cv, "rate|%d" % s, m).items()}
                             for c, m in groups.items()} for s in RATE_S}
    chk_score = {
        "unmodified_oof_max_abs_diff_vs_cache_cv_published_k40": maxdiff,
        "unmodified_recall_equals_evasion_json_reference": unmod == ref_json["reference"],
        "rate_recalls_equal_evasion_json": {k: v == ref_json[k] for k, v in rates.items()},
    }
    assert maxdiff == 0.0, maxdiff
    assert chk_score["unmodified_recall_equals_evasion_json_reference"], (unmod, ref_json["reference"])
    assert all(chk_score["rate_recalls_equal_evasion_json"].values()), rates

    # ------------------------------------------------------------------ results
    variants = ["jitter|%g" % J for J in JS] + ["jitterflow|%g" % J for J in JS] + ["expgap"]

    def cfg_names(v):
        return [("%s|d%d" % (v, d)) for d in DRAWS]

    recall = {"unmodified": {**unmod, "by_attack_type": {t: {d: r3(x) for d, x in recall_of(cv, "__unmodified__", m).items()}
                                                           for t, m in by_type.items()}}}
    for v in variants:
        rec = {}
        for cname, members in list(groups.items()) + [("by_attack_type::" + t, m) for t, m in by_type.items()]:
            per = [recall_of(cv, c, members) for c in cfg_names(v)]
            rec[cname] = {d: {"mean": r3(np.mean([p[d] for p in per])), "min": r3(min(p[d] for p in per)),
                              "max": r3(max(p[d] for p in per)), "draws": [r3(p[d]) for p in per]}
                          for d in C.DETECTORS}
        recall[v] = rec
    dropped = {}
    for v in ["jitter|%g" % J for J in JS] + ["expgap"]:
        dv = {}
        for cname, members in groups.items():
            tot = sum(n_pk[int(i)] for i in members)
            per = [sum(drops[c][int(i)] for i in members) for c in cfg_names(v)]
            share_rows = [float(np.mean([drops[c][int(i)] / n_pk[int(i)] for i in members if n_pk[int(i)]]))
                          for c in cfg_names(v)]
            dv[cname] = {"packets_in_observation": int(tot), "dropped_per_draw": per,
                         "dropped_share_pooled_mean": r3(np.mean(per) / tot) if tot else None,
                         "dropped_share_mean_over_rows_with_traffic": r3(np.mean(share_rows))}
        dropped[v] = dv
    files = {
        "features.csv": C.FEATURES, "independent_pool.json": C.POOL, "common.py": C.HERE / "common.py",
        "compute_oof.py": C.HERE / "compute_oof.py", "evasion.py": C.HERE / "evasion" / "evasion.py",
        "fasthost.py": C.HERE / "evasion" / "fasthost.py", "switch_model.py": Path(SM.__file__),
        "jitter.py": Path(__file__).resolve(), "results/evasion.json": C.HERE / "results" / "evasion.json",
        "cache/cv_published_k40.npz": C.CACHE / "cv_published_k40.npz",
    }
    summary = {
        "protocol": {
            "what": "randomized packet timing of malicious executions; host features, benign rows and training unchanged",
            "detectors": "RF500 balanced seed 42 host / network / concatenated; stacked = LR on inner OOF (seed 7)",
            "cv": "Table V: StratifiedGroupKFold(5, shuffle) fold seeds %s, published cv_group" % C.FOLD_SEEDS,
            "threshold": 0.5,
            "recall": "share of (fold assignment, malicious row) pairs flagged; all malicious rows counted, "
                      "rows without packets keep their features",
            "packets": "IPv4 TCP/UDP frames with offset in [0, 20 s) from sample_started_wall_us",
            "variants": {"jitter|J": "offset += U(0, J) s (whole us), stable re-sort, offsets >= 20 s dropped",
                         "jitterflow|J": "same delays; each bidirectional flow keeps its packet order",
                         "expgap": "same order, offsets = 20 s * S_k / S_(N+1), S = cumulative Exp(1) gaps"},
            "J_seconds": JS, "draws": DRAWS,
            "seeds": "np.random.default_rng([%d, row, code, draw]); code = round(J*1000) for jitter (shared by "
                     "jitterflow), %d for expgap" % (BASE_SEED, EXP_CODE),
        },
        "checks": {**chk_feat, **chk_score},
        "baseline_evasion_json_reference": ref_json["reference"],
        "recall": recall,
        "slowed_reproduced_from_evasion_json": rates,
        "dropped_packets": dropped,
        "per_row_packets_in_observation": {rows[int(i)]["execution_id"]: n_pk[int(i)] for i in mal},
        "inputs_sha256": {k: sha256(p) for k, p in files.items()},
        "runtime_seconds": round(time.time() - t_start, 1),
    }
    C.write_json(C.HERE / "results" / "evasion_jitter.json", summary)
    print("wrote results/evasion_jitter.json in %.0f s" % (time.time() - t_start))


if __name__ == "__main__":
    main()
