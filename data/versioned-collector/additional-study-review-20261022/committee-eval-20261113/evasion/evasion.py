"""Evasion analysis (committee item 8). Offline simulations on the recorded executions.

Only malicious executions are changed; the attacker controls its own process tree, not the monitor's
launcher (the prologue is left untouched). Detectors are trained on unmodified data (Table V protocol: ten
fold assignments, grouped 5-fold); the malicious test rows are scored with modified features, benign test
rows are unchanged, so any loss is a loss of recall.

Host-side (network features unchanged)
  pad_append_f     after each (window, process) burst, f x n calls of the most common benign system call
  pad_interleave_f f calls of that system call after every own call
  pad_benign_f     after each burst, f x n calls copied from real benign processes of the same ABI (mimicry)
  split_within_N   each burst split into N consecutive parts run by N processes of the monitored tree
  split_across_N   the work split into N separate process trees, each judged on its own (detected if any is)
Network-side (host features unchanged)
  rate_s           traffic slowed s times (inter-packet gaps x s); what no longer fits in 20 s is not seen
Both
  pad_benign_5+rate_10

    /usr/bin/python3 evasion.py [--jobs 4]
"""
import argparse
import json
import sys
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C  # noqa: E402
import fasthost as FH  # noqa: E402
import switch_model as SM  # noqa: E402
from compute_oof import _fit_stream_models, _predict_stream  # noqa: E402

PAD_F = [0.5, 1, 2, 5, 10]
INTERLEAVE_F = [1, 2, 5]
SPLIT_N = [2, 4, 8, 16]
ACROSS_N = [2, 4, 8]
RATE_S = [2, 5, 10, 50]
D = {}


def abi(mode):
    return "i386" if mode.startswith("i386") else "amd64"


def benign_templates(rows):
    """Most common benign system call and a long benign call sequence (non-prologue), per ABI."""
    counts, seqs = {"amd64": Counter(), "i386": Counter()}, {"amd64": [], "i386": []}
    for i, r in enumerate(rows):
        if r["category"] != "benign":
            continue
        w, p, s, root, pro = FH.load_events(i)
        a = abi(r["mode"])
        own = s[~pro]
        counts[a].update(own.tolist())
        seqs[a].append(own)
    return ({a: counts[a].most_common(1)[0][0] for a in counts},
            {a: np.concatenate(seqs[a]) for a in seqs})


def perturb_host(i, kind, level, pad_id, template, rng):
    """Host columns (90) of row i after the perturbation; for split_across, a list of part columns."""
    w, p, s, root, pro = FH.load_events(i)
    order = np.arange(len(w), dtype=np.int64) * 64  # room to insert up to 63 calls after each call
    hc = D["host_cols"]
    if not (~pro).any():  # the program made no call of its own (crashed at start): nothing to change
        x = FH.to_columns(FH.host_windows(w, p, s), hc)
        return [x] if kind == "split_across" else x
    if kind in ("pad_append", "pad_benign"):
        own = ~pro
        idx, gid, gstart, rank = FH.group_structure(w[own], p[own])
        n_g = np.diff(np.append(gstart, own.sum()))
        m_g = np.round(level * n_g).astype(int)
        gw, gp = w[own][idx][gstart], p[own][idx][gstart]
        last_order = order[own][idx][np.append(gstart[1:], own.sum()) - 1]
        total = int(m_g.sum())
        pw, pp = np.repeat(gw, m_g), np.repeat(gp, m_g)
        within = np.arange(total) - np.repeat(np.cumsum(m_g) - m_g, m_g)
        if kind == "pad_append":
            ps = np.full(total, pad_id)
        else:
            start = rng.integers(0, max(1, len(template) - 1), size=len(m_g))
            ps = template[(np.repeat(start, m_g) + within) % len(template)]
        # padded calls come right after the burst's last own call: fractional offsets in a float order key
        po = np.repeat(last_order, m_g).astype(float) + (within + 1) / (np.repeat(m_g, m_g) + 1.0)
        W = np.concatenate([w, pw]); P = np.concatenate([p, pp]); S = np.concatenate([s, ps])
        O = np.concatenate([order.astype(float), po])
        return FH.to_columns(FH.host_windows(W, P, S, order=O), hc)
    if kind == "pad_interleave":
        own = np.flatnonzero(~pro)
        k = int(level)
        pw, pp = np.repeat(w[own], k), np.repeat(p[own], k)
        po = np.repeat(order[own], k) + np.tile(np.arange(1, k + 1), len(own))
        W = np.concatenate([w, pw]); P = np.concatenate([p, pp]); S = np.concatenate([s, np.full(len(pw), pad_id)])
        O = np.concatenate([order, po])
        return FH.to_columns(FH.host_windows(W, P, S, order=O), hc)
    if kind in ("split_within", "split_across"):
        N = int(level)
        own = ~pro
        idx, gid, gstart, rank = FH.group_structure(w[own], p[own])
        n_g = np.diff(np.append(gstart, own.sum()))
        chunk_sorted = (rank * N) // n_g[gid]
        chunk = np.empty(own.sum(), int); chunk[idx] = chunk_sorted
        if kind == "split_within":
            P = p.copy()
            newpid = np.where(chunk == 0, p[own], p[own] * N + chunk + (1 << 30))  # part 0 stays in the process
            P[own] = newpid
            return FH.to_columns(FH.host_windows(w, P, s), hc)
        parts = []
        own_idx = np.flatnonzero(own)
        for j in range(N):
            keep = pro.copy()  # every tree is started the same way, so each carries the launcher's prologue
            keep[own_idx[chunk == j]] = True
            parts.append(FH.to_columns(FH.host_windows(w[keep], p[keep], s[keep]), hc))
        return parts
    raise ValueError(kind)


def slowed_network(i, factor):
    out = C.output_dir(D["dirs"][i])
    start = int(json.loads((out / "run.json").read_text())["sample_started_wall_us"])
    win_us = 500_000
    table = SM.FlowTable(0.5, 3)
    res, cur = [], 0
    for time_us, ts, frame in SM.read_pcap(out / "packet_capture.pcap"):
        off = time_us - start
        if off < 0:
            continue
        off2 = off * factor
        if off2 // win_us >= 40:
            break
        wdx = off2 // win_us
        while cur < wdx:
            res.append(table.read_window(cur)); cur += 1
        pk = SM.parse_flow_packet(frame)
        if pk is not None:
            table.update(wdx, (start + off2) / 1e6, *pk, len(frame))  # == ts for factor 1 (correctly rounded)
    while cur < 40:
        res.append(table.read_window(cur)); cur += 1
    arr = np.asarray([[r[f] for f in SM.FEATURES] for r in res])
    order = [SM.FEATURES.index(s) for s in C.signals(D["net_cols"])]
    return C.summarize(arr[None][:, :, order])[0]


def feature_job(args):
    i, kind, level = args
    rng = np.random.default_rng(1000 + i)
    a = abi(D["rows"][i]["mode"])
    if kind == "rate":
        return i, kind, level, slowed_network(i, int(level))
    return i, kind, level, perturb_host(i, kind, level, D["pad"][a], D["template"][a], rng)


def cv_job(seed):
    y, g, Xh, Xn = D["y"], D["g"], D["Xh"], D["Xn"]
    mal = np.flatnonzero(y == 1)
    out = {}
    for tr, te in StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(Xh, y, g):
        models = _fit_stream_models(Xh, Xn, y, g, tr)
        te_m = np.intersect1d(te, mal)
        for cfg, feats in D["perturbed"].items():
            kind = cfg.split("|")[0]
            for i in te_m:
                h, n = Xh[i:i + 1], Xn[i:i + 1]
                if kind == "rate":
                    n = feats[i][None]
                elif kind == "both":
                    h, n = feats[i][0][None], feats[i][1][None]
                elif kind == "split_across":
                    parts = np.asarray(feats[i])
                    P = _predict_stream(models, parts, np.repeat(n, len(parts), 0))
                    out.setdefault(cfg, {}).setdefault(int(i), []).append({d: float(P[d].max()) for d in C.DETECTORS})
                    continue
                else:
                    h = feats[i][None]
                P = _predict_stream(models, h, n)
                out.setdefault(cfg, {}).setdefault(int(i), []).append({d: float(P[d][0]) for d in C.DETECTORS})
    return seed, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()
    rows, hc, nc = C.load()
    y = C.labels(rows)
    dirs = C.run_dirs(rows)
    pad, template = benign_templates(rows)
    D.update(rows=rows, host_cols=hc, net_cols=nc, dirs=dirs, pad=pad, template=template)
    mal = np.flatnonzero(y == 1)
    # sanity: no perturbation (f=0, N=1, s=1) reproduces the dataset
    chk = perturb_host(int(mal[0]), "pad_append", 0.0, pad["amd64"], template["amd64"], np.random.default_rng(0))
    assert np.allclose(chk, C.matrix([rows[mal[0]]], hc)[0]), "f=0 does not reproduce the row"
    chk = slowed_network(int(mal[0]), 1)
    assert np.allclose(chk, C.matrix([rows[mal[0]]], nc)[0], rtol=1e-12, atol=1e-12), "rate 1 does not reproduce the row"
    for i in mal[:20]:
        ref = C.matrix([rows[i]], hc)[0]
        for kind in ("split_within", "split_across"):
            got = perturb_host(int(i), kind, 1, pad["amd64"], template["amd64"], np.random.default_rng(0))
            got = got[0] if kind == "split_across" else got
            assert np.allclose(got, ref, rtol=1e-12, atol=1e-12), (kind, i)
    netmal = [int(i) for i in mal if C.matrix([rows[i]], ["net_pkts_total_delta__sum"])[0, 0] > 0]
    jobs = ([(int(i), k, f) for i in mal for k, fs in (("pad_append", PAD_F), ("pad_benign", PAD_F),
                                                       ("pad_interleave", INTERLEAVE_F), ("split_within", SPLIT_N),
                                                       ("split_across", ACROSS_N)) for f in fs]
            + [(i, "rate", s) for i in netmal for s in RATE_S])
    with Pool(a.jobs) as pool:
        res = pool.map(feature_job, jobs, chunksize=4)
    Xh, Xn = C.matrix(rows, hc), C.matrix(rows, nc)
    perturbed = {}
    for i, kind, level, f in res:
        perturbed.setdefault("%s|%s" % (kind, level), {})[i] = f
    for cfg in [c for c in perturbed if c.startswith("rate|")]:  # rows without traffic: unchanged
        for i in mal:
            perturbed[cfg].setdefault(int(i), Xn[i])
    perturbed["both|pad_benign5+rate10"] = {int(i): (perturbed["pad_benign|5"][int(i)], perturbed["rate|10"][int(i)]) for i in mal}
    D.update(y=y, g=C.groups_published(rows), Xh=Xh, Xn=Xn, perturbed=perturbed)
    with Pool(min(10, a.jobs * 2)) as pool:
        cv = dict(pool.map(cv_job, C.FOLD_SEEDS, chunksize=1))
    cats = np.asarray([r["category"] for r in rows])
    P0 = {d: np.load(C.CACHE / "cv_published_k40.npz")[d] for d in C.DETECTORS}  # unperturbed reference
    summary = {"pad_syscall": pad, "reference": {}}
    for cat in ("malware", "network_attack"):
        m = cats == cat
        summary["reference"][cat] = {d: round(float((P0[d][:, m] >= .5).mean()), 3) for d in C.DETECTORS}
    for cfg in sorted(perturbed, key=lambda c: (c.split("|")[0], float(c.split("|")[1]) if c.split("|")[1][0].isdigit() else 0)):
        rec = {}
        for cat in ("malware", "network_attack"):
            vals = {d: [] for d in C.DETECTORS}
            for seed in C.FOLD_SEEDS:
                for i, lst in cv[seed].get(cfg, {}).items():
                    if cats[i] == cat:
                        for d in C.DETECTORS:
                            vals[d].extend(x[d] >= .5 for x in lst)
            rec[cat] = {d: round(float(np.mean(v)), 3) for d, v in vals.items() if v}
        summary[cfg] = rec
    C.write_json(C.HERE / "results" / "evasion.json", summary)
    print("wrote results/evasion.json")


if __name__ == "__main__":
    main()
