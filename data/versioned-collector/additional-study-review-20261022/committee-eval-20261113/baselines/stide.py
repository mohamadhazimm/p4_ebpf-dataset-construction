"""Pure HIDS baseline: STIDE (Forrest et al. 1996; Hofmeyr, Forrest and Somayaji 1998), unsupervised.

Normal profile = the set of all length-6 system-call sequences of the BENIGN training runs (sliding window over
each thread's token sequence; a thread shorter than 6 calls contributes one sequence padded with an end token).
A test sequence that is not in the profile is a mismatch. Per run:
  * lfc  = maximum locality frame count: largest number of mismatches among any 20 consecutive sequences of a
           thread (Hofmeyr et al.), maximum over all threads of the run (0..20);
  * frac = mismatched sequences / all sequences of the run (0..1).
Threshold (fixed before scoring, training side only): held-out scores of the training-benign runs are obtained by
splitting their groups into 5 inner folds (profile built from the other 4); threshold = 95th percentile of those
held-out scores; a run is flagged when its score is strictly greater. A second operating point uses the maximum
of the held-out scores. The profile used on the test rows is built from all training-benign runs.

Variants: traces as collected (prologue included; primary) and prologue-free (root-process events before its
2nd exec_success dropped). Optional: lookahead pairs (pH/ebpH style): for every call and each of the 7 preceding
calls of the same thread (window 8) the pair (previous call, call, distance); a call is anomalous when any of its
pairs is missing from the benign pair profile; lfc/frac as above over calls.

Protocols: Table V (all 240 rows, ten published fold assignments; only label-0 rows of the training side are
used) and Table IV (the published held-out split; profile from the 77 benign training rows).

    /usr/bin/python3 stide.py [--lookahead]
"""
import argparse
import sys
from multiprocessing import Pool

import numpy as np

import bl_common as B

K = 6          # sequence length (Forrest et al. used 6 in the 1996 paper)
FRAME = 20     # locality frame (Hofmeyr et al. 1998)
LA_WINDOW = 8  # lookahead-pair window (pairs at distances 1..7)

DATA = {}      # filled in the parent before forking the pool


def load_runs(variant):
    """Per run: list of int arrays (dense token ids >= 1), one per thread."""
    raw = []
    for i in range(240):
        z = np.load(B.CACHE / "syscalls" / ("%03d.npz" % i))
        tok, off, rt, pl = z["tok"], z["off"], int(z["root_thread"]), int(z["prologue_len"])
        threads = []
        for t in range(len(off) - 1):
            s = tok[off[t]:off[t + 1]]
            if variant == "prologue_free" and t == rt:
                s = s[pl:]
            if len(s):
                threads.append(s)
        raw.append(threads)
    vocab = np.unique(np.concatenate([np.concatenate(t) for t in raw if t]))
    base = len(vocab) + 1                                  # dense ids 1..V; 0 is the padding/end token
    runs = [[(np.searchsorted(vocab, s) + 1).astype(np.int64) for s in t] for t in raw]
    return runs, base


def seq_codes(runs, base):
    """Per run: (codes of all length-K windows, start position of each window's thread within the run)."""
    assert base ** K < 2 ** 62
    out = []
    for threads in runs:
        codes, starts = [], []
        pos = 0
        for s in threads:
            if len(s) >= K:
                w = np.lib.stride_tricks.sliding_window_view(s, K)
            else:
                w = np.concatenate([s, np.zeros(K - len(s), dtype=np.int64)])[None, :]
            c = np.zeros(len(w), dtype=np.int64)
            for j in range(K):
                c = c * base + w[:, j]
            codes.append(c)
            starts.append(np.full(len(c), pos, dtype=np.int64))
            pos += len(c)
        if codes:
            out.append((np.concatenate(codes), np.concatenate(starts)))
        else:
            out.append((np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.int64)))
    return out


def pair_codes(runs, base):
    """Per run: (pair codes array (n_calls, LA_WINDOW-1) with -1 where no earlier call, thread start per call)."""
    D = LA_WINDOW - 1
    out = []
    for threads in runs:
        codes, starts = [], []
        pos = 0
        for s in threads:
            n = len(s)
            c = np.full((n, D), -1, dtype=np.int64)
            for d in range(1, D + 1):
                if n > d:
                    c[d:, d - 1] = (s[:-d] * base + s[d:]) * LA_WINDOW + d
            codes.append(c)
            starts.append(np.full(n, pos, dtype=np.int64))
            pos += n
        if codes:
            out.append((np.concatenate(codes), np.concatenate(starts)))
        else:
            out.append((np.zeros((0, D), dtype=np.int64), np.zeros(0, dtype=np.int64)))
    return out


def run_scores(codes, starts, profile, pairs):
    """(lfc, frac) of one run against a sorted profile array."""
    n = len(codes)
    if n == 0:
        return 0.0, 0.0
    if pairs:
        valid = codes >= 0
        pos = np.searchsorted(profile, np.where(valid, codes, 0))
        pos = np.minimum(pos, len(profile) - 1)
        hit = (profile[pos] == codes) | ~valid
        mis = (~hit.all(axis=1)).astype(np.int64)
    else:
        pos = np.minimum(np.searchsorted(profile, codes), len(profile) - 1)
        mis = (profile[pos] != codes).astype(np.int64)
    cs = np.concatenate([[0], np.cumsum(mis)])
    idx = np.arange(n)
    lo = np.maximum(idx + 1 - FRAME, starts)
    wsum = cs[idx + 1] - cs[lo]
    return float(wsum.max()), float(mis.sum() / n)


def profile_of(rows_idx):
    u = DATA["uniq"]
    parts = [u[i] for i in rows_idx]
    return np.unique(np.concatenate(parts)) if parts else np.zeros(0, dtype=np.int64)


def score_rows(rows_idx, profile):
    pairs = DATA["pairs"]
    return np.asarray([run_scores(*DATA["codes"][i], profile, pairs) for i in rows_idx]).reshape(-1, 2)


def fit_score(train_benign, test, g):
    """Unsupervised fit on train_benign rows; returns test scores (n_test, 2) and thresholds (2 scores x 2 rules)."""
    inner, k = B.inner_benign_folds(g[train_benign])
    held = np.zeros((len(train_benign), 2))
    for j in range(k):
        prof = profile_of(train_benign[inner != j])
        held[inner == j] = score_rows(train_benign[inner == j], prof)
    thr95 = np.asarray([B.threshold_from(held[:, s]) for s in range(2)])
    thrmax = held.max(axis=0)
    prof = profile_of(train_benign)
    return score_rows(test, prof), thr95, thrmax, len(prof)


def _assignment(k):
    y, g, F = DATA["y"], DATA["g"], DATA["F"]
    n = len(y)
    raw = np.zeros((n, 2)); t95 = np.zeros((n, 2)); tmax = np.zeros((n, 2))
    sizes = []
    for f in range(5):
        tr, te = np.flatnonzero(F[k] != f), np.flatnonzero(F[k] == f)
        trb = tr[y[tr] == 0]
        s, a, b, npf = fit_score(trb, te, g)
        raw[te] = s; t95[te] = a; tmax[te] = b
        sizes.append(npf)
    return k, raw, t95, tmax, sizes


def margin(raw, thr):
    return raw - thr


def run_variant(name, variant, pairs, rows, y, g, cat, split, F):
    runs, base = load_runs(variant)
    DATA.clear()
    DATA.update(y=y, g=g, F=F, pairs=pairs)
    DATA["codes"] = pair_codes(runs, base) if pairs else seq_codes(runs, base)
    DATA["uniq"] = [np.unique(c[c >= 0]) if pairs else np.unique(c) for c, _ in DATA["codes"]]
    B.log(name, "codes ready; base", base, "positions", sum(len(c) for c, _ in DATA["codes"]))
    with Pool(min(B.MAX_JOBS, len(B.C.FOLD_SEEDS))) as p:
        res = p.map(_assignment, range(len(B.C.FOLD_SEEDS)))
    res.sort(key=lambda t: t[0])
    raw = np.stack([r[1] for r in res]); t95 = np.stack([r[2] for r in res]); tmax = np.stack([r[3] for r in res])
    out = {"table5": {}, "table4": {}, "profile_sizes_table5": [r[4] for r in res]}
    for s, sname in enumerate(("lfc", "frac")):
        pred95 = (raw[:, :, s] > t95[:, :, s]).astype(int)
        predmax = (raw[:, :, s] > tmax[:, :, s]).astype(int)
        sc = margin(raw[:, :, s], t95[:, :, s])
        out["table5"][sname] = {"p95": B.summarize_table5(y, cat, sc, pred95),
                                "max": B.summarize_table5(y, cat, margin(raw[:, :, s], tmax[:, :, s]), predmax)}
        B.save_scores("%s_%s_table5" % (name, sname), score=sc, pred=pred95, pred_max=predmax, raw=raw[:, :, s],
                      threshold=t95[:, :, s], threshold_max=tmax[:, :, s], folds=F)
    tr, te = B.table4_split(cat, split)
    trb = tr[y[tr] == 0]
    s4, a4, b4, npf = fit_score(trb, te, g)
    out["table4"]["profile_size"] = npf
    for s, sname in enumerate(("lfc", "frac")):
        pred = (s4[:, s] > a4[s]).astype(int)
        predm = (s4[:, s] > b4[s]).astype(int)
        out["table4"][sname] = {"threshold_p95": float(a4[s]), "threshold_max": float(b4[s]),
                                "p95": B.summarize_table4(y, cat, te, s4[:, s], pred),
                                "max": B.summarize_table4(y, cat, te, s4[:, s], predm)}
        B.save_scores("%s_%s_table4" % (name, sname), test_index=te, score=s4[:, s], pred=pred, pred_max=predm,
                      threshold=a4[s], threshold_max=b4[s])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lookahead", action="store_true", help="also run the optional lookahead-pair variant")
    a = ap.parse_args()
    rows, y, g, cat, split, mode = B.dataset()
    F = B.table5_folds(y, g)
    results = {"settings": {"k": K, "frame": FRAME, "lookahead_window": LA_WINDOW,
                            "threshold": "95th percentile of inner held-out training-benign run scores (5 inner "
                                         "group folds, seed %d); flag if score > threshold" % B.INNER_THRESHOLD_SEED,
                            "second_operating_point": "max of the same held-out scores",
                            "auc_score": "raw score minus the fold's 95th-percentile threshold (pooled out-of-fold)"}}
    todo = [("stide6_collected", "collected", False), ("stide6_prologuefree", "prologue_free", False)]
    if a.lookahead:
        todo += [("lap8_collected", "collected", True)]
    for name, variant, pairs in todo:
        B.log("variant", name)
        results[name] = run_variant(name, variant, pairs, rows, y, g, cat, split, F)
        for s in ("lfc", "frac"):
            t5 = results[name]["table5"][s]["p95"]; t4 = results[name]["table4"][s]["p95"]
            B.log("  %-22s %-4s TableV BA %s AUC %s | TableIV BA %.3f AUC %.3f" % (
                name, s, B.fmt(t5["balanced_accuracy"]), B.fmt(t5["auc"]), t4["balanced_accuracy"], t4["auc"]))
    B.write_json(B.RESULTS / "stide.json", results)


if __name__ == "__main__":
    sys.exit(main())
