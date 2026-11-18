"""Bags of system-call 1-, 2- and 3-grams per run (input of the supervised n-gram HIDS).

n-grams are taken inside each thread's token sequence (cache/syscalls, ABI-tagged tokens), never across threads.
Variants: "collected" (traces as recorded, launcher prologue included, like the thesis's host features),
"prologue_free" (root-process events before its 2nd exec_success removed), and the diagnostic "startup50" (only the
first 50 calls of the target program in the root thread, i.e. its runtime/C-library start-up; used to measure how
much a start-up fingerprint alone separates the classes) and its complement "nostart50" (all threads, with the
launcher prologue and those 50 start-up calls removed from the root thread).

The vocabulary is NOT fixed here: vocab(...) selects, from the training rows of a fold only, the n-grams that
occur in at least MIN_DF training runs; matrix(...) builds log1p(count) features over that vocabulary.
"""
import numpy as np
from scipy import sparse

import bl_common as B

MIN_DF = 2
BASE = 1024          # tokens are < 2048 (abi << 10 | id); dense ids below keep codes small
SHIFT = 1 << 40      # code = n * SHIFT + packed tokens


def _runs(variant):
    raw = []
    for i in range(240):
        z = np.load(B.CACHE / "syscalls" / ("%03d.npz" % i))
        tok, off, rt, pl = z["tok"], z["off"], int(z["root_thread"]), int(z["prologue_len"])
        th = []
        for t in range(len(off) - 1):
            s = tok[off[t]:off[t + 1]].astype(np.int64)
            if variant == "prologue_free" and t == rt:
                s = s[pl:]
            if variant == "startup50":
                s = s[pl:pl + 50] if t == rt else s[:0]
            if variant == "nostart50" and t == rt:
                s = s[pl + 50:]
            if len(s):
                th.append(s)
        raw.append(th)
    vocab = np.unique(np.concatenate([np.concatenate(t) for t in raw if t]))
    assert len(vocab) < BASE
    return [[np.searchsorted(vocab, s) + 1 for s in th] for th in raw], vocab


def bags(variant):
    """Per run: (sorted unique n-gram codes, counts). Cached in cache/ngrams_<variant>.npz."""
    path = B.CACHE / ("ngrams_%s.npz" % variant)
    if path.exists():
        z = np.load(path)
        off = z["off"]
        return [(z["codes"][off[i]:off[i + 1]], z["counts"][off[i]:off[i + 1]]) for i in range(len(off) - 1)]
    runs, vocab = _runs(variant)
    out = []
    for th in runs:
        parts = []
        for s in th:
            parts.append(SHIFT * 1 + s)
            if len(s) >= 2:
                parts.append(SHIFT * 2 + s[:-1] * BASE + s[1:])
            if len(s) >= 3:
                parts.append(SHIFT * 3 + (s[:-2] * BASE + s[1:-1]) * BASE + s[2:])
        c, n = np.unique(np.concatenate(parts), return_counts=True) if parts else (np.zeros(0, np.int64),
                                                                                      np.zeros(0, np.int64))
        out.append((c.astype(np.int64), n.astype(np.int64)))
    off = np.cumsum([0] + [len(c) for c, _ in out])
    np.savez_compressed(path, codes=np.concatenate([c for c, _ in out]), counts=np.concatenate([n for _, n in out]),
                        off=off, token_vocab=vocab)
    return out


def vocab(bag, train_idx, min_df=MIN_DF):
    codes = np.concatenate([bag[i][0] for i in train_idx])
    u, df = np.unique(codes, return_counts=True)
    return u[df >= min_df]


def matrix(bag, idx, voc):
    """CSR matrix (len(idx) x len(voc)) of log1p(counts)."""
    indptr, indices, data = [0], [], []
    for i in idx:
        c, n = bag[i]
        pos = np.searchsorted(voc, c)
        pos = np.minimum(pos, len(voc) - 1)
        keep = voc[pos] == c if len(voc) else np.zeros(len(c), bool)
        indices.append(pos[keep]); data.append(np.log1p(n[keep].astype(np.float64)))
        indptr.append(indptr[-1] + int(keep.sum()))
    ind = np.concatenate(indices) if indices else np.zeros(0, np.int64)
    dat = np.concatenate(data) if data else np.zeros(0)
    return sparse.csr_matrix((dat, ind, np.asarray(indptr)), shape=(len(idx), len(voc)))
