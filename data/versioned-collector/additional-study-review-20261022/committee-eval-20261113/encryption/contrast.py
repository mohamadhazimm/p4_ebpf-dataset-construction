"""Two-group contrast of feature vectors: change between tasks vs spread between repeats of one task (numpy only).

Shared by dataset_http_https.py and sliver_transports.py (the latter cannot import the former: the frozen Sliver
loader puts the release's evaluation/common.py into sys.modules under the name "common").
"""
from itertools import combinations

import numpy as np


def stats(XA, XB, scale):
    """Per column: means, change, pooled within-task SD, complete separation of the two sets of repeats, change in
    units of `scale` (a reference SD per column), relative change against side A."""
    mA, mB = XA.mean(0), XB.mean(0)
    d = mB - mA
    dof = len(XA) + len(XB) - 2
    ss = ((XA - mA) ** 2).sum(0) + ((XB - mB) ** 2).sum(0)
    sdw = np.sqrt(ss / dof) if dof > 0 else np.full_like(d, np.nan)
    if min(len(XA), len(XB)) >= 2:
        sep = (XB.min(0) > XA.max(0)) | (XB.max(0) < XA.min(0))
    else:
        sep = np.zeros_like(d, bool)
    with np.errstate(divide="ignore", invalid="ignore"):
        beyond = np.where(sdw > 0, np.abs(d) > 2 * sdw, d != 0)
        z = np.where(scale > 0, d / np.where(scale > 0, scale, 1), 0.0)
        rel = np.where(np.abs(mA) > 0, d / np.where(np.abs(mA) > 0, np.abs(mA), 1), np.where(d != 0, np.inf, 0.0))
        den = (np.abs(mA) + np.abs(mB)) / 2
        sym = np.where(den > 0, np.abs(d) / np.where(den > 0, den, 1), 0.0)
    return {"mean_a": mA, "mean_b": mB, "delta": d, "sd_within": sdw, "separated": sep, "beyond_2sd": beyond,
            "z": z, "rel_change": rel, "sym_rel": sym}


def distance_summary(ZA, ZB):
    """Euclidean distance between the two means (columns already scaled), mean distance between two repeats of one
    task, and an exact permutation p-value over all relabelings of the runs when each side has >= 3 runs."""
    dist = float(np.linalg.norm(ZB.mean(0) - ZA.mean(0)))
    within = [float(np.linalg.norm(a - b)) for Z in (ZA, ZB) for a, b in combinations(Z, 2)]
    out = {"between_means": dist, "mean_within_pair": float(np.mean(within)) if within else None,
           "max_within_pair": float(np.max(within)) if within else None,
           "n_a": int(len(ZA)), "n_b": int(len(ZB)), "perm_p": None, "perm_relabelings": None}
    if min(len(ZA), len(ZB)) >= 3:
        Z = np.vstack([ZA, ZB])
        n, k = len(Z), len(ZA)
        vals = []
        for idx in combinations(range(n), k):
            m = np.zeros(n, bool)
            m[list(idx)] = True
            vals.append(np.linalg.norm(Z[~m].mean(0) - Z[m].mean(0)))
        vals = np.asarray(vals)
        out["perm_p"] = float((vals >= dist - 1e-12).mean())
        out["perm_relabelings"] = int(len(vals))
    return out


def block_summary(st, idx, names, ZA, ZB, top=5):
    sel = {k: v[idx] for k, v in st.items()}
    az = np.abs(sel["z"])
    order = np.argsort(-az)[:top]
    return {"columns": int(len(idx)), "changed": int((sel["delta"] != 0).sum()),
            "beyond_2sd_within": int(sel["beyond_2sd"].sum()), "separated": int(sel["separated"].sum()),
            "median_sym_rel_change": float(np.median(sel["sym_rel"])),
            "median_abs_z": float(np.median(az)), "max_abs_z": float(az.max()),
            "largest_z": [[names[idx[j]], round(float(sel["z"][j]), 3), float(sel["mean_a"][j]),
                           float(sel["mean_b"][j])] for j in order],
            "distance": distance_summary(ZA[:, idx], ZB[:, idx])}
