"""Supervised n-gram HIDS (and the software hybrid) on the toolchain-matched benign collection. Offline, no VM.

Question. On the 240 released rows the n-gram HIDS scored above the thesis host detector (Table V BA 0.868 vs 0.784),
but the n-grams of the target's first 50 calls alone scored 0.863: it mostly sees how a program was built. With the
benign programs rebuilt with the malware's toolchains (toolchain21-collect/20261113T203411281909Z), the five start-up
flags fell to 0.385 while the thesis host detector stayed at 0.787 (../toolchain/score_toolchain.py). This script asks
the same of the n-gram HIDS and of the software hybrid built on it.

Same rows, groups, splits and folds as score_toolchain.py:
  A transfer:    detectors trained on the 240 released rows, applied to the 85 accepted new benign runs
  B replacement: Table V protocol (10 published fold seeds) with the 87 static benign rows replaced by the new runs
  C held-out:    the released Table IV split with the same replacement; forest seeds 42 and 0-9
  D mixed:       Table V protocol on all 240 rows plus the new runs
Detectors exactly as supervised.py (RandomForest(500, balanced), threshold 0.5; the n-gram vocabulary is the n-grams
present in >= 2 training runs, refit on every training set): ngram (as collected, the published primary variant),
ngram_pf (prologue-free), ngram_startup (n-grams of the target's first 50 calls only), ngram_nostart (without the
prologue and those 50 calls), flow (CICFlowMeter-like), sw_concat, sw_stacked, sw_concat_nostart, sw_stacked_nostart.
The thesis detectors (host, network, concat, stacked) are recomputed on the same pools for paired comparisons.

Checks before any new score:
  1. the new runs pass extract_syscalls.py's gates (2nd root exec = target path, events in the 40 windows = the
     telemetry total, 178-call launcher prologue, syscall numbers < 1024);
  2. the n-gram bags built here equal the cached bags of the 240 rows, n-gram by n-gram, for all four variants;
  3. all nine detectors reproduce the saved Table V and Table IV scores of the 240 rows exactly;
  4. the thesis detectors reproduce ../results/toolchain_scores.json on pools A-D.
The protocol (with the decision rule) is written to results/toolchain_ngram_protocol.json before any score.

    /usr/bin/python3 toolchain_ngram.py ../../toolchain21-collect/20261113T203411281909Z
"""
import collections
import csv
import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from scipy import sparse
from sklearn.model_selection import StratifiedGroupKFold

import bl_common as B
import extract_syscalls as XS
import flow_extract as FE
import ngrams as NG

C = B.C
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "toolchain"))
import score_toolchain as ST  # noqa: E402  new_run(): the thesis features of a new run, as the host test built them

NEW_CACHE = B.CACHE / "syscalls_toolchain"
VARIANTS = {"ngram": "collected", "ngram_pf": "prologue_free", "ngram_startup": "startup50",
            "ngram_nostart": "nostart50"}
BASES = ("ngram", "ngram_pf", "ngram_startup", "ngram_nostart", "flow")
DETS = BASES + ("sw_concat", "sw_stacked", "sw_concat_nostart", "sw_stacked_nostart")
THESIS = ("host", "network", "concat", "stacked")
C_SEEDS = [42, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
LOW_ACTIVITY = 100  # malware with fewer post-target calls (the baselines README's low-activity diagnostic)
D = {}  # pools, shared with forked workers


# ------------------------------------------------------------------------------------------------ inputs
def new_cases(attempt):
    protocol = json.loads((attempt / "protocol.json").read_text())
    val = sorted(attempt.glob("validation-*.json"))[-1]
    accepted = {r["sample"] for r in json.loads(val.read_text())["cases"] if r["status"] == "accepted"}
    out = []
    for c in protocol["cases"]:  # same order as score_toolchain.py
        if c["label"] != "benign" or c["sample"] not in accepted:
            continue
        out.append((c, sorted((attempt / "runs" / c["sample"] / "output").glob("run_*"))[-1]))
    return out, val


def telemetry_total(run):
    tel = list(csv.DictReader(open(run / "telemetry.csv", newline="", encoding="utf-8-sig")))
    assert len(tel) == 40, run
    return int(round(sum(float(r["host_total_syscalls_total"]) for r in tel)))


def sequences(paths, variant):
    """Per run: list of per-thread ABI-tagged token arrays, sliced as ngrams._runs does for `variant`."""
    raw = []
    for p in paths:
        z = np.load(p)
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
    return raw


def bags_from(raw, token_vocab):
    """ngrams.bags coding (1-3-grams inside each thread), dense token ids over the sorted union token_vocab.

    A dense id map over a larger sorted token set is a strictly increasing remap of the cached one, so n-gram codes
    keep their relative order and every training matrix (columns in code order) is unchanged; check 2/3 verify it.
    """
    out = []
    for th in raw:
        parts = []
        for s0 in th:
            s = np.searchsorted(token_vocab, s0) + 1
            assert (token_vocab[s - 1] == s0).all()
            parts.append(NG.SHIFT * 1 + s)
            if len(s) >= 2:
                parts.append(NG.SHIFT * 2 + s[:-1] * NG.BASE + s[1:])
            if len(s) >= 3:
                parts.append(NG.SHIFT * 3 + (s[:-2] * NG.BASE + s[1:-1]) * NG.BASE + s[2:])
        if parts:
            c, n = np.unique(np.concatenate(parts), return_counts=True)
        else:
            c, n = np.zeros(0, np.int64), np.zeros(0, np.int64)
        out.append((c.astype(np.int64), n.astype(np.int64)))
    return out


def decoded(codes, counts, token_vocab):
    """{(n, token, token, token): count} with -1 for absent positions (to compare bags across id maps)."""
    tv = np.concatenate([[-1], token_vocab.astype(np.int64)])
    n, p = codes // NG.SHIFT, codes % NG.SHIFT
    a, b, c = p // (NG.BASE * NG.BASE), (p // NG.BASE) % NG.BASE, p % NG.BASE
    return dict(zip(zip(n.tolist(), tv[a].tolist(), tv[b].tolist(), tv[c].tolist()), counts.tolist()))


# ------------------------------------------------------------------------------------- the detectors
def feats(pool, name, idx, train_idx):
    P = D[pool]
    if name in VARIANTS:
        bag = P["bags"][name]
        return NG.matrix(bag, idx, NG.vocab(bag, train_idx))
    return P["flow"][idx]


def rf_prob(pool, name, tr, te, seed):
    y = D[pool]["y"]
    return C.rf(seed).fit(feats(pool, name, tr, tr), y[tr]).predict_proba(feats(pool, name, te, tr))[:, 1]


def concat_prob(pool, names, tr, te, seed):
    y = D[pool]["y"]
    Xtr = sparse.hstack([sparse.csr_matrix(feats(pool, n, tr, tr)) for n in names]).tocsr()
    Xte = sparse.hstack([sparse.csr_matrix(feats(pool, n, te, tr)) for n in names]).tocsr()
    return C.rf(seed).fit(Xtr, y[tr]).predict_proba(Xte)[:, 1]


def stacked_prob(pool, a, b, tr, te, seed, pa, pb, memo):
    """supervised.stacked_prob: stacker on inner OOF probabilities of RF(a) and RF(b) (inner seed 7)."""
    y, g = D[pool]["y"], D[pool]["g"]
    gt = g[tr]
    ia, ib = np.zeros(len(tr)), np.zeros(len(tr))
    inner = StratifiedGroupKFold(min(5, len(set(gt))), shuffle=True, random_state=C.INNER_SEED)
    for k, (itr, ite) in enumerate(inner.split(np.zeros((len(tr), 1)), y[tr], gt)):
        r, s = tr[itr], tr[ite]
        for name, arr in ((a, ia), (b, ib)):
            if (name, k) not in memo:
                memo[(name, k)] = rf_prob(pool, name, r, s, seed)
            arr[ite] = memo[(name, k)]
    st = C.stacker().fit(np.column_stack([ia, ib]), y[tr])
    return st.predict_proba(np.column_stack([pa, pb]))[:, 1]


def fit_predict(pool, tr, te, seed=42):
    out = {d: rf_prob(pool, d, tr, te, seed) for d in BASES}
    out["sw_concat"] = concat_prob(pool, ("ngram", "flow"), tr, te, seed)
    out["sw_concat_nostart"] = concat_prob(pool, ("ngram_nostart", "flow"), tr, te, seed)
    memo = {}
    out["sw_stacked"] = stacked_prob(pool, "ngram", "flow", tr, te, seed, out["ngram"], out["flow"], memo)
    out["sw_stacked_nostart"] = stacked_prob(pool, "ngram_nostart", "flow", tr, te, seed, out["ngram_nostart"],
                                             out["flow"], memo)
    return out


def job(args):
    kind, pool, k = args
    if kind == "cv":
        y, g = D[pool]["y"], D[pool]["g"]
        n = len(y)
        P, folds = {}, np.full(n, -1)
        seed = C.FOLD_SEEDS[k]
        for f, (tr, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=seed).split(
                np.zeros((n, 1)), y, g)):
            folds[te] = f
            for d, p in fit_predict(pool, tr, te).items():
                P.setdefault(d, np.zeros(n))[te] = p
        B.log("pool", pool, "fold seed", seed, "done")
        return args, P, folds
    P = fit_predict(pool, D[pool]["tr"], D[pool]["te"], seed=k)
    B.log("pool", pool, "forest seed", k, "done")
    return args, P, None


# --------------------------------------------------------------------------------------- summaries
def ba_of(y, prob):
    return C.metrics(y, prob)["balanced_accuracy"]


def cv_summary(y, cats, M, cls=None, low=None):
    """M: (assignments, n) probabilities. BA/AUC over assignments, flag rates by category (mean over them)."""
    bas = [ba_of(y, M[k]) for k in range(M.shape[0])]
    aucs = [C.metrics(y, M[k])["auc"] for k in range(M.shape[0])]
    flag = M >= 0.5
    out = {"ba_mean": float(np.mean(bas)), "ba_sd": float(np.std(bas, ddof=1)) if len(bas) > 1 else 0.0,
           "ba_min": float(np.min(bas)), "ba_max": float(np.max(bas)), "ba_by_assignment": [float(b) for b in bas],
           "auc_mean": float(np.mean(aucs)),
           "flagged_by_category": {c: float(flag[:, cats == c].mean()) for c in sorted(set(cats))}}
    if cls is not None:
        m = cats == "benign_toolchain"
        out["new_benign_flagged_by_class"] = {k: float(flag[:, m][:, cls == k].mean()) for k in sorted(set(cls))}
    if low is not None:
        out["low_activity_malware_recall"] = float(flag[:, low].mean())
    return out


def paired(y, M_a, M_b):
    """Detector a vs b on identical rows: BA difference per assignment, wins, exact McNemar per assignment."""
    d = [ba_of(y, M_a[k]) - ba_of(y, M_b[k]) for k in range(M_a.shape[0])]
    mc = [C.mcnemar_exact(y, (M_a[k] >= .5).astype(int), (M_b[k] >= .5).astype(int)) for k in range(M_a.shape[0])]
    return {"ba_diff_mean": float(np.mean(d)), "ba_diff_by_assignment": [float(x) for x in d],
            "a_better": int(sum(x > 0 for x in d)), "b_better": int(sum(x < 0 for x in d)),
            "ties": int(sum(x == 0 for x in d)), "mcnemar_p_below_0.05": int(sum(m["p"] < 0.05 for m in mc)),
            "mcnemar": mc}


def verdict(p):
    """Pre-stated rule (protocol): beats if mean diff >= 0.02 and better in >= 8 of 10; not if <= 0 or <= 2 of 10."""
    if p["ba_diff_mean"] >= 0.02 and p["a_better"] >= 8:
        return "n-gram HIDS beats the thesis host detector"
    if p["ba_diff_mean"] <= 0 or p["a_better"] <= 2:
        return "n-gram HIDS does not beat the thesis host detector"
    return "unclear"


# --------------------------------------------------------------------------------------------- main
def main():
    t_start = time.time()
    attempt = Path(sys.argv[1]).resolve()
    cases, val = new_cases(attempt)
    rows, y_d, g_d, cat_d, split_d, mode_d = B.dataset()
    n_d, n_t = len(rows), len(cases)
    assert n_d == 240 and n_t == 85, (n_d, n_t)
    tc_scores = HERE.parent / "results" / "toolchain_scores.json"

    proto = {
        "written_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "purpose": "rerun the supervised system-call n-gram HIDS and the software hybrid on the toolchain-matched "
                   "benign collection, with the pools, rows, groups, splits and folds of score_toolchain.py",
        "attempt": str(attempt), "validation": str(val), "new_benign_runs": n_t,
        "pools": {"A": "train on the 240 released rows, apply to the 85 new benign runs",
                  "B": "Table V protocol, the 87 static benign rows replaced by the 85 new runs (238 rows)",
                  "C": "released Table IV split with the same replacement, forest seeds 42 and 0-9",
                  "D": "Table V protocol on the 240 rows plus the 85 new runs (325 rows)"},
        "detectors": list(DETS), "thesis_detectors": list(THESIS),
        "settings": {"rf": "RandomForestClassifier(n_estimators=500, class_weight='balanced', random_state=seed, "
                           "n_jobs=1)", "threshold": 0.5, "ngram_min_df": NG.MIN_DF, "fold_seeds": C.FOLD_SEEDS,
                     "inner_seed": C.INNER_SEED, "C_forest_seeds": C_SEEDS},
        "decision_rule": "Primary: pool B, 'ngram' (as collected, the published primary variant) vs the thesis host "
                         "detector on identical folds. Beats if its mean BA is >= 0.02 higher and it is higher in "
                         ">= 8 of 10 assignments; does not beat if the mean difference is <= 0 or it is higher in "
                         "<= 2 of 10; otherwise unclear. Everything else (pools A, C, D; other variants; software "
                         "hybrids vs the thesis hybrids; flag rates by toolchain class; low-activity malware recall) "
                         "is reported without a rule.",
        "already_seen_before_this_run": ["n-gram / software-hybrid scores on the 240 rows (baselines README)",
                                         "thesis detectors and the five start-up flags on pools A-D "
                                         "(results/toolchain_scores.json)"],
        "not_seen_before_this_run": "any n-gram or software-hybrid score on pools A-D",
        "inputs_sha256": {str(p): B.sha256_file(p) for p in (
            Path(__file__).resolve(), HERE / "ngrams.py", HERE / "supervised.py", HERE / "extract_syscalls.py",
            HERE / "flow_extract.py", HERE / "bl_common.py", HERE.parent / "common.py",
            HERE.parent / "toolchain" / "score_toolchain.py", attempt / "protocol.json", val, tc_scores,
            C.FEATURES, B.CACHE / "flows" / "features.npz", B.CACHE / "syscalls_summary.json")},
    }
    B.write_json(B.RESULTS / "toolchain_ngram_protocol.json", proto)
    B.log("protocol written")

    # ---- check 1: tokens of the new runs, with extract_syscalls's gates
    XS.OUT = NEW_CACHE
    NEW_CACHE.mkdir(parents=True, exist_ok=True)
    jobs = [(j, run, c["mode"].replace("native_", ""), telemetry_total(run)) for j, (c, run) in enumerate(cases)]
    with Pool(B.MAX_JOBS) as p:
        ext = sorted(p.map(XS._work, jobs, chunksize=1), key=lambda d: d["row"])
        fl = sorted(p.map(FE.work, [(j, run) for j, (c, run) in enumerate(cases)], chunksize=1))
    B.log("check 1: new-run tokens extracted, all gates passed (%d runs)" % len(ext))
    flow_t = np.asarray([v for _, v, _ in fl])
    flow_d = np.load(B.CACHE / "flows" / "features.npz")["X"]
    assert flow_d.shape == (240, len(FE.RUN_FEATURES)) and flow_t.shape == (n_t, len(FE.RUN_FEATURES))

    # ---- bags over the union token set (325 runs), and check 2 against the cached bags of the 240 rows
    paths = [B.CACHE / "syscalls" / ("%03d.npz" % i) for i in range(n_d)] + \
            [NEW_CACHE / ("%03d.npz" % j) for j in range(n_t)]
    full = sequences(paths, "collected")
    tv = np.unique(np.concatenate([np.concatenate(t) for t in full if t]))
    assert len(tv) < NG.BASE
    bags, check2 = {}, {}
    for name, variant in VARIANTS.items():
        raw = full if variant == "collected" else sequences(paths, variant)
        bags[name] = bags_from(raw, tv)
        z = np.load(B.CACHE / ("ngrams_%s.npz" % variant))
        off, ctv = z["off"], z["token_vocab"]
        same = sum(decoded(z["codes"][off[i]:off[i + 1]], z["counts"][off[i]:off[i + 1]], ctv) ==
                   decoded(bags[name][i][0], bags[name][i][1], tv) for i in range(n_d))
        assert same == n_d, (name, same)
        check2[name] = "%d/%d runs: identical n-gram counts" % (same, n_d)
    B.log("check 2: bags equal the cache for all four variants", check2)
    new_tokens = sorted(set(tv.tolist()) - set(np.load(B.CACHE / "ngrams_collected.npz")["token_vocab"].tolist()))

    # ---- pools
    flow_all = np.vstack([flow_d, flow_t])
    y_t = np.zeros(n_t, int)
    g_t = np.asarray(["benign_project::" + c["project"] for c, _ in cases])
    cls_t = np.asarray([c["toolchain_class"] for c, _ in cases])
    project_split = {r["project"]: r["split"] for r in rows if r["category"] == "benign"}
    split_t = np.asarray([project_split.get(c["project"]) or ("train" if c.get("split_suggestion") == "train"
                                                              else "test") for c, _ in cases])
    keep = ~((cat_d == "benign") & (mode_d != "amd64_dynamic"))
    assert int((~keep).sum()) == 87
    ib = np.concatenate([np.flatnonzero(keep), n_d + np.arange(n_t)])      # pool B/C rows in the 325-run index
    id_ = np.arange(n_d + n_t)                                           # pool D rows
    y_all, g_all = np.concatenate([y_d, y_t]), np.concatenate([g_d, g_t])
    cat_all = np.concatenate([cat_d, np.asarray(["benign_toolchain"] * n_t)])
    split_all = np.concatenate([split_d, split_t])
    post = []
    for p in paths:
        z = np.load(p)
        post.append(len(z["tok"]) - int(z["prologue_len"]))
    low_all = (cat_all == "malware") & (np.asarray(post) < LOW_ACTIVITY)

    def pool(index, **extra):
        return dict(bags={n: [bags[n][i] for i in index] for n in VARIANTS}, flow=flow_all[index],
                    y=y_all[index], g=g_all[index], **extra)
    tr4, te4 = B.table4_split(cat_d, split_d)
    D["d240"] = pool(np.arange(n_d), tr=tr4, te=te4)
    D["A"] = pool(id_, tr=np.arange(n_d), te=n_d + np.arange(n_t))
    gen_b = np.isin(cat_all[ib], ["malware", "benign", "benign_toolchain"])
    trc = np.flatnonzero(gen_b & (split_all[ib] == "train"))
    tec = np.flatnonzero(gen_b & (split_all[ib] == "test"))
    D["B"] = pool(ib)
    D["C"] = pool(ib, tr=trc, te=tec)
    D["D"] = pool(id_)

    # ---- every detector: check 3 (d240) and the new pools in one process pool
    todo = [("cv", "d240", k) for k in range(len(C.FOLD_SEEDS))] + [("split", "d240", 42)] + \
           [("split", "A", 42)] + [("cv", "B", k) for k in range(len(C.FOLD_SEEDS))] + \
           [("split", "C", s) for s in C_SEEDS] + [("cv", "D", k) for k in range(len(C.FOLD_SEEDS))]
    with Pool(B.MAX_JOBS) as p:
        res = p.map(job, todo, chunksize=1)
    R = {}
    for (kind, pl, k), P, folds in res:
        R.setdefault(pl, {})[(kind, k)] = (P, folds)

    def cv_matrix(pl, d):
        return np.stack([R[pl][("cv", k)][0][d] for k in range(len(C.FOLD_SEEDS))])

    def cv_folds(pl):
        return np.stack([R[pl][("cv", k)][1] for k in range(len(C.FOLD_SEEDS))])

    check3 = {}
    F240 = B.table5_folds(y_d, g_d)
    assert (cv_folds("d240") == F240).all()
    for d in DETS:
        s5 = np.load(HERE / "scores" / ("%s_table5.npz" % d))
        s4 = np.load(HERE / "scores" / ("%s_table4.npz" % d))
        assert (s5["folds"] == F240).all() and (s4["test_index"] == te4).all()
        e5 = float(np.abs(cv_matrix("d240", d) - s5["score"]).max())
        e4 = float(np.abs(R["d240"][("split", 42)][0][d] - s4["score"]).max())
        check3[d] = {"table5_max_abs_diff": e5, "table4_max_abs_diff": e4}
        assert e5 == 0.0 and e4 == 0.0, (d, e5, e4)
    B.log("check 3: all nine detectors reproduce the saved 240-row scores exactly")

    # ---- thesis detectors on the same pools (check 4)
    hc, nc = C.load()[1:]
    hs, ns = C.signals(hc), C.signals(nc)
    H, N, _, _ = C.per_window(rows, hc, nc)
    Xh_d, Xn_d = C.summarize(H), C.summarize(N)
    newf = [ST.new_run(run, c["mode"], hs, ns) for c, run in cases]
    Xh_all = np.vstack([Xh_d, C.summarize(np.stack([x[0] for x in newf]))])
    Xn_all = np.vstack([Xn_d, C.summarize(np.stack([x[1] for x in newf]))])
    TA = C.fit_predict(Xh_all, Xn_all, y_all, g_all, np.arange(n_d), n_d + np.arange(n_t))
    TB, FB = C.cv_all(Xh_all[ib], Xn_all[ib], y_all[ib], g_all[ib])
    TD, FD = C.cv_all(Xh_all, Xn_all, y_all, g_all)
    assert (FB == cv_folds("B")).all() and (FD == cv_folds("D")).all()
    TC = {s: C.fit_predict(Xh_all[ib], Xn_all[ib], y_all[ib], g_all[ib], trc, tec, rf_seed=s) for s in C_SEEDS}
    ref = json.loads(tc_scores.read_text())
    check4 = {}
    for d in THESIS:
        a = round(float((TA[d] >= .5).mean()), 3)
        b = [round(float(np.mean([ba_of(y_all[ib], TB[d][k]) for k in range(10)])), 3),
             round(float(np.std([ba_of(y_all[ib], TB[d][k]) for k in range(10)], ddof=1)), 3)]
        dd = [round(float(np.mean([ba_of(y_all, TD[d][k]) for k in range(10)])), 3),
              round(float(np.std([ba_of(y_all, TD[d][k]) for k in range(10)], ddof=1)), 3)]
        cc = [round(ba_of(y_all[ib][tec], TC[s][d]), 3) for s in C_SEEDS]
        check4[d] = {"A": [a, ref["A_transfer_flag_rate"][d]["all"]],
                     "B": [b, [ref["B_replacement_table_v"][d]["ba_mean"], ref["B_replacement_table_v"][d]["ba_sd"]]],
                     "C": [cc, ref["C_heldout"][d]["ba_by_seed"]],
                     "D": [dd, [ref["D_mixed_table_v"][d]["ba_mean"], ref["D_mixed_table_v"][d]["ba_sd"]]]}
        assert all(v[0] == v[1] for v in check4[d].values()), (d, check4[d])
    B.log("check 4: thesis detectors reproduce toolchain_scores.json on pools A-D")

    # ---- results
    out = {"protocol": str(B.RESULTS / "toolchain_ngram_protocol.json"),
           "checks": {"1_new_run_gates": "all %d runs passed (178-call prologue, 2nd root exec = target, events = "
                                         "telemetry total)" % n_t,
                      "2_bags_equal_cache": check2, "3_reproduce_240_row_scores": check3,
                      "4_thesis_detectors_reproduce_toolchain_scores": check4},
           "token_set": {"union_tokens": int(len(tv)), "tokens_new_in_toolchain_runs": len(new_tokens),
                         "new_tokens_abi_number": [[t >> 10, t & 1023] for t in new_tokens]},
           "new_runs": {"by_class": dict(collections.Counter(cls_t.tolist())),
                        "post_target_calls_median": float(np.median(np.asarray(post)[n_d:])),
                        "flows_per_run_median": float(np.median([n for _, _, n in fl])),
                        "extraction": ext},
           "low_activity_malware_rows": int(low_all.sum())}
    # A: transfer
    PA = R["A"][("split", 42)][0]
    out["A_transfer_flag_rate"] = {
        d: {"all": float((P >= .5).mean()),
            "by_class": {k: float((P[cls_t == k] >= .5).mean()) for k in sorted(set(cls_t))}}
        for d, P in list(PA.items()) + [("thesis_" + d, TA[d]) for d in THESIS]}
    # B and D: Table V protocol
    for name, index, T in (("B", ib, TB), ("D", id_, TD)):
        y, cats, low = y_all[index], cat_all[index], low_all[index]
        cls = cls_t if name in ("B", "D") else None
        summ = {d: cv_summary(y, cats, cv_matrix(name, d), cls, low) for d in DETS}
        summ.update({"thesis_" + d: cv_summary(y, cats, T[d], cls, low) for d in THESIS})
        comp = {"ngram vs thesis host": paired(y, cv_matrix(name, "ngram"), T["host"]),
                "ngram_pf vs thesis host": paired(y, cv_matrix(name, "ngram_pf"), T["host"]),
                "ngram_nostart vs thesis host": paired(y, cv_matrix(name, "ngram_nostart"), T["host"]),
                "ngram_startup vs thesis host": paired(y, cv_matrix(name, "ngram_startup"), T["host"]),
                "sw_concat vs thesis concat": paired(y, cv_matrix(name, "sw_concat"), T["concat"]),
                "sw_stacked vs thesis stacked": paired(y, cv_matrix(name, "sw_stacked"), T["stacked"]),
                "sw_concat vs thesis stacked": paired(y, cv_matrix(name, "sw_concat"), T["stacked"])}
        out["%s_table_v" % name] = {"rows": int(len(y)), "detectors": summ, "paired": comp}
        for d in DETS:
            B.save_scores("toolchain_%s_%s" % (name, d), score=cv_matrix(name, d), folds=cv_folds(name),
                          rows=index)
    out["primary_verdict"] = verdict(out["B_table_v"]["paired"]["ngram vs thesis host"])
    # C: held-out split, forest seeds
    yc = y_all[ib][tec]
    cres = {}
    for d in DETS:
        v = [C.metrics(yc, R["C"][("split", s)][0][d]) for s in C_SEEDS]
        cres[d] = {"ba_by_seed": [round(m["balanced_accuracy"], 3) for m in v],
                   "ba_mean": float(np.mean([m["balanced_accuracy"] for m in v])),
                   "ba_sd": float(np.std([m["balanced_accuracy"] for m in v], ddof=1)),
                   "seed42": {k: v[0][k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")},
                   "new_benign_flagged_seed42": float((R["C"][("split", 42)][0][d][
                       cat_all[ib][tec] == "benign_toolchain"] >= .5).mean())}
    for d in THESIS:
        v = [C.metrics(yc, TC[s][d]) for s in C_SEEDS]
        cres["thesis_" + d] = {"ba_by_seed": [round(m["balanced_accuracy"], 3) for m in v],
                               "ba_mean": float(np.mean([m["balanced_accuracy"] for m in v])),
                               "ba_sd": float(np.std([m["balanced_accuracy"] for m in v], ddof=1)),
                               "seed42": {k: v[0][k] for k in ("balanced_accuracy", "auc", "tn", "fp", "fn", "tp")}}
    out["C_heldout"] = {"train": int(len(trc)), "test": int(len(tec)),
                        "test_new_benign": int((cat_all[ib][tec] == "benign_toolchain").sum()), "detectors": cres}
    out["seconds"] = round(time.time() - t_start, 1)
    B.write_json(B.RESULTS / "toolchain_ngram.json", out)

    def line(s):
        return "%.3f +/- %.3f" % (s["ba_mean"], s["ba_sd"])
    for name in ("B", "D"):
        S = out["%s_table_v" % name]["detectors"]
        B.log("pool %s:" % name, "; ".join("%s %s (new benign flagged %.2f)" % (
            d, line(S[d]), S[d]["flagged_by_category"].get("benign_toolchain", float("nan")))
            for d in ("ngram", "ngram_startup", "ngram_nostart", "thesis_host", "sw_concat", "sw_stacked",
                      "thesis_concat", "thesis_stacked")))
    B.log("pool C:", "; ".join("%s %.3f +/- %.3f" % (d, cres[d]["ba_mean"], cres[d]["ba_sd"])
                                 for d in ("ngram", "ngram_startup", "ngram_nostart", "thesis_host",
                                           "sw_concat", "sw_stacked", "thesis_concat", "thesis_stacked")))
    B.log("pool A flag rate on new benign:", {d: round(v["all"], 3) for d, v in out["A_transfer_flag_rate"].items()})
    B.log("primary verdict:", out["primary_verdict"], out["B_table_v"]["paired"]["ngram vs thesis host"]["ba_diff_mean"])


if __name__ == "__main__":
    sys.exit(main())
