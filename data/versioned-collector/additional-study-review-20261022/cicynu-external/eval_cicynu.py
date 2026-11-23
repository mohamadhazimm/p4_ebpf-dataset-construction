#!/usr/bin/env python3
"""Evaluate the host, network and hybrid views on CIC-YNU-IoTMal, following protocol.json.

Usage: eval_cicynu.py <features dir> <out json>
"""
import json, sys, hashlib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

fdir, out = sys.argv[1], sys.argv[2]
ARCHS = ["arm", "mips", "mipsel", "x86"]
df = pd.concat([pd.read_csv(f"{fdir}/{a}.csv") for a in ARCHS], ignore_index=True)
df = df.replace([np.inf, -np.inf], np.nan)
y = (df.family != "Benign").astype(int).to_numpy()
fam = df.family.to_numpy(); arch = df.arch.to_numpy()

NET = [c for c in df.columns if c.startswith("net_")] + ["n_pcap_rows", "n_packets"]
H10 = [c for c in df.columns if c.startswith("h10_")]
HC = [c for c in df.columns if c.startswith("hc_")]
df["act_host"] = np.log1p(df.n_calls); df["act_net"] = np.log1p(df.n_packets)
VIEWS = {"host10": H10, "hostc50": HC, "net": NET, "concat": H10 + NET,
         "act_host": ["act_host"], "act_net": ["act_net"], "act_both": ["act_host", "act_net"]}
X = {k: df[v].to_numpy(float) for k, v in VIEWS.items()}


def forest():
    return RandomForestClassifier(n_estimators=500, class_weight="balanced", random_state=42, n_jobs=12)


def fit_prob(view, tr, te):
    m = forest().fit(X[view][tr], y[tr])
    return m.predict_proba(X[view][te])[:, 1]


def stacked(tr, te, p_host_te, p_net_te):
    inner = StratifiedKFold(5, shuffle=True, random_state=7)
    oof = np.zeros((len(tr), 2))
    for a, b in inner.split(tr, y[tr]):
        oof[b, 0] = forest().fit(X["host10"][tr[a]], y[tr[a]]).predict_proba(X["host10"][tr[b]])[:, 1]
        oof[b, 1] = forest().fit(X["net"][tr[a]], y[tr[a]]).predict_proba(X["net"][tr[b]])[:, 1]
    lr = LogisticRegression(class_weight="balanced", max_iter=1000).fit(oof, y[tr])
    return lr.predict_proba(np.column_stack([p_host_te, p_net_te]))[:, 1]


def run_fold(tr, te):
    p = {v: fit_prob(v, tr, te) for v in VIEWS}
    p["stacked"] = stacked(tr, te, p["host10"], p["net"])
    return p


def metrics(yt, pr):
    pred = (pr >= 0.5).astype(int)
    rec = float((pred[yt == 1] == 1).mean()) if (yt == 1).any() else float("nan")
    spec = float((pred[yt == 0] == 0).mean()) if (yt == 0).any() else float("nan")
    auc = float(roc_auc_score(yt, pr)) if len(set(yt)) == 2 else float("nan")
    return {"ba": (rec + spec) / 2, "recall": rec, "specificity": spec, "auc": auc, "n": int(len(yt))}


DET = list(VIEWS) + ["stacked"]
res = {"n": int(len(y)), "malware": int(y.sum()), "benign": int((1 - y).sum()),
       "features_sha256": {a: hashlib.sha256(open(f"{fdir}/{a}.csv", "rb").read()).hexdigest() for a in ARCHS}}

# P1: random stratified 5-fold, five fold assignments
p1 = {d: [] for d in DET}; p1_fam = {d: {} for d in DET}; p1_arch = {d: {} for d in DET}
for seed in [42, 0, 1, 2, 3]:
    oof = {d: np.zeros(len(y)) for d in DET}
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=seed).split(X["net"], y):
        p = run_fold(tr, te)
        for d in DET:
            oof[d][te] = p[d]
    for d in DET:
        p1[d].append(metrics(y, oof[d]))
        for f in sorted(set(fam)):
            m = fam == f
            p1_fam[d].setdefault(f, []).append(float(((oof[d][m] >= 0.5) == (y[m] == 1)).mean()))
        for a in ARCHS:
            m = arch == a
            p1_arch[d].setdefault(a, []).append(metrics(y[m], oof[d][m])["ba"])
    print("P1 seed", seed, {d: round(p1[d][-1]["ba"], 3) for d in DET}, flush=True)
res["P1_random"] = {d: {"per_assignment": p1[d],
                        "ba_mean": float(np.mean([m["ba"] for m in p1[d]])), "ba_sd": float(np.std([m["ba"] for m in p1[d]], ddof=1)),
                        "auc_mean": float(np.mean([m["auc"] for m in p1[d]])),
                        "recall_mean": float(np.mean([m["recall"] for m in p1[d]])),
                        "specificity_mean": float(np.mean([m["specificity"] for m in p1[d]])),
                        "correct_share_by_family": {f: float(np.mean(v)) for f, v in p1_fam[d].items()},
                        "ba_by_arch": {a: float(np.mean(v)) for a, v in p1_arch[d].items()}} for d in DET}
best_single = np.maximum([m["ba"] for m in p1["host10"]], [m["ba"] for m in p1["net"]])
best_hybrid = np.maximum([m["ba"] for m in p1["concat"]], [m["ba"] for m in p1["stacked"]])
res["P1_random"]["fusion_gain_per_assignment"] = (best_hybrid - best_single).tolist()

# P2: leave one family out
rng = np.random.default_rng(42)
ben = np.where(y == 0)[0]; bucket = np.zeros(len(y), int) - 1
for a in ARCHS:
    idx = ben[arch[ben] == a]; idx = rng.permutation(idx)
    for k, chunk in enumerate(np.array_split(idx, 4)):
        bucket[chunk] = k
FAMS = ["Mirai", "DarkNexus", "Gafgyt", "Generic"]
p2 = {d: {} for d in DET}; pooled = {d: {"mal": [], "ben": []} for d in DET}
for k, F in enumerate(FAMS):
    te = np.where((fam == F) | (bucket == k))[0]
    tr = np.where((fam != F) & (bucket != k))[0]
    p = run_fold(tr, te)
    for d in DET:
        m = metrics(y[te], p[d]); m["train_malware"] = int(y[tr].sum()); p2[d][F] = m
        pooled[d]["mal"].append(((p[d][y[te] == 1] >= 0.5)).astype(int))
        pooled[d]["ben"].append(((p[d][y[te] == 0] < 0.5)).astype(int))
    print("P2", F, {d: round(p2[d][F]["ba"], 3) for d in DET}, flush=True)
for d in DET:
    rec_w = float(np.concatenate(pooled[d]["mal"]).mean()); spec = float(np.concatenate(pooled[d]["ben"]).mean())
    rec_f = float(np.mean([p2[d][F]["recall"] for F in FAMS]))
    p2[d]["pooled"] = {"recall_sample_weighted": rec_w, "recall_family_mean": rec_f, "specificity": spec,
                       "ba_sample_weighted": (rec_w + spec) / 2, "ba_family_mean": (rec_f + spec) / 2}
res["P2_family_out"] = p2

# P3: leave one architecture out
p3 = {d: {} for d in DET}
for a in ARCHS:
    te = np.where(arch == a)[0]; tr = np.where(arch != a)[0]
    p = run_fold(tr, te)
    for d in DET:
        p3[d][a] = metrics(y[te], p[d])
    print("P3", a, {d: round(p3[d][a]["ba"], 3) for d in DET}, flush=True)
for d in DET:
    p3[d]["mean_ba"] = float(np.mean([p3[d][a]["ba"] for a in ARCHS]))
res["P3_arch_out"] = p3

# decision rules
act_p2 = max(p2[b]["pooled"]["ba_family_mean"] for b in ["act_host", "act_net", "act_both"])
act_p3 = max(p3[b]["mean_ba"] for b in ["act_host", "act_net", "act_both"])
r1 = {"host10_minus_activity_P2": p2["host10"]["pooled"]["ba_family_mean"] - act_p2,
      "host10_minus_activity_P3": p3["host10"]["mean_ba"] - act_p3}
r1["met"] = bool(r1["host10_minus_activity_P2"] >= 0.05 and r1["host10_minus_activity_P3"] >= 0.05)
gains = res["P1_random"]["fusion_gain_per_assignment"]
p2_gain = max(p2["concat"]["pooled"]["ba_family_mean"], p2["stacked"]["pooled"]["ba_family_mean"]) - \
    max(p2["host10"]["pooled"]["ba_family_mean"], p2["net"]["pooled"]["ba_family_mean"])
r2 = {"P1_gains": gains, "P1_assignments_ge_0.02": int(sum(g >= 0.02 for g in gains)), "P2_gain_family_mean": p2_gain}
r2["met"] = bool(r2["P1_assignments_ge_0.02"] >= 4 and p2_gain >= 0.02)
res["decision_rules"] = {"R1_host_beyond_activity": r1, "R2_fusion_helps": r2}

# descriptive importances (full data)
imp = {}
for v in ["host10", "net", "concat"]:
    m = forest().fit(X[v], y)
    order = np.argsort(m.feature_importances_)[::-1][:12]
    imp[v] = [(VIEWS[v][i], float(m.feature_importances_[i])) for i in order]
res["importance_full_data"] = imp
json.dump(res, open(out, "w"), indent=2)
print("R1", r1); print("R2", r2)
