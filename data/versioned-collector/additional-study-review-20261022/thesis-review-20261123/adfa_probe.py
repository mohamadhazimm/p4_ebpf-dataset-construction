#!/usr/bin/env python3
"""Reproduce the thesis's ADFA-LD feature probe (Ch5, tab:host-feature-probe).

The thesis reports accuracy 93.56% (test) and 93.38% +/- 0.58% (five-fold CV) for a
Random Forest on eight sequence statistics per trace, with the training and
validation traces as benign and the attack traces as malicious. The original
probing script is not on the lab workstation. This script recomputes the eight
statistics from the public ADFA-LD archive and reports accuracy next to balanced
accuracy and the majority-class share, under the same labelling, so that the
thesis can state which measure its number is.

Usage: adfa_probe.py <extracted ADFA-LD dir> <output json>
"""
import collections, hashlib, json, math, os, sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import accuracy_score, balanced_accuracy_score
from sklearn.model_selection import StratifiedKFold, StratifiedGroupKFold, train_test_split

FEATURES = ["total_syscalls", "unique_syscalls", "first100_unique", "entropy",
            "avg_run_length", "max_run_length", "transition_count", "rare_syscall_ratio"]


def stats(seq):
    n = len(seq)
    counts = collections.Counter(seq)
    runs, longest, cur = 0, 0, 0
    prev = None
    for s in seq:
        if s == prev:
            cur += 1
        else:
            runs += 1
            cur = 1
            prev = s
        longest = max(longest, cur)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0
    return [n, len(counts), len(set(seq[:100])), entropy,
            n / runs if runs else 0.0, longest, max(runs - 1, 0),
            sum(1 for c in counts.values() if c == 1) / n if n else 0.0]


def load(root):
    rows, labels, groups, kinds = [], [], [], []
    h = hashlib.sha256()
    for sub, label in (("Training_Data_Master", 0), ("Validation_Data_Master", 0),
                       ("Attack_Data_Master", 1)):
        base = os.path.join(root, sub)
        for dirpath, _, files in sorted(os.walk(base)):
            for f in sorted(files):
                if not f.endswith(".txt"):
                    continue
                p = os.path.join(dirpath, f)
                data = open(p, "rb").read()
                h.update(data)
                seq = [int(x) for x in data.split()]
                if not seq:
                    continue
                rows.append(stats(seq))
                labels.append(label)
                rel = os.path.relpath(dirpath, base)
                # attack traces of one attack run share a folder; each normal trace is its own group
                groups.append(f"{sub}/{rel}" if label else f"{sub}/{f}")
                kinds.append(sub if not label else rel.rsplit("_", 1)[0])
    return np.array(rows, float), np.array(labels), np.array(groups), kinds, h.hexdigest()


def forest(seed=42):
    return RandomForestClassifier(n_estimators=500, random_state=seed, n_jobs=4)


def main():
    root, out = sys.argv[1], sys.argv[2]
    X, y, g, kinds, digest = load(root)
    res = {"traces": int(len(y)), "normal": int((y == 0).sum()), "attack": int((y == 1).sum()),
           "attack_runs": int(len(set(g[y == 1]))), "trace_bytes_sha256": digest,
           "majority_class_share": float(max((y == 0).mean(), (y == 1).mean())),
           "attack_types": dict(collections.Counter(k for k, l in zip(kinds, y) if l))}
    res["features"] = FEATURES
    for name, cw in (("unweighted", None), ("balanced_weights", "balanced")):
        r = {}
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        m = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=4, class_weight=cw).fit(Xtr, ytr)
        p = m.predict(Xte)
        r["split80_20"] = {"accuracy": accuracy_score(yte, p), "balanced_accuracy": balanced_accuracy_score(yte, p),
                           "attack_recall": float((p[yte == 1] == 1).mean()),
                           "normal_specificity": float((p[yte == 0] == 0).mean())}
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
        m = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=4, class_weight=cw).fit(Xtr, ytr)
        p = m.predict(Xte)
        r["split70_30"] = {"accuracy": accuracy_score(yte, p), "balanced_accuracy": balanced_accuracy_score(yte, p)}
        if cw is None:
            pi = permutation_importance(m, Xte, yte, scoring="balanced_accuracy", n_repeats=10, random_state=42, n_jobs=4)
            r["permutation_importance_70_30"] = sorted(
                ((FEATURES[i], float(pi.importances_mean[i])) for i in range(len(FEATURES))), key=lambda t: -t[1])
            r["impurity_importance_70_30"] = sorted(
                ((FEATURES[i], float(m.feature_importances_[i])) for i in range(len(FEATURES))), key=lambda t: -t[1])
        for cvname, splitter, use_groups in (("cv5_stratified", StratifiedKFold(5, shuffle=True, random_state=42), False),
                                             ("cv5_grouped_by_attack_run", StratifiedGroupKFold(5, shuffle=True, random_state=42), True)):
            acc, ba = [], []
            for tr, te in splitter.split(X, y, g if use_groups else None):
                m = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=4, class_weight=cw).fit(X[tr], y[tr])
                p = m.predict(X[te])
                acc.append(accuracy_score(y[te], p)); ba.append(balanced_accuracy_score(y[te], p))
            r[cvname] = {"accuracy_mean": float(np.mean(acc)), "accuracy_sd": float(np.std(acc)),
                         "balanced_accuracy_mean": float(np.mean(ba)), "balanced_accuracy_sd": float(np.std(ba))}
        res[name] = r
    # balanced subsample, as the CIC-DDoS2019 probes were run
    rng = np.random.default_rng(42)
    idx0 = rng.choice(np.where(y == 0)[0], size=int((y == 1).sum()), replace=False)
    idx = np.concatenate([idx0, np.where(y == 1)[0]])
    Xb, yb = X[idx], y[idx]
    Xtr, Xte, ytr, yte = train_test_split(Xb, yb, test_size=0.3, stratify=yb, random_state=42)
    m = forest().fit(Xtr, ytr); p = m.predict(Xte)
    res["balanced_subsample_70_30"] = {"per_class": int((y == 1).sum()), "accuracy": accuracy_score(yte, p),
                                       "balanced_accuracy": balanced_accuracy_score(yte, p)}
    json.dump(res, open(out, "w"), indent=2)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
