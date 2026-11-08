"""Self-check of audit v2 claims that were asserted but not measured (derived, exploratory, read-only).

1. F-transfer as defined in report Section 9: a model trained only on benign script (0) vs benign ELF (1)
   ranks malware above held-out benign scripts. Malware is never in training; script groups are cross-fitted.
2. F-strat in the native-only stratum (Addendum A, H3) using the stored CIs.
3. Whether emulation changes the original model's top host families (medians by execution class).
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupKFold

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import diagnostics as d  # noqa: E402

TOP = ["dup2", "execve", "openat", "unique_threads", "openat_success", "event", "fork", "close", "mmap", "mprotect"]


def load():
    header = {r["sample"]: r for r in csv.DictReader((HERE / "elf_header_linkage.csv").open())}
    rows = []
    for r in csv.DictReader((HERE / "features_derived.csv").open()):
        r = dict(r, label=int(r["label"]))
        r["execution"] = header[r["sample"]]["execution"] if r["cohort"] == "malware" else "native"
        rows.append(r)
    return rows


def transfer(rows, cols, folds=5):
    scripts = [r for r in rows if r["cohort"] == "benign_script"]
    elf = [r for r in rows if r["cohort"] == "benign_elf"]
    malware = [r for r in rows if r["cohort"] == "malware"]
    groups = np.asarray([r["group"] for r in scripts])
    script_prob = np.full(len(scripts), np.nan)
    malware_prob = np.zeros(len(malware))
    x_s, x_e, x_m = (np.nan_to_num(d.matrix(s, cols)) for s in (scripts, elf, malware))
    for fold, (train, test) in enumerate(GroupKFold(folds).split(x_s, groups=groups), start=1):
        assert not set(groups[train]) & set(groups[test])
        model = RandomForestClassifier(n_estimators=300, max_features="sqrt", min_samples_leaf=2,
                                       class_weight="balanced_subsample", random_state=d.SEED + fold, n_jobs=-1)
        model.fit(np.vstack((x_s[train], x_e)), np.r_[np.zeros(len(train)), np.ones(len(x_e))])
        script_prob[test] = model.predict_proba(x_s[test])[:, 1]
        malware_prob += model.predict_proba(x_m)[:, 1] / folds
    out = {}
    for name, keep in (("all_malware", lambda r: True), ("native_malware", lambda r: r["execution"] == "native"),
                       ("emulated_malware", lambda r: r["execution"] == "qemu_user")):
        mask = np.asarray([keep(r) for r in malware])
        y = np.r_[np.zeros(len(scripts)), np.ones(int(mask.sum()))]
        out[name] = {"malware": int(mask.sum()), "held_out_benign_scripts": len(scripts),
                     "auc_malware_vs_heldout_scripts": round(float(roc_auc_score(y, np.r_[script_prob, malware_prob[mask]])), 4)}
    return out


def medians(rows):
    classes = defaultdict(list)
    for r in rows:
        key = r["cohort"] if r["cohort"] != "malware" else f"malware_{r['execution']}"
        classes[key].append(r)
    table = {}
    for fam in TOP:
        col = f"post__ebpf_{fam}_count__sum" if f"post__ebpf_{fam}_count__sum" in rows[0] else None
        if col is None:
            col = next((c for c in rows[0] if c.startswith("post__") and f"_{fam}" in c and c.endswith("__sum")), None)
        if col is None:
            continue
        table[col] = {k: float(np.median([float(r[col] or 0) for r in v])) for k, v in sorted(classes.items())}
    return table


def main() -> int:
    rows = load()
    linkage = json.loads((HERE / "elf_header_linkage_results.json").read_text())
    native = linkage["models"]["native_malware_vs_benign_elf"]["models"]
    host_ci, nuis_ci = native["host_all"]["ba_group_bootstrap_95ci"], native["nuisance_only"]["ba_group_bootstrap_95ci"]
    result = {
        "status": "derived, exploratory, post hoc; no execution",
        "f_transfer_threshold_auc": 0.75,
        "f_transfer_host_all": transfer(rows, d.HOST),
        "f_transfer_post_exec": transfer(rows, d.POST),
        "f_strat_native_stratum": {"host_ci": host_ci, "nuisance_ci": nuis_ci,
                                   "triggered": host_ci[0] <= nuis_ci[1]},
        "post_exec_median_sum_by_class": medians(rows),
        "class_sizes": {k: sum(1 for r in rows if (r["cohort"] if r["cohort"] != "malware"
                                                   else f"malware_{r['execution']}") == k)
                        for k in ("benign_script", "benign_elf", "malware_native", "malware_qemu_user")},
    }
    (HERE / "self_check_results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
