#!/usr/bin/env python3
"""DERIVED, EXPLORATORY diagnostics A-E for the independent perfect-score audit (2026-10-20).

Read-only over frozen scale-100x100 and benign-ELF-100 (.14) outputs and the original model
outputs. Writes only into this directory: features_derived.csv, diagnostics_results.json.
These are post-hoc diagnostics, not detector-performance estimates. Requires run_audit.csv
from audit_runs.py.
"""
from __future__ import annotations

import csv
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.metrics import balanced_accuracy_score, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

HERE = Path(__file__).resolve().parent
COLLECTOR = HERE.parent
STUDY = COLLECTOR.parents[1]
SCALE = COLLECTOR / "scale-100x100-v14-20261020T072500Z"
P4_DIR = STUDY.parents[1] / "p4_ebpf"
sys.path.insert(0, str(STUDY / "src"))
sys.path.insert(0, str(P4_DIR))
import exec_boundary as eb  # noqa: E402
from analyze_p4_pcap_ablation import P4_SAMPLE_FEATURES, derive_p4_features  # noqa: E402
from build_dataset import aggregate  # noqa: E402

csv.field_size_limit(sys.maxsize)
SEED = 42
STATS = ("mean", "max", "sum", "std", "active_windows")
CONTRACT = json.loads((STUDY / "data/benign/revision3/labeled_sample_dataset.feature_columns.json").read_text())
HOST = list(CONTRACT["host"])
FAMILIES = sorted({f.removeprefix("host__").rsplit("__", 1)[0] for f in HOST})
POST = [f"post__{f.removeprefix('host__')}" for f in HOST]
NUISANCE = ["rc_exit0", "rc_timeout", "rc_signaled", "rc_nonzero", "root_alive_at_end", "root_exit_s",
            "post_exec_last_s", "raw_syscalls", "post_exec_raw_syscalls", "named_events",
            "distinct_pids", "active_windows", "pcap_packets", "connect_present"]
ACQUISITION = ["n_watch_paths", "start_hour_utc"]
ABLATION = {
    "dup": {"ebpf_dup2_count", "ebpf_dup3_count"},
    "process_lifecycle": {"ebpf_fork_count", "ebpf_exit_count", "ebpf_unique_threads", "ebpf_kill_count",
                          "ebpf_ptrace_count"},
    "exec_loader": {"ebpf_execve_count", "ebpf_execveat_count", "ebpf_mmap_count", "ebpf_mprotect_count",
                    "ebpf_openat_count", "ebpf_openat_success_count", "ebpf_openat2_count",
                    "ebpf_openat2_success_count", "ebpf_close_count"},
    "activity_total": {"ebpf_event_count"},
    "network": {"ebpf_socket_count", "ebpf_connect_count", "ebpf_sendto_count", "ebpf_recvfrom_count",
                "ebpf_bind_count", "ebpf_listen_count", "ebpf_accept_count", "ebpf_accept4_count"},
    "file_write": {"ebpf_write_count", "ebpf_writev_count", "ebpf_pwrite64_count", "ebpf_file_write_success_count",
                   "ebpf_file_writev_success_count", "ebpf_file_pwrite64_success_count", "ebpf_file_write_bytes",
                   "ebpf_renameat_count", "ebpf_renameat2_count", "ebpf_unlinkat_count"},
}
assert set().union(*ABLATION.values()) == set(FAMILIES), set(FAMILIES) ^ set().union(*ABLATION.values())


# ---------------------------------------------------------------- feature construction
def build_features() -> list[dict]:
    aligned = {}
    with (SCALE / "modeling/p4_29x29/aligned_p4_host_candidate_dataset.csv").open() as handle:
        for row in csv.DictReader(handle):
            aligned[row["sample_artifact"]] = row
    out = []
    with (HERE / "run_audit.csv").open() as handle:
        audit = [row for row in csv.DictReader(handle) if row["quality"] == "accepted"]
    for row in audit:
        run_dir = COLLECTOR / row["run_dir"]
        metadata, named, raw, stored = eb.load_run(run_dir)
        rec: dict = {"cohort": row["cohort"], "sample": row["sample"], "group": f"{row['cohort']}::{row['group']}",
                     "label": int(row["cohort"] == "malware"), "in_183_model": row["in_183_model"] == "True"}
        for family in FAMILIES:
            summary = aggregate([float(window[family]) for window in stored])
            for stat in STATS:
                rec[f"host__{family}__{stat}"] = summary[stat]
        try:
            derived = eb.derive_counters(named, raw, metadata["sample_root_pid"], 2, len(stored), stored)
            rec["post_exec_ok"] = True
            for family in FAMILIES:
                summary = aggregate([derived[w][family] for w in range(len(stored))])
                for stat in STATS:
                    rec[f"post__{family}__{stat}"] = summary[stat]
        except eb.BoundaryError as error:
            rec["post_exec_ok"] = False
            rec["post_exec_error"] = str(error)
        if row["cohort"] == "benign_elf":
            pcap = run_dir / "packet_capture.pcap"
            features, _, diagnostics = derive_p4_features(pcap, stored, metadata, byte_layer="ethernet",
                                                          rate_window="nominal")
            rec["p4_alignment"] = diagnostics["alignment_status"]
            if rec["p4_alignment"] == "unique":
                rec.update({name: features[name] for name in P4_SAMPLE_FEATURES})
        else:
            rec["p4_alignment"] = row["p4_alignment"]
            if row["sample"] in aligned:
                rec.update({name: float(aligned[row["sample"]][name]) for name in P4_SAMPLE_FEATURES})
                for name in HOST:  # parity with the frozen modeling dataset
                    if not math.isclose(float(aligned[row["sample"]][name]), rec[name], rel_tol=1e-9, abs_tol=1e-9):
                        raise SystemExit(f"host parity mismatch {row['sample']} {name}")
        rc = int(row["return_code"])
        alive = row["root_exit_s"] == ""
        rec.update({
            "return_code": rc,
            "rc_exit0": float(rc == 0), "rc_timeout": float(alive and rc in (-15, -9)),
            "rc_signaled": float(rc < 0 and not (alive and rc in (-15, -9))), "rc_nonzero": float(rc > 0),
            "root_alive_at_end": float(alive),
            "root_exit_s": 20.0 if alive else float(row["root_exit_s"]),
            "post_exec_last_s": float(row["post_exec_last_s"] or 0.0),
            "raw_syscalls": float(row["raw_syscalls"]), "post_exec_raw_syscalls": float(row["post_exec_raw_syscalls"]),
            "named_events": float(row["named_events"]), "distinct_pids": float(row["distinct_pids"]),
            "active_windows": float(row["active_windows"]), "pcap_packets": float(row["pcap_packets_captured"] or 0),
            "connect_present": float(int(row["connect_events"]) > 0),
            "n_watch_paths": float(row["n_watch_paths"]),
            "start_hour_utc": float(row["started_at_utc"][11:13]) + float(row["started_at_utc"][14:16]) / 60,
            "observation_s": float(row["observation_s"]),
        })
        out.append(rec)
    return out


# ---------------------------------------------------------------- evaluation helpers
def matrix(rows, cols):
    return np.asarray([[float(r[c]) if r.get(c, "") != "" else np.nan for c in cols] for r in rows], dtype=float)


def splits_for(labels, groups, seed=SEED, folds=5):
    return list(StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed).split(
        np.zeros((len(labels), 1)), labels, groups))


def check_splits(labels, groups, splits):
    for train, test in splits:
        assert not set(groups[train]) & set(groups[test]), "group leakage"
        assert set(labels[train]) == {0, 1}, "train fold missing a class"


def mi_select(train_x, train_y, cols, seed, k=29):
    info = mutual_info_classif(np.nan_to_num(train_x), train_y, random_state=seed)
    fam = defaultdict(list)
    for i, c in enumerate(cols):
        fam[c.rpartition("__")[0]].append(i)
    keep = set(sorted(fam, key=lambda f: (-float(np.mean(info[fam[f]])), f))[:k])
    return [i for i, c in enumerate(cols) if c.rpartition("__")[0] in keep]


def oof(x, y, splits, trees=300, select_cols=None, extra=None, stump=False, importances=None, cols=None):
    """Out-of-fold probabilities. All preprocessing (selection) is fit on training folds only."""
    prob = np.full(len(y), np.nan)
    for fold, (train, test) in enumerate(splits, start=1):
        idx = list(range(x.shape[1]))
        if select_cols is not None:
            idx = mi_select(x[train], y[train], select_cols, SEED + fold)
        xt, xv = np.nan_to_num(x[train][:, idx]), np.nan_to_num(x[test][:, idx])
        if extra is not None:
            xt, xv = np.hstack((xt, np.nan_to_num(extra[train]))), np.hstack((xv, np.nan_to_num(extra[test])))
        if stump:
            model = DecisionTreeClassifier(max_depth=1, class_weight="balanced", random_state=SEED)
        else:
            model = RandomForestClassifier(n_estimators=trees, max_features="sqrt", min_samples_leaf=2,
                                           class_weight="balanced_subsample", random_state=SEED + fold, n_jobs=-1)
        model.fit(xt, y[train])
        prob[test] = model.predict_proba(xv)[:, 1] if len(model.classes_) == 2 else float(model.classes_[0])
        if importances is not None and cols is not None and select_cols is None and extra is None:
            for c, v in zip(cols, model.feature_importances_):
                importances[c] += v / len(splits)
    return prob


def metrics(y, prob, groups=None, boot=1000):
    pred = (prob >= 0.5).astype(int)
    out = {"n": int(len(y)), "malware": int(y.sum()), "benign": int((1 - y).sum()),
           "balanced_accuracy": round(float(balanced_accuracy_score(y, pred)), 4),
           "roc_auc": round(float(roc_auc_score(y, prob)), 4) if len(set(y)) == 2 else None,
           "tn_fp_fn_tp": confusion_matrix(y, pred, labels=[0, 1]).ravel().tolist()}
    if groups is not None and boot:
        out["ba_group_bootstrap_95ci"] = cluster_bootstrap(y, pred, groups, boot)
    return out


def cluster_bootstrap(y, pred, groups, n):
    rng = np.random.default_rng(SEED)
    by_class = {c: sorted({g for g, l in zip(groups, y) if l == c}) for c in (0, 1)}
    index = defaultdict(list)
    for i, g in enumerate(groups):
        index[g].append(i)
    values = []
    for _ in range(n):
        chosen = []
        for c in (0, 1):
            for g in rng.choice(by_class[c], size=len(by_class[c]), replace=True):
                chosen.extend(index[g])
        chosen = np.asarray(chosen)
        values.append(balanced_accuracy_score(y[chosen], pred[chosen]))
    return [round(float(np.percentile(values, 2.5)), 4), round(float(np.percentile(values, 97.5)), 4)]


def group_permutation(x, y, groups, observed, n=50, trees=100):
    rng = np.random.default_rng(SEED)
    unique = sorted(set(groups))
    group_label = {g: int(y[groups == g][0]) for g in unique}
    labels = np.asarray([group_label[g] for g in unique])
    scores = []
    for _ in range(n):
        shuffled = dict(zip(unique, rng.permutation(labels)))
        yp = np.asarray([shuffled[g] for g in groups])
        sp = splits_for(yp, groups)
        try:
            check_splits(yp, groups, sp)
        except AssertionError:
            continue
        scores.append(float(balanced_accuracy_score(yp, (oof(x, yp, sp, trees=trees) >= 0.5).astype(int))))
    scores = np.asarray(scores)
    return {"permutations": int(len(scores)), "mean_ba": round(float(scores.mean()), 4),
            "max_ba": round(float(scores.max()), 4),
            "p_value": round(float((1 + np.sum(scores >= observed)) / (1 + len(scores))), 4)}


def top_families(importances, k=10):
    fam = defaultdict(float)
    for c, v in importances.items():
        fam[c.split("__")[1]] += v
    return [f for f, _ in sorted(fam.items(), key=lambda t: -t[1])[:k]]


# ---------------------------------------------------------------- experiments
def main() -> int:
    rows = build_features()
    with (HERE / "features_derived.csv").open("w", newline="") as handle:
        fields = sorted({k for r in rows for k in r})
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    results: dict = {"derived": True, "exploratory_post_hoc": True, "seed": SEED,
                     "inputs": [str(SCALE), str(COLLECTOR / "benign-elf-100-v14-20261020T140000Z")]}

    # R0: recompute original OOF metrics from saved predictions; cluster bootstrap CIs.
    with (SCALE / "modeling/p4_29x29/oof_predictions.csv").open() as handle:
        saved = list(csv.DictReader(handle))
    results["R0_original_oof_recomputed"] = {}
    for model in sorted({r["model"] for r in saved}):
        sub = [r for r in saved if r["model"] == model]
        y = np.asarray([int(r["label"]) for r in sub])
        p = np.asarray([float(r["probability_malware"]) for r in sub])
        g = np.asarray([r["group_id"] for r in sub])
        results["R0_original_oof_recomputed"][model] = metrics(y, p, g)

    # Original-host malware top families (fold-averaged importance in the frozen run).
    orig_imp = defaultdict(float)
    with (SCALE / "modeling/p4_29x29/fold_feature_importance.csv").open() as handle:
        for r in csv.DictReader(handle):
            if r["model"] == "host_ebpf_family_balanced":
                orig_imp[r["feature"]] += float(r["importance"])
    orig_top = top_families(orig_imp)
    results["original_host_top10_families"] = orig_top

    def cohort(*names):
        return [r for r in rows if r["cohort"] in names]

    def run_block(name, subset, label_fn, include, perm=False, ablate=False):
        y = np.asarray([label_fn(r) for r in subset])
        g = np.asarray([r["group"] for r in subset])
        sp = splits_for(y, g)
        check_splits(y, g, sp)
        block = {"samples": len(subset), "class_counts": dict(Counter(int(v) for v in y)),
                 "groups_per_class": {c: len({gg for gg, yy in zip(g, y) if yy == c}) for c in (0, 1)},
                 "grouping_unit": "malware signature / benign tool family (cohort-prefixed)",
                 "cv": "StratifiedGroupKFold(5, shuffle, seed 42); selection fit on train folds only",
                 "models": {}}
        imp: dict = defaultdict(float)
        for model in include:
            if model == "host_all":
                x = matrix(subset, HOST)
                prob = oof(x, y, sp, importances=imp, cols=HOST)
            elif model == "host_mi29":
                prob = oof(matrix(subset, HOST), y, sp, select_cols=HOST)
            elif model == "post_exec_host_all":
                prob = oof(matrix(subset, POST), y, sp)
            elif model == "p4":
                prob = oof(matrix(subset, P4_SAMPLE_FEATURES), y, sp)
            elif model == "hybrid_mi29_p4":
                prob = oof(matrix(subset, HOST), y, sp, select_cols=HOST, extra=matrix(subset, P4_SAMPLE_FEATURES))
            elif model == "nuisance_only":
                prob = oof(matrix(subset, NUISANCE), y, sp)
            elif model == "acquisition_metadata_only":
                prob = oof(matrix(subset, ACQUISITION), y, sp)
            elif model == "dup2_max_stump":
                prob = oof(matrix(subset, ["host__ebpf_dup2_count__max"]), y, sp, stump=True)
            block["models"][model] = metrics(y, prob, g)
        if imp:
            block["host_all_top10_families"] = top_families(imp)
            block["overlap_with_original_malware_top10"] = sorted(set(block["host_all_top10_families"]) & set(orig_top))
        if perm and "host_all" in block["models"]:
            block["host_all_group_permutation"] = group_permutation(
                matrix(subset, HOST), y, g, block["models"]["host_all"]["balanced_accuracy"])
        if ablate:
            x_all = matrix(subset, HOST)
            block["ablation_post_hoc"] = {}
            for name_, fams in ABLATION.items():
                drop = [i for i, c in enumerate(HOST) if c.split("__")[1] not in fams]
                only = [i for i, c in enumerate(HOST) if c.split("__")[1] in fams]
                block["ablation_post_hoc"][name_] = {
                    "without": metrics(y, oof(x_all[:, drop], y, sp, trees=200), g, boot=0)["balanced_accuracy"],
                    "only": metrics(y, oof(x_all[:, only], y, sp, trees=200), g, boot=0)["balanced_accuracy"],
                }
            for stat in STATS:
                only = [i for i, c in enumerate(HOST) if c.endswith(f"__{stat}")]
                block["ablation_post_hoc"][f"summary_{stat}_only"] = {
                    "only": metrics(y, oof(x_all[:, only], y, sp, trees=200), g, boot=0)["balanced_accuracy"]}
            block["single_nuisance_stumps"] = {
                c: metrics(y, oof(matrix(subset, [c]), y, sp, stump=True), g, boot=0)["balanced_accuracy"]
                for c in NUISANCE}
        results[name] = block
        return y, g

    # Reproduce original 183-sample host task with this loader (sanity) + nuisance + ablations (D, C).
    s183 = [r for r in rows if r["in_183_model"]]
    run_block("S183_script_benign_vs_malware", s183, lambda r: r["label"],
              ["host_all", "host_mi29", "post_exec_host_all", "nuisance_only", "acquisition_metadata_only",
               "dup2_max_stump"], ablate=True)

    # A: benign shell script (label 0) vs benign ELF (label 1), host only.
    a = cohort("benign_script", "benign_elf")
    run_block("A_benign_script_vs_benign_elf", a, lambda r: int(r["cohort"] == "benign_elf"),
              ["host_all", "post_exec_host_all", "nuisance_only", "dup2_max_stump"])

    # B: benign ELF vs malware, common P4-aligned subset, plus full-host sensitivity.
    b_aligned = [r for r in cohort("benign_elf", "malware") if r["p4_alignment"] == "unique"]
    run_block("B_benign_elf_vs_malware_p4_aligned", b_aligned, lambda r: r["label"],
              ["p4", "host_all", "host_mi29", "hybrid_mi29_p4", "post_exec_host_all", "nuisance_only",
               "acquisition_metadata_only", "dup2_max_stump"], perm=True, ablate=True)
    b_all = cohort("benign_elf", "malware")
    y_b, g_b = run_block("B_benign_elf_vs_malware_all_accepted_host", b_all, lambda r: r["label"],
                         ["host_all", "post_exec_host_all", "nuisance_only"])
    results["B_alignment_exclusions"] = {
        c: dict(Counter(r["p4_alignment"] for r in b_all if r["cohort"] == c)) for c in ("benign_elf", "malware")}

    # B fold-seed stability (host_all, P4) on aligned subset.
    y = np.asarray([r["label"] for r in b_aligned]); g = np.asarray([r["group"] for r in b_aligned])
    stab = defaultdict(list)
    for seed in range(100, 105):
        sp = splits_for(y, g, seed=seed)
        check_splits(y, g, sp)
        for model, cols in (("host_all", HOST), ("p4", P4_SAMPLE_FEATURES), ("nuisance_only", NUISANCE)):
            stab[model].append(float(balanced_accuracy_score(y, (oof(matrix(b_aligned, cols), y, sp, trees=200) >= 0.5))))
    results["B_fold_seed_stability"] = {m: {"mean": round(float(np.mean(v)), 4), "min": round(min(v), 4),
                                            "max": round(max(v), 4)} for m, v in stab.items()}

    # E: family-disjoint feasibility and leave-group-out per-group error (GroupKFold 10) on B all-host.
    x = matrix(b_all, HOST)
    gk = list(GroupKFold(n_splits=10).split(x, y_b, g_b))
    check_splits(y_b, g_b, gk)
    prob = oof(x, y_b, gk)
    per_group = {}
    for grp in sorted(set(g_b)):
        idx = g_b == grp
        per_group[grp] = {"n": int(idx.sum()), "mean_prob_malware": round(float(prob[idx].mean()), 3),
                          "error_rate": round(float(np.mean((prob[idx] >= 0.5) != y_b[idx])), 3)}
    sizes = Counter(g_b)
    results["E_feasibility"] = {
        "B_groups": {"benign_elf_tools": len({gg for gg in g_b if gg.startswith("benign_elf")}),
                     "malware_signatures": len({gg for gg in g_b if gg.startswith("malware")}),
                     "malware_singletons": sum(1 for gg, n in sizes.items() if gg.startswith("malware") and n == 1),
                     "largest_group": max(sizes.values())},
        "GroupKFold10_host_all": metrics(y_b, prob, g_b),
        "per_group_heldout": per_group,
    }

    results["observation_seconds_distinct_values"] = sorted({r["observation_s"] for r in rows})
    (HERE / "diagnostics_results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({k: v for k, v in results.items() if k != "E_feasibility"}, indent=1)[:20000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
