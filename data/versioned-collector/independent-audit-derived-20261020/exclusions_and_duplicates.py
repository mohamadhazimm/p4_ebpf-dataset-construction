#!/usr/bin/env python3
"""DERIVED, EXPLORATORY: class-dependent exclusions and exact duplicate feature vectors.

Read-only over run_audit.csv and features_derived.csv in this directory; writes
exclusions_duplicates_results.json. No model is trained.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import diagnostics as d  # noqa: E402

csv.field_size_limit(sys.maxsize)


def duplicate_clusters(x: np.ndarray, labels: np.ndarray, groups: np.ndarray, splits) -> dict:
    """Group identical rows; report clusters spanning groups, labels, or validation folds."""
    fold_of = np.empty(len(labels), dtype=int)
    for fold, (_, test) in enumerate(splits):
        fold_of[test] = fold
    clusters: dict[bytes, list[int]] = defaultdict(list)
    for index, row in enumerate(np.nan_to_num(x, nan=-1e300)):
        clusters[row.tobytes()].append(index)
    multi = [members for members in clusters.values() if len(members) > 1]
    return {
        "rows": int(len(labels)),
        "unique_vectors": len(clusters),
        "duplicate_clusters": len(multi),
        "rows_in_duplicate_clusters": int(sum(len(m) for m in multi)),
        "clusters_spanning_groups": sum(len({groups[i] for i in m}) > 1 for m in multi),
        "clusters_spanning_labels": sum(len({labels[i] for i in m}) > 1 for m in multi),
        "clusters_spanning_folds": sum(len({fold_of[i] for i in m}) > 1 for m in multi),
        "cross_group_clusters": [sorted({str(groups[i]) for i in m}) for m in multi
                                 if len({groups[i] for i in m}) > 1],
        "largest_clusters": sorted(
            ({"size": len(m), "groups": sorted({str(groups[i]) for i in m})} for m in multi),
            key=lambda item: -item["size"])[:8],
    }


def main() -> int:
    with (HERE / "run_audit.csv").open() as handle:
        audit = list(csv.DictReader(handle))
    with (HERE / "features_derived.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    # run_audit.csv has no ELF alignment; diagnostics.py computed it fresh into features_derived.csv.
    fresh = {(r["cohort"], r["sample"]): r["p4_alignment"] for r in rows}
    for r in audit:
        r["p4_alignment"] = fresh.get((r["cohort"], r["sample"]), r["p4_alignment"])
    exclusions = {}
    for cohort in ("malware", "benign_script", "benign_elf"):
        cohort_rows = [r for r in audit if r["cohort"] == cohort]
        rejected = [r for r in cohort_rows if r["quality"] != "accepted"]
        misaligned = [r for r in cohort_rows if r["quality"] == "accepted" and r["p4_alignment"] != "unique"]
        exclusions[cohort] = {
            "collected": len(cohort_rows),
            "quality_rejected": len(rejected),
            "accepted_p4_misaligned": len(misaligned),
            "misaligned_by_group": dict(Counter(r["group"].rsplit("::", 1)[-1] for r in misaligned)),
            "misaligned_median_pcap_packets": float(np.median([float(r["pcap_packets_captured"] or 0) for r in misaligned])) if misaligned else None,
            "aligned_median_pcap_packets": float(np.median([float(r["pcap_packets_captured"] or 0) for r in cohort_rows if r["p4_alignment"] == "unique"])),
        }
    subsets = {
        "S183": [r for r in rows if r["in_183_model"] == "True"],
        "A_script_vs_elf": [r for r in rows if r["cohort"] in ("benign_script", "benign_elf")],
        "B_all_accepted": [r for r in rows if r["cohort"] in ("malware", "benign_elf")],
    }
    duplicates = {}
    for name, subset in subsets.items():
        if name == "A_script_vs_elf":
            y = np.asarray([int(r["cohort"] == "benign_elf") for r in subset])
        else:
            y = np.asarray([int(r["label"]) for r in subset])
        g = np.asarray([r["group"] for r in subset])
        splits = d.splits_for(y, g)
        duplicates[name] = {cols_name: duplicate_clusters(d.matrix(subset, cols), y, g, splits)
                            for cols_name, cols in (("host", d.HOST), ("post_exec", d.POST))}
    out = {"derived": True, "exploratory": True, "exclusions": exclusions, "duplicates": duplicates}
    (HERE / "exclusions_duplicates_results.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
