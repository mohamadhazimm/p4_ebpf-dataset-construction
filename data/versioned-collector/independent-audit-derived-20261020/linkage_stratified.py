#!/usr/bin/env python3
"""DERIVED, EXPLORATORY, POST-HOC: static-vs-dynamic linkage as a class proxy (audit 2026-10-20).

Linkage proxy: any lineage process opens a path containing 'libc.so' (named openat events)
after the root's second exec. This is an observed-loader proxy, not an ELF-header parse;
a crashing dynamic binary that dies before the loader opens libc would be misread as static.
Reads frozen outputs only; writes linkage.csv and linkage_results.json here.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import diagnostics as d  # noqa: E402

csv.field_size_limit(sys.maxsize)


def linkage(run_dir: Path) -> dict:
    meta = json.loads((run_dir / "run.json").read_text())
    root = meta["sample_root_pid"]
    with (run_dir / "syscall_events.csv").open(newline="") as handle:
        execs = [int(r["timestamp_ns"]) for r in csv.DictReader(handle)
                 if int(r["pid"]) == root and r["detail"] in ("id=59", "id=322")]
    boundary = execs[1] if len(execs) >= 2 else None
    libc = ld_cache = False
    with (run_dir / "ebpf_events.csv").open(newline="") as handle:
        for r in csv.DictReader(handle):
            if boundary is not None and r["event"] == "openat" and int(r["timestamp_ns"]) > boundary:
                libc |= "libc.so" in r["detail"]
                ld_cache |= "ld.so.cache" in r["detail"]
    return {"libc_opened_after_exec": int(libc), "ld_so_cache_after_exec": int(ld_cache)}


def main() -> int:
    with (HERE / "features_derived.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    with (HERE / "run_audit.csv").open() as handle:
        run_dirs = {(r["cohort"], r["sample"]): r["run_dir"] for r in csv.DictReader(handle)}
    for r in rows:
        r.update(linkage(d.COLLECTOR / run_dirs[(r["cohort"], r["sample"])]))
        r["label"] = int(r["label"])
    with (HERE / "linkage.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["cohort", "sample", "group", "return_code",
                                                    "libc_opened_after_exec", "ld_so_cache_after_exec"])
        writer.writeheader()
        writer.writerows({k: r[k] for k in writer.fieldnames} for r in rows)

    out: dict = {"derived": True, "exploratory_post_hoc": True,
                 "proxy": "libc.so opened by any lineage process after root's second exec"}
    out["by_cohort"] = {c: dict(Counter(int(r["libc_opened_after_exec"]) for r in rows if r["cohort"] == c))
                        for c in ("malware", "benign_script", "benign_elf")}
    out["malware_dynamic_by_return_code"] = dict(Counter(
        f"rc={r['return_code']}|libc={r['libc_opened_after_exec']}"
        for r in rows if r["cohort"] == "malware").most_common())
    out["malware_dynamic_signatures"] = sorted({r["group"] for r in rows if r["cohort"] == "malware"
                                                and r["libc_opened_after_exec"]})

    # Rule "no libc -> malware" (no fitting) on the original 183 and on ELF-vs-malware.
    def rule(subset):
        y = np.asarray([r["label"] for r in subset])
        p = np.asarray([1.0 - r["libc_opened_after_exec"] for r in subset])
        g = np.asarray([r["group"] for r in subset])
        return d.metrics(y, p, g)

    s183 = [r for r in rows if r["in_183_model"] == "True"]
    b_all = [r for r in rows if r["cohort"] in ("malware", "benign_elf")]
    out["rule_no_libc_is_malware"] = {"S183": rule(s183), "B_all_accepted": rule(b_all)}

    # Linkage-stratified: dynamic malware vs benign ELF (all dynamic). Static malware has no
    # benign counterpart in any collected cohort, so its discrimination cannot be evaluated.
    dyn = [r for r in b_all if r["libc_opened_after_exec"]]
    y = np.asarray([r["label"] for r in dyn])
    g = np.asarray([r["group"] for r in dyn])
    sp = d.splits_for(y, g)
    d.check_splits(y, g, sp)
    block = {"samples": len(dyn), "class_counts": dict(Counter(y.tolist())),
             "groups_per_class": {c: len({gg for gg, yy in zip(g, y) if yy == c}) for c in (0, 1)},
             "models": {}}
    for name, cols in (("host_all", d.HOST), ("post_exec_host_all", d.POST), ("nuisance_only", d.NUISANCE)):
        block["models"][name] = d.metrics(y, d.oof(d.matrix(dyn, cols), y, sp), g)
    p4_rows = [r for r in dyn if r["p4_alignment"] == "unique"]
    yp = np.asarray([r["label"] for r in p4_rows]); gp = np.asarray([r["group"] for r in p4_rows])
    spp = d.splits_for(yp, gp)
    d.check_splits(yp, gp, spp)
    block["p4_aligned_subset"] = {"samples": len(p4_rows),
                                  "p4": d.metrics(yp, d.oof(d.matrix(p4_rows, d.P4_SAMPLE_FEATURES), yp, spp), gp),
                                  "host_all": d.metrics(yp, d.oof(d.matrix(p4_rows, d.HOST), yp, spp), gp)}
    out["dynamic_only_benign_elf_vs_malware"] = block
    (HERE / "linkage_results.json").write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
