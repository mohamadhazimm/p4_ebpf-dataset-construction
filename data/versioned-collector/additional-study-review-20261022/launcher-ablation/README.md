# Launcher-confound ablation (2026-11-04)

Tests whether the host detector keys on the fixed launch prologue (the common launch wrapper
`/bin/bash -c 'exec "$@"'`) rather than on program behaviour. The prologue is exactly 178 system
calls, identical in all 240 rows of `dataset/features.csv` (host total = syscall_count + 178), and
occurs entirely in window 0 (before the target's `execve`).

## Run
    python3 lt_build.py            # builds features_launcherfree.csv from the raw runs; prints gates
    python3 lt_eval_heldout.py     # held-out (Table IV) + grouped-CV, original vs launcher-free
    python3 lt_eval_combined.py    # combined (Table V); writes combined_results.txt

`lt_build.py` removes the root process's pre-`execve` calls (the prologue) per run, recomputes the
90 host features with the release `features/host_model.py` (windows 1-39 are untouched), and gates:
(1) the full recompute reproduces the released 90 host columns for all 240/240 rows, and (2) the
removed prologue is exactly 178 calls for all 240. Raw runs: revision5-collection/.../20261025T100025568989Z/runs
(malware+benign+null) and the flood21/realtools/vm-batches background batches (attack/net-benign/null).

## Result (as-collected -> launcher-free; network untouched)
- Held-out:  host 0.929 -> 0.929 (identical CM 24/4/0/26); hybrid 0.926 -> 0.946.
- Grouped CV: host 0.632 -> 0.748; hybrid 0.718 -> 0.807.
- Combined:  host 0.784 -> 0.832; hybrid 0.823 -> 0.866.

The prologue is class-independent, so it cannot separate the classes; removing it leaves held-out
detection identical and raises every CV estimate. The reported figures are conservative, not
inflated. Report as a robustness ablation; the released dataset keeps the prologue (every collected
row has it), so `evaluation/` still reproduces the paper's as-collected numbers.
