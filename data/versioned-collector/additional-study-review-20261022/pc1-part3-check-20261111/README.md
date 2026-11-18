# Check of PC1.md part 3 (2026-11-11)

Offline checks of p4_ebpf `c64f029` (PC1.md "Results, part 3"): the startup-free detectors of
`live_test/prologuefree/features_05s_prologuefree.csv` (= `../launcher-ablation-05s/run-20261111/`) and
the 47 live executions rescored. No VM, no model promotion, no merge.

## 1. The programs' own start-up, call by call (`first50.py`)

`/usr/bin/python3 first50.py` (run inside `results/`) reads the raw `syscall_events.csv` of the 105
benign dataset runs (revision5) and lists the root's first 50 calls after its second exec success
(the program's first calls; x86_64 or i386 names from the kernel headers) -> `results/dataset_first50.json`.
The distinct count equals the startup-free `host_first50_unique_mean__max` in 103 of 105 rows (the
other two have child processes in window 0).

- All 18 dynamic programs: the loader and the C library start `brk mmap access openat fstat ... arch_prctl
  set_tid_address set_robust_list rseq mprotect ... prlimit64 getrandom munmap`, then the program.
  17-22 distinct (median 19).
- 47 of 59 amd64-static and 21 of 28 i386-static (glibc 2.35 static builds of this host) contain
  `set_tid_address set_robust_list rseq ... prlimit64 ... getrandom` too; the other 19 are musl builds
  (curl, wget, openssl, ...: `arch_prctl set_tid_address` only).
- The guest's libc is 2.43-2ubuntu2.4 (workspace ledger, 2026-10-21; the VM is named
  Ubuntu-Clean-24.04), not 2.39 as PC1.md says.
- This host (glibc 2.35): `/usr/bin/b2sum` makes 17 distinct calls in its first 50, the same five
  (`results/b2sum_host_glibc2.35.strace`). PC1 (glibc 2.31) has 9-16 (median 12). Not measured on PC1
  call by call: one `strace /usr/bin/b2sum` there would show it.

## 2. Table V and the training CV depend on the scikit-learn version

scikit-learn 1.8.0 changed `StratifiedGroupKFold(shuffle=True)`. Before it, the rows of per-group class
counts were shuffled but not mapped back to the samples, so the class balance of each fold was computed
from other groups' counts. Folds were still group-disjoint, so no leakage.
`sklearn-1.9.1/_split.py` is that file from the 1.9.1 wheel (BSD-3, `COPYING`; wheel hashes in
`wheels.sha256`); the scripts patch its `_iter_test_indices` / `_find_best_fold` into the installed
1.7.0, leaving everything else of 1.7.0, and call the release's `evaluation/` code unchanged.

`run_patched.py CSV stock|patched` -> `results/table5.txt`; BA mean +/- sd over the 10 fold assignments:

| | host | network | hybrid |
|---|---|---|---|
| published, stock 1.7 | 0.784 +/- 0.022 | 0.756 +/- 0.016 | 0.823 +/- 0.015 |
| published, >=1.8 shuffle | 0.795 +/- 0.026 | 0.759 +/- 0.014 | 0.834 +/- 0.017 |
| published, PC1 (1.9.1) | 0.796 | 0.760 | 0.828 |
| startup-free, stock 1.7 | 0.832 +/- 0.023 | 0.756 +/- 0.016 | 0.866 +/- 0.026 |
| startup-free, >=1.8 shuffle | 0.854 +/- 0.023 | 0.759 +/- 0.014 | 0.869 +/- 0.023 |
| startup-free, PC1 (1.9.1) | 0.852 | 0.760 | 0.872 |

The stock run reproduces the paper exactly. The shuffle accounts for nearly all of PC1's change in host
and network; the hybrid's remaining 0.006 comes from other 1.7 -> 1.9 changes (not traced).
Table IV (the frozen held-out split) does not use the splitter and is the same in every version.

`cv_patched.py CSV` -> `results/training_cv_seed42.txt`: `heldout.py`'s training grouped CV (one fold
assignment, seed 42): published 0.747 / 0.632 / 0.718 (network / host / hybrid) stock, 0.747 / 0.757 /
0.804 with the >=1.8 shuffle. `cv_seeds.py CSV` -> `results/cv_seeds.txt`, the same over fold seeds
42, 0-8:

| training grouped CV, mean +/- sd (min-max) | network | host | hybrid |
|---|---|---|---|
| published, stock | 0.734 +/- 0.039 (0.623-0.747) | 0.701 +/- 0.043 (0.632-0.786) | 0.748 +/- 0.036 (0.684-0.805) |
| published, >=1.8 | 0.744 +/- 0.004 | 0.722 +/- 0.019 (0.698-0.757) | 0.779 +/- 0.031 (0.719-0.819) |
| startup-free, stock | 0.734 +/- 0.039 | 0.791 +/- 0.025 (0.748-0.840) | 0.815 +/- 0.036 (0.730-0.854) |
| startup-free, >=1.8 | 0.744 +/- 0.004 | 0.782 +/- 0.018 (0.754-0.814) | 0.811 +/- 0.027 (0.781-0.861) |

The paper's host 0.632 is the lowest of the ten stock assignments. Removing the launcher raises the
training CV in each case, by +0.06 to +0.09 (host) and +0.03 to +0.07 (hybrid) on average, less than
the +0.116 / +0.089 of seed 42 alone.
