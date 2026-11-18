# The 240 rows without the launch prologue, at 0.5 s (2026-11-11)

Redoes the 2026-11-04 launcher ablation with scripts that stay here (the first run's were temporary).

    /usr/bin/python3 build_05s.py run-20261111       # about 2 min
    /usr/bin/python3 ../switch-exact-1s/score_rows.py run-20261111/scores.json \
        published=<release>/dataset/features.csv prologuefree=run-20261111/features_05s_prologuefree.csv

- **Gate:** with every call, the release's `host_model.py` on each run's `syscall_events.csv` reproduces
  the 90 published host columns of all 240 rows (relative 1.8e-15).
- **Prologue:** the root process's calls before its second exec success (`bash -c 'exec "$@"'` -> the
  program): 178 in all 240 runs.
- Network columns and metadata are copied unchanged. Scoring uses the release's evaluation code unchanged.

| BA | host | network | hybrid |
|---|---|---|---|
| Table IV, as published | 0.929 (24/4/0/26, AUC 0.993) | 0.750 | 0.926 (26/2/2/24) |
| Table IV, prologue-free | 0.929 (24/4/0/26, AUC 0.973) | 0.750 | 0.946 (25/3/0/26) |
| Table V, as published | 0.784 +- 0.022 | 0.756 +- 0.016 | 0.823 +- 0.015 |
| Table V, prologue-free | 0.832 +- 0.023 | 0.756 +- 0.016 | 0.866 +- 0.026 |
| training grouped CV, as published | 0.632 | 0.747 | 0.718 |
| training grouped CV, prologue-free | 0.748 | 0.747 | 0.807 |

The same numbers as on 2026-11-04. The live rows of PC1 (134-call prologue) are not here and cannot be
recomputed: the monitor aggregates per process in the kernel, and the launcher and the program are one
process, so their calls are already merged.

| file | SHA-256 |
|---|---|
| `build_05s.py` | `0d766aebe47032ed2486eaa2a9c0bea9fac7eb36bb6112167bdd82476985b68c` |
| `run-20261111/features_05s_prologuefree.csv` | `0ba3e62df86ba2b43d69f4f04d66ea880c982071a72921fa1ef91722d8d2ca7b` |
| `run-20261111/build.json` | `1d0186af886f7a5975f8a467f3c9539def4baa4feb083fd10050a2a6623b54fb` |
| `run-20261111/scores.json` | `eb5e815a339da5ec88dc7d2be790ab2688e6a27222cbdc0bba373e5e437d265c` |
