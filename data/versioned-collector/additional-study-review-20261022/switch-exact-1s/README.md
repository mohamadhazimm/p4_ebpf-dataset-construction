# The 240 rows at 1 s with the switch's rules (2026-11-08)

Step 1 of p4_ebpf RUNBOOK 19.5.7 / 19.7.5 item 4: the offline reference for the replays of the
cohort captures through the switch. Results and reading are in RUNBOOK 19.8.2.

    /usr/bin/python3 build_rows.py run-20261108        # 1m40s
    /usr/bin/python3 score_rows.py scores-20261108.json NAME=CSV ...

## `build_rows.py`

**The gate:** each of the 240 runs reproduces its published row before it is rebuilt.
- Network: the release `switch_model.py` at 0.5 s gives the 145 columns, to 1.7e-15.
- Host: the release `host_model.py` on `syscall_events.csv` gives the 90 columns, to 1.8e-15.

**The rebuild,** at 1 s x 20 windows:
- network `published`: `switch_model.py`'s rules;
- network `switch`: the six rules of p4_ebpf `live_test/package_cohort.SwitchRules`;
- host `ascollected`: the 0.5 s windows paired;
- host `prologuefree`: the same without the root's calls before its second exec success (178 per
  run, all 240).

**Outputs** in `run-20261108/`:
- the four `features_1s_*.csv`, in the layout of `features.csv`;
- `windows_1s_switch_prologuefree.csv`, the per-window table for step 3;
- `build.json`: the gates, run directories, run ids, anchors and hashes.

## `score_rows.py`

It uses the release's `evaluation/combined.py` (`run`, 10 fold assignments) and `heldout.py`
unchanged. `baseline_check.json` shows that it reproduces Tables IV and V from `features.csv`.

## Hashes

| file | SHA-256 |
|---|---|
| `build_rows.py` | `29b15a2e0eb3191ce3334ffb2cf6014b792e84a05d3139d6c147b238ebcbd563` |
| `score_rows.py` | `c9456be5ebee806caf7ba7f4f3086fc471d7340a273605ce8934e9ec7aea260b` |
| `scores-20261108.json` | `2b1b8e1a37f028d71bea4ea245ff834dbdbc3b7f10b23929303298505657be8c` |
| `features_1s_switch_prologuefree.csv` | `d8922129c3bb5a8010381880709665cbf5710c030d327d6eddba587c2528e9da` |
| `windows_1s_switch_prologuefree.csv` | `253b12908092aa371eb4110fa057ef1375399ec25b926d1d7ea348e30618af14` |

The packager behind both, p4_ebpf `live_test/package_cohort.py`, has SHA-256
`3270300af4ad2b3bce099963f9b90b2d1e27386f4981831ada23eb08daee46a3` (uncommitted).

Provisional until the release's `--switch-exact` mode exists: rerun with it, and compare.
