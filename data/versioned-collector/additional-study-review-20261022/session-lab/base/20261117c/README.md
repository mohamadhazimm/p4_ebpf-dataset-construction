# Session-lab base dataset, final (2026-11-17)

Every session-lab run collected under the main settings, including the two benign batches added on 2026-11-17,
pooled into one dataset under one acceptance rule. Each row is one program injected into a running background
(180-s sessions, 4x background, hidden in-kernel monitors, network captured on the Sink behind a passive sinkhole)
and judged by its own windows from its injection. Built by `../../final_netbenign.sh` with
`../../with_runs.py ... -- build_base.py`. Description and caveats: thesis repository `data/lab/session_lab.md`
(§11 for the base, §16 for the benign batches and the cue split); numbers in its `data/lab/session_lab.json`.

**Never merge these rows with the paper's 240-row dataset.** The launch path (no Python launcher prologue), the
background, the monitors and the Sink all differ.

## Runs

| name | attempt (`../../runs/`) | what |
|---|---|---|
| main | `20261115T214153675625Z` | the dataset's programs; stopped at its deadline |
| tpilot | `20261116T100129450384Z` | one sample of each of 13 Triage network-active families, 13 benign |
| floods | `20261116T124104912903Z` | the paper's attack types, 8 network-active benign, 3 nulls |
| triage | `20261116T153432251861Z` | 54 Triage malware (13 families, capped), 44 benign, controls |
| rest | `20261116T223142789936Z` | the main plan's unreached and never-booted sessions, the first pilot's 9 dataset malware |
| silentbenign | `20261117T013400746805Z` | 18 benign clients aimed at the sinkhole's silent listener, 3 nulls |
| netbenign | `20261117T113428913222Z` | 53 benign network clients of 8 programs against answered servers, 3 nulls; 3 repeats (left out) |

The first pilot (1x background) and the stopped first attempt of the network-client batch
(`20261117T105520781257Z`) are left out.

## Rows

Primary view (`relaxed`, `sessions`): **435 rows**, 182 malicious (`label` 1) against 253 benign rows and controls.

| stratum | rows |
|---|---:|
| `malware_dataset99` | 98 |
| `malware_dataset_extra` (LockBit `4dc06ece`, Mirai `0882f75e`) | 2 |
| `malware_triage` | 66 |
| `attack` (floods) | 16 |
| `benign_cli` | 110 |
| `benign_network` | 128 |
| `null` | 15 |

Files, columns, rules and views are as in `../20261117/README.md`; this build adds the two benign batches'
rows. `table45/` holds the Table V-format tables (`table5_base.*`, `table5_paper_sb_nb.*`), `silent-server/` the
silent-listener rows and cross-tab, `cue-split/` the split of the hybrid's lead by row group (`../../cue_split.py`).

## Scores (primary view; balanced accuracy ± sd, 10 fold assignments)

| | host | network | concatenated | stacked |
|---|---|---|---|---|
| 20 s | 0.814 ± 0.017 | 0.735 ± 0.023 | 0.870 ± 0.025 | 0.840 ± 0.022 |
| 80 s | 0.857 ± 0.014 | 0.776 ± 0.014 | 0.887 ± 0.014 | 0.862 ± 0.015 |

Concatenated minus host at 20 s: +0.056 (10 of 10); stacked minus host +0.026 (9 of 10). Baselines at 20 s at most
0.60 (lifetime and batch; two batches are benign only); random features reach 0.54.

## Read before using the network columns

The sinkhole's catch-all listener accepts every connection INetSim does not serve and never sends data. Malware
met it far more often than benign programs (111 of 166 malware rows, 21 of 253 benign rows). The network view
flags 86% of the malware that met it and 10% of the malware that did not, about its 11% on benign rows that did
not. Outside the floods, its malware signal is that cue. Of the concatenated hybrid's lead over host, +0.020 is
earned on the rows that met the listener, +0.037 on rows that never did, and about +0.020 (floods, rows without
network traffic) cannot involve it (`cue-split/cue_split.json`). Use `silent-server/silent_server_rows.csv` to
split or control for it.
