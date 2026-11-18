# Session-lab base dataset (2026-11-17)

Every session-lab run collected under the main settings, pooled into one dataset under one acceptance rule. Each
row is one program injected into a running background (180-s sessions, 4x background, hidden in-kernel monitors,
network captured on the Sink behind a passive sinkhole) and judged by its own windows from its injection. Built by
`../../final_base.sh` with `../../build_base.py`. The full description and every caveat are in the thesis
repository's `data/lab/session_lab.md` (§11 for this dataset); the numbers are in its `data/lab/session_lab.json`
(`base_dataset`).

**Never merge these rows with the paper's 240-row dataset.** The launch path (no Python launcher prologue), the
background, the monitors and the Sink all differ.

## Runs

| name | attempt (`../../runs/`) | what |
|---|---|---|
| main | `20261115T214153675625Z` | the dataset's programs; stopped at its 10:00 UTC deadline |
| tpilot | `20261116T100129450384Z` | one sample of each of 13 Triage network-active families, 13 benign |
| floods | `20261116T124104912903Z` | the paper's attack types, 8 network-active benign, 3 nulls |
| triage | `20261116T153432251861Z` | 54 Triage malware (13 families, capped), 44 benign, controls |
| rest | `20261116T223142789936Z` | the main plan's unreached and never-booted sessions, the first pilot's 9 dataset malware |

The first pilot (1x background) is left out. Main and rest together hold exactly one accepted session of every
program of the dataset.

## Rows

368 program sessions ran. Two floods are rejected under both rules, and five malware whose program never started
are left out (NoEscape and four the dataset rejected).

Primary view (`relaxed`, `sessions`): **361 rows**.

| stratum | rows |
|---|---:|
| `malware_dataset99` (the dataset's malware, all but NoEscape) | 98 |
| `malware_dataset_extra` (LockBit `4dc06ece`, Mirai `0882f75e`, rejected by the dataset) | 2 |
| `malware_triage` (13 Triage families) | 66 |
| `attack` (floods) | 16 |
| `benign_cli` (command-line tasks: 78 of the dataset's, 32 of the Triage cohort's) | 110 |
| `benign_network` (network-active benign: 27 of the dataset's tasks; the pilot's, Triage cohort's and flood batch's clients) | 59 |
| `null` (a program that does nothing) | 10 |

That is 182 malicious rows (`label` 1) against 179 benign rows and controls (`label` 0). The malicious rows cover
40 malware families and 15 attack instances; the benign rows and controls fall into 37 groups.

## Files

- `base_<rule>_<view>_<span>.csv`. Each row has its metadata, then the release's 90 host and 145 network columns
  (same names as `p4-ebpf-malware-detection/dataset/features.csv`).
  - Metadata columns: `execution_id run attempt sid kind stratum label group family project program name mode sha256
    archive t_inject_s in_unique accepted_relaxed accepted_strict`.
  - `rule`: `relaxed` (primary) tolerates a capacity-only overflow of the host monitor's 64-slot connect-address
    set in malware and attack sessions, the rule the flood and Triage batches declared before they ran (11
    sessions). `strict` tolerates nothing.
  - `view`: `sessions` (primary) keeps every accepted program session; a program collected twice is two rows of one
    `group`, so grouped CV never splits them. `unique` keeps each program's first session.
  - `span`: `20s` = 40 windows of 0.5 s from the injection; `80s` = 160.
- `manifest.csv`: every program session that ran, with `accepted_relaxed`, `accepted_strict` and `program_ran`.
- `base.json`, `base.txt`: grouped cross-validation scores (malware family, attack instance and benign project held
  out; 10 fold assignments; threshold 0.5; the paper's four detectors), per stratum and per family, detector minus
  host, baselines (activity, lifetime, injection time, batch, mode) with a random-feature reference, and the C2-implant
  subset.
- `silent-server/`: the sinkhole's silent-listener cue per program (`silent_server_rows.csv`), the cue as a rule
  (`silent_server.json`), and each detector's flags split by the cue (`crosstab.json`).
- `dataset-programs/comparison.json`: `compare_session_lab.py` on main + rest (the dataset's programs against their
  dataset rows).
- `SHA256SUMS`: hashes of the CSVs, the manifest and `base.json`.

## Scores (primary view; balanced accuracy ± sd / AUC)

| | host | network | concat | stacked |
|---|---|---|---|---|
| 20 s | 0.854 ± 0.024 / .92 | 0.769 ± 0.017 / .80 | 0.869 ± 0.015 / .94 | 0.886 ± 0.023 / .92 |
| 80 s | 0.903 ± 0.014 / .94 | 0.775 ± 0.017 / .80 | 0.894 ± 0.018 / .95 | 0.905 ± 0.015 / .93 |

Baselines at 20 s are at most 0.67 (lifetime; 0.71 at 80 s); random features reach 0.54.

## Read before using the network columns

The sinkhole's catch-all listener accepts every connection that INetSim does not serve and never sends data, and
only malware met it. Over this dataset the network view flags 99% of the malware that met the listener and 15% of
the malware that did not, fewer than the 18% of benign programs it flags. Outside the floods (which target the
Sink's own address), the network columns' malware signal is that cue. Use `silent-server/silent_server_rows.csv`
(`tcp_silent_server`, `tcp_silent_server_client_sent`) to split or control for it.

## Loading

```python
import csv
rows = list(csv.DictReader(open("base_relaxed_sessions_20s.csv")))
host = [c for c in rows[0] if c.startswith("host_")]   # 90
net = [c for c in rows[0] if c.startswith("net_")]     # 145
X = [[float(r[c]) for c in host + net] for r in rows]
y = [int(r["label"]) for r in rows]
groups = [r["group"] for r in rows]                     # hold these out together
```
