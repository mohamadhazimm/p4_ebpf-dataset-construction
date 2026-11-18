# Cross-dataset test: train on LID-DS 2021, test on our dataset, and the reverse (2026-11-12)

Offline. No VM operation, no new data. The protocol is in `cross_eval.py`'s docstring and was written to
`protocol.json` before any row was scored.

    /usr/bin/python3 build_ours_10s.py run-20261112                  # about 1 min
    /usr/bin/python3 cross_eval.py run-20261112 run-20261112         # about 8 min
    /usr/bin/python3 report_cross.py run-20261112/cross-20261112T153637Z

## Data

- **LID-DS:** 15 scenarios, 1,721 attack and 15,305 normal windows of 10 s (20 × 0.5 s), from
  `../lidds-external`. The 15,305 end-of-recording control windows were only scored.
- **Ours:** the 240 rows of `dataset/features.csv`, cut to their first 20 windows (10 s), so both
  sides have the same shape. Malicious: 99 malware + 15 DoS runs. Benign: 105 programs, 18
  network-active, 3 null runs.
- **Gate:** each run's raw data reproduce its published row (network 1.7e-15, host 1.8e-15), and
  cutting 40 windows to 20 equals computing 20 directly.
- **Primary version:** our rows without the 178-call launcher, since LID-DS servers are already running
  and have no launcher. Secondary: as collected.

Models are the paper's: forests of 500 trees, balanced, seed 42, and the stacked hybrid.

## Results (primary version, threshold 0.5; BA / AUC)

| | host | network | hybrid | concatenated |
|---|---|---|---|---|
| Train LID-DS, test ours (240) | 0.553 / 0.705 | 0.524 / 0.591 | 0.554 / 0.622 | 0.524 / 0.621 |
| Train ours, test LID-DS (17,026) | 0.514 / 0.581 | 0.587 / 0.608 | 0.557 / 0.623 | 0.558 / 0.614 |
| *In domain: ours, 10 s, grouped CV (10 assignments)* | *0.822 / 0.898* | *0.750 / 0.763* | *0.841 / 0.921* | |
| *In domain: LID-DS, seen attack types (E2)* | *0.858 / 0.982* | *0.884 / 0.991* | *0.961 / 0.995* | *0.912 / 0.996* |
| *In domain: LID-DS, unseen service (E1, mean)* | *0.519 / 0.730* | *0.596 / 0.760* | *0.648 / 0.753* | *0.586 / 0.780* |

As collected (with the launcher): train LID-DS → ours hybrid 0.614 / 0.633, host 0.531 / 0.723;
train ours → LID-DS hybrid 0.566 / 0.640, host 0.539 / 0.609. Neither direction transfers.

**Train LID-DS → test ours.** The model calls almost everything of ours normal: host flags 10% of
malware and 0% of benign. The network model flags 67% of the DoS runs, and the hybrid 80%, but the
hybrid also flags 61% of the network-active benign and 32% of the benign programs. With the threshold
set on our own benign rows (5% false alarms), it catches 10-18% of the malicious runs.

**Train ours → test LID-DS.** The host model calls almost every server window malicious: 96% of normal
windows flagged, 99% of attacks. The network model is less biased (37% recall, 20% false alarms). With
the threshold set on each service's own normal windows (5% false alarms), it catches 26-30% of the
attacks on average. Per-scenario AUC is high only where the attack changes the traffic a lot: CouchDB
CVE-2017-12635 0.98, CVE-2020-23839 0.99, Tomcat CVE-2020-9484 0.96, and for the network model SQL
injection 0.85. The mean per-scenario AUC (0.64-0.71) is close to LID-DS's own leave-one-service-out
AUC (0.73-0.78). So moving to a new service already costs most of the accuracy, even inside LID-DS.

## Why: the two datasets measure different things

A forest tells the two datasets apart with AUC 0.997 (host), 0.988 (network), 0.97 (activity alone).
Medians per 10 s:

| | calls | packets | flows (max) | host-active windows (of 20) |
|---|---|---|---|---|
| LID-DS normal | 22,263 | 531 | 14 | 19 |
| LID-DS attack | 28,650 | 854 | 24 | 18 |
| ours benign | 518 | 0 | 0 | 1 |
| ours malware | 562 | 4 | 1 | 1 |
| ours DoS | 150,020 | 39,847 | 1,017 | 3 |

- LID-DS observes a server that is already running and busy, and the attack is a request to it.
- Ours observes one program from its start: most finish in under a second, and the malware is mostly
  not triggered.
- Our benign programs are almost never active for 10 s (2% of them are), while 58% of LID-DS windows
  are active in at least 18 of 20.
- So a model trained on ours reads "busy all the time" as malicious. A model trained on LID-DS sees
  every one of our rows as quieter than any normal server window.

## What this does and does not show

- **Shows:** the features and the models do not carry over between a program-execution dataset and a
  server-exploit dataset. Each dataset needs its own benign data. This matches the IoT-23 and LID-DS
  E1 results (per-site benign enrollment is a deployment requirement).
- **Does not show:** that the architecture or features are wrong. In domain, both datasets give
  the paper's pattern (hybrid ≥ the better sensor).
- Not tried, would be post hoc: a timing-free view of the features, or training on both datasets
  together.

| file | SHA-256 |
|---|---|
| `build_ours_10s.py` | `2b2e42c8880bffa689256b9a2cb9d85356148c87d0548a7f53ed99e7b27ea150` |
| `cross_eval.py` | `5a66f1a943b7bfd56892faec2e179bd14e41b0561e0619d0f88cd951b40adc40` |
| `report_cross.py` | `381000b0af89bf5e005ee0661f1735cdc8bff6a0cc9da0eb8345d438c238c224` |
| `run-20261112/features_10s_prologuefree.csv` | `9a76abc1859e5b5390bfb9afeba219ab4f58964e355869db71c8412e5c28a3ee` |
| `run-20261112/features_10s_ascollected.csv` | `945958ef6b435ed4f94e83b250a53636c3468f5a7d935f49e4818e0c191b1a6b` |
| `run-20261112/build.json` | `ef9fabfdaf6a26d3d7ca0672d47aa8846197449b5803f7007434d6d7a9373a02` |
| `run-20261112/cross-20261112T153637Z/protocol.json` | `5642df7ceb49d8fb013ff3a489dad6245409874d6c7549cc482a0ab662677bcb` |
| `run-20261112/cross-20261112T153637Z/results.json` | `6cd9d3ac37d475340e762bf2b578808c2dec0d490d5cfada809af1f79cc0c9a9` |
| `run-20261112/cross-20261112T153637Z/probabilities.npz` | `bbc2291f65c7b42dbc566eae7aeb68fa0233a105e6f63ffd0587b346e41047be` |

## Like-for-like split (2026-11-12, `like-for-like/`)

Why LID-DS reaches 0.96 and ours 0.82: LID-DS's E2 uses random folds, so every scenario's exploit is in
training and test. Our Table V holds out whole families and projects. Scored the same random way
(`split_check.py`, release `combined.run` with each row its own group, 10 assignments), our 240 rows give
host 0.937 ± 0.009 (AUC 0.979), network 0.787 ± 0.003 (0.842), hybrid 0.945 ± 0.008 (0.985). The
grouped run reproduces Table V exactly (0.784 / 0.756 / 0.823). LID-DS's own held-out test (new service,
E1) gives hybrid 0.648.

Remaining misses (Table V, hybrid, saved predictions): 95% of the missed malware made fewer than 300 calls
after its start (44 of the 99 malware made fewer than 300 calls: 24 with 1-99 calls are caught 31% of the time, 19 with 100-299
calls 57%). Malware with at least 300 calls is caught 98-100% of the time.

`split_check.py` 71aedfe167e2dc0d..., `split_check.json` 1377c8e87a16129d...
