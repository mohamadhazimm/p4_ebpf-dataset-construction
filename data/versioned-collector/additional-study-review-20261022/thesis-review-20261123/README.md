# Thesis review analyses, 2026-11-23

Offline analyses made for the readiness review of the thesis. No VM operation, no sample execution, no
model promotion, no merge. All of them are exploratory and post hoc (the data had been examined). Run
each script with `/usr/bin/python3` (scikit-learn 1.7) from this folder; result files stay on the lab
workstation.

| Script | Question | Result file |
|---|---|---|
| `adfa_probe.py` | The ADFA-LD feature probe again, with balanced accuracy | `adfa_probe.json` |
| `learning_curve.py` | Does detection of unseen families improve with more training families, or with more samples per family? | `learning_curve.json`, `.log` |
| `model_family.py` | Does the choice of classifier matter? | `model_family.json`, `.log` |
| `activity_strata.py` | Is the balanced accuracy of about 0.8 uniform, or a mix of programs that ran and programs that did almost nothing? | `activity_strata.json`, `.log` |
| `activity_strata_controls.py` | Inside each group, how far do running time, call count and packet count alone go? | `activity_strata_controls.json`, `.log` |
| `session_operating_point.py` | Recall at 1%, 5% and 10% false alarms on the session base dataset | `session_operating_point.json`, `.log` |

Pools: **A** the first collection's 240 released rows (Table V protocol); **B** its 204 malware and benign
workload rows; **S** the session base dataset, primary view, 20 s (435 rows, `session-lab/base/20261117c`).
Protocol everywhere: whole families, attack runs and benign projects held out, `StratifiedGroupKFold(5)`,
fold seeds 42 and 0-8, Random Forest with 500 trees, balanced, threshold 0.5. Every script first reproduces
the published numbers (Table V: host 0.784, network 0.756, concatenated 0.812; session base: 0.814, 0.735,
0.870).

## Learning curves

In every training fold the training data is cut down, with the test fold unchanged: by **groups** (a fraction
of the families and projects, all their rows) or by **rows** (every group kept, a fraction of each group's
rows, at least one). Balanced accuracy, mean over 10 fold assignments.

| Pool | Cut | 12.5% | 25% | 50% | 75% | 100% |
|---|---|---|---|---|---|---|
| B, host | groups (3 to 22 malware families) | 0.672 | 0.720 | 0.765 | 0.783 | 0.798 |
| B, host | rows (49 to 163 rows, all families) | 0.765 | 0.775 | 0.794 | 0.808 | 0.798 |
| B, concatenated | groups | 0.700 | 0.731 | 0.787 | 0.811 | 0.829 |
| B, concatenated | rows | 0.773 | 0.784 | 0.815 | 0.829 | 0.829 |
| S, host | groups (6 to 44 malicious groups) | 0.677 | 0.729 | 0.795 | 0.815 | 0.814 |
| S, host | rows (91 to 348 rows, all groups) | 0.807 | 0.815 | 0.809 | 0.806 | 0.814 |
| S, concatenated | groups | 0.643 | 0.724 | 0.802 | 0.845 | 0.870 |
| S, concatenated | rows | 0.837 | 0.846 | 0.860 | 0.862 | 0.870 |

- Breadth matters more than depth. At the same training size, more groups win: in S, one or two rows of
  every group (91 rows) give the host detector 0.807, a quarter of the groups with all their rows (95 rows)
  0.729; in B, 0.765 (49 rows) against 0.720 (43 rows).
- Depth still helps somewhat: from one or two rows per group to all rows, host +0.01 (S), +0.03 (B), +0.07
  (A); concatenated +0.03 (S), +0.06 (B), +0.06 (A). Breadth, from a quarter of the groups to all of them:
  host +0.09 (S), +0.08 (B), +0.14 (A); concatenated +0.15 (S), +0.10 (B), +0.11 (A).
- The end of the curves: the last quarter of the groups adds host -0.001 (S), +0.015 (B), +0.027 (A) and
  concatenated +0.025 (S), +0.018 (B), +0.015 (A). The host detector is close to its ceiling on S; the
  hybrid is not.
- These curves describe diminishing returns inside these two collections, not what families from other
  sources would add.

## Classifier

Library defaults fixed before the run, nothing tuned. Balanced accuracy (host / network / concatenated).

| Classifier | A, first collection | S, session base |
|---|---|---|
| Random Forest (thesis) | 0.784 / 0.756 / 0.812 | 0.814 / 0.735 / 0.870 |
| Extra Trees | 0.797 / 0.756 / 0.828 | 0.806 / 0.728 / 0.857 |
| Gradient boosting | 0.767 / 0.743 / 0.804 | 0.787 / 0.732 / 0.822 |
| Logistic regression | 0.762 / 0.772 / 0.808 | 0.782 / 0.758 / 0.828 |
| SVM (RBF) | 0.785 / 0.719 / 0.784 | 0.796 / 0.743 / 0.844 |

No classifier is clearly better than the Random Forest: Extra Trees is 0.01-0.02 higher on the first
collection and 0.01 lower on the session base; the others are equal or lower, by up to 0.05 (gradient
boosting, concatenated, session base). The concatenated hybrid is above the host view for every classifier
in both pools (+0.028 to +0.056) except the SVM on the first collection (-0.001).

## Detection by how much the program did

Share flagged by the program's own system-call count (pool A: calls after the launch prologue, from the
published Table V out-of-fold probabilities; pool S: all calls of the program's control group in its 20 s,
launch included: a null run makes a median 186 calls there against 18 in pool A, so the two pools' counts
are not on the same scale). Bins fixed before pool S was looked at; for pool A the 300-call boundary was
first seen on 2026-11-12.

| Pool A | n | Host | Network | Concatenated | Stacked |
|---|---|---|---|---|---|
| Malware, under 100 calls | 25 | 0.37 | 0.16 | 0.37 | 0.33 |
| Malware, 100-299 | 19 | 0.43 | 0.53 | 0.64 | 0.57 |
| Malware, 300-999 | 6 | 0.90 | 0.67 | 1.00 | 1.00 |
| Malware, 1,000 or more | 49 | 0.98 | 0.68 | 0.97 | 0.98 |
| Benign, under 100 calls | 28 | 0.29 | 0.09 | 0.30 | 0.24 |
| Benign, 100-299 | 18 | 0.27 | 0.00 | 0.08 | 0.06 |
| Benign, 300-999 | 19 | 0.02 | 0.00 | 0.01 | 0.01 |
| Benign, 1,000 or more | 40 | 0.07 | 0.00 | 0.03 | 0.06 |
| **BA, under 300 calls** (44 malware, 46 benign) | | 0.558 | 0.633 | 0.637 | 0.634 |
| **BA, 300 calls or more** (55 malware, 59 benign) | | 0.957 | 0.841 | 0.974 | 0.971 |

| Pool S | n | Host | Network | Concatenated |
|---|---|---|---|---|
| Malware, 100-299 calls | 34 | 0.39 | 0.20 | 0.44 |
| Malware, 300-999 | 32 | 0.57 | 0.67 | 0.76 |
| Malware, 1,000 or more | 100 | 0.92 | 0.70 | 0.95 |
| Benign, 100-299 | 73 | 0.09 | 0.31 | 0.09 |
| Benign, 300-999 | 81 | 0.06 | 0.17 | 0.08 |
| Benign, 1,000 or more | 84 | 0.20 | 0.04 | 0.08 |
| **BA, under 300 calls** (34 malware, 73 benign) | | 0.651 | 0.446 | 0.678 |
| **BA, 300 calls or more** (132 malware, 165 benign) | | 0.850 | 0.794 | 0.913 |

- The call count alone does not separate the classes inside either group of pool A (AUC 0.51 and 0.58).
- The quiet malware of pool A: Qilin 10, Gafgyt 9, Akira 6, BrickStorm 4, Mirai 3, Tsunami 3, GetShell 2
  and 7 single samples; 23 exited normally, 13 with status 1, 3 on a segmentation fault. On Triage
  (`sample-intel-20261113/triage_network-20261115.csv`), 24 of the 44 were silent too, 15 used the network
  (Gafgyt 8, Tsunami 2, Mirai, Nitrogen, PromptLock, BrickStorm, INC) and 5 were uncertain; of the 55 active
  ones, 44 used the network there.
- In the active group of pool A, 38 of the 55 malware sent packets and 5 of the 59 benign programs did: the
  benign programs that use the network are mostly short tasks. The 18 extra network-active benign runs
  (median 5,457 calls) are flagged by host 18%, network 35%, concatenated 36%, stacked 18%.
- Controls (`activity_strata_controls.py`, `.json`, `.log`): a forest on one cue alone, same protocol,
  scored inside each group. In the active group: number of windows with host activity 0.696 (A) and 0.616
  (S); log of the packet count 0.771 (A) and 0.744 (S); log of the call count 0.548 (A) and 0.516 (S). In
  the quiet group every cue is at or below chance (0.34-0.55). The detectors are well above every cue in
  the active group (host 0.957 and 0.850, concatenated 0.974 and 0.913).
- Reading: the detectors are accurate on programs that ran and near chance on programs that did almost
  nothing; 44 of the 99 malware samples of the first collection did almost nothing in the sealed laboratory.
  In the active group, running longer and sending traffic already separate the classes partly, so the
  active-group scores should be read next to those cues.

## Operating points on the session base dataset

Share of the 182 malicious rows flagged when at most 1%, 5% or 10% of the 253 benign rows are flagged
(threshold set per fold assignment after scoring).

| Span | Benign flagged | Host | Network | Concatenated |
|---|---|---|---|---|
| 20 s | 1% | 0.54 | 0.10 | 0.55 |
| 20 s | 5% | 0.66 | 0.40 | 0.76 |
| 20 s | 10% | 0.73 | 0.57 | 0.83 |
| 80 s | 1% | 0.56 | 0.35 | 0.52 |
| 80 s | 5% | 0.72 | 0.58 | 0.78 |
| 80 s | 10% | 0.80 | 0.66 | 0.86 |

At 1% the concatenated hybrid and the host view catch the same share; the hybrid's lead appears at 5% and
10% (+0.06 to +0.10).
