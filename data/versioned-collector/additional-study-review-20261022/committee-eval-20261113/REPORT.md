# Committee response: analyses on the existing data (2026-11-13)

All results below are offline, on the 240 executions of the release dataset (`dataset/features.csv`), with the
paper's detectors (random forests of 500 trees; hybrids: *concatenated* = one forest on all 235 columns,
*stacked* = logistic regression on inner out-of-fold probabilities of the two forests). Two protocols:
**Table IV** (held-out split: 150 training rows, 54 test rows from 11 malware families and 11 benign projects
never seen in training) and **Table V** (all 240 rows, grouped 5-fold cross-validation, ten fold assignments,
mean +/- sd). Before anything new, the loader reproduced the published features (largest relative difference
1.5e-17) and Tables IV and V exactly (`verify_baseline.py`). scikit-learn 1.7.0.

| Committee item | Status | Main result |
| --- | --- | --- |
| 1 Real switch | offline gap quantified; hardware replay of 107 captures ready for PC1 (p4_ebpf PC1.md Part 4, pushed 2026-11-15) | switch rules change balanced accuracy by at most 0.006, held-out decisions not at all; three bulk-upload captures hold frames above the MTU (offload), split to wire size they change nothing (§1.1) |
| 2 Rigorous evaluation | done | hybrid > host only on the combined pool (stacked +0.039, CI +0.013 to +0.072); attack tools held out: Slowloris missed by every view; five start-up flags alone score as well as the host detector, **but with the benign programs rebuilt with the malware's toolchains the flags fall to 0.39 and the host detector stays at 0.787 (§2.4a): it does not depend on the start-up** |
| 3 Dataset | datasheet + rejection log drafted; temporal split done; encrypted traffic: existing pairs and a new TLS 1.1-1.3/QUIC collection (§3) | 11 rejected executions documented; trained on malware first seen up to June 2026, no detector loses accuracy on the 24 newer samples (host 0.919, network 0.833, concatenated 0.959, stacked 0.953); both hybrids beat host-only in 11 of 11 forest seeds (+0.03 to +0.04), by fewer false alarms |
| 4 Socket attribution | implemented (eBPF socket tracer + per-flow join) and measured live, with and without a malware co-runner | live: every benign flow attributed to the right process and cgroup (2,841 alone; 8,517 beside Mirai, Kaiji, Chaos), the socket join equals ground truth in every window, the window join changes 98-145 of 145 columns; DNS relayed by the guest's local resolver is attributed to the resolver |
| 5 Online detection | streaming analysis; a per-window verdict tool for the switch's own windows ready for PC1 (Part 7) | ~95% of detections in the first 0.5 s window |
| 7 Baselines | done (section 7) | unsupervised STIDE and Kitsune near chance; software flow features 0.780 vs the switch's 0.756; supervised n-grams 0.868 on the released rows, but trained there they flag 73% of benign programs rebuilt with the malware's toolchains (host 11%); retrained with those programs they still beat the host detector, 0.824 vs 0.787, the edge lying in the program's first 50 calls |
| 8 Evasion | offline simulation done, randomized timing added (2026-11-15) | evading one view leaves the other: hybrid recall falls to roughly the remaining view's level; random timing does not evade |
| C2 (advisor) | two VM runs done: real implants against a sinkhole (server down), our own Sliver implants under command (server up) | server down: host 0.80 at 20 s, network and connection-shape features near chance; server up: the tasks show in host activity (52 vs 9 calls per 0.5-s window), not in beacon packet counts; host 0.917, concatenated 0.908, network 0.892, stacked 0.887 at 20 s, and the activity baseline 0.917: the implants are far busier than the benign clients (section 10) |
| 6 Mitigation | offline estimate done (§11); the drop rule on the switch proposed for PC1 (Part 7) | median time to containment 0.86 s, 98% of attack runs within 1 s; a drop rule stops 44% of a 20-s attack run's packets (the bursts start before any verdict) and 88% of the malware's; 20% of benign runs blocked at threshold 0.5, 5% at 0.8; a switch-side first stage (new flows per source, packets per flow; estimate, §11.1) would stop every attack run 4-200 ms after it starts (over 99% of their packets), at thresholds set on these data |
| 9 Multi-host | host-level join (`--scope-ip`) implemented and tested; the run proposed for PC1 (Part 8) | not measured |
| Lab cue (found by us) | measured (§2.7) | in the sealed lab only malware leaves connections unanswered, and the network detector's general-malware detection rests largely on that: the cue alone scores 0.769 on the held-out split (network detector 0.750), all 13 held-out network detections carry it, and answering the same C2 samples halves the network flags (18 -> 9 of 28); floods and the host detector do not depend on it; without the cue runs the hybrid's combined-pool edge over host-only is not robust (4 of 10 assignments); the external LID-DS result does not rest on it (§2.7) |

## 2. Rigorous evaluation

### 2.1 Both hybrids, confidence intervals, McNemar

Confidence intervals: cluster bootstrap, whole groups (families, projects, attack runs) resampled within each
class (10,000 resamples for Table IV, 4,000 for Table V). McNemar: exact test on paired decisions.

**Table IV (held-out, 54 rows)**

| Detector | BA | AUC | TN/FP/FN/TP | BA 95% CI | BA over 11 forest seeds |
| --- | ---: | ---: | --- | --- | --- |
| Network-only | 0.750 | 0.788 | 28/0/13/13 | 0.645-0.875 | 0.750 +/- 0.000 |
| Host-only | 0.929 | 0.993 | 24/4/0/26 | 0.846-1.000 | 0.927 +/- 0.005 |
| Hybrid, concatenated | 0.926 | 0.982 | 26/2/2/24 | 0.821-1.000 | 0.926 +/- 0.000 |
| Hybrid, stacked | 0.963 | 0.995 | 27/1/1/25 | 0.895-1.000 | 0.932 +/- 0.021 (0.909-0.963) |

McNemar: stacked vs host p = 0.63 (3 vs 1 discordant), concatenated vs host p = 1.0; stacked, concatenated and
host each vs network p = 0.003, 0.022, 0.049. On unseen families the two hybrids and host are statistically
indistinguishable; all three beat network-only. The stacked hybrid's 0.963 is the best of eleven forest seeds.

**Table V (combined pool, 240 rows, ten fold assignments)**

| Detector | BA | 95% CI of the mean | AUC | Recall | Specificity | F1 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| Host-only | 0.784 +/- 0.022 | 0.681-0.875 | 0.839 | 0.745 | 0.824 | 0.768 |
| Network-only | 0.756 +/- 0.016 | 0.658-0.853 | 0.769 | 0.582 | 0.931 | 0.702 |
| Hybrid, concatenated | 0.812 +/- 0.021 | 0.707-0.903 | 0.876 | 0.782 | 0.842 | 0.800 |
| Hybrid, stacked | 0.823 +/- 0.015 | 0.723-0.909 | 0.866 | 0.773 | 0.874 | 0.808 |

Paired differences (same resamples): stacked - host +0.039 +/- 0.025, better in 9 of 10 assignments, CI +0.013 to
+0.072 (P > 0 = 0.999), McNemar p < 0.05 in 5 of 10; concatenated - host +0.028, 10 of 10, CI -0.014 to +0.072;
stacked - concatenated +0.011, not significant; host - network +0.028, not significant. The CI of each mean is
wide because whole families are resampled; the paired differences are tighter.

Relation to the thesis's E2d, which reported the stacked - host edge as 0.036 [-0.001, 0.081]
(`bootstrap_designs.py`, same cached predictions, 4,000 resamples):

| Statistic | Resampling | Point | 95% CI | P(> 0) |
| --- | --- | ---: | --- | ---: |
| mean over assignments of each assignment's BA (the published Table V statistic) | within class | +0.039 | +0.013 to +0.071 | 1.000 |
| same | all groups (as E2d) | +0.039 | +0.012 to +0.072 | 0.999 |
| BA of the probability-averaged ensemble of the ten assignments (E2d's statistic) | within class | +0.036 | -0.002 to +0.083 | 0.967 |
| same | all groups (as E2d) | +0.036 | -0.002 to +0.083 | 0.965 |

The difference comes from the statistic, not the resampling. Neither interval includes the variability of
training (the outer folds share data), so the edge is best described as small, consistent and borderline.

Where today's analyses meet the earlier follow-ups (thesis AGENTS.md §4.18): grouping by attack type reproduces
E2a (unseen Slowloris missed, unseen floods caught by network); concatenated 0.812 equals E2b; the switch rules
agree with E3 (network 0.750-0.756, stacked 0.822-0.823) and add the per-rule decomposition, the live
collector's corrections and the attack recall under a read budget; the co-runner simulation is the
attribution-level counterpart of E4's measured background traffic.

Artifact baselines (forests on one input, Table V protocol): return code 0.658, lifetime (host active windows)
0.588, activity (log system calls) 0.470, execution mode 0.401.

### 2.2 Which families each view misses (Table V, share flagged over ten assignments)

- Missed by every view: Qilin 0/10 (stops at once without its password argument), BrickStorm (4), GetShell (2),
  Nitrogen (1); Akira about half (0.45-0.52).
- Caught by host only (silent on the network): Tsunami (8), DeskRAT (3), Bert (2), LockBit, NoEscape, CatStorm,
  ChinaZ.
- Gained by fusion: DDoSAgent (host 0.47, network 0.33, stacked 0.67, concatenated 0.60); Gafgyt (0.82 / 0.90 ->
  0.99 / 1.00); PromptLock (0.50 / 1.00 -> 1.00).
- Benign false alarms: rsync (host 0.90), the two beacons (host 1.00), the three null runs (host and stacked
  0.90), bulk uploads (network 0.44), DNS bursts (network 0.57).

### 2.3 Network attacks grouped by tool

Published grouping holds each attack *run* out alone, so runs of the same tool are on both sides of a fold.

| Grouping | Slowloris | GoldenEye | SYN flood | UDP flood | Stacked BA |
| --- | --- | --- | --- | --- | ---: |
| Published (per run) | 0.96/0.96/0.92/0.98 | 1.00 all | 0.93/1.00/0.97/1.00 | 0.90/1.00/1.00/1.00 | 0.823 |
| By attack type | 0.00/0.10/0.00/0.00 | 1.00/0.55/0.90/1.00 | 0.30/0.97/0.70/0.78 | 0.00/0.95/0.45/0.47 | 0.782 |
| By implementation (C generator vs Python tools) | 0.00 all | 1.00/0.00/1.00/0.80 | 0.10/0.97/0.25/0.95 | 0.00/1.00/0.03/0.15 | 0.796 |

(host / network / concatenated / stacked recall.) Findings: (1) Slowloris is detected only when other Slowloris
runs are in training: tool fingerprinting, as the committee suspected; an unseen slow attack is missed by every
view. (2) The network view generalizes to unseen SYN and UDP floods (0.95-1.00). (3) The learned fusion does not:
trained only on the Python tools, which the host view catches, both hybrids learn to discount the network view
and miss most UDP floods. Flood detection should therefore not depend on the learned fusion alone (the thesis's
switch-side flood argument). (4) The Python-interpreter giveaway is not supported: with both Python tools held
out together, host flags GoldenEye 1.00 and Slowloris 0.00, though both run in the same interpreter. Overall
stacked BA falls from 0.823 to 0.78-0.80, host from 0.784 to 0.75, network from 0.756 to 0.73-0.74.

Benign Python programs added (2026-11-15, `encryption/python_benign.py`, `encryption/python_benign.json`;
exploratory pools, the published numbers stand). The encrypted-traffic collection (§3) gives 24 benign Python network
clients started exactly like the Python attack tools (flood_gen `pyexec` -> `/usr/bin/python3`) and 30 benign Go
clients. Added to the 240 rows, the Python clients in one group and the Go clients in another, under the same three
groupings (ten assignments; the 240-row pool reproduces the table above):

| Pool, grouping | GoldenEye (host / network / stacked) | Slowloris (host / network / stacked) | Python clients flagged (host / network / stacked) |
| --- | --- | --- | --- |
| + Python clients, published | 1.00 / 0.90 / 1.00 | 0.98 / 0.96 / 0.96 | 0.68 / 0.07 / 0.25 |
| + Python clients, by attack type | 1.00 / 0.25 / 0.85 | 0.00 / 0.00 / 0.00 | 0.65 / 0.00 / 0.12 |
| + Python clients, by implementation | 1.00 / 0.00 / 0.65 | 0.00 / 0.00 / 0.00 | 0.66 / 0.00 / 0.21 |
| + Python and Go clients, by implementation | 1.00 / 0.00 / 0.10 | 0.00 / 0.00 / 0.00 | 0.24 / 0.00 / 0.08 (Go 0.29 / 0.00 / 0.20) |

- With benign Python programs in the training data the host view still flags GoldenEye in every assignment and still
  misses an unseen Slowloris: the interpreter is not what it keys on.
- Held out as a group, the benign Python clients are flagged by the host view 65-68% of the time; with the Go clients
  also in training, 7-24%. So the host view's false alarms on these programs come from the benign set's lack of
  always-on network programs, not from Python itself.
- The stacked hybrid's GoldenEye recall falls as benign network clients are added (by implementation: 0.80 -> 0.65 ->
  0.10): trained without either Python tool, it follows the network view, which misses GoldenEye.

### 2.4 Feature importance: not volume or lifetime, not the start-up (2.4a)

Grouped permutation (the five summary columns of one signal shuffled together, out of fold, ten assignments):
the host detector's decisive signal is the rare-system-call ratio (AUC drop 0.056 for its maximum, 0.025 for its
mean), followed by distinct calls among the first 50, entropy and total calls (each <= 0.007). The rare-call ratio
is nearly unrelated to activity (Spearman -0.20). Shuffling every lifetime-like column at once (`active_windows`
of all signals) costs 0.004 AUC, every volume column (`sum`) 0.009. Retraining the host forest: without the volume
signals 0.782, without all `active_windows` and `sum` columns 0.780, shape only (48 columns) 0.772 / AUC 0.837
(all 90: 0.784 / 0.839), volume only 0.519, `active_windows` only 0.637. Network importance is spread over
redundant features (average packet size, byte ratios); on the held-out split the network detector relies most on
its `active_windows` family (AUC drop 0.076): persistence of communication, which also tracks lifetime.

### 2.4a The program start-up: a confound in the data, not in the detector (`startup_check.py`, `startup_check2.py`, `toolchain/`)

The baselines (section 7) found that n-grams of each program's first 50 calls alone match the full n-gram
detector. The same holds for the thesis's host view. The study built its static benign programs with glibc
2.35, whose start-up issues `rseq`, `getrandom` and `set_robust_list`; most static malware is built with other
C libraries or runtimes.

| `rseq` among the target's first 50 calls | benign | malware |
| --- | --- | --- |
| amd64 static | 47/59 | 3/57 |
| i386 static | 21/28 | 0/28 |
| amd64 dynamic (the guest's own glibc for both) | 18/18 | 11/14 |

The 19 benign programs without it are musl-built network clients (4 curl, 3 openssl, 4 wget, 8 inetutils);
curl, inetutils and wget are among the benign projects the host view flags (0.30-0.38).

| Host-side input (network block and protocol unchanged) | Table IV BA (host / concatenated / stacked) | Table V BA (host / concatenated / stacked) |
| --- | --- | --- |
| Published host features | 0.929 / 0.926 / 0.963 | 0.784 / 0.812 / 0.823 |
| Launcher prologue removed | 0.929 / 0.946 / 0.929 | 0.832 / 0.836 / 0.866 |
| Prologue and each process's first 50 calls removed | 0.799 / 0.872 / 0.907 | 0.688 / 0.800 / 0.787 |
| Prologue and first 100 calls removed | 0.687 / 0.758 / 0.828 | 0.640 / 0.761 / 0.765 |
| Host features from each process's first 50 calls only | 0.768 / 0.768 / 0.839 | 0.860 / 0.854 / 0.886 |
| Five start-up flags only (no host features) | 0.904 / 0.942 / 0.942 | 0.837 / 0.908 / 0.921 |

Five yes/no flags score as well as the 90 host columns, above the protocol's 0.75 claim gate on both splits: in
this dataset the start-up alone separates the classes. Whether the host detector reads behaviour or the toolchain
cannot be settled by the cuts above: removing each process's first 50 or 100 calls also removes the early behaviour
of minimal static malware. (Written before the test below, this section first read the association as part of the
host view's accuracy; the test overturned that.)

Direct test: benign programs built with the malware's toolchains (`../toolchain21-collect/20261113T203411281909Z`,
90 runs with the dataset's collector and settings, 20 s; `toolchain/score_toolchain.py`, `results/toolchain_scores.json`).
- 81 builds of the dataset's benign programs and of 4 Go projects: older static glibc (2.5, 2.12, 2.17, 2.27, 2.31)
  29, uClibc 0.9.30.1 19, Go 1.13-1.24 22, UPX-packed 11; 59 amd64 static and 28 i386 static with the 6 controls,
  the dataset's static mix. Plus 6 unchanged dataset tasks as controls and 3 nulls. No malware.
- 88 of 90 accepted. Both Go `hexdump` runs were rejected for eBPF event loss.
- The controls reproduce their dataset rows. The two compute tasks are identical in all 235 columns. The four
  network clients are identical in 227: the other 8 are flow durations, about 3 ms apart. So the new batch measures
  like the dataset.
- The new benign start like the malware. `rseq` 3.5% of the new benign and 3.5% of the static malware;
  `set_robust_list` 40% and 38%; `set_tid_address` 46% and 45% (the dataset's static benign: 78%, 78%, 100%).

| Pool (protocol unchanged) | Five flags | Host | Network | Concatenated | Stacked |
| --- | --- | --- | --- | --- | --- |
| Published Table V (240 rows) | 0.837 | 0.784 | 0.756 | 0.812 | 0.823 |
| Table V, the 87 static benign rows replaced by the 85 new runs (238 rows) | 0.385 +/- 0.054 | 0.787 +/- 0.019 | 0.772 +/- 0.006 | 0.815 +/- 0.010 | 0.818 +/- 0.019 |
| Table V, the 85 new runs added (325 rows) | 0.582 +/- 0.029 | 0.784 +/- 0.009 | 0.779 +/- 0.005 | 0.827 +/- 0.011 | 0.822 +/- 0.021 |
| Published Table IV (flags at forest seed 42; detectors as 11-seed means) | 0.904 | 0.927 | 0.750 | 0.926 | 0.932 |
| Table IV split, same replacement (test: 26 malware, 44 benign), 11 forest seeds | 0.431 | 0.913 +/- 0.007 | 0.750 | 0.887 +/- 0.006 | 0.901 |
| Share of the 85 new benign flagged by the detectors trained on the 240 rows | 0.906 | 0.106 | 0.000 | 0.141 | 0.106 |

Reading.
- With benign programs that start like the malware, the five flags fall below chance (0.39 and 0.43).
- The host detector keeps its accuracy: 0.787 against 0.784 on the combined pool, 0.913 against 0.927 on the
  held-out split.
- Its malware recall is unchanged (0.72 on the combined pool; 26 of 26 on the held-out split), and so is its benign
  false-alarm rate on the combined pool (15.5% against 15.4%).
- Detectors trained on the original rows flag 11% of the new benign programs, where the flags flag 91%. So even the
  detector trained on the confounded data was not relying on the start-up: the association is real in the data,
  but the host features carry enough other signal to reach the same accuracy without it.
- The hybrids hold on the combined pool (0.815-0.818). On the held-out split they are a little lower (0.887-0.901),
  because the larger test set has more benign false alarms (host 8 of 44 against 4 of 28).
- The flag rates by toolchain (transfer): uClibc 21% and UPX 18% of the new benign are flagged by the host detector,
  older glibc 7%, Go 5%.
- Limits: static builds of command-line programs only, one benign-only batch (its controls reproduce the dataset).
  The PC1 live gap (dynamic programs on glibc 2.31) is not covered: its cause remains open, but the start-up alone
  is now an unlikely explanation.
- The supervised n-gram baseline, rerun on the same pools (section 7), behaves the opposite way. Trained on the 240
  rows it flags 73% of the new benign programs. Retrained with them it still beats the host detector (0.824 vs
  0.787), with an edge that lies in the program's first 50 calls.

### 2.5 Time to detection (retrained per observation length)

| Observation | Host | Network | Concatenated | Stacked | Stacked, held-out |
| --- | ---: | ---: | ---: | ---: | ---: |
| 0.5 s | 0.770 | 0.669 | 0.795 | 0.793 | 0.945 |
| 1 s | 0.763 | 0.663 | 0.784 | 0.781 | 0.981 |
| 2 s | 0.758 | 0.710 | 0.789 | 0.777 | 0.981 |
| 5 s | 0.769 | 0.732 | 0.801 | 0.798 | 0.981 |
| 10 s | 0.773 | 0.750 | 0.809 | 0.813 | 0.963 |
| 20 s | 0.784 | 0.756 | 0.812 | 0.823 | 0.963 |

(Table V balanced accuracy, mean of ten assignments; last column Table IV.) The host verdict is available after
the first window; the network view needs about 10 s.

### 2.6 Streaming (committee item 5)

One model per detector trained on all observation prefixes (0.5-20 s) and evaluated every window; a benign run
counts as a false alarm if it is flagged at any time. About 95% of the detections it ever makes happen in the
first 0.5 s window (stacked: 74% of malicious runs flagged at 0.5 s, 78% by 20 s; floods 98% at 0.5 s). Any-time
false alarms grow from 16% to 19% over the 20 s. Trade-off (any-time false alarms by 20 s vs detected by 20 s):
stacked 0.19/0.78 at threshold 0.5, 0.05/0.61 at 0.8, 0.006/0.50 at 0.9; concatenated 0.23/0.82, 0.06/0.74,
0.035/0.65.

### 2.7 A lab cue: connections nobody answered (found 2026-11-13; measured 2026-11-15, `cue/unanswered_cue.py`)

In the sealed lab only the lab's server (the Sink, 10.0.0.1) answers; a packet to any other address is dropped.
Every benign program talks to the Sink, so a connection that nobody answers is a malware-only cue that a real
network would not give. Protocol, definitions and decision rules were written before the analysis ran
(`results/unanswered_cue_protocol.json`; it lists what had already been looked at). A flow is a bidirectional
IPv4 TCP/UDP 5-tuple in the 40 feature windows, parsed with the release's switch model; it is unanswered when no
packet comes back. The parsed packet counts equal `net_pkts_total_delta__sum` in all 240 rows.

| Rows | Runs | No TCP/UDP traffic | Every flow answered | Some flows unanswered | No flow answered |
| --- | ---: | ---: | ---: | ---: | ---: |
| Malware | 99 | 47 | 10 | 12 | 30 |
| Benign CLI programs | 105 | 80 | 25 | 0 | 0 |
| Network-active benign | 18 | 0 | 18 | 0 | 0 |
| Network attacks | 15 | 0 | 8 | 3 | 4 |
| Null | 3 | 3 | 0 | 0 | 0 |

So 42 of the 52 sending malware left at least one flow unanswered (the earlier run-level count, 30, counted only
runs without any reply packet). Their unanswered flows go to public addresses (346 of 351); the attack runs' go
to the fan-out targets in 10.0.0.0/8. The 10 malware runs whose flows were all answered (Kaiji 4, Katana 2,
Ngioweb 2, Chaos, Kaiten) are all in the training split.

What the network detector does with it:

| | Table V (10 assignments) | Table IV (forest seed 42) |
| --- | --- | --- |
| Network detector, BA | 0.756 | 0.750 (28/0/13/13) |
| The cue alone: flag a run that left a flow unanswered | 0.715, no false alarm | **0.769** (28/0/12/14) |
| Network detections that left a flow unanswered | 74% (81% of the malware ones) | 13 of 13 |
| Network recall on malware: no traffic / every flow answered / some or none answered | 0.00 / 0.97 (10 runs) / 0.99-1.00 | 0.00 / none in the test split / 0.92-1.00 |

The cue alone does better than the network detector on the held-out split. The host detector's recall does not
follow it (Table V: 0.98 on answered malware, 0.87-1.00 on the cue runs, 0.49 on malware without traffic).

Without the cue (every run with an unanswered flow removed: 191 rows, 57 malware, 8 attack runs, 126 benign):

| Detector | Table V protocol on the 191 rows, BA (10 assignments) | Table IV split, cue runs removed from training: BA on the 54 test rows (TN/FP/FN/TP, seed 42; mean of 11 seeds) |
| --- | --- | --- |
| Host | 0.744 +/- 0.030 | 0.927 (25/3/1/25); 0.945 |
| Network | 0.599 +/- 0.046 | 0.511 (6/22/5/21); 0.431 |
| Concatenated | 0.754 +/- 0.031 | 0.849 (26/2/6/20); 0.848 |
| Stacked | 0.768 +/- 0.038 | 0.911 (23/5/0/26); 0.920 |

Pre-stated rules. R1 (network signal beyond the cue: on the cue-free pool the network detector's BA exceeds
max(0.5, the traffic rule's 0.468) by at least 0.05 in at least 8 of 10 assignments) is met in 8 of 10: "signal
beyond the cue". That signal is small and comes from the answered runs: answered malware flagged 0.82 and answered
attack runs 0.89, against answered benign programs 0.00 and network-active benign 0.17. On runs without traffic
the network detector returns one constant; trained without the cue runs it fell on the malware side (benign
without traffic flagged 0.84, malware without traffic 0.75), which is why it flags 22 of the 28 held-out benign
programs on Table IV. R2 (the hybrid's edge over host-only survives without the cue: at least +0.02 in at least 8
of 10 assignments): stacked +0.024, 4 of 10; concatenated +0.010, 4 of 10: "no clear edge". The host detector
does not need the cue runs: trained without them it scores 0.927 on the held-out split (published 0.929).

The direct test, already collected: the 28 C2/backdoor malware of the sinkhole run (§10: the sinkhole answers
every connection) against their own 20-s runs of 2026-10-25 (nothing answered). In the earlier runs 18 left
every flow unanswered, 3 had every flow answered, 7 sent nothing; in the sinkhole run 19 had every flow answered,
1 some, 1 none, 7 sent nothing. Malware flagged, of 28 (first 20 s; the sinkhole run's 28 benign clients scored
the same way):

| Detectors | Run | Host | Network | Concatenated | Stacked |
| --- | --- | ---: | ---: | ---: | ---: |
| Table IV (seed 42) | 2026-10-25, unanswered | 24 | 18 | 22 | 22 |
| | sinkhole, answered | 23 | **9** | 16 | 13 |
| | the 28 benign clients of the sinkhole run | 18 | 14 | 14 | 14 |
| Trained on all 240 rows | 2026-10-25, unanswered | 23 | 21 | 25 | 25 |
| | sinkhole, answered | 19 | **7** | 21 | 19 |
| | the 28 benign clients of the sinkhole run | 10 | 8 | 9 | 10 |

Of the 18 earlier runs that left every flow unanswered, the network detector (Table IV) gave 16 a probability of
1.00 (the others 0.98 and 0.71). In the sinkhole run the 17 of them that were now answered scored 0.06-0.97 (the
four Meterpreter stagers 1.00 -> 0.13; Rekoobe 1.00 -> 0.12-0.15), and the one Sliver whose connection still went
unanswered kept 0.98. The host detector's flags barely move. The runs
differ in more than the answers (date, runner .21 vs .22, the sinkhole's DNS answer), but the answers are the
large change.

Reading. In this lab the network detector's general-malware detection rests largely on connections nobody
answered: the cue alone does better on the held-out split, every held-out network detection carries it, and when
the same C2 samples are answered the network flags halve. Floods do not depend on it (the 8 answered attack runs
are caught 0.97 as published, 0.89 without the cue runs in training), and the host detector does not use it. The
hybrid's combined-pool edge over host-only does not survive removing the cue runs (R2). Outside the lab benign
programs also meet unanswered connections (dead servers, filtered ports) and C2 servers usually answer, so the
network view's general-malware recall measured here is optimistic. Training data in which every connection is
answered for benign programs and malware alike would remove the cue; the sinkhole run (§10) is a step in that
direction, and there the network view did not separate the implants from beacon-like benign clients.

**LID-DS, checked for the same cue (2026-11-15, `cue/lidds_cue_check.py`, `cue/lidds_gain_without_cue.py`;
`results/lidds_cue_check.json`, `results/lidds_gain_without_cue.json`).** In LID-DS 2021 (thesis note
`lidds2021.md`) the victim is a server that answers attackers and normal users alike. Its captures were deleted
after extraction, so the check uses the saved features: U = `net_flow_count_seen__sum - net_flows_with_ba__sum`,
the active flows without a reverse packet so far, summed over the windows. On our 240 rows U > 0 finds all 49
runs with an unanswered flow and also 13 busy runs (attack runs and network-active benign, U 1-82) whose answer
came in the next window, so it can only overstate the cue. In LID-DS, U > 0 in 56% of attack windows, 43% of
normal and 26% of end-control windows; no attack window lacks reverse packets entirely (normal 1.6%). The rule
"flag U > 0" scores BA 0.565 pooled (AUC of U 0.599; the flow count alone 0.626). Per scenario it is near chance
(BA 0.43-0.61) in 13 of 15 and separates in two: CVE-2020-23839 (0.909, AUC 0.994) and SQL injection (0.714, AUC
1.000), where host, network and hybrid already score 0.97-1.00. Gain over the better single sensor (the network in
every case) at matched false alarms, recomputed from the saved out-of-fold scores of the ten assignments (no
refit):

| Scenarios | Attack / normal windows | Stacked hybrid, points at 0.1 / 1 / 2 / 5% | Concatenated | Positive |
| --- | --- | --- | --- | --- |
| All 15 (as reported) | 1,721 / 15,305 | +5.7 / +5.6 / +4.4 / +2.4 | +7.5 / +6.2 / +5.1 / +3.6 | 10/10 at every rate |
| Without CVE-2020-23839 and SQL injection | 1,481 / 13,248 | +6.2 / +6.3 / +5.4 / +3.1 | +8.6 / +7.3 / +6.2 / +4.4 | 10/10 |
| Also without CouchDB and Juice Shop (BA 0.61, AUC 0.69) | 1,242 / 11,201 | +8.5 / +7.4 / +6.2 / +3.4 | +10.4 / +8.4 / +7.1 / +4.5 | 10/10 |

The scenarios left out were chosen after seeing the check, so this is a sensitivity check. The LID-DS fusion gain
does not rest on unanswered connections; it is larger in the scenarios without them.

## 4. Window-level vs socket-level join (committee item 4)

Exact simulation: each run's per-window flow aggregates recombine into the switch features of concurrent traffic
(a mixture of one run reproduces the dataset with difference 0; flows of different programs share no switch
state). A test execution is replayed with k co-runners from the same test fold, starting 0-10 s later; host
features stay the program's own (eBPF attributes system calls to processes); the switch features are the
program's own flows (socket join) or every flow of the window (window join, the current design).

| Co-runners | Socket join (stacked BA) | Window join: network / concatenated / stacked BA | Window join: benign CLI false alarms (network / stacked) |
| --- | ---: | --- | --- |
| none | 0.823 | 0.756 / 0.812 / 0.823 | 0.02 / 0.10 |
| 1 benign | 0.823 | 0.729 / 0.801 / 0.805 | 0.08 / 0.11 |
| 4 benign | 0.823 | 0.701 / 0.781 / 0.789 | 0.13 / 0.13 |
| 8 benign | 0.823 | 0.681 / 0.765 / 0.784 | 0.18 / 0.14 |
| 1 malicious | 0.823 | 0.600 / 0.651 / 0.699 | 0.58 / 0.46 |
| 1 malicious + 7 benign | 0.823 | 0.597 / 0.655 / 0.734 | 0.54 / 0.34 |

With benign co-runners the network view's flood recall falls from 0.99 to 0.87 (k = 8) as benign traffic dilutes
the flood signature. Retraining on mixtures does not help (stacked 0.773 at k = 8, more false alarms). With one
malicious co-runner the window join cannot tell which program is responsible, and benign programs sharing the host
are flagged 46-58% of the time. Several hosts behind the switch: if the join scopes flows by host IP, one program
per host is the socket-join case; without scoping it is the table above. The table assumes perfect socket
attribution; section 4.1 implements it and measures it live.

### 4.1 Socket-level attribution implemented and measured live (benign only)

Implementation (p4_ebpf, uncommitted). `ebpf_perf/sockowner/` is a small eBPF tracer, separate from the in-kernel
monitor (which is unchanged). Two `cgroup_skb` programs see every IPv4 packet a local socket sends or receives and
record the first packet of each 5-tuple on a socket, with the socket cookie and the socket's cgroup. The 5-tuple is
read from the packet itself, so it is the switch's flow key, raw sockets included. Inbound copies delivered to raw
sockets are ignored. Two `cgroup/sock_create` and `sock_release` programs record which process created each socket.
Later packets of a known flow cost one hash lookup and emit nothing. `sockjoin.py` joins switch flows to owners;
`hybrid_collector.py --sockowner` runs the tracer and writes a second CSV whose network features count only the
flows of the monitored cgroup (`report_keys` per window, `owned_indexes` in the summarizer). Tests: on a capture
mixing two programs the socket join reproduces each program's own 29 window features exactly; the collector suite
(145 tests) passes.

Live check (`sockowner-check/`, analysis VM, kernel 7.0.0-38, benign clients only, Sink as the only destination;
approved by the user). Seven clients in six cgroups for 15 s, each writing a receipt for every flow it opened (local
port, process, socket creator): mixed HTTP/DNS/UDP (two processes sharing cgroup c1), 4 threads in one process, a
socket used by a forked child, a 2,000-destination UDP burst, 100 raw-socket SYNs. Ground truth = the receipts; the
capture on enp0s3 stands for the switch's view. Second run `runs/20261113T202924619160Z` (the first run, `...202157...`,
gave the same attribution but its cgroup ids and the raw client's receipts were unreadable because the guest's sudo
uses umask 077; fixed and rerun):

| Measure | Result |
| --- | --- |
| Client flows in the capture | 2,841 (all flows on the wire) |
| Attributed to a socket | 2,841 (100%) |
| Right cgroup | 2,841 (100%) |
| Right process (socket creator, from receipts) | 2,841 (100%; inherited socket -> its creator) |
| Tracer drops / map errors / failures | 0 / 0 / 0; 749 sockets, 2,844 flow sightings |
| Sighting vs first captured packet | median 7 us earlier (max 0.12 ms earlier) |
| Socket join = ground truth, per client cgroup | 40/40 windows, 145/145 columns, all six cgroups |
| Window join = ground truth | 6/40 windows (the empty ones); 113-145 columns differ |
| Process-level join inside the shared cgroup | 40/40 windows for each of the two processes |

The first run also caught an inbound UDP flow from the Sink's Sliver WireGuard listener (left from the testbed run)
to a guest port with no socket: correctly unattributed (no local owner). The tracer's per-datagram cost could not be
resolved in the VM: the spread between repeats of a 200,000-datagram send (0.3-4.5 us per datagram) exceeds any
difference with the tracer on; its per-packet work after the first packet of a flow is one hash lookup. A
bare-metal measurement (PC1) remains to be done. Limits: one host, benign clients, 15 s, IPv4; accepted TCP
sockets have no creation event (their flows carry the listener's cgroup); a switch bucket shared by two flows is
attributed by the flow it reported.

### 4.2 Socket-level attribution with a malware co-runner (live)

Approval "i approve it" (2026-11-13). The harness of 4.1 (seven benign receipt clients in six cgroups, 15 s) plus
one dataset malware sample in its own cgroup c7, started with the clients and killed with its cgroup 2 s after
they end (`../sockowner-check/run_sockowner_malware.py`, `guest_attr_malware.sh`, `analyze_sockowner_malware.py`;
runs in `../sockowner-check/runs-malware/`).
- Samples, fixed before any run: the dataset malware with the most distinct flows in their own dataset capture,
  one per family, top three families.
- The archives are the dataset's own transports. On the host they were checked in memory only (one member, its
  SHA-256 is the sample's).
- In the guest, the script removed the credential and the sudo cache before the sample started. The sample ran
  as `nobody`, unable to reach the harness files.
- One boot per sample. The VM was restored after each run; all three runs completed normally.

| | Mirai `07146515` (amd64) | Kaiji `2e2481d9` (i386) | Chaos `d538053a` (amd64) |
| --- | --- | --- | --- |
| Sample processes alive at the end | 58 (renamed `[kthreadd]`, `[kworker]`) | 1 | 1 |
| Benign client flows: right cgroup and right process | 2,843 / 2,843 | 2,832 / 2,832 | 2,842 / 2,842 |
| Flows from the sample's own sockets, attributed to c7 | 260 (905 packets; 215 processes) | 9 (18 packets) | 16,305 (44,142 packets) |
| Flows the sample caused through the guest's DNS stub, attributed to `systemd-resolved` | 0 | 30 (60 packets) | 25,432 (132,436 packets) |
| Sample flows attributed to a client cgroup / unattributed | 0 / 0 | 0 / 0 | 0 / 0 |
| Tracer drops, map errors, failures | 0, 0, 0 | 0, 0, 0 | 0, 0, 0 |
| Socket join = client ground truth (each of 6 cgroups) | 40/40 windows, 0/145 columns | same | same |
| Window join, client + the sample's flows: columns differing | 111 (98-112) | 132-143 | 144-145 |
| Network detector on the 4 normal clients, truth → client + sample | 0.47-0.50 → 0.86-0.91 | 0.45-0.70 → 0.60-0.71 | 0.48-0.51 → 0.90 |
| Normal clients flagged, socket join / window join with the sample | 1 / 4 | 3 / 4 | 2 / 4 |
| The sample's own socket-joined columns, network detector | 0.965 | 0.846 | 0.872 |

Reading.
- Under concurrent malware (a 58-process scanner, an i386 bot, a flood of 41,737 flows in about 18 s), every benign flow
  went to the right process and cgroup, and every flow from the sample's own sockets went to the sample's cgroup.
  None leaked either way, and the tracer lost nothing.
- The socket join reproduces each benign program's own features exactly. The window join changes nearly all of
  them and pushes the normal clients' scores from about 0.5 to 0.6-0.9, the live counterpart of the simulation in
  section 4.
- New limit: traffic a program sends through a local relay is attributed to the relay. Kaiji's and Chaos's DNS
  went to the guest's stub resolver (`systemd-resolved`), which forwarded it to the Sink. For Chaos that is 61%
  of the flows it caused on the wire. Mirai uses its own DNS server, so all its traffic stayed in c7.
- A per-program network view needs either no local relay (programs use the network's resolver directly) or a
  link from the relay's outbound flows back to the requester. The dataset's window join counted the relayed
  queries with the sample.
- The synthetic benign clients sit near the network detector's boundary (truth 0.45-0.70). The decision counts
  therefore depend on the run, and the shift in probability is the robust measure.
- Not measured: several hosts, the tracer's per-packet cost on bare metal, IPv6.

## 1. The switch vs its software model (committee item 1)

The switch's six rules (p4_ebpf `package_cohort.SwitchRules`: IPv4 lengths, fixed-offset parsing, CRC-16
buckets with collisions, direction, 32-bit nanosecond timestamps, idle eviction) on all 240 captures at 0.5 s.
The live collector's dataset profile corrects two of them (adds 14 B per packet, unwraps the timestamps).

| Configuration | Rows changed | Table V BA (network / stacked) | Decision flips per assignment (network) | Table IV flips |
| --- | ---: | --- | ---: | ---: |
| Software model | 0 | 0.756 / 0.823 | 0 | 0 |
| Dataset profile (collisions, eviction, parsing, direction) | 48 | 0.756 / 0.822 | 1.2 | 0 |
| Raw registers (all six rules) | 110 | 0.750 / 0.823 | 2.7 | 0 |
| + read budget 800 buckets per 0.5 s (measured capacity) | 10 runs overloaded | 0.754 / 0.822 | 1.6 | 0 |
| + read budget 350 (slower route) | 11 runs overloaded | 0.752 / 0.822 | 2.1 | 0 |

The dataset profile changes 48 rows, all through flow durations (idle eviction restarts long-idle flows);
collisions touch 4 rows (Chaos and three fan-out floods). Network-only recall on the 15 attacks: 0.99 (model),
0.95 (profile), 0.92 (budget 800), 0.89 (budget 350); the stacked hybrid stays at 0.97. The 32-bit wrap is
already resolved in the control plane (RUNBOOK 19.9; live durations 0-18 s on PC1); only overload can widen the
unwrap's uncertainty. Not yet done: the replay of all 110 captures with traffic through the Wedge, which measures
the same on the hardware (`p4_ebpf/PC1.md` Part 4; scorer `switchgap/score_switch_replay.py`; 33 new captures
in `switchgap/captures-extra.tar.gz`).

### 1.1 Frames above the MTU in three captures (2026-11-15, `offload/resegment.py`, `results/offload_resegment.json`)

The guest captured its own traffic before the NIC's segmentation offload split it. Three runs hold frames longer
than 1514 B: the bulk uploads `bulkup_200`, `bulkup_400`, `bulkup_700` (4,370, 8,824 and 15,072 such frames, up to
65,226 B; every other capture with traffic stays under 1514 B). The dataset counted each as one packet; on the wire,
and at the switch, it is up to ~45 segments. Split into wire-size segments (same timestamp and flags, the payload cut
at the frame's own MSS), the three uploads carry 5.8 times as many packets (`bulkup_200` 14,266 -> 82,735), their
largest frame is 1514 B and their mean packet size falls from 1,110-3,527 B to 200-633 B. The release's switch model
reproduces the published rows on the original captures first (difference 0). Table V with the three rows replaced is
unchanged (host 0.784, network 0.756 -> 0.757, concatenated 0.812, stacked 0.823), and the uploads stay flagged by
the network detector (0.8-0.9 of the assignments -> 0.9) and the concatenated hybrid (1.0): the network view's false
alarms on bulk uploads do not come from the oversized frames. These three captures cannot be replayed on the switch
as they are (PC1.md Part 4 skips them).

## 8. Evasion (committee item 8)

Only malicious executions modified (the attacker controls its process tree, not the monitor's launcher); detectors
trained on unmodified data. Recall on malware (host / network / concatenated / stacked):

| Attack | Malware recall | Flood recall (stacked) |
| --- | --- | ---: |
| none | 0.71 / 0.52 / 0.76 / 0.74 | 0.99 |
| pad 5x with the commonest benign call | 0.49 / 0.52 / 0.59 / 0.58 | 0.95 |
| pad 10x with real benign call sequences | 0.54 / 0.52 / 0.57 / 0.58 | 0.99 |
| 5 padding calls after every call | 0.41 / 0.52 / 0.54 / 0.56 | 0.95 |
| traffic slowed 10x | 0.71 / 0.39 / 0.74 / 0.74 | 1.00 |
| traffic slowed 50x | 0.71 / 0.30 / 0.71 / 0.72 | 1.00 |
| benign padding 5x + slowed 10x | 0.56 / 0.39 / 0.61 / 0.57 | 0.97 |
| split over 4 processes in the tree | 0.96 / 0.52 / 0.96 / 0.92 | 0.99 |
| split over 4 separately judged trees | 0.96 / 0.52 / 0.98 / 0.94 | 0.96 |

Randomized timing (2026-11-15, `evasion/jitter.py`, `results/evasion_jitter.json`; three fixed-seed draws per
variant, which differ by at most 0.013): each packet delayed by U(0, J), J = 0.1, 0.5, 2, 5 s, or spread over the
observation with exponential gaps. Network recall stays 0.512-0.523 (unmodified 0.520), the other three detectors
change by at most 0.001, flood recall (stacked) 0.993-1.000; the one dip is the concatenated hybrid on Slowloris at
J = 0.1 s (0.92 -> 0.85). J = 5 s pushes 13% of the malware's packets past the 20-s end. The network features key on
counts, sizes and flags, so this shows the detectors do not rely on timing, not that they resist traffic-shape
mimicry. Checks: the jitter path is bit-identical to `slowed_network` for factors 1-50 on all 114 malicious rows.

Mimicry against the host view leaves the network view: the hybrids fall to 0.54-0.59, close to what the network
view catches on its own (0.52). Slowing traffic leaves the host view: the hybrids stay at 0.71-0.76. The combined
attack gives 0.57-0.61, little below mimicry alone. Floods stay detected: slowed ten times they still look like
floods to the network view. Splitting work across processes does not help
an attacker here, but partly because the benign training programs are mostly single processes, so many small
processes look malicious; this is a property of the dataset, not a robustness guarantee.

## 3. Dataset (committee item 3)

- `datasheet/DATASHEET.md` (Gebru et al. structure: composition, collection, gates, biases, uses) and
  `datasheet/rejection_log.csv` (11 executions collected but rejected: 6 of 105 malware, 5 of 20 attack runs).
  Ready to add to the release repository's `dataset/`; not committed.
- Temporal split (2026-11-14; `temporal/temporal_split.py`, protocol `results/temporal_protocol.json` written
  2026-11-14 09:46:27Z before any model was trained, results `results/temporal_split.json`). Correction: the
  dates were not missing. The threat-intel lookup of 2026-11-13 (`../sample-intel-20261113/`) had already saved
  the MalwareBazaar first-seen date of 91 of the 99 samples. That lookup used the abuse.ch key; the HTTP 403 came
  from the older MalwareBazaar key that `temporal/lookup_first_seen.py` reads. The 8 samples without a date
  (collected from Triage, unknown to MalwareBazaar: Qilin 6, Akira 1, DeskRAT 1) are left out.
  - Design: malware sorted by first-seen date, the latest 24 of the 91 (the Table IV test fraction) test, the 67
    older ones train. The 105 benign keep their Table IV split, so only the malware assignment changes. Same rows,
    features, detectors and forest settings; Table IV reproduced exactly first.
  - Balanced accuracy, mean ± sd over 11 forest seeds (random splits: 10 draws, forest seed 42):

    | Split | Test malware | Host | Network | Concatenated | Stacked |
    | --- | --- | --- | --- | --- | --- |
    | Family-held-out (Table IV) on the 91 dated | 25 | 0.924 ± 0.008 | 0.760 | 0.924 | 0.965 ± 0.015 |
    | Temporal: train first seen 2020-03 to 2026-06-08, test 2026-06-15 to 2026-10-22 | 24 | 0.919 ± 0.009 | 0.833 | 0.959 ± 0.010 | 0.953 ± 0.014 |
    | Temporal, latest 18 / 30 / 36 as test | 18 / 30 / 36 | 0.920 / 0.929 / 0.929 | 0.833 / 0.817 / 0.833 | 0.962 / 0.949 / 0.964 | 0.962 / 0.930 / 0.929 |
    | Random malware split (reference) | 24 | 0.901 ± 0.012 | 0.808 ± 0.055 | 0.922 ± 0.014 | 0.928 ± 0.025 |

  - No loss on newer malware over this horizon. Against family-held-out on the same samples no detector drops by
    the pre-stated 0.05: host −0.005, stacked −0.012, network +0.073, concatenated +0.034.
  - New families: host and stacked catch all 24 newer samples, including the 5 from 4 families never seen in
    training (CatStorm, CoinMiner, INC, NoEscape). The network view catches 2 of those 5 and 14 of the 19 from
    known families.
  - Hybrid vs host. Concatenated is +0.040 ± 0.012 and stacked +0.034 ± 0.017, each better in 11 of 11 forest
    seeds.
    - Concatenated stays ahead at every cutoff (+0.021 to +0.041). Stacked is ahead only with the two later
      cutoffs and ties host with the earlier one (2026-05-28).
    - Host-only misses no malware here, so the whole edge is fewer false alarms on the same 28 benign test
      programs: 2 against 4 at forest seed 42.
    - Bootstrap interval at forest seed 42: +0.000 to +0.111. It never goes below zero but includes zero.
      McNemar p 0.5.
  - Artifact baselines: metadata 0.378, activity 0.533, mode 0.411. The gate is not triggered.
  - Limits:
    - The test dates cover four months.
    - 19 of the 24 test samples are from families also in training.
    - First seen means first submission to MalwareBazaar, not release.
    - The benign programs have no dates and the same 28 are the test benign of every row, so the rows differ
      only in malware recall.
    - The numbers are small.
- Encrypted traffic on existing data (2026-11-15, `encryption/README.md`, `encryption/results*.json`):
  - Pairs: the dataset's only clean plaintext/TLS pairs are curl's two tasks (`GET http://10.0.0.1/` and
    `-k GET https://10.0.0.1/`, TLS 1.3) in three builds (rows 87/88, 126/127, 182/183), with 2-5 repeats of each
    from earlier phases on the same runner (114 runs with the wget, openssl and telnet yardsticks).
  - Network features: TLS adds the handshake, tickets, record overhead and the server's resets (12 -> 16-18
    packets, 1,288 -> 4,183-4,309 B); 97 of 145 columns move outside the repeat range, a distance of 3.7-4.2
    dataset standard deviations against at most 0.64 for any cleartext task change and 0.25 between repeats. Flow,
    connection and SYN counts and directions are unchanged.
  - Host features: the TLS library's work, a distance of 0.5-1.7, like replacing curl by wget (1.5-1.9).
  - Decisions over 540 HTTP/HTTPS pair comparisons: network 0 changes (it never flags these clients); host 183
    (179 toward fewer alarms on HTTPS), stacked 29 (all fewer), concatenated 54 (both ways); curl -> wget for
    comparison: 195, 29, 33. Between repeats: 0 of 420 for every detector.
  - Own Sliver implants, HTTP vs HTTPS vs mTLS beacons: TLS check-ins carry 2.3-2.7 times the bytes; at 20 s HTTP
    and HTTPS are about as far apart as the a/b repeats, at 5 min 4-10 times. Host, concatenated and stacked flag
    all six beacons in every transport; network none.
  - Reading: the features do shift with encryption, deterministically, mostly sizes, byte ratios and teardown, so
    "the features don't shift" cannot be claimed; no network decision changed, and the host and stacked changes
    went toward fewer false alarms. One TLS version (1.3) and one small request: the new collection below covers
    TLS 1.1-1.3 and QUIC.
- Encrypted-traffic collection (2026-11-15, `../transport21-collect/20261115T104423464636Z/`, driver
  `collect_transport21.py`, analysis `transport21/analyze_transport21.py` -> the attempt's
  `analysis/transport_analysis.json`). One benign client moves the same requests over plain HTTP/1.1, TLS 1.1, TLS
  1.2, TLS 1.3 (HTTP/1.1) and QUIC (HTTP/3) to our own server on the Sink; two clients (Go `labtransport`, static,
  all five transports; Python standard library through flood_gen's `pyexec`, as the Python attack tools ran, four
  transports); three workloads (poll: a new connection every 1 s, GET 4 KiB; session: one connection, GET 1 KiB
  every 100 ms; bulk: GET 1 MiB, new connection each, 0.5 s apart), two repeats, 16 s in the 20-s observation;
  3 nulls. 57/57 accepted (quality, exact exec, 40 windows, no eBPF loss, client summaries with only successful
  requests over the intended version, Sink traffic). The server's log: plain 833 requests, TLS 1.1 832, TLS 1.2
  833, TLS 1.3 832, HTTP/3 416. The release switch model reproduces the collector's network columns on every run
  (8e-16).
  - Capture view: inside the guest, receive offload merges a TCP download's segments into frames of up to 64 KB
    (Go TLS 1.2 bulk: 1,860 of 3,801 frames above 1514 B), QUIC's datagrams stay separate. A "wire" view splits
    every TCP frame above 1514 B into MTU-size segments (`offload/resegment.py`): bulk TCP then carries 25,000-27,800
    packets against QUIC's 29,500-29,800, instead of 3,600-7,100 as captured.
  - Shift against plain HTTP, mean absolute difference over the columns in dataset standard deviations (network,
    wire view; repeat spread in brackets): poll TLS 0.16-0.36 (0.00-0.06), QUIC 0.48 (0.01); session TLS
    0.05-0.10 (0.00-0.03), QUIC 0.60 (0.09); bulk TLS 0.5-9.4 (0.2-1.1), QUIC 11.1 (0.7) — bulk transfers of
    about 32 MiB lie far outside the dataset's range, so small relative changes are many dataset deviations. Host
    side: TLS 0.04-0.45, QUIC 0.16-0.31 (repeats 0.00-0.16): the TLS library's work (Python poll 1,401 -> 2,007-2,039
    calls; QUIC runs in user space, Go session 5,500 -> 14,500-14,800 calls).
  - Detectors trained on the 240 rows (all runs benign, so every flag is a false alarm), as captured (wire):

    | Transport | Runs | Host | Network | Concatenated | Stacked |
    | --- | ---: | ---: | ---: | ---: | ---: |
    | plain HTTP | 12 | 10 (10) | 0 (0) | 2 (3) | 5 (7) |
    | TLS 1.1 | 12 | 10 (10) | 0 (0) | 0 (0) | 1 (1) |
    | TLS 1.2 | 12 | 10 (10) | 0 (0) | 0 (0) | 0 (1) |
    | TLS 1.3 | 12 | 9 (9) | 0 (0) | 1 (1) | 2 (2) |
    | QUIC | 6 | 5 (5) | 0 (0) | 1 (1) | 1 (1) |

  - Reading: encryption shifts the payload-free features deterministically (handshakes double a short connection's
    packets, record overhead, QUIC's own packet and ACK pattern), more than repeats do, but for request/response
    workloads by less than half a dataset deviation; no transport caused a network alarm, and the hybrids flagged
    the encrypted runs no more than the plaintext ones. The host detector flags 9-10 of 12 of these clients in
    every transport: new always-on Go/Python clients, the same transfer failure as the C2 benign clients (§10), not
    an effect of encryption. Benign only (no encrypted attacks), one server, self-signed certificate.
- More attack tools: not prepared (the build of further published attack tools was stopped by a safety system).
- Benign Python programs and more families: the encrypted-traffic collection includes 24 benign Python client runs;
  more families need new samples.

## 7. Baselines (`baselines/README.md`, `baselines/results.json`)

Same rows, same two protocols; unsupervised detectors trained on benign training rows only, thresholds fixed
before scoring (95th percentile of held-out training-benign scores).

| Baseline | Table V BA | Table V AUC | Table IV BA |
| --- | --- | ---: | ---: |
| STIDE, 6-grams, mismatch fraction (Forrest et al.) | 0.527 +/- 0.010 | 0.713 | 0.641 |
| Lookahead pairs, window 8 (pH/ebpH style) | 0.572 +/- 0.027 | 0.745 | 0.758 |
| Supervised system-call 1-3-grams, RF500 | 0.868 +/- 0.040 | 0.955 | 0.875 |
| same, start-up (first 50 calls) removed | 0.801 +/- 0.026 | 0.894 | 1.000 |
| same, first 50 calls only | 0.863 +/- 0.031 | 0.949 | 0.911 |
| Kitsune (KitNET, max RMSE; Mirsky et al.) | 0.555 +/- 0.043 | 0.676 | 0.692 |
| Kitsune features + RF500 | 0.735 +/- 0.029 | 0.787 | 0.734 |
| CICFlowMeter-style flow features + RF500 | 0.780 +/- 0.005 | 0.792 | 0.750 |
| Software hybrid (n-grams + flows), concatenated / stacked | 0.919 / 0.872 | 0.978 / 0.972 | 0.946 / 0.982 |
| same without the start-up, concatenated / stacked | 0.855 / 0.858 | 0.948 / 0.915 | 0.929 / 1.000 |
| Thesis: host / network / concatenated / stacked | 0.784 / 0.756 / 0.812 / 0.823 | 0.839 / 0.769 / 0.876 / 0.866 | 0.929 / 0.750 / 0.926 / 0.963 |

Reading. Unsupervised STIDE and Kitsune are near chance: they need a per-program normal profile, and every test
program is unseen (STIDE's frame count saturates for 46% of benign runs; Kitsune flags every Slowloris but 7.5%
of the floods). Unconstrained software flow features score like the switch's 29 (0.780 vs 0.756; identical
decisions on the held-out split): restricting the network view to what the switch computes costs little.
On the released rows, supervised n-grams over the full system-call trace beat the 18 in-kernel summaries, partly
through the same start-up association (2.4a). Rerun on the toolchain-matched benign (`baselines/toolchain_ngram.py`,
pools of 2.4a, decision rule written before scoring; checks: all nine detectors reproduce their 240-row scores
exactly, the thesis detectors reproduce `results/toolchain_scores.json`):

| Pool | n-gram HIDS | same, without the target's first 50 calls | first 50 calls only | Thesis host | Software hybrid, concat / stacked | Thesis concat / stacked |
| --- | --- | --- | --- | --- | --- | --- |
| A: rebuilt benign flagged, trained on the 240 rows | 0.73 | 0.16 | 0.91 | 0.11 | 0.80 / 0.68 | 0.14 / 0.11 |
| B: replacement, Table V BA | 0.824 ± 0.023 | 0.788 ± 0.012 | 0.641 ± 0.041 | 0.787 ± 0.019 | 0.868 / 0.861 | 0.815 / 0.818 |
| C: held-out split, BA over 11 forest seeds | 0.967 ± 0.012 | 0.937 ± 0.006 | 0.515 ± 0.021 | 0.913 ± 0.008 | 0.989 / 0.890 | 0.887 / 0.901 |
| D: mixed, Table V BA | 0.816 ± 0.018 | 0.789 ± 0.018 | 0.718 ± 0.019 | 0.784 ± 0.009 | 0.870 / 0.865 | 0.827 / 0.822 |

The two results:
* **Trained on the released rows, the n-gram detector is mostly a build detector.** It flags 73% of the rebuilt
  benign programs (Go 100%, uClibc 95%, UPX 73%), against the host summaries' 11%.
* **Retrained with them, it still beats the host detector** under the pre-stated rule: pool B, +0.037 BA, higher in 9
  of 10 assignments, exact McNemar p < 0.05 in 2.
  * The whole edge is fewer false alarms on the rebuilt programs: 2% vs 16%; the host's are uClibc 37% and UPX 36%.
    Its malware recall is lower (0.684 vs 0.722).
  * The edge disappears without the target's first 50 calls (0.788 vs 0.787).
  * Those calls alone still score 0.641. They hold the C-library start-up and the program's first actions, and build
    identity finer than the class-level matching cannot be excluded.
  * So the remaining edge is real on these data, but not attributable to behaviour alone.

The software hybrid stays 0.04-0.05 above the thesis hybrid (about 0.03 without the 50 calls). So the compact
representation costs some host accuracy when the training data covers the deployment's build toolchains, and buys
robustness when it does not (73% vs 11% false alarms) and a lower cost: n-grams need the ordered call sequence, and our
streaming monitor cost +0.29-0.36 µs per call against +0.05 µs for the in-kernel aggregates. Details:
`baselines/README.md` section 8.

Software extraction cost (packets per CPU-second, two flood captures):
Zeek 9.0.1 38k-698k, tshark 59k, a Python flow extractor 20k-521k, Kitsune's feature extractor 0.1k-8.5k;
100 Gb/s at 64 B would need 213-3,875 Zeek cores, against the switch's line rate in hardware. Caveats: Kitsune
used at most 20,000 packets per run; the start-up diagnostics and one flow-extractor fix came after seeing
scores; thresholds and model settings were fixed before.

## 10. Command and control: server down, then server up (advisor's request)

Two 5-minute collections in the sealed lab (runner .22, quiet baseline, families or programs held out, ten fold
assignments). Real C2 samples cannot be commanded: Sliver, Cobalt Strike and Winnti check the operator's keys.
So the first run lets real implants reach a sinkhole, and the second runs implants built with our own Sliver
server. The second is the only run with a command phase.

**Server down: real implants against the sinkhole** (`sinkhole-c2-5min/20261113T084625506148Z`, protocol `929eb0c3...`).
- Cases: 28 malware from 6 families (Sliver 8, Cobalt Strike 4, Meterpreter 4, Rekoobe 10, Winnti 1, Merlin 1) and
  28 benign clients from 7 programs that poll, retry or hold connections like beacons.
- The Sink completed TCP connections and answered web and DNS requests; every other port was held open silently.
- Of the 28 implants, 13 kept contacting their server on a schedule (11 over TCP, 2 over UDP), 9 made one connection and waited, and 6 never used the network. None got commands. All 59 runs passed the technical checks.
- Balanced accuracy at 20 s / 1 min / 5 min:

| Detector | 20 s | 1 min | 5 min |
| --- | --- | --- | --- |
| Host | 0.800 (AUC 0.853) | 0.671 | 0.634 |
| Network | 0.564 | 0.611 | 0.561 |
| Connection-shape features (30, pre-registered) | 0.554 | 0.604 | 0.564 |
| Concatenated | 0.632 | 0.630 | 0.652 |
| Stacked | 0.655 | 0.521 | 0.457 |

- Pre-registered rule for the connection features: 11 of 12 comparisons show no clear gain. The exception:
  shape view at 5 min, +0.134, higher in 10 of 10 assignments.
- The benign clients poll like beacons, so payload-free network features cannot separate them from implants.

**Server up: own Sliver implants under command** (`sliver-c2-5min/20261113T175035504465Z`, protocol `84e90094...`;
both ends ours).
- Implants: 12 amd64 builds of one framework in 6 transport groups (mTLS, HTTP, HTTPS and WireGuard beacons every
  5 s; mTLS and WireGuard sessions).
- Controls: 12 benign amd64-dynamic clients from the sinkhole run, so mode carries no signal; 3 nulls.
- An operator script tasked each live implant every 25 s with a fixed benign list: identity, file list, uname and
  id, download of `/etc/hostname`, upload of a file to `/tmp`.
- 27/27 runs accepted; 12/12 benign as designed.
- Both WireGuard beacons exited with status 2 after ~800 calls and never connected (cause unknown; the WireGuard
  sessions worked).
- 124 taskings were logged, all with results; 120 fell inside the runs, 12 per live implant.
- Activity per 0.5-s window, 10 s before to 5 s after each logged tasking vs elsewhere (first 20 s left out):

| | Host calls (near / elsewhere) | Packets (near / elsewhere) |
| --- | --- | --- |
| Sessions (4) | 51.8-70.0 / 1.1-4.8 | 5.2-6.6 / 0.2 |
| Beacons (6) | 44.0-52.6 / 10.7-16.5 | 1.2-3.3 / 1.2-3.2 |
| All live implants | 52.5 / 9.4 | 3.6 / 1.4 |

- The window spans 10 s before the logged tasking because a session runs its tasks before the call returns. A
  beacon runs them at its next check-in.
- So the command phase shows in host activity for every transport. In packet counts it shows only for sessions:
  a beacon checks in every 5 s whether or not it carries a task.

Detection, balanced accuracy (AUC), transports held out; switch and connection features without our server's
stray WireGuard packets (see below; `sliver-c2-5min/recompute_without_stray_wg.py`, which first reproduced the
saved as-collected results exactly; as collected in brackets where it differs):

| Detector | 20 s | 5 min | 20 s, live implants only |
| --- | --- | --- | --- |
| Host | 0.917 (0.957) | 0.850 (0.899) | 0.988 |
| Network | 0.892 (0.834) [0.908] | 0.821 (0.811) [0.871] | 0.975 [0.996] |
| Concatenated | 0.908 (0.936) | 0.850 (0.882) | 0.992 |
| Stacked | 0.887 (0.850) [0.917] | 0.850 (0.836) | 0.992 |
| Activity baseline (total calls) | 0.917 (0.908) | 0.825 (0.869) | 1.000 |

Reading.
- The implants are far busier than the benign clients: the activity baseline matches every detector.
- Each transport held out still leaves the same implant code in training. So this run shows that the command
  phase is measurable and that the detectors flag these implants. It is not a test of generalization.
- Connection features, same pre-registered rule: 9 of 12 comparisons show no clear gain; the three gains are all
  in the shape view (+0.075 at 20 s, +0.079 at 1 min, +0.108 at 5 min; as collected +0.100, +0.104 and +0.092,
  the last not a gain), the same direction as with the server down.
- Transfer of the paper's detectors (trained on the 240 rows, unchanged): 10 of 12 implants flagged by host,
  concatenated and stacked, 2 of 12 by network; of the 12 benign clients, host flags 6, network 2, concatenated 2,
  stacked 4: the published host detector does not carry over to always-on network clients, as the sinkhole run had
  shown. (Corrected 2026-11-15, `encryption/README.md`: the server's WireGuard listener kept sending handshakes,
  UDP from 10.0.0.1:51820 about every 5 s, into four later runs, positions 17, 18, 19 and 27, three benign and
  `lab-https-beacon-b`. The switch counts them as one long UDP flow. They caused the network detector's only beacon
  alarm and three benign false alarms; the earlier figures, network 3 of 12 implants and 5-6 of 12 benign flagged,
  included them. Recomputed without them, the within-run table above changes only for the network view and the
stacked hybrid; the command-phase measure does not change: `lab-https-beacon-b` 1.89 / 2.03 packets per window
near / elsewhere instead of 1.98 / 2.12.)
- Detectors trained on the sinkhole run flag 12 of 12 implants at 20 s (all four views). Its training set contains
  8 real Sliver samples. Its benign clients are the same programs, so their 0/12 false alarms are not a transfer
  result.

## 11. Mitigation, estimated offline (committee item 6; `mitigation/README.md`, `mitigation/results.json`)

The streaming setup of §2.6 scored after every 0.5-s window (Table V protocol, ten assignments); a run is contained
at T = (w + 1) x 0.5 s + R + L after its first flagged window w, with R = 0.35 s (the read budget) and the rule's
install time L = 1, 10 or 100 ms (unmeasured); the rule drops every frame the host sends from T on (per host: a
per-flow rule would not stop fan-out floods). Packets and bytes before and after T come from each run's capture
(the counts equal the dataset's in all 240 runs; no spoofed source address). Stacked hybrid, threshold 0.5, L = 10 ms:

| Group | Contained by 20 s | Median T | Within 1 s | Packets stopped (mean per run) |
| --- | ---: | ---: | ---: | ---: |
| SYN floods (4) | 100% | 0.86 s | 100% | 42% |
| UDP floods (4) | 100% | 0.86 s | 98% | 44% |
| Slowloris (5) | 100% | 0.86 s | 96% | 50% |
| GoldenEye (2) | 100% | 0.86 s | 100% | 36% |
| Malware sending traffic (52) | 100% | 0.86 s | 94% | 88% |

- The floods send 15-100% of their packets before 0.86 s, the earliest any rule of this pipeline can act, so the
  stopped share equals the ceiling of a detector that flags every attack in its first window (44%): the limit is
  the window plus the read, not the detector. From L = 1 ms to 100 ms the share falls only from 44% to 42%.
- These are 20-s runs whose floods are bursts; for an attack that keeps going, the stopped share is a lower bound.
- Benign runs blocked: 20% at threshold 0.5 (CLI 17%, network-active 24%, nulls 90%), 80% of them at 0.86 s; 5% at
  0.8 (94% of attacks still contained), 1% at 0.9 (82%).
- All 52 sending malware are flagged partly because, in this dataset, 42 of them left a connection unanswered (30
  got no reply packet at all) while every benign run that sent packets got replies (§2.7); the attacker is assumed
  not to react to the drop.

### 11.1 A first stage in the switch's data plane (committee item 5, optional; estimate, `firststage/newflow_rule.py`)

The learned detectors decide after a 0.5-s window and a register read, so the floods send much of their traffic
first (§11). A rule the switch evaluates on every packet would not wait. Two counters, each a register the switch
can keep: new flows per source address (the switch already reports every flow's first packet) and packets per
flow (its existing per-flow counter), both in tumbling 10-ms bins. A host is blocked when one bin exceeds the
largest count of any of the 126 benign rows, so no benign row is blocked here by construction. Protocol written
first (`results/firststage_protocol.json`). The per-flow rule was added after the first run showed that a UDP
flood to one server is a single flow, which a new-flow counter cannot see (`results/firststage_protocol_addendum.json`;
the first run is kept as `results/firststage_v1_newflow_only.json`). Traffic and drop rule as in §11; packets
counted as on the wire (offload frames split to MTU size).

| Attack runs | Detected | Median time to alarm | Packets stopped: rule in the data plane / drop installed 10 ms later | Learned stacked hybrid (§11) |
| --- | ---: | ---: | --- | ---: |
| SYN floods (4) | 4 | 4 ms | 100% / 99% | 42% |
| UDP floods (4) | 4 | 7 ms | 100% / 99% | 44% |
| Slowloris (5) | 5 | 44 ms | 100% / 94% | 50% |
| GoldenEye (2) | 2 | 198 ms | 100% / 99% | 36% |

- Thresholds: new flows per source k = 2 per 10 ms (the benign maximum, an interactive session) and packets per flow
  k = 371 per 10 ms (a bulk upload). Every attack run except the three UDP floods to the sink opens 55-733 new
  flows per 10 ms; those three are one flow each, at 629-1,484 packets per 10 ms.
- Margin. The new-flow counter has room: at 10 times the benign maximum it catches the same runs as fast. The
  per-flow packet counter has little: the UDP floods to the sink reach only 1.7-4 times the benign upload's rate,
  and at twice the threshold one of them is missed. With 100-ms bins the combination still catches all 15 runs at
  5 times its thresholds (98% of the attack packets stopped).
- The new-flow counter also trips on 13 general-malware runs (Chaos, DeskRAT, Kaiji and Mirai, which scan): a
  detection, not a false alarm. It catches no other malware, so it would complement the learned detectors, which
  catch the general malware, not replace them.
- The per-destination counter that the switch program was compiled with in tests (not deployed) catches Slowloris,
  GoldenEye and three of the SYN floods, but none of the UDP floods (29% of the attack packets stopped): a
  per-source counter is needed.
- Limits: the thresholds come from this dataset, whose benign programs are mild network users (at most 2 new flows
  per 10 ms); a real host, a browser loading a page or a busy server, needs its own calibration. Bins, counters and
  the drop were simulated offline; the switch program was not changed, so the resources (one or two registers and
  a comparison) and the reset of the bins are not measured. A source that spoofs its address defeats a per-source
  counter.

## Limitations of these analyses

Post-hoc analyses of an already-examined dataset (not a blind evaluation). The simulations (attribution,
evasion, switch rules) are exact recombinations or replays of recorded data under stated assumptions: distinct
5-tuples and whole-window offsets for mixtures, perfect socket attribution, padding and splitting without other
side effects, offline read-budget emulation. Benign programs are command-line tools and a traffic generator.

## Files

`common.py`, `verify_baseline.py` (gate); `compute_oof.py`, `analyze_rigor.py`, `importance.py` (item 2,
`results/rigor.json`, `results/importance.json`); `attribution/` (item 4, `results/attribution_superposition.json`);
`switchgap/` (item 1, `results/switch_gap.json`, `results/switch_budget.json`); `evasion/` (item 8,
`results/evasion.json`); `datasheet/`; `temporal/`; `baselines/` (item 7); `cue/` (§2.7); `firststage/` (§11.1); C2 runs: `../sinkhole-c2-5min/` and `../sliver-c2-5min/` (`analyze_sliver.py`, `command_phase.py`; results in each attempt's `analysis/`); socket attribution: `../sockowner-check/` (`runs/`, `runs-malware/`). Caches in `cache/`.
