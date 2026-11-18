# Committee baselines: software HIDS, NIDS and hybrid detectors on the thesis dataset

Offline analysis of the 240 already-collected executions (2026-11-13). No sample was executed, no VM was started,
no existing file outside this folder was changed. All scripts are in this folder; caches, scores and logs too.

**Bottom line.** Same 240 runs, same 20-second windows, same folds and the thesis's random forest:

| | Table V BA (10 assignments) | Table IV BA (held-out) |
| --- | --- | --- |
| Thesis host / network / stacked hybrid | 0.784 / 0.756 / 0.823 | 0.929 / 0.750 / 0.926 (concat) |
| STIDE (unsupervised HIDS), best variant | 0.585 ± 0.015 (STIDE k=6, mismatch fraction, prologue-free) | 0.758 (Lookahead pairs (window 8), anomalous-call fraction) |
| Kitsune (unsupervised NIDS), max RMSE | 0.555 ± 0.043 | 0.692 |
| Kitsune AfterImage aggregates + RF | 0.735 ± 0.029 | 0.734 |
| CICFlowMeter-like flows + RF (software NIDS) | 0.780 ± 0.005 | 0.750 |
| System-call n-gram HIDS + RF | 0.868 ± 0.040 | 0.875 |
| Software hybrid (n-grams + flows), concat / stacked | 0.919 ± 0.035 / 0.872 ± 0.024 | 0.946 / 0.982 |
| Diagnostic: first 50 calls of the program only | 0.863 ± 0.031 | 0.911 |
| Diagnostic: n-grams without those 50 calls | 0.801 ± 0.026 | 1.000 |
| *Toolchain-matched benign (section 8):* n-gram HIDS vs thesis host | 0.824 ± 0.023 vs 0.787 ± 0.019 | 0.967 vs 0.913 (11 forest seeds) |
| *Toolchain-matched benign (section 8):* software hybrid vs thesis hybrid, concat / stacked | 0.868 / 0.861 vs 0.815 / 0.818 | 0.989 / 0.890 vs 0.887 / 0.901 |

* The unsupervised baselines (STIDE, Kitsune) are well below the thesis detectors.
* Software flow features do about as well as the switch's 29 signals: network-only detection is limited by the malware
  that sends nothing in the window.
* Supervised detectors with full system-call identities score higher than the thesis on Table V, but almost all of
  that is reachable from the first 50 calls of each program, i.e. its C-library / runtime start-up, which identifies
  how the binary was built (the benign programs were all compiled by the study with a few toolchains, the malware
  with many). Without those
  calls the n-gram HIDS is between the thesis host and hybrid detectors, and the software hybrid is about 0.03 above
  the thesis hybrid while using information a line-rate switch and an in-kernel aggregate monitor do not export.
* Section 8 reruns them with benign programs rebuilt using the malware's toolchains. Trained on the released rows,
  the n-gram HIDS flags 73% of those rebuilt benign programs (thesis host 11%): it is mostly a build detector.
  Retrained with them, it still beats the thesis host detector (+0.037 BA, 9 of 10 assignments). The whole edge comes
  from fewer false alarms on the rebuilt programs, and it disappears without the program's first 50 calls (0.788 vs
  0.787).

## 1. Data, protocols and inputs

**Rows and protocols.** The 240 rows of `p4-ebpf-malware-detection/dataset/features.csv`, loaded with the verified
`../common.py` (unchanged). Two protocols, identical to the thesis:

* **Table V** — all 240 rows, ten fold assignments (`StratifiedGroupKFold(5, shuffle=True, random_state=s)`,
  s = 42, 0..8; groups = published `cv_group`: malware family, benign project/shape, attack instance). The fold
  assignment is recomputed with the same call (`bl_common.table5_folds`) and checked against a re-split with the real
  host matrix. Results: mean ± sd (ddof 1) over the ten assignments.
* **Table IV** — the published held-out split: 150 training / 54 test rows (malware and CLI benign only; 11 malware
  families and 11 benign projects of the test side never appear in training).

`compare_thesis.py` re-derives the thesis detectors with the loader and asserts the published values (Table V BA
host .784, network .756, stacked .823; Table IV host .929, network .750, concat .926) before any comparison. The
loader's Table V concatenated hybrid gives .812 (the earlier .809 diagnostic used network-first column order with the
same RF); the thesis stacked hybrid on the Table IV split gives .963 (not a published cell).

**Same observation window as the thesis.** Every baseline sees exactly the 20-second observation of each run:

* *System calls* — `syscall_events.csv` events with `window_id` 0..39 (the sample's process tree, raw syscall
  entries). Gate, all 240 runs: number of events = `host_total_syscalls_total__sum` of features.csv (10,006,454 events
  in total), the root process's 2nd exec_success is the target path, the launcher prologue is 178 calls.
* *Packets* — frames with whole-microsecond time in [`sample_started_wall_us`, +20 s), the window of the thesis's
  switch model (`features/switch_model.py`); 1,535,742 frames in total, checked against an independent reader.

**System-call tokens (ABI).** The trace line has no ABI, and i386 and x86-64 numbers collide, so every token is
`(abi << 10) | number`. The ABI is reconstructed per process from `exec_events.csv` and the fork records of
`ebpf_events.csv`: the root process is x86-64 until its 2nd exec_success (the collector's python3 and /bin/bash
launcher), then uses the row's mode (i386 for `i386_static`); later execs of guest system binaries (/usr/bin,
/usr/sbin, /bin, /sbin, /lib*) are x86-64, other images (the sample or a copy of it) use the row's mode; a forked
process inherits its parent's ABI. This refines the plain "row mode" rule: in i386 runs the 178-call launcher and
the guest tools that malware starts (systemctl, sed, sh, ...) are 64-bit programs (44,962 such x86-64 tokens in the
56 i386 runs). Sequences are per thread (tid), ordered by timestamp.

## 2. Baselines and exact settings

All supervised detectors use the thesis's classifier, `RandomForestClassifier(n_estimators=500,
class_weight="balanced", random_state=42, n_jobs=1)` (`common.rf()`), decision threshold 0.5. Unsupervised
detectors train only on the **benign (label 0) rows of the training side** (Table V: all label-0 rows of the four
training folds, i.e. CLI benign, network-active benign and null runs; Table IV: the 77 CLI benign training rows).

**Threshold rule of the unsupervised detectors (fixed before scoring).** A training-benign run scored by a model built
on itself is optimistic (for STIDE it scores exactly 0, since all its sequences are in the profile). So held-out
training-benign scores are obtained first: the training-benign *groups* are shuffled (seed 7) and dealt into 5 inner
folds; for each inner fold a model is built on the other four and scores the held-out runs. The threshold is the
**95th percentile** (numpy, linear interpolation) of these held-out scores, and a run is flagged when its score is
**strictly greater**. A second operating point uses the **maximum** of the held-out scores. The model applied to the
test rows is then built on all training-benign runs. Pooled out-of-fold AUC uses the score minus the fold's threshold
(STIDE) or log10(score / threshold) (Kitsune), so that each fold's decision boundary sits at 0.

### 2.1 Pure HIDS — STIDE (`stide.py`)
* Profile: the set of all length-**6** sequences (sliding window over each thread's token sequence; a thread shorter
  than 6 calls gives one sequence padded with an end token) of the training-benign runs.
* Per run: **lfc** = maximum locality frame count = largest number of mismatching sequences among any **20**
  consecutive sequences of a thread, maximum over threads (0..20) (Hofmeyr, Forrest, Somayaji 1998); **frac** =
  mismatching sequences / all sequences of the run.
* Variants: traces as collected (prologue included; primary), prologue-free (root-process events before its 2nd
  exec_success dropped), and the optional **lookahead pairs** (pH/ebpH style, window 8: for each call the pairs
  (call j back, call, j) for j = 1..7; a call is anomalous if any pair is missing from the benign pair profile;
  lfc/frac over calls).

### 2.2 Supervised system-call n-gram HIDS (`ngrams.py`, `supervised.py`)
* Per run: bag of **1-, 2- and 3-grams** inside each thread's token sequence (never across threads), features =
  **log1p(count)**. Vocabulary = n-grams present in **≥ 2 training runs**, refit on every training set (outer folds
  and the stacker's inner folds), so test runs never shape the vocabulary. 9,465 distinct n-grams exist in the whole
  dataset (274 tokens).
* Variants: as collected (primary) and prologue-free.
* Diagnostics (not baselines; added after the first n-gram results, to interpret them): the same RF on the n-grams
  of only the **first 50 calls of the target program** (root thread right after the launcher: its C-library /
  language-runtime start-up), which measures how far a start-up fingerprint alone separates the classes; its
  complement, the n-gram HIDS with the launcher prologue **and** those 50 calls removed from the root thread (all other
  threads and processes unchanged); and the two software hybrids (Section 2.4) built on that complement.

### 2.3 Pure NIDS — Kitsune (`kitsune_extract.py`, `kitsune_eval.py`; official code in `vendor/kitsune-py`)
* Per-packet features: tshark with the official field list and flags parses each capture; the in-window rows are kept
  (count checked against the independent pcap reader); the **official, unmodified** `FeatureExtractor.FE` reads that
  .tsv and the official `netStat`/`AfterImage` compute one vector per packet. The current repository version returns
  **100** features (the paper's 15 "Host BW" statistics are commented out in `netStat.updateGetStats`); decay
  factors λ = 5, 3, 1, 0.1, 0.01.
* **Packet cap: first 20,000 in-window packets of each run** (all packets for 224 of 240 runs; the 16 larger runs are
  11 network-attack runs, the scanning Chaos sample and 4 bulk/DNS benign runs). The slowest capped runs still took
  46 min (SYN fan-out floods) and 86 min (udp_fan_60k) on one core. Reason: the official Python AfterImage updates every
  covariance tracker of a source on every packet, so the cost per packet grows with the number of distinct peers of a
  source; measured on `syn_fan_40k`: 1,000 packets 3.7 s, 5,000 99 s, 10,000 548 s (≈ quadratic), i.e. days for the
  100k-150k-packet fan-out floods.
* KitNET (official `KitNET/`): max autoencoder size **10**, learning rate **0.1**, hidden ratio **0.75**, grace
  periods **FM = 5,000** and **AD = 50,000** (official example). Training stream: from each benign training run at most
  **4,000** packet vectors (random subset, generator seeded with the row number), pooled, shuffled (seed 42),
  truncated to FM + AD + 1 = 55,001 packets and fed to `KitNET.process()` one by one; with fewer packets both grace
  periods keep the 1:10 ratio (final models of the Table V folds: 12k-55k packets; Table IV: only 372 packets, because its 77 benign
  training runs are CLI programs with a few packets each).
* Scoring: KitNET's RMSE for every packet, computed in batch with the trained weights; checked against the official
  per-packet `execute()` on sampled packets in every Table V assignment and in Table IV (maximum relative difference
  ≤ 2.2e-16). Run score = **maximum** RMSE over its packets (primary; also 99th percentile and mean); a run without
  packets gets the lowest score (0).
* Supervised variant: per-run **mean, max and standard deviation** of the 100 AfterImage features (300 features, zeros
  for runs without packets) + RF500.

### 2.4 Unconstrained software network features and software hybrid (`flow_extract.py`, `supervised.py`)
* CICFlowMeter-like bidirectional flows over the in-window IPv4 TCP/UDP packets; the first packet's direction is
  forward. A TCP flow is one connection: it is terminated by RST or by FIN in both directions, trailing packets stay
  in it, and only a new SYN on a terminated 5-tuple opens a new flow (this avoids CICFlowMeter's known split of
  connections at the first FIN); no timeout within 20 s.
* Per flow (38): duration; forward/backward packets and payload bytes; payload-length min/max/mean/std per direction;
  inter-arrival mean/std/min/max overall and per direction; SYN/FIN/RST/PSH/ACK/URG counts; forward/backward header
  bytes; payload bytes/s; packets/s; down/up ratio; average payload; TCP flag. Per run (115): flow count plus mean,
  max and std over flows of each (zeros when no flow; 130 of 240 runs have no TCP/UDP flow in the window).
* Software hybrid of these flow features with the n-gram HIDS features: **concatenated** RF500, and **stacked**
  logistic regression (`common.stacker()`) on inner out-of-fold probabilities of the n-gram RF and the flow RF, inner
  `StratifiedGroupKFold(min(5, groups), shuffle=True, random_state=7)` — exactly `common.fit_predict`'s design.

## 3. Results

Recomputed by `make_summary.py` from the saved scores. Table V: mean ± sd over the ten fold assignments; the flag
columns are the fraction of runs flagged per category (= recall for malware and attacks, false-alarm rate for the
benign categories), averaged over assignments (99 general malware, 15 network attacks, 105 CLI benign, 18 network
benign, 3 null). Unsupervised detectors at their primary operating point (95th percentile of held-out training-benign
scores); the maximum-based operating point is in `results.json` (`second_operating_point_max`). Rows marked
"Diagnostic" are controls for interpreting the n-gram results, not baselines. Table IV is one fixed split with 26
malware and 28 benign test rows: one decision moves its BA by about 0.02, so it is less reliable than Table V.

### Table V protocol (240 rows, 10 fold assignments)

| detector | BA | AUC | recall | specificity | malware | attacks | CLI benign | net. benign | null |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Thesis host (eBPF, 18 ADFA signals x 5) | 0.784 ± 0.022 | 0.839 ± 0.026 | 0.745 | 0.824 | 0.715 | 0.940 | 0.154 | 0.183 | 0.90 |
| Thesis network (switch, 29 signals x 5) | 0.756 ± 0.016 | 0.769 ± 0.033 | 0.582 | 0.931 | 0.520 | 0.987 | 0.023 | 0.350 | 0.00 |
| Thesis hybrid, concatenated | 0.812 ± 0.021 | 0.876 ± 0.019 | 0.782 | 0.842 | 0.755 | 0.967 | 0.106 | 0.356 | 0.80 |
| Thesis hybrid, stacked | 0.823 ± 0.015 | 0.866 ± 0.029 | 0.773 | 0.874 | 0.739 | 0.993 | 0.095 | 0.178 | 0.90 |
| STIDE k=6, max locality frame count (frame 20) | 0.500 ± 0.000 | 0.725 ± 0.018 | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.00 |
| STIDE k=6, mismatch fraction | 0.527 ± 0.010 | 0.713 ± 0.031 | 0.125 | 0.929 | 0.032 | 0.733 | 0.055 | 0.178 | 0.00 |
| STIDE k=6, LFC, prologue-free | 0.500 ± 0.000 | 0.710 ± 0.019 | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.00 |
| STIDE k=6, mismatch fraction, prologue-free | 0.585 ± 0.015 | 0.739 ± 0.028 | 0.237 | 0.933 | 0.190 | 0.547 | 0.045 | 0.206 | 0.00 |
| Lookahead pairs (window 8), LFC | 0.500 ± 0.000 | 0.808 ± 0.020 | 0.000 | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.00 |
| Lookahead pairs (window 8), anomalous-call fraction | 0.572 ± 0.027 | 0.745 ± 0.059 | 0.204 | 0.940 | 0.110 | 0.820 | 0.038 | 0.194 | 0.00 |
| System-call 1-3-gram HIDS, RF500 | 0.868 ± 0.040 | 0.955 ± 0.017 | 0.874 | 0.862 | 0.859 | 0.973 | 0.131 | 0.083 | 0.70 |
| System-call 1-3-gram HIDS, RF500, prologue-free | 0.849 ± 0.031 | 0.951 ± 0.015 | 0.859 | 0.840 | 0.841 | 0.973 | 0.141 | 0.167 | 0.80 |
| Kitsune/KitNET, run score = max packet RMSE | 0.555 ± 0.043 | 0.676 ± 0.057 | 0.163 | 0.948 | 0.129 | 0.387 | 0.012 | 0.294 | 0.00 |
| Kitsune/KitNET, run score = 99th-pct packet RMSE | 0.555 ± 0.043 | 0.686 ± 0.063 | 0.162 | 0.948 | 0.149 | 0.247 | 0.015 | 0.272 | 0.00 |
| Kitsune/KitNET, run score = mean packet RMSE | 0.568 ± 0.040 | 0.689 ± 0.044 | 0.188 | 0.949 | 0.154 | 0.413 | 0.018 | 0.250 | 0.00 |
| Kitsune AfterImage aggregates (mean/max/std), RF500 | 0.735 ± 0.029 | 0.787 ± 0.016 | 0.590 | 0.879 | 0.534 | 0.960 | 0.113 | 0.183 | 0.00 |
| CICFlowMeter-like flow features, RF500 | 0.780 ± 0.005 | 0.792 ± 0.035 | 0.588 | 0.971 | 0.525 | 1.000 | 0.004 | 0.178 | 0.00 |
| Diagnostic: n-grams of the target's first 50 calls only (start-up), RF500 | 0.863 ± 0.031 | 0.949 ± 0.017 | 0.923 | 0.803 | 0.915 | 0.973 | 0.168 | 0.250 | 0.90 |
| Diagnostic: n-gram HIDS without prologue and those 50 start-up calls, RF500 | 0.801 ± 0.026 | 0.894 ± 0.016 | 0.659 | 0.944 | 0.611 | 0.973 | 0.036 | 0.167 | 0.10 |
| Software hybrid (n-gram + flows), concatenated RF500 | 0.919 ± 0.035 | 0.978 ± 0.009 | 0.924 | 0.914 | 0.916 | 0.973 | 0.060 | 0.167 | 0.50 |
| Software hybrid (n-gram + flows), stacked LR | 0.872 ± 0.024 | 0.972 ± 0.008 | 0.846 | 0.898 | 0.827 | 0.973 | 0.076 | 0.206 | 0.40 |
| Diagnostic: software hybrid without start-up n-grams, concatenated | 0.855 ± 0.013 | 0.948 ± 0.008 | 0.761 | 0.949 | 0.728 | 0.980 | 0.024 | 0.167 | 0.30 |
| Diagnostic: software hybrid without start-up n-grams, stacked | 0.858 ± 0.014 | 0.915 ± 0.021 | 0.760 | 0.956 | 0.723 | 1.000 | 0.024 | 0.167 | 0.00 |

### Table IV protocol (held-out split, 54 test rows)

| detector | BA | AUC | recall | specificity | TN/FP/FN/TP |
| --- | --- | --- | --- | --- | --- |
| Thesis host (eBPF, 18 ADFA signals x 5) | 0.929 | 0.993 | 1.000 | 0.857 | 24/4/0/26 |
| Thesis network (switch, 29 signals x 5) | 0.750 | 0.788 | 0.500 | 1.000 | 28/0/13/13 |
| Thesis hybrid, concatenated | 0.926 | 0.982 | 0.923 | 0.929 | 26/2/2/24 |
| Thesis hybrid, stacked | 0.963 | 0.995 | 0.962 | 0.964 | 27/1/1/25 |
| STIDE k=6, max locality frame count (frame 20) | 0.500 | 0.661 | 0.000 | 1.000 | 28/0/26/0 |
| STIDE k=6, mismatch fraction | 0.641 | 0.739 | 0.462 | 0.821 | 23/5/14/12 |
| STIDE k=6, LFC, prologue-free | 0.500 | 0.644 | 0.000 | 1.000 | 28/0/26/0 |
| STIDE k=6, mismatch fraction, prologue-free | 0.467 | 0.749 | 0.077 | 0.857 | 24/4/24/2 |
| Lookahead pairs (window 8), LFC | 0.500 | 0.795 | 0.000 | 1.000 | 28/0/26/0 |
| Lookahead pairs (window 8), anomalous-call fraction | 0.758 | 0.793 | 0.731 | 0.786 | 22/6/7/19 |
| System-call 1-3-gram HIDS, RF500 | 0.875 | 1.000 | 1.000 | 0.750 | 21/7/0/26 |
| System-call 1-3-gram HIDS, RF500, prologue-free | 0.893 | 1.000 | 1.000 | 0.786 | 22/6/0/26 |
| Kitsune/KitNET, run score = max packet RMSE | 0.692 | 0.701 | 0.385 | 1.000 | 28/0/16/10 |
| Kitsune/KitNET, run score = 99th-pct packet RMSE | 0.692 | 0.701 | 0.385 | 1.000 | 28/0/16/10 |
| Kitsune/KitNET, run score = mean packet RMSE | 0.654 | 0.733 | 0.308 | 1.000 | 28/0/18/8 |
| Kitsune AfterImage aggregates (mean/max/std), RF500 | 0.734 | 0.825 | 0.538 | 0.929 | 26/2/12/14 |
| CICFlowMeter-like flow features, RF500 | 0.750 | 0.819 | 0.500 | 1.000 | 28/0/13/13 |
| Diagnostic: n-grams of the target's first 50 calls only (start-up), RF500 | 0.911 | 0.974 | 1.000 | 0.821 | 23/5/0/26 |
| Diagnostic: n-gram HIDS without prologue and those 50 start-up calls, RF500 | 1.000 | 1.000 | 1.000 | 1.000 | 28/0/0/26 |
| Software hybrid (n-gram + flows), concatenated RF500 | 0.946 | 1.000 | 1.000 | 0.893 | 25/3/0/26 |
| Software hybrid (n-gram + flows), stacked LR | 0.982 | 1.000 | 1.000 | 0.964 | 27/1/0/26 |
| Diagnostic: software hybrid without start-up n-grams, concatenated | 0.929 | 1.000 | 1.000 | 0.857 | 24/4/0/26 |
| Diagnostic: software hybrid without start-up n-grams, stacked | 1.000 | 1.000 | 1.000 | 1.000 | 28/0/0/26 |

### Pairwise vs thesis (exact McNemar on identical rows)

Table V: mean ΔBA (baseline − thesis) over the ten assignments, and in how many assignments the baseline is significantly better / worse (p < 0.05). Table IV: ΔBA and p.

| baseline | vs thesis stacked | vs thesis host | vs thesis network | Table IV vs thesis concat | Table IV vs host | Table IV vs network |
| --- | --- | --- | --- | --- | --- | --- |
| stide6_collected_lfc | -0.323 (0 / 10) | -0.284 (0 / 10) | -0.256 (0 / 10) | -0.426 (p=0.000) | -0.429 (p=0.000) | -0.250 (p=0.000) |
| stide6_collected_frac | -0.297 (0 / 10) | -0.258 (0 / 10) | -0.230 (0 / 10) | -0.284 (p=0.001) | -0.287 (p=0.003) | -0.109 (p=0.307) |
| stide6_prologuefree_lfc | -0.323 (0 / 10) | -0.284 (0 / 10) | -0.256 (0 / 10) | -0.426 (p=0.000) | -0.429 (p=0.000) | -0.250 (p=0.000) |
| stide6_prologuefree_frac | -0.238 (0 / 10) | -0.199 (0 / 10) | -0.171 (0 / 10) | -0.459 (p=0.000) | -0.462 (p=0.000) | -0.283 (p=0.000) |
| lap8_collected_lfc | -0.323 (0 / 10) | -0.284 (0 / 10) | -0.256 (0 / 10) | -0.426 (p=0.000) | -0.429 (p=0.000) | -0.250 (p=0.000) |
| lap8_collected_frac | -0.251 (0 / 10) | -0.212 (0 / 10) | -0.184 (0 / 10) | -0.168 (p=0.049) | -0.170 (p=0.049) | +0.008 (p=1.000) |
| ngram | +0.044 (4 / 0) | +0.084 (8 / 0) | +0.112 (7 / 0) | -0.051 (p=0.549) | -0.054 (p=0.549) | +0.125 (p=0.263) |
| ngram_pf | +0.026 (0 / 0) | +0.065 (5 / 0) | +0.093 (7 / 0) | -0.033 (p=0.754) | -0.036 (p=0.754) | +0.143 (p=0.167) |
| kitsune_max | -0.268 (0 / 10) | -0.229 (0 / 10) | -0.201 (0 / 10) | -0.234 (p=0.004) | -0.236 (p=0.012) | -0.058 (p=0.250) |
| kitsune_p99 | -0.268 (0 / 10) | -0.229 (0 / 10) | -0.201 (0 / 10) | -0.234 (p=0.004) | -0.236 (p=0.012) | -0.058 (p=0.250) |
| kitsune_mean | -0.255 (0 / 10) | -0.216 (0 / 10) | -0.188 (0 / 10) | -0.272 (p=0.001) | -0.275 (p=0.004) | -0.096 (p=0.062) |
| kitsune_rf | -0.088 (0 / 8) | -0.049 (0 / 2) | -0.021 (0 / 2) | -0.192 (p=0.006) | -0.195 (p=0.013) | -0.016 (p=1.000) |
| flow | -0.044 (0 / 0) | -0.005 (0 / 0) | +0.023 (3 / 0) | -0.176 (p=0.022) | -0.179 (p=0.049) | +0.000 (p=1.000) |
| ngram_startup | +0.040 (1 / 0) | +0.079 (6 / 0) | +0.107 (8 / 0) | -0.015 (p=1.000) | -0.018 (p=1.000) | +0.161 (p=0.096) |
| ngram_nostart | -0.022 (0 / 1) | +0.017 (2 / 0) | +0.045 (4 / 0) | +0.074 (p=0.125) | +0.071 (p=0.125) | +0.250 (p=0.000) |
| sw_concat | +0.096 (9 / 0) | +0.135 (9 / 0) | +0.163 (10 / 0) | +0.021 (p=1.000) | +0.018 (p=1.000) | +0.196 (p=0.021) |
| sw_stacked | +0.049 (5 / 0) | +0.088 (9 / 0) | +0.116 (9 / 0) | +0.056 (p=0.375) | +0.054 (p=0.375) | +0.232 (p=0.002) |
| sw_concat_nostart | +0.032 (2 / 0) | +0.071 (8 / 0) | +0.099 (10 / 0) | +0.003 (p=1.000) | +0.000 (p=1.000) | +0.179 (p=0.049) |
| sw_stacked_nostart | +0.035 (2 / 0) | +0.074 (10 / 0) | +0.102 (10 / 0) | +0.074 (p=0.125) | +0.071 (p=0.125) | +0.250 (p=0.000) |

## 4. Comparison with the thesis's reference numbers

Reference numbers (published; reproduced here before any comparison): Table V BA host .784, network .756, stacked
hybrid .823 (concatenated .812 with the loader; .809 in the earlier diagnostic); Table IV BA host .929, network .750,
concatenated hybrid .926.

* **Pure HIDS (STIDE family) — clearly below the thesis host detector.** Table V BA 0.500-0.585 (AUC 0.71-0.81) vs
  host 0.784 (AUC 0.839); Table IV 0.467-0.758 vs 0.929; worse than the thesis's stacked hybrid in all ten fold
  assignments (exact McNemar p < 0.05). A profile pooled from other benign programs cannot tell an unseen benign
  program from malware (caveat 2).
* **Supervised n-gram HIDS — higher on Table V, lower on Table IV, and largely a start-up artefact.** Table V BA
  0.868 ± 0.040 vs host 0.784 and stacked 0.823 (significantly better than the stacked hybrid in 4 of 10 assignments,
  never worse); Table IV 0.875 vs host 0.929 (7 benign false alarms vs 4; p = 0.55). The
  first 50 calls of the program alone reach 0.863 ± 0.031 (Table V); without them the n-gram HIDS falls to 0.801 ± 0.026,
  between the thesis host and stacked detectors (caveat 1).
* **Pure NIDS (Kitsune) — below the thesis network detector.** KitNET with the max-RMSE run score gives Table V
  BA 0.555 ± 0.043 (AUC 0.676) vs the thesis network detector's 0.756 (AUC 0.769), and Table IV 0.692 vs 0.750. It
  flags 39% of the attack runs, 13% of the general malware and 29% of the network-active benign runs. By attack type it
  flags every Slowloris run (maximum RMSE ~10^5-10^6) but only 7% of the SYN/UDP floods and 10% of the GoldenEye runs:
  the floods' maximum RMSE (median 1.0-1.8) is well above that of CLI benign runs (median 0.01) but below the
  thresholds (median 19 over folds), which are set by held-out benign *network* runs (90th percentile of their max RMSE
  ~750; bulk2000 reaches 7,654 when held out). Per packet, AfterImage's damped statistics (per source, host pair and
  socket pair) of a single-destination flood resemble the benign bulk uploads, and each packet of a fan-out flood
  resembles the opening of a new connection, which the benign transfers do thousands of times (e.g. syn_fan_40k: 0.94
  against a threshold of 153 in the first fold). Used as supervised features (per-run mean/max/std + RF500), the same
  AfterImage statistics give 0.735 ± 0.029 (Table V) / 0.734 (Table IV) and catch 95-97% of the floods — close to, but
  below, the switch features.
* **Unconstrained software flow features — about the same as the switch's 29 signals.** Table V BA 0.780 ± 0.005 vs
  network 0.756 (AUC 0.792 vs 0.769); on Table IV the flow RF makes exactly the thesis network detector's
  decisions (28/0/13/13, BA 0.750). Network-only detection is limited by the malware that sends nothing in the
  window, not by the switch's feature constraints: 47% of the 99 malware runs have no TCP/UDP flow in it; the flow RF
  flags 100% of the malware runs that have one and 0% of the others (switch features: 99% and 0%), so both reach a
  general-malware recall of about 0.52 (0.525 vs 0.520). The richer flow statistics mainly reduce false alarms on the
  network-active benign runs (0.178 vs 0.350).
* **Software hybrid — higher than the thesis hybrid, but inherits the n-gram start-up artefact.** Concatenated
  0.919 ± 0.035, stacked 0.872 ± 0.024 (Table V) vs thesis stacked 0.823 / concatenated 0.812; Table IV 0.946 / 0.982 vs
  0.926 (thesis concatenated) / 0.963 (thesis stacked, not published). Built on the n-grams without the start-up
  calls (diagnostic) the software hybrid gives 0.855 ± 0.013 / 0.858 ± 0.014 on Table V, i.e. still about 0.03 above
  the thesis stacked hybrid (significantly better in 2 of 10 assignments, never worse); it uses full system-call
  identities and unconstrained flows computed in software, which a line-rate switch plus an in-kernel aggregate
  monitor do not provide, and its other threads/processes may still carry runtime fingerprints (e.g. Go runtime
  threads). The full software hybrid (concatenated) is significantly better than the thesis stacked hybrid in 9 of 10
  assignments.

## 5. Software extraction throughput

`throughput.py`: packets per CPU-second on the two largest attack captures (whole files; Kitsune on the first in-window
packets). Cores for 100 Gb/s = packet rate / per-core rate (148.8 Mpps at 64 B, 23.5 Mpps at 512 B), assuming
perfect scaling and ignoring capture and load-balancing costs, so they are lower bounds.

| extractor | syn_fan_150k (150,404 packets, 149,425 flows) | udp_sink_250k (250,020 packets, 1 flow) | cores for 100 Gb/s at 64 B / 512 B (best capture) | (worst capture) |
| --- | --- | --- | --- | --- |
| CICFlowMeter-like extractor (`flow_extract.py`, pure Python) | 19,600 pkt/s | 520,800 pkt/s | 286 / 45 | 7,600 / 1,200 |
| Kitsune AfterImage (official, pure Python) | 136 pkt/s (first 2,000 packets; 7 pkt/s over the first 20,000) | 8,490 pkt/s (first 20,000) | 17,500 / 2,770 | ~1.1 M / ~170,000 |
| tshark -T fields, Kitsune's 19 fields (C) | 58,900 pkt/s | 59,900 pkt/s | 2,490 / 390 | 2,520 / 400 |
| Zeek 9.0.1, default scripts, `-C -r` (C++) | 38,400 pkt/s | 697,500 pkt/s | 213 / 34 | 3,880 / 610 |

Per-flow work dominates on the fan-out flood (one flow per packet): the Python extractor and Zeek fall to
~20k and ~38k packets per CPU-second, while on a single-flow flood they reach 0.5-0.7 M. Kitsune's official
Python AfterImage is ~8,500 packets/s at best and degrades with the number of peers of a source (≈ quadratic). The
Kitsune authors state that their C++ implementation is about 100× faster than the Python one; even 100× would leave
~175 cores (64 B) at best. The thesis's switch computes its 29 flow signals in the data plane at line rate (measured
separately in the thesis, not in this folder).

## 6. Caveats and deviations

1. **Start-up fingerprint (most important).** The supervised n-gram HIDS — and therefore the software hybrid built on
   it — is strong on this dataset, but the diagnostic that sees only the **first 50 calls of the target program**
   scores about the same (Table V BA 0.863 ± 0.031 and Table IV 0.911, vs 0.868 ± 0.040 and 0.875 for the full n-gram HIDS). Those calls are the C-library / language-runtime initialisation (e.g.
   glibc 2.35 static start-up with `rseq` and `getrandom` in the benign builds; older start-ups without them in
   Qilin (`getrlimit`, `open`, `time`) and Akira (`time`); the Go runtime's `mmap`/`sigaltstack`/`rt_sigaction` storm
   in BrickStorm). The benign programs were all compiled by the study with a few toolchains (static glibc 2.35 or musl
   builds; the dynamic builds load the guest's C library), while the malware binaries come with many different
   toolchains and runtimes, so the start-up identifies how a binary was built, not what it does. The
   n-gram detector's gain over the thesis host detector is concentrated on runs with little activity: malware with
   < 100 post-target calls is flagged in 61% of cases by the n-gram HIDS and 84% by the start-up-only diagnostic, vs 33% by the thesis's stacked hybrid and 9% by the n-gram HIDS without the start-up calls (25 runs, Table V decisions averaged over the ten assignments); Qilin is flagged 0.67 / 1.00 / 0.00 / 0.00 of the time by the same four detectors; samples that only printed an error and exited (e.g. Qilin's
   "No password specified!" after 56 calls) have no malicious behaviour to detect. These scores therefore do **not**
   show better behavioural detection; they show that full system-call identities expose a toolchain artefact of this
   dataset, which the thesis's identity-free descriptors (counts, entropy, run lengths, first-N unique counts, where
   the root process's first 100 calls are the fixed launcher) cannot read directly. A benign set built with the same
   toolchains as the malware would be needed to measure the HIDS baselines' behavioural accuracy: section 8 does
   this (2026-11-14).
2. **STIDE needs a per-program profile.** STIDE was designed to model the normal behaviour of one program. Under the
   group-held-out protocols every test program is unseen, and a profile pooled from other benign programs flags most
   unseen benign programs too: the maximum locality frame count saturates at 20 for 46% of the CLI benign runs (82% of
   malware, 100% of attacks). With the pre-stated rule (score > 95th percentile of held-out benign scores, which is 20)
   the LFC variants flag nothing (BA 0.500); this is not a tuning artefact but a lack of separation, see the AUCs.
   For information only (post hoc, not a pre-stated rule): flagging LFC = 20 would give Table V BA 0.711 (STIDE) and
   0.774 (lookahead pairs) with 46% / 28% of CLI benign runs flagged.
3. **Kitsune packet cap and implementation.** Each run's first 20,000 in-window packets only (16 runs affected); the
   cap can only lower a run's maximum RMSE, i.e. it slightly favours specificity. The official Python code is used
   unmodified except two runtime shims (the `np.Inf` alias removed in NumPy 2.0; Cython supplied so that
   `pyximport.install()` can be called — no Cython module is used). The current netStat returns 100 features instead
   of the paper's 115. KitNET was given a per-run-capped, shuffled sample of the benign training packets (not a
   continuous benign stream); in Table IV its training set is only 372 packets from 77 CLI programs. Packet scores
   are computed in batch with the official weights (checked equal to `execute()`).
4. **Unsupervised thresholds.** Taken from inner held-out benign groups on the training side (in-sample benign scores
   are 0 for STIDE by construction). The 95th percentile targets about 5% false alarms on unseen benign groups; the
   maximum is reported as a second operating point. AUC is threshold-free.
5. **Flow features are CICFlowMeter-like, not the CICFlowMeter tool.** Own implementation (standard library),
   payload-based lengths, IPv4 TCP/UDP only, connection-based TCP termination. A first version split each TCP
   connection at its final ACK (1-packet flows); this was found in a flow-count check (bulk2000: 3,828 flows for
   2,000 connections) and corrected before the final scoring. The first version gave Table V BA 0.768 ± 0.010 / Table
   IV 0.750 (flows), 0.917 / 0.929 (concatenated software hybrid); its results are kept in
   `results/supervised_v1_flowsplit.json`.
6. **ABI reconstruction.** System-call numbers are tagged with an ABI inferred from execs and forks (Section 1); the
   trace itself does not record it. A process with no fork record defaults to the run's mode.
7. **Throughput numbers are lower bounds on cores.** Single-core CPU time on two captures, perfect scaling assumed, no
   capture/load-balancing cost; the two Python extractors are unoptimised research code, tshark and Zeek are compiled
   tools. Kitsune's per-packet cost depends on how many peers a source has.
8. **Same data, same limits as the thesis.** 114 malicious runs (99 malware samples from a purposive cohort, 15
   self-generated attacks), CLI benign programs, post-hoc analysis of an already examined design, small per-family
   counts. Table V numbers are means over ten fold assignments of the same 240 runs, not independent replications;
   Table IV is a single split of 54 rows.
9. **Diagnostics were added after seeing results.** The start-up diagnostics (Section 2.2) and the flow-count fix
   (caveat 5) came after the first n-gram/flow scores; all other settings (thresholds, caps, model parameters) were
   fixed before scoring and not changed afterwards.

## 7. Files and how to rerun

Run from this folder with `/usr/bin/python3` (scikit-learn 1.7.0, NumPy 2.2.6, SciPy 1.15.3 from the user site; do
not use `-I`, which hides them). Each script uses at most ten processes (`BL_JOBS` lowers it).

| step | command | output |
| --- | --- | --- |
| system-call tokens | `extract_syscalls.py` | `cache/syscalls/*.npz`, `cache/syscalls_summary.json` |
| STIDE (+ lookahead pairs) | `stide.py --lookahead` | `results/stide.json`, `scores/stide6_*`, `scores/lap8_*` |
| flows | `flow_extract.py` | `cache/flows/features.npz` |
| n-gram HIDS, flows, software hybrid | `supervised.py` | `results/supervised.json`, `scores/{ngram,ngram_pf,flow,sw_concat,sw_stacked}_*` |
| start-up diagnostics | `supervised.py --startup` | `results/supervised_startup.json`, `scores/{ngram_startup,ngram_nostart,sw_concat_nostart,sw_stacked_nostart}_*` |
| Kitsune features (~90 min wall, official code) | `kitsune_extract.py` | `cache/kitsune/{tsv,vec,meta}`, `cache/kitsune/summary.json` |
| Kitsune / KitNET | `kitsune_eval.py` | `results/kitsune.json`, `scores/kitsune_{max,p99,mean}_*` |
| Kitsune aggregates + RF | `supervised.py --kitsune` | `results/supervised_kitsune.json`, `scores/kitsune_rf_*` |
| thesis detectors + McNemar | `compare_thesis.py` | `scores/thesis_*`, `results/compare_thesis.json` |
| throughput | `throughput.py` | `results/throughput.json`, `results/throughput_flow_extractor.json` (if run) |
| summary | `make_summary.py` | `results.json` (+ the tables of this README on stdout) |
| toolchain-matched rerun (section 8) | `toolchain_ngram.py ../../toolchain21-collect/20261113T203411281909Z` | `results/toolchain_ngram_protocol.json` (written first), `results/toolchain_ngram.json`, `scores/toolchain_{B,D}_*`, `cache/syscalls_toolchain/`, `logs/toolchain_ngram.log` |

**Saved scores** (`scores/<name>_table5.npz`, `scores/<name>_table4.npz`), rows in features.csv order:
* Table V files: `score` (10 × 240; probability for supervised detectors, margin to the fold threshold for
  unsupervised ones), `pred` (10 × 240, 0/1 decisions of the primary operating point), `folds` (10 × 240 fold index;
  rows of assignment k use seed `common.FOLD_SEEDS[k]`); unsupervised also `pred_max`, `raw` (raw score),
  `threshold`, `threshold_max` (per row: the threshold of its fold).
* Table IV files: `test_index` (the 54 test rows), `score`, `pred` (and `pred_max`, `threshold`, `threshold_max` for
  unsupervised detectors).
* `scores/thesis_{host,network,concat,stacked}_*` hold the thesis detectors in the same format (recomputed with
  `common.py`), so `common.mcnemar_exact(y, pred_a, pred_b)` can be applied row by row.

`results.json` holds, per detector, Table V metrics (mean/sd/min/max and every assignment), flag rates, Table IV
metrics and confusion counts, the second operating point of the unsupervised detectors, the pairwise McNemar
summaries, the throughput measurements, the extraction summaries and `diagnostics` (every fact quoted in Sections 4
and 6, recomputed from the caches and saved scores).

Other files: `bl_common.py` (shared helpers), `vendor/VENDOR.md` (provenance and SHA-256 of third-party code),
`logs/` (run logs), `.gitignore` (keeps caches and third-party binaries out of git).

## 8. Rerun on the toolchain-matched benign programs (`toolchain_ngram.py`, 2026-11-14)

Caveat 1 asked for a benign set built with the malware's toolchains. It now exists:
`toolchain21-collect/20261113T203411281909Z`, 85 accepted benign runs. These are the dataset's static programs
rebuilt with older glibc, uClibc 0.9.30.1 + GCC 4.1.2, Go 1.13-1.24 and UPX, plus 6 dataset controls; their five
start-up flags match the malware's. `toolchain_ngram.py` scores every supervised detector of this folder on the four
pools of `../toolchain/score_toolchain.py`, using its rows, groups, splits and folds. It also recomputes the thesis
detectors on the same folds, for paired comparisons. The protocol and the decision rule were written before any score
(`results/toolchain_ngram_protocol.json`, 2026-11-14 08:01 UTC).

Four checks passed:
1. All 85 runs pass `extract_syscalls.py`'s gates.
2. The n-gram bags built here equal the cached ones on all 240 rows, for all four variants.
3. All nine detectors reproduce their saved 240-row Table V and Table IV scores exactly (maximum difference 0).
4. The thesis detectors reproduce `../results/toolchain_scores.json` on every pool.

Results: `results/toolchain_ngram.json` (SHA-256 `8cf08ae4...`). In the table:
* A: share of the 85 rebuilt benign programs flagged by detectors trained on the 240 released rows.
* B: the 87 static benign rows replaced by the rebuilt ones (238 rows); Table V protocol, mean ± sd over 10
  assignments.
* C: the released held-out split with the same replacement (70 test rows, 37 of them rebuilt programs); mean ± sd over
  11 forest seeds.
* D: all 240 rows plus the 85 (325 rows); Table V protocol.

| Detector | A | B | C | D |
| --- | ---: | --- | --- | --- |
| n-gram HIDS | 0.73 | 0.824 ± 0.023 | 0.967 ± 0.012 | 0.816 ± 0.018 |
| n-gram HIDS, prologue-free | 0.71 | 0.828 ± 0.021 | 0.970 ± 0.008 | 0.823 ± 0.020 |
| Diagnostic: first 50 calls only | 0.91 | 0.641 ± 0.041 | 0.515 ± 0.021 | 0.718 ± 0.019 |
| Diagnostic: without those 50 calls | 0.16 | 0.788 ± 0.012 | 0.937 ± 0.006 | 0.789 ± 0.018 |
| Software hybrid, concat / stacked | 0.80 / 0.68 | 0.868 / 0.861 | 0.989 / 0.890 | 0.870 / 0.865 |
| same without the 50 calls, concat / stacked | 0.16 / 0.16 | 0.848 / 0.852 | 0.964 / 1.000 | 0.855 / 0.856 |
| Thesis host | 0.11 | 0.787 ± 0.019 | 0.913 ± 0.008 | 0.784 ± 0.009 |
| Thesis concat / stacked | 0.14 / 0.11 | 0.815 / 0.818 | 0.887 / 0.901 | 0.827 / 0.822 |

Pool B in detail (flag rate per category, mean over the 10 assignments):

| Detector | Malware (99) | <100 post-target calls (25) | Attacks (15) | Rebuilt benign (85) | Dynamic CLI benign (18) | Net. benign (18) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| n-gram HIDS | 0.684 | 0.32 | 1.00 | 0.022 | 0.150 | 0.133 |
| without the 50 calls | 0.633 | 0.29 | 1.00 | 0.076 | 0.056 | 0.167 |
| first 50 calls only | 0.576 | 0.74 | 1.00 | 0.416 | 0.106 | 0.167 |
| Thesis host | 0.722 | 0.44 | 0.91 | 0.155 | 0.144 | 0.156 |

**Findings**

1. **Trained on the released rows, the n-gram HIDS is mostly a build detector.** It flags 73% of the rebuilt
   benign programs: Go 100%, uClibc 95%, UPX 73%, older glibc 55%, and 0% of the six dataset controls. The thesis
   host detector flags 11% (uClibc 21%, UPX 18%). Without the target's first 50 calls the n-gram HIDS flags 16% (Go 70%,
   every other class 0%). On benign software from build toolchains its training data did not cover, the published
   n-gram detector would raise false alarms on most programs.
2. **Retrained with the rebuilt programs in the benign training data, it still beats the thesis host detector**
   under the pre-stated rule (pool B: +0.037 BA, higher in 9 of 10 assignments; exact McNemar p < 0.05 in 2 of 10).
   * The whole edge is specificity. It flags 2% of the rebuilt programs, against the host's 16% (the host's false
     alarms there are uClibc 37% and UPX 36%). It catches fewer malware (0.684 vs 0.722, low-activity malware 0.32 vs
     0.44) and more attack runs (1.00 vs 0.91).
   * Without the target's first 50 calls the edge disappears: 0.788 vs 0.787, 5 of 10 assignments each way.
   * The n-grams of those 50 calls alone still score 0.641 and flag 19-80% of the rebuilt programs per class.
   * For these static builds the 50 calls hold both the C-library start-up and the program's first actions. Finer
     build identity than our class-level matching (the study used a few specific toolchains per class, the malware
     many) cannot be excluded.
   * So on these data the n-gram's remaining advantage is real, but it cannot be credited to behaviour alone.
3. **The software hybrid stays above the thesis hybrid.**
   * Pool B: +0.053 BA concatenated vs concatenated, +0.043 stacked vs stacked; higher in 10 of 10 assignments.
   * Still about +0.03 without the 50 calls (0.848 / 0.852 vs 0.815 / 0.818).
   * The software flow features alone (0.780) match the switch's (0.772), so the edge comes from the host side.
4. **Pools C and D agree in direction:** n-gram 0.967 vs host 0.913 on the held-out split, 0.816 vs 0.784 on the
   mixed pool.

**Reading.** Full system-call identities let a detector learn more than the 18 in-kernel summaries when the benign
training data covers the build toolchains seen in deployment (about +0.04 BA here). The same detector, trained on data
that does not cover them, flags most programs built with an unfamiliar toolchain (73%, against 11% for the summaries).
The summaries trade some accuracy for robustness to build artefacts and for cost:
* n-grams need the ordered call sequence;
* our streaming monitor, which exports it, cost +0.29-0.36 µs per call against +0.05 µs for the in-kernel aggregates
  (`p4_ebpf/ebpf_perf/COMPARISON.md`);
* an in-kernel n-gram counter (as ebpH keeps lookahead pairs) would sit in between and was not measured.

**Limits.**
* One benign-only collection batch; one set of toolchains per class.
* The per-class and per-category breakdowns were reported without a rule.
* Post hoc on data whose 240-row part was already examined.
