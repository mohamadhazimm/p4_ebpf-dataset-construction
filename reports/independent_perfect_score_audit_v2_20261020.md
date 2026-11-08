# Independent Audit of the Perfect Host/Hybrid Scores (v2), 2026-10-20

Status: **derived, exploratory, post hoc**. This report does not replace
`reports/independent_classifier_audit_20261020.md` or any frozen result. No malware was executed, no VM was
operated, no frozen capture/snapshot/runner/model output was modified, and runner schema `.14` was not changed.
All new code and outputs are in
`data/versioned-collector/independent-audit-derived-20261020/` (called **DERIVED** below).

The task was to explain what the classifier learns, not to raise the score.

---

## 1. Executive Conclusion

| Claim | Verdict | Confidence |
| --- | --- | --- |
| The host BA 1.000 and hybrid BA 1.000 on the 183-sample scale100 cohort reflect detection of malicious behavior. | **Not supported.** | High |
| The perfect score is produced mainly by a shortcut: benign **shell scripts** versus malware **ELF executables**. The shortcut acts through launch and process-lifecycle syscalls (dup2, fork, execve, openat, mmap, mprotect). | Supported | High |
| After matching file format (benign ELF vs malware), most of the remaining host signal (BA 0.88–0.96) is explained by **static vs dynamic linkage**, plus runtime and lifecycle differences. | Supported, using a proxy | Medium |
| *Addendum A (ELF headers):* the remaining signal is explained by **artifact construction and execution mode**: 87/98 malware are static or static-PIE by header, and 46/98 are non-x86 binaries run under **qemu-user emulation**, while all benign runs are native. A fixed rule "emulated or header-static → malware" gives BA 0.954 on benign ELF vs malware, above the learned host model (0.880). | Supported (headers + event logs) | High |
| The present design allows a malicious-behavior interpretation. | **No.** | High |

Why the design does not allow that interpretation:
- Class is fully confounded with acquisition metadata. Collection time and watch-path count alone give BA 0.995–1.0.
- No benign sample is statically linked.
- Two malware samples with no target activity at all receive probability 1.0 of being malware.
- There are only 10 independent benign ELF groups.

**The decisive evidence, all from grouped out-of-fold (OOF) validation:**

1. A classifier separating **benign scripts from benign ELF** gets BA 0.975. 7 of its top-10 host families are the same as the malware classifier's top-10 (experiment A). The original model's best features therefore distinguish file format and launch path, not maliciousness.
2. A single dup2 split gives BA 0.957 on the original cohort and 0.515 once benign is also ELF.
3. A fixed rule with no fitting, *"no libc opened after exec → malware"*, gives BA 0.886 on the original 183 samples and 0.878 on benign ELF vs malware.
   - The learned host model on the latter scores 0.880.
   - All 200 benign runs (script and ELF) load libc dynamically. Only 24 of 98 accepted malware do.
4. Among dynamically linked samples only (100 benign ELF vs 24 malware, 13 signatures), host BA is 0.867 [0.74, 0.955]. A nuisance-only model (exit status, timing, volume) gets 0.811 [0.69, 0.909]. The confidence intervals overlap.
5. Malware CoinMiner `9e5b93d3…` and NoEscape `d7e5d1da…` produced **zero target syscalls after exec**: only the Python/bash launcher was recorded. Both still received OOF probability **1.0** in the saved host and hybrid predictions. The model labels "launcher-only, no target activity" as malware.

> **Correction (Addendum A).** Items 3–4 use a run-time proxy. The ELF-header check shows that the proxy measures "some process in the lineage loaded libc", not binary linkage: only 8 of the 24 proxy-dynamic malware are dynamic by header; the other 16 are static binaries whose spawned children (`sh`, `crontab`, `update-rc.d`, `iptables`, `pgrep`, …) loaded libc. Header-defined native dynamic malware is only 9 samples (7 signatures).

P4-only results (0.694; 0.785 on benign ELF vs malware) are also not interpretable as behavior. Malware and benign were collected at different times from different snapshots. The P4 model also scored launcher-only CoinMiner at 0.83. Network confounding was not decomposed further in this audit.

---

## 2. Verified Evidence (paths and line references)

Paths are relative to the study root `vbox-runs/hybrid-rf-study-20261010/`.

### Launch path and observation window

| Fact | Location |
| --- | --- |
| The sample is launched as `/bin/bash -c 'exec "$@"' sample-launch <command>`. | [src/malware_runner.py](../src/malware_runner.py#L2617) |
| Popen uses `start_new_session=True`. The Python child sets up stdio (3 dup2 calls), then exec #1 runs bash, then exec #2 runs the target. | [src/malware_runner.py](../src/malware_runner.py#L2624) |
| The root PID is recorded. | [src/malware_runner.py](../src/malware_runner.py#L2628) |
| The observation end is set to `min(now, start + timeout)`. | [src/malware_runner.py](../src/malware_runner.py#L2689) |
| Process-group termination. Processes that call `setsid` escape the kill but remain traced; the VM is restored for each sample. | [src/malware_runner.py](../src/malware_runner.py#L949-L966) |

### eBPF tracing

| Fact | Location |
| --- | --- |
| Raw syscall probe is gated on `@tracked[pid]`. | [src/malware_runner.py](../src/malware_runner.py#L1897) |
| Lineage starts at fork. | [src/malware_runner.py](../src/malware_runner.py#L1987) |
| Exit removes `@tracked[tid]`. If a thread-group leader exits before its threads, those threads stop being traced (minor edge case). | [src/malware_runner.py](../src/malware_runner.py#L1991-L1993) |
| There is no `sched_process_exec` probe and the execve return value is not recorded, so exec success is not directly observed. | — |

### Collection-side filtering and aggregation

| Fact | Location |
| --- | --- |
| `EbpfCollector.collect` starts from the root PID and its lineage. | [src/malware_runner.py](../src/malware_runner.py#L2184), [L2202](../src/malware_runner.py#L2202) |
| Events after the end of the observation are excluded. | [src/malware_runner.py](../src/malware_runner.py#L2215) |
| Window assignment. | [src/malware_runner.py](../src/malware_runner.py#L2218) |
| Raw-syscall fallback counters are recorded. | [src/malware_runner.py](../src/malware_runner.py#L2331) |
| The five summary statistics include `active_windows`. With a constant 20 s / 40-window observation, `mean` equals `sum/40`, so the two columns are redundant. | [src/build_dataset.py](../src/build_dataset.py#L57), [L69-L79](../src/build_dataset.py#L69-L79) |

### Exec-boundary layer (`exec_boundary.py`, derived and untracked)

- [src/exec_boundary.py](../src/exec_boundary.py#L82-L93) takes the timestamp of the N-th root execve.
- It does **not** check whether the exec succeeded; a failed exec still sets a boundary. This is shown by the test `test_exec_boundary_does_not_verify_exec_success`.
- Window denominators remain 40.

### Frozen 29+29 modeling script

`data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/run_scale100_p4_29x29.py`:
- Quality exclusion: L124–L132.
- P4-alignment exclusion: L171. This exclusion is also applied to the host-only and hybrid models.
- `StratifiedGroupKFold`: L227.
- Mutual-information (MI) selection inside each training fold: L260–L266.
- RF with 500 trees: L313–L314.

### Saved OOF probabilities for launcher-only malware

In `.../modeling/p4_29x29/oof_predictions.csv`:

| Sample | host | hybrid | P4 |
| --- | --- | --- | --- |
| CoinMiner `9e5b93d3…` | 1.0 | 1.0 | 0.835 |
| NoEscape `d7e5d1da…` | 1.0 | 1.0 | 0.492 |

### Per-run audit (DERIVED `run_audit_summary.json`)

**Exec boundary**
- All 300 runs have exactly 2 root raw execs.
- Target comm observed after the boundary: malware 96/98 accepted, benign script 100/100, benign ELF 100/100.
- No PID-reuse suspects and no events before sample start.

**Return codes (accepted runs)**

| Cohort | Exit 0 | Other outcomes |
| --- | --- | --- |
| Malware (98) | 43 | 19 rc1, 19 timeout (−15), 12 SIGSEGV (−11), 3 rc255, 1 rc127, 1 (−17) |
| Benign script (100) | 95 | 3 rc9, 2 rc12 |
| Benign ELF (100) | 79 | 19 timeout, 1 rc1, 1 rc18 |

**Runtime and activity**

| Measure | Malware | Benign script | Benign ELF |
| --- | --- | --- | --- |
| Root exits in < 1 s | 62/98 | 100/100 | 51/100 |
| Post-exec activity after 1 s | 28/98 | 0/100 | 46/100 |
| Median post-exec raw syscalls | 268 | 538 | 322 |
| Median distinct PIDs | 1 | 4 | 1 |
| Median dup2 events | 3 | 5 | 3 |
| Runs with connect | 40 | 15 | 43 |

**Acquisition**

| Cohort | Collection window (2026-10-20 UTC) | Snapshot | Watch paths |
| --- | --- | --- | --- |
| Malware | 07:33–09:13 | `clean-current-runner-2026-10-18.1-malware` | 1 |
| Benign script | 09:16–10:31 | `clean-benign-expanded-20261017` | 1 |
| Benign ELF | 13:37–14:56 | `clean-paired-elf-watchpath-pilot-v4-20261018` | 2 |

Collection was not interleaved.

---

## 3. Literature Review (pitfalls mapped to this study)

Sources were verified in this session unless marked otherwise. Only claims supported by the retrieved text are made.

| Source | Pitfall | How it applies here |
| --- | --- | --- |
| Arp et al., "Dos and Don'ts of Machine Learning in Computer Security," USENIX Security 2022 | Sampling bias; spurious correlations; inappropriate baselines; lab-only evaluation | Benign and malware are drawn from different artifact populations (scripts vs ELF, dynamic vs mostly static). Shortcut features beat or equal the "behavioral" model. |
| Pendlebury et al., "TESSERACT," USENIX Security 2019 | Spatial and temporal bias | Collection time and cohort lineage are perfectly class-aligned. There is no time-disjoint test. |
| Rossow et al., "Prudent Practices for Designing Malware Experiments," IEEE S&P 2012, DOI 10.1109/SP.2012.14 | Goodware representativeness; activation checks; dataset balance | Malware activation is not verified: 2 samples have no target syscalls and 55/98 do not exit 0. Benign coverage is narrow. |
| Canali et al., ISSTA 2012, DOI 10.1145/2338965.2336768 | Behavior models can be evaluated in ways that overstate accuracy | Syscall-count features need goodware diversity to be meaningful. |
| Lanzi et al., "AccessMiner," CCS 2010, DOI 10.1145/1866307.1866353 | Diverse real benign workloads matter for syscall detectors | Abstract only partly retrieved; cited only for this general point. |
| Cozzi et al., "Understanding Linux Malware," IEEE S&P 2018, DOI 10.1109/SP.2018.00054 | Linux malware differs in linking, architecture and packaging | Supports stratifying by linkage and architecture. No static-linking percentage is claimed. |
| Küchler et al., NDSS 2021 | Sandbox behavior depends on observation time | Here 62/98 malware roots exit in under 1 s. A fixed 20 s window does not equal active runtime. |
| Engelen, Rimmer, Joosen, SPW 2021, DOI 10.1109/SPW53761.2021.00009; D'Hooge et al., PST 2022, DOI 10.1109/PST55820.2022.9851974 | Collection artifacts and non-metadata contaminant features | The launcher dup2 burst, loader activity and acquisition metadata act as contaminants. |
| Geirhos et al., "Shortcut learning," Nature Machine Intelligence 2020, DOI 10.1038/s42256-020-00257-z | Models use the easiest decision rule | A dup2 stump (0.957) and the libc rule (0.886) match "behavioral" models. |
| Kapoor & Narayanan, "Leakage and the reproducibility crisis," Patterns 2023, DOI 10.1016/j.patter.2023.100804 | Leakage taxonomy, including non-independence and selection effects | P4 alignment exclusion depends on class and changes host results. Exact duplicate vectors exist within groups. |
| Liu, Caragea, Ou, Roy, arXiv:2410.19364 (**preprint**) | Train/test leakage through duplicates in malware detection | Exact host-vector duplicates were checked: none cross folds in the original data (Section 7). |
| Sommer & Paxson, IEEE S&P 2010 (**not re-verified this session**) | Gap between ML anomaly detection results and operational validity | Background only. |

---

## 4. Implementation Audit

**Correct as implemented (verified):**
- Lineage gating, time-window filtering and window assignment.
- MI selection is fit only on training folds. The test `test_selection_sees_training_rows_only` passes, and the frozen script computes MI inside each fold loop.
- `StratifiedGroupKFold` folds keep groups disjoint (`check_splits`).
- Re-derived host features match the frozen aligned dataset (parity check in `diagnostics.py`).
- Fork tracking reaches grandchildren. Example: a Gafgyt double-fork grandchild was traced.

**Weaknesses (none on its own explains BA 1.0):**
1. **Exec success is not observed.**
   - The runner has no exec probe and does not record the execve return value.
   - `exec_boundary.find_exec_boundary` accepts a failed exec.
   - The audit uses the comm name after the boundary as a proxy. Two malware runs have no post-exec root syscalls at all.
2. **The launcher's syscalls are attributed to the sample.** About 178 launcher syscalls (including 3 dup2) are in every vector. They are constant across classes. Even so, they make a launcher-only failed run look like a short malware run.
3. **Named execve rows are missing for the root in about 75% of runs** across all cohorts, so the gap does not differ by class. The raw fallback fills the counter (89/100/87 runs), but path detail is lost.
4. **The P4 alignment exclusion is applied to the host model.**
   - 11 benign ELF runs that the classifier finds hard are dropped: find 3, tail 2, md5sum 2, curl, ping, openssl, vmstat.
   - Host BA on benign ELF vs malware changes from 0.880 (all 198 accepted) to 0.956 (181 aligned).
   - Exclusion rules that depend on another modality are not neutral.
5. **Redundant and degenerate summaries.** The mean/sum pair is redundant, and `active_windows` is a duration proxy: the median number of active windows is 1 in every cohort.
6. **Exit tracking is keyed on `tid`.** This is a minor thread-leader edge case.
7. **Small permutation count.** `group_permutation` with 50 permutations gives a minimum possible p-value of 1/51 = 0.0196. Report it as such.

---

## 5. Experiment Reconstruction

**Original 29+29 experiment**
- Data: scale100 `.14` cohort, 200 collected runs.
  - 2 CatStorm quality rejects (1,522 and 27 kernel PCAP drops).
  - 15 non-unique P4 alignments (6 malware, 9 benign).
  - Leaves 183 samples (92 malware / 91 benign) in 28 malware signature groups and 18 benign tool groups.
- Validation: `StratifiedGroupKFold(5, shuffle, seed 42)`.
- Features: per-fold MI selection of 29 of the 35 host families (145 columns), plus 29 P4 families (145 columns).
- Classifier: RF with 500 trees, `min_samples_leaf=2`, `balanced_subsample`.

**Reproduction (`diagnostics.py`, R0 and S183)**
- From the saved OOF file, recomputed BA is host 1.0, hybrid 1.0 and P4 0.6941 (AUC 0.8365).
- Re-fitting with an independent loader (RF with 300 trees) also gives host_all 1.0, host_mi29 1.0 and post-exec host 1.0.
- Group cluster-bootstrap CIs for host and hybrid are [1, 1]. This is a sign of a degenerate separation, not of precision.

**Collection order and lineage**
- Malware, then benign script, then (four hours later) benign ELF, each from a different snapshot.
- The ELF cohort also used 2 watch paths instead of 1.
- An "acquisition-only" model (watch-path count, UTC start hour) gets BA 0.995 on the 183 and 1.0 on benign ELF vs malware.
- Every downstream comparison is therefore confounded with collection batch. This is a design problem that no feature ablation can fix.

---

## 6. Benign ELF Cohort Assessment

**Source:** `data/versioned-collector/benign-elf-100-v14-20261020T140000Z/`.

**Collection facts**
- 10 tools × 10 argument profiles. Tools: curl, dd, find, md5sum, openssl, ping, tail, tar, vmstat, wget.
- 100/100 runs retrieved and quality-accepted.
- Return codes: 79 exit 0, 19 timeout, 1 rc1, 1 rc18.
- 11 runs have non-unique P4 alignment.

**Strengths**
- It removes the dup2/script shortcut: dup2 stump BA falls from 0.957 to 0.515.
- It adds long-running and network workloads:
  - 46/100 runs are still active after 1 s, compared with 28/98 malware;
  - 43/100 runs connect, compared with 40/98 malware.

**Limitations**
1. **Only 10 independent groups.** The 10 profiles of one tool are not independent samples. Exact duplicate host vectors include tail (8 identical), tar (5) and curl (4).
2. **All 100 runs are dynamically linked glibc programs from the distribution.** 74/98 malware appear static by the libc proxy. Linkage is therefore nearly a label proxy (Section 7, L1). *(Superseded by Addendum A: by header, 87/98 malware are static or static-PIE, and 46/98 run under qemu-user.)*
3. **A different snapshot, collection time and watch-path count** from the malware, so acquisition metadata gives BA 1.0.
4. **Narrow workloads:** coreutils-style utilities and network clients. There are no daemons, no process-spawning servers, no non-glibc runtimes and no i386 binaries.
5. **Hard negatives exist.** Under `GroupKFold(10)`, every ping run (10/10) and every tail run (10/10) is misclassified as malware. This suggests long-lived or periodic benign programs look "malicious" to the model.

**Verdict:** this is a useful *falsification* control. It is not adequate as the benign class for a performance claim.

---

## 7. Diagnostic Experiments

### How to run

- Working directory: DERIVED.
- Python: `/usr/bin/python3`.
- Validation: `StratifiedGroupKFold(5, shuffle=True, random_state=42)`, unless noted.
- Grouping unit:
  - malware: MalwareBazaar signature (`malware::malware_signature::<sig>`);
  - benign: tool family (`benign_script::<pkg>` or `benign_elf::<tool>`).
- Every split passed `check_splits`: no group in both train and test, and both classes in train.
- Confidence intervals: 95% class-stratified group cluster bootstrap with 1,000 resamples.
- Labels: **all analyses are exploratory and post hoc**.

### Inputs

- Frozen scale100 runs under `scale-100x100-v14-20261020T072500Z/runs/`.
- Frozen ELF runs under `benign-elf-100-v14-20261020T140000Z/runs/benign-elf/`.
- Frozen OOF and aligned datasets under `.../modeling/p4_29x29/`.
- Feature contract `data/benign/revision3/labeled_sample_dataset.feature_columns.json`.

### Commands and outputs

| Command | Outputs |
| --- | --- |
| `audit_runs.py` | `run_audit.csv`, `run_audit_summary.json` |
| `diagnostics.py` (3 min 52 s) | `features_derived.csv`, `diagnostics_results.json`, `diagnostics_stdout.txt` |
| `linkage_stratified.py` | `linkage.csv`, `linkage_results.json` |
| `exclusions_and_duplicates.py` | `exclusions_duplicates_results.json` |

Note: after `diagnostics.py` had run, its `matrix()` function was changed to map empty strings to NaN. This only removes a crash path for blank cells; the stored results contain no blank cells and are unaffected.

### Results

| ID | Question | Samples (mal/ben) | Groups (mal/ben) | Result (BA unless stated) |
| --- | --- | --- | --- | --- |
| R0 | Do the saved OOF predictions reproduce? | 92/91 | 28/18 | host 1.0 [1, 1]; hybrid 1.0; P4 0.694 [0.613, 0.770] |
| S183 | Independent refit on the original cohort | 92/91 | 28/18 | See S183 detail below |
| A | Benign script vs benign ELF, host features only | 100 ELF / 100 script | 10/18 | host_all 0.975 [0.925, 1.0], AUC 1.0. 7/10 top families shared with the malware model |
| B-aligned | Benign ELF vs malware, P4-aligned | 92/89 | 28/10 | See B-aligned detail below |
| B-all | Benign ELF vs malware, all accepted | 98/100 | 29/10 | host_all 0.880 [0.728, 0.990], AUC 0.976, TN78 FP22 FN2 TP96; post-exec same; nuisance 0.760 |
| C | Post-hoc ablations | as S183 / B | — | See ablation table below |
| D | Duration and workload predictors | as above | — | The 20 s capture is constant for every run, so it carries no information. Actual runtime is informative: in S183, nuisance stumps named_events 0.848 and distinct_pids 0.832; in B, active_windows-only 0.749 |
| E | Family-disjoint feasibility; `GroupKFold(10)` on B-all | 98/100 | 29/10 | 10 benign groups; 9 malware singletons; largest group 10. host_all 0.880, AUC 0.975, TN80 FP20 FN4 TP94. All ping and tail runs are false positives; INC, LockBit, one Akira and one Katana are missed |
| Stab | Fold-seed stability on B-aligned, seeds 100–104 | 92/89 | 28/10 | host mean 0.951 (0.866–0.984); P4 0.786; nuisance 0.797 |
| L1 | Linkage proxy (libc opened after the 2nd exec), as a fixed rule: no libc → malware | 92/91 (S183); 98/100 (B-all) | — | Benign 200/200 dynamic; malware 24/98 dynamic. S183 0.886 [0.799, 0.946], TN91 FP0 FN21 TP71. B-all 0.878 [0.799, 0.936] |
| L2 | Dynamic-only: benign ELF vs dynamic malware | 24/100 | 13/10 | host_all 0.867 [0.74, 0.955] (TN90 FP10 FN4 TP20); post-exec same; nuisance 0.811 [0.69, 0.909]. P4-aligned subset (21/89): P4 0.581 [0.49, 0.71]; host 0.923 [0.85, 0.99] |
| X1 | Do exclusions depend on class? | — | — | Quality rejects: malware 2, script 0, ELF 0. P4 misalignment: malware 6, script 9, ELF 11. Host B-all vs B-aligned changes 0.880 → 0.956 |
| X2 | Exact duplicate host vectors | S183 / A / B-all | — | 13 / 23 / 16 duplicate clusters. None spans labels or folds. One post-exec cluster spans groups: the two zero-activity malware (CoinMiner, NoEscape), whose post-exec vectors are both all-zero |
| F1 | Do launcher-only samples get malware scores? | 2 malware | — | Saved OOF: host and hybrid 1.0 for both; P4 0.835 and 0.492 |

**S183 detail**
- host_all 1.0, host_mi29 1.0, post-exec host_all 1.0.
- nuisance-only 0.907 [0.825, 0.970].
- acquisition-only 0.995.
- dup2 stump 0.957.

**B-aligned detail**
- P4 0.785 [0.711, 0.860].
- host_all 0.956 [0.896, 0.995], AUC 0.977, TN84 FP5 FN3 TP89.
- host_mi29 0.899; hybrid 0.939; post-exec 0.956.
- nuisance 0.721; acquisition-only 1.0; dup2 stump 0.515.
- Group permutation (50 permutations): mean 0.486, max 0.683, p = 0.0196 (the minimum possible).

**Experiment C: post-hoc ablations (BA, "without group" / "only group")**

| Group | S183 without | S183 only | B-aligned without | B-aligned only |
| --- | --- | --- | --- | --- |
| dup | 0.956 | 0.946 | 0.905 | 0.581 |
| process_lifecycle | 0.967 | 0.913 | 0.783 | 0.757 |
| exec_loader | 1.0 | 0.924 | 0.855 | 0.811 |
| activity_total | 1.0 | 0.934 | 0.899 | 0.633 |
| network | 1.0 | 0.581 | 0.944 | 0.632 |
| file_write | 0.989 | 0.688 | 0.956 | 0.611 |

**Top host families**

| Comparison | Top families |
| --- | --- |
| Original model | dup2, execve, openat, unique_threads, openat_success, event, fork, close, mmap, mprotect |
| A (script vs ELF) | Shares dup2, execve, fork, mmap, mprotect, openat, unique_threads |
| B (ELF vs malware) | fork, openat_success, openat, unique_threads, close, mmap, event, exit, file_write_bytes, mprotect |

The B list is dominated by loader and lifecycle syscalls, consistent with the linkage result L1.

**Caveats on the linkage proxy (L1/L2).** The proxy is "a named openat of a path containing `libc.so` after exec". It is not an ELF-header parse:
- a dynamic binary that crashes before the loader opens libc counts as static;
- musl or uClibc dynamic binaries are misclassified if they do not open a `libc.so` path.

A static header check of the artifacts (without executing them) is still needed to confirm linkage.

---

## 8. Evaluation Redesign

**Goal:** to make "the model detects malicious behavior" a testable claim, design out the confounds shown above rather than ablating them after the fact.

### 8.1 Acquisition

1. **One snapshot for both classes**, with the same runner hash and the same watch paths. Benign and malware must not have separate cohort lineages.
2. **Randomized, interleaved collection order.** Use blocked randomization so each block contains both classes. Record the order and include acquisition-only models as negative controls.
3. **Use the same launch path for every sample.** Keep the identical wrapper, and record exec success with a `sched_process_exec` probe or the execve return value. Do not infer it.
4. **Activation criteria, defined before collection.** Example criteria:
   - target exec observed;
   - at least N post-exec target syscalls;
   - not terminated by a crash within X ms.

   Report results both for all samples and for activated samples. Do not silently drop samples; report the inert fraction for each family.

### 8.2 Benign workloads (Experiment F)

**Match** these factors between classes:
- file format (ELF);
- architecture (x86-64 and i386);
- **linkage** (static glibc, static musl, dynamic glibc, Go, Rust);
- launch path;
- privileges;
- network reachability (the same Sink);
- the observation window.

Required benign static programs, for example: busybox-static, statically built Go programs (e.g., backup/sync clients, small web servers), Rust/musl builds, static i386 builds.

**Stratify** all metrics by:
- linkage;
- architecture;
- runtime class: short (< 1 s), long (> 5 s), daemonizing;
- activation outcome;
- network presence.

Each benign workload class should be represented by several *independent upstream projects*, not by argument profiles of one tool:

| Workload class | Benign examples |
| --- | --- |
| File I/O | compressors, archivers, backup/sync tools |
| CPU | hashing, compression, encoding |
| Process spawning | make/build drivers, shell-free supervisors |
| TCP | clients and servers |
| DNS | resolver clients |
| TLS | TLS clients against the internal Sink |
| Long-running and periodic | ping-, tail- and monitor-style tools; daemons that `setsid` |
| Short-running | utilities |

**Do not control away** behavior that defines maliciousness:
- C2 connection attempts;
- scanning;
- flooding;
- persistence writes;
- mass rename or encryption;
- killing other processes;
- ptrace or injection;
- privilege changes.

Benign workloads should exercise the same *mechanical primitives* (connect, write bursts, spawn, rename). The question is whether the model separates *patterns* rather than *presence* of a primitive. Do not equalize the malicious-pattern features themselves.

### 8.3 Validation

- **Grouping.** Group malware by family and benign by upstream project. Signatures are imperfect families, so add similarity-based clustering of artifacts where available.
- **Splits.** Use nested family-disjoint CV, so that feature selection and hyperparameters are tuned inside the training folds. Also use a **time-disjoint** external test: malware first seen later, and benign releases later.
- **Size.** Use at least about 30 independent groups per class and stratum, as an illustrative target. With 10 benign groups, CIs span about 0.25 BA.
- **Statistics.**
  - Group cluster bootstrap CIs.
  - Group-level permutation tests with at least 1,000 permutations.
  - Mandatory baselines run on the same folds: nuisance-only, acquisition-only, a linkage stump and a dup2 stump.
- **Reporting.** Report per-stratum metrics and the inert/crash fraction. Do not tie host-model exclusions to P4 alignment; report the P4-aligned subset as a sensitivity analysis.

---

## 9. Falsification Criteria (to state before the redesigned evaluation)

The interpretation "the host model detects malicious behavior" is **rejected** if any of the following holds.

1. **F-acq:** Acquisition-only or nuisance-only models have a BA confidence interval whose upper bound is ≥ 0.60, or that overlaps the host model's CI. The design is still confounded; fix it before interpreting results.
2. **F-strat:** Within any one linkage × architecture × runtime stratum, the lower bound of the host BA CI is ≤ the upper bound of the nuisance-only BA CI.
3. **F-transfer:** A model trained only on *benign static vs benign dynamic* (or *script vs ELF*) ranks malware-vs-benign with AUC ≥ 0.75 on the main test set. The main signal would then be an artifact property.
4. **F-inert:** Activation-failed or launcher-only samples receive malware probabilities comparable to activated malware. **This is already observed** (F1: probability 1.0).
5. **F-ext:** On the family- and time-disjoint external test, BA drops by more than the bootstrap CI width, or falls to the nuisance baseline.
6. **F-attrib:** The top features are loader or launch families, and removing them brings performance down to nuisance level. Evidence for behavior requires that the dominant features map to event-level behavior primitives that can be verified in the raw traces.

**Current status:** F-acq, F-strat (in the dynamic-only stratum the CIs overlap), F-inert and the A-transfer condition (A gives 0.975 with shared features) are all triggered on existing data. A behavioral interpretation is not supported.

> **Correction (Addendum B).** The "A-transfer" statement above was inferred from shared features, not measured as F-transfer defines it. It has now been measured: a model trained with **no malware** (benign script vs benign ELF) ranks malware above held-out benign scripts with AUC 0.987, so F-transfer is triggered. F-strat is also triggered in the native-only stratum (Addendum A, H3).

---

## 10. Prioritized Action Plan

1. **Stop citing BA 1.0 (host/hybrid) and P4 0.69 as detector performance.** Report them as a confound demonstration, citing this report and DERIVED.
2. **Static linkage check, with no execution.** Parse the ELF headers of the 98 accepted malware artifacts (PT_INTERP, DT_NEEDED, e_machine) to replace the libc proxy. Read-only. **Done — see Addendum A.** It added a new requirement: stratify or match by **execution mode** (native vs qemu-user), not only by linkage.
3. **Add exec-success instrumentation** in a *new* runner schema (not `.14`): a `sched_process_exec` probe and the exec return code. Validate it on benign samples before any malware collection.
4. **Benign pilot.** Collect a static and dynamic benign pilot matched by architecture and linkage, with several independent projects per workload class (Section 8.2). Use one snapshot, the same watch paths, interleaved order, and authorized benign execution only.
5. **Preregister** the activation criteria, strata, baselines and falsification criteria (Section 9) before any new malware collection, which requires separate authorization.
6. **Re-evaluate** with nested family-disjoint and time-disjoint validation and ≥ 1,000 group permutations. Report per-stratum results and inert fractions.
7. **Fix the exclusion coupling.** Remove P4-alignment exclusions from host-only analyses, or report both versions.
8. **Collection, if ever resumed.** Do not resume the paused 500-sample collection. Any new collection uses a fresh run root under the latest runner, as `AGENTS.md` requires.

---

## Validation of this audit

- `cd DERIVED && /usr/bin/python3 -m unittest test_audit_derived -v` passes **17/17**. The tests use synthetic fixtures only and cover:
  - failed exec and zero post-exec activity;
  - launcher comm persisting after exec;
  - the exec boundary not verifying success;
  - missing root rows;
  - PID reuse;
  - the linkage proxy boundary;
  - group-leakage and single-class guards;
  - MI selection seeing training rows only;
  - group-constant label permutation;
  - the bootstrap;
  - duplicate clustering, including NaN.
- The existing `tests.test_exec_boundary` still passes.

**SHA-256 of derived scripts**

| File | SHA-256 |
| --- | --- |
| `audit_runs.py` | `156b9db1…5bd69` |
| `diagnostics.py` | `70aad6a6…ed2c8` |
| `linkage_stratified.py` | `6f7a194f…8070e` |
| `exclusions_and_duplicates.py` | `b1e93e7b…c4404` |
| `test_audit_derived.py` | `09c63a2f…ba7` |

**SHA-256 of derived results**

| File | SHA-256 |
| --- | --- |
| `diagnostics_results.json` | `b2c873bd…e5b82ea04` |
| `linkage_results.json` | `e648c3ee…3c5d0d` |
| `exclusions_duplicates_results.json` | `862735cc…6f04` |
| `run_audit_summary.json` | `48325bd4…2280e6` |

**Limits**
- The sample sizes are small: 10 independent benign ELF groups and 24 dynamic malware samples.
- Linkage is a runtime proxy, not a header parse.
- Ablations are post hoc.
- Permutation p-values are bounded by 50 permutations.
- MalwareBazaar signatures are imperfect families.
- No causal claim beyond the confound demonstrations is made.

---

## Addendum A: Static ELF-Header Check, 2026-10-20

Status: derived, exploratory, post hoc. **No sample was executed.** Each host copy of the 100 scale100 malware archives (`data/malware/full-cohort-323/samples/`) was streamed with `7z x -so` into memory and only its ELF headers were parsed. No ELF bytes were written to disk or made executable. A post-run `find` found no new extracted file outside DERIVED.

Code: `DERIVED/elf_header_linkage.py`; tests: `DERIVED/test_elf_header_linkage.py` (6/6, synthetic ELF fixtures: dynamic with DT_NEEDED, static, static-PIE, big-endian 32-bit MIPS, UPX/Go markers, malformed input). Outputs: `elf_header_linkage.csv`, `elf_header_linkage_results.json`.

### A.1 Identity checks (100/100 each)

- Every archive has exactly one member, and it is the member the guest chose (`chosen.txt`).
- Host archive size equals the guest `extract.log` size; member size equals the guest extracted size.
- `e_machine` and ELF class equal the guest-recorded values.
- Member SHA-256 equals the sample name, so the host copy is the executed artifact. Parse errors: 0.

### A.2 What the 98 accepted malware artifacts are

| Execution × header linkage | Count |
| --- | ---: |
| native x86 (x86-64 41, i386 11) · static | 41 |
| native · static-PIE | 2 |
| native · dynamic (`/lib64/ld-linux-x86-64.so.2`) | 9 |
| qemu-user (ARM 34, MIPS 5, SPARC 2, AArch64 2, SH 1, m68k 1, PPC 1) · static | 41 |
| qemu-user · static-PIE | 3 |
| qemu-user · dynamic (Android `/system/bin/linker`; `/lib/ld-linux-aarch64.so.1`) | 2 |

Markers: UPX 12 (8 emulated), Go build-info 13.

**Emulation is a new confound.** `scripts/vbox_malware_batch.sh` (`sample_architecture_supported`, ~L785) runs non-x86 samples through guest qemu-user handlers. The traced process is then the **emulator**: its x86-64 syscalls, memory mapping and signal handling are what eBPF records. Independent confirmation from frozen events: an `openat` of `/proc/sys/vm/mmap_min_addr` after the root's second exec (a qemu-user start-up read) occurs in **46/46** emulated and **0/52** native accepted malware, and in **0/200** benign runs. One example failure reason reads `qemu: uncaught target signal 11`. Both dynamic emulated samples ended with rc 255, consistent with the guest lacking their target loader (not verified in the guest). The qemu binary's own linkage was not inspected; 41/46 emulated runs never opened libc, which is consistent with a statically linked handler.

**The libc proxy (L1/L2) measured lineage, not linkage.** Header vs proxy disagree for 19/98:
- 16 header-static samples were proxy-dynamic because **child processes** loaded libc: `sh`, `crontab`, `update-rc.d`, `iptables`, `systemctl`, `insmod`, `pgrep`, `sed`, `chmod`, … (BillGates, ChinaZ, DDoSTF ×3, DeskRAT ×3, FlylegitBot, Prometei ×2, XorDDoS ×2, Akira ×3). Several of these are persistence or system-modification commands, i.e. plausibly behavioral, so the L2 "dynamic-only" stratum mixed linkage with spawning behavior.
- 3 header-dynamic samples were proxy-static: CoinMiner `9e5b93d3…` (x86-64, PT_INTERP but no resolvable DT_NEEDED, rc −11 with zero post-exec target syscalls), and the two emulated dynamic samples (rc 255).

### A.3 Fixed rules and header-defined strata (grouped OOF, same helpers as Section 7)

| ID | Comparison | Samples (M/B) | Groups (M/B) | Result: BA [95% group CI], TN FP FN TP |
| --- | --- | --- | --- | --- |
| H1 | Rule "emulated → malware" | 92/91 (S183); 98/100 (B-all) | — | 0.750 [0.66, 0.83] 91 0 46 46; 0.735 [0.65, 0.82] 100 0 52 46 |
| H2 | Rule "emulated **or** header-static → malware" | 92/91; 98/100 | — | **0.957** [0.91, 0.99] 91 0 8 84; **0.954** [0.91, 0.98] 100 0 9 89 |
| H3 | Native malware vs benign ELF | 52/100 | 22/10 | host_all 0.921 [0.80, 0.99]; post-exec 0.921; nuisance 0.838 [0.72, 0.94] |
| H4 | Native **header-dynamic** malware vs benign ELF | 9/100 | 7/10 | host_all 0.456 [0.29, 0.66] (AUC 0.56); post-exec 0.466; nuisance 0.712 [0.55, 0.89] (AUC 0.92) |

Benign artifacts are not on the host, so benign linkage remains the run-time proxy (all native and loading glibc; the benign ELF tools are distribution binaries). H2 needs no training and exceeds the learned host model on B-all (0.880). H4 is the only stratum matched on file format, architecture, execution mode and linkage; there the host model is at chance and below the nuisance model. With 9 malware in 7 signatures this is very low-powered and must not be read as a performance estimate, but it gives **no** evidence of behavior-specific signal once the artifact confounds are matched.

### A.4 Consequences

- The confound is broader than "script vs ELF" and "static vs dynamic": it is **benign native distribution binaries vs malware that is mostly static and half emulated**. F-strat (Section 9) is triggered in the H4 stratum.
- Section 8.2 must add **execution mode** to the matching factors. Either restrict the main evaluation to native x86 artifacts, or run matched benign non-x86 static binaries (e.g. busybox-static builds for ARM/MIPS) under the same qemu-user handlers. Report emulated samples as a separate stratum.
- The spawned-child observation (A.2) is a candidate *behavioral* primitive (process spawning of persistence/system tools). It should be tested with benign workloads that also spawn system utilities, as Section 8.2 already requires.

**SHA-256:** `elf_header_linkage.py` `a2633026…dcdd24`; `test_elf_header_linkage.py` `d80bb23b…4810a4`; `elf_header_linkage.csv` `2d0b46a6…f80adee4`; `elf_header_linkage_results.json` `0f417e57…59af0ff`.

**Limits:** header parsing does not establish run-time loader behavior; UPX/Go detection is a byte-marker heuristic; the guest qemu handler binary and the benign binaries were not header-inspected; H3/H4 reuse the Section 7 feature set and are post hoc.

---

## Addendum B: Self-Check of Unmeasured Claims, 2026-10-20

Status: derived, exploratory, post hoc; no execution. Code `DERIVED/self_check.py`; output `self_check_results.json`.

**B.1 F-transfer, measured as defined in Section 9.** Train an RF (300 trees, same settings as Section 7) on benign script (0) vs benign ELF (1) only. Benign script groups are cross-fitted with `GroupKFold(5)`, so each script is scored by a model that never saw its tool family; malware is never in training and receives the mean over the five models.

| Features | Malware vs held-out scripts AUC (all 98 / native 52 / emulated 46) |
| --- | --- |
| host_all | **0.987** / 0.979 / 0.995 |
| post-exec host | **0.987** / 0.980 / 0.996 |

Threshold 0.75: **triggered**. A detector that has never seen malware reproduces the original malware-vs-script ranking almost perfectly. This is the most direct evidence that the original S183 separation is the script-vs-ELF artifact. Caveat: the script side uses all 100 accepted scripts, not only the 91 in S183.

**B.2 F-strat in the native stratum.** H3 host CI [0.80, 0.99] overlaps nuisance-only [0.72, 0.94]: triggered.

**B.3 Does emulation drive the top families?** Post-exec median sums by class (benign script / benign ELF / native malware / emulated malware): events 226.5 / 155 / 45 / 42; openat 84 / 24 / 2.5 / 2; openat_success 24 / 13 / 1.5 / 2; mmap 59 / 29 / 24 / 17.5; mprotect 17 / 8 / 6 / 7. Native and emulated malware look alike on these features; both are much less active than benign workloads. So emulation is a provenance confound (the trace is the emulator's) but is not, by itself, what separates the classes. The dominant separator in B is low post-exec activity, consistent with short-lived, crashing or inert malware (Section 7 D; 55/98 not exit 0).

**SHA-256:** `self_check.py` `5d2ce0bb…dc440e762b5`; `self_check_results.json` `b310970706…207bfdac5`.
