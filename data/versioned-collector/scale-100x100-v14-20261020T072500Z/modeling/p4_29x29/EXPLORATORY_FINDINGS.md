# P4 29x29 Exploratory Grouped Model

**Investigation verdict, 2026-10-20:** the perfect host/hybrid result is reproducible but unsuitable as a detector-performance claim. Event attribution and controlled ablations show strong launch/workload shortcuts. See the investigation below; increasing the sample count under the same collection design will not remove those shortcuts.

## Scope and data

This is the corrected analysis for the requested feature scope. Network inputs are the 29 base signal families defined in `p4_ebpf/analyze_p4_pcap_ablation.py`, each represented by mean, maximum, sum, standard deviation, and active-window count (145 columns). Host candidates come only from `data/benign/revision3/labeled_sample_dataset.feature_columns.json`: 35 signal families with the same five summaries. In each training fold, exactly 29 whole host families are selected, producing 145 host columns. The hybrid combines those with the 145 P4 columns for exactly 290 model inputs. Metadata is used only for grouping, labels, and audit, never as a predictor.

The analysis reads existing collection outputs only. Of 200 samples, the two quality-rejected CatStorm captures are excluded: `00e7101582c9f2c894199a7e638fb04d48e6fa81c791d71a120cdd079dd1293c.zip` (1,522 reported kernel PCAP drops) and `e19c541a774d34a4d562edd7117cf0bfc7faca90e0a7386dbdd67909efc764f4.zip` (27 drops). Fifteen additional quality-accepted samples are excluded because PCAP-to-telemetry window alignment is not unique (six malware and nine benign). The final set contains 92 malware and 91 benign samples.

P4 features are reconstructed offline using captured-Ethernet bytes and nominal 0.5-second rates, matching this collector's stored feature semantics. Across the 183 included captures, all 26,535 extracted-versus-stored P4 summary comparisons match exactly. This establishes reconstruction parity for the included data; it is not live P4 evidence.

## Validation protocol

Validation uses five-fold `StratifiedGroupKFold` with seed 42. Malware source-signature groups and benign tool-family groups remain intact between training and validation, with both classes represented in every fold. For each fold, median imputation and host-family selection are fit from training data only. Host families are ranked by their mean mutual information across the five summaries. The classifier is a 500-tree Random Forest (`max_features="sqrt"`, `min_samples_leaf=2`, balanced-subsample class weights); all 183 samples receive an out-of-fold prediction for each feature set.

## Out-of-fold results

| Feature set | Features | Balanced accuracy | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P4 network | 145 | 0.694 | 0.836 | 65 | 26 | 30 | 62 |
| Selected host (29 families) | 145 | 1.000 | 1.000 | 91 | 0 | 0 | 92 |
| 29+29 hybrid | 290 | 1.000 | 1.000 | 91 | 0 | 0 | 92 |

The hybrid made the same thresholded OOF calls and achieved the same ROC-AUC as host-only. These results show no observed benefit from adding the P4 features to the selected host set on this cohort. Network-only performance was lower and produced errors in both classes.

Fold-averaged split importance was led in host-only by `host__ebpf_dup2_count__max`, `host__ebpf_dup2_count__std`, and `host__ebpf_dup2_count__mean`. The hybrid was likewise dominated by host `dup2` and `execve` summaries. P4 network importance was led by `network__p4_net_flow_duration_max__max`. These are descriptive model importances, not causal explanations or independent evidence of malicious behavior.

## Limitations

This is exploratory cohort discrimination, not a general malware-detection estimate. Artifact type is perfectly aligned with class in the source cohort: benign examples are shebang scripts and malware examples are ELF files. Although artifact metadata is excluded from model inputs and family groups do not cross folds, launch mechanics, workload, activity, duration, and acquisition labels can remain encoded in telemetry. The sample selection is purposive, and malware source signatures are not guaranteed to represent distinct behavioral families. The P4 values are offline PCAP reconstructions, not live-switch measurements. Do not interpret the perfect host/hybrid score as evidence of generalization; a matched benign ELF cohort and an external family-disjoint evaluation are still needed.

## Investigation of the perfect host score

The reproducible investigation is [investigate_perfect_scores.py](investigate_perfect_scores.py); its machine-readable evidence is [perfect_score_investigation.json](perfect_score_investigation.json). It reads existing outputs, leaves the original model results intact, and reruns training only for diagnostic controls. The original host probabilities reproduce to a maximum absolute error of 1.11e-16.

### Confirmed experimental shortcuts

- All 91 benign inputs are shebang scripts; all 92 malware inputs are ELF files. Artifact metadata is not a predictor, but this distinction remains observable through process/syscall activity. Family-disjoint folds cannot remove a class-wide distinction present in every family.
- Every included sample has exactly three root-PID `python3` `dup2` events before the executable launch. The runner's `Popen` redirects stdin/stdout/stderr, and representative archived raw sequences place these calls before the first `execve`. Both classes then pass through the common Bash wrapper. Benign scripts add shell redirections and tool subprocesses; the common wrapper does not make these workloads equivalent.
- Peak `dup2` is at least 4 in every benign sample, versus exactly 3 in 84/92 malware samples. A training-fold-fitted one-feature tree learns the same 3.5 threshold in all five folds and obtains TN91/FP0/FN8/TP84, or 95.65% balanced accuracy. This is a diagnostic shortcut search, not an independently selected detector benchmark.
- All 91 benign root processes exit within 7.155-181.565 ms of launch. All their candidate-host activity is in window 0; the other 39 windows are zero. Malware activity varies: 57/92 likewise have only one active window, while others have later activity. Equal 20-second observation does not mean equal workload duration or activity.

### Controlled tests

All values below are pooled OOF balanced accuracy, not ordinary accuracy. Except for the explicitly marked inclusion sensitivity, tests retain the original saved group-disjoint fold assignments. Random Forest controls use the original 500-tree settings and seed; MI family selection is rerun on training data only where applicable. Ablations deliberately change the diagnostic feature budget and are not replacements for the production 29+29 protocol.

| Diagnostic | Balanced accuracy | What it establishes |
| --- | ---: | --- |
| Original host-29 reproduction | 100.00% | Saved result is reproducible |
| Single peak-dup2 tree | 95.65% | One launch-sensitive count almost separates classes |
| First 0.5-second window only | 98.91% | Almost all separation is already available at startup |
| 13 process/startup families only, 65 columns | 100.00% | No other host families are needed to reproduce perfect separation |
| Remove dup2 family; reselect host-29 | 97.81% | Deleting just one shortcut is insufficient |
| Remove all 13 process/startup families, 110 remaining columns | 72.15% | These families explain much of the original separation |
| Use only mean/max summaries | 98.90% | Dropping sums/active-window summaries alone does not solve it |
| Convert host columns to presence/absence | 75.45% | Numeric intensity is more informative than mere occurrence |
| Exclude window 0 | 68.48% | Benign becomes entirely zero; residual activity shortcut remains |
| Exclude first two seconds | 63.04% | No repaired-performance claim: all benign and 68 malware are zero |
| Exit-0 subset only: 86 benign, 39 malware | 100.00% | Crashes/nonzero exits alone do not explain the score |
| All 198 quality-accepted samples, host-only, fresh grouped folds | 99.00% | P4 alignment exclusions are not the main cause |
| 20 shuffled-label controls | 49.93% mean | Pipeline does not recover shuffled labels above chance on average |

The removed 13 families are `dup2`, `dup3`, `execve`, `execveat`, `openat`, `openat_success`, `close`, `mmap`, `mprotect`, `fork`, `exit`, `event_count`, and `unique_threads`. These are startup-sensitive, not exclusively startup events. Removing them also removes legitimate behavior, so 72.15% is not an unbiased estimate of malware-detection ability. Window deletion likewise removes real activity and is diagnostic only.

Shuffled-label tests use 100 trees for each of 20 seeds (1000-1019); labels are shuffled at sample level, folds remain fixed, and both MI selection and training use shuffled training labels. Balanced accuracy ranges from 43.16% to 56.25%, averaging 49.93%. These are negative controls, not a group-level permutation significance test, and cannot prove the absence of every possible leakage channel.

### Data and implementation checks

- The explicit host allowlist contains only 175 `host__ebpf_*` candidate columns; each original fold selects 145 columns from exactly 29 whole families. Labels, names, return codes, group IDs, and artifact metadata are not model columns. The original 29+29 outputs were not replaced by these diagnostics.
- There is no source-group overlap between training and validation. Host vectors have 162 unique values among 183 samples; all 13 duplicate-vector groups remain within one fold. Network vectors are all unique. Exact duplicate host-vector leakage across folds is therefore not the explanation; binary-level relatedness and grouping quality remain unverified.
- Independently recomputed all 32,025 candidate host summary cells from telemetry, with no mismatch. Archived named-event counts plus recorded raw-syscall fallback deficits also reconcile to telemetry for all syscall-count families checked. This is host-side verification, separate from the earlier P4 parity check.
- Named events all lie within the recorded observation and the ancestry reconstructed from the sample root and archived forks. The BPF probe initially admits all runner children, but the current Python aggregator applies a sample-lineage/time filter. Older notes about unfiltered aggregation do not establish a current defect. The 743 accepted events named `sudo` occur in one malware descendant, PID 4593 forked from root PID 4586 of sample `035a6840a15e6dcea0403627bb22f749e3aba785da74c839400d5209cccd5292.zip`; a process name alone is not collector-helper contamination.

These checks support a launch/workload confound rather than direct label-column leakage or broken score calculation. They do not isolate a causal effect of artifact type independently of workload: class and artifact type have no overlap in these data. Raw launch spot checks cover two samples per class; all-sample named-event and telemetry checks cannot certify events that were never recorded, successful attack activation, or full kernel-level attribution.

### Required design changes before a performance claim

Use diverse benign ELF applications, including network clients/services and file-processing workloads, not only short scripted controls. Match launch method, arguments, activity, observation settings, snapshot configuration, and sensor versions across classes. Balance/interleave collection order, retain strict capture quality gates, and verify what actually executed. A matched small pilot and a family-disjoint external evaluation should precede scaling. Any future payload-only features need a defined exec boundary and a separate versioned derivation; do not silently alter frozen captures or remove selected features until a desired score appears. No new collection, runner repair, or VM operation was performed for this investigation.

## Reproduction and artifacts

From the study repository root:

```bash
/usr/bin/python3 data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/run_scale100_p4_29x29.py
/usr/bin/python3 data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/investigate_perfect_scores.py
```

The script SHA-256 is `fc70e671c55b9812b0aa855494df17b695d68500af30b95f2ee512612566ae32`. It writes `metrics.json`, `feature_columns.json`, `aligned_p4_host_candidate_dataset.csv`, `p4_alignment_audit.csv`, `host_family_selection_by_fold.csv`, `oof_predictions.csv`, and `fold_feature_importance.csv` alongside itself. The full-feature exploratory artifacts remain in the parent `modeling/` directory and are explicitly superseded for this requested protocol.