# Independent Classifier Audit

**Audit date:** 2026-10-20  
**Scope:** Frozen scale-100x100 schema-.14 cohort and its P4 29x29 evaluation; read-only status review of the separate benign-ELF collection.  
**Disposition:** The saved OOF scores are reproducible, but the experiment does not support a claim that the model detects malicious behavior or generalizes to malware in deployment. No source, model, capture, snapshot, or collection output was changed by this audit.

## Executive Assessment

The host-only and hybrid models obtain perfect pooled out-of-fold balanced accuracy and ROC-AUC on the 183-sample analysis set. The result is not explained by an observed train/validation group overlap, direct label/name predictors, or exact duplicate feature vectors crossing folds. The evaluation implementation fits imputation and host-family selection on each training fold, and the saved probabilities reproduce.

The central validity problem is instead a class-wide acquisition/workload confound: all benign examples in the analyzed cohort are shebang scripts, while all malware examples are ELF artifacts. The host-only model relies heavily on process/syscall activity that exposes that difference. A one-feature peak-`dup2` tree reaches 95.65% balanced accuracy; several startup/process families alone reproduce 100%. Boundary diagnostics show that removing launcher-only activity does not remove the signal: the target workloads themselves remain different. The labels represent source/acquisition classification, not independently verified malicious behavior during these runs.

The P4-only result is materially weaker (BA 0.694, AUC 0.836). Its inputs are offline PCAP reconstructions, not live P4 measurements. The hybrid adds no observed benefit over host-only on this cohort. Accordingly, the strongest supported interpretation is **cohort discrimination under a confounded collection design**, not behavioral malware detection.

## Verified Findings

### Score and evaluation pipeline

- Recomputed analysis: 183 samples (91 benign, 92 malware), five `StratifiedGroupKFold` splits, seed 42. Pooled OOF confusion counts are P4 `TN65/FP26/FN30/TP62`, host `TN91/FP0/FN0/TP92`, and hybrid `TN91/FP0/FN0/TP92`.
- The modeling script keeps source-signature groups for malware and tool-family groups for benign samples within folds. No group overlap is reported. Median imputation and mutual-information host-family selection are fitted on each training fold. The 29 P4 families and selected 29 host families each contribute five summaries; the hybrid has 290 columns.
- The saved host probabilities reproduce to maximum absolute error `1.11e-16`. The investigation independently recomputed 32,025 host summary cells and found no mismatch. Exact duplicate host vectors exist, but all duplicate groups are confined to a single fold; the network vectors are unique in this set. These checks reduce evidence for ordinary pipeline or exact-vector leakage; they do not establish lineage independence or rule out near-duplicates.
- Results are pooled sample-level OOF metrics from one fixed five-fold assignment, not an external temporal test or an uncertainty interval. A group-disjoint split is useful, but MalwareBazaar source signatures are not guaranteed to represent distinct behavioral families. Pooled sample-level metrics also give more weight to larger groups than a family-macro estimand would.

Evidence: [`metrics.json`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/metrics.json), [`run_scale100_p4_29x29.py`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/run_scale100_p4_29x29.py), [`perfect_score_investigation.json`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/perfect_score_investigation.json).

### What the host model is exploiting

- In the 183 evaluated samples, benign artifacts are all `script_shebang`; malware artifacts are all `elf`. Artifact metadata is not a predictor, but artifact format and launch/workload behavior are represented in the host telemetry. There is no within-class/artifact overlap in this cohort to separate those effects statistically.
- Every included sample has three root-PID `python3` `dup2` events in pre-target-launch setup. The peak-`dup2` stump uses the same 3.5 threshold in every fold and reaches BA 0.9565. The 13 process/startup-sensitive families alone reach BA 1.0. First-window host features reach BA 0.9891.
- Every benign root process exits within about 7.2–181.6 ms, with observed host activity in the first window. A fixed 20-second observation therefore does not equalize actual workload duration or activity.
- A separate derived post-exec analysis removes pre-target root events and still reports BA 1.0 for host and hybrid. The removed launcher-only component alone is not predictive (BA 0.447); the target script-versus-ELF workload distinction remains. This rejects the narrow hypothesis that only the common launcher explains the perfect score, but does not remove the broader workload confound.
- These are diagnostic ablations, not a corrected performance estimate. Deleting selected features or windows after inspecting labels cannot establish a valid detector.

Evidence: [`EXPLORATORY_FINDINGS.md`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/EXPLORATORY_FINDINGS.md), [`investigate_perfect_scores.py`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/investigate_perfect_scores.py), [`post_exec_results.json`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/post_exec/post_exec_results.json).

### Execution-boundary caveat

The derived boundary code chooses the second root-PID raw syscall-entry whose ID is `execve` or `execveat`. The current runner records generic `tracepoint:raw_syscalls:sys_enter` IDs and named `sys_enter_execve` events; the inspected probe does not record a successful-exec scheduler event or an exec syscall return value. Thus the second entry is a plausible wrapper/target boundary for the expected launch sequence, but the archived evidence does not prove that the call succeeded or that it was the intended target image.

The synthetic tests cover the expected sequence, descendants, timestamp equality, ABI handling, and parity. They do not cover a failed target `execve`, PID reuse, missing ancestry, or comparison with an independent successful-exec event. Treat post-exec features as a diagnostic derivation with this assumption, not ground-truth payload-only telemetry. This uncertainty does not change the primary conclusion: the original, uncut model is already confounded, and the post-exec diagnostic remains confounded too.

Evidence: [`exec_boundary.py`](../src/exec_boundary.py), [`test_exec_boundary.py`](../tests/test_exec_boundary.py), and the probe construction in [`malware_runner.py`](../src/malware_runner.py).

### P4 measurement and sample inclusion

- P4 inputs are reconstructed offline from PCAPs. The analysis explicitly uses captured-Ethernet byte lengths and nominal 0.5-second rate windows to match the frozen collector’s stored semantics. All 26,535 stored-versus-reconstructed summary comparisons match for included samples. This is a parity result, not validation against a running P4 target, hardware counters, or BFRT state.
- Two malware captures were excluded for reported PCAP kernel drops (1,522 and 27). Fifteen additional accepted captures were excluded because PCAP-to-telemetry window alignment was not unique: six malware and nine benign. The resulting analysis contains 92 malware and 91 benign samples. Selection on alignment/quality is defensible for feature validity but could alter the evaluated population; report the excluded set and retain sensitivity analyses.
- P4-only BA/AUC are 0.694/0.836. Hybrid and host-only scores are identical. On these data there is no observed hybrid gain to attribute to network/P4 features.

Evidence: [`analyze_p4_pcap_ablation.py`](../../../p4_ebpf/analyze_p4_pcap_ablation.py), [`test_pcap_window_alignment.py`](../../../p4_ebpf/tests/test_pcap_window_alignment.py), [`p4_alignment_audit.csv`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/p4_alignment_audit.csv), and [`metrics.json`](../data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/p4_29x29/metrics.json).

### Collection quality is not behavioral truth

The scale cohort retrieved all 200 samples with matching provenance and structural/archive validation. Malware quality is 98 accepted and two rejected; benign quality is 100 accepted. The two rejected traces must remain excluded. Malware process outcomes include only 45 exit-0 runs among 98 accepted samples; benign has 95 exit-0 runs among 100 accepted. Retrieval completion and sensor-quality acceptance do not mean a sample successfully activated or performed its claimed behavior. Nor does exit code zero by itself verify malicious behavior.

The current study labels are malware-source provenance versus selected benign workload provenance. They are not independent per-run labels for whether malicious behavior was actually observed. Any claim about behavior requires a separate activation/behavior ground truth, with failures and non-activation reported rather than silently treated as positive behavioral examples.

### Benign-ELF collection: provisional status

At the read-only check on 2026-10-20, the separate 100-run benign ELF campaign was still active on the user’s VM, with `nic1=intnet`, `nic2=none`, and profile 09 being collected. Its frozen plan is ten ELF utilities times ten argument profiles under schema `.14`; that is 100 executions but only ten executable/tool groups. The inventory found 82 runs with retrieval completed and collection quality accepted: 65 exit 0, 16 timeout (`-15`), and one exit 1. One visible item (`vmstat`, profile 09) had no `run.json` yet. No aggregate/model outputs existed in the campaign root at the audit check.

This collection is a useful artifact-format counterfactual, but it is not yet a result and must not be analyzed as 100 independent benign programs. On completion, validate all per-run provenance, quality, finite telemetry, archive hashes, and alignment; group repeated profiles by utility for evaluation and uncertainty. Do not stop or alter the active coordinator based on this report.

Evidence: [`experiment_manifest.json`](../data/versioned-collector/benign-elf-100-v14-20261020T140000Z/experiment_manifest.json), [`run_elf_100.sh`](../data/versioned-collector/benign-elf-100-v14-20261020T140000Z/run_elf_100.sh), and the campaign’s `coordinator.log` and per-profile logs.

## Literature Synthesis

- Arp et al., [“Dos and Don’ts of Machine Learning in Computer Security”](https://www.usenix.org/conference/usenixsecurity22/presentation/arp), USENIX Security 2022, review common design/implementation/evaluation pitfalls and empirically show that they can produce unrealistic security-system results and interpretations. This supports separating a correct model run from a valid security claim.
- Pendlebury et al., [TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury), USENIX Security 2019, formalize spatial and temporal constraints and evaluate malware classifiers on a large temporal dataset. The current random grouped folds do not substitute for an external time/family evaluation.
- Engelen et al., [“Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study”](https://doi.org/10.1109/SPW53761.2021.00009), IEEE Security and Privacy Workshops 2021, is a dataset-quality case study. D’Hooge et al., [“Discovering Non-Metadata Contaminant Features in Intrusion Detection Datasets”](https://doi.org/10.1109/PST55820.2022.9851974), PST 2022, directly motivates checking features that leak dataset construction artifacts even when obvious metadata fields are absent. These are relevant precedents, not evidence that the present PCAPs have the same specific defects.
- Lin et al., [“Dataset Bias in Android Malware Detection”](https://arxiv.org/abs/2205.15532), is an arXiv preprint. Its experiments report sensitivity to VirusTotal labeling thresholds, malware-family composition, and partition strategy; it should be cited as a preprint, not a peer-reviewed venue paper.
- Liu et al., [“The Impact of Train-Test Leakage on Machine Learning-based Android Malware Detection”](https://arxiv.org/abs/2410.19364), is also cited here as an arXiv preprint (v2, 2025). It reports identical/nearly identical representations across train/test and shows that removing leakage can affect both scores and model comparisons.
- Molina-Coronado et al., [“Towards a fair comparison and realistic evaluation framework of Android malware detectors based on static analysis and machine learning”](https://doi.org/10.1016/j.cose.2022.102996), *Computers & Security* 124 (2023), provides an additional realistic-evaluation reference.

## What Would Support a Behavioral Claim

1. Pre-register the estimand: distinguish “malware-source artifact versus selected benign artifact” from “telemetry predicts a verified malicious behavior.” Define the behavior labels and non-activation/crash treatment before fitting.
2. Break the format-label association. Include benign ELF and malware ELF workloads, plus any relevant script formats in both labels where scientifically meaningful. Match launch wrapper, arguments, privileges, observation windows, host image, sensor versions, network reachability, and workload duration/activity as far as possible. Randomize and interleave collection order.
3. Treat the executable or family as the statistical unit. Keep all repeated profiles/runs for an executable in one split. Use a genuinely external holdout by malware family/source and benign utility/workload, ideally also time; do not tune on that holdout. Report sample-level and group-macro metrics with group-aware uncertainty.
4. Apply predeclared per-run quality gates and publish the full exclusion ledger. Keep retrieval, sensor acceptance, process outcome, observed behavior, and label provenance as separate variables.
5. Compare P4-only, host-only, and hybrid on exactly the same valid samples and held-out groups. Report paired hybrid-minus-best-single-model uncertainty, false-positive/negative rates, calibration, and precision at a stated deployment prevalence. Select thresholds only on training/validation data.
6. Validate P4 separately against a live target using known-answer traces and register/readback comparisons. Until that exists, call the current values “offline P4-shaped PCAP features,” not live P4 measurements.
7. Use negative controls that can expose the shortcut: artifact type, tool/family identity, return code, duration/activity, first-window-only, and launch-sensitive features; perform group-level label permutations and evaluate matched ELF-only subsets. These are diagnostics, not invitations to remove inconvenient features after seeing test scores.

The shortcut hypothesis would be weakened if useful discrimination persisted on independently held-out malware families and benign executable groups after format, launch, workload, activity, and sensor-quality matching, with no comparable artifact/workload-only baseline and with verified behavior labels. It would be strengthened if performance falls sharply in those matched/external strata or a format/workload baseline performs similarly. Even a successful matched evaluation would support predictive association, not by itself prove that any feature is causally malicious.

## Validation and Limits of This Audit

Focused checks rerun during this audit:

- `/usr/bin/python3 -m unittest tests.test_exec_boundary -v`: 19 passed; two existing `ResourceWarning`s identify unclosed test file handles.
- From `p4_ebpf/`, `/usr/bin/python3 -m unittest discover -s tests -p 'test_pcap_window_alignment.py' -v`: 2 passed.

This audit did not execute malware, start or resume any collection, change the runner/schema, change snapshots, retrain the frozen model, or modify existing captures/results. The benign-ELF campaign remains active and its results are provisional. Source-group labels are imperfect proxies for behavioral families; archived telemetry cannot prove events that were never captured; and offline PCAP parity cannot certify live P4 behavior.
