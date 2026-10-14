# Malware Detection Study: Methods and Results

This guide records the study chronologically and explains how the final binary classifiers were built and evaluated. It is intended as a quick research handoff and presentation source. The accompanying tables are generated from the committed cohort artifacts, not manually estimated.

## Executive Summary

The experiment compares three Random Forest classifiers on the same grouped, out-of-fold sample predictions:

1. **Network-only:** 45 aggregate packet/flow features.
2. **Host/eBPF-only:** 45 kernel event-counter features.
3. **Hybrid:** both feature sets, 90 total.

The final cohort contains 224 malware samples with usable telemetry and 138 benign controls (362 samples total). In five-fold, signature/package-family-grouped evaluation, hybrid reaches 0.929 balanced accuracy, host reaches 0.918, and network reaches 0.874. Hybrid modestly exceeds host-only on this cohort; this is exploratory evidence, not a general claim that hybrid detection is always superior.

## 1. Research Question and Comparison Design

The central question is whether network-level aggregate telemetry, host-level eBPF activity, or both provide the strongest discrimination between malware and benign Linux workloads under equal feature budgets.

All three classifiers use the same examples, fold assignments, class weighting, and Random Forest configuration. Malware is the positive class. Each model produces an out-of-fold probability for every sample; the default decision threshold is 0.5. The comparison is binary malware-versus-benign classification, not multi-class family recognition.

## 2. Malware Acquisition and Cohorts

Malware samples were selected from MalwareBazaar metadata as Linux ELF candidates. The acquisition tooling de-duplicates SHA-256 values, checks candidate format/architecture, downloads encrypted ZIP archives, and verifies archive hashes before staging. Malware labels reflect cohort provenance; neither successful execution nor a MalwareBazaar family signature is treated as independent ground truth for behavior.

The final inventory has 231 acquired malware records:

| Cohort | Acquired | With archived telemetry | Without usable telemetry |
| --- | ---: | ---: | ---: |
| Earlier cohorts | 189 | 186 | 3 |
| Additional MalwareBazaar batch, 2026-10-14 | 42 | 38 | 4 |
| **Total** | **231** | **224** | **7** |

The newest 42-sample batch comprised 5 backdoor, 10 botnet, 13 DDoS, 7 other-ELF, and 7 ransomware selections. The model excludes all seven acquisitions without usable telemetry, while preserving them in the inventory and outcome reports. The current modeled set contains 12 backdoor, 86 botnet, 80 DDoS, 17 other-ELF, 27 ransomware, and 2 Trojan samples. Categories are MalwareBazaar metadata; signatures can span categories.

## 3. Isolated Execution and Collection

Samples were run in the `Ubuntu-Clean-24.04` VirtualBox guest from clean snapshots. The `Sink` VM provided the emulated network service. Both guests were attached only to the internal `malnet` network; the malware VM had no NAT or public interface. Each sample was staged and run independently, with a clean restore between samples.

The collection configuration used a 20-second execution limit, 0.5-second telemetry windows, packet capture on `enp0s3`, and eBPF event collection. Collection status and program exit status are distinct: a malware sample remains malware-labeled if it exits nonzero or times out, but it cannot enter the model without archived telemetry.

For the latest 42-sample batch, 38 runs produced telemetry: 25 process completions, 7 nonzero exits, 2 signaled exits, and 4 timeouts. Three additional runs failed to transfer their output, and one executable was incompatible with the guest architecture. The successful captures contributed 195 telemetry windows and 21,189 eBPF event rows. Together with the prior expansion, this leaves 224 malware samples in the final model.

## 4. Benign Controls and Labels

The control set contains 138 generated benign Linux workloads grouped into 28 package families. The workloads cover safe command-line activities such as file/text operations, compression, Git, process inspection, and requests to the isolated sink. The benign workload manifest supplies labels and package-family groups.

The binary labels are assigned by provenance: acquired malware is label 1; generated benign workloads are label 0. Runtime success is not used as the malware label. The study therefore measures discrimination against this controlled benign workload mix, not against all activity on a general-purpose Linux host.

## 5. Telemetry and Feature Construction

Variable-length telemetry windows are aggregated to one row per sample using five summaries for each base signal: mean, maximum, sum, standard deviation, and number of active windows. The model uses nine network and nine host signal families:

| Sensor | Base signal families |
| --- | --- |
| Network | Captured bytes, bytes/second, received bytes, sent bytes, flow count, captured packets, packets/second, received packets, sent packets |
| Host/eBPF | Connect calls, successful `pwrite64`, write bytes, successful `write`, successful `writev`, successful `openat2`, successful `openat`, `sendto`, socket calls |

This gives 45 features per sensor and 90 for the hybrid model. The comparison excludes observer-only CPU/memory/process fields, file-watcher fields, timestamps, sample names, labels, and execution outcomes. The full engineering output contains a wider 35-host/9-network feature inventory; the equal-budget comparison selects the nine host and nine network families above.

The eBPF write counters are successful syscall-return counts and bytes scoped to the sample process and observed descendants. Without file-descriptor tracking they do not prove that a write targeted a regular file or identify a path. Filename strings from `openat` are unreliable and are not model features.

## 6. Grouped Cross-Validation and Classifier

The evaluation uses five-fold `StratifiedGroupKFold` with shuffle and seed 42. The 57 groups comprise 29 malware signature groups and 28 benign package-family groups. Samples sharing a malware signature or benign package family stay in one fold, preventing those groups from appearing in both train and test partitions. An audit found no group crossing folds. The same fold splits are used for all three feature sets.

Each fold fits median imputation on its training partition, then a 500-tree Random Forest with `max_features="sqrt"`, `min_samples_leaf=2`, and `class_weight="balanced_subsample"`. Random seeds are derived from the configured seed and fold number. Pooled metrics are computed from the combined out-of-fold predictions, rather than by averaging predicted labels or training on the test fold.

## 7. Overall Results

| Feature set | Features | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network | 45 | 0.870 | 0.874 | 0.928 | 0.857 | 0.891 | 0.929 | 123 | 15 | 32 | 192 |
| Host/eBPF | 45 | 0.914 | 0.918 | 0.957 | 0.902 | 0.929 | 0.976 | 129 | 9 | 22 | 202 |
| Hybrid | 90 | 0.928 | 0.929 | 0.958 | 0.924 | 0.941 | 0.985 | 129 | 9 | 17 | 207 |

Hybrid improves balanced accuracy by about 1.12 percentage points over host-only and makes five fewer malware false negatives at the same nine false positives. Network-only has the lowest pooled scores in this cohort. Fold-to-fold variation is reported in `cv_metrics.csv` and `cv_metrics.json`; the results should be interpreted with the grouped fold design and cohort size in mind.

## 8. Metadata-Category Results

The category table below pairs each modeled category with the same 138 benign controls using the global model's out-of-fold predictions. Other malware categories are excluded from that category's negative class. The balanced-accuracy values are category-versus-benign slices, not scores from separately trained category models. Detection counts are also included to make small categories visible.

| Category | Modeled / acquired | Network BA (detected) | Host BA (detected) | Hybrid BA (detected) |
| --- | ---: | ---: | ---: | ---: |
| Backdoor | 12 / 12 | 0.904 (11/12) | 0.967 (12/12) | 0.967 (12/12) |
| Botnet | 86 / 90 | 0.870 (73/86) | 0.933 (80/86) | 0.962 (85/86) |
| DDoS | 80 / 82 | 0.896 (72/80) | 0.917 (72/80) | 0.924 (73/80) |
| Other ELF | 17 / 18 | 0.887 (15/17) | 0.850 (13/17) | 0.850 (13/17) |
| Ransomware | 27 / 27 | 0.798 (19/27) | 0.893 (23/27) | 0.875 (22/27) |
| Trojan | 2 / 2 | 0.946 (2/2) | 0.967 (2/2) | 0.967 (2/2) |

The Trojan result is based on only two samples and is not a reliable estimate of Trojan detection performance. Category scores are descriptive because the labels are source metadata and signatures can contain mixed categories.

## 9. Interpretation and Limitations

- The modest hybrid-over-host improvement is specific to this cohort and split; it does not establish a universal hybrid advantage.
- The benign controls are generated workloads from 28 package families, not a representative sample of ordinary Linux users or production services.
- Malware family/category values originate in MalwareBazaar metadata and are not independently verified runtime behavior. Several signatures map to multiple categories.
- Category rows reuse the same benign controls and are slices of global binary-model predictions; they are not independent category classifiers or multiclass results.
- Seven acquired malware records had no usable telemetry and were excluded from training/evaluation. Their acquisition and collection status remains visible in the inventory/outcome report.
- The network features are aggregate packet/flow counters designed to resemble implementable network telemetry. This experiment is not a live P4 hardware benchmark.
- The committed final feature matrix supports independent reruns of model training and scoring. Raw per-event collector traces, PCAPs, VM outputs, and malware archives are not published; rebuilding collection or the full upstream telemetry merge requires those local inputs and the isolated lab.

## 10. Repository Artifact Map

The current cohort directory is `data/malware/revision4/family-heldout-balanced-224-v1-20261014/`:

- `labeled_sample_dataset_full_35host_9network.csv` is the final engineered training table; its neighboring JSON files define the feature columns.
- `reports/balanced_9network_9host/cv_metrics.csv` and `.json` contain pooled and fold-level overall metrics.
- `reports/balanced_9network_9host/out_of_fold_predictions.csv` contains all sample-level predictions for all three feature sets.
- `reports/balanced_9network_9host/feature_importance.csv` contains model feature importances.
- `reports/balanced_9network_9host/category_analysis/` contains per-category metrics, per-sample predictions, collection/execution outcomes, summary metadata, and `overall_and_category_scores.csv`.
- `models/balanced_9network_9host/` contains the three fitted final estimators. Only load trusted Joblib files.
- `data/malware/malware_sample_inventory_all_expansions_20261014.csv` records all 231 acquisitions, including the seven excluded records and their statuses.

The small JSONL acquisition manifests and feature-selection configuration are also included. Raw malware ZIPs, executables, packet captures, per-run directories, and detailed merged collector streams are deliberately excluded from this private repository.

## 11. Reproduce the 224-Sample Model Evaluation

From the repository root, create the Python environment and rerun the training/evaluation from the committed final sample table:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

OUTPUT_DIR=/tmp/hybrid-rf-reproduction
COHORT=data/malware/revision4/family-heldout-balanced-224-v1-20261014
FEATURES=data/malware/revision4/family-heldout-stable-151-v1-20261014/feature_breadth_comparison/balanced_9network_9host_feature_columns.json

python3 src/train_compare.py \
  --dataset "$COHORT/labeled_sample_dataset_full_35host_9network.csv" \
  --feature-columns "$FEATURES" \
  --reports-dir "$OUTPUT_DIR/reports" \
  --models-dir "$OUTPUT_DIR/models" \
  --folds 5 --seed 42

python3 src/analyze_malware_category_results.py \
  --inventory data/malware/malware_sample_inventory_all_expansions_20261014.csv \
  --predictions "$OUTPUT_DIR/reports/out_of_fold_predictions.csv" \
  --output-dir "$OUTPUT_DIR/category_analysis"
```

This reproduces the grouped evaluation and metadata-category analysis without rerunning malware. Rebuilding the final engineered table from raw collector logs is a separate upstream task; those detailed collector inputs are local-only because they are large and contain per-event process identifiers/details. The committed feature table and code are sufficient to rerun the reported classifier comparison.

## 12. Suggested Presentation Flow

1. **Question:** Do network and host/eBPF signals provide complementary evidence?
2. **Safe collection:** MalwareBazaar provenance, clean snapshots, isolated `malnet`, and the 20-second/0.5-second collection configuration.
3. **Dataset:** 224 modeled malware + 138 benign; 57 signature/package groups; seven acquisitions excluded for missing telemetry.
4. **Fair comparison:** identical five-fold grouped splits and 45/45/90 feature budgets.
5. **Results:** overall balanced accuracy 0.874 / 0.918 / 0.929; emphasize the modest hybrid gain and category-level variation.
6. **Caveats:** metadata labels, controlled benign workload mix, tiny Trojan category, and no live P4 hardware claim.

Suggested headline: *Hybrid telemetry modestly improved grouped out-of-fold detection on this cohort, mainly by reducing malware misses relative to host-only; broader validation is needed.*