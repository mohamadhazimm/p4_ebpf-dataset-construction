# Superseded: Full-Feature Exploratory Grouped Model

This historical analysis used all 169 collector features and is not the requested p4_ebpf 29+29 protocol. The authoritative corrected analysis is [the P4 29x29 report](p4_29x29/EXPLORATORY_FINDINGS.md); the artifacts below are retained only to preserve the earlier exploratory run.

## Data and protocol

This run uses the 198 collection-quality-accepted samples: 98 malware and 100 benign. The two malware captures rejected for reported PCAP drops are excluded. Each sample's 40 telemetry windows are summarized using mean, maximum, sum, population standard deviation, and active-window count for each of the 169 declared features. This produces 330 network/P4-shaped, 515 host/runtime, and 845 combined aggregate columns.

Validation is five-fold `StratifiedGroupKFold` (seed 42). Malware source-signature groups (acquisition metadata, not necessarily distinct behavioral families) and benign tool families are kept intact within each fold; no group crosses from training to validation. Fold sizes vary because the split is group-constrained: 27 to 52 validation samples, with both labels represented in every fold. The classifier is the repository's fixed 500-tree Random Forest with median imputation fit inside each training fold, `min_samples_leaf=2`, and balanced-subsample class weights.

## Out-of-fold results

| Feature set | Features | Balanced accuracy | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network/P4-shaped | 330 | 0.728 | 0.855 | 70 | 30 | 24 | 74 |
| Host/runtime | 515 | 0.975 | 0.999 | 95 | 5 | 0 | 98 |
| Combined | 845 | 0.975 | 1.000 | 95 | 5 | 0 | 98 |

At the 0.5 threshold, the combined model makes the same classifications as host-only; its small ROC-AUC difference is not meaningful evidence of added value on this cohort. All five host/combined false positives are held-out `psmisc` benign samples in fold 4. Network-only is weaker and has errors in both classes.

## What it appears to learn

The combined full-data model's largest importances are host path/file telemetry: `host_unique_file_directories__max`, `host_open_path_home_count__sum`, `host_open_path_home_count__max`, `host_unique_file_directories__mean`, and `host_unique_open_paths__max`. These are descriptive importances from the final model refit on all 198 accepted samples, not fold-independent explanations.

The underlying cohort has a complete artifact/launch distinction: all 100 benign inputs are `script_shebang`; all 98 modeled malware inputs are `elf`. Artifact type and process outcome were not model features, but the class/artifact distinction is perfectly correlated and can produce different observed telemetry. As another descriptive contrast, median `host_unique_file_directories__max` is 13 for benign and 1 for malware; median `host_open_path_home_count__sum` is 24 versus 0. These differences do not establish malicious behavior.

## Interpretation limits

This is a useful first pattern check, not an estimate of general malware-detection performance. Grouped folds prevent source-signature/tool-family overlap but cannot correct the class/launch/workload confound, activity and duration differences, or the purposive sample selection; source signatures are not guaranteed to represent distinct code families. Malware labels reflect acquisition cohort, not independently verified runtime behavior; only 45 of 98 accepted malware processes exited 0, while 95 of 100 benign processes exited 0. The network features are collected packet/P4-shaped telemetry, not measurements from a live P4 switch. No external holdout was used.

The OOF predictions and metrics are the validation results. `src/train_compare.py` also refits and saves models on all 198 accepted samples after CV; those `.joblib` files are exploratory artifacts, not the models that generated the held-out predictions. Do not deploy or cite the scores as a detector benchmark without a better-matched benign ELF cohort and an external, family-disjoint evaluation.

## Reproduction and artifacts

From the study repository root:

```bash
/usr/bin/python3 data/versioned-collector/scale-100x100-v14-20261020T072500Z/prepare_scale100_model_data.py
/usr/bin/python3 src/train_compare.py \
  --dataset data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/accepted_sample_dataset.csv \
  --feature-columns data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/accepted_sample_dataset.feature_columns.json \
  --reports-dir data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/reports \
  --models-dir data/versioned-collector/scale-100x100-v14-20261020T072500Z/modeling/models \
  --folds 5 --seed 42
```

`dataset_summary.json` and `split_audit.json` record sample selection and fold assignments. `reports/cv_metrics.json`, `reports/out_of_fold_predictions.csv`, and `reports/feature_importance.csv` contain the model results and diagnostics.
