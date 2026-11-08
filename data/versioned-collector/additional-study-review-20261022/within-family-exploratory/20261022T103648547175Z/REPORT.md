# Within-Family Exploratory Resplit

## Scope

User-authorized offline reallocation and fixed-model refit. Original data, splits, models and production collector are unchanged. No VM, sample execution or new collection occurred.

This answers known-family/project evaluation, NOT unseen-family generalization. All data were already examined, so this is post-hoc exploratory rather than fresh blind validation.

## Split

Primary training: {'benign': 98, 'malware': 84}. Primary validation: {'benign': 99, 'malware': 85}.
All366 common-aligned cases are used once; all417 host-eligible cases remain in a separately labeled sensitivity analysis. Exact class halves differ by at most one case. No oversampling or deletion to force equal class totals.
Benign project/program units keep architecture/build variants together. Malware hashes are distinct, but near-duplicate malware lineages have NOT been certified disjoint.

Both-side primary coverage: 14/20 malware signatures and 18/36 benign projects.
Remaining unsplittable groups are training-only; duplicating them into validation would leak samples. Full assignments and exceptions are in [coverage.csv](coverage.csv) and [split_dataset.csv](split_dataset.csv). Attack categories are not independently verified or invented from family names.

## Primary Results

| Model | Accuracy | Balanced Accuracy | ROC-AUC | TN / FP / FN / TP |
| --- | ---: | ---: | ---: | --- |
| network_p4 | 67.3913% | 67.4510% | 0.762805 | 66 / 33 / 27 / 58 |
| host_29_families | 96.7391% | 96.8865% | 0.995009 | 94 / 5 / 1 / 84 |
| hybrid_29_plus_29 | 95.6522% | 95.7932% | 0.990790 | 93 / 6 / 2 / 83 |

Hybrid minus host balanced accuracy: -1.0933 percentage points; paired group-bootstrap95% descriptive interval [-4.8678, 0.0].

## Controls And Limitations

The activity-only control reaches82.3411% balanced accuracy, above the prior0.75 claim-blocking reference; nuisance-only reaches48.5324%. This is a material workload-confounding warning, not evidence of malicious-behavior generalization.

An independent post-fit audit found15 cross-partition groups of identical selected-host145 vectors, covering20 validation cases. Executable identities and benign program blocks do not overlap, but coarse behavior can coincide across distinct programs/samples. No full host175+P4145 source-feature vector crosses partitions. This does NOT certify malware near-duplicate or lineage separation. The split/models were not changed after these findings.

Fixed RF500/balanced/seed42/n_jobs1/sqrt/threshold0.5; training-only MI selects29 complete host families. P4/host/hybrid widths145/145/290. One frozen metadata-only optimized split; no search for favorable scores.
Equal-group weighting, per-mode/per-group results, training-only family-grouped OOF and activity/nuisance baselines are in [model-fit/metrics.json](model-fit/metrics.json). OOF tests unseen training groups and is a different estimand from the final known-family split. The host-all-eligible sensitivity uses a different population and is not the primary sensor comparison.
The previous attribution pilot found unrelated background connectivity traffic in all controls. Resplitting does not repair that issue. Family concentration, related malware, task/toolchain/acquisition shortcuts, tiny groups and selection bias remain. This result cannot establish that balancing caused a model improvement or that one method generally outperforms another.

## Reproduction And Evidence

Run the owning script with --self-test, --prepare-only, then --train <prepared-attempt>. --verify <attempt> checks source/model/split hashes, zero split-unit overlap, training-only selection, actual fitted widths/settings and exact saved probabilities. Original protocol/result/model hashes are frozen in [protocol.json](protocol.json).

Metrics SHA-256: `6b9acba34231864730216fce26367347729916d27582e30f6aa033e6d70d7944`.
