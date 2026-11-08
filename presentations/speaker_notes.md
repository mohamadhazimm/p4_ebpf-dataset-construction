# Speaker Notes: Hybrid Malware Detection

Companion to `malware_detection_study.pptx`.

## 1. Hybrid Malware Detection

Open with the question: does combining host and network observations help distinguish this malware cohort from a controlled benign workload set? The headline result is a modest hybrid improvement over host-only under grouped out-of-fold evaluation. This is not a live P4 hardware result or a claim of universal superiority.

## 2. Malware families

The primary model cohort contains 224 malware samples across 28 named family labels; 8 samples have no assigned family label. The register counts family labels in the modeled cohort, not attack behavior verified independently. The supplemental intake adds 11 MalShare Mirai samples outside model scoring: one compatible I386 sample completed an isolated run, while ten other architectures were not run on the x86-64 guest.

## 3. Cohort and exclusions

The source-aware catalog contains 242 malware records: 231 from MalwareBazaar and 11 supplemental MalShare samples. The primary evaluation remains 224 modeled MalwareBazaar malware plus 138 benign workloads, for 362 samples. Seven earlier acquisitions lacked usable telemetry; the 11 MalShare additions remain supplemental, including the single I386 run, and do not change the reported model scores.

## 4. Isolated collection

The malware guest is Ubuntu-Clean-24.04 and is restored from a clean snapshot before every sample. Its only enabled adapter is VirtualBox internal network malnet; the sink VM uses the same network, with no NAT, bridged, or host-only interface. Each encrypted archive and extracted payload is hash-verified. One sample runs for at most 20 seconds while packet capture and eBPF collect 0.5-second windows. The malware VM is powered off and reverted after each run.

## 5. Feature construction

The raw collection produces multiple time windows per sample. Dataset construction aggregates each selected base signal using mean, maximum, sum, standard deviation, and active-window count. Nine network signal families produce 45 values; nine selected host/eBPF families also produce 45. Hybrid concatenates them for 90. The feature contract intentionally excludes CPU and memory observer metrics, timestamps, labels, filenames, process details, and execution status.

## 6. Evaluation protocol

StratifiedGroupKFold uses five folds and seed 42. The 57 groups are 29 malware signature groups plus 28 benign package-family groups; no group crosses folds. Within each fold, median imputation is fit only on the training partition, followed by the same Random Forest configuration: 500 trees, square-root feature sampling, minimum leaf size two, and balanced subsample weights. Each sample receives one held-out probability for each feature set. Balanced accuracy is the mean of sensitivity and specificity, which is useful when class sizes differ.

## 7. Overall results

These pooled out-of-fold values come directly from cv_metrics.csv. Hybrid balanced accuracy is 0.929, compared with 0.918 for host-only and 0.874 for network-only. Hybrid ROC-AUC is 0.985. Balanced accuracy is not the same as accuracy: it gives equal weight to sensitivity and specificity. The displayed bar axis starts at 0.70 to make small differences readable, so compare the printed values rather than visual bar length alone.

## 8. Category results

This chart uses balanced accuracy for each metadata category versus the same 138 benign controls, from the global model's out-of-fold predictions. The sample count is shown beside each category because the groups vary from 2 Trojan samples to 86 botnet samples. Hybrid is strongest for botnet and DDoS, and ties host for backdoor and the two-sample Trojan slice. Network scores higher on the small Other ELF slice, while host is strongest for ransomware. These are descriptive slices and not independently trained category classifiers.

## 9. Error profile

The confusion counts make the operating-point tradeoff concrete. Network has 32 false negatives and 15 false positives. Host has 22 and 9. Hybrid has 17 and 9. Relative to host-only, the hybrid model reduces false negatives by five without increasing false positives on this pooled OOF set. This is a cohort-specific threshold result at 0.5, not a guarantee at another deployment threshold.

## 10. Limitations and next steps

The evidence is limited by the size and provenance of the cohort, the generated benign workload mix, and metadata-derived malware categories. The study does not yet validate network features against a live P4 target and should not be presented as field performance. The next experiment should increase independent malware signatures and benign environments, verify behaviors where possible, and compare packet-capture-derived network counters with a running P4 pipeline.

## 11. Reproduction and discussion

The committed feature matrix is sufficient to rerun training, out-of-fold scoring, and category analysis without rerunning malware. The walkthrough document is the detailed narrative and includes exact commands, caveats, and a full artifact map. Raw malware, packet captures, per-run VM outputs, and detailed event-level collector streams are excluded. Close with the proposed next steps and invite questions about group splits, label provenance, and the distinction between PCAP aggregates and live P4 measurements.
