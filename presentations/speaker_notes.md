# Speaker Notes: Hybrid Malware Detection

Companion to `malware_detection_study.pptx`.

## 1. Hybrid Malware Detection

Open with the question: does combining host and network observations help distinguish this malware cohort from a controlled benign workload set? The headline result is a modest hybrid improvement over host-only under grouped out-of-fold evaluation. This is not a live P4 hardware result or a claim of universal superiority.

## 2. Research question

The experiment compares three binary classifiers on identical samples and grouped folds. Network-only uses packet and flow counters, host-only uses eBPF-derived system-call counters, and hybrid combines them. The question is whether the two sensor views add complementary evidence under comparable feature budgets, not whether the model identifies a malware family.

## 3. Cohort and exclusions

The inventory contains 231 acquisitions. 224 malware samples had archived telemetry and were included; 7 did not and were excluded. The final binary dataset adds 138 benign workloads, yielding 362 evaluated samples. The newest batch had 42 acquisitions, 38 telemetry captures, and four without usable telemetry. The 195 telemetry windows and 21,189 eBPF events refer to the newest batch's successful captures, not the whole cohort.

## 4. Isolated collection

Candidate archives were selected from MalwareBazaar metadata, verified by SHA-256, staged in a guest restored from a clean snapshot, and run one at a time. The malware VM and sink VM used only the internal malnet network. Packet capture and eBPF telemetry were collected in parallel. The 20-second cap and 0.5-second windows were consistent across the collection. A nonzero exit or timeout did not change the malware label; missing archived telemetry did exclude a sample.

## 5. Feature construction

The raw collection produces multiple time windows per sample. Dataset construction aggregates each selected base signal using mean, maximum, sum, standard deviation, and active-window count. Nine network signal families produce 45 values; nine selected host/eBPF families also produce 45. Hybrid concatenates them for 90. The feature contract intentionally excludes CPU and memory observer metrics, timestamps, labels, filenames, process details, and execution status.

## 6. Evaluation protocol

StratifiedGroupKFold uses five folds and seed 42. The 57 groups are 29 malware signature groups plus 28 benign package-family groups; no group crosses folds. Within each fold, median imputation is fit only on the training partition, followed by the same 500-tree Random Forest configuration. Each sample receives one held-out probability for each feature set. Balanced accuracy is the mean of sensitivity and specificity, which is useful when class sizes differ.

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
