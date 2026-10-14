# Hybrid Malware Detection Study

This folder contains the inputs, benign workload definitions, telemetry, model code, saved estimators, and evaluation reports for a network-only vs host-only vs hybrid Random Forest comparison.

## Related Repositories

- [Thesis and research overview](https://github.com/mohamadhazimm/a-unified-p4-ebpf-architecture-for-host-and-network-malware-detection)
  contains the written research, figures, and supporting analysis.
- [P4 + eBPF Hybrid Monitor](https://github.com/MohamadMHazim/p4_ebpf)
  contains the programmable data-plane and host-monitor implementation.

These repositories are maintained independently. This study covers dataset
construction and offline model evaluation; it does not replace measurements on
a live P4 target.

## Agent Orientation

This is a research pipeline comparing network-only, host/eBPF-only, and hybrid malware classifiers. The current evaluation uses 224 malware samples with archived telemetry and 138 benign controls. Malware category labels are MalwareBazaar metadata, not independently confirmed runtime behavior. Earlier sections and paths are retained for historical cohorts; use the latest cohort paths below when reporting current results.

### Repository map

- `src/` contains the Python acquisition, inventory, dataset, feature, model-training, and category-analysis code. Start with `build_dataset.py`, `build_feature_breadth_dataset.py`, `train_compare.py`, and `analyze_malware_category_results.py` for the analysis path.
- `scripts/` contains VirtualBox staging, isolated collection, merge, and experiment orchestration. `run_malware_revision4_pipeline.sh` is the revision-4 pipeline entry point; `vbox_malware_batch.sh` runs samples and collects telemetry.
- `workloads/` generates benign workloads and hybrid emulation scenarios.
- `data/` holds cohort manifests, package metadata, telemetry, datasets, and generated results. Cohort-specific outputs live under versioned `data/malware/revision4/family-heldout-*` directories. The full datasets, raw run artifacts, and malware samples are local research inputs, not source files.
- `models/` and `reports/` contain baseline model artifacts and metrics; newer revision-specific outputs are kept with their cohort under `data/malware/revision4/`.
- `tests/` contains focused unit tests. Run them with `python3 -m unittest discover -s tests`.
- `requirements.txt` lists Python dependencies.

### Current results

- Evaluation dataset: `data/malware/revision4/family-heldout-balanced-224-v1-20261014/labeled_sample_dataset_full_35host_9network.csv`.
- Overall and per-category scores: `data/malware/revision4/family-heldout-balanced-224-v1-20261014/reports/balanced_9network_9host/category_analysis/overall_and_category_scores.csv`.
- Acquisition and collection inventory: `data/malware/malware_sample_inventory_all_expansions_20261014.csv`.
- The evaluation dataset and raw out-of-fold predictions are local-only and excluded from Git. The aggregate score CSV and inventory above are the published results for the current cohort.
- Cross-validation is five-fold `StratifiedGroupKFold`, grouped by malware signature and benign package family. The current run has 57 groups, with no group crossing folds. Network and host each use 45 features; hybrid uses 90.

### Workflow

1. Acquire and verify MalwareBazaar metadata and encrypted archives with `src/acquire_malwarebazaar_samples.py` and `src/enrich_malwarebazaar.py`.
2. Stage samples and collect inside the isolated VirtualBox environment using the scripts in `scripts/`.
3. Merge per-run output with `scripts/merge_collector_csvs.py`.
4. Build labeled and wide-feature datasets with `src/build_dataset.py` and `src/build_feature_breadth_dataset.py`.
5. Train/evaluate with `src/train_compare.py`; generate metadata-category slices with `src/analyze_malware_category_results.py`.

### Safety and credentials

Never commit API keys, passwords, malware archives or executables, packet captures, or per-run VM output. Keep `MALWARE_BAZAAR_API_KEY` and `VBOX_GUEST_PASSWORD` in the local environment; do not paste their values into commands recorded in the repository. The malware VM must use only the internal `malnet` network, with no NAT or public interface. `.gitignore` excludes local secrets and all experimental data by default. Only the reviewed workload/package manifests, 231-row inventory, and current aggregate category-score CSV are allowed into this repository; model binaries and generated datasets remain local.

## Data and labels

- `data/malware/combined_collector.csv` is the final 138-sample MalwareBazaar Linux corpus with host, eBPF, and packet-reference telemetry. Malware label `1` comes from cohort provenance, not process exit status.
- `data/packages/debs/` contains Ubuntu 24.04 Noble amd64 packages downloaded from the official signed archive. `package_manifest.csv` records versions and hashes; `SHA256SUMS` verifies the package files.
- `data/benign/workload_manifest.csv` maps 138 generated workloads to 28 official package families. They perform safe local file, text, compression, editor, Git, process-inspection, and internal HTTP/DNS tasks. Network requests resolve to the isolated INetSim sink at `10.0.0.1`; the workloads do not contact public services.
- `data/benign/combined_collector.csv` and per-run archives are produced by the collection step.
- `data/benign/revision2/` is the revised cohort: input fixtures are built on the host and staged outside the watched sample workspace before collection. Its data, reports, and models remain separate from the original cohort.
- `data/benign/revision3/` contains balanced read-only, light-write, and multi-write workloads, pre-staged fixtures, and separate smoke-test outputs. Revision-3 collection is pending the guest credential becoming available to the shell environment.

The guest currently identifies itself as Ubuntu 26.04, even though the VM name contains `24.04`. Noble package binaries are unpacked into a private directory, not installed system-wide. The generator and setup script validate key downloaded commands before the collection snapshot is created.

## Sensor contract

The comparable host feature set uses only counters derived from kernel eBPF tracepoints: syscall events, successful `openat`/`openat2` returns, positive-return `write`/`pwrite64`/`writev` calls and returned byte counts, and observed sample-process threads. Write events are scoped to the sample process and observed fork descendants, but are syscall-level: without file-descriptor tracking they are not guaranteed to represent regular-file writes and are not attributed to paths. Guest `openat` filename strings are currently blank/unreliable. Watchdog and `psutil` fields remain diagnostic and are excluded from the model.

Network model inputs are captured packet count, captured packet bytes, and directional flow counts keyed by IP addresses, protocol, and TCP/UDP ports when present. These are deliberately aggregate counters that can be collected by packet capture today and mapped to P4 counters/flow state later; OS socket statistics and packet-reference fields are excluded from the model. The malware VM must remain on the isolated `malnet` internal network, with INetSim as its only network peer.

## Prepare and collect

The VM must be attached only to the isolated `malnet` internal network. Set the existing guest password in the shell environment; the scripts pass it through a mode-600 temporary file.

```bash
python3 workloads/generate_workloads.py \
  --output-dir data/benign/revision3/workload_scripts \
  --fixture-dir data/benign/revision3/workload_fixtures \
  --manifest data/benign/revision3/workload_manifest.csv \
  --package-manifest data/packages/package_manifest.csv \
  --count 138

WORKLOAD_SET_DIR=data/benign/revision3 \
BENIGN_SNAPSHOT=clean-emulated-hybrid-rf-v3-20261011 \
VBOX_GUEST_PASSWORD='your guest password' scripts/prepare_guest.sh
```

`prepare_guest.sh` restores the known clean malware baseline, stages verified packages, scripts, and prebuilt fixtures, extracts packages without installing them, validates the benign tools and internal sink, and creates a separate snapshot. Fixtures live outside the per-sample workspace monitored during execution. Revision 3 assigns exactly 46 workloads to each file-activity mode and marks controlled-sink download cases in the manifest. The dedicated `/tmp` write smoke script is staged outside the 138-sample directory. Do not attach NAT or a public interface to the malware VM.

First run both smoke workloads: the benign curl workload checks the internal sink, and the dedicated script writes, reads, and removes a file under `/tmp` so the successful-open/write eBPF events can be checked outside the watched workspace.

```bash
VBOX_GUEST_PASSWORD='your guest password' ./scripts/vbox_malware_batch.sh \
  --vm Ubuntu-Clean-24.04 --guest-user csci \
  --guest-malware-dir /home/csci/Downloads/hybrid-rf-study/workload_smoke \
  --guest-runner /home/csci/Downloads/malware_runner.py \
  --snapshot clean-emulated-hybrid-rf-v3-20261011 \
  --output-dir data/benign/revision3/smoke --timeout 20 --window-sec 0.5 \
  --iface enp0s3 --ebpf

BENIGN_DATA_DIR=data/benign/revision3 \
BENIGN_SNAPSHOT=clean-emulated-hybrid-rf-v3-20261011 \
RUN_TAG=benign-v3-full-20261011 RESUME=1 \
VBOX_GUEST_PASSWORD='your guest password' scripts/collect_benign.sh

VBOX_GUEST_PASSWORD='your guest password' ./scripts/vbox_malware_batch.sh \
  --vm Ubuntu-Clean-24.04 --guest-user csci \
  --guest-malware-dir /home/csci/Downloads/malwarebazaar_linux_ransomware_ddos_all \
  --guest-runner /home/csci/Downloads/malware_runner.py \
  --snapshot clean-emulated-hybrid-rf-v3h-20261011 \
  --output-dir data/malware/revision3/runs/malware-v3-full-20261011 --resume \
  --timeout 20 --window-sec 0.5 --iface enp0s3 --ebpf
python3 scripts/merge_collector_csvs.py data/malware/revision3/runs/malware-v3-full-20261011 \
  --output data/malware/revision3/combined_collector.csv
```

Inspect the smoke run's `ebpf_events.csv` for a successful `/tmp/ebpf-write-smoke-...` open and positive write bytes, and verify the curl run has captured traffic to/from the internal sink before starting either full collection.

## Train and compare

Create an isolated Python environment and install `requirements.txt`, then run:

```bash
BENIGN_DATA_DIR=data/benign/revision3 \
MALWARE_CSV=data/malware/revision3/combined_collector.csv \
DATASET=data/benign/revision3/labeled_sample_dataset.csv \
REPORTS_DIR=data/benign/revision3/reports \
MODELS_DIR=data/benign/revision3/models \
scripts/run_experiment.sh
```

`build_dataset.py` aggregates variable-length telemetry windows to one row per sample using mean, maximum, sum, standard deviation, and active-window counts. It does not use artifact names, labels, execution status, or timestamps as model features. Host features are numeric eBPF-derived columns only; network features are the packet-capture packet/byte/flow counters only. This keeps comparisons tied to implementable sensor signals rather than the host-side observer.

`train_compare.py` evaluates all three feature sets on the same 5-fold `StratifiedGroupKFold` splits. Benign runs from the same package family stay in one fold; malware samples are grouped by artifact. Each model uses the same class-balanced Random Forest configuration. Reports include pooled out-of-fold accuracy, balanced accuracy, precision, recall, F1, ROC-AUC, confusion counts, fold variation, per-sample predictions, and feature importances. Final fitted models are saved under `models/`.

Do not treat an accuracy increase as proof of a hybrid-architecture benefit unless the group-held-out scores and uncertainty support it. The benign cohort consists of controlled command-line workloads, so the result estimates discrimination against this benign workload mix, not all benign Linux activity. Include multiple benign workload types and inspect class-specific recall and false positives.

## Observed results

Five-fold grouped cross-validation on 276 balanced samples produced these pooled out-of-fold results:

| Feature set | Accuracy | Balanced accuracy | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network | 0.851 | 0.851 | 0.929 | 117 | 21 | 20 | 118 |
| Host/eBPF | 1.000 | 1.000 | 1.000 | 138 | 0 | 0 | 138 |
| Hybrid | 1.000 | 1.000 | 1.000 | 138 | 0 | 0 | 138 |

Host/eBPF and hybrid tie on this original cohort; adding network features did not improve on host/eBPF alone. These initial benign scripts created their fixture inputs inside the monitored workspace, which inflated benign file-activity features and made the original host score an unfair comparison. Revision 2 moves fixture creation before monitoring and is intended to test that specific confound. The perfect original scores indicate separation of the collected cohorts, not general malware-detection performance. Malware samples are split by individual artifact, not by malware family, so related samples may occur in different folds. Validate with family-held-out malware and a broader, independently collected benign corpus before drawing deployment conclusions.

## Revision 2 findings

Revision 2 pre-stages input fixtures outside the monitored workspace. All 138 runs completed with active packet and eBPF collection and zero packet drops. The revised five-fold grouped-CV results are:

| Feature set | Accuracy | Balanced accuracy | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network | 0.859 | 0.859 | 0.934 | 122 | 16 | 23 | 115 |
| Host/eBPF | 0.996 | 0.996 | 0.999 | 138 | 0 | 1 | 137 |
| Hybrid | 0.996 | 0.996 | 0.999 | 138 | 0 | 1 | 137 |

This is not evidence that host features generalize better or that hybrid improves on host-only. The remaining benign workloads all create output files during the monitored run, while only 5 of 138 malware samples produced file events in the watched workspace. File-activity features alone score 0.996 accuracy on the same folds. Removing those features lowers host accuracy to 0.986; eBPF alone also scores 0.986. Revision 2 fixed fixture-setup timing but did not eliminate the benign-versus-malware file-activity imbalance.

The malware PCAPs include external TCP SYN attempts with no observed SYN-ACK or payload, consistent with public-network access being blocked. The VM has no NAT, but it is attached to an internal network with an INetSim sink: sink HTTP traffic did receive responses. The malware runner's filesystem watcher is scoped to the sample workspace, so zero watched file events does not prove a sample made no writes elsewhere. eBPF `openat` counts are syscall-entry counts and do not establish that an open or write succeeded. A representative benchmark still needs benign workloads with a range of file behaviors, validated download behavior against a controlled sink, and filesystem telemetry that can attribute successful writes outside the workspace. Malware-family-held-out evaluation also remains outstanding.

Revision-2 data, reports, and estimators are under `data/benign/revision2/`; the original dataset and model artifacts remain unchanged under their original paths.

## Revision 3 status

The revision-3 benign and malware cohorts each contain 138 samples. All runs have active eBPF and packet capture; kernel packet drops were zero. The benign manifest has 46 read-only, 46 light-write, and 46 multi-write workloads. Malware runner outcomes were 65 `completed`, 34 `signaled`, 23 `nonzero_exit`, 11 `timeout`, and 5 `runtime_dependency_missing`; these describe sample execution, not sensor-collection failures. One initially empty malware output was preserved outside the merge input and successfully recaptured before analysis.

Five-fold `StratifiedGroupKFold` on 276 balanced samples (benign grouped by package family, malware grouped by individual artifact) produced:

| Feature set | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network | 0.837 | 0.837 | 0.792 | 0.913 | 0.848 | 0.911 | 105 | 33 | 12 | 126 |
| Host/eBPF | 0.993 | 0.993 | 1.000 | 0.986 | 0.993 | 1.000 | 138 | 0 | 2 | 136 |
| Hybrid | 0.993 | 0.993 | 1.000 | 0.986 | 0.993 | 1.000 | 138 | 0 | 2 | 136 |

Host/eBPF and hybrid made no false positives in any of the three benign workload modes. Network-only produced 33 false positives: 14 read-only, 19 light-write, and none multi-write. Adding network features did not change host-only thresholded predictions; its ROC-AUC increase from 0.9996 to 0.9997 is negligible. The host result is strong on this controlled cohort, not evidence of general deployment performance. The malware folds hold out individual artifacts, not malware families; the benign corpus is a defined workload mix; and 73 malware samples had a nonzero, signaled, timeout, or missing-runtime outcome while still producing telemetry. Use family-held-out malware and broader independently collected benign activity for stronger generalization claims.

Revision-3 data, reports, and estimators are under `data/benign/revision3/` and `data/malware/revision3/`. The exploratory 12-sample malware merge is retained separately as `data/malware/revision3/combined_collector_exploratory12_20261012.csv`; it is not used by the revision-3 dataset or results.

## MalwareBazaar Signature-Grouped Pilot (2026-10-14)

This is a separate real-sample comparison built from the existing revision-3 telemetry: 138 MalwareBazaar Linux samples and 138 generated benign workloads. Training reused captured telemetry only; no samples were launched for this model run. The six revision-4 captures are not included. The dataset uses the same stable feature sets as the synthetic pilot (15 network and 45 host features), with five-fold `StratifiedGroupKFold`: MalwareBazaar signatures define malware groups, and benign package families define benign groups. All 276 samples received out-of-fold predictions, with no group crossing folds.

Reproduce the dataset and model run from the study root with:

```bash
python3 src/build_dataset.py \
  --malware-csv data/malware/revision3/combined_collector.csv \
  --malware-family-metadata data/malware/revision3/malwarebazaar_metadata.jsonl \
  --benign-csv data/benign/revision3/combined_collector.csv \
  --benign-manifest data/benign/revision3/workload_manifest.csv \
  --output data/malware/revision3/family-heldout-stable-v1-20261014/labeled_sample_dataset.csv

python3 src/train_compare.py \
  --dataset data/malware/revision3/family-heldout-stable-v1-20261014/labeled_sample_dataset.csv \
  --reports-dir data/malware/revision3/family-heldout-stable-v1-20261014/reports \
  --models-dir data/malware/revision3/family-heldout-stable-v1-20261014/models \
  --folds 5 --seed 42
```

Metadata yields 12 malware signature buckets: 11 named signatures and one `unassigned` bucket containing seven samples. The benign cohort spans 28 package families. The largest named signature group, Mirai, contains 77 samples, so held-out fold sizes are uneven. Signatures are source metadata, not independently verified behavioral family labels.

| Feature set | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network | 0.804 | 0.804 | 0.780 | 0.848 | 0.813 | 0.887 | 105 | 33 | 21 | 117 |
| Host/eBPF | 0.957 | 0.957 | 0.963 | 0.949 | 0.956 | 0.994 | 133 | 5 | 7 | 131 |
| Hybrid | 0.949 | 0.949 | 0.977 | 0.920 | 0.948 | 0.994 | 135 | 3 | 11 | 127 |

Host-only leads accuracy and F1. Hybrid makes two fewer false positives than host-only, but four more false negatives; the ROC-AUC difference is less than 0.001. This pilot does not show an overall hybrid advantage on the real-sample cohort. Results are limited to these signature groups and a generated benign workload mix, so they are not a deployment-performance estimate. Dataset, out-of-fold predictions, metrics, and estimators are under `data/malware/revision3/family-heldout-stable-v1-20261014/`.

## P4 Feature-Family Balance and Label Scope

The offline P4-PCAP family-balanced analysis is under `data/benign/revision3/p4_pcap_family_balanced_ablation/`. The full dataset contains 138 benign and 138 malware samples. Benign samples have manifest-backed package and workload labels across 28 package families and 18 workload families. Per the collection history, the MalwareBazaar acquisition included ransomware and DDoS samples. The stored cohort merged the hash-named files into one input directory and did not preserve a hash-to-category mapping; none has a verified per-artifact subtype or malware-family label in this dataset. The current binary classifier detects malware vs. benign in this cohort; it is not yet a ransomware-vs-DDoS classifier.

The offline P4 pool has 29 base signal families, each represented by five window statistics. The eBPF pool has 35 base signal families with the same five statistics. The family-balanced model selects 29 eBPF signal families using training-fold-only mean mutual information across each family's summaries, then compares those 145 host columns with all 145 P4 columns. The previous top-145-individual-column selection is retained as `column_balanced_hybrid` for comparison; fold selections are in `p4_pcap_feature_family_selections.csv`.

PCAP window assignment can be reconstructed unambiguously for 188 of the 276 historical samples; the other 88 remain excluded from this CV because their missing process-start times allow multiple packet-to-window assignments. On the 188-sample subset, pooled out-of-fold accuracy / ROC-AUC is 0.8191 / 0.8747 for P4 network, 0.9947 / 0.9990 for eBPF host, 0.9947 / 0.9982 for full hybrid, and 0.9894 / 0.9984 for family-balanced hybrid. These are exploratory offline P4-shaped results, not measurements from a live P4 target; family balancing does not improve over host-only on this cohort.

Future malware runs record `sample_started_at_utc` in `run.json`, so PCAP windows can be assigned directly. Expand the corpus by adding independently sourced and verified malware families with behavior labels, then evaluate family-held-out folds. More hashes from the same unlabeled pool would increase the row count without establishing attack-type coverage or family-level generalization. Keep the existing isolated-VM and no-public-egress requirements for any future execution.

## MalwareBazaar Metadata Enrichment

`src/enrich_malwarebazaar.py` queries `get_info` for the 138 malware SHA-256 hashes and writes metadata-only JSONL records to `data/malware/revision3/malwarebazaar_metadata.jsonl`. It does not download or submit samples. The script reads `MALWARE_BAZAAR_API_KEY` from the environment (and accepts the legacy `MALWAREBAZAAR_AUTH_KEY` name), resumes completed hashes, retries transient failures, and waits one second between requests. The MalwareBazaar community API documents fair-use principles but no numeric rate limit for this query.

Enter the key without echoing it or putting it in shell history, make a one-hash probe, then run the remaining lookups:

```bash
install -d -m 700 "$HOME/.config/malwarebazaar"
read -rsp 'Replacement MalwareBazaar Auth-Key: ' MALWARE_BAZAAR_API_KEY
printf '\n'
printf 'export MALWARE_BAZAAR_API_KEY=%q\n' "$MALWARE_BAZAAR_API_KEY" > "$HOME/.config/malwarebazaar/env"
chmod 600 "$HOME/.config/malwarebazaar/env"
export MALWARE_BAZAAR_API_KEY
python3 src/enrich_malwarebazaar.py --limit 1
python3 src/enrich_malwarebazaar.py
unset MALWARE_BAZAAR_API_KEY
```

The returned `signature` is MalwareBazaar's family label and `tags` are its associated tags; retain these as source metadata and validate any ransomware/DDoS subtype mapping rather than inferring behavior from an ambiguous family or tag. Use `--dry-run` to inspect the hash list without network access. The API key is never written to the output.

## Revision 4 Malware Expansion

`src/acquire_malwarebazaar_samples.py` selects up to four previously unseen Linux ELF families per category: exact MalwareBazaar `ransomware` tags, exact `ddos` tags, and other ELF families without either tag. It excludes hashes and family signatures already present in revision 3, for a maximum of 12 downloads. MalwareBazaar documents a limit of 2,000 file downloads per IP per day. The tool stores only encrypted API ZIPs in `data/malware/revision4/incoming/`, verifies that each is a bounded, password-protected single-file ZIP, and records the API labels and archive checksums in `download_manifest.jsonl`; it does not extract or execute samples on the host.

The acquisition script reads `MALWARE_BAZAAR_API_KEY` from the environment first, then from the nearest ancestor `.env` file (the workspace-root `.env` in this setup). The pipeline, staging helper, and standalone collector read `guest_password` from that `.env` when `VBOX_GUEST_PASSWORD` is not exported; they do not prompt or print credential values. Keep the file private (`chmod 600 .env`). The pipeline stages archives into a separate snapshot, runs collection, merges telemetry, and writes validation output to `data/malware/revision4/pipeline.log`.

```bash
cd /home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010
bash scripts/run_malware_revision4_pipeline.sh
```

Candidate requests are limited to 100 results per category to keep API responses bounded. Downloaded archives remain encrypted on the host and are streamed through SHA-256 verification inside the isolated VM before the new snapshot is created. Staging failures restore the revision-3 baseline. The pipeline stops before staging if no verified archives were downloaded and summarizes collector statuses, telemetry rows, and merged record types at the end.

### Revision 4 Collection Results (2026-10-13)

The capped queries found no further unseen family signatures, so the run used six previously verified encrypted archives. All six runs completed with eBPF active, producing 14 telemetry windows, 3,351 eBPF events, and six PCAPs. The merged file contains 3,365 rows: 14 `telemetry_window` records and 3,351 `ebpf_event` records. Results are in `data/malware/revision4/combined_collector.csv` and `data/malware/revision4/runs/malware-v4-gui-20261013/`.

This is collection output, not a new model evaluation. The six hashes include three `DDoSAgent` signatures, one `Prometei`, one `FlylegitBot`, and one record without a signature (tagged `apex3` and `ddos`). Repeated hashes from one family do not establish family-level generalization, and MalwareBazaar tags alone do not verify runtime behavior.

### Additional MalwareBazaar Acquisition (2026-10-14)

The candidate selector searches up to 250 results for ransomware, DDoS, botnet, backdoor, trojan, stealer, and other ELF samples, while excluding hashes and signatures already represented in the prior metadata and valid revision-4 archives. It selected seven new signatures: LockBit and PromptLock (ransomware), XorDDoS and GetShell (DDoS), DeskRAT and BrickStorm (backdoor), and NoEscape (other ELF). All seven archives in `data/malware/revision4/incoming/` passed SHA-256, single-member ZIP, encrypted-member, sample-size, and mode-`0600` checks. They were first staged in `/home/csci/Downloads/malwarebazaar_linux_ransomware_ddos_all`, then collected from a dedicated directory in the clean `clean-emulated-hybrid-rf-v3h-plus7-runset-20261014` snapshot. The VM is powered off and isolated on `malnet` after collection. Four samples have no architecture value in MalwareBazaar metadata and remain marked `Unknown` in the inventory.

The seven runs produced 151 telemetry windows and 665,819 eBPF event rows; eBPF was active for every run. Sample outcomes were two `completed`, three `timeout`, one `nonzero_exit`, and one `signaled`. These outcomes do not define the malware labels. The LockBit run reached its time limit after 5,018 positive write events and 223,117,923 observed write bytes, making it a pronounced host-feature outlier. Results are retained for the cohort but should be interpreted with that single-sample influence in mind.

`data/malware/malware_sample_inventory_20261014.csv` is the Excel-friendly inventory of 151 samples (138 revision-3 originals, six previously collected revision-4 samples, and seven additions). It records signatures, tags, inferred OS/format, architecture, size, capture state, and inclusion in the expanded model. `src/build_malware_sample_inventory.py` regenerates it from the saved metadata and capture manifests. MalwareBazaar tags guide sampling but do not establish runtime behavior.

### Expanded 151-Sample Family-Grouped Evaluation (2026-10-14)

The expanded comparison uses 151 MalwareBazaar malware samples and the existing 138 generated benign workloads, for 289 labeled samples total. It uses 15 network and 45 host features with five-fold `StratifiedGroupKFold`; all 22 malware signature groups and 28 benign package groups remain wholly within one fold. The input collector is `data/malware/revision4/family-heldout-stable-151-v1-20261014/combined_collector_151.csv`; dataset, family metadata, reports, out-of-fold predictions, and models are in the same directory. The merge contains 981 telemetry windows and 810,041 eBPF event rows across all 151 malware samples.

| Feature set | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network | 0.792 | 0.791 | 0.794 | 0.815 | 0.804 | 0.849 | 106 | 32 | 28 | 123 |
| Host/eBPF | **0.941** | **0.943** | **0.993** | 0.894 | **0.941** | **0.995** | 137 | 1 | 16 | 135 |
| Hybrid | 0.938 | 0.939 | 0.978 | **0.901** | 0.938 | 0.992 | 135 | 3 | 15 | 136 |

Host-only leads on accuracy, balanced accuracy, F1, and ROC-AUC. Hybrid identifies one additional malware sample at the 0.5 threshold, but produces two additional false positives. Fold sizes are highly uneven: one test fold contains 105 malware and 35 benign samples, in part because the largest signature group contains 77 Mirai samples. The seven added runs include timeout and nonzero outcomes despite active sensors; MalwareBazaar metadata, not process exit status, defines the positive label. These results are exploratory, based on source signatures and generated benign controls, and do not establish an overall hybrid advantage or deployment performance.

### Per-Category Malware Outcomes

The saved grouped out-of-fold predictions were joined to the 151-sample inventory by SHA-256. This is a descriptive breakdown of the existing binary malware-versus-benign models, not a multiclass attack-family classifier. The category rule uses `malwarebazaar_category` when available; otherwise it uses exact tags in priority order: ransomware, DDoS, backdoor, botnet (including Mirai/Gafgyt), then other/unclassified. These are MalwareBazaar metadata labels, not verified behavior observed during execution.

This real-sample cohort covers five MalwareBazaar metadata groups only. It does not contain standalone scanning, password, XSS, injection, or MITM attack instances. TON_IoT includes several of those labels, but the prepared host/network files are category-level aggregates without event-level joins; adding them requires synchronized traces or paired controlled runs.

| Metadata category | Samples | MB signatures | Network detected | Host detected | Hybrid detected |
| --- | ---: | ---: | ---: | ---: | ---: |
| Backdoor | 2 | 2 | 2/2 | 2/2 | 2/2 |
| Botnet | 72 | 2 | 49/72 (0.681) | 65/72 (0.903) | 64/72 (0.889) |
| DDoS | 61 | 10 | 57/61 (0.934) | 55/61 (0.902) | 58/61 (0.951) |
| Other ELF | 4 | 4 | 4/4 | 3/4 (0.750) | 3/4 (0.750) |
| Ransomware | 12 | 7 | 11/12 (0.917) | 10/12 (0.833) | 9/12 (0.750) |

The current cohort therefore has different leaders by metadata group: host-only for botnet, hybrid for DDoS, and network-only for ransomware and other ELF. The 72 botnet samples come from only two MalwareBazaar signatures, and backdoor has only two samples, so those category estimates have very few independent families. These rates should not be read as a general sensor ranking: the target remains binary, and labels come from archive metadata rather than independently confirmed runtime behavior.

This is not yet a multiclass attack-type result. Three signatures have conflicting per-sample categories: Mirai has 56 botnet and 21 DDoS samples, DDoSAgent has two DDoS and one other-ELF sample, and Unassigned has five DDoS and three ransomware samples. The default five-fold grouped split leaves botnet absent from one training fold, while the default two-fold grouped split leaves other ELF absent from one training fold. A family-held-out multiclass score would therefore require adjudicated family labels or more independently verified samples; majority relabeling would hide the metadata conflict.

Execution outcomes are separate from malware labels. Every sample remains positive based on cohort provenance, including samples that timed out, exited nonzero, were signaled, or had a missing runtime dependency.

| Metadata category | Completed | Nonzero exit | Signaled | Timeout | Runtime dependency missing |
| --- | ---: | ---: | ---: | ---: | ---: |
| Backdoor | 0 | 0 | 0 | 2 | 0 |
| Botnet | 40 | 0 | 30 | 0 | 2 |
| DDoS | 24 | 23 | 2 | 9 | 3 |
| Other ELF | 3 | 0 | 1 | 0 | 0 |
| Ransomware | 6 | 1 | 2 | 3 | 0 |

Regenerate the machine-readable category metrics, execution outcomes, and per-sample decisions with:

```bash
python3 src/analyze_malware_category_results.py
```

Outputs are written to `data/malware/revision4/family-heldout-stable-151-v1-20261014/reports/category_analysis/`. `sample_predictions.csv` retains each model's out-of-fold score and TP/FN outcome alongside the metadata category and runner status.

## Controlled Hybrid Scenario v6 (2026-10-14)

This separate hypothesis test uses 20 controlled `attack_simulation` samples and 40 `benign_control` samples across five UDP scenario families and four paired variants per family. The attack scripts are safe simulations, not malware, and send only to the directed broadcast `10.0.0.255` on the isolated `malnet` network. `data/hybrid_scenarios/v6/validated-runs-20261014/` contains one manifest-validated capture per sample; retries are preferred only when their eBPF action counts and PCAP packet counts match the manifest.

The metrics below use those 60 selected original/retry captures; they do not include captures from the later scoped-collector smokes. A separate scoped attack/file-only pair produced identical 45-feature stable host vectors. The attack had one captured broadcast packet, while the file-only control's matched UDP send to `127.0.0.1` had none in the interface capture. The final Guest Control readiness path also passed a separate one-sample attack smoke; none of these smoke runs were added to the training cohort.

The model uses 15 network features and 45 host features. Host inputs are limited to matched send/socket/connect counts, successful open counts, and successful write counts/bytes. Intermittent syscall-entry counters and aggregate event/thread bookkeeping are excluded. This preserves the experiment's pairing contract: attack and file-only controls have equivalent host activity, while attack and network-only controls have equivalent network activity. `src/malware_runner.py` also now filters eBPF probes to the sample process tree and waits for bpftrace's confirmed probe-attachment message. The scoped collector passed an isolated smoke run with the expected sendto, write-byte, and PCAP counts.

Five-fold `StratifiedGroupKFold` held out each scenario family as a group. Pooled out-of-fold results:

| Feature set | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network | 0.667 | 0.700 | 0.500 | 0.800 | 0.615 | 0.750 | 24 | 16 | 4 | 16 |
| Host/eBPF | 0.667 | 0.700 | 0.500 | 0.800 | 0.615 | 0.750 | 24 | 16 | 4 | 16 |
| Hybrid | 0.933 | 0.900 | 1.000 | 0.800 | 0.889 | 1.000 | 40 | 0 | 4 | 16 |

On this designed simulation, hybrid improves over either individual sensor: it removes the 16 false positives from each single-sensor model while retaining the same 4 false negatives. Treat this as a controlled complementarity result, not malware-detection efficacy. There are only five independent scenario families; hybrid fold accuracy has a standard deviation of 0.149, and one held-out family accounts for all four false negatives at the default 0.5 threshold. More independent scenario families and thresholds chosen without test-fold access are needed before making broader claims.

## P4-Sourced Scenario Expansion and Feature Breadth (2026-10-14)

The canonical network contract is `p4_ebpf/hybrid_collector.py::NET_ZERO`: 29 window-level signal families. `analyze_p4_pcap_ablation.py::P4_FEATURES` has the exact same 29 names. The canonical HostMon output contract is `HOST_ZERO`: 26 window-level features. These counts are base signal families, not model columns.

Five safe scenario families were added under `data/hybrid_scenarios/v7/`: DNS-shaped UDP query, mixed-size UDP payloads, timed UDP burst, bounded TCP connect, and bounded TCP connect fan-out. Each has four variants and three conditions. `attack_simulation` stages and reads a temporary file and sends the scenario traffic to the internal sink; `benign_file_only` performs the same file work and directs the network action to loopback; `benign_network_only` sends the same scenario traffic to the sink without staging the file. They are generated simulations, not malware. The existing v1 HTTP/TCP/UDP cohort is retained as the five-family historical comparison.

The v7 sink-off captures are preserved at `data/hybrid_scenarios/v7/runs/p4-additions/` as diagnostics. The primary v7 captures at `data/hybrid_scenarios/v7/runs/p4-additions-sinkon/` were collected with the malware VM and `Sink` VM on `malnet` only. All 60 new runs completed with packet capture and eBPF active; their PCAPs align uniquely to telemetry windows. The sink-on smoke confirmed IPv4 TCP/UDP packets were visible to the offline P4 parser. No NAT, bridged, host-only, or public egress was enabled. The sink was shut down after collection.

The primary analysis reuses 60 v1 samples and 60 v7 samples. It includes only complete attack/file-only/network-only triplets for which every run has active sensors and unique PCAP alignment, and both the attack and network-only control contain at least one IPv4 TCP/UDP packet eligible for the P4 feature derivation. Twelve ambiguously aligned v1 samples exclude their whole paired triplets; one additional attack triplet fails the P4 packet-visibility gate. The resulting dataset has 28 triplets (84 rows: 28 attack simulations and 56 benign controls) in 9 independent scenario-family groups. Five-fold `StratifiedGroupKFold` holds out whole families. The threshold is fixed at 0.5. Host signal-family selection uses training-fold-only mean mutual information across each signal's five summaries.

Pooled out-of-fold results:

| Feature set | Derived columns | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P4-shaped network, offline | 145 | 0.631 | 0.545 | 0.421 | 0.286 | 0.340 | 0.714 | 45 | 11 | 20 | 8 |
| Observed eBPF host | 170 | 0.726 | 0.768 | 0.556 | 0.893 | 0.685 | 0.843 | 36 | 20 | 3 | 25 |
| Full hybrid | 315 | 0.881 | 0.848 | 0.875 | 0.750 | 0.808 | 0.953 | 53 | 3 | 7 | 21 |
| Equal signal-family hybrid | 290 | 0.905 | 0.884 | 0.885 | 0.821 | 0.852 | 0.952 | 53 | 3 | 5 | 23 |

The equal-budget hybrid's mean family-level balanced-accuracy gain over the better single sensor is 0.076. A bootstrap over the 9 held-out families gives a 95% interval of [-0.104, 0.229], which includes zero. Fold standard deviation in balanced accuracy is 0.149 for the equal-budget hybrid, 0.065 for host/eBPF, and 0.141 for offline P4-shaped network. This supports a conditional complementarity hypothesis for these designed interactions, but nine families and the wide interval do not establish a general hybrid advantage. The pair audit confirms the file-write event count and bytes match attack/file-only in all 28 included triplets. Broader host summaries match exactly in 90.8% of fields on average; P4-shaped network summaries match exactly in 44.5% of fields on average between attack and network-only controls, so these are semantically matched, not byte-for-byte identical sensor vectors.

Feature breadth, counting raw signal families separately from five derived sample summaries:

| Sensor / budget | Base signal families | Derived sample columns | Evidence in this cohort |
| --- | ---: | ---: | --- |
| Canonical P4 network collector | 29 | 145 | Offline PCAP-derived approximation |
| Canonical HostMon collector | 26 | 130 | Source schema only; HostMon was not collected |
| Observed eBPF host telemetry | 34 | 170 | Collected syscall/event counters and byte value; not the HostMon schema |
| Full observed eBPF + offline P4-shaped | 63 | 315 | Combined, unequal signal budget |
| Equal-family eBPF + P4-shaped | 58 | 290 | 29 eBPF families selected in each training fold + all 29 P4 families |

The machine-readable `feature_contract.csv` maps all 29 P4, 26 HostMon, and 34 observed eBPF families to their source signals and summaries; `feature_breadth.csv` records the budgets. Other outputs are `p4_emulated_scenario_dataset.csv`, `p4_emulated_scenario_dataset.feature_columns.json`, `pcap_alignment_audit.csv`, `paired_control_audit.csv`, `host_signal_family_selections.csv`, `out_of_fold_predictions.csv`, and `analysis_report.json`, all under `data/hybrid_scenarios/v7/p4_family_breadth_20261014/`.

**Parity boundary:** the analysis derives P4-shaped features from PCAPs; it does not read a live P4 target. The Tofino SDE executables were unavailable in this environment. The P4 source allocates 65,536 CRC16 flow buckets, while the offline analyzer uses exact IPv4/protocol/endpoint tuples, so collisions, target direction behavior, hardware timestamp units, and register wraparound are not validated. The current `read_registers_with_index.py` requests eight registers absent from the inspected `ingress.p4`: `reg_bytes_ba`, `reg_fin`, `reg_iat_cnt`, `reg_iat_last`, `reg_iat_max`, `reg_iat_min`, `reg_iat_sum`, and `reg_pkts_ba`; missing reads default to zero. This source/build mismatch must be resolved before claiming collector parity on hardware. The experiment's host side is observed eBPF telemetry, not the canonical 26-field HostMon output.

Reproduce the additions and evaluation from the study root (with the existing internal-only sink configured and `.env` available):

```bash
python3 workloads/generate_hybrid_scenarios.py \
  --scenario-pack p4-additions --replicates 4 \
  --output-dir data/hybrid_scenarios/v7-replay/workloads \
  --manifest data/hybrid_scenarios/v7-replay/scenario_manifest.csv
ENV_FILE="$PWD/../../.env" \
SCENARIO_DIR="$PWD/data/hybrid_scenarios/v7-replay" \
SCENARIO_SNAPSHOT=clean-emulated-hybrid-scenarios-p4-replay \
GUEST_ROOT=/home/csci/Downloads/hybrid-scenarios-p4-replay \
  bash scripts/prepare_hybrid_scenarios.sh
VBoxManage startvm Sink --type headless
ENV_FILE="$PWD/../../.env" bash scripts/vbox_malware_batch.sh \
  --vm Ubuntu-Clean-24.04 --guest-user csci \
  --guest-malware-dir /home/csci/Downloads/hybrid-scenarios-p4-replay/workloads \
  --guest-runner /home/csci/Downloads/malware_runner.py \
  --snapshot clean-emulated-hybrid-scenarios-p4-replay \
  --output-dir data/hybrid_scenarios/v7-replay/runs/p4-additions-sinkon \
  --timeout 20 --window-sec 0.5 --iface enp0s3 --ebpf
VBoxManage controlvm Sink acpipowerbutton
python3 src/analyze_p4_emulated_scenarios.py \
  --new-manifest data/hybrid_scenarios/v7-replay/scenario_manifest.csv \
  --new-runs data/hybrid_scenarios/v7-replay/runs/p4-additions-sinkon
```

## Paired Network-Sink Malware Pilot (2026-10-14)

This exploratory pilot compares the same 12 MalwareBazaar ELF samples and 12 benign package workloads with the isolated `Sink` VM powered off (`sink_off`) and with INetSim plus local DNS active on `malnet` (`sink_on`). Both VMs used only the internal `malnet` adapter; no NAT, bridged, host-only, default route, or public DNS was enabled. The sink's Netplan configuration now assigns `10.0.0.1/24` to `enp0s3`. Its dnsmasq config binds to the internal interface, uses `no-resolv`, and maps names to `10.0.0.1`.

The pilot collectors expose different raw eBPF schemas: the malware runs have nine model counters, while benign runs have only three in common. To avoid treating uncollected counters as zero, both conditions use the intersection of three network signals (`net_packets_captured`, `net_bytes_captured`, `net_flow_count`) and three host signals (`ebpf_connect_count`, `ebpf_sendto_count`, `ebpf_socket_count`). Each base signal is summarized by mean, max, sum, standard deviation, and active-window count (15 columns per sensor; 30 hybrid columns). The 24 samples are grouped by malware signature or benign package family and evaluated with five-fold `StratifiedGroupKFold`, seed 42. Both conditions use the same samples, feature definitions, and fold assignments.

Pooled out-of-fold metrics:

| Condition | Feature set | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Sink off | Network | 0.625 | 0.625 | 0.615 | 0.667 | 0.640 | 0.566 | 7 | 5 | 4 | 8 |
| Sink off | Host/eBPF | 0.625 | 0.625 | 0.667 | 0.500 | 0.571 | 0.611 | 9 | 3 | 6 | 6 |
| Sink off | Hybrid | 0.583 | 0.583 | 0.600 | 0.500 | 0.545 | 0.604 | 8 | 4 | 6 | 6 |
| Sink on | Network | 0.667 | 0.667 | 0.700 | 0.583 | 0.636 | 0.729 | 9 | 3 | 5 | 7 |
| Sink on | Host/eBPF | 0.667 | 0.667 | 0.750 | 0.500 | 0.600 | 0.694 | 10 | 2 | 6 | 6 |
| Sink on | Hybrid | 0.625 | 0.625 | 0.615 | 0.667 | 0.640 | 0.688 | 7 | 5 | 4 | 8 |

Network-only accuracy increased by 0.042 and ROC-AUC by 0.163 with the sink on, but fold ROC-AUC standard deviations are 0.330 (off) and 0.351 (on). With only 12 malware and 12 benign groups, these scores are highly variable and are not evidence of a reliable performance gain. Malware execution outcomes were 5 completed, 2 signaled, 1 timeout, and 4 nonzero exits with the sink off; with the sink on they were 5 completed, 2 signaled, 2 timeouts, and 3 nonzero exits. All 12 samples per condition have archived telemetry; execution status does not determine the malware label. The final DNS-ready sink-on benign gate completed all 12 controls. Earlier sink-on benign attempts, before DNS was configured, are preserved but are not used in the model.

| Condition | Class | Captured packets | Captured bytes | Flows |
| --- | --- | ---: | ---: | ---: |
| Sink off | Benign | 39 | 2,600 | 16 |
| Sink off | Malware | 60 | 3,491 | 19 |
| Sink on | Benign | 79 | 8,052 | 19 |
| Sink on | Malware | 166 | 16,087 | 114 |

All artifacts are under `data/malware/revision4/network_sink_pilot_20261014/`: selection manifests are in `selection/`; per-sample archives, logs, and merged collectors are in `sink_off/` and `sink_on/`; aligned 3+3 datasets, feature-column manifests, out-of-fold predictions, metrics, feature importances, and estimators are in each condition's `model/` directory. Use `sink_on/benign_dns_ready/combined_collector.csv` for the final valid sink-on benign cohort. The paired model reports are `sink_off/model/reports_common_3plus3/cv_metrics.json` and `sink_on/model/reports_common_3plus3/cv_metrics.json`.

The selected telemetry merge, labeled dataset, reports, and estimators are `data/hybrid_scenarios/v6/combined_collector_validated.csv`, `data/hybrid_scenarios/v6/labeled_sample_dataset_stable.csv`, `data/hybrid_scenarios/v6/reports/stable-features/`, and `data/hybrid_scenarios/v6/models/stable-features/`. Guest Control readiness checks now use five-second probes with a 60-second deadline, report progress, and show the final VBox diagnostic instead of silently polling for six minutes.

## MalwareBazaar Expanded Collection and Balanced Evaluation (2026-10-14)

The additional MalwareBazaar search selected and downloaded 38 encrypted ELF samples. The archives were SHA-256 verified and staged in `/home/csci/Downloads/malwarebazaar_expanded_20261014`; collection used the clean `clean-emulated-hybrid-expanded-20261014` snapshot, a 20-second run limit, packet capture, and eBPF. Both VMs remained on the isolated `malnet` internal network, and both were powered off after collection.

| MalwareBazaar selection category | Downloaded | Distinct signatures |
| --- | ---: | ---: |
| Backdoor | 5 | 4 |
| Botnet | 8 | 6 |
| DDoS | 8 | 7 |
| Other ELF | 7 | 4 |
| Ransomware | 8 | 5 |
| Trojan | 2 | 1 |
| Stealer | 0 | 0 |

These are source tags and selection strata, not independently verified runtime behaviors. No new stealer candidates were returned by the bounded search. Of the 38 runs, 35 produced archived telemetry: 21 runtime-completed, 8 nonzero exit, 3 signaled, 2 timed out, and 1 missing runtime dependency. The other three were retained in the inventory but excluded from model fitting because no telemetry archive was available: RedGoBot/DDoS (`output_archive_failed`), Mirai/botnet (`output_copy_failed`), and Moobot/other ELF (`runner_failed`). Retrying those three reproduced the same collection statuses. Runtime outcome does not change the malware label.

The expanded binary dataset combines the prior 151 captured malware samples, 35 new captured samples, and 138 benign controls (324 total). Malware samples are grouped by MalwareBazaar signature and benign controls by package family: 29 malware groups and 28 benign groups remain within folds in five-fold `StratifiedGroupKFold`. The comparison uses a fixed equal sensor budget: nine network signal families and nine host/eBPF signal families, each summarized by five statistics (45 columns per sensor; 90 hybrid columns).

| Feature set | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network (45 columns) | 0.895 | 0.896 | 0.922 | 0.892 | 0.907 | 0.941 | 124 | 14 | 20 | 166 |
| Host/eBPF (45 columns) | 0.920 | 0.922 | 0.949 | 0.909 | 0.929 | 0.983 | 129 | 9 | 17 | 169 |
| Hybrid (90 columns) | 0.929 | 0.933 | 0.966 | 0.909 | 0.936 | 0.989 | 132 | 6 | 17 | 169 |

Hybrid has the highest pooled balanced accuracy, 1.1 percentage points above host-only, with the same recall and three fewer false positives. This is a modest result on this cohort, not evidence of a general hybrid advantage. Relative to the prior 151-malware balanced-feature run, the fold composition changed as well as the sample count, so score movement cannot be attributed to sample addition alone.

Out-of-fold malware detection by metadata category is descriptive binary malware-versus-benign recall, not multiclass attack classification. Counts below include only samples with archived telemetry; three additional acquisitions are listed in the inventory as uncollected.

| Metadata category | Modeled samples / acquired | Network detected | Host detected | Hybrid detected |
| --- | ---: | ---: | ---: | ---: |
| Backdoor | 7 / 7 | 5/7 | 7/7 | 7/7 |
| Botnet | 79 / 80 | 74/79 | 77/79 | 77/79 |
| DDoS | 68 / 69 | 63/68 | 59/68 | 59/68 |
| Other ELF | 10 / 11 | 7/10 | 7/10 | 6/10 |
| Ransomware | 20 / 20 | 16/20 | 17/20 | 18/20 |
| Trojan | 2 / 2 | 1/2 | 2/2 | 2/2 |

The unified score file is `data/malware/revision4/family-heldout-balanced-186-v1-20261014/reports/balanced_9network_9host/category_analysis/overall_and_category_scores.csv`. Its `overall` rows score all 324 out-of-fold predictions. Each `attack_category_vs_benign` row scores that category's malware against the same 138 benign controls, excluding other malware categories. These are slices of the globally trained binary models, not independently trained category classifiers; the repeated benign controls and small signature counts make category metrics descriptive. The file includes accuracy, balanced accuracy, precision, recall, F1, ROC-AUC, confusion counts, sample counts, and signature counts.

Several signatures span multiple MalwareBazaar categories, including Mirai, Gafgyt, and DDoSAgent. Treat these category rates as exploratory metadata slices; they do not establish verified attack-type performance. Full sample outcomes and predictions are in `data/malware/revision4/family-heldout-balanced-186-v1-20261014/reports/balanced_9network_9host/category_analysis/`; the 189-row inventory is `data/malware/malware_sample_inventory_expanded_20261014.csv`.

Rebuild the new collector merge, dataset, equal-budget model, inventory, and category report from the study root:

```bash
python3 scripts/merge_collector_csvs.py \
  data/malware/revision4/runs/malware-v5-expanded-20261014 \
  --output data/malware/revision4/combined_collector_expanded_20261014.csv

python3 src/build_dataset.py \
  --malware-csv data/malware/revision4/family-heldout-stable-151-v1-20261014/combined_collector_151.csv \
  --malware-csv data/malware/revision4/combined_collector_expanded_20261014.csv \
  --malware-family-metadata data/malware/revision4/family-heldout-stable-151-v1-20261014/malware_family_metadata_151.jsonl \
  --malware-family-metadata data/malware/revision4/incoming/expanded_20261014_download_manifest.jsonl \
  --benign-csv data/benign/revision3/combined_collector.csv \
  --benign-manifest data/benign/revision3/workload_manifest.csv \
  --output data/malware/revision4/family-heldout-balanced-186-v1-20261014/labeled_sample_dataset.csv

python3 src/build_feature_breadth_dataset.py \
  --dataset data/malware/revision4/family-heldout-balanced-186-v1-20261014/labeled_sample_dataset.csv \
  --collector data/malware/revision4/family-heldout-stable-151-v1-20261014/combined_collector_151.csv \
  --collector data/malware/revision4/combined_collector_expanded_20261014.csv \
  --collector data/benign/revision3/combined_collector.csv \
  --output data/malware/revision4/family-heldout-balanced-186-v1-20261014/labeled_sample_dataset_full_35host_9network.csv

python3 src/train_compare.py \
  --dataset data/malware/revision4/family-heldout-balanced-186-v1-20261014/labeled_sample_dataset_full_35host_9network.csv \
  --feature-columns data/malware/revision4/family-heldout-stable-151-v1-20261014/feature_breadth_comparison/balanced_9network_9host_feature_columns.json \
  --reports-dir data/malware/revision4/family-heldout-balanced-186-v1-20261014/reports/balanced_9network_9host \
  --models-dir data/malware/revision4/family-heldout-balanced-186-v1-20261014/models/balanced_9network_9host \
  --folds 5 --seed 42

python3 src/build_malware_sample_inventory.py --include-expanded \
  --output data/malware/malware_sample_inventory_expanded_20261014.csv

python3 src/analyze_malware_category_results.py \
  --inventory data/malware/malware_sample_inventory_expanded_20261014.csv \
  --predictions data/malware/revision4/family-heldout-balanced-186-v1-20261014/reports/balanced_9network_9host/out_of_fold_predictions.csv \
  --output-dir data/malware/revision4/family-heldout-balanced-186-v1-20261014/reports/balanced_9network_9host/category_analysis
```

### Additional MalwareBazaar Batch and Updated Scores (2026-10-14)

A further plan-only MalwareBazaar search found 42 additional unique encrypted ELF archives. They were SHA-256 verified, staged into `/home/csci/Downloads/malwarebazaar_additional_20261014`, and collected from the separate `clean-emulated-hybrid-additional-20261014` snapshot. Both VMs used only the internal `malnet` network and were powered off after collection.

| Selection category | Downloaded |
| --- | ---: |
| Backdoor | 5 |
| Botnet | 10 |
| DDoS | 13 |
| Other ELF | 7 |
| Ransomware | 7 |
| Trojan / stealer | 0 |

Thirty-eight runs produced archived telemetry, 195 telemetry windows, and 21,189 eBPF event rows. Runtime outcomes among those 38 were 25 completed, 7 nonzero exits, 2 signaled, and 4 timeouts. Three Mirai/botnet output transfers failed again on retry; one Mirai/DDoS executable was incompatible with the guest architecture and produced no sensor telemetry. These four remain in the inventory, but are not model inputs. The previous 38-sample expansion had 35 telemetry captures and 3 collection failures, so the combined inventory contains 231 acquisitions and the combined model uses 224 malware captures plus 138 benign controls.

The updated five-fold `StratifiedGroupKFold` uses 29 malware signature groups and 28 benign package groups. All 57 groups stay within a single fold. Network and host each use 45 columns from nine signal families; hybrid uses 90 columns.

| Feature set | Accuracy | Balanced accuracy | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Network (45 columns) | 0.870 | 0.874 | 0.928 | 0.857 | 0.891 | 0.929 | 123 | 15 | 32 | 192 |
| Host/eBPF (45 columns) | 0.914 | 0.918 | 0.957 | 0.902 | 0.929 | 0.976 | 129 | 9 | 22 | 202 |
| Hybrid (90 columns) | 0.928 | 0.929 | 0.958 | 0.924 | 0.941 | 0.985 | 129 | 9 | 17 | 207 |

| Metadata category | Modeled / acquired | Network BA | Host BA | Hybrid BA |
| --- | ---: | ---: | ---: | ---: |
| Backdoor | 12 / 12 | 0.904 | 0.967 | 0.967 |
| Botnet | 86 / 90 | 0.870 | 0.933 | 0.962 |
| DDoS | 80 / 82 | 0.896 | 0.917 | 0.924 |
| Other ELF | 17 / 18 | 0.887 | 0.850 | 0.850 |
| Ransomware | 27 / 27 | 0.798 | 0.893 | 0.875 |
| Trojan | 2 / 2 | 0.946 | 0.967 | 0.967 |

Each category row scores that metadata category against the same 138 benign controls using the global model's out-of-fold predictions; other malware categories are excluded from that row's negative class. These are descriptive slices, not independently trained category classifiers. Category labels come from MalwareBazaar metadata, and the two-sample Trojan result is especially tentative. Compared with the 186-malware run above, fold membership changes with the added samples, so the score difference cannot be attributed to the added batch alone.

The updated score file is `data/malware/revision4/family-heldout-balanced-224-v1-20261014/reports/balanced_9network_9host/category_analysis/overall_and_category_scores.csv`. It contains the overall rows and all six category scores with accuracy, balanced accuracy, precision, recall, F1, ROC-AUC, confusion counts, and sample/signature counts. The 231-row inventory is `data/malware/malware_sample_inventory_all_expansions_20261014.csv`.

Reproduce the updated dataset, evaluation, inventory, and score file from the study root:

```bash
python3 scripts/merge_collector_csvs.py \
  data/malware/revision4/runs/malware-v6-additional-20261014 \
  --output data/malware/revision4/combined_collector_additional_20261014.csv

python3 src/build_dataset.py \
  --malware-csv data/malware/revision4/family-heldout-stable-151-v1-20261014/combined_collector_151.csv \
  --malware-csv data/malware/revision4/combined_collector_expanded_20261014.csv \
  --malware-csv data/malware/revision4/combined_collector_additional_20261014.csv \
  --malware-family-metadata data/malware/revision4/family-heldout-stable-151-v1-20261014/malware_family_metadata_151.jsonl \
  --malware-family-metadata data/malware/revision4/incoming/expanded_20261014_download_manifest.jsonl \
  --malware-family-metadata data/malware/revision4/incoming/additional_20261014_download_manifest.jsonl \
  --benign-csv data/benign/revision3/combined_collector.csv \
  --benign-manifest data/benign/revision3/workload_manifest.csv \
  --output data/malware/revision4/family-heldout-balanced-224-v1-20261014/labeled_sample_dataset.csv

python3 src/build_feature_breadth_dataset.py \
  --dataset data/malware/revision4/family-heldout-balanced-224-v1-20261014/labeled_sample_dataset.csv \
  --collector data/malware/revision4/family-heldout-stable-151-v1-20261014/combined_collector_151.csv \
  --collector data/malware/revision4/combined_collector_expanded_20261014.csv \
  --collector data/malware/revision4/combined_collector_additional_20261014.csv \
  --collector data/benign/revision3/combined_collector.csv \
  --output data/malware/revision4/family-heldout-balanced-224-v1-20261014/labeled_sample_dataset_full_35host_9network.csv

python3 src/train_compare.py \
  --dataset data/malware/revision4/family-heldout-balanced-224-v1-20261014/labeled_sample_dataset_full_35host_9network.csv \
  --feature-columns data/malware/revision4/family-heldout-stable-151-v1-20261014/feature_breadth_comparison/balanced_9network_9host_feature_columns.json \
  --reports-dir data/malware/revision4/family-heldout-balanced-224-v1-20261014/reports/balanced_9network_9host \
  --models-dir data/malware/revision4/family-heldout-balanced-224-v1-20261014/models/balanced_9network_9host \
  --folds 5 --seed 42

python3 src/build_malware_sample_inventory.py --include-additional \
  --output data/malware/malware_sample_inventory_all_expansions_20261014.csv

python3 src/analyze_malware_category_results.py \
  --inventory data/malware/malware_sample_inventory_all_expansions_20261014.csv \
  --predictions data/malware/revision4/family-heldout-balanced-224-v1-20261014/reports/balanced_9network_9host/out_of_fold_predictions.csv \
  --output-dir data/malware/revision4/family-heldout-balanced-224-v1-20261014/reports/balanced_9network_9host/category_analysis
```