# Corrected host collector pilot: completed

All 40 captures are available and audited. Training contains 10 malware and
10 benign samples; validation contains another 10 malware and 10 benign samples.
Each capture uses the same five-second observation horizon, ten half-second
windows, closed stdin, and common Bash exec launcher. P4 features are PCAP
reconstructions, not live switch-register observations.

## Collection corrections

- Raw syscall sequences pass through the chronological sample-process lineage
  filter instead of including unrelated runner children.
- The observation cutoff excludes shutdown activity, while recording continues
  after an early root-process exit to retain descendants within the horizon.
- Filtered raw syscalls are archived separately in `syscall_events.csv`.
- Worker-thread exit no longer removes kernel tracking for the entire process.
- Native benign commands replace generated shell workloads. Original command
  basenames are retained because renamed Ubuntu coreutils multicall binaries
  fail dispatch. All twenty payloads passed execution preflight and completed
  successfully during recorded runs.
- Isolated DNS and HTTP responses were verified at `10.0.0.1`; no host-connected
  network adapter was enabled. Clipboard and drag-and-drop were disabled in
  the staged collection snapshot.

Runner schema: `2026-10-18.1`.
Runner SHA-256:
`e7f935b497800d84f1a8675d2c0c659741f66158c69dc9835245932cc205f67c`.

The twenty corrected malware captures were reused from
`../telemetry-2026-10-18.1-pilot40-fixed-20261018/` with matching runner hash and
observation settings. Twenty native benign controls were recollected here.
The earlier failed benign controls and failed-preflight manifests are preserved
outside this analysis. The source is recorded in `pilot_manifest.json`.

## Results

All three models use the same split, median imputation fitted on training only,
500-tree random forest, seed 42, and decision threshold 0.5. Each raw signal has
five summaries: mean, maximum, sum, standard deviation, and active-window count.
Metadata, filenames, return codes, and collection status are not model inputs.

| Model | Signals / columns | Accuracy | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P4 | 29 / 145 | 60% | 0.62 | 7 | 3 | 5 | 5 |
| Native HostMon fields | 26 / 130 | 95% | 0.99 | 9 | 1 | 0 | 10 |
| Hybrid | 55 / 275 | 95% | 1.00 | 9 | 1 | 0 | 10 |

Balanced accuracy equals accuracy because validation has equal class counts.
Host and hybrid both falsely flag `bzip2` and detect all ten validation malware
samples. Hybrid ranks the examples better in this tiny set, but does not improve
thresholded accuracy. Thresholds were not tuned on validation.

## Interpretation

The old peak-dup2 shortcut is gone: every training sample in both classes has
peak count 3. A training-fitted decision stump on that feature gives 50%
validation accuracy, compared with 95% on the earlier shell-workload subset.

Strong host separation remains in syscall repetition and entropy. In validation,
the median peak top-syscall frequency is approximately 0.28 for benign and 0.73
for malware; median maximum mean entropy is approximately 4.01 versus 2.84.
The false-positive `bzip2` has frequency 0.53 and entropy 2.73, consistent with
those separating patterns. These are observed correlations, not a causal proof
that the model learned malicious intent.

All benign samples have raw syscall activity in only one window. Malware
validation samples have a median of five active windows. A fixed observation
horizon removes unequal window counts, not differences in workload lifetime.
The models can still exploit those lifecycle differences.

The collector defects were real, but were not demonstrated to be the sole
explanation of earlier host accuracy. This pilot changes sample count, benign
workloads, launch structure, networking, observation horizon, and filtering;
its 95% cannot be treated as a controlled decrease from the earlier 97-99%.

## Quality checks and limits

All forty captures passed pinned provenance, sample separation, exact horizon,
raw-event lineage, and per-window raw syscall count checks. Saved predictions
reproduce all reported main-model metrics. The exact native 26-field contract
matches the repository collector. Twelve focused collector tests passed.

One malware training trace reports 149,064 lost eBPF events. Excluding that
sample leaves host and hybrid accuracy at 95%; P4 becomes 55% with the smaller
training set. This sensitivity is recorded rather than silently discarding
or treating the trace as complete.

Malware training outcomes include three completed, three signaled, two nonzero
exits, one timeout, and one missing dependency. Malware validation includes
eight completed, one signaled, and one nonzero exit. Successful collector output
does not establish successful or representative malware execution.

Validation has only twenty samples: one mistake changes accuracy by five
percentage points. The approximate binomial Wilson interval for 19/20 is
76.4-99.1%; related samples make independence an additional assumption.
This is not family-held-out validation, and benign package groups overlap.
Native field names also do not establish equivalence to the live repository
HostMon implementation. A larger, behaviorally varied, group-disjoint cohort
is needed before claiming generalization or a hybrid advantage.

## Artifacts

- `modeling/metrics.json`: metrics, trace-loss sensitivity, and dup2 control.
- `modeling/capture_audit.json`: hashes, raw command counts, and tracing warnings.
- `modeling/validation_predictions.csv`: per-sample main-model predictions.
- `modeling/feature_columns.json`: exact model inputs.
- `modeling/feature_importances.csv`: random-forest impurity importances.
- `modeling/models/`: three fitted models.

The collection VM is powered off after clean-snapshot restoration. The sink
was already running when this collection resumed and was left running.