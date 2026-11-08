# Corrected P4 CSVs

These offline-derived outputs replace only the 29 `p4_network` columns in the
original collection. The original captures, run metadata, archives, CSVs, and
previous model results are preserved. No samples were executed again.

The original runner processed all PCAP packets before summarizing windows,
allowing final flow state to erase earlier-window packet deltas. Reconstruction
here advances flow state chronologically using the repository's
`p4_ebpf/analyze_p4_pcap_ablation.py` implementation. All 1,474 samples have exact
packet/window counter alignment. P4 values changed for 382 samples (38,338 cells).
These remain PCAP-derived P4-shaped features, not live P4-register observations.

## Outputs

- `exports/malware-training-535.csv`: 521 samples, 1,584 windows, 895,902 eBPF events.
- `exports/malware-holdout-323.csv`: 315 samples, 1,491 windows, 238,490 eBPF events.
- `exports/benign-training-500.csv`: 500 samples, 2,227 windows, 251,777 eBPF events.
- `exports/benign-validation-138.csv`: 138 samples, 727 windows, 236,768 eBPF events.
- `telemetry/<cohort>/<sample_artifact>/telemetry.csv`: corrected per-sample windows.
- `reconstruction_audit.csv`: original input hashes, corrected CSV hashes, and alignment diagnostics.
- `reconstruction_summary.json`: implementation hashes and collection provenance.

Only host-completed samples with pinned original runner provenance are included.
Non-P4 telemetry values and raw eBPF events are retained. The original runner
hash identifies acquisition; reconstruction has separate implementation hashes.
The collector source fix changes its hash, so it must not be substituted into an
old version-pinned snapshot or resume session without explicit restaging.

## Frozen-Split Evaluation

Results are in `../modeling/hostmon-p4-family10-corrected-20261018/`.
The exact sample assignments and feature columns from
`../modeling/hostmon-p4-family10-20261018/` were retained and checked.
Training has 95 malware and 500 benign samples; validation has 741 malware and
138 benign samples. P4 and host each have 29 signals (145 aggregated columns);
hybrid has 58 signals (290 columns). Five singleton families are training-only.

| Model | Accuracy | Balanced accuracy | ROC-AUC | TN | FP | FN | TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| P4 | 0.820250 | 0.698791 | 0.744338 | 72 | 66 | 92 | 649 |
| HostMon/eBPF | 0.990899 | 0.994602 | 0.999990 | 138 | 0 | 8 | 733 |
| Hybrid | 0.989761 | 0.993927 | 0.999980 | 138 | 0 | 9 | 732 |

The host predictions are unchanged within floating-point precision. This is
within-family validation, not unseen-family validation. It does not demonstrate
an improvement from hybrid fusion on this cohort.