# Host performance investigation

Offline investigation on 200 previously collected samples: 100 training and
100 validation, each balanced 50 malware / 50 benign. No samples were executed,
collector logic changed, or original outputs overwritten. All results below
are exploratory, not an independent confirmatory test.

## Assessment

The high host score is reproducible, but it is not trustworthy evidence of
general malware-detection performance yet. There is a confirmed process-filtering
defect in raw syscall sequence collection, plus strong evidence of an easy
shell-workload-versus-executable distinction. These can coexist with genuine
malware behavior; this investigation cannot quantify each contribution.

## Confirmed collector defect

In `src/malware_runner.py`, `ebpf_program` tracks all direct children of the
runner and their descendants. `_record_host_syscall` accepts their raw syscalls
after the sample start without checking the sample PID or descendant set.
The later `collect` method filters specific named events, but does not repeat
that filtering for the already-aggregated raw syscall sequence statistics.

`EbpfCollector.stop` launches a `sudo` child while tracing is still active.
That is a concrete runner-helper path into the raw sequence. A synthetic check
set sample PID 100, injected a raw syscall from PID 999, and confirmed PID 999
appeared in `host_stats_by_window`. No tracing or workload execution was needed.

This affects raw sequence statistics and process counts, not necessarily every
field in the native 26-field group. The stricter filtering on named-event
counters does not remove the separate workload-design confound.

The archived `ebpf_events.csv` files contain named events, not raw syscall rows.
Therefore raw sequence statistics cannot be repaired exactly from these CSVs.
The synthetic reproduction proves the acceptance bug, not the fraction of
observed model accuracy attributable to it.

## Fixed-Split Experiments

Each row uses the same 100 training and 100 validation samples. Forest settings
are unchanged. Single-feature thresholds are fitted on training only.

| Diagnostic | Validation accuracy |
| --- | ---: |
| Original 26 native fields, five summaries each | 97% |
| Native fields, maximum summary only | 95% |
| Sequence-shape fields, mean/max summaries only | 100% |
| Seven filtered HostMon action fields, five summaries each | 83% |
| First window only, 26 native fields | 100% |
| First window only, P4 | 54% |
| Window-count-only decision stump | 68% |
| Peak dup2-count-only decision stump | 95% |
| Maximum syscall run-length statistic decision stump | 92% |
| Native model with shuffled training labels | 56% |

The run-length stump uses `host_avg_run_length_max__max`, not
`host_max_run_length_max__max`. Sequence-shape and first-window models still
use potentially contaminated raw sequence fields. The 83% action-only result
also removes useful sequence information, so its decrease is not an estimate
of the contamination effect.

## Workload and execution differences

- Benign inputs are generated Bash workloads; malware inputs are executables.
- Peak `dup2` count is at least 3 for every benign sample. Malware median is 2
  in both splits. A training-derived threshold of 2.5 alone gives 95% accuracy.
- Benign scripts can end in `curl --max-time 5 http://example.com/...` under
  `set -e`. The logs confirm 49/100 benign samples hit DNS-resolution timeouts
  and returned code 28. Another four benign samples had other nonzero exits.
- Sixteen of the 100 malware samples segfaulted. Eighteen malware samples had
  at most ten accepted named events; no benign samples were that quiet.
- Collection stops when the root process exits. Successful launch or return
  code zero therefore does not establish sustained or successful malicious
  execution, particularly for payloads that daemonize.

These differences make launch structure, interpreter/library behavior, and
failed execution plausible predictors. Duration alone is insufficient: its
stump scored 68%, and strong host separation remained in first-window data.
Matching network timeouts and workload launch structure is necessary before
interpreting these scores as malware-specific discrimination.

## Family and package holdout

Five-fold stratified group CV used all 200 samples, grouping malware by family
label and benign by package. There were 48 groups; each group appeared in
validation exactly once, with no group crossing a fold's train/test boundary.

| Model | Pooled out-of-fold accuracy | False positives | Missed malware |
| --- | ---: | ---: | ---: |
| P4 | 64.5% | 45 | 26 |
| Native HostMon | 97.5% | 4 | 1 |
| Native HostMon + P4 | 98% | 4 | 0 |

Family overlap is therefore not a sufficient explanation on this subset.
This grouping relies on available labels, not verified binary similarity.
CV training sizes differ from the fixed split. The hybrid difference is one
sample, not convincing evidence of a benefit. There was one validation sample
whose native feature vector exactly matched training vectors; exact feature
duplicates likewise do not explain most of the accuracy.

## Recommended next step

Fix raw syscall filtering before any new validation. Use a common launch
wrapper for both classes, capture a fixed observation horizon including child
processes, and archive the raw syscall stream with process lineage. Build a
small matched benign/malware pilot with controlled DNS and network responses,
and separately report crashes, dependency failures, and minimal execution.
Do not tune the models until that pilot is collected and the collection checks
pass. No new malware execution is authorized or performed by this report.

Machine-readable evidence is in `diagnostics.json`. The offline runner is
`scripts/investigate_host_separability.py`, relative to the study root.