# Training-Only Fusion And Background-Traffic Gate

Date: 2026-10-22. These are exploratory diagnostics, not a new detector
performance evaluation or a released collection protocol.

## Work Completed

The fixed OR and equal-mean rules were declared in `protocol.json` before
computing this comparison. Both use the existing 0.5 threshold. No threshold
search, model fit, validation scoring, case exclusion, VM operation, service
change, new capture or malware execution occurred. The existing datasets,
feature contracts, models, validation predictions and metrics remain unchanged.

The comparison reuses the three models' saved training-only grouped
out-of-fold predictions: 259 cases, 137 benign and 122 malware, in 23 groups.
The original trainer selects host features within each fold's training data.
Fold reconstruction matched saved fold summaries, and every group has only
one out-of-fold assignment. Saved primary OOF metrics reproduce exactly.

## Fusion Results

| Rule | Sample-Weighted BA | Equal-Group-Weighted BA | False Positives | Missed Malware |
| --- | ---: | ---: | ---: | ---: |
| Host-only | 91.43% | 89.77% | 10 | 12 |
| Existing concatenated hybrid | 90.93% | 93.86% | 8 | 15 |
| OR of host/network alerts | 72.45% | 84.21% | 71 | 4 |
| Equal-mean host/network score | 84.51% | 85.73% | 11 | 28 |
| Network-only | 52.55% | 65.93% | 66 | 57 |

The OR score is `max(host, network)`; at 0.5 it implements an OR of alerts.
It preserves every host-positive alert and increases detected malware from
110 to 118, but adds 61 false positives. Its sample-weighted accuracy is
71.04%, versus host-only 91.51%. Thus alert preservation and accuracy are
different objectives. Neither fixed late-fusion alternative improves the
current sample-weighted balanced accuracy; neither is adopted or tested on
the consumed validation set. Combined scores are not calibrated probabilities.

Equal-group weighting assigns each observation weight 1/group-size before
computing class-balanced accuracy. It answers a different question from
sample weighting. Coreutils contributes 88 cases and Mirai 83: together
171/259 cases. The host/hybrid correct counts differ in these groups:

| Training Group | Cases | Host Correct | Hybrid Correct |
| --- | ---: | ---: | ---: |
| Inetutils | 10 | 7 | 9 |
| GetShell | 3 | 0 | 2 |
| Mirai | 83 | 75 | 70 |

This explains the direction change between sample-weighted and group-weighted
OOF comparisons. It does not establish which detector generalizes better.
Some groups are singletons and the fold sizes are 46, 100, 91, 13 and 9, so
folds must not be treated as equally precise independent trials. Retain the
existing primary metric and report both views; do not switch metrics to make
hybrid win. There is no new independent or blind evaluation here.

## Full Eligible-Capture Audit

All 417 host-eligible captures were decoded passively with Tshark. Recorded
telemetry intervals, rather than nominal rebinning, determine packet-window
membership. All 417 contain in-window HTTP for `connectivity-check.ubuntu.com`.

| Split/Label | Cases | With Connectivity Check | Zero Recorded Target Connect |
| --- | ---: | ---: | ---: |
| Training benign | 151 | 151 | 138 |
| Training malware | 150 | 150 | 36 |
| Validation benign | 62 | 62 | 52 |
| Validation malware | 54 | 54 | 29 |

In total, 255 cases have both that ambient signature and no recorded
sample-scoped connect. This is systematic evidence of a background-relevance
concern, not just a pattern in six selected prediction errors. These 417
include 51 cases with nonunique P4 alignment; all remain in the passive audit,
but only 259 aligned training cases enter the fusion comparison.

All audited metadata retain accepted quality, observed target exec and zero
reported packet-drop/counter-gap/eBPF-loss values. Every decoded PCAP hash was
independently rechecked. That verifies integrity of the inspected artifacts,
not never-recorded-event completeness or attribution of every packet.

No packet was removed and no network feature was recalculated for fitting.
An HTTP hostname is not process ownership. A missing connect event does not
rule out connectionless UDP, a target-induced daemon request, previously
established sockets or missing detail. These captures cannot retrospectively
supply a complete PID-to-flow mapping. The audit does not show that every
packet is background, nor that background alone caused the hybrid reversal.
The validation traffic inspection is not new classification scoring and
does not make that consumed split available for tuning.

## Background-Controlled Pilot Gate

This is a draft for separate approval, not a launch authorization or a frozen
sample manifest. No existing snapshot should be changed.

1. Create a separate child baseline with the same isolation, common launch,
   source hashes and strict capture settings. Record service, route, clock,
   interface and fixture states. Any background-service changes apply equally
   to both future labels, and their hashes/configuration are frozen.
2. First use benign null, file-only and internal-Sink network known-answer
   controls in each proposed execution mode. Reuse existing ABI/loader evidence;
   repeat only cases necessary to test the new baseline/attribution question.
   Freeze identities, expected outputs, order, repeat counts and failure rules
   before execution. Use one VM, isolated intnet only, with clean restores.
3. For known-answer network controls, record the workload PID, timestamps,
   local/remote address and port and a unique diagnostic request marker, and
   reconcile them with the PCAP. Markers are diagnostic evidence, not detector
   inputs. Destination port or a hostname alone is insufficient ownership.
4. Require controlled target traffic to be recovered exactly under the strict
   archive/PCAP/loss/exec gates. Test that null and file-only controls do not
   emit the designated target flow. Inventory all residual background traffic;
   define any background budget before data exists and report failures.
5. Do not infer complete malware flow ownership from a benign marker test.
   A general attribution claim requires appropriate full-tuple socket/process
   event coverage, including UDP and descendants. If new runner instrumentation
   is required, use a separately versioned schema/hash and compatibility audit.
6. Preserve all old results and failures. A new baseline changes the traffic
   population; do not silently filter old PCAPs or merge its new captures with
   old data as equivalent. Review compatibility and dataset roles first.
7. Compare any selected fusion design using training groups only, then freeze
   it before obtaining genuinely untouched evaluation data. No such evaluation
   is available in this attempt. Do not retune on the already consumed split.

The new background-controlled release is therefore **not ready**. This is a
gate for a proposed new design, not a retroactive change to earlier readiness
records or a declaration that every existing capture is invalid.

## Reproduction And Evidence

From the study root, run the current combined attempt's
`check_fusion_readiness.py --self-test`, then the script without arguments.
Each run creates a separate timestamped output and refuses overwrite.

- [Scope and fixed rules](protocol.json)
- [Complete numeric result](result.json)
- [Training-only scores and reconstructed folds](training_fusion_predictions.csv)
- [Per-fold results](training_by_fold.csv)
- [Per-group results](training_by_group.csv)
- [Changed decisions against host](training_changes_vs_host.csv)
- [Per-case traffic flags](traffic_flags.csv)
- [PCAP paths, metadata, hashes and decoded flow context](traffic_context.json)
- [Diagnostic source](../../check_fusion_readiness.py)

Independent verification recomputed sample/group-weighted confusion matrices,
balanced accuracy and AUC, checked OR preservation, training-only identities,
whole-group folds and all 417 PCAP hashes, and verified frozen inputs unchanged.
Synthetic negative tests reject invalid numeric scores, validation-row joins,
duplicate model/sample rows and group mismatches. No fresh VM-state claim is
made by this offline work.