# Hybrid Reversal Investigation

Date: 2026-10-22. Scope: post-hoc inspection of unchanged saved models,
predictions and existing captures. No refitting, threshold changes, collection,
VM operation or modification of frozen evidence occurred.

## Conclusion

The evidence does not establish a new packet-loss, feature-order or P4
reconstruction bug. It does establish two separate concerns:

1. The current hybrid is a separately trained feature-concatenation forest,
   not an OR or a vote of the saved host and network detectors. It does not
   guarantee preservation of host detections.
2. The network feature windows contain background-style guest traffic without
   demonstrated sample attribution. This is a collection-design limitation,
   even when packet counters and reconstruction are correct.

Neither finding proves that all network features are invalid, or that background
traffic or feature sampling alone caused the observed difference. Models must
not be changed on this consumed validation set to force hybrid superiority.

## Same-Case Comparison

| Evaluation | Cases | Host Accuracy | Hybrid Accuracy |
| --- | ---: | ---: | ---: |
| Previous fitted models, original validation | 81 | 90.12% | 91.36% |
| New fitted models, same original validation | 81 | 91.36% | 90.12% |
| New fitted models, added validation cases | 26 | 100.00% | 88.46% |
| New fitted models, all validation | 107 | 93.46% | 89.72% |

The immediately preceding combined hybrid lead was one additional correct
decision out of 81, not a large stable advantage. Adding data both changed the
fit and added 26 validation cases. Comparing the old 81 directly to the new 107
does not isolate either effect. All old validation identities remain present.

Even before the extension, training-only grouped OOF balanced accuracy favored
host: 87.94% versus hybrid 83.13%. Prior validation AUC also favored host
(0.9688 versus 0.9584), despite the hybrid's one-case thresholded lead.
Current training OOF BA is host 91.43% versus hybrid 90.93%.
Confidence intervals overlap; these are exploratory, group-limited results.

## Exact Disagreements

The current host and hybrid disagree on six cases. Host alone is correct on
five; hybrid alone on one. Net difference: four additional hybrid errors.

| Case | Label | Host Score | Network Score | Hybrid Score | Correct Model |
| --- | --- | ---: | ---: | ---: | --- |
| Qilin `8f8283a7...` | malware | 0.588 | 0.628 | 0.492 | host |
| diff3 | benign | 0.542 | 0.554 | 0.468 | hybrid |
| i386 net-tools hostname | benign | 0.300 | 0.476 | 0.740 | host |
| lessecho | benign | 0.264 | 0.312 | 0.746 | host |
| mklost+found | benign | 0.320 | 0.242 | 0.554 | host |
| uuidgen | benign | 0.306 | 0.118 | 0.718 | host |

Scores are saved malware probabilities at the frozen threshold 0.5, not
calibration guarantees. A feature-fusion forest can score above both standalone
forests or below both because it learns different trees and interactions.
For Qilin both standalone models detect it, while hybrid does not. For uuidgen
both standalone models are correct, while hybrid raises a false alert.

## Model Construction

Both standalone and hybrid forests use 500 trees, balanced class weights,
seed 42, one job, and the same selected 145 host columns within each fitted pair.
Hybrid receives those columns plus 145 P4 columns. Both use sklearn's
`max_features="sqrt"` setting:

- Host: 145 inputs, configured split-candidate count 12.
- Hybrid: 290 inputs, configured split-candidate count 17.
- Under uniform candidate sampling, expected host candidates for hybrid are
  17 x 145/290 = 8.5, versus 12 for host-only.

Thus doubling the inputs does not preserve the standalone tree-search problem.
Constant/invalid split features can cause additional search; the expectation is
not a measured count of valid host split candidates at every node. A separate
training-only ablation is required to establish the causal effect of this choice.
Current hybrid impurity importance is 90.18% host / 9.82% network, compared with
89.37% / 10.63% before. Impurity importance is not causal attribution or proof
that the network information improves generalization.

## Collection Evidence

Tshark decoded each of the six disagreement PCAPs. Exact recorded telemetry
intervals were used to check packet eligibility, not a uniform synthetic grid.

| Case | In-Window IPv4 TCP/UDP Packets | Recorded Target Connect Calls |
| --- | ---: | ---: |
| Qilin `8f8283a7...` | 67 | 0 |
| diff3 | 65 | 0 |
| hostname | 47 | 0 |
| lessecho | 49 | 0 |
| mklost+found | 66 | 0 |
| uuidgen | 67 | 0 |

All six contain in-window HTTP requests for `connectivity-check.ubuntu.com` and
DNS queries for Ubuntu NTP/bootstrap and local service discovery. The decoded
HTTP client path is guest `10.0.0.10` to internal Sink `10.0.0.1`; domain names
do not demonstrate public-network contact. No HTTP user agent was available.

These signatures and the zero recorded target connect counts support a concern
about ambient OS traffic entering P4 features, especially for the non-network
benign programs. They do not independently establish process ownership of every
packet, rule out connectionless UDP activity, or prove all these packets are
unrelated to the target. Packet-to-process attribution remains unresolved.

All six cases have accepted capture quality, zero reported packet drops,
counter discrepancy and eBPF loss, and unique P4 alignment/parity. The prior
full reconciliation verified 53,070 stored-versus-PCAP P4 summaries without
mismatch. Correct extraction does not imply behaviorally relevant traffic.
Known rejected and missing captures remain excluded; no case was rerun.

## Recommended Next Gate

- Define the intended fusion objective. An OR of standalone alerts preserves
  host-positive malware alerts, but can only maintain or increase false
  positives; it does not guarantee better accuracy, balanced accuracy or AUC.
- Compare late fusion or host-preserving alternatives using training-only
  grouped validation, not tuning against these 107 consumed cases.
- Before another collection, preregister a common background-controlled
  baseline and verify sample-flow attribution or matched no-workload controls.
  Any new snapshot or service change must apply to both labels and be recorded
  as a new collection design, not silently applied to frozen captures.
- Evaluate selected alternatives on genuinely untouched data. Do not select
  features, discard valid counterexamples or change thresholds to make hybrid win.

## Artifacts And Validation

- [Machine-readable comparison](summary.json)
- [Exact disagreements](paired_disagreements.csv)
- [PCAP paths, recorded-window flow evidence and metadata](packet_context.json)
- [Reproducible diagnostic](../../investigate_hybrid.py)

The diagnostic reproduces every saved primary probability for both versions
from the actual saved models and prepared feature rows, verifies model hashes,
and checks paired sample/label identity. Synthetic guards reject duplicate
model/sample rows and label disagreement. Editor and Pylance syntax checks pass.
Collection sources, fitted models, predictions, thresholds and original metrics
remain unchanged. This investigation does not certify general capture
completeness or causal maliciousness, and makes no fresh VM-state claim.