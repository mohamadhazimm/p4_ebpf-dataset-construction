# Detector Remediation Plan

Date: 2026-10-22. Status: **offline audit complete; no new collection or detector release**.

## Authorization And Evidence

The user approved starting the proposed offline lineage/near-duplicate audit and evidence-gap protocol. This phase does not authorize sample execution, VM operation, production edits, another model search or a replacement split. All existing data, exclusions, models and historical results remain unchanged. Existing validation is consumed; it cannot become untouched through resplitting.

The authoritative [audit report](remediation-audit/20261022T114711085419Z/REPORT.md), [case evidence](remediation-audit/20261022T114711085419Z/binary_and_behavior_cases.json), [relationships](remediation-audit/20261022T114711085419Z/relationship_edges.json), [clusters](remediation-audit/20261022T114711085419Z/relationship_clusters.json) and [coverage](remediation-audit/20261022T114711085419Z/activity_mode_coverage.json) cover all 417 accepted host cases, including all 366 common-aligned cases. They do not silently restore rejected or missing captures. All 417 original executable identities were verified, with no source gap; 43,284 same-mode binary pairs were screened. No malware bytes were written to disk or executed: existing source members were streamed into bounded memory.

The [frozen gate protocol](remediation-audit/20261022T114711085419Z/remediation_protocol.json) is a design artifact, not a collection release. Its launch/model gates are false. Future exact identities, quotas, group allocation, workloads and precision requirements are not yet frozen or approved.

## Confirmed Relationships

Fifteen groups have identical selected executable regions, covering 43 malware cases. Twelve groups cross the exploratory within-family resplit, covering 37 cases, including 19 validation cases. No exact-code group crosses the original group-disjoint allocation. These are different evaluations and must not be conflated.

| Acquisition Signature | Exact-Code Groups | Cases | Groups Crossing Resplit |
| --- | ---: | ---: | ---: |
| XorDDoS | 5 | 18 | 4 |
| Prometei | 2 | 8 | 2 |
| Mirai | 3 | 6 | 3 |
| Akira | 2 | 5 | 1 |
| Bert | 1 | 2 | 1 |
| DeskRAT | 1 | 2 | 1 |
| Qilin | 1 | 2 | 0 |

Decision: review each exact-code group as a conservative future blocking candidate, including configuration/data differences and provenance. Do not split such candidates merely because whole-file hashes differ. Do not claim identical whole programs, behavior or independently verified malware lineage from code-region identity. Do not delete cases or retroactively change reported performance.

TLSH identifies 6,608 heuristic candidate pairs, including 294 direct cross-label pairs. For example, benign binutils elfedit and a GetShell-labeled executable have code/whole-file distances 7/17. Static runtimes, common libraries and compiler output can dominate the score; this does not establish that these programs share an attack lineage or that either acquisition label is wrong. Fuzzy transitive components reach 132 and 65 cases. Decision: **do not automatically use TLSH components as deduplication or split units**. Keep the frozen <=30/<=60 review tiers as screening heuristics and require localized code/provenance review before grouping unrelated projects/signatures. No match is not independence certification, particularly across architectures, packing or rebuilt variants.

On all 417 cases, exact host175 has 31 nontrivial groups, 18 crossing the resplit; nonempty post-target canonical sequences have 16 groups, nine crossing it. One raw-sequence group crosses the original project-disjoint allocation: binutils cxxfilt and less lessecho. This is equivalent recorded numeric-ID/window/root-descendant shape, not identical raw files or functionality. Empty traces are not joined, and numeric-ID sequences are compared within declared native mode; descendant ABI and arguments remain unknown. Earlier collision counts restricted to the 366 common cases/selected representation have a different denominator.

## Task And Activity Gaps

Both labels occur in 13/18 predefined mode/activity cells, covering 400/417 cases. This coarse overlap does not remove continuous activity, runtime, task or source confounding. The three occupied one-label cells are:

| Native Mode | Recorded Post-Target Calls | Malware Cases | Benign Cases |
| --- | --- | ---: | ---: |
| amd64 dynamic | 1,000-9,999 | 3 | 0 |
| amd64 dynamic | >=10,000 | 4 | 0 |
| i386 static | >=10,000 | 10 | 0 |

Coreutils supplies 100/213 benign cases; Mirai supplies 103/204 malware cases. Additional executables from those same groups do not create independent project/family evidence. Coverage at native amd64 static is 126 benign/144 malware, amd64 dynamic 21/12, and i386 static 66/48. Do not add emulated or other modes as label-exclusive substitutes.

Decision: prioritize independently authenticated non-Coreutils projects with substantive file, archive, database, computation and network tasks in the missing ranges/modes. Use real task/semantic outcomes, not busy waits, unrelated helper network traffic or activity padding. Freeze task arguments and outcome checks before capture; do not select favorable observed activity or delete low-activity cases. These are sourcing priorities, not an approved executable list, sample count or instruction to execute workloads.

## Ordered Remediation Gates

1. **Reviewed relationship units.** Retain exact evidence and source-review decisions, including uncertainty. Freeze conservative program/task/lineage blocking before any candidate allocation. TLSH alone is not adequate. Binary similarity does not establish malicious activation or acquisition-label correctness.
2. **Independent task/source feasibility.** Identify exact authenticated sources, distinct projects/programs and mode-compatible workloads addressing the gaps above. Preserve global DDoSAgent/util-linux exclusions. Review independent group diversity, task outcomes and an appropriate precision/power target rather than inventing a sample quota.
3. **Attribution instrumentation design.** Specify PID/socket/flow lifetime and clocks, TCP and unconnected UDP, descendants, PID reuse, existing sockets and mixed ABI. Preserve unknown ownership explicitly. Include benign null/file/network cases with unique markers, complete endpoints and real TCP/UDP application receipts. Captured UDP or ICMP port-unreachable is not successful application delivery.
4. **Separate versioned benign pilot.** Any collector/export semantic change gets a new schema/hash and compatibility analysis. The .18 runner, snapshots and captures remain immutable. Require strict reported loss/gap, archive/exec/finite-feature, marker/tuple/time and packet recovery checks, plus residual-background accounting. Do not silently substitute PID-filtered traffic for interface-wide P4 or claim general attribution/completeness from bounded controls. This gate requires separate authorization before production or VM changes.
5. **Prospective evaluation design.** The current within-family evaluation remains a known-family exploratory question. Unseen-family evaluation is a separate question, not an automatic replacement. Agree the future primary target, keep reviewed related units whole, report group/mode strata and reserve prospective cases before model selection. Independently sourced lineages/tasks, an external label custodian and time separation strengthen the gate; merely changing hashes does not. Neither historical resplitting nor newly added examples of already-examined behavior constitute a fresh independent validation claim.
6. **Frozen capture release.** Freeze exact executable/source/workload hashes, labels/provenance, common baseline, interleaved order, nulls, settings and analysis. Obtain explicit launch approval. Preserve every retrieval, quality, exec and alignment exception; no automatic retry/replacement. Lost events cannot be reconstructed or made valid by dropping a loss flag.
7. **Bounded nested development selection.** Keep the 145/145/290 primary budgets, training-fold-only host MI and sample-weighted balanced accuracy unless explicitly amended. RF500/seed42/threshold0.5 remains the reproducible baseline. Compare host, P4, concatenation and nested late fusion inside declared grouped development folds, with calibration/selection fitted inside those folds. Fix the candidate/complexity budget in advance. Report false positives, recall, calibration and group metrics without choosing a favorable seed, grouping or metric. A simpler host-only candidate remains legitimate.
8. **One locked final evaluation.** Lock the candidate and host comparator before revealing prospective test outcomes. Report paired differences and group-aware uncertainty alongside all failures and denominators. Do not retune after the final test or promise a hybrid win. A defensible estimate of generalization is the goal, not the highest score in the consumed data.

## Verification And Boundaries

[Audit verification](remediation-audit/20261022T114711085419Z/verification.json) rehashed 1,737 inputs and reproduced the graph evidence. [Independent verification](remediation-audit/20261022T114711085419Z/independent_verification.json) re-read all 417 source byte streams, independently parsed ELF section/segment offsets with the standard library, reproduced region SHA-256/TLSH and checked all 6,782 relationship edges. Production runner/batch/stager hashes are unchanged. Self-tests and editor/Pylance syntax checks passed.

Analysis tools were installed only in a workspace-local directory: pyelftools0.32 and python-tlsh4.5.0. Versions and actual library bytes are pinned; this is not a claim of signed upstream tool provenance. The older pip lacked --report and the configured index lacked TLSH4.7.2, so the supported logged install used4.5.0 before the real audit. No system packages or editor interpreter settings changed. Original source/build authentication evidence was reused; this was not a fresh distribution-signature audit or a repeat of full capture/PCAP acceptance.

Malware source lineage, representative independent benign coverage, packet ownership, malicious activation and never-recorded-event completeness remain unresolved. Missing history and consumed validation are irreversible. No sample execution, VM operation, production edit, collection, split reassignment, model fit or new prediction occurred. No current VM/Sink-state claim is made.

## Reproduction

From the study root:

```bash
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/audit_remediation.py --self-test
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/audit_remediation.py --verify data/versioned-collector/additional-study-review-20261022/remediation-audit/20261022T114711085419Z
```

The --run option creates a new timestamped, non-overwriting audit; reuse this completed evidence before repeating it. The next task is offline source/task feasibility and an instrumentation specification, not an automatic collection or model release.