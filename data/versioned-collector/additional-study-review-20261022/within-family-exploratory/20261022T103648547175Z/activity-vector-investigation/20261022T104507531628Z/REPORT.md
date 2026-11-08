# Activity Shortcuts And Host-Vector Collisions

Read-only, post-hoc investigation. Original captures, split, models, probabilities and primary results were not changed. No sample execution or VM operation.

## Activity

The activity-only model uses exactly log(1 + post-target lineage raw-syscall count), not syscall identities or paths. Activity can reflect the assigned task or execution conditions, not maliciousness.

- training benign: n=98, median=42.0, q10=24.0, q90=231.79999999999998, zero=0.
- training malware: n=84, median=1301.0, q10=18.0, q90=106944.8, zero=1.
- validation benign: n=99, median=36.0, q10=23.0, q90=175.0, zero=0.
- validation malware: n=85, median=1370.0, q10=27.800000000000004, q90=107646.6, zero=0.

Activity-only BA was 82.34% on the original184 validation cases. This breaches the prior0.75 confounding-warning reference and blocks a clean malicious-behavior interpretation.

## Vector Collisions

All 15 selected-host collision groups also collide across the complete 175 host candidates. Selecting 29 of the 35 families did not introduce these particular collisions. The affected validation cases are 13 malware and seven benign; every collision group has only one acquisition label. Host and hybrid classify all 20 correctly, but exact-vector overlap is weaker evidence than evaluation on independently represented behavior.

Exact executable hashes and benign program units differ across partitions. They can nevertheless map to identical coarse summaries. A collision does not by itself prove a copied capture, corrupt export, or near-identical executable.

- selected_host145: 15 cross-split groups, 20 validation cases, 0 mixed-label groups.
- all_host175: 15 cross-split groups, 20 validation cases, 0 mixed-label groups.
- network145: 0 cross-split groups, 0 validation cases, 0 mixed-label groups.
- selected_host_plus_network290: 0 cross-split groups, 0 validation cases, 0 mixed-label groups.

Reaggregation checked 64050 host-summary cells from recorded telemetry without mismatch. Raw exec/syscall evidence reconciled every collision member: 46 cases. Among collision groups, 7 had different post-target syscall-ID histograms and 10 had different canonical raw sequences. See collision_groups.json and raw_collision_cases.json for exact identities, source paths and pre/post-exec counts.

## Saved-Score Diagnostics

Overlap/nonoverlap and fixed activity/mode-bin results are in result.json and activity_bins.json. They use saved probabilities only, without refitting, filtering the original dataset or tuning thresholds.

| Subset | Cases | P4 BA | Host BA | Hybrid BA | Activity BA |
| --- | ---: | ---: | ---: | ---: | ---: |
| overlap | 20 | 44.51% | 100.00% | 100.00% | 85.16% |
| nonoverlap | 164 | 70.35% | 96.59% | 95.35% | 81.82% |

Post-hoc equalization within fixed activity/mode cells retains nonzero weight on 134 of184 cases. It changes the population: NOT a corrected test score, causal estimate or model-selection criterion.

- network_p4: descriptive weighted BA=63.9567%.
- host_29_families: descriptive weighted BA=89.9725%.
- hybrid_29_plus_29: descriptive weighted BA=86.4011%.
- activity_only: descriptive weighted BA=67.4672%.
- nuisance_only: descriptive weighted BA=57.1842%.

## Interpretation And Next Gate

### Concrete Raw-Evidence Examples

- Benign `head` has 27 post-target calls and `tail` has 31, but identical host175 vectors. The differing raw calls are read (one versus two), lseek (one versus three) and newfstatat (two versus three), which are outside the 35-family host counter representation. This is information loss in the feature definition, not a detected CSV-copy error.
- The two checksum programs b2sum and sha512sum each have the same 30-call canonical post-target sequence. XZ xzdec and lzmadec likewise share a 25-call canonical sequence. Distinct legitimate programs can therefore be indistinguishable to syscall-count features.
- A seven-sample Qilin collision group shares a 56-call canonical post-target sequence; a separate three-sample Qilin group does too. This raises a behavioral-redundancy/lineage concern but does not prove binary near-duplication. Canonical comparisons omit arguments, exact timestamps and absolute PIDs, so they do not assert identical raw trace files.
- Training NoEscape sample `d7e5d1da2d8cd498a57878ce912a098a2397be05ea26e10d83aa096695ce74a7.zip` has observed exact target exec, process signal -11 and zero recorded post-target raw syscalls. Its 178 pre-target raw calls and named pre-target events (including19 openat,14 mmap,4 mprotect and3 dup2) still contribute nonzero host features. It collides with malware having two or three post-target calls. This is not demonstrated malicious behavior, and missing never-recorded activity cannot be ruled out.

Across all 46 collision members, median named-event counts are 53 before the exact target boundary and nine after it. Pre-target events are real recorded launch/exec-related behavior, not target malicious-activity evidence. A common launcher is not by itself proof of class leakage: earlier boundary-neutralization findings must not be replaced by that unsupported claim.

### What The Activity Evidence Means

The saved host forest's largest family impurity importances are unique threads (18.75%), fork count (17.20%), openat success (12.95%) and mprotect (10.25%). Training-only Spearman correlations with log activity reach0.884 for event-count sum and0.838 for close-count sum. These are associations and impurity importances, not controlled evidence that the classifier relies only on activity.

The fixed activity/mode reweighting gives descriptive BA67.47% for activity-only,89.97% for host and86.40% for hybrid, compared with original82.34%,96.89% and95.79%. It balances broad bins, not individual syscall totals; residual within-bin activity differences remain. Only134 cases have nonzero weight and total effective weight is56, equally28 per class. These changed-weighting results cannot establish a causal shortcut effect or replace the primary scores.

The nonoverlap subset still has host BA96.59% and hybrid95.35%, so the 20 exact host-vector overlaps do not by themselves explain the entire high score. Conversely, high performance on that selected subset does not certify lineage independence, activity neutrality, malicious activation or generalization.

High activity-only discrimination confirms activity-label association in these data, not that the host model uses only that shortcut. Identical host-vector overlap makes independence weaker than unique hashes suggest. Removing overlapping validation cases after seeing scores does not create clean validation.
For a future reviewed design, group related malware binaries before splitting, expand independent benign projects with overlapping task/activity ranges, retain startup/low-activity outcomes, and reserve an untouched evaluation. Verify source lineage/near-duplicates statically without executing samples. Compare richer post-target/sequence representations only with training-only selection and explicit new-analysis authorization; never remove features or tune against consumed validation to force a preferred winner.
The existing background-traffic attribution issue remains separate and unresolved. These diagnostics do not certify completeness, malicious activation, causal shortcut dependence or generalization. No new collection or model release is authorized by this report.
