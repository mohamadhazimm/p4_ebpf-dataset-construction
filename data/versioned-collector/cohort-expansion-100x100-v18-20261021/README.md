# Additional 100 + 100 Preparation

## Combined X64 And I386 Analysis, 2026-10-22

User-authorized **joint offline training is complete**, after globally removing
`malware_signature::DDoSAgent` and `benign_project::util-linux` (35 eligible
cases). Original splits for retained groups, captures and earlier models were
preserved. There was no recollection, VM operation or production-code change.

Compatibility passed: the same schema-.18 runner/hash, settings, host/P4
contracts, Ethernet-byte and nominal-rate semantics were verified. All 4,099
regular archive members hash-matched; 58,975 host-summary and 43,355 P4-summary
comparisons had zero mismatches, with 30,109 independent PCAP records. The 337
retained executable hashes are distinct and no group crosses training/validation.
Watched paths differ (earlier cohort two, expansion one); selected host inputs
are syscall counters, not filesystem-watch summaries. This does not eliminate
task, toolchain, activity or acquisition confounding.

Primary common-aligned data: **218 training** (115 benign, 103 malware; 22
groups) and **81 validation** (43 benign, 38 malware; 33 groups). Thirty-eight
nonunique-P4 cases remain only in host sensitivity (252 training/85 validation).
One shared model per feature set was fitted on both cohorts, not an average of
old models. RF500/balanced/seed42/threshold0.5 and training-only host-family
selection were retained; input widths are 145/145/290. Cohort/mode metadata is
used only in a separate nuisance baseline, not the detector feature matrices.

| Model | Validation Balanced Accuracy | ROC-AUC | TN / FP / FN / TP |
| --- | ---: | ---: | --- |
| P4 only | 0.634 | 0.669 | 33 / 10 / 19 / 19 |
| Selected host | 0.899 | 0.969 | 40 / 3 / 5 / 33 |
| Hybrid | 0.914 | 0.958 | 39 / 4 / 3 / 35 |

Full evidence and models:
[combined metrics](combined-analysis/20261022T044439885696Z/analysis/model-fit/metrics.json),
[compatibility audit](combined-analysis/20261022T044439885696Z/analysis/compatibility_audit.json),
[frozen protocol](combined-analysis/20261022T044439885696Z/protocol.json).
Reproduction uses `analyze_combined_cohorts.py --prepare-only`, then
`--train <new-combined-attempt>`; it never operates the VM or executes samples.
Saved shared models exactly reproduce both cohorts' saved predictions.

**Post-hoc exploratory only: both source validation sets were already consumed.**
Host/hybrid group-bootstrap BA intervals overlap ([0.799, 0.974] and
[0.828, 0.978]); training-grouped OOF BA is 0.879/0.831. Hybrid BA is 0.904 on
the retained x64 subset (39 cases), 0.948 on i386 (42); host is 0.864/0.966.
Activity-only BA is 0.862 on i386 despite 0.599 overall, a workload-confounding
warning. Mode proportions and family coverage differ. All 100 training-only
group permutations completed (empirical p=0.0396), not a validation significance
test. Do not tune these consumed outcomes, claim hybrid superiority or describe
offline P4 reconstructions as live-switch evidence.

## Separate I386 Evaluation (Preserved)

Status, 2026-10-22: **derived offline training and required secondary checks
are complete**. The original stopped workflow and all captures remain unchanged.
The four failed runs contain no recoverable local telemetry; none was rerun.
The separate analysis excludes four lossy captures, one verified out-of-contract
ELF linkage case, 13 unobserved target execs and four null controls. Of 178
host-eligible cases, 157 have unique P4 alignment for the primary comparison:
115 training (63 benign, 52 malware) and 42 held-out i386 (29 benign, 13 malware).
The other 21 remain eligible only for the host-only sensitivity analysis.

| Model | Held-Out Balanced Accuracy | ROC-AUC | TN / FP / FN / TP |
| --- | ---: | ---: | --- |
| P4 only | 0.755 | 0.948 | 17 / 12 / 1 / 12 |
| Selected host | 0.862 | 0.997 | 21 / 8 / 0 / 13 |
| Hybrid | 0.914 | 0.999 | 24 / 5 / 0 / 13 |

Authoritative complete metrics:
[derived metrics.json](i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z/collection/derived-analysis/20261022T042419139084Z/analysis/model-fit/metrics.json).
Sibling outputs include saved models/hashes, predictions, group/fold audits,
training-only feature selections and 100 training-group label permutations.
The parent analysis directory contains the eligibility and P4 audits; the
attempt root preserves recovery evidence, source hashes and its complete status.
Commands used were `analyze_retrieved_i386.py --prepare-only` followed by
`--train <derived-attempt>`, never the capture task. Feature widths remain
145/145/290; forest settings, groups and training-only selection are unchanged.

This is exploratory, not evidence of general detector or hybrid superiority.
Only three malware groups remain in validation: 11 XorDDoS and BillGates/ChinaZ
singletons. Quality/exec/alignment exclusions reduced 30 planned validation
malware to 13 primary cases. Host/hybrid group-bootstrap intervals overlap
([0.786, 0.944] and [0.824, 0.965]); their training-grouped OOF balanced
accuracies are 0.888/0.734, respectively. Group-weighted activity-only balanced
accuracy is 0.756 despite the sample-weighted 0.606 baseline, so activity/task
confounding remains a concern. P4 is offline reconstruction. **This validation
split is now consumed; do not tune or rescore it as confirmatory evidence.**

## Original Workflow Stop (Preserved)

At the initial status check, post-capture validation had stopped and training
had not started. All 204 frozen positions were attempted;
200 have completed retrieval/run metadata, two have `runner_failed`, and two
have `output_copy_failed`. Of the 200 retrieved records, 196 report accepted
collection quality and four rejected. These are status counts, not a completed
whole-cohort archive/feature/eligibility audit.

The coordinator stopped at `2026-10-21T23:46:46.616688+00:00` because sample
`21f52381d8fe434cf4eed4d8968b8f58b8b97fa3af9ffd1f4f206d4269bb0042.zip`
was planned as native i386 static but its run metadata records
`linkage=static-pie`, machine 3, execution mode `native_compat`, with target exec
observed. `collection/status.json` is `stopped_requires_review`; neither a
model-fit directory nor final model metrics exists at the original output
location. The completed derived analysis above does not rewrite this stop.
Do not broaden the gate,
change the frozen allocation or retry samples without review. Raw outputs and
the original stop are preserved. Fresh read-only inspection found the guest
powered off on the original clean TLS snapshot, NIC1 internal malnet, other
NICs disabled. No workload or VM operation was performed for this status check.

## Capture And Queued Training Workflow

The focused VS Code task is **Capture i386 held-out cohort and train**. It ran
`run_i386_holdout_collection.py --execute-and-train` on the accepted snapshot
and frozen 204-position order: 100 malware, 100 benign and four null controls.
There is no automatic case retry, replacement, resume or old-data merge.
Do not edit this coordinator, the pinned batch/runner or frozen analysis
dependencies while the workflow is active.

Original capture output root:
`i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z/collection/`.
Its `launch_manifest.json` freezes authorization, snapshot, schema, input/helper
hashes and settings. `status.json` reports the current phase. Live batch output
is in `collection.log`; the release root's append-only `collection-console.log`
also preserves prelaunch, validation and training output.

After the batch, the coordinator restores the original clean TLS snapshot and
powers off before offline archive/provenance/quality/exec/finite-feature checks
and P4 alignment/parity reconstruction. It reports exclusions, retains
low-activity cases and runs the frozen RF/29+29 analysis without held-out tuning.
The original intended results path was `analysis/model-fit/metrics.json` under
the capture output root; the completed derived results use the separate path
above. `metrics-primary.json` is provisional until secondary analyses finish.
The i386 validation split becomes consumed when scored. An invariant failure
sets `stopped_requires_review`; it does not trigger a recollection or changed
protocol. Read the status/log rather than assuming capture or training success.

Prelaunch self-tests reproduced seven saved benign/null captures and exercised
the training wrapper only on synthetic group-disjoint data, with test-only
reduced estimator/bootstrap/permutation sizes. The real workflow remains
500-tree RF, balanced classes, seed 42, one worker and threshold 0.5, with
145/145/290 feature budgets, training-only selection and secondary checks.
An initial task invocation failed before VM/sample operation at cross-repository
hash-path handling; its empty output directory and console traceback are
preserved as `collection-prelaunch-failed-cross-repo-hash/` and in the console
log. The repaired coordinator hash is
`5cb319be8e9f0985a6642eb6c93416989e7ea6f4cb335d7f22cd461a5142f4f7`.
All frozen release and production sources remain unchanged.

## Accepted I386-Held-Out Amendment

Authoritative release assessment:
[i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z/gates/20261021T203538557730Z/release_assessment.json](i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z/gates/20261021T203538557730Z/release_assessment.json).
It supersedes the earlier `collection_ready=false` allocation assessment, not
the historical captures or consumed validation set.

- Each label has 70 training cases (49 native static x64 and 21 native static
	i386) and 30 validation cases (native static i386 only). All malware signature
	groups and benign upstream projects remain whole and disjoint across splits.
- Training has four malware signatures and three benign projects; validation
	has three malware signatures and 11 benign projects. Validation malware is
	28 XorDDoS plus BillGates and ChinaZ singletons. This is an exploratory,
	previously explored, highly concentrated transfer evaluation, not a blind
	confirmatory result or held-out x64 evaluation. Architecture variants of a
	program are not independent upstream projects.
- Thirty validation executables were built from 11 authenticated source
	projects, passed strict static ELF32 checks, then passed substantive host
	and isolated-guest workloads. Four earlier new-hash/old-program i386
	candidates were excluded; no repeated profiles or aliases filled these slots.
- The pinned collector starts with an empty workspace. Collection arguments
	therefore reference staged input fixtures explicitly, retain private output
	paths, and use a common user terminfo fixture. All 100 exact collection-form
	benign workloads passed in the guest, followed by all 204 transport dry-runs.
- Seven fresh benign/null captures (four nulls plus mke2fs, tput and unshar)
	passed exact target exec, active sensors, quality, semantic outputs, finite
	telemetry, safe archive hashes and independent PCAP counts: 47,320 feature
	cells, 86 regular archived members and 479 packets/PCAP records. Reported
	kernel drops, counter discrepancies, eBPF loss and unresolved ABI were zero.
	Both per-mode null maxima were 20, giving descriptive activity floors of 45;
	low activity is not a primary-analysis exclusion or delivery test.
- Frozen analysis uses 145 P4 columns, 145 training-selected host columns and
	290 hybrid columns, with no validation tuning, no automatic retries,
	replacements or resume. Per-mode/group results and nuisance/permutation
	checks remain required. Offline P4 alignment/parity is still a post-collection
	gate, not a claim that future captures will all pass.

Use the accepted gate snapshot
`clean-native-heldout-gates-v18-20261021T203538557730Z`, UUID
`2d0928cc-ce09-4b2e-848f-75f1ef06dcb5`, not the candidate snapshot name in
the earlier packaging manifest. Runner schema/hash and batch/staging pins
remain unchanged. Release readiness SHA-256:
`f7c311a9a0fb698fa8d38e733aee47a2ea9bda6db06d12653675c384236c3e42`.
The assessment records the remaining protocol/order/evidence hashes.

Re-audit saved evidence without executing workloads, using a new report name:

```sh
/usr/bin/python3 data/versioned-collector/cohort-expansion-100x100-v18-20261021/audit_i386_holdout_readiness.py \
	data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z/gates/20261021T203538557730Z \
	--output-name release-recheck.json
```

The saved-evidence re-audit reproduced the sensor result and rejected positive
packet discrepancies, eBPF loss and absent target exec. Final safety inspection
found the guest powered off on the original clean TLS snapshot, only internal
malnet networking, Sink running internal-only, and no collection/staging process.
No malware, full collection, model fitting, old-run resume, production edit or
historical capture replacement occurred. Preserve failed build/fixture/login
attempts. Fresh safety/hash checks and explicit launch authorization remain
required before running the frozen full order; readiness is not general
capture-completeness or detector-effectiveness certification.

`prepare_inventory.py` reuses the existing strict ELF parser, streams local
malware members through 7z into memory, and verifies member identities. It
checks catalog archive hashes where available and rehashes benign candidates
against the prior build audit. It never executes sample binaries. `inventory.json`
preserves exact paths, hashes, prior identity exclusions, modes, and groups.
The script refuses to overwrite that inventory; use a new attempt for changes.

| Additional inventory | Count | Limitations |
| --- | ---: | --- |
| Native x86-64 static malware | 51 | 49 Mirai, two unassigned; no unused strict dynamic candidates |
| Native i386 static malware | 72 | 43 XorDDoS, 16 Mirai; other groups small |
| Qemu ARMEL static malware | 80 | Requires exact mode-matched benign controls |
| Benign unused executable hashes | 221 | Includes alternate builds of previously used programs |
| Benign unused project/program pairs | 193 | Not yet selected or safe-workload-preflighted |

Additional means absent from the preceding 100x100 identity manifests, not
never explored in historical pilots. Hash uniqueness alone does not establish
independent software sources. Unused benign programs may require interactive,
privileged, unsafe, or unsupported workloads; this inventory does not accept them.
The report reuses a prior source/build audit, not a fresh source-authentication run.

Native i386 and static ARMEL/ARM64/MIPSEL benign workloads have bounded earlier
pilot evidence. That does not establish malware activation or scalable capture
completeness. Qemu host telemetry measures the emulator and its host syscalls,
not original guest-ISA syscalls. Missing interpreters/libraries remain a runtime
failure mode, especially for dynamic foreign-architecture programs.

Before readiness: agree on architecture scope and the role of the additional
data; match architecture/linkage/native-or-emulated mode across labels; retain
project/signature grouping; source and authenticate missing benign builds;
define bounded noninteractive workloads and outcome checks; freeze a separate
protocol/order/null calibration; then obtain guest-preflight authorization.
Full collection needs separate authorization. Do not change or reuse the
consumed prior validation set as a fresh confirmatory test. Keep collection
disabled until every readiness gate passes.

## Fresh Native Compatibility Gate

The user authorized checking i386 before including it and preparing the x64
candidates. Attempt [native-checks/20261021T150457461296Z](native-checks/20261021T150457461296Z)
contains the frozen protocol, payload identities, staging/dry-run/collection
logs, original audit failure, derived reports and final VM-state evidence.
Only authenticated static amd64/i386 BusyBox binaries were executed: null,
file and internal HTTP workloads, twice each, in interleaved architecture order.
These are two executable identities, not 12 independent software sources.

The fresh child snapshot was `clean-native-abi-v18-20261021T150457461296Z`,
staged from the clean malware-lineage baseline with unchanged schema `.18`
runner SHA-256 `3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49`.
Each observation was 20 seconds with 0.5-second windows, eBPF, broad capture,
the common launcher and the frozen default buffer/drain settings.

All 12 targets executed exactly, exited 0 and passed strict sensor quality.
All 81,120 declared feature cells were finite; 152 archived regular members
hash-matched host output. Aggregate received/captured/PCAP-record counts were
850/850/850, with zero reported kernel drops, counter discrepancies, eBPF
loss or unresolved ABI. Each file workload saved `299\n` and had exactly 300
post-target writes. Each network workload saved an HTTP 200 response from
the internal Sink. Both modes had post-target syscall counts null=20,
file=6111, net=99 in both repeats; per-mode activity floors were 45.

The original driver audit failed, not the workload executions: it assumed
raw CSV rows retained `abi=` and that i386 mode was named `native`. The actual
parser strips the ABI after using it, and i386 is recorded as `native_compat`.
The frozen driver and failed reports are preserved. The accepted derived audit
uses exact target exec, known static same-architecture BusyBox descendants,
numeric syscall IDs and collector diagnostics. Arbitrary mixed-ABI per-event
attribution cannot be independently reconstructed from this CSV alone.

Revalidate existing captures without rerunning samples, using a new report name:

```sh
cd vbox-runs/hybrid-rf-study-20261010
/usr/bin/python3 data/versioned-collector/cohort-expansion-100x100-v18-20261021/validate_native_checks.py \
	data/versioned-collector/cohort-expansion-100x100-v18-20261021/native-checks/20261021T150457461296Z \
	--output-name validation-recheck.json
```

Authoritative result: [native-checks/20261021T150457461296Z/validation-derived-r2.json](native-checks/20261021T150457461296Z/validation-derived-r2.json),
SHA-256 `c75e55a44eb6c01249d38184868d437ce1c0e63e4a9f2a4570f1d5db89e0edfc`.
Do not rerun the frozen driver merely to repair its audit assumptions. This
benign smoke does not certify arbitrary malware activation, general capture
completeness, dynamic i386 dependencies or classifier performance.

Cleanup verified the guest powered off on `clean-tls-paired-2026-10-19`,
UUID `72de0a02-2e71-42b8-85e2-78c21d6b00f9`; guest and running Sink retain
only internal `malnet` networking. No production code or historical captures
were changed, no malware was run and no model was fitted.

## Native Candidate Preparation

Latest separate attempt:
[native-preparation/20261021T151822271708Z/preparation.json](native-preparation/20261021T151822271708Z/preparation.json).
Its hash-bound i386 gate supports conditional inclusion, not collection readiness.
The verified named malware pool is 49 static x64 candidates (all Mirai) and
69 static i386 candidates; unassigned groups and all preceding cohort identities
are excluded. Every source archive/member identity and ELF mode was rechecked
in memory without malware execution. This is 118 candidates, not a final 100.
Mirai and XorDDoS account for 108/118, so family concentration remains substantial.

[native-preparation/20261021T151822271708Z/benign-x64-workload-drafts.json](native-preparation/20261021T151822271708Z/benign-x64-workload-drafts.json)
provides 49 distinct unused static x64 program identities, bounded arguments,
hashed data fixtures and draft outcome checks: 39 coreutils and 10 util-linux.
These are only two upstream project groups. No draft has passed guest preflight;
some exact semantic output checks remain pending. Existing source authentication
is referenced, not freshly repeated.

Distinct authenticated i386 benign builds are still missing. Host GCC advertises
`-m32`, but its 32-bit static `libc.a` lookup was unresolved and no dedicated
i386 compiler was found. This is a build prerequisite, not a guest support failure.
BusyBox aliases/repeats do not fill independent benign executable quotas.
Complete those builds, x64 semantic/workload preflight, matched per-label mode
quotas, dataset-role/grouping review and frozen null/order/protocol gates before
requesting full collection. The consumed previous validation split is untouched.

## Host Checks And Split Feasibility, 2026-10-21

The earlier i386-toolchain blocker is superseded by the accepted host-only build
report at
[`i386-toolchain-probe/20261021T153000Z/i386-controls-20261021T161011Z/i386-control-build-results.json`](i386-toolchain-probe/20261021T153000Z/i386-controls-20261021T161011Z/i386-control-build-results.json).
It records 51 distinct statically linked ELF32 controls with successful bounded
host semantic checks: 39 coreutils, two diffutils and 10 util-linux. The x64
host preflight at
[`native-preparation/20261021T154925322129Z/x64-host-preflight.json`](native-preparation/20261021T154925322129Z/x64-host-preflight.json)
accepted 49/49 profiles: 38 coreutils, one procps and 10 util-linux. Neither
report represents guest preflight or collection readiness. The accepted x64
report SHA-256 is `33ca57873c13d9d673cd102dd3adecb54cfa0996aa9c3f59ddd1a3fd5d650da2`;
the i386 report SHA-256 is `dff8555b507d0042684b49a2f12145df569b1727212edb914cf4f2e58496e6d2`.

The combined 100 benign identities form only four project groups: coreutils 77,
util-linux 20, diffutils 2 and procps 1. Whole-project validation subset sizes
are 0, 1, 2, 3, 20, 21, 22, 23, 77, 78, 79, 80, 97, 98, 99 and 100. Thus a
30-case whole-project validation partition is impossible. The native malware
inventory has 118 named candidates across seven signature groups (Mirai 65,
XorDDoS 43, Gafgyt 6, and four singletons); all 49 x64 candidates are Mirai.
This cannot meet the existing 9-training/10-validation signature-group design
reference.

Reproduce the hash-pinned feasibility audit from the study repository root:

```sh
/usr/bin/python3 data/versioned-collector/cohort-expansion-100x100-v18-20261021/audit_native_split_feasibility.py \
	--x64-preparation data/versioned-collector/cohort-expansion-100x100-v18-20261021/native-preparation/20261021T154925322129Z \
	--i386-report data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-toolchain-probe/20261021T153000Z/i386-controls-20261021T161011Z/i386-control-build-results.json
```

The authoritative revision-2 report is
[`native-preparation/20261021T154925322129Z/split-feasibility-r2.json`](native-preparation/20261021T154925322129Z/split-feasibility-r2.json)
(SHA-256 `bcf537626c432be5b531476963b26fd21f5f2de194d2cd48b43efd42689f2241`);
it records `not_ready_group_split_infeasible`. The auditor SHA-256 is
`bfc2f30e3e848fe14ebd025963049e9c01391a56f0773b25c246e0b82df49d19`. The
earlier `split-feasibility.json` is preserved; revision 2 corrects the recorded
input paths to be relative to the study repository root. No malware collection
or guest preflight was started. The conditional launch request therefore did not meet
its start condition. Next, obtain additional authenticated project-diverse
benign controls and enough malware signature groups, then freeze and re-audit
the grouped split and mode quotas before guest preflight. Do not replace the
grouped design with sample-random splitting or count repeated profiles as
independent projects without explicit protocol review.

## Actual Native Guest Readiness, 2026-10-21

The guest-preflight-pending state above is superseded for the actual 49 x64
and 51 i386 controls. All 100 exact executable hashes passed their bounded
noninteractive workloads in the isolated guest, with exit zero and semantic
output checks. The accepted report is
[operational-readiness/20261021T195042849982Z/guest_preflight.json](operational-readiness/20261021T195042849982Z/guest_preflight.json).
The separate new driver preserves original basenames, accepted arguments,
hashed fixtures, previous host reports and the frozen production sources.

Four actual new controls, b2sum and sha1sum on both architectures, also passed
the pinned `.18` batch collector. The evidence is
[operational-readiness/20261021T195332842767Z-sensors/validation.json](operational-readiness/20261021T195332842767Z-sensors/validation.json):
27,040 finite feature cells, 48 archive members hash-matched, 270 independent
PCAP records matching received/captured counters, and zero reported packet
drops, counter discrepancies, eBPF loss or unresolved ABI. Exact target exec,
native/native_compat mode and real digest output passed. Read-only negative
audit probes reject positive packet gaps, positive eBPF loss and absent exec.
These four short runs are not stress or all-100 sensor certification. Their
30/32 post-target syscalls do not exceed the earlier activity floor of 45;
successful output remains separate from the activation heuristic.

Commands from the study root (each creates a new attempt and executes benign
controls only):

```sh
/usr/bin/python3 data/versioned-collector/cohort-expansion-100x100-v18-20261021/prepare_native_guest_preflight.py --execute-benign-checks
/usr/bin/python3 data/versioned-collector/cohort-expansion-100x100-v18-20261021/check_native_control_sensors.py --execute-benign-checks
```

Use the saved evidence instead of repeating these checks unnecessarily. The
consolidated status is
[operational-readiness/readiness-assessment-20261021.json](operational-readiness/readiness-assessment-20261021.json).
It distinguishes passed benign operational checks from `collection_ready=false`.
The retained project/family-held-out design is still blocked: no whole-project
subset contains 30 benign cases, and all remaining named x64 malware are
Mirai, preventing x64 malware in both family-disjoint partitions. The earlier
9/10 signature-group counts are a prior design reference, not a universal
collector requirement. A final selection, approved split/mode quotas, dataset
role, preregistration and order remain unfrozen. No artifact-random split or
training-only role was substituted for the user's retained held-out design.

No malware or full cohort ran, and the BusyBox gate was not repeated. Two
staging-only startup failures are preserved separately; the new driver now
uses a guest-login event and the locally verified `--timeout 120000` syntax.
Final measured state: guest powered off on the original clean TLS snapshot,
both guest and Sink internal-malnet-only, Sink running, and no preflight,
staging or collector process remains. Production `.18` sources and historical
captures are unchanged.