# Native x86-64 redesign

User authorized redesign on 2026-10-21. This supersedes the earlier mixed-mode
candidate, not any historical capture. The full 100+100 collection has not
started; only benign readiness checks and sensor captures have run.

## Design

Keep **100 unique malware artifacts**, 70 training and 30 validation. Use native
x86-64 only, avoiding unavailable i386/ARMEL benign quotas and native-versus-QEMU
shortcuts. Exclude unassigned signatures and binaries with PT_DYNAMIC but no
PT_INTERP; the latter include self-relocating static binaries and must not be
silently counted as interpreter-linked dynamic executables. Legacy classification
is retained only for explicit `--design original` reproduction.

| Per label | Training | Validation | Total |
| --- | ---: | ---: | ---: |
| Static x86-64 | 63 | 21 | 84 |
| Interpreter-linked dynamic x86-64 | 7 | 9 | 16 |
| All | 70 | 30 | 100 |

Malware signatures: 9 training groups and 10 validation groups, with no overlap.
Validation: Bert, BrickStorm, CatStorm, DDoSAgent, DeskRAT, INC, LockBit,
PromptLock, Qilin, RedGoBot. Selection is deterministic, based on source identity,
headers and signature groups, not new runtime success or model scores. Earlier
pilots explored some of these groups: this is a new grouped evaluation, **not a
previously unseen blind test**. Source category labels are incomplete and not
independently verified behavior.

All 100 malware cases require fresh collection in the eventual common-snapshot
interleaved experiment. No implicit reuse of the earlier 20-case pilot. The
earlier draft manifests are preserved outside this directory and are superseded.

## Benign Sources

`benign-project-plan.json` allocates 100 distinct executable hashes across 14
training and 12 validation upstream projects. No project crosses the split.
At most 20 executables come from any one project. Repeated profiles, multicall
aliases and hash-identical copies do not fill missing executable slots. Binary
count is not independent project count; related utilities remain correlated.

All 26 allocated source projects have been downloaded from Ubuntu Jammy main or
universe through workspace-local authenticated APT indexes. The audit verifies:

1. InRelease signatures against the installed Ubuntu archive keyring;
2. source-index hashes against signed InRelease metadata;
3. descriptor hashes against those source indexes;
4. every source archive's hash and size against its authenticated descriptor.

System APT sources and installed packages were not changed. Source/build
preparation did not operate guests; the later readiness phase stages new child
snapshots on the existing isolated network. Build tooling uses the host compiler
and static libc, with the five explicit musl rebuilds described below. This does not
establish guest compatibility, upstream test-suite success, bit-for-bit build
reproducibility or toolchain neutrality across labels.

Build check, 2026-10-21: all **100 allocated project/mode slots** are covered,
with zero build shortfalls. The compatible-build audit inventories 297 static and 24 dynamic ELF
build candidates across the authenticated sources. Those surplus candidates are
not the selected 100-case executable manifest; unallocated dynamic diffutils outputs
do not fill other projects' quotas. The report distinguishes
`build_allocations_complete: true` from `collection_ready: false`.

The earlier local m4 runtime-library failure is resolved by scoped
`LD_LIBRARY_PATH` in `build-tool-env.sh`. Authenticated build prerequisites remain
unpacked under `build-tools/root`, without system installation or maintainer
scripts. Autotools data paths and versioned generator names are set locally.
Util-linux, procps and binutils required explicit libtool all-static links; the
independent ELF audit verifies the resulting linkage rather than trusting flags.
Project-specific recipes also handle gawk's omitted documentation, bzip2's static
library, Git's generated header, rsync's in-tree build, jq's generated-source
directory and curl's stale shared-library products. Optional Texinfo regeneration
is skipped with `MAKEINFO=true`; binary compilation errors are not ignored. The
earlier report is retained as
`preparation-audit-before-build-tools-20261021.json`.

Workload check, 2026-10-21: the unchanged runner supplies `stdin=DEVNULL`, with no
interactive terminal. A host-only, read-only nano check using `-I --view README.md`
under that input condition exited 1 with `Too many errors from stdin`. This is
not guest activation evidence or a successful editing workload. Do not substitute
`--help`/`--version` and call it substantive workload validation. The user approved
replacing the interactive allocation. Nano's validation/dynamic slot is now
`xz-utils` 5.2.5-2ubuntu1.2, authenticated through the same source-index chain and
built successfully. The previous plan and audit are preserved as
`benign-project-plan-before-noninteractive-amendment-20261021.json` and
`preparation-audit-before-noninteractive-amendment-20261021.json`. Split/linkage
quotas and runner `.18` are unchanged. No guest sample or malware was executed
during these build and host-only checks.

`prepare_executables.py` selects the exact 100 benign build identities into
`manifests/benign-executables.json`: 70 training, 30 validation, 84 static and 16
dynamic, with globally distinct hashes, original build basenames and disjoint
upstream projects. It checks each hash and ELF linkage against the audit and
records source-descriptor and build provenance. `readelf` inventories direct
NEEDED libraries without executing the binaries; this is not guest dependency
resolution. Inetutils `inetd` replaces stdin-driven `tftp`, and Git's foreground
`git-daemon` replaces `git-shell`, within their existing project quotas. These
choices precede workload freezing and do not replace failed collection cases.

The identity manifest's build-only status remains
`exact_build_identities_selected_workloads_not_validated`; the dated readiness
evidence, not this build-only status, determines workload readiness. In particular,
`unzipsfx` requires a separately hashed appended data-only ZIP fixture, and xargs
needs an argument file rather than collector stdin. The readiness phase validates
safe arguments, bounded foreground services, fixtures, output checks and target
exec separately from activation. Help-output discovery is not accepted workload
evidence, and no network service was started on the host during option discovery.

## Reproduction

From the study repository:

```bash
/usr/bin/python3 data/versioned-collector/cohort-100x100-v18-20261021/prepare_selection.py --design native-x64
/usr/bin/python3 data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/audit_redesign.py
/usr/bin/python3 data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/prepare_executables.py
```

To repeat a demonstrated build:

```bash
bash data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/prepare_benign_source.sh diffutils static
```

The source helper supports `fetch`, `static`, and `dynamic`, with recipes for the
allocated projects and modes. Source descriptors, original archives, build
provenance and logs are retained locally. Auditing uses the system Python's
`apt_pkg` parser; no host Python packages were installed. Regenerating a manifest
is preparation, not permission to launch a batch.

## Collection Gates

Before starting the full collection:

1. Complete all allocated builds; freeze exact executable hashes, source/project
   identity, ELF linkage, interpreter and dependency inventory, safe arguments,
   input fixtures and expected output checks. Do not substitute extra coreutils
   binaries for missing independent projects. Amend allocations explicitly if
   build coverage is infeasible; do not change them after seeing validation scores.
2. Use the accepted dated preregistration and frozen code/manifests from the
  readiness attempt below. This explanatory document is not a retroactive
  preregistration of historical pilots. Reverify frozen hashes before launch;
  regenerating preparation inputs can invalidate the accepted release.
3. Stage both labels into one common clean child snapshot with latest source
   schema `.18` and pinned runner/batch/staging hashes. Match wrapper, workspace,
   watch paths, privileges, snapshot, observation settings and tool availability.
   Retain basename/argv semantics; never replace frozen historical runners.
4. Prepare benign static and dynamic null controls, three repeats each, in the
   same snapshot. Freeze the activation algorithm: target exec must be observed;
   progress requires post-target lineage raw syscalls above the corresponding
   null maximum plus 25. Progress is not maliciousness or network delivery.
5. Freeze a seed-42 randomized interleaved case order within split/linkage blocks;
   alternate labels, randomize the starting label, spread null controls across
   the run. Do not collect all malware before benign. Keep the validation labels
   out of model tuning. Record order and UTC time for nuisance audits.
6. Reverify source hashes/schema, no competing collectors, powered-off clean
   state, and internal-only NICs for guest and Sink. Use explicit schema options
   when staging and collecting. No NAT, bridged or host-only NICs. No public
   workload destinations. Preserve the paused historical cohort unchanged.

Use 20-second fixed observations, 0.5-second windows, enp0s3, eBPF, common
wrapper, `.18` defaults: 65,536-KiB immediate-mode PCAP, 1,000-ms drain, 16,384
bpftrace perf pages/CPU. Freeze those values in the experiment manifest rather
than relying on historical script defaults. Restore and power off the clean
guest after the experiment and verify Sink isolation separately.

## Evaluation Rules

- Log retrieval, sensor quality, exec success, activation, and output/delivery
  checks separately. Reject sensor/provenance failures under the strict `.18`
  gate. Apply the same prespecified exclusions to both labels, report all 100
  attempted malware identities and exclusions by group/linkage, and never
  replace failed validation cases to improve scores. No automatic retries.
- Primary analysis: quality-accepted, target-observed cases, including low
  activity. Report progressed-only sensitivity separately to expose activation
  selection. Do not equate exit 0 with activation or malicious execution.
- Use offline PCAP reconstruction with captured-Ethernet bytes and nominal
  rates. Require unique telemetry-window alignment and stored/reconstructed
  parity. Use a common aligned set for P4, host and hybrid comparisons, plus an
  all-eligible host-only sensitivity to reveal alignment-selection bias.
- Exactly 145 P4 columns (29 families x five summaries), 145 host columns (29
  of 35 candidate families x five summaries), hybrid 290. Select host families
  using training-only mutual information averaged over the five summaries.
  Refit selection within every inner grouped fold. No case IDs, artifact paths,
  signatures, labels, timestamps, return codes or acquisition metadata as inputs.
- Choose RF hyperparameters and threshold without validation outcomes. Freeze
  them before scoring validation once. Any tuning uses only grouped training
  folds with whole malware signatures and benign projects kept together.
- Report balanced accuracy, ROC-AUC, confusion matrices and per-linkage results.
  Also report group-weighted results and cluster-bootstrap uncertainty by
  malware signature/benign project. Qilin dominates validation and Mirai training;
  sample-weighted scores alone are insufficient. No unrepresented-mode claims.
- Include nuisance-only and training-label-permutation checks. Audit linkage,
  build/runtime provenance, collection order, watch paths and activity. A high
  nuisance score or narrow activity shortcut blocks a malicious-behavior claim;
  matching architecture/linkage does not prove all confounds are removed.

## Readiness Preflight, 2026-10-21

`prepare_workloads.py` defines 100 noninteractive profiles, data-only fixtures,
an appended-data ZIP for unzipsfx, and six supplemental static/dynamic nulls.
`run_readiness.py` freezes a dated protocol, 206-position interleaved order,
package, hashes and fresh common child snapshot before benign-only checks. It
never executes malware or starts the full collection. Readiness requires:

1. All 100 hash-allowlisted benign workloads pass loader, input, exit and
  program-specific output checks on the common snapshot.
2. The existing batch validates all 206 planned names in dry-run mode.
3. Twelve benign sensor runs pass provenance, target exec, strict quality,
  40 windows of 169 finite features, and safe archive/member hash checks:
  six nulls, cp, jq and four ZIP-tool transport cases. Null maxima plus 25
  calibrate activity floors. Low activity is not a primary exclusion.
4. Frozen input hashes remain unchanged, and cleanup restores the original
  clean TLS snapshot, powered off and isolated. The Sink stays internal-only.

The earlier 95/100 attempt is preserved under
`readiness/20261021T101635233272Z/`. A static absent-user NSS lookup crashed under
guest policy `files systemd sss`; the exact target-specific crash stacks were not
established. The user chose compatible rebuilds instead of guest-policy changes.
A matching-glibc 2.43 probe also failed and was not adopted. Authenticated Ubuntu
musl packages plus authenticated ncurses source now build traceroute, ping, ftp,
whois and top statically. Only these five selected executable identities changed;
project, split and linkage quotas did not. Original builds/manifests remain
preserved. Musl uses files/DNS rather than guest systemd/SSS NSS plugins: this is
a runtime difference and potential nuisance, not proof of toolchain neutrality.

Compatibility build reproduction, after preparing the payload diagnostic source:

```bash
bash prepare_compatible_static.sh --musl
bash prepare_compatible_static.sh --ncurses
HAZIM_COMPAT_LIBC=1 bash prepare_benign_source.sh inetutils static
HAZIM_COMPAT_LIBC=1 bash prepare_benign_source.sh procps static
```

All 100 real guest workloads passed in `readiness/20261021T104014911252Z/`.
That attempt remains `not_ready`: its first sensor audit used the wrong metadata
key. A corrected derived audit accepted its eight saved captures, but a later
dispatch check found four ELF tools also detected as ZIP files. No captures were
deleted or relabeled as an originally accepted release.

The four archive-looking ELF tools (zip, zipnote, zipsplit and unzipsfx) now use
one-member outer transport archives. Their original executable basenames and
exact ELF hashes are preserved and checked independently. The production batch
is unchanged. The expanded smoke verifies extraction chooses the intended native
member. Direct guest preflight still checks the raw executable identity.

FTP and WHOIS use real loopback fixtures on ports 65015 and 65014, started by a
common user `@reboot` entry on both labels. Connection evidence and WHOIS reply
content are checked. Guest NSS policy, system packages, privileges and production
runner `.18` are unchanged. The unsupported traceroute option, omitted empty Git
fixture directories and bzip2recover output contract were repaired; recovered
bzip2 content is compared independently. An internal route/service gate precedes
workload checks, but cannot guarantee link readiness after every future restore.

Accepted release: `readiness/20261021T104951987641Z/readiness.json`, mirrored in
`readiness-current.json`, records `collection_ready: true`. At that readiness
checkpoint, `full_collection_started: false` was accurate; the separately
authorized batch and its post-run record are in
`readiness/20261021T104951987641Z/collection_manifest.json` and
`readiness/20261021T104951987641Z/collection_validation.json`.

All 100 guest checks, 206 batch dry-run names and 12 readiness sensor cases
passed. The readiness smoke checked 81,120 finite feature cells and 148 archive
members; Scapy reconciled 900 received/captured/PCAP records with zero reported
packet drops, counter gaps or eBPF loss.

The accepted snapshot is `clean-cohort-native-v18-20261021T104951987641Z`, UUID
`05d9c29c-551b-4489-ba62-bd7e641499f9`. Frozen manifests, exact case order,
protocol, code and payload hashes remain in that attempt. Null activity floors
are static 40 and dynamic 55; cp completed a verified copy with only 39 syscalls,
so output success must not be equated with exceeding this heuristic. Low
activity remains included in the primary analysis.

The user separately authorized collection, launched 2026-10-21T11:10:49Z on the
accepted snapshot and frozen order. The batch completed all 206 positions, but
only 204 archives were retrieved: 203 quality-accepted and one rejected for
27,620,596 lost eBPF events. Two malware outputs were not retrieved, one after a
PCAP `PermissionError` during Scapy processing and one after a missing runner
output directory caused archive failure. Both causes remain unresolved; the
frozen protocol forbids automatic retries or replacements. Exact IDs and logs
are in `readiness/20261021T104951987641Z/collection_validation.json` and
`readiness/20261021T104951987641Z/collection/runs/`.

All 204 archived records match runner schema/hash `.18`, with 40 x 169 finite
features each and 2,485 safe regular archive members hash-matched to extracted
files. Across these records, 18,236 PCAP records match tcpdump received/captured
counters; reported kernel drops and counter discrepancies are zero. The one
eBPF-loss record remains rejected, so matching packet counts do not establish
loss-free telemetry. Process return codes and target-exec/activation counts are
separate in the validation report; retrieval and sensor quality are not proof
of successful workload execution or malicious behavior.

The guest is powered off on the accepted collection snapshot, with only internal
malnet enabled. The Sink is the only running VM and remains internal-only. No
retry, historical resume or public networking occurred. Offline P4 alignment and
modeling were then performed from retrieved artifacts only; no guest or
collector operation was part of the analysis.

## Initial Held-Out Model Evaluation, 2026-10-21

Reproduce the read-only preparation and model run from the study repository:

```bash
/usr/bin/python3 data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/readiness/20261021T104951987641Z/prepare_model_data.py
/usr/bin/python3 data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/readiness/20261021T104951987641Z/train_model.py
```

The authoritative outputs are under
`readiness/20261021T104951987641Z/analysis/model-fit-r3/`; partial failed
attempts in `analysis/model-fit/` and `analysis/model-fit-r2/` are preserved and
are not results. Preparation excluded the one quality-rejected malware record,
both unretrieved records, all three target-exec-not-observed records, and six
calibration nulls. The primary comparison also excludes 18 otherwise eligible
records without unique PCAP/window alignment. No rejected or missing record
entered a model; low-activity target-observed records remain included.

Primary common-aligned set: training 119 (67 benign, 52 malware; 22 groups),
validation 57 (30 benign, 27 malware; 21 groups). P4 and hybrid use 145 and 290
columns, respectively; host uses 29 of 35 candidate families (145 columns),
selected by training-only mutual information over the five summaries. RF
settings and threshold (500 trees, balanced class weight, seed 42, 0.5 cutoff)
follow the preregistration. Host selection is refit inside five-fold
StratifiedGroupKFold training-only OOF and on the full training split. Validation
was scored once, without tuning.

| Model | Validation BA | ROC-AUC | TN / FP / FN / TP | Group-weighted BA | 95% group-bootstrap BA interval |
| --- | ---: | ---: | --- | ---: | --- |
| P4-shaped network | 0.565 | 0.756 | 25 / 5 / 19 / 8 | 0.539 | 0.409–0.649 |
| Host, 29 families | 0.706 | 0.957 | 29 / 1 / 15 / 12 | 0.792 | 0.538–0.951 |
| Hybrid, 29 + 29 | 0.761 | 0.952 | 29 / 1 / 12 / 15 | 0.829 | 0.608–0.975 |

The hybrid has three more true positives than host-only at the fixed threshold,
with the same false-positive count, and +0.056 balanced accuracy. Its ROC-AUC is
slightly lower than host-only. Group-bootstrap intervals are broad and overlap;
this small held-out result is exploratory, not evidence of reliable hybrid
improvement or detector generalization. The separate host-only all-eligible
sensitivity (which includes 18 non-uniquely-aligned cases) scores 59 validation
cases at BA 0.707 / AUC 0.938 and is not a like-for-like comparison with the
primary common set.

The preregistered activity-only and nuisance-only checks scored BA 0.480 and
0.293 on the primary validation set, below the 0.75 claim-blocking threshold.
That does not rule out other workload, build, acquisition or label confounds.
On training-only grouped OOF, hybrid BA was 0.794; 100 group-respecting label
permutations had mean BA 0.436 (95% interval 0.178–0.732; empirical upper-tail
p=0.030). This is a small training negative control, not a validation-set
significance test. Validation has only nine malware signature groups, labels
are acquisition labels, the source selection is purposive, and P4 features are
offline PCAP reconstructions rather than live-switch measurements.

`readiness/20261021T104951987641Z/analysis/preparation_audit.json` reports 176 unique alignments and 25,520
stored-versus-reconstructed P4 summary comparisons with zero mismatches. The
model metrics are in
`readiness/20261021T104951987641Z/analysis/model-fit-r3/metrics.json` and sample
predictions in
`readiness/20261021T104951987641Z/analysis/model-fit-r3/validation_predictions.csv`.
These validation results have been consumed;
do not tune features, thresholds or model choices against this split and report
the same result as confirmatory evidence.