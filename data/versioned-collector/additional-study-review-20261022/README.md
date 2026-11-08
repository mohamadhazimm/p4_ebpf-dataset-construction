# Additional Data Study Review

Date: 2026-10-23. Status: **Actual V3 performance stopped at case007 and was independently audited; corrected release inputs pass offline checks, but performance and final collection release remain not accepted**.
The initial inventory below was offline. A subsequent, explicitly approved
source-only VM export recovered all 535 original source files without executing
them. The user later authorized benign readiness checks and, separately, the
capture-only full launch described below. Existing captures, models, consumed validation results,
production sources and paused batches remain unchanged.

## Current Live Capability

2026-10-24: all three performance attempts stopped at case007 for one deterministic
reason. Guest NetworkManager connectivity checks are the only enp0s3 traffic, and
their backoff doubles, so about 180s after boot a full-sensor file task captures
nothing. See [the V4 procedure](PERFORMANCE_PROTOCOL_V4.md). The user chose per-case
capture-path probes. The [V4 launcher](run_performance_v4.py) and
[saved-only auditor](audit_performance_v4.py) pass local tests, and build-only
attempt `scoped-performance-v4/20261024T075036053052Z/` is frozen. No V4 guest
attempt has run; one needs explicit launch approval. `collection_ready=false`.

After the user's `okay let's go with your thoughts and instincts`, a separate
[prospective benchmark quiet policy](BENCHMARK_QUIET_POLICY_V1.md) and
[local decision oracle](benchmark_quiet_policy_v1.py) distinguish benchmark
capture eligibility from original collection quality. They preserve the original
quiet rejection and propose four separate, independently audited same-attempt
pre/post positive controls outside every complete benchmark case, with no measured
helper traffic or change to tasks, setup-inclusive timing or overhead limits.
Brackets are not continuous-completeness proof. Local tests pass32 negative
guards; the [non-overwriting proposal](benchmark-quiet-policy-proposals/20261023T134930924478Z/contract.json)
records explicit no-execution and no-acceptance flags. There is no guest adapter,
raw-control auditor or new VM attempt in this phase. Those integrations and a
separately reviewed execution approval remain required. Actual V3 case007 and
all measured sources/evidence remain unchanged and rejected; `performance_accepted=false`,
`collection_ready=false`. No fresh VM-state check is claimed by this local work.

The renewed request authorized the [separate one-attempt V3 procedure](PERFORMANCE_V3_ATTEMPT_PROTOCOL.md), retaining the original strict gate. Its [actual guest result](scoped-performance-v3/20261023T132643813743Z/guest_result.json) stops at case007 with `packet_capture_interface_no_traffic`: all eight amd64 file tasks exit0 and produce exact16MiB outputs, but only six warmups and one scored baseline complete measurement acceptance. No scored full/original pair or accepted median exists. The rejected capture has exact exec, active sensors, up/carrier1, zero PCAP/NIC traffic and zero reported loss/gaps. FINISH follows actual observation end by6981ns before PCAP shutdown; ACK takes2.338055384s within12s. No traffic, task, timing, quality or budget amendment was made. The single approval is consumed; no retry is queued.

The [independent saved-only audit](scoped-performance-v3/20261023T132643813743Z/audit-v3-derived-20261023T133108968886Z.json) verifies159 safe members,33,800 finite cells,96 reconciled PCAP records, actual task/identity/lifecycle/startup receipts and cleanup. The new [release-specific assessment](release-specific-assessments/20261023T133344751813Z/assessment.json) verifies the corrected16 pairs,32 bounded ELF inspections,16 exact benign component bindings and466 input hashes, including unchanged417 assignments. The benchmark executes performance tasks, not the selected final release workloads; one selected xxhsum hash is merely present and unused in its payload. Exact common payload/helper allowlists/collection-form task fixtures/scoped coverage and benign-null-order rehearsal remain unaccepted. See the [outcome and reproducible commands](release-specific-assessments/20261023T133344751813Z/REPORT.md). `performance_accepted=false`, `collection_ready=false`. Saved and fresh checks confirm original TLS/off, isolated Sink/running, production pins unchanged and no competing collector. No malware/full collection, fitting, history merge/resume or service/policy change occurred.

The earlier [V3 completion repair](PERFORMANCE_PROTOCOL_V3.md) exports the missing summary API in a separate version, preserving measured V2. Its [local regression](check_performance_v3.py) passes the actual guest driver's complete84-position loop with simulated subprocesses/measurements, independent final-summary comparison, actual missing-export reproduction, quality/runner/budget failure stops and credential/archive cleanup. Inherited actual local pidfd/wait4, all84 parser, startup and lifecycle checks pass; generated runtime schema/Session/module bindings and old measured hashes verify. This is local regression evidence, NOT an accepted overhead result. At that earlier checkpoint the user selected **Keep original strict gate; no new attempt**. The renewed request and consumed single attempt above supersede only that launch restriction, not the strict gate or the historical local-only procedure. Final empirical performance and release gates remain pending.

The separately approved [performance V2 procedure](PERFORMANCE_PROTOCOL_V2.md) was executed once in [the new frozen attempt](scoped-performance-v2/20261023T123753101282Z/guest_result.json). It stopped at case007, the first scored original-sensor amd64 file case: `packet_capture_interface_no_traffic`. All eight tasks exited0 with exact16MiB file outputs, but only six unscored warmups and one scored baseline completed measurement acceptance. No scored full/original pair or accepted overhead median exists; guest i386/network cases did not run. The rejected capture has link up/carrier1, zero packets and zero NIC traffic, with zero reported loss/gaps. Its FINISH follows actual observation end by9404ns before original PCAP shutdown, and its ACK arrives2.237901229s later within the original12s. This is a no-traffic rejection, not the earlier lifecycle failure or proof of disconnection/completeness. No diagnostic28s lifetime, helper traffic, task extension, timing-boundary change or relaxed limit was imported.

The [independent saved-only prefix audit](scoped-performance-v2/20261023T123753101282Z/audit-derived-20261023T124157629287Z.json) verifies159 safe evidence members,33,800 finite cells,83 reconciled PCAP records, source/payload hashes, actual task measurements, both full executed-inode/v6 receipts and cleanup. A further saved-only check verifies the rejected final task, raw lifecycle, strict no-traffic predicate and removed cgroup. Three baseline sensor-quality rejections remain unchanged because sensors were intentionally disabled. Saved cleanup and fresh read-only checks confirm original TLS/off, Sink/running/internal-only, unchanged production pins and no competitor. The single performance launch approval is consumed; no retry is queued. `performance_accepted=false`, `collection_ready=false`.

A post-run AST/runtime check also found an unreached completion-path defect: the inherited guest calls `performance.summarize`, but [the frozen new adapter](performance_v2.py) does not export it. Local `getattr` reproduces AttributeError; this did not cause the earlier case007 stop. Prelaunch tests missed this complete-design adapter path. Measured sources/evidence are now immutable. Any repair needs a separate version and complete84-case API regression; any new measurement needs explicit review/authorization. Quiet-file capture handling under the unchanged no-traffic gate, approved performance acceptance and final common payload/helper/null/order/scoped release gates remain unresolved. Existing417 assignments, approved tasks/limits and all older evidence remain unchanged; no malware/full collection, fitting, historical resume/merge or service/policy change is authorized.

The separately approved [V4 bounded startup correction](CAPTURE_LIVENESS_PROTOCOL_V4.md) completed its [one actual six-control diagnostic](capture-liveness-v4-readiness/20261023T114938416460Z/guest_result.json), with exact unchanged null argv, four independently recovered internal-Sink HTTP200 transactions and both quiet cases passing the original quality gate. The [saved-only independent audit](capture-liveness-v4-readiness/20261023T114938416460Z/audit-v4-derived-20261023T115433685531Z.json) verifies139 safe members,40,560 finite cells,190 reconciled PCAP records, all lifecycle deadlines, actual28s full-recorder attachment and three exact executed-inode/v6 receipts with zero error/loss counters. FINISH precedes unchanged original teardown; startup's actual authenticated probe3 succeeded within21.251s of its absolute120s budget. The frozen inherited audit initially compared integer Python dictionary keys to JSON string keys; a [separate saved-only auditor](audit_capture_liveness_v4.py) corrects only that comparison and rejects six altered case/value/type probes, without changing measured sources or rerunning controls. Saved and fresh read-only checks confirm original TLS/off, Sink/running/internal-only, unchanged production pins and no competitor. The two quiet intervals contain22/21 packets; this is not continuous-completeness proof, automatic transfer of the diagnostic lifetime, performance acceptance or a collection release. The approved launch is consumed. A separately reviewed and explicitly authorized corrected performance attempt and final common payload/helper/null/order gates remain required; `collection_ready=false`.

The separately approved [V3 lifecycle/publication correction](CAPTURE_LIVENESS_PROTOCOL_V3.md) is implemented and locally tested, preserving every V2 numeric limit and all original feature/helper ASTs. Its [one actual launch](capture-liveness-v3-readiness/20261023T111107169124Z/failure.json) successfully staged a fresh child but stopped at `Guest login event timed out`, before invoking any diagnostic control or helper transaction. The [independent saved-only launch audit](capture-liveness-v3-readiness/20261023T111107169124Z/launch-audit-20261023T111521144771Z.json) verifies30 frozen source hashes,17 safe payload members, exact planned argv/order, unchanged helpers and saved cleanup. Original TLS/off and isolated Sink/running were also freshly verified read-only. This supplies no actual V3 FINISH/attachment/liveness or performance evidence. The notification wait fails before the launcher's Guest Control probe; the underlying readiness cause and whether that unattempted probe would have worked remain unresolved. V3's one approval was consumed; the separately approved V4 result above does not relabel this failure. No benchmark/malware launch, fitting, traffic padding, service/policy change or limit relaxation is queued; `collection_ready=false`.

The user explicitly approved implementing and executing the [V2 diagnostic](CAPTURE_LIVENESS_PROTOCOL_V2.md), without changing its historical authorization flags or [V1](CAPTURE_LIVENESS_PROTOCOL_V1.md). The [actual attempt](capture-liveness-readiness/20261023T102537476340Z/guest_result.json) ran two exact null targets and stopped at the first failure. Original-pre passed: one bounded internal-Sink HTTP200 transaction and exact expected body recovered from78 PCAP records. Original-quiet had22 reconciled packets and zero reported loss, but failed `Finish request deadline`; it was not a no-traffic rejection. Original-post and all three full-condition cases did not run. The [saved-only prefix audit](capture-liveness-readiness/20261023T102537476340Z/partial-audit-20261023T102947067164Z.json) verifies37 safe members,13,520 finite cells,100 PCAP records, frozen hashes and both cgroup cleanups. Saved execution cleanup restored original TLS/off and isolated Sink/running.

The verified V2 ordering defect is that original sensor shutdown occurs between actual observation end and FINISH, despite V2's3s allowance. Those original shutdown routines permit waits longer than3s. The failed case did not publish its actual-end/FINISH clock bundle before rejection, so the exact violation is reported, not independently reconstructed from the original clamped20s modeling boundary. The accepted positive control does not settle quiet-capture completeness. No full28s attachment or performance result was obtained. Measured `.22` sources and evidence remain frozen; the separately approved V3 repair and its pre-control launch failure are described above. Original20s/40window semantics, approved tasks/timing/limits and417 assignments remain unchanged. `collection_ready=false`.

The [new exec-inode gate](exec-identity-readiness/20261023T075642576210Z/identity-validation-complete-20261023T080126521309Z.json) verifies four actual native x86 executed images at kernel exec stops, with exact task-lifetime/clock linkage, complete retrieval,83 safe members,27,040 finite cells,143 reconciled PCAP records and4,640 matching P4 window values. All reported counters are clean; twelve capture/receipt corruption guards reject. Earlier root-log publication failure remains preserved. The [handoff](REMEDIATION_IMPLEMENTATION.md#executed-inode-gate) distinguishes this bounded success from library/interpreter, arbitrary namespace/bypass/allocator and performance coverage. Cleanup restored original TLS/off and isolated Sink/running. Accepted `.19` and `.20` evidence and production `.18` remain separate and frozen.

The [original proposal](release-proposals/20261023T080357234937Z/proposal.json) remains immutable. The user approved the engineering-only16-pair/32-case scope and prospective limits, then the exact [source correction](release-proposals/20261023T081218460447Z/source-correction.json) after a [failed bounded source review](release-contracts/20261023T081114963922Z/contract.json). Five XorDDoS slots changed to reject an out-of-file ELF segment and cross-role identical executable regions. All16 benign identities, ABI/family/role quotas and417 existing assignments remain unchanged; code-region uniqueness is not certified lineage independence. No malware launch, fit, old resume or `.18` merge is authorized.

The [actual benign performance attempt](scoped-performance/20261023T082811709603Z/guest_result.json) stopped at case007: the first scored original-sensor file task had zero interface traffic despite recorded link up/carrier1. Eight amd64 file tasks completed correctly, but no scored full/original pair completed. The [saved-only independent audit](scoped-performance/20261023T082811709603Z/partial-audit-20261023T083438551253Z.json) verifies143 safe evidence members, all exact16MiB outputs,33,800 finite instrumented cells,96 reconciled PCAP records, actual exec receipts and all cgroup cleanup. Three baseline cases intentionally had no sensors; their original quality rejection is preserved. Neither the quiet capture nor unscored warmup timings establish performance acceptance. Original TLS/off and isolated Sink/running were restored. No measurement retry or budget change occurred. See [the current contract and performance outcome](REMEDIATION_IMPLEMENTATION.md#proposed-release-contract). `collection_ready=false`; a separately reviewed liveness-control/implementation protocol is required before another measurement.

The [integrated candidate guest result](integrated-collector-readiness/20261023T073025468843Z/guest_result.json) accepts four actual benign captures: amd64 null/file/internal-Sink TCP+UDP and static-i386 xxhsum. Candidate schema is `2026-10-23.19-attribution-candidate`; production `.18` and all feature/helper implementations remain unchanged. An authenticated broker moves only the blocked existing Bash wrapper into a temporary cgroup after sensor readiness. All four targets exit0 with original sensors active, zero reported errors/loss and cgroups removed. Earlier parser and cgroup-permission failures are preserved, not relabeled. Six UDP sends/captures do not establish UDP application acceptance.

The [saved-only host audit](integrated-collector-readiness/20261023T073025468843Z/validation-derived-20261023T073511619318Z.json) verifies75 safe archive members,27,040 finite feature cells,138 reconciled PCAP records, four unique recorded-window alignments and4,640 P4 window-cell comparisons with zero mismatch using Ethernet bytes/nominal rates. Four corruption guards reject; the original59 runner/exec-boundary tests pass. Saved and fresh checks confirm original TLS/off and isolated Sink/running. This completes the bounded integration gate, not general executable-inode/hash attestation, ownership/frame coverage, rate/performance acceptance or a study allocation. Exact future units/roles/quotas/precision and release-specific payload/null/order rehearsal remain pending; `collection_ready=false`. No malware/full collection, fitting, old resume, policy change or `.18` compatibility merge occurred. See the [implementation handoff](REMEDIATION_IMPLEMENTATION.md#integrated-collector-gate).

The [actual additional benign guest gate](additional-benign-guest-readiness/20261023T065653342361Z/readiness.json) now accepts all24 substantive static amd64/i386 task variants,429 safe evidence members and428 input/output hashes. Eight actual guest-generated C outputs also compile and execute correctly on the host, explicitly not a guest compiler claim. The fresh child was restored to original clean TLS/off with Sink running/internal-only. No BPF, malware, collection or policy change occurred. The [successor exact assessment](current-release-assessments/20261023T065959031921Z/readiness.json) rehashes387 inputs and finds a maximum16 hypothetical matched pairs from the16 independently counted benign program units/32 variants. This does not prove malware-lineage independence or assign future roles/quotas. Existing417 exploratory roles remain unchanged; common new-schema integration, reviewed prospective roles/precision and remaining scoped attribution/performance/release gates still block collection.

The subsequent approved [additional benign source preparation](additional-benign-preparation/20261023T061710877601Z/source-authentication.json) authenticates twelve independent new projects. All24 static amd64/i386 builds pass independent ELF-header/hash checks, and [all24 substantive host task variants](additional-benign-workloads/20261023T065054122807Z/result.json) now pass. Variants remain twelve program units; prior failures are preserved and unchanged successful tasks are explicitly reused. The [handoff](REMEDIATION_IMPLEMENTATION.md#current-measured-state) records the checks and limitations. No new guest result, collection release, prospective allocation, model fit or policy change is implied; guest/common-schema/scoped coverage/performance and exact role/quota gates remain open. The four-unit matching assessment below is its earlier immutable checkpoint, not a claim that no later programs have been built.

The [actual v6 mixed-ABI audit](attribution-live-capability/20261023T055432338935Z/validation-derived-20261023T055556476378Z.json) verifies real guest load/attachment, one actual same-task amd64 exec59 to i386 return11 transition, two UDP echoes, four sends/four receives, eight exact marked IP snapshots and two install/close/final matches. All 3,211 observations reconcile with zero error/loss counters; seventeen specific plus five generic corruptions reject. Actual exit ID/ABI and originating entry fields remain distinct. The earlier positive-counter v5 attempt remains failed and unchanged.

The [paired overhead audit](attribution-live-capability/20261023T060303975236Z/validation-derived-20261023T060510784262Z.json) verifies three baseline and three instrumented 32-echo runs, AB/BA/AB order, all 192 actual echoes and zero error/loss counters in every instrumented capture. Both conditions use temporary per-run cgroups. Median wall time is 93.04ms baseline versus 93.34ms instrumented (+0.32%); paired ratios range0.8972-1.0917. These short Python-plus-echo measurements do not establish a general performance budget, stress/loss envelope, kernel-map memory or global-hook overhead. Fork/exec maximum RSS includes parent memory and is not steady-state process memory. The first private-manifest permission failure remains preserved; no success gate or policy was weakened. Cleanup restores original TLS/off and isolated running Sink.

The [current release assessment](current-release-assessments/20261023T060937943623Z/readiness.json) independently verifies270 inputs, all seven prior-plan manifests and strict remaining source headers:10 amd64-static,225 i386-static, zero unused amd64-dynamic in the checked pool. Eight validated builds remain FOUR program units, allowing at most four hypothetical matched pairs from these units, not a global maximum or selected release. Existing417 exploratory known-family assignments are hash-verified unchanged; no new roles or quotas are assigned. New common runner/schema/launcher/snapshot integration, reviewed prospective units/roles/precision, remaining scoped coverage and performance acceptance are still incomplete. `collection_ready=false`; no malware/full collection, fitting, old resume, production/data or privileged policy change occurred. Earlier paragraphs below record prior bounded phases, not current blanket absence of those capabilities.

The [same-PID exec/CLOEXEC derived gate](attribution-live-capability/20261022T170107824584Z/validation-derived-20261022T171611222897Z.json) verifies flagged-socket filp_close during exec, matching deferred final release, actual EBADF and retained-socket use afterward: two exact echoes, 6,259 observations, four sends/four receives and eight marked snapshots with all error/loss counters zero. Thirteen specific plus five generic corruption guards reject, including a missing second retained close. Final release occurred 11,825ns after exec success, falsifying the original timing hypothesis; that failed report/protocol remain preserved. One first-send entry cookie is uninitialized and requires exact raw-FD proof plus a nonzero completion, never an injected cookie. Cleanup restored original TLS/off and isolated running Sink. General attribution and collection readiness remain false.

The [bounded descriptor-history gate](attribution-live-capability/20261022T164356740045Z/validation-derived-20261022T164937888396Z.json) adds actual forked inheritance, retained parent use and SCM_RIGHTS receive/install/use/close evidence for one shared UDP socket: three exact echoes, 3,278 observations, six sends/six receives and 12 complete marked IP snapshots, all error/loss counters zero. The original failed report remains preserved; derived validation handles FD-number reuse and explicitly records three receives that requested no peer-address output. Five generic and ten descriptor corruption guards pass without a guest rerun. The [saved TCP audit](attribution-live-capability/20261022T142433957154Z/validation-derived-20261022T165134075557Z.json) additionally verifies an actual shared thread files table and worker-installed accepted socket. Cleanup and production pins pass. These are bounded histories, not arbitrary ownership, exec-time CLOEXEC closure or collection release.

The [HTTP Ethernet gate](attribution-live-capability/20261022T163150993977Z/validation-derived-20261022T163427626540Z.json) now verifies four actual Sink HTTP200 receipts and application body hashes, four inode/cookie install-final matches, and 48 unique exact IP-byte-to-Ethernet-frame joins under recorder clock bounds. Actual application/capture namespace cookies and process namespace inodes agree. All 3,890 observations reconcile with zero error/loss counters; independent PCAP parsing confirms 94 received/captured/file frames with zero drops. The 46 residual frames remain unassigned. The original namespace-contract failure is preserved separately. Cleanup removed the cgroup and restored original clean TLS/off plus isolated running Sink. This is a bounded diagnostic using a separately frozen 4096KiB capture, not production capture acceptance or general ownership. `collection_ready=false`; shared/transferred FD, mixed ABI, bypass, hash, overhead/integration and exact allocation gates remain open. The approved target is the largest feasible independently matched cohort with retained exploratory known-family roles, not blind evaluation or permission for malware/full collection. Loopback-only statements below describe the earlier UDP/TCP gates.

Later gates add [connected UDP plus a bounded duplicate/close check](attribution-live-capability/20261022T142008554211Z/validation-derived-20261022T142748557966Z.json) and [TCP application/cookie/inode/data evidence](attribution-live-capability/20261022T142433957154Z/validation-derived-20261022T142748127251Z.json). TCP's original failed report is preserved; a derived-only audit corrects the blocking-connect assumption using actual EINPROGRESS, the subsequent SO_ERROR call and real data exchange. No task was rerun for that audit correction. Both gates have zero error/loss counters and saved clean isolated cleanup. All traffic remains loopback; no Ethernet-frame ownership or full descriptor coverage is claimed. `collection_ready=false` while frame/namespace/hash/bypass/overhead/integration and actual study allocation gates remain open.

The [live handoff](REMEDIATION_IMPLEMENTATION.md#actual-live-capability) records actual guest load/attachment after preserved verifier and lifecycle-boundary failures. The [v5 pass](attribution-live-capability/20261022T140909677363Z/guest_result.json) loaded 23 programs and verified 16 UDP application echoes, 32 completed sends, 32 completed receives, 64 exact packet markers and a genuine parent-linked clone return, with zero recorded error/loss counters. Cleanup restored original clean TLS/off; Sink remained internal-only/running. This is one bounded loopback task, not complete descriptor/namespace/Ethernet-frame attribution or overhead evidence. Ownership/frame flags and `collection_ready` remain false. No malware/full collection, model operation, role change or production edit occurred. Further benign coverage and exact release identities/roles/prospective evaluation remain open; earlier no-load statements below are historical.

## Earlier Readiness Continuation

The [updated implementation handoff](REMEDIATION_IMPLEMENTATION.md#current-repair-pass)
records the compatible static netcat repair: the
[single-task guest check](remediation-static-guest-readiness/20261022T133122216945Z/readiness.json)
accepted its original exact-byte task and reused three unchanged static passes.
All four dynamic tasks passed earlier. These are still four program/project
units, not eight independent samples. Original failures are preserved; no guest
policy or success criterion was weakened.

The separately versioned [v3 allocator candidate](attribution-v3/build_allocator.py)
uses a guest-present free hook in place of v2's unavailable `close_files` hook.
All 21 programs/recorder and offline guards pass, including a field check against
saved actual guest BTF. This is not verifier, attachment or live lifetime proof.
No BPF load/attachment, malware/full collection, model fitting or role change
occurred. The guest was restored to the original powered-off isolated baseline.
Exact matched identities, complete lifetime/frame attribution, a frozen live
pilot and release gates remain open; `collection_ready=false`. Do not attach the
unsupported v2 object or infer live readiness from v3 build/type checks.

## Benign Builds And Attribution Implementation

This section records the initial build-only phase, before the continuation above.

The user approved the next benign acquisition/build and separately versioned
instrumentation phase. The [implementation report](REMEDIATION_IMPLEMENTATION.md)
records four authenticated source builds: libarchive/bsdtar, Perl, ImageMagick/convert
and netcat-openbsd/nc. Actual ELF checks establish four distinct native amd64
dynamic binaries, not i386-static coverage or validated workloads. Ten build
dependencies were extracted locally, without system installation or policy changes.

The new `attribution-sensor-v1` candidate compiles eleven BPF programs and a
userspace recorder. Offline record/loss/argument guards and object inspection pass;
no BPF was loaded or attached. Packet current PID is not ownership, and all frame
and ownership verification flags remain false. Complete descriptor/lifetime
history, namespace/frame mapping, guest verifier support, application receipts,
overhead and a frozen benign-only pilot remain open. Interface-wide P4 is unchanged.

[Independent verification](remediation-preparation/20261022T122641888212Z/independent_verification.json)
rechecked source/dependency identities, four ELF/NEEDED records, sensor sources and
outputs, and unchanged production/source-dataset pins. No target workload, VM,
capture, model fit or new dataset allocation occurred. `collection_ready=false`.

## Source Feasibility And Attribution Design

This section describes the earlier design-only phase, before the approved builds above.

The [implementation handoff specification](REMEDIATION_SPEC.md) records the next
offline phase:334 exact build identities checked,22 unused build variants but
only16 project/program units and zero new projects. No new activity range was
measured. Eight additional projects have cached signed source metadata, not
acquired/built/preflighted executables. The
[feasibility summary](remediation-feasibility/20261022T121416376772Z/summary.json)
and exact source/task proposals preserve these distinctions. Offline signature
and source hashes were rechecked; independent ELF/exclusion verification checked
all334 candidates and544 input hashes.

The attribution specification defines complete socket/process/lifetime/frame
evidence, unknown/shared cases, UDP application receipts, ABI export and an
unexecuted benign pilot matrix. The [synthetic oracle](attribution_contract.py)
passes19 ownership cases plus invalid-endpoint rejection, not live attribution.
No collector/source acquisition/build/workload/VM/model operation occurred in
this phase; production pins and historical artifacts remain unchanged.
`collection_ready=false`; implementation and benign validation need separate
authorization and frozen inputs. Existing interface-wide P4 is not silently
replaced with PID-filtered traffic.

## Offline Remediation Audit

The user approved the offline relationship audit and remediation protocol, not
another collection or detector release. The [remediation plan](REMEDIATION_PLAN.md)
records the verified gaps, review decisions and ordered next gates. The
[audit report](remediation-audit/20261022T114711085419Z/REPORT.md) covers all417
accepted source identities and43,284 same-mode binary comparisons. Fifteen
identical-executable-region groups cover43 malware cases;12 groups cross the
exploratory resplit, none the original group-disjoint allocation. This is not
proof of identical whole programs or independently verified lineage. TLSH
produces cross-label/common-runtime warnings and is not used to automatically
deduplicate or assign splits. The three occupied activity/mode cells missing
benign coverage and Coreutils/Mirai concentration are explicit sourcing targets.

Independent verification reproduced all417 ELF/code/TLSH fingerprints and
all6,782 relationship edges;1,737 input hashes and production pins passed.
No sample execution, VM operation, model fitting or new prediction occurred.
The frozen gate protocol keeps `collection_ready=false`. Previously consumed
validation remains exploratory; missing telemetry cannot be recovered.

## Completion And Model Results

The user separately authorized completion checks and model fitting. The frozen
96-position collection finished; 91 runs were retrieved and five malware runs
failed. Two retrieved malware captures were quality-rejected (packet discrepancy
2, and 1,877,062 lost eBPF events); three further malware cases lacked observed
target exec. Failures are preserved and excluded, not retried or replaced.
The retrieval audit verifies 615,160 finite feature cells, 1,101 safe matching
archive members and 171,034 PCAP records. These are bounded structural/sensor
checks, not proof of malware activation or general capture completeness.

[Derived extension analyzer](analyze_matched45.py) freshly reconciled raw
features, archives and PCAPs, matching the frozen schema, architecture/linkage,
target-exec, ABI, quality and split rules. Eighty extension cases are host-eligible;
67 also have unique P4 alignment/parity. Nulls are calibration only, and low
activity is retained. Previous captures/models and split roles remain unchanged.

The new joint dataset has 417 host-eligible cases. The primary common-aligned
comparison uses 259 training cases and 107 validation cases (60 benign/47 malware),
with no duplicate executable identities or train/validation group overlap.
All 53,070 PCAP-versus-stored P4 and 72,975 host-summary comparisons match.
RF settings, training-only feature selection and the 145/145/290 budgets are fixed.

| Model | Accuracy | Balanced Accuracy | ROC-AUC |
| --- | ---: | ---: | ---: |
| P4 network | 64.49% | 62.80% | 0.669 |
| Host | 93.46% | 93.71% | 0.976 |
| Hybrid | 89.72% | 90.14% | 0.952 |

Host makes five false positives/two false negatives; hybrid eight/three.
Host performed better on this evaluation; it is not evidence that the hybrid
generalizes better. Group-bootstrap intervals overlap. All 100 training-only
group-label permutations completed; they are not validation significance tests.
The older i386 subset still has high activity-only discrimination. Coreutils
concentration, task/toolchain/acquisition differences and exclusion bias remain.
Previously consumed validation is exploratory, not a new blind test. P4 is
offline PCAP reconstruction, not live-switch measurement.

Authoritative [metrics](combined-analysis/20261022T092936019065Z/analysis/model-fit/metrics.json),
[compatibility audit](combined-analysis/20261022T092936019065Z/analysis/compatibility_audit.json),
[case exclusions](combined-analysis/20261022T092936019065Z/analysis/extension_eligibility_audit.csv)
and [verification](combined-analysis/20261022T092936019065Z/verification.json)
are in a separate derived attempt. Saved primary models reproduce every saved
probability exactly. Final fresh read-only checks confirmed the guest restored,
powered off and isolated; the Sink remains internal-only. No new sample execution,
VM operation, policy change or historical batch resume occurred during modeling.

## Matched45 Collection Started

The user explicitly authorized one capture of the frozen 96-entry order: 45
malware, 45 benign and six null controls. The dedicated VS Code task is
`Collect matched45 extension (capture only)`.
[Launch manifest](matched45-readiness/20261022T072823231146Z/collection/launch_manifest.json)
records start `2026-10-22T08:04:00.491963+00:00`, coordinator PID `2377581`,
the accepted snapshot/UUID and frozen source hashes. Its
[status](matched45-readiness/20261022T072823231146Z/collection/status.json)
and [streamed batch log](matched45-readiness/20261022T072823231146Z/collection/collection.log)
are the current progress sources. At confirmation the three initial null
controls had completed and position 4 had started. These are progress counts,
not final quality or activation acceptance.

The capture-only coordinator preserves failures, forbids retries, replacements
and resume, and restores the original powered-off isolated TLS snapshot on
completion or interruption. Do not start competing VM work or edit pinned
workflow/collector inputs while active. No model fitting or merge is queued.
Retrieval auditing is not merge acceptance: exact target/mode/ABI, null and
unique recorded-window Ethernet/nominal P4 parity gates remain pending.
Readiness records below retain their historical no-full-collection flags;
the separate launch manifest and status record the newly authorized execution.

## Matched45 Benign Readiness Checks

The user requested collection readiness for the frozen 45 malware and 45 benign
identities. This authorizes bounded benign workload and benign/null sensor checks
only. Full collection, malware execution, model fitting and old-batch resume are
disabled; eventual launch requires separate authorization.

[Host evidence](matched45-workloads/20261022T071951046972Z/host_preflight.json)
accepts all 45 exact benign workloads under DEVNULL stdin, bounded runtime and
strict zero-exit plus substantive output/state checks. Filesystem tools operate
only on disposable regular files/images, never block devices. The first host
attempt (41/45) and its CLI/fixture-contract failures remain preserved.

The current frozen [release protocol](matched45-readiness/20261022T072823231146Z/protocol.json)
contains 45 malware transports, 45 benign transports and six null repetitions
across the three matched native modes. The 96-position order and exploratory
preregistration preserve inherited group roles, exclusions, 27/18 per-label
split budgets and 145/145/290 feature/model rules. All 45 guest workloads and all
96 transport dry-runs passed; all 19 benign/null sensor gates passed and their
saved evidence was independently reproduced. A transport-only `mklost+found` naming repair replaced `+` in the outer
ZIP filename, not the executable basename or identity. The prior failed release
and its passing guest report remain unchanged.

[Independent saved-evidence auditor](audit_matched45_readiness.py) checks the
package, exact original executable names/hashes, fixtures, arguments, mode/split
budgets, readiness evidence hashes, archives, PCAP reconciliation and nulls. Its
full mode also rejects injected packet discrepancy, eBPF loss and absent target
exec. It never operates a VM or executes samples. Both package and full saved
readiness validation passed.

Authoritative [readiness record](matched45-readiness/20261022T072823231146Z/gates/20261022T072901422487Z/readiness.json)
has `collection_ready=true`, `full_collection_started=false`, `malware_executions=0`.
The [independent recheck](matched45-readiness/20261022T072823231146Z/gates/20261022T072901422487Z/readiness-recheck-20261022T074431583615Z.json)
verified 19 exact native target execs, 128,440 finite feature cells, 233 safe archive
members matching host output, and 1,376 PCAP records matching received/captured
counters. Reported PCAP kernel drops, counter discrepancies, eBPF losses and
unresolved ABI counts were zero; capture buffers were restored. Three injected
negative probes were rejected. Null maxima are amd64 dynamic30, amd64 static20,
i386 static20, giving descriptive activity floors55/45/45, not delivery or
maliciousness criteria and not primary-analysis exclusions.

Use accepted snapshot `clean-matched45-v18-20261022T072901422487Z`, UUID
`a3af439c-ad5f-403c-a7fe-df2676c17999`, only after separate launch authorization
and fresh safety/hash checks. Do not rebuild the frozen payload/order or use the
earlier failed release. Final saved and fresh read-only checks confirmed the
guest powered off on original `clean-tls-paired-2026-10-19`, internal malnet only;
Sink remains running/internal-only and no workflow process remains.

This is bounded benign readiness, not arbitrary malware activation or stress/loss
certification. Mutations outside archived workspaces were checked in direct guest
preflight, not claimed recovered from capture archives. Coreutils27 training
concentration and task/toolchain/activity/acquisition confounds remain. Consumed
validation remains exploratory. Future captures still require strict per-run
quality/exec/archive checks and unique offline Ethernet/nominal-rate P4 alignment
and parity before merging; readiness is not permission to launch automatically.

## Current Merge Readiness

The user requires eventual merging with the current data, not an independent
incompatible dataset. The anchor is the completed joint analysis at
`cohort-expansion-100x100-v18-20261021/combined-analysis/20261022T044439885696Z/`:
337 host-eligible / 299 common-aligned cases from the two 100+100 collections.
These are actual eligible populations, not 400 automatically accepted inputs.
Retained family/project roles, duplicate/program exclusions and the global
DDoSAgent/util-linux exclusions remain fixed. Both old validation sets are
already consumed; the extension remains exploratory, not newly confirmatory.

Authoritative new evidence:

- [Verified recovered sources](source-recovery/20261022T055952526099Z/source_verification.json):
  535/535 source/member identities match, missing 0. Sources are 450 raw ELF
  `.triage` files plus 85 archives. Copied files have mode 0600; archive members
  were only streamed for inspection. Identity verification is not activation.
- [Merge-readiness assessment](merge-readiness/20261022T060242194318Z/readiness.json)
  and [per-candidate audit](merge-readiness/20261022T060242194318Z/candidate_audit.json):
  `collection_ready=false`, status `blocked_before_release_preflight`.
- [Saved final VM state](source-recovery/20261022T055952526099Z/final_vm_state.json):
  guest off on `clean-tls-paired-2026-10-19`, NIC1 intnet/malnet and NICs2-8 none;
  Sink remains running/internal-only. A fresh read-only check confirmed this.

Of all 535 recovered identities, 29 are strict-static amd64, 5 interpreter-linked
dynamic amd64 and 273 strict-static i386. Other modes, including eight i386
static-PIE cases, one dynamic i386 and one unresolved bounded program-header
parse, are outside the existing primary merge contract. Header modes are not
guest execution/dependency evidence.

After prior-identity, mode, excluded-group and unresolved-group-role checks,
278 malware are **source-stage candidates only**: amd64 static28/dynamic5 and
i386 static245, training62/validation216. They cover eight existing groups:
BillGates7, CatStorm1, CoinMiner5, Gafgyt1, GetShell2, Mirai45, Prometei9,
XorDDoS208. Source availability no longer blocks this pool; these counts do not
constitute a selected collection manifest.

Do not append all original training records as training: 251 malware and 227
benign script entries inherit **validation-group** roles in the current combined
allocation. Their old training labels cannot override global group separation.
The four candidate benign project labels absent from the combined allocation
also need whole-project roles reviewed before release.

**Approved preparation target:** the user approved 45 malware plus 45 matched
benign cases, with at most 10 malware per family. Exact identities are now frozen
in [the matched identity attempt](matched45-identities/20261022T070700658382Z/identity-readiness.json),
not an accepted collection release. Expanding to the entire source pool would
mainly add XorDDoS validation cases, not diverse training evidence.

### Approved 45+45 Identity Allocation

Both labels have 27 training and 18 validation cases, with these identical
architecture/linkage budgets:

| Role | Mode | Cases Per Label |
| --- | --- | ---: |
| Training | Native amd64 dynamic | 5 |
| Training | Native amd64 static | 16 |
| Training | Native i386 static | 6 |
| Validation | Native amd64 static | 3 |
| Validation | Native i386 static | 15 |

[Malware identities](matched45-identities/20261022T070700658382Z/malware-selection.json)
were selected without runtime-outcome filtering: sort family/mode/hash, then
round-robin modes within each family to cap 10. Family counts are BillGates7,
CatStorm1, CoinMiner5, Gafgyt1, GetShell2, Mirai10, Prometei9 and XorDDoS10.
Existing family/project roles and the global exclusions remain unchanged.

[Benign identities](matched45-identities/20261022T070700658382Z/benign-executables.json)
have 45 distinct hashes and project/program pairs, with no reuse of either prior
cohort's planned identities/programs. All 90 identities and their source files
were hash-checked; strict ELF headers match the intended modes and split quotas.
Sources for the seven selected benign projects were checked again against signed
Ubuntu source indexes. Some candidates are previously uncredited outputs of
accepted full builds; their individual hashes are first frozen here, not claimed
as previously accepted workloads or independent rebuilds.

The [new build report](matched45-builds/20261022T065930151864Z/build.json)
accepts 13 build-only outputs from Coreutils, Less, XZ, net-tools and SQLite.
Earlier failed attempts are preserved. Repairs used normal Coreutils generated
header dependencies, scoped workspace terminal libraries, and Libtool
`-all-static` at final link. The user separately approved continuing local build
repair after the third attempt failed actual ELF linkage validation. No system
package installation, guest policy change or target workload execution occurred;
compiler/configure helper programs did run on the host.

**Diversity limitation:** all 27 additional training controls are Coreutils
programs, not 27 independent projects. Validation controls are e2fsprogs8,
XZ3, Less2, net-tools2, sharutils2 and SQLite1. Matching modes and fresh hashes
does not remove project/task/activity/toolchain confounding. Identity-only reports
remain build/identity evidence, not runtime acceptance; subsequent benign workload
and sensor evidence is recorded separately above.

The later readiness request authorized benign workload/guest/sensor checks, but
not full collection. The identity-stage `collection_ready=false` is immutable;
only a separate accepted release can supersede that operational state. Future captures must
match the current `.18` runner/hash/settings, 40x169 telemetry and 145/145/290
analysis contract. Post-collection archive/PCAP/quality/exec checks and fresh P4
alignment/parity remain mandatory before any actual merge.

`check_merge_readiness.py --self-test` rejects group-role collisions, duplicate
identities, globally excluded groups and static-PIE scope changes. Run its
`--source-verification <saved-source_verification.json>` mode from the study root
for a new pinned assessment. `--require-ready` returns exit 2 when blocked.
The initial source-export login race and first archive-only inspection report
are preserved. The corrected source verification ran offline on saved files,
not by rerunning samples or repeating the successful export.

## Recommendation

Use the original 535 malware identities as a **development/source-recovery
pool**, and the 500 benign scripts as a **task/fixture library**. Do not resume
the old batch, concatenate its telemetry with current data, or call these pools
an untouched final test. Prioritize verified sources, independent groups and
matched execution/workload coverage over reaching 500 cases per label.

Source recovery and strict identity/mode allocation are complete. The next gate
is substantive benign workload and guest/sensor validation, not training. A separate
final evaluation requires genuinely reserved independent data and a protocol
frozen before its outcomes are inspected.

## Measured Inventory

Authoritative evidence:
[summary](attempts/20261022T052110153141Z/summary.json),
[malware identity review](attempts/20261022T052110153141Z/malware-535-review.json),
[benign workload review](attempts/20261022T052110153141Z/benign-500-review.json).
The two earlier attempts are retained: the first used narrower catalogs; the
second added original exact-hash labels. The final attempt adds historical
model exposure and case-normalized group counts.

| Pool | Verified inventory fact | Design consequence |
| --- | --- | --- |
| Original malware training | 535 distinct hash-named identities; 517 retrieved, 8 runner failures, 10 output-copy failures | These are not 535 quality-accepted or activated runs |
| Family labels | 14 case-normalized acquisition-label groups | Not 535 independent families; broader taxonomy remains subject to review |
| Concentration | Mirai 236 + XorDDoS 234 = 470/535 (87.9%) | Uncapped expansion would mostly reinforce two existing families |
| Other labels | CoinMiner 9, Prometei 9, Gafgyt 8, BillGates/CatStorm/DDoSAgent/Kimwolf 7 each, FlylegitBot 4, Akira/GetShell/PromptLock 2 each, Qilin 1 | Useful development diversity, but many groups are tiny |
| Historical use | Label table marks 521 training, 14 not in that older model | Not an untouched test, even when absent from recent models |
| Recent native case overlap | 26 previously planned native-cohort identities, all XorDDoS; 509 absent from those two case orders | Absence from recent orders does not imply historical novelty |
| Source coverage | 72 archive/member identities independently hash-verified from current catalog paths; 463 sources not located in those catalogs | Recover original sources before deciding architecture/linkage quotas |
| Immediately available additional native sources | 16 strict-static i386, plus one i386 static-PIE exception; together 15 XorDDoS and 2 Mirai | Not sufficient to solve family diversity or justify changing the static-only scope |
| Saved architecture evidence | 85 `chosen.txt` records, including 27 x64; 450 lack that record | Log architecture is not independently verified linkage or target activation |
| Original benign training | 500 distinct script hashes, all shebang scripts | Script identity is not executable identity |
| Benign diversity | 108 declared package/template pairs across 22 package labels | Repeats are nested within templates/projects, not independent software sources |
| Benign collection state | 286 retrieved, 1 partial, 213 not started | Do not resume merely to complete the count |
| Endpoint review | 164 profiles declare controlled downloads; 182 contain URL authorities needing isolated-endpoint review | These are different checks; neither proves public-network communication |

The 535/323 original malware identity lists do not overlap. That historical
split does not restore independence after their data have been explored.
FlylegitBot and Kimwolf are absent from the two recent native case-order group
sets, but were explored in earlier family/mode work. DDoSAgent was explicitly
excluded from the joint fit to resolve a role collision; do not silently
reintroduce it into that experiment.

Known catalog source members were streamed into memory with a 64-MiB bound;
none was written as an executable or run. `ET_DYN` without an interpreter is
recorded as static-PIE, not silently folded into static. Header facts do not
establish successful guest execution. The bulk original input location recorded
in extraction logs is guest `/home/csci/Downloads/model training`; no guest was
booted or source exported during this review. The desktop/downloads directory
listings did not reveal a separate bulk source directory, but this is not an
exhaustive assertion about all host storage.

## Three Dataset Roles

1. **Historical diagnostic archive:** retain the old `.18.1` captures for
   debugging, source linkage and workload investigation. One retrieved malware
   capture reports positive kernel PCAP drops. The old metadata lacks the
   current target-exec/quality contract; retrieval success is not acceptance.
   Never merge old and current telemetry without a justified compatibility audit.
2. **Development/training pool:** use source-verified identities absent from
   prior case orders where practical, but disclose historical exposure. Reuse
   validated current captures for development when their settings and roles fit.
   New captures require a separate frozen run using the latest verified runner;
   do not modify frozen snapshots or resume old experiments with new code.
3. **Final evaluation:** reserve whole independent malware groups and benign
   upstream projects, preferably acquired later, before viewing outcomes. A
   later sample from a known family can support temporal transfer, not a claim
   about unseen families. Previously examined cohorts cannot become blind tests
   through resplitting or renaming.

## Proposed Experimental Design

Question: does P4 add useful detection information beyond host counters after
execution mode and workload/acquisition shortcuts are controlled?

- **Execution strata:** prefer a native-x64 primary study, separately reporting
  static and interpreter-linked dynamic binaries. Final feasibility depends on
  recovered headers, not the 27 logged x64 names alone. Add native i386 only if
  both labels have enough independent matched groups in each partition. Keep
  emulated modes in a separately declared secondary study; emulator host syscalls
  must not become a label shortcut. Static-PIE remains separate pending review.
- **Groups before counts:** normalize source taxonomy and upstream project
  aliases, audit duplicate hashes and near-duplicate/build lineage, then assign
  whole groups. Do not randomly split repeated profiles or choose only prior
  exit-zero/network-active malware. Use a deterministic, outcome-independent
  group/mode allocation and report any infeasible constraint rather than waive it.
- **Family concentration:** cap dominant families in the development pilot and
  report macro/group-weighted results as well as sample-weighted results. A cap
  of 10 per family would reduce the 509 additional recent-order identities to
  at most 85 before source, mode or quality checks. This is a feasibility
  illustration, not a frozen cap, sample manifest or claim of 85 ready cases.
- **Benign tasks:** reuse substantive comparison, archive/compression, search,
  database, process and network tasks from the scripts, but launch actual native
  tools with safe argument/fixture manifests and preserve multicall basenames.
  Do not add helper `curl` traffic to unrelated file tasks. Use real loopback or
  isolated-Sink services for intended HTTP/TLS/SSH/transfer tasks on both labels'
  common environment. Interactive tools require validated noninteractive modes;
  help/version output is not successful substantive activity.
- **Candidate project expansion:** after aliases, netcat-openbsd, OpenSSH, Perl
  and Vim are absent from the current combined project's labels. These are
  candidates for investigation, not newly authenticated or globally untouched
  controls. Keep all executables/profiles of a project in one group. Source,
  linkage, safe tasks and guest dependencies still need verification.
- **Activity:** include overlapping ranges of real target lifetime, active
  windows, syscall and network activity across labels. A 20-second observation
  does not imply a 20-second task. Use predefined workload intensity bands and
  null controls; do not discard quiet targets or pad malware behavior to obtain
  a preferred distribution. Report matched-activity sensitivity separately.
- **Acquisition controls:** common clean snapshot, launcher, watch scope,
  fixtures, services, observation settings and sensor configuration for both
  labels. Interleave labels and strata in a frozen seeded order. Record compiler,
  libc/linkage and source provenance; architecture matching alone is insufficient.
- **Network attribution:** separate target-attributed, background and unresolved
  traffic using process/descendant socket evidence, flow tuples, timing and Sink
  logs where available. A connect attempt is not a successful connection; a NIC
  packet is not automatically sample-generated. Verify TLS/QUIC with a dissector.
  Any required collector instrumentation needs its own reviewed version/schema;
  this proposal does not change the current runner or historical features.
- **Coverage and loss:** publish every attempted identity and failure. Keep
  retrieval, sensor quality, exact target exec, activity and verified task output
  separate. Freeze the primary eligible-set rule and show attrition by label,
  family and mode; retain low activity. Preserve rejected/lost traces and do not
  silently retry or replace them. Check relevant event-rate stress behavior;
  earlier buffer successes do not cover arbitrary bursts.

## Evaluation Contract

Keep the current 29 P4 / 29 training-selected host-family protocol: 145/145/290
columns, RF500/balanced/seed42/n_jobs1, threshold 0.5, training-only MI and
grouped folds. No cohort/architecture/task metadata enters the primary detector.
Use separate activity, acquisition/mode and build-provenance nuisance controls.

Report malware recall, benign specificity/false alarms, balanced accuracy, AUC,
group-weighted and per-mode/per-family results on the same eligible cases. For
hybrid versus host, predefine a paired difference in balanced accuracy and
group-aware uncertainty, rather than infer superiority from separate scores.
Selection, threshold decisions and any tuning stay within development data.
Freeze a single final evaluation before scoring it; no split search for a better
number. P4 remains offline reconstruction unless separately measured live.

## Next Gates

1. Recover/export the missing original sources and exact metadata without
   execution, with separately reviewed VM access if needed; verify archive/member
   hashes and headers. Review label confidence/taxonomy and historical roles.
2. Produce a source-verified, whole-group/mode feasibility table and safe native
   benign task manifest. Prefer underrepresented groups to extra Mirai/XorDDoS.
   Source new independent groups if the desired final claim is infeasible locally.
3. Agree dataset roles and quotas, then freeze protocol, identities, common
   snapshot, interleaved order and acceptance/exclusion rules. Reuse existing
   benign ABI/null evidence; only run new preflight for uncovered binaries,
   workloads or stress conditions after authorization.
4. Obtain explicit approval before guest operation/sample execution or new
   collection. No current source inventory or this recommendation grants it.

## Reproduction

From the study root:

```bash
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/audit_original_cohorts.py --self-test
/usr/bin/python3 -u data/versioned-collector/additional-study-review-20261022/audit_original_cohorts.py
```

Each invocation creates a separate timestamped review attempt and pins its input
hashes. Original captures, scripts and manifests are only read. The audit does
not certify package authentication, workload safety, sample activation,
never-recorded-event completeness or detector generalization.