# Prospective Benchmark Quiet-Capture Policy V1

Date: 2026-10-23. Status: local policy development only.

The user accepted proceeding with the recommended approach: "okay let's go
with your thoughts and instincts". This authorizes defining and locally testing
the revised benchmark-validation policy. It does not silently amend production
quality, authorize another VM attempt or launch malware/full collection.
The previous V3 attempt remains failed and its one-attempt receipt consumed.

## Decision

Keep the original collection-quality result byte-for-byte. A future separately
versioned benchmark may additionally classify a capture as
`quiet_with_bracketing_controls_not_completeness_proof` when its ONLY original
rejection is `packet_capture_interface_no_traffic` and every requirement below
passes. This is a benchmark capture-eligibility classification, not accepted
production quality, proof of continuous capture, a detector input or collection
readiness. It cannot retrospectively repair V3.

All other missing/positive loss, gap, ABI, link, identity, lifecycle, buffer,
task-result and raw-evidence failures remain blocking. A quiet capture must
have a valid independently parsed empty PCAP, exactly zero packet counters,
zero interface packet/byte/drop deltas, active sensors, unchanged buffers,
up/carrier1 receipts covering the observation and zero unresolved ABI/loss.
An empty file, unavailable counter or boolean posing as an integer does not pass.

## Independent Controls

A proposed future attempt adds FOUR separate positive capture-health controls:
original-pre, full-pre, then the original84 benchmark cases, then full-post,
original-post. Each control uses the existing exact native-amd64 null target
`null liveness_null 1` with ONE existing bounded numeric internal-Sink HTTP200
helper transaction outside its target cgroup, as in the preserved V4 diagnostic.
The helper request/response must be independently recovered from raw PCAP and
match actual application bytes, endpoints, namespace, clocks and the pinned
258-byte response body. Four distinct requests/evidence bindings are required.
There are no helpers in any measured benchmark case.

All controls and benchmark cases must bind to the same prospective attempt UUID,
manifest hash, snapshot UUID, actual guest boot, capture network namespace,
enp0s3 interface, frozen original capture/helper definitions and settings.
Both pre-controls must finish before every complete benchmark case starts;
both post-controls must start after every complete benchmark case finishes,
including its sensor setup and teardown. The raw control clocks must follow
the declared order; each helper stays inside its separate control envelope,
before that control's target observation and within the original2s bound.
No restore, namespace
substitution, old diagnostic run, missing/failed control or synthetic receipt
can supply a bracket. Healthy controls on either side do not prove continuous
health in between; that limitation must remain in the result.

Controls remain separate diagnostics. Their existing diagnostic-only28s recorder
lifetime is NOT transferred to the benchmark. Each benchmark retains its22s
recorder request,20s observation,12s ACK and actual pre-Bash-Popen-to-pidfd-exit
task wall INCLUDING observer/FIFO/cgroup setup. Full identity, actual attachment
coverage, raw lifecycle and loss checks must pass independently even for quiet
cases. Target file16MiB/loopback64-echo tasks,84 positions, two warmups/five scored
repetitions and original counterbalancing remain unchanged. Proposed total is
at most88 captures, of which ONLY84 are benchmark cases. These new controls
require explicit prospective execution approval; none is authorized here.

## Performance Acceptance

Keep median full/original wall<=1.10, every scored pair<=1.25, median task CPU<=1.15,
recorder RSS<=256MiB and zero observed loss/gaps. Never lengthen tasks, remove
setup from timing, add measured helper traffic, relax a budget or retry after
results. The observed75-105ms full versus20-22ms original warmups are an overhead
warning, not scored estimates. Resolving quiet validation does not solve that
possible setup-cost problem or guarantee a passing benchmark.

Stop at the first actual task, evidence, quality or scored-pair failure and
preserve the prefix. Missing post-controls leave quiet cases unqualified, not
retroactively accepted. Only a complete independently audited design with valid
brackets can supply accepted medians. The exact final release payload, helper
allowlists, task/fixture bindings, scoped coverage and benign/null order remain
separate release gates. Existing417 assignments are unchanged.

## Local Implementation

[The decision oracle](benchmark_quiet_policy_v1.py) reproduces the hash-pinned
production quality function, preserves its quiet rejection and tests normal
and quiet benchmark classifications plus fail-closed mutations. It consumes
facts that a FUTURE independent raw auditor must establish. Its transaction
recovery and context fields are not themselves raw proof. The synthetic fixtures
exercise decisions only, never capture, performance or release acceptance.

No guest adapter, raw bracketing-control auditor or launch CLI is implemented
in this local policy module. Before any VM operation, those integrations must
be implemented/tested against real payload bindings, independently reviewed,
frozen and explicitly authorized. The actual V3 sources/artifacts stay immutable.

From the study repository:

```bash
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/benchmark_quiet_policy_v1.py --self-test
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/benchmark_quiet_policy_v1.py --write-contract
```

The second command creates a non-overwriting local proposal with source hashes
and explicit no-execution flags. `performance_accepted=false`,
`collection_ready=false`. No VM operation or fresh state inspection is claimed.