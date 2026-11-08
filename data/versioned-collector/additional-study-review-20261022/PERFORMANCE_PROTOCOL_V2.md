# Versioned Benign Performance Gate V2

Date: 2026-10-23. Prospective approval: **Approve Versioned Harness And One
Benign Performance Attempt**. This authorizes local implementation/tests,
freezing and exactly one fresh benign-only performance attempt, followed by
an independent saved-only audit. No automatic retry is authorized.

The failed [.21 attempt](scoped-performance/20261023T082811709603Z/guest_result.json)
and all measured V2/V3/V4 liveness sources and evidence remain immutable.
The [V4 diagnostic](capture-liveness-v4-readiness/20261023T114938416460Z/audit-v4-derived-20261023T115433685531Z.json)
is not benchmark acceptance, continuous completeness or a collection release.

## Unchanged Experiment

- The exact original static amd64/i386 C task source, actual owned16MiB
  file round trip and64 loopback UDP echoes are unchanged. No helper traffic,
  public workload network, padding, longer task or altered outcome is allowed.
- Preserve exact84-case order: two unscored warmups and five scored repetitions
  per ABI/task, three conditions baseline/original/full, alternating condition
  order exactly as the frozen prior manifest. Stop at first runner, quality,
  measurement or scored full/original pair failure; no replacement or retry.
- Preserve original20s fixed observation,40 windows,0.5s interval, enp0s3,
  immediate broad capture,65536KiB PCAP buffer,1000ms drain and16384 perf pages.
  Baseline intentionally disables both original sensors. Its quality status is
  preserved, not treated as sensor evidence. Instrumented conditions must pass
  the original strict quality gate, including no-traffic rejection.
- Preserve actual pre-Bash-Popen through pidfd-exit wall measurement and wait4
  CPU accounting. FIFO migration and full-only executed-inode observer setup
  remain INSIDE that target boundary. Recorder resource accounting stays separate.
- Preserve full/original wall median<=1.10, every scored pair<=1.25, task CPU
  median<=1.15, recorder RSS<=256MiB and zero observed loss/errors/packet gaps.
  Do not adjust limits after results. Early stopping prevents an incomplete
  attempt from supplying accepted medians or a performance release.

## Scoped Corrections

The separate schema is `2026-10-23.25-performance-lifecycle-harness`.
Original feature/helper implementations and all measured sources stay unchanged.

1. Use the separately tested V4 post-staging startup function: authenticated
   `/bin/true`, one absolute120s startup budget, at most three5s probes, remaining
   notification budget with a probe reserve and credential-free raw receipts.
2. Send exactly one FINISH at actual pre-clamp observation end, before unchanged
   original sensor teardown. Read ACK after teardown using only the remainder of
   the ORIGINAL12s end-to-ACK budget; broker exit wait remains5s. Publish early
   and final raw lifecycle receipts even when later quality fails.
3. Keep the original full recorder request at22s and its existing attachment
   path. The diagnostic-only28s lifetime is NOT imported. Keep original observer
   lifetime, target release deadlines, broker deadlines and80s case bound.
4. Preserve original authenticated per-run cgroup ownership, exact target image,
   actual v6 identity/counters and cleanup. SIGTERM follows bounded failure
   cleanup; credentials never enter reports or archives.

## Required Checks

Before launch: unchanged task/source and84-case order, original argv/parser and
feature/helper ASTs; actual pidfd/wait4 behavior; fake-clock immediate single
FINISH/shrinking12s ACK, send/ACK/publication failures and cleanup; startup
failure/corruption checks; guest-depth payload imports, generated Python/Bash
syntax and unchanged actual recorder/object identities. No local pass is a
guest or benchmark outcome.

Execute once on one fresh isolated clean child with the common lock, production,
competitor and NIC checks, existing protected authentication and restoration of
original TLS/off plus isolated Sink/running on success, failure or interruption.

Independently audit frozen source/transport/payload hashes, safe bounded unique
regular evidence members, report equality, actual prefix/order and every available
task receipt/owned output/resource boundary. Verify original sensors and quality,
finite features, independent PCAP/counter reconciliation, full image/v6 evidence,
raw lifecycle clocks and cleanup. Preserve any failed final case and distinguish
attempted tasks from appended accepted measurements. Only all84 accepted cases
with every approved limit met can establish this bounded performance gate.

No malware/full collection, fitting, historical resume/merge, service/NSS/policy
change, relaxed quality gate or change to the417 assignments is authorized.
Even a passing benchmark requires final release-specific common payload/helper,
exact task/fixture/null/order and scoped fail-closed review before readiness;
malware launch remains separately unauthorized. `collection_ready=false`.