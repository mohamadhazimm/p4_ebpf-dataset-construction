# Prospective Capture-Liveness Protocol V2

Date: 2026-10-23. Status: **revised for review; implementation and execution not authorized by this document**.

The user requested revision after review of [V1](CAPTURE_LIVENESS_PROTOCOL_V1.md). V1 and every measured source/evidence artifact remain immutable. This separate proposal addresses the missing full-recorder lifetime budget and exact null-target arguments. Revision approval is preparation only, not approval of the proposed diagnostic timing, implementation, guest execution, benchmark retry or collection. `collection_ready=false`.

## Question And Discriminating Check

The [preserved attempt](scoped-performance/20261023T082811709603Z/guest_result.json) stopped at case007 with `packet_capture_interface_no_traffic`. Link up/carrier1, independent PCAP count0 and NIC RX/TX deltas0 establish the recorded predicate, not whether the path was usable during that interval. The [independent partial audit](scoped-performance/20261023T082811709603Z/partial-audit-20261023T083438551253Z.json) remains partial evidence, not performance acceptance.

Working hypothesis: the configured guest-to-Sink application and Ethernet capture paths can recover a bounded transaction in separate positive controls surrounding a capture with no intentional workload networking. Application failure or failure to uniquely recover its request and response from the PCAP disconfirms this bounded hypothesis. Passing controls cannot prove uninterrupted capture or connectivity in the intervening quiet interval.

## Frozen Contract

The JSON and prose below are both normative. No execution entry point is supplied. Before any guest operation, a separately reviewed implementation must freeze its exact sources, generated runner, diagnostic recorder/broker, helper identity, request bytes, expected response fixture, payload, case argv, order and independent auditor. Missing fields or unsatisfied prerequisites stop before launch; none may be inferred from results.

```json
{
  "protocol_schema": "2026-10-23.capture-liveness-proposal.v2",
  "supersedes_for_review": "CAPTURE_LIVENESS_PROTOCOL_V1.md",
  "preparation_authorized": true,
  "diagnostic_timing_proposal_approved": false,
  "implementation_authorized": false,
  "diagnostic_execution_authorized": false,
  "benchmark_execution_authorized": false,
  "malware_execution_authorized": false,
  "model_fitting_authorized": false,
  "collection_ready": false,
  "existing_assignments_unchanged": 417,
  "preserved_attempt": "scoped-performance/20261023T082811709603Z",
  "benchmark_task_wall_boundary": "Before original Bash Popen through pidfd exit readiness; includes FIFO/root migration and full-only attestor setup, not coarse telemetry polling",
  "benchmark_file_bytes": 16777216,
  "benchmark_actual_udp_echoes": 64,
  "benchmark_warmups_per_condition_abi_task": 2,
  "benchmark_scored_repetitions_per_condition_abi_task": 5,
  "benchmark_maximum_cases": 84,
  "limits": {
    "full_vs_original_task_wall_median_ratio_max": 1.10,
    "full_vs_original_task_wall_any_pair_ratio_max": 1.25,
    "full_vs_original_task_cpu_median_ratio_max": 1.15,
    "recorder_rss_mib_max": 256,
    "observed_sensor_errors_max": 0,
    "observed_sensor_loss_max": 0,
    "observed_packet_counter_gap_max": 0
  },
  "capture": {
    "interface": "enp0s3",
    "observation_seconds": 20,
    "window_seconds": 0.5,
    "broad_unfiltered_ethernet": true,
    "immediate_mode": true,
    "buffer_kib": 65536,
    "drain_ms": 1000,
    "perf_pages_per_cpu": 16384,
    "quality_gate_unchanged": true
  },
  "diagnostic_timing": {
    "clock": "CLOCK_MONOTONIC",
    "scope": "diagnostic_only_not_benchmark",
    "full_recorder_attached_lifetime_seconds": 28,
    "full_attachment_to_broker_ready_maximum_seconds": 1,
    "broker_ready_to_observation_start_maximum_seconds": 3,
    "broker_ready_to_target_request_maximum_seconds": 4,
    "broker_target_request_deadline_seconds": 5,
    "target_release_ack_deadline_seconds": 8,
    "observation_start_to_end_receipt_maximum_seconds": 21,
    "minimum_planned_observation_coverage_reserve_seconds": 3,
    "observation_end_to_finish_request_maximum_seconds": 3,
    "broker_finish_request_deadline_after_ready_seconds": 30,
    "full_recorder_teardown_maximum_seconds": 2,
    "broker_finish_ack_deadline_seconds": 15,
    "case_process_deadline_seconds": 80
  },
  "null_target": {
    "binary_basename": "attribution-control",
    "sha256": "da37ee8d8e49c7e864fea73593293932c5400761512bc2491db40354080c5038",
    "argument_semantics": ["mode", "marker", "repeat"],
    "arguments": ["null", "liveness_null", "1"],
    "stdin": "DEVNULL",
    "rebuild_allowed": false,
    "substitution_allowed": false
  },
  "transaction": {
    "source_ipv4": "10.0.0.10",
    "destination_ipv4": "10.0.0.1",
    "destination_tcp_port": 80,
    "connections_per_positive_control": 1,
    "automatic_retries": 0,
    "total_deadline_seconds": 2,
    "request_maximum_bytes": 512,
    "response_maximum_bytes": 16384,
    "nonce_bits": 128,
    "http_status_required": 200,
    "dns_allowed": false,
    "public_network_allowed": false
  },
  "cases": [
    {"id": "original-pre", "condition": "original", "phase": "pre", "helper_transactions": 1, "target_arguments": ["null", "liveness_null", "1"]},
    {"id": "original-quiet", "condition": "original", "phase": "quiet", "helper_transactions": 0, "target_arguments": ["null", "liveness_null", "1"]},
    {"id": "original-post", "condition": "original", "phase": "post", "helper_transactions": 1, "target_arguments": ["null", "liveness_null", "1"]},
    {"id": "full-pre", "condition": "full", "phase": "pre", "helper_transactions": 1, "target_arguments": ["null", "liveness_null", "1"]},
    {"id": "full-quiet", "condition": "full", "phase": "quiet", "helper_transactions": 0, "target_arguments": ["null", "liveness_null", "1"]},
    {"id": "full-post", "condition": "full", "phase": "post", "helper_transactions": 1, "target_arguments": ["null", "liveness_null", "1"]}
  ],
  "source_pins": {
    "CAPTURE_LIVENESS_PROTOCOL_V1.md": "d94d315d055aaf323c1b0a7602581bf998f52718424baf8fc97bd7d05b5bf1ca",
    "attribution_control.c": "2b294343448f23cc918d0d04a86fd9005d67e90749147d62a884319f1a58883e",
    "../../../src/malware_runner.py": "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49",
    "../../../scripts/vbox_malware_batch.sh": "4490a4cec6e26307d1f3e00f28c09a07d6b8fdcfd8bc12a12961ee34f6887f9f",
    "../../../scripts/stage_versioned_runner_snapshot.sh": "5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103",
    "scoped-performance/20261023T082811709603Z/protocol.json": "18b2e85ddf98da6629a4887943a9fab172fc2853eab5bb5bd881a389492fc9bd",
    "scoped-performance/20261023T082811709603Z/integrated_runner.py": "885e707b1683ef4fb52f774046f5c27168cdbdf8b2800c34508e946aa3fca852",
    "scoped-performance/20261023T082811709603Z/guest_result.json": "23684332c71b23511b6b8d2eb4db343ddbff929ca3dfbe490745b1d3ff52c649",
    "scoped-performance/20261023T082811709603Z/evidence.tgz": "e63d4029082a2061b4d771a6e829e7f2ce5c9169b7d3e95005f26a5852c57e70",
    "scoped-performance/20261023T082811709603Z/final_vm_state.json": "9727b8851645ed65d204a0cbce03beb1e287df3f247e9575df1758095d9a465c",
    "scoped-performance/20261023T082811709603Z/partial-audit-20261023T083438551253Z.json": "b20627ec6d3c0b600d692440e1504b20cf03518b38975b0fbc7931954ae7ae28",
    "release-proposals/20261023T081218460447Z/source-correction.json": "3b5a3a78f8d47de7de31c04a534e46555e5b4a9a409e81c28df69929b7ef75eb"
  }
}
```

## Diagnostic Lifetime Budget

The inherited full recorder starts its duration immediately before attachment readiness and requests only `ceil(20)+2=22` seconds. A permitted two-second helper plus the 20-second observation leaves no forwarding or launch margin. Reusing that duration is forbidden in this proposal. V2 instead proposes a **28-second full-sidecar attachment lifetime for these six diagnostics only**, identical across all three full cases. This is not a change to the 20-second original observation, its 40 windows, the one-second PCAP drain, the frozen benchmark recorder, the observer's timing boundary or any performance limit. It needs explicit review/approval before implementation.

Use these actual monotonic receipts, not wall-clock estimates or scheduling delays:

- `A`: all full-sidecar hooks attached and ring-buffer reader ready; the new diagnostic recorder arms its exact 28-second deadline here. `R`: runner receives broker readiness after all required original sensors are ready. For full cases require `0 <= R-A <= 1s`; a stale readiness message rejects.
- `H0`/`H1`: helper start and closed completion in a positive case, with `R <= H0 <= H1`, `H1-H0 <= 2s`. Include helper spawn/receipt handoff in the overall `R` to `O` budget; the connect/send/read deadline cannot reset on progress. Quiet cases have no helper receipts or networking. Do not wait out unused budget.
- `O`: unchanged `sample_started_monotonic_ns`, before the original target Bash Popen. Require `0 <= O-R <= 3s`, and in positive cases `H1 < O`. The actual `TARGET` request must reach the broker by `R+4s`; its input deadline is `R+5s`. Existing target Popen, root migration, Bash-ready handshake and full-only attestor setup remain inside the original task-wall boundary. Bound release acknowledgement by eight seconds without moving that work outside the boundary.
- `E`: actual `observation_ended_monotonic_ns`. Request exactly 20 seconds with 0.5-second windows and require 40 valid windows, `20s <= E-O <= 21s`. The extra second is a maximum scheduling/receipt tolerance, not another requested observation window, sleep, workload extension or permission to repair late data.
- Therefore the planned latest full observation end is `A+1+3+21=A+25s`, leaving three seconds before the planned detach at `A+28s`. These are hard per-case bounds, not averages. Any exceeded bound rejects/stops; do not extend a timer, shorten the observation or repeat a case after seeing a result.
- Send `FINISH` by `E+3s`, including the unchanged one-second PCAP drain and local handoff. The broker's finish-input deadline is `R+30s`; its acknowledgement deadline is 15 seconds from the actual finish request. Full-sidecar natural teardown must complete by `A+30s` (28-second capture plus at most two seconds teardown). Each runner process has a separate 80-second outer bound, including setup and publication; timeout still requires cleanup and a failed preserved prefix, not acceptance.

A future separately versioned diagnostic recorder/broker must record actual `A`, `R`, `O`, `E`, detach-start `D`, final exit and finish-request/ack timestamps, with exact recorder PID/start, cgroup, boot identity and source hashes. Require actual hooks to remain attached over `[O,E]`: `A <= O < E <= D`, as well as the prospective budget above and natural successful exit. The existing final `clock.after` occurs after detachment/teardown and is **not** evidence for `D`. Lifecycle receipts must come from the controlling operations, not timestamps invented by the auditor. Preserve raw v6 observations and all strict counters; separately version/hash any lifecycle instrumentation without changing existing frozen sources or feature/event semantics. Independently validate full exec-inode/kernel receipts even when original quiet-case quality is rejected; do not rely on an accepted-quality-only metadata branch.

## Exact Null Target

Recover the existing accepted native-amd64 `attribution-control` binary from the frozen payload and require the pinned SHA256. Do not rebuild or substitute it. Every case must freeze the same target argv suffix, exactly `['null', 'liveness_null', '1']`; the executable is the first argv element at its frozen absolute payload path. The production common Bash wrapper and DEVNULL stdin remain unchanged. The program requires three arguments: mode, marker and repeat. The marker uses only `a-z`, digits and underscore; repeat must be 1 or 2. The chosen constant marker and repeat1 are valid and identical in all six cases. Case IDs and HTTP nonces are separate helper/evidence fields, never null-target arguments. In particular, `original-pre` is not a valid marker and a phase index is not a repeat value. Each report/archive must contain the exact effective target argv and the original stdout/exit/exec evidence; do not add a new target receipt file or extra target work.

## Proposed Diagnostic Procedure

1. After separate implementation and diagnostic-launch approval, take the existing common lock and use protected authentication, production pins and competitor/isolation checks. Start one fresh isolated child from the verified clean malware-lineage baseline. Use internal malnet only, Sink running, NICs2-8 none. Do not alter services, networking policy, NSS, installed packages or existing snapshots. Freeze the exact child UUID and source/payload hashes before target execution.
2. Execute the six cases once in the declared order on the same boot without per-case restores. Each has its own PCAP, counters, run directory, exact declared null argv and unchanged original quality result. Only original/full instrumentation differs as declared. A new diagnostic harness requires a new schema/hash and unchanged production feature/helper AST verification. No baseline, i386, file benchmark or network benchmark executes. These repeats are not new independent study units.
3. In each positive case, after original sensor readiness and full recorder readiness where applicable, run exactly one unprivileged helper outside the target cgroup. Use the numeric endpoints and unique request path `/hazim-liveness/<attempt>/<case>/<nonce>` with HTTP/1.0, numeric Host and Connection: close. Freeze exact request bytes before capture. Enforce the single two-second monotonic total deadline across connect/send/read, including partial progress, and the lifetime budget above. Preserve raw request/response bytes, body SHA256/length, actual endpoints, helper PID/start, process/network namespaces and realtime/monotonic bounds. A standards-based bounded HTTP parser must verify HTTP200 and the independently frozen expected Sink fixture; never learn the expected body from the result. Close and finish before `O` and target Popen. This scheduling is diagnostic-only, not an approved benchmark procedure.
4. Quiet captures launch only the same null target with the declared instrumentation. No liveness helper, keepalive, DNS lookup, route probe, service request, traffic generator, periodic retry or other intentional workload networking during setup, observation or drain. Record pre/post link/carrier and NIC RX/TX packets/bytes/drops without changing the interface. Preserve ambient/unassigned traffic without ownership claims. Never mix positive-control PCAP/counters into a quiet case or add synthetic records.
5. Independently audit each positive control: complete untruncated Ethernet capture, exact application receipt, one unambiguous endpoint/time/namespace-compatible TCP stream containing the exact nonce-bearing request and complete expected response body. Reassemble TCP by sequence numbers; reconcile identical retransmissions and reject conflicting overlaps, missing bytes or ambiguous joins. Do not match by port, marker substring or packet-hook current PID alone. Independently count every classic-PCAP record and reconcile original received/captured/drop counters. Preserve all frames. This proves recovery of this helper transaction, not target ownership, UDP, arbitrary coverage or continuous completeness.
6. Require exact null exec/argv, exit0, native ABI/linkage, finite 40x169 cells, the declared timing receipts and zero observed loss/error/gap counters for every case. Full cases additionally require actual exec-inode/kernel lifetime matches and strict v6 receipts even if original quality is rejected. Verify helper exclusion from target cgroup/sensor scope, natural sensor/capture shutdown, rmem restoration and every temporary cgroup removal. Quiet cases retain original quality: exactly `packet_capture_interface_no_traffic` may be recorded as the diagnostic observation, never accepted or waived. Any additional rejection reason stops.
7. Stop at the first positive-control failure, exceeded deadline, missing/ambiguous evidence, identity/argv discrepancy, unexpected quality rejection, sensor loss/error/gap or cleanup failure. Preserve the exact prefix; no retry, replacement or automatic restart. On all exits stop child process groups, detach sensors, remove owned cgroups and restore original clean TLS/off with isolated Sink/running. A new-version broker must have bounded SIGINT/SIGTERM/timeout cleanup tested locally before deployment. Restoration failure is failure, not best-effort success.

## Interpretation And Release Restrictions

- Passing both flanking controls around a zero-traffic quiet case means only `positive_controls_passed_quiet_interval_unresolved`, not continuous healthy capture/connectivity or repaired case007.
- Application success without unique PCAP recovery means `application_succeeded_capture_recovery_failed`. Application failure means `application_path_failed_cause_unresolved`, not automatically a capture, link or Sink failure. Nonzero NIC deltas alone do not pass.
- All three captures passing original quality still prove only bounded diagnostic capability. Ambient quiet-case packets are not target traffic or general completeness evidence.
- No diagnostic timing, CPU or RSS enters benchmark repetitions, warmups, ratios, medians or acceptance. The proposed 28-second diagnostic sidecar lifetime is not transferable to a benchmark or approved performance-envelope change. Fixed order has carryover/cache/service-state limitations; no causal original/full performance comparison is allowed.
- Positive controls cannot clear a quiet benchmark's no-traffic gate. Do not import them into a later observation/drain or prime a pass. Even successful diagnostics do not settle silent-benchmark acceptance or authorize a retry.
- Retain every approved benchmark task, ABI/condition count, timing boundary, limit, early-stop rule and failed artifact. Observer startup remains unresolved; do not accept warmup overhead, pad workload, suppress services, increase benchmark duration, move measurement boundaries or adjust budgets after results.
- Implementation and proposed diagnostic timing need review/approval; diagnostic launch needs separate explicit authorization. A future benchmark likewise needs a separately reviewed procedure and launch approval. Scoped coverage and common release payload/null/order gates remain open. No malware/full collection, fitting, historical resume, `.18` merge, role change or readiness claim is authorized.

## Required Implementation Checks

Before any launch, local tests must reject changed pins, target identity/argv, missing mode/marker/repeat, hyphenated case-ID markers, repeats outside 1-2, public/DNS endpoints, invalid nonce/request/response, partial-response deadline extension, quiet-case helper activity, helper target-cgroup membership, marker-only/ambiguous/gapped TCP joins, positive loss/gaps, missing exec/ABI/cleanup and promotion of quiet rejection or diagnostic statistics into benchmark acceptance.

Fake-clock lifecycle tests must exercise a near-two-second successful transaction plus forwarding/handoff and latest permitted observation end within the 28-second lifetime; reject inherited 22-second duration, stale readiness, every exceeded phase budget, early detach with a misleadingly late final clock, missing/altered lifecycle receipts and deadline reset. Test identical argv for all six cases and independent full identity validation when original quality is no-traffic rejected. Mock interruption/timeout cleanup on both instrumentation paths without VM operation/BPF attachment. Test finite outer deadlines and preserve failed prefixes without retries. These future runtime tests are required, **not claimed executed**. The executable diagnostic and independent saved-only auditor do not yet exist. Offline arithmetic/argv/hash checks alone are not runtime acceptance.