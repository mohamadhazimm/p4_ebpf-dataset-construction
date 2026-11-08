# Prospective Capture-Liveness Protocol V1

Date: 2026-10-23. Status: **prepared for review; implementation and execution not authorized by this document**.

The user approved preparing this separate protocol after the stopped `.21` performance attempt. That approval is not permission to implement or execute a new guest diagnostic, repeat the benchmark, change its acceptance contract, or launch collection. `collection_ready=false`.

## Question And Discriminating Check

The [preserved attempt](scoped-performance/20261023T082811709603Z/guest_result.json) stopped at case007 with `packet_capture_interface_no_traffic`. Link up/carrier1, independent PCAP count0 and NIC RX/TX deltas0 establish the recorded predicate, not whether the path was usable during that interval. The [independent partial audit](scoped-performance/20261023T082811709603Z/partial-audit-20261023T083438551253Z.json) remains partial evidence, not performance acceptance.

Working hypothesis: the configured guest-to-Sink application and Ethernet capture paths can recover a bounded transaction in separate positive controls surrounding a capture with no intentional workload networking. Failure to receive the application response or uniquely recover its request and response from the PCAP would disconfirm this bounded hypothesis. Passing controls cannot prove uninterrupted capture or connectivity in the intervening quiet interval.

## Frozen Contract

This block is the machine-readable review contract. The prose requirements below are also normative. No execution entry point is supplied. A future implementation must freeze its exact sources, generated runner, helper identity, request bytes, expected response fixture, payload, order and auditor before any guest operation. Missing fields or unsatisfied prerequisites stop before launch; they are not defaults to infer during execution.

```json
{
  "protocol_schema": "2026-10-23.capture-liveness-proposal.v1",
  "preparation_authorized": true,
  "implementation_authorized": false,
  "diagnostic_execution_authorized": false,
  "benchmark_execution_authorized": false,
  "malware_execution_authorized": false,
  "collection_ready": false,
  "model_fitting_authorized": false,
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
    {"id": "original-pre", "condition": "original", "phase": "pre", "helper_transactions": 1},
    {"id": "original-quiet", "condition": "original", "phase": "quiet", "helper_transactions": 0},
    {"id": "original-post", "condition": "original", "phase": "post", "helper_transactions": 1},
    {"id": "full-pre", "condition": "full", "phase": "pre", "helper_transactions": 1},
    {"id": "full-quiet", "condition": "full", "phase": "quiet", "helper_transactions": 0},
    {"id": "full-post", "condition": "full", "phase": "post", "helper_transactions": 1}
  ],
  "source_pins": {
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

## Proposed Diagnostic Procedure

1. After separate implementation and diagnostic-launch approval, use the existing common lock, protected authentication, production pins and competitor/isolation checks. Start one fresh isolated child from the verified clean malware-lineage baseline. Use internal malnet only, Sink running, NICs2-8 none. Do not alter services, networking policy, NSS, installed packages or existing snapshots. Freeze the exact child UUID and source/payload hashes before target execution.
2. Execute the six cases above once in that order, on the same boot without per-case restores. Each is a separate 20-second broad Ethernet capture with its own PCAP, counters, run directory and original quality result. Use the exact previously accepted native-amd64 `attribution-control null` identity, SHA256 `da37ee8d8e49c7e864fea73593293932c5400761512bc2491db40354080c5038`, for all six target executions. Recover and hash that existing binary from the frozen payload; do not rebuild, substitute a program or count these repeats as new study units. Only original and full instrumentation differ as declared; any new harness needs a new schema/hash and unchanged production feature/helper AST verification. No baseline, i386, file benchmark or network benchmark executes in this diagnostic.
3. In each pre/post positive-control capture, after original sensor readiness and full recorder readiness where applicable, run exactly one unprivileged helper transaction before the target Bash Popen. The helper stays outside the target cgroup. Use a bound numeric source address, numeric internal destination and unique request path `/hazim-liveness/<attempt>/<case>/<nonce>` with HTTP/1.0, numeric Host and Connection: close. Freeze the exact request bytes before the capture. Apply a single monotonic total deadline covering connect/send/read, including partial progress; per-read timeout resets cannot extend it. Preserve raw request/response bytes, body SHA256 and length, actual local/remote endpoints, PID/start lifetime, process/network namespace identity and realtime/monotonic bounds. A standards-based bounded HTTP parser must verify the response against an independently frozen expected Sink fixture, not learn an expected body from the diagnostic result. The helper must finish and close before the original measured target-launch boundary; do not move or exclude attestor setup from that boundary. This scheduling is diagnostic-only, not an approved benchmark procedure.
4. In each quiet capture, launch only the same null target with the declared instrumentation. Do not schedule a liveness helper, keepalive, DNS lookup, route probe, service request, traffic generator, periodic retry or other intentional workload networking during observation or drain. Record pre/post link/carrier and interface RX/TX packets/bytes/drops without changing the interface. Retain any ambient traffic without claiming ownership. Never combine a positive-control PCAP/counter set with the quiet case or add synthetic records.
5. Independently audit each positive control: complete untruncated Ethernet capture, exact application receipt, one unambiguous endpoint/time/namespace-compatible TCP stream containing the exact nonce-bearing request and complete expected response body. Reassemble TCP by sequence numbers; reconcile identical retransmissions explicitly, rejecting conflicting overlaps, missing bytes or ambiguous stream joins. Do not match by port, marker substring or packet-hook current PID alone. Independently count all classic-PCAP records and reconcile original received/captured/drop counters. Preserve all frames, including unassigned traffic. PCAP recovery is evidence for this helper transaction, not target ownership, UDP, arbitrary workload coverage or continuous completeness.
6. Require exact null target exec, exit0, native ABI/linkage, finite 40x169 feature cells and strict zero observed loss/error/gap counters for every executed case. Full cases also require actual exec-inode/kernel lifetime matches, strict v6 receipts and recorder shutdown. Verify helper exclusion from target cgroup/sensor scope, natural sensor/capture shutdown, restoration of rmem, and removal of every temporary cgroup. Quiet cases retain their original quality status: exactly `packet_capture_interface_no_traffic` may be reported as the diagnostic observation under study, never as an accepted capture or a waived gate. Any additional rejection reason stops for review.
7. Stop on the first positive-control failure, timeout, ambiguous/missing evidence, identity discrepancy, unexpected quality rejection, sensor loss/error/gap or cleanup failure. Preserve the exact executed prefix and failure; no retries, replacement controls or automatic restart. On all exits stop child process groups, detach sensors, remove owned cgroups and restore original clean TLS/off with isolated Sink/running. A new-version broker must have bounded SIGINT/SIGTERM/timeout cleanup, tested locally before deployment. Failure to restore is a failure, not a best-effort success.

## Interpretation And Release Restrictions

- Both flanking positive controls passing with a zero-traffic quiet case means only `positive_controls_passed_quiet_interval_unresolved`. It does not prove a healthy path throughout the quiet interval or retroactively repair case007.
- Application success without unique PCAP recovery means `application_succeeded_capture_recovery_failed`. It is not a capture pass; preserve counters and bytes for investigation.
- Application failure means `application_path_failed_cause_unresolved`, not automatically a capture failure, link failure or Sink failure. A nonzero NIC delta alone is not positive-control acceptance.
- All three captures in a condition passing original quality still proves only bounded diagnostic capability. Ambient quiet-case packets are not target traffic and are not evidence of general capture completeness.
- No timing, CPU or RSS from this diagnostic may enter benchmark repetitions, warmups, ratios, medians or performance acceptance. Fixed case order has carryover/cache/service-state limitations; no causal original/full performance comparison is allowed.
- Positive controls are separate diagnostic traffic, not a remedy for the strict no-traffic predicate. They cannot make a quiet benchmark acceptable. Do not import them into a later benchmark's observation/drain or use them to prime a pass. A successful diagnostic does not authorize another benchmark or settle how a silent benchmark can satisfy the unchanged gate.
- Keep all approved benchmark tasks, ABI/condition counts, timing semantics, limits, early-stop rules and failed artifacts unchanged. Observer startup remains an unresolved engineering/performance risk; this protocol does not optimize it or accept the unscored warmup costs. No service suppression, workload padding, duration increase, moved measurement boundary or post-result budget adjustment is proposed.
- A future benchmark still needs a separately reviewed implementation/procedure and explicit execution authorization. Remaining scoped coverage and common release payload/null/order gates remain open. No malware/full collection, model fitting, historical resume, `.18` compatibility merge, role change or readiness claim is authorized.

## Required Implementation Checks

Before any proposed launch, local tests must reject changed source/payload pins, public/DNS endpoints, invalid nonce/request size, response mismatch, partial-response deadline extension, helper activity in a quiet case, helper membership in the target cgroup, marker-only/ambiguous/gapped TCP joins, positive loss/gap counters, missing exec/ABI evidence, missing cleanup and any attempt to promote quiet no-traffic rejection or diagnostic timings into benchmark acceptance. Mocked interruption/timeout tests must exercise cleanup on both instrumentation paths without VM operation or BPF attachment. The executable implementation and its independent saved-only auditor do not yet exist; this document does not assert these checks have run.