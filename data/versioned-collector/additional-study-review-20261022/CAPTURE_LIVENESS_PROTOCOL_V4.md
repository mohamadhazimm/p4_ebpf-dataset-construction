# Capture-Liveness V4 Startup Procedure

Date: 2026-10-23. User approval: **Approve Versioned Startup Fix And One Benign Diagnostic**.

This separately versioned startup correction inherits [V3](CAPTURE_LIVENESS_PROTOCOL_V3.md) and every numeric diagnostic/task limit in [V2](CAPTURE_LIVENESS_PROTOCOL_V2.md). Measured V2/V3 sources, protocols and failed attempts remain immutable. The V3 notification timeout is not proof that Guest Control was unusable.

The new launcher retains the hash-pinned common lock, production/competitor/isolation checks, staging, protected authentication and original TLS/off plus isolated Sink/running cleanup. Only its post-staging startup procedure changes. A successful authenticated Guest Control `/bin/true` is required; a login notification alone never establishes readiness. Start and all startup subprocesses share one absolute 120-second deadline. At most three probes are allowed, each bounded by five seconds and the remaining deadline. Between failed probes a bounded notification wait may use only the remaining time minus a five-second probe reserve. A notification or individual probe timeout cannot establish readiness; only the remaining absolute budget may be used afterward. An interruption, failed/timed-out start, exhausted probes/deadline or late success rejects. A credential-free `startup-readiness.json` publishes the actual command types, return codes and monotonic clocks even on failure. No service, policy, NSS, networking or snapshot contents are changed to manufacture readiness.

Local startup/corruption/interruption tests, inherited lifecycle tests, actual recorder build checks and complete guest-depth payload imports precede the launch. The sole prospective execution is one fresh clean child and the unchanged six controls in order: original-pre, original-quiet, original-post, full-pre, full-quiet, full-post. All six retain exact `null liveness_null 1`; only the four positive controls perform their one previously approved internal-Sink transaction. Stop at the first failure and preserve all artifacts. V3 immediate FINISH/raw publication, original sensor shutdown, 20-second observation, 28-second full attachment lifetime, all end/ack/case deadlines and strict quality/identity gates are unchanged.

Independent saved-only audit must verify startup's actual successful probe/deadline, all source/payload identities, actual control order, V3 early/raw/final clock joins, FINISH before PCAP teardown, full identity/attachment receipts where executed, HTTP/TCP/PCAP evidence and cleanup. Missing cases are not a complete pass. A quiet no-traffic rejection remains unresolved, never promoted. Success is diagnostic only, not performance acceptance or collection readiness. No automatic retry, benchmark retry, malware/full collection, fitting, old resume, traffic padding, service/policy change, relaxed limit or changed417 assignments is authorized.

```json
{
  "protocol_schema": "2026-10-23.capture-liveness-proposal.v4",
  "schema": "2026-10-23.24-capture-liveness-startup-diagnostic",
  "implementation_authorized": true,
  "diagnostic_execution_authorized": true,
  "fresh_attempts_authorized": 1,
  "startup_absolute_seconds": 120,
  "startup_maximum_probes": 3,
  "startup_probe_seconds": 5,
  "case_count": 6,
  "positive_transaction_count": 4,
  "all_v2_diagnostic_and_task_limits_unchanged": true,
  "benchmark_retry_authorized": false,
  "malware_execution_authorized": false,
  "fitting_authorized": false,
  "collection_ready": false
}
```