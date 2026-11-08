# Performance V4: Per-Case Capture-Path Probes

Date: 2026-10-24. Status: prospective procedure. A guest attempt needs a
separate explicit launch approval; this document authorizes none by itself.

## Why V4 exists

All three earlier attempts ([V1](scoped-performance/20261023T082811709603Z/guest_result.json),
[V2](scoped-performance-v2/20261023T123753101282Z/guest_result.json),
[V3](scoped-performance-v3/20261023T132643813743Z/guest_result.json)) stopped at
case007 with `packet_capture_interface_no_traffic`. The saved PCAPs show why.
The only traffic on the isolated enp0s3 is incidental guest NetworkManager
connectivity checks (plus early DNS/mDNS). Against the INetSim Sink their
interval doubles (measured +16/+32/+64s). About 180s after boot the next check
falls outside a 20s capture. Case007 is the first full-sensor file task, which
makes no network traffic of its own, so it is the first empty capture. Every
single-boot run of this design fails there. The `.18` gate
(`src/malware_runner.py` `assess_collection_quality`) counts every PCAP frame,
so it measures ambient traffic, not whether the capture path works.

## Decision

The user chose per-case probes (2026-10-24) over the earlier
[quiet-policy V1](BENCHMARK_QUIET_POLICY_V1.md) bracketing controls and over a
fresh boot per case. This reverses the quiet policy's "zero intentional helpers
in measured cases" rule, for the reasons and within the limits below.

## What changes

[The V4 adapter](performance_v4.py) derives the runner from the hash-pinned
[V3 harness](performance_v3.py) and inserts exactly three statements into the
generated `main`. Every original feature/helper function stays byte-identical:

1. After tcpdump readiness and before eBPF start, sample start and task Popen:
   one TCP connect from the runner process to `10.0.0.1:80` (1s timeout), closed
   with `SO_LINGER 0` (RST), then a 0.2s settle.
2. After observation end and eBPF shutdown, before the PCAP drain/stop: the
   same probe again.
3. After the unchanged `assess_collection_quality`, both probes must be
   recovered from the published PCAP: an outbound SYN from the recorded local
   port and a Sink SYN-ACK or RST, within the probe interval ±1s. Neither probe
   tuple may have any frame inside the feature windows. Otherwise the case is
   rejected (`capture_path_probe_*`). This never relaxes an earlier finding.

Baseline cases have no sensors and are not probed. Probe frames fall outside
the task wall, wait4 CPU, telemetry windows/P4 features and the target cgroup.
Because they are captured packets, the original no-traffic reason can no longer
fire. The stricter per-case probe-recovery requirement takes its place. The
quality function itself is unchanged. The probes are not application helper
transactions (no payload). `helper_transactions` therefore stays 0, and the
probes are counted separately.

## What is unchanged

The 84-case order: amd64/i386 static, the owned 16MiB exact file roundtrip and
64 loopback UDP echoes, baseline/original/full, two unscored warmups and five
counterbalanced scored repetitions. Also unchanged: the 20s/40x0.5s observation
with original enp0s3 capture settings, the 22s recorder request, the 12s ACK
budget and immediate FINISH. The task wall runs from before Bash Popen to the
actual pidfd exit, including observer/FIFO/cgroup setup. Limits stay: full/original
wall median <=1.10, every scored pair <=1.25, task CPU median <=1.15, recorder
RSS <=256MiB, and zero sensor loss/errors/packet-counter gaps. Stop at the
first failure, with no retry, replacement or post-result budget change.

## What the probes prove and do not prove

A recovered pre/post pair shows that this case's single tcpdump process
captured real traffic on enp0s3 just before and just after the feature windows,
and that the Sink answered. It does not prove continuous in-window completeness,
and it does not repair V1-V3. A case with zero in-window frames between
recovered probes is a genuinely quiet task, not a dead link.

## Execution and audit

[The launcher](run_performance_v4.py) pins the V4 sources and this document.
It reuses the V3 input pins and the inherited common-lock, production,
competitor, isolation, staging, bounded-startup and cleanup path. It writes an
exclusive one-attempt receipt under `scoped-performance-v4/`. From the study
root:

```bash
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/run_performance_v4.py --check-only
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/run_performance_v4.py --freeze-only
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/run_performance_v4.py --execute-benign-checks
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/audit_performance_v4.py <attempt>
```

[The saved-only auditor](audit_performance_v4.py) runs the inherited independent
V2 evidence/performance audit bound to V4. It then re-derives every sensor
case's probes from the raw PCAP with Scapy, a parser separate from the guest
code. It also checks wall and monotonic ordering against the recorded telemetry
windows and observation clocks, and reports how many cases were quiet in-window.

Performance acceptance is not collection release. The common release payload,
helper allowlists, collection-form fixtures, scoped fail-closed coverage and
benign/null/order rehearsal remain separate gates. Until those pass,
`performance_accepted` follows the audited result and `collection_ready=false`.
No malware, full collection, fitting, historical resume/merge, service/NSS/policy
change or change to the 417 assignments is authorized.
