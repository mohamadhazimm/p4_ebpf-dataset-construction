# Family-Wide v8 Loss Audit

## Scope

Runner schema `2026-10-19.8` (SHA-256
`1f08c55ec6c2304cc4598971e9ba8e03fcbe0f31cb0d2ca39cf7bc21a18fbaa0`), with
the 16,384-page bpftrace default and 16-MiB tcpdump buffer, was used for 48 new
malware captures across 28 named families and four benign controls. One
previously validated LockBit v8 capture was reused, not executed again. The
selection contains 49 distinct malware artifacts: two for 21 families and one
for each of seven singleton families (BillGates, ChinaZ, FlylegitBot, INC,
Nitrogen, NoEscape, PromptLock). `unassigned` was excluded.

Benign controls were two paired TLS curl runs, a two-million-call read-only
syscall probe, and the bounded internal packet/syscall stress probe. Each
workload used its own fresh child snapshot. The malware observation was
8 seconds fixed with 0.5-second windows. No paused cohort was resumed.

## Sensor Results

Across all 53 records, including the reused LockBit run:

| Check | Result |
| --- | ---: |
| Retrieval completed | 53/53 |
| Collection quality accepted | 53/53 |
| Reported eBPF loss | 0 runs, 0 events |
| Reported PCAP kernel drops | 0 runs, 0 packets |
| Validation issues | 0 |
| Positive tcpdump received-minus-captured gaps | 19 runs, 262 packets total |

The last row is unresolved. The quality gate tests `dropped_by_kernel`, while
tcpdump's `packets_received_by_filter` exceeds `packets_captured` in 19 runs.
Do not equate the zero kernel-drop counter with fully reconciled PCAP files or
claim the 262-count discrepancy is explained. Per-run details are preserved in
`loss_monitor_results.json`.

The benign high-syscall probe captured 2,001,036 raw syscall events with no
eBPF loss. The packet-stress control also reported no eBPF loss or kernel PCAP
drops, but its counters were 50,065 received, 50,041 captured. It contains
50,025 P4-eligible in-window packets, matching the telemetry total; 15 frames
fall outside the telemetry windows and per-window packet placement differs,
so offline reconstruction reports `telemetry_interval_counter_mismatch`. This
is a window-alignment/parity limitation, distinct from the total in-window
packet count and the kernel-drop counter.

## Process Outcomes And Validation

All runs are sensor-quality accepted, but malware process outcomes are not all
successful executions: 30 exited zero, 8 timed out with signal 15, 1 timed out
with signal 9, 6 were signaled, and 8 returned nonzero. Keep these execution
outcomes separate from sensor quality and retrieval.

The validator checks runner/schema provenance, the bpftrace loss logs against
`run.json`, tcpdump logs against numeric metadata, 169 finite features across
16 windows, raw/named event row counts, buffer restoration, and every regular
archive member against host extraction. Re-run it from the workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/family-loss-monitor-v8-20261019T152933Z/audit_family_loss_monitor.py
```

The generated `loss_monitor_results.json` includes per-sample counters,
process statuses, artifact hashes, family summaries, and counter-gap details.

## Safety And Limits

The malware guest is restored to `clean-tls-paired-2026-10-19`, powered off,
with only `nic1=intnet`. The existing Sink remains internal-only; no collector
process remains. This is a finite audit of the selected artifacts and benign
stress loads, not a guarantee against loss for every workload or duration. The
received/captured discrepancy needs separate investigation before interpreting
PCAPs as fully loss-free.