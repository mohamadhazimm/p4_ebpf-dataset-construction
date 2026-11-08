# Runner v4 Family Coverage Smoke, 2026-10-19

This is a small collection-path/collector smoke, not a model evaluation. It
uses the current runner (`2026-10-19.4`) on one purposively selected sample
from each of 28 named malware families, plus two benign curl controls. The
older cohort was used to select artifacts only; all reported output comes from
fresh runs. Selection is not random or prevalence-representative. The
unassigned group is excluded.

## Run Settings

- 8-second fixed observation, 0.5-second windows, `enp0s3`, eBPF, common launch wrapper.
- Malware and benign classes used separate clean child snapshots and output roots.
- Internal network only (`malnet`); no public network interface was attached.
- Runner SHA-256: `46bcb7e7420ce9eb4c4eeb907e2fcd354c675a96ce1b85d44486f80c3a44c55a`.
- Batch SHA-256: `ddbcea7ff7995bdb843a19d93d8640360e6fa31766d6897c9a942e03a66b4894`.
- Staging SHA-256: `5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103`.

The exact family/artifact mapping is in [experiment_manifest.json](experiment_manifest.json);
sample lists, stage logs, dry-run logs and collection logs are preserved here.

## Outcomes

All 30 selected artifacts were present in their guest snapshots, and all 30
were retrieved with `host_run.txt status=completed`. Process outcomes across
malware and benign runs: 18 exited 0, 7 timed out at the observation cap, 2
were signaled, and 3 exited nonzero. A completed batch retrieval does not mean
the workload itself exited successfully.

Every output passes runner/hash provenance, 16-window / 176-column schema,
169 finite-feature, archive SHA-256 parity, eBPF/PCAP active, event metadata
counts, and IPv4 endpoint reconciliation checks. Across the 30 runs, all
1,920 endpoint-feature cells reconcile with raw events. All 308 regular
archive members matched their extracted host copies. No invalid IPv4 connect
event was observed.

PCAP-to-window alignment is unique in **25/30** runs. In those runs, all
**11,600** compared P4 cells match offline reconstruction, and there are no
feature-value mismatches. P4 reconstruction was intentionally refused for
five runs with `telemetry_interval_counter_mismatch`; their features must not
be treated as validated. Those cases are CatStorm, DeskRAT, FlylegitBot,
Gafgyt and Nitrogen. CatStorm also reports **1,045 PCAP kernel drops**.

Two runs report eBPF loss warnings: Gunra and LockBit. These remain
loss-flagged even though their batch archives were retrieved. Zero loss
warnings or drops elsewhere does not prove absence of unreported kernel loss.

## Interpretation

The v4 raw-syscall fallback is included and version-pinned. These outputs test
collector behavior across diverse sample families; they do not establish
malware activation, sample attribution for every packet, representative family
performance, classifier validity or live-P4 measurements. Prior connect
activity informed sample selection but is not reused as fresh-run evidence.

## Cleanup

After the final run, the guest was restored to original snapshot
`clean-tls-paired-2026-10-19` (UUID
`72de0a02-2e71-42b8-85e2-78c21d6b00f9`) and verified powered off. The guest
and pre-existing Sink remain attached only to isolated `malnet`; other NICs
are disabled. No collection process remains. The paused large collection was
not resumed and no model was trained.

Repeat the read-only QA from the workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/runner-v4-family-smoke-20261019T130151Z/validate_family_smoke.py
```