# Fresh Bash Retrieval Pilot, 2026-10-19

Four newly executed cases, not reused captures. The Bash retrieval and measured
window checks pass for these four cases. This is not dataset-wide acceptance,
classifier validation, sample-traffic attribution, or live-P4 certification.

## Results

| Case | Execution / exit | Windows | Captured frames in windows | P4-eligible packets | Named eBPF rows | Raw syscall rows |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| curl-pair-01 | completed / 0 | 40 | 88 | 87 | 422 | 758 |
| 50f7fafb...triage | completed / 0 | 40 | 82 | 81 | 61 | 30,787 |
| curl-pair-02 | completed / 0 | 40 | 88 | 87 | 425 | 757 |
| b5af6310...triage | completed / 0 | 40 | 71 | 71 | 278 | 4,617 |

- All 40 regular archive members match extracted host files by SHA-256; no escaping or special members were found. This is archive-to-host parity, not a separate guest-source checksum.
- All 160 telemetry rows have the expected 176 columns and 169 finite, nonmissing feature values.
- Both sensors report active. All runs report zero PCAP kernel drops; no nonzero eBPF loss warning was found. This does not prove zero unreported kernel loss.
- PCAP-to-recorded-window assignment is unique, with zero packet-count error in all four runs. P4 eligibility intentionally excludes non-IP/TCP/UDP frames.
- All 4,640 exported P4 feature cells match offline reconstruction under the frozen runner's explicit byte/rate contracts.
- All 1,186 named eBPF rows and 36,919 raw syscall rows reconcile with metadata and per-window exported counts. No archived event disagrees with its nominal window or corresponding recorded UTC interval in these four traces.
- Actual window duration deviations reach 63.630, 15.434, 34.008 and 21.985 ms respectively. The absence of observed event-boundary disagreements here does not prove nominal and recorded windows are interchangeable generally.

Full sample names, hashes and settings are in [pilot_manifest.json](pilot_manifest.json).
Per-case checks, source/artifact SHA-256 values and timing diagnostics are in
[qa_results.json](qa_results.json). Original captures and CSVs remain unchanged.

## Timing Compatibility Repair

The first full comparison exposed 26 rate-cell differences: the frozen VM
runner divides byte/packet deltas by nominal 0.5-second windows, whereas the
repaired offline extractor defaults to actual recorded window durations.

The shared extractor now accepts explicit `rate_window="nominal"` or
`rate_window="recorded"` and tags the choice in diagnostics/schema. Its default
remains recorded duration. The study reconstruction wrapper explicitly requests
`byte_layer="ethernet", rate_window="nominal"` to reproduce the frozen runner.
No runner, snapshot, raw telemetry or PCAP was replaced or rewritten.

Focused validation: 38 collector/repair/alignment tests and 14 runner tests passed.
The new rate test checks both conventions on the same jittered interval.

## Protocol And Attribution Limits

`tshark` confirms one ClientHello, one ServerHello and six encrypted-data frames
on the same TCP stream in each benign control, SNI `cdn.fwupd.org`.
The controls use `curl --insecure` against the isolated Sink, so certificate-chain
validation is deliberately not tested.

Neither fresh malware capture contains decoded TLS handshake or application
data. They must not be counted as encrypted-malware evidence. HTTP dissection
also shows Ubuntu `connectivity-check.ubuntu.com` GET/200 exchanges in all four
PCAPs. Such background traffic is not evidence of malware communication.
These checks do not attribute every packet to a sample or establish attack
activation. All four selected artifacts are ELF, but different workloads,
clean snapshot contents and activity remain potential confounders.

## Collection And Safety

Collected with `scripts/vbox_malware_batch.sh`, one frozen sample manifest per
invocation, `--timeout 20 --window-sec 0.5 --iface enp0s3 --ebpf
--fixed-observation --common-launch-wrapper`. Controls additionally used the
staged guest argument directory. The batch logs are `case-01.log` through
`case-04.log`; the manifest records exact sample and guest-directory choices.

Runner schema: `2026-10-18.1`.
Runner SHA-256: `faf7997fdadba9e71bfbb67ff0d7600746ffffecac762d7f8ed3622bd08215f9`.
Control snapshot: `clean-tls-paired-2026-10-19`.
Malware snapshot: `clean-current-runner-2026-10-18.1-malware`.

The four named cases ran in fixed B/M/B/M order; no random sample draw was
performed. The original manifest's seed description is corrected by its
`selection_execution_note`, not evidence of representative random sampling.

Before and after collection, the malware guest and Sink had only internal
`malnet` NICs, with other NICs disabled. After the final run, the guest was
restored to original snapshot `clean-tls-paired-2026-10-19`
(`72de0a02-2e71-42b8-85e2-78c21d6b00f9`) and verified powered off. The pre-existing
Sink remains running and isolated. No batch/coordinator process remains.
The paused large collection was not resumed; no detector was retrained.

## Recheck Existing Fresh Outputs

From the workspace root; this only reads captures and rewrites the QA JSON:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/fresh-batch-qa-20261019T105924Z/validate_pilot.py
```

## Zero-Feature Audit, 2026-10-19

A read-only `csv.DictReader` scan of all four fresh telemetry files, testing
`float(value) == 0` for every declared feature, found 40 of 169 features zero
across all 160 windows. Another 126 features contain both zero and nonzero
windows; three are nonzero in every window.

| Group | All-zero columns |
| --- | ---: |
| Network runtime | 0 / 9 |
| P4-shaped network | 0 / 29 |
| Additional PCAP | 4 / 28 |
| Host runtime | 8 / 13 |
| Host syscall sequences | 4 / 26 |
| Additional host events | 7 / 27 |
| eBPF counters | 17 / 35 |
| System I/O | 0 / 2 |

Per-run all-zero feature counts: curl-pair-01 47, malware 50f7... 55,
curl-pair-02 42, malware b5af... 51. Zero here means an actual numeric zero,
not an empty or missing CSV value.

The four network extras are `net_icmp_packets`, `net_other_ip_packets`,
`net_ipv6_packets`, and `net_tcp_urg_packets`. The eight host-runtime zeros
are all watched-filesystem features; only each run's workspace was watched,
so these do not establish absence of writes elsewhere.

Confirmed endpoint-detail limitation: each control has six archived `connect`
events, all reporting `addr=0 port=0`. Consequently zero
`host_unique_ip_total`, `host_unique_port_total`, `host_unique_remote_ips`
and `host_unique_remote_ports` must not be interpreted as no connections.
This audit establishes missing endpoint detail in these records, not the
underlying probe-level cause. No runner/capture change or collection occurred.