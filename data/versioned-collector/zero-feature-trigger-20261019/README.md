# Benign Zero-Feature Known-Answer Probe, 2026-10-19

This controlled workload is intended to distinguish unobserved activity from
features that fail to respond when their source operations are performed. It
uses the frozen VM runner on a new child of the repaired benign snapshot; it
does not execute malware or train a model.

The payload attempts file create/rename/unlink operations (including a
ransom-note-keyword filename), `renameat`, `renameat2`, `unlinkat`, `pwrite64`,
`writev`, `openat2`, `accept`, `execveat`, and `ptrace`. It also attempts ICMP
to the isolated Sink, an IPv6 link-local multicast datagram, a large UDP packet,
a TCP urgent byte to the internal Sink, and an IPv4 multicast join plus an
optional experimental raw-IP packet. Each operation reports success or an
explicit error to the archived sample stdout.

The original malware run established 24 globally all-zero features over 400
windows. This test expects event-driven fields to change only when the guest
kernel supports and the sensor captures the operation. Raw-socket privilege,
network route/interface support, and probe attachment can prevent some packet
features from changing. Record each outcome; do not coerce or backfill values.

## Provenance

See [experiment_manifest.json](experiment_manifest.json) for source hashes,
snapshot identities, settings and all 24 target features. The single sample is
listed in [manifests/trigger.txt](manifests/trigger.txt). The workload source
and setup logic are in [zero_feature_probe.sh](zero_feature_probe.sh).

The guest is required to have only internal `malnet` networking, with other
NICs disabled. Restore the original snapshot after collection. Preserve the
raw CSVs, events, PCAP, sample stdout and runner logs alongside the final
comparison report.

## Measured Result

The benign probe completed with exit 0 under schema `2026-10-19.3`; both
sensors were active, the run has 40 windows, all 169 features are finite, and
the PCAP reports zero kernel drops. The archive is present and matches all 10
regular members by SHA-256.

Exactly 12 of the 24 targeted columns became nonzero:

- eBPF: `ebpf_accept_count`, `ebpf_file_pwrite64_success_count`,
  `ebpf_file_writev_success_count`, `ebpf_openat2_success_count`,
  `ebpf_ptrace_count`, `ebpf_writev_count`.
- Host filesystem: `host_files_moved`, `host_ransom_note_like_files`.
- PCAP: `net_icmp_packets`, `net_large_packet_count`,
  `net_other_ip_packets`, `net_tcp_urg_packets`.

The other 12 remain zero. Six have direct raw-syscall evidence from the
payload process but no corresponding named eBPF entry event:
`execveat` (syscall 322), `openat2` (437), `pwrite64` (18), `renameat` (264),
`renameat2` (316), and `unlinkat` (263). In particular, the exit probes did
record successful `openat2` and `pwrite64`, while their entry counters stayed
zero. The raw `syscall_events.csv` and named `ebpf_events.csv` are included
under the output run. This is a measured discrepancy in the named-probe path;
its root cause is not established or repaired by this workload test.

`host_rename_total`, `host_unlink_total`,
`host_unique_rename_paths`, `host_unique_unlink_paths`, and
`host_execveat_event_count` also stayed zero because their source named events
were absent. `net_ipv6_packets` stayed zero because the script's IPv6 send
returned `ENETUNREACH`; the raw experimental IP-protocol send was denied with
`EPERM`. The IGMP membership report did produce two `net_other_ip_packets`,
so that feature changed even though raw protocol 253 was unavailable.

Packet dissection confirmed 3 ICMP frames, 2 IGMP frames, one frame at least
1200 bytes, and one TCP urgent-flag frame; no IPv6 or protocol-253 frame was
captured. These are deliberately generated benign events on loopback or the
isolated internal network, not malware traffic.

Read-only verification from the workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/zero-feature-trigger-20261019/validate_zero_probe.py
```

No production runner code was changed for the v3 experiment. The guest was
restored to `clean-tls-paired-2026-10-19` and powered off after the run; the
Sink remains on isolated `malnet`. No malware was executed and no model was
trained.

## Raw Syscall Fallback Retry, Schema 2026-10-19.4

The v3 known-answer run showed six successful raw syscalls without matching
named entry events. The Python collector previously archived generic raw
syscalls for sequence statistics, then skipped them when building event
counters and action summaries.

The runner now maps raw syscall numbers using the running process's ELF ABI
(x86-64 or i386). Per-window named counters are filled only for the deficit
between raw syscall count and named event count, avoiding double-counting.
Host exec/rename/unlink totals also receive that deficit. Raw syscall IDs do
not include filenames, so fallback-generated rename/unlink events cannot
produce path features unless a named path event supplied the path.

Regression suite: `/usr/bin/python3 -m unittest tests.test_malware_runner_hostmon -v`
from the study repository: **18 passed**. Tests cover named/raw deduplication,
missing named probes, host action summaries, x86-64/i386 ELF identification
and i386 syscall numbering.

The same benign workload was run again under a new child snapshot; the v3
capture remains unchanged. In the v4 result, **23/24 target features are
nonzero**. All six previously missing syscall entry counters are now nonzero:
five had named events this time, and `execveat` was recovered from one raw
syscall record. `host_execveat_event_count`, rename/unlink totals and path
features are also nonzero in this capture. This demonstrates fallback
behavior for one controlled run, not that named-probe delivery is now reliable
in every workload.

The only remaining targeted zero is `net_ipv6_packets`: the workload's IPv6
send returned `ENETUNREACH`. V4 reports active sensors, 40 windows, 169 finite
features, and zero PCAP drops. Read
[probe_fallback_results.json](probe_fallback_results.json) for the complete
v3/v4 table, raw/named counts, event provenance and artifact hashes. The v4
capture is under `runs-raw-fallback/benign/`; its source and snapshot hashes
are in [fallback_retry_manifest.json](fallback_retry_manifest.json).

Runner schema: `2026-10-19.4`; runner SHA-256
`46bcb7e7420ce9eb4c4eeb907e2fcd354c675a96ce1b85d44486f80c3a44c55a`.
The clean child `clean-zero-feature-trigger-2026-10-19-r2` was restored to
original `clean-tls-paired-2026-10-19` after collection; the guest is powered
off and isolated. No malware collection, model training or paused-cohort
resume occurred.

Repeat the read-only comparison from the workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/zero-feature-trigger-20261019/validate_zero_probe_fallback.py
```