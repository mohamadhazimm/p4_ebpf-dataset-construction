# PCAP Counter Drain Comparison

Two benign packet-stress runs used schema `2026-10-19.9`, a 16-MiB tcpdump
buffer, 16,384 bpftrace pages/CPU, and the same 50,000-packet / 50,000-stat
internal workload. Only the tcpdump drain changed:

| Drain | Received by filter | Captured | Kernel drops | Counter discrepancy | eBPF loss | Quality |
| ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 500 ms | 50,063 | 50,062 | 0 | 1 | 0 | rejected |
| 1,000 ms | 50,045 | 50,045 | 0 | 0 | 0 | accepted |

The 1,000-ms run cleared the discrepancy in this repeat, but later v10 runs
with 1,000 and 2,000 ms had gaps of 1 and 24 respectively. Drain time therefore
does not reliably explain or eliminate the tcpdump counter gap. Schema v9's
quality gate rejects any nonzero or unavailable
`received - captured - kernel_dropped` discrepancy. Do not treat zero kernel
drops alone as proof that the PCAP is fully reconciled.

The source runs are preserved under `runs/benign-packet-stress-v9/` and
`runs/benign-packet-stress-v9-drain-1000/`; `drain-trial-1000.json` pins the
one-factor comparison. This is benign isolated stress, not malware evidence.