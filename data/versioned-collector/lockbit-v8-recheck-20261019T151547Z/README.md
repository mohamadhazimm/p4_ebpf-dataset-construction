# LockBit v8 Loss Recheck

## Result

The exact LockBit artifact rejected in the v6 repeat was collected once with
runner schema `2026-10-19.8`, runner SHA-256
`1f08c55ec6c2304cc4598971e9ba8e03fcbe0f31cb0d2ca39cf7bc21a18fbaa0`, and the
default 16,384 bpftrace perf pages per CPU. The eight-second fixed observation
used the same `enp0s3` interface, eBPF, common launch wrapper, and 16-MiB
tcpdump buffer. The run used a fresh child snapshot and a new output directory.

| Measurement | Previous v6 LockBit run | New v8 LockBit run |
| --- | ---: | ---: |
| Raw syscall rows | 2,271,313 | 2,565,063 |
| bpftrace lost events | 264,304 | 0 |
| PCAP kernel drops | 0 | 0 |
| Quality | rejected | accepted |

The new run archived 16 telemetry windows (178 CSV columns), with 13 regular
archive members SHA-256 matching host extraction. eBPF and packet capture were
active. Offline PCAP reconstruction processed 62 frames, assigned 23 eligible
packets to observation windows, and produced 145 P4-shaped features. This is
offline reconstruction, not live P4 performance evidence; full benchmark
output is saved in `pcap_benchmark.json`.

The sample process timed out at the configured eight-second limit (return
code `-9`). Retrieval completed and collection quality was accepted; those are
separate statuses. The timeout does not imply that the malware exited
successfully.

Recheck provenance, loss logs, raw-row reconciliation, finite feature values,
PCAP counters, and archive member hashes from the workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/lockbit-v8-recheck-20261019T151547Z/validate_lockbit_v8.py
```

## Limits And Cleanup

This is one repeat of one artifact and does not prove loss-free capture for
every malware event mix or observation duration. The prior v6 capture remains
rejected and is not retroactively changed. No cohort was resumed and no model
was trained. The guest was restored to `clean-tls-paired-2026-10-19`, powered
off with `nic1=intnet` and other NICs disabled. The pre-existing Sink remains
running on internal `malnet` only.