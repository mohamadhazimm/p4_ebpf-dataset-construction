# Interface-Counter Sequence Diagnostic

## Result

The benign probe sent 50,000 unique sequence-marked multicast datagrams and
50,000 read-only `stat` calls. Runner schema `2026-10-19.11` recorded
`enp0s3` RX/TX counters immediately before sample launch and after tcpdump
shutdown.

- All 50,000 sequence IDs were captured exactly once.
- PCAP and tcpdump counters matched: 50,065 received, 50,065 captured, zero
  kernel drops, discrepancy zero.
- eBPF lost events: zero. Collection quality: accepted.
- Interface deltas: TX 50,035 packets / 4,502,991 bytes / zero drops; RX 27
  packets / 3,215 bytes / zero drops.
- The PCAP has three more frames than the sum of interface RX/TX packet deltas.

This repeat captures every known workload datagram and has reconciled tcpdump
counters. However, previous runs at similar drain settings produced gaps of 1,
24, and 38, so one clean repeat does not prove that the counter issue is fixed.
The guest has no `dumpcap` or `tshark`; the independent comparison here is
interface counters, not a second capture backend. Root cause remains
unconfirmed.

Recheck sequence IDs, interface counters, tcpdump statistics, telemetry and
archive hashes from the workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/pcap-interface-sequence-v11-20261019T194156Z/validate_interface_sequence_v11.py
```

The guest was restored to `clean-tls-paired-2026-10-19`, powered off and
isolated. No malware was executed and the paused cohort was not resumed.