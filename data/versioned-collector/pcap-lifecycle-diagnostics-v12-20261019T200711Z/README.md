# PCAP Lifecycle Diagnostics v12

Status: validated and VM restored. This experiment ran the benign sequence-marked multicast probe three times in separate output roots with runner schema `2026-10-19.12`.

The runner records tcpdump spawn/readiness, stop/drain/SIGINT/exit timing, selected timestamped stderr lines, interface RX/TX counters at the drain boundary and after shutdown, and an independent count of records in the saved PCAP. Each run uses the isolated `malnet` internal interface; no malware or public network is involved.

## Results

All three sample executions returned 0, and each PCAP contains all 50,000 unique sequence IDs exactly once. There were zero reported PCAP kernel drops and zero eBPF lost events in all runs. The independent PCAP record count equaled tcpdump's `packets captured` count in every run, and 11 archived regular files per run matched their host-extracted SHA-256.

| Repeat | PCAP records / captured | Received by filter | Kernel drops | Quality | NIC RX/TX packet deltas |
| --- | ---: | ---: | ---: | --- | ---: |
| 01 | 50,027 | 50,027 | 0 | accepted | 9 / 50,017 |
| 02 | 50,046 | 50,046 | 0 | accepted | 16 / 50,028 |
| 03 | 50,061 | 50,062 | 0 | rejected, discrepancy 1 | 27 / 50,035 |

In repeat 03, the known workload sequences are complete and the saved PCAP has exactly the number of records tcpdump says it captured. The one-count discrepancy is specifically between `packets received by filter` and `packets captured`; it is not introduced by archive retrieval or PCAP publication. The interface RX+TX totals differ from PCAP frame counts by +1, +2, and -1 across repeats, with zero interface-reported drops, so those counters do not independently resolve the extra received count.

The final tcpdump summary appeared 0.27-0.37 ms after SIGINT and the process exited normally about 15.4 ms after SIGINT. This gives no evidence of a stalled shutdown, but does not establish why one packet is counted as received and not captured in repeat 03. The underlying counter discrepancy remains unresolved.

Recheck all three traces and archive hashes from the study repository root:

```sh
PYTHONPATH=/tmp/hazim-validation-deps-20261019 /usr/bin/python3 data/versioned-collector/pcap-lifecycle-diagnostics-v12-20261019T200711Z/validate_lifecycle_diagnostics.py
```

The guest was restored to `clean-tls-paired-2026-10-19`, powered off and isolated. No malware was executed and the paused cohort was not resumed. These three repeats characterize only this bounded workload; they do not prove general capture completeness or explain every prior gap.
