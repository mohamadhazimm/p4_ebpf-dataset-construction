# PCAP Counter Discrepancy Follow-Up

## Fix Applied

Schema v9 added `packet_capture_counter_discrepancy = packets_received_by_filter
- packets_captured - dropped_by_kernel` and rejects nonzero or unavailable
values. It also added a configurable tcpdump drain grace before SIGINT. Schema
v10 sets that grace to 1,000 ms by default. This makes unexplained gaps visible
and prevents those captures from being accepted; it does not establish the
underlying source of the discrepancy.

## Measured Drain Trials

| Runner | Drain | Received | Captured | Kernel drops | Discrepancy | eBPF loss | Quality |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| v8 | 500 ms | 50,065 | 50,041 | 0 | 24 | 0 | accepted by old gate |
| v9 | 500 ms | 50,063 | 50,062 | 0 | 1 | 0 | rejected |
| v9 | 1,000 ms | 50,045 | 50,045 | 0 | 0 | 0 | accepted |
| v10 default | 1,000 ms | 50,062 | 50,061 | 0 | 1 | 0 | rejected |
| v10 explicit | 2,000 ms | 50,065 | 50,041 | 0 | 24 | 0 | rejected |

These repeats are nonmonotonic: longer drain did not reliably eliminate the
gap. Keep the quality rejection and do not label the gap proven kernel packet
loss.

## Known-Answer Check

The sequence-numbered benign probe sent 50,000 uniquely marked datagrams. Its
PCAP contains all 50,000 unique IDs with no missing or duplicate workload
packets, but the tcpdump counters still differ by 38 (50,064 received,
50,026 captured, zero kernel drops). See
`../pcap-sequence-v10-20261019T191430Z/README.md` and run its validator. This
shows the known workload packets are present in that PCAP; it does not explain
the extra received count or establish that unrelated traffic was fully
captured.

**Conclusion:** the collector now rejects unresolved PCAP counter gaps instead
of silently accepting them. The gap's root cause remains unproven. No malware
was run for these follow-ups; the guest was restored and powered off after each
trial.