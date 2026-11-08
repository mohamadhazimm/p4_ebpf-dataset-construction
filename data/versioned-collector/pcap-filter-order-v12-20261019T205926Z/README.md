# Filtered PCAP Position Diagnostic v12

Status: validated; guest restored. This benign test ran three identical sequence-marked multicast probes in positions 1, 2, and 3 of one batch, with a BPF filter limited to the probe's exact UDP destination and port. Every run started from the same clean snapshot. This tests whether unfiltered background traffic or end-of-batch position relates to the intermittent tcpdump counter discrepancy.

The payload emits up to 50,000 packets to `239.255.42.198:65003`, with a unique sequence number in each packet. The capture filter is `udp and dst host 239.255.42.198 and dst port 65003`. Runner schema, hashes, snapshot, sample-list, and settings are in `experiment_manifest.json`.

## Results

All three positions were accepted. Each sent 50,000 packets, and tcpdump reported 50,000 received / 50,000 captured / zero kernel drops. The PCAP contained exactly 50,000 records, with every sequence ID present once and no duplicates. eBPF loss was zero, and 11 archive files per run matched host-extracted SHA-256.

| Position | Run | Received / captured / PCAP | Quality |
| --- | --- | ---: | --- |
| First | `run_20261019T210316Z` | 50,000 / 50,000 / 50,000 | accepted |
| Middle | `run_20261019T210400Z` | 50,000 / 50,000 / 50,000 | accepted |
| Last | `run_20261019T210438Z` | 50,000 / 50,000 / 50,000 | accepted |

This weakens the simple “last sample in the batch” explanation: the last filtered run was clean. The absence of a gap under the exact-flow filter supports the possibility that unfiltered background traffic contributes to the earlier counter difference, but a single three-position batch cannot establish that cause. The test also changed the BPF filter, so it cannot isolate filter effects from all other variability. A second capture path is still needed for definitive attribution.

Recheck from the study repository root:

```sh
PYTHONPATH=/tmp/hazim-validation-deps-20261019 /usr/bin/python3 data/versioned-collector/pcap-filter-order-v12-20261019T205926Z/validate_filtered_order.py
```

The guest was restored to `clean-tls-paired-2026-10-19`, powered off and isolated. No malware or external network was involved.
