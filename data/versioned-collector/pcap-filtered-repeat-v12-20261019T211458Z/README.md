# Filtered PCAP Counter Repeat v12

Status: validated; guest restored. This benign-only experiment repeated the same sequence-marked UDP probe 12 times in one ordered batch. Each run booted from the same clean snapshot and used the exact filter `udp and dst host 239.255.42.198 and dst port 65003`.

The purpose was to see whether the counter discrepancy recurs under filtering across more positions, including the final positions. The first three filtered positions were clean, while prior unfiltered batches included one-count gaps. These 12 repeats improve the comparison but still cannot prove the root cause or replace an independent capture backend.

Runner, helper, probe, sample-list hashes, snapshot, filter, and collection settings are in `experiment_manifest.json`. No malware, external network, or paused-cohort resume was involved.

## Results

All 12 runs were accepted. Each sent 50,000 packets, and each had 50,000 received by filter, captured, and written to PCAP. All sequence IDs appeared exactly once; there were zero reported kernel drops and eBPF losses. The PCAP record count matched tcpdump's captured count in every run; 11 archive members per run matched host-extracted SHA-256.

There was no discrepancy in any position, including position 12. Compared with the unfiltered 12-malware QA, which had one discrepancy in 12 runs, this supports—but does not prove—the hypothesis that packets outside the exact probe flow contribute to the mismatch. The earlier unfiltered three-run benign diagnostic also had one gap, while the filtered three-position batch had none. Because filtering changes which packets are counted and this is one synthetic workload, this does not prove the collector is generally loss-free or rule out tcpdump/libpcap accounting behavior.

Recheck from the study repository root:

```sh
PYTHONPATH=/tmp/hazim-validation-deps-20261019 /usr/bin/python3 data/versioned-collector/pcap-filtered-repeat-v12-20261019T211458Z/validate_filtered_repeat.py
```

The guest was restored to `clean-tls-paired-2026-10-19`, powered off and isolated. The Sink remains internal-only.
