# Overnight QA v12

Status: frozen before staging. Wave 1 is 50 unique malware artifacts across 24 families plus 50 benign native-ELF workload runs. The benign controls are 10 preflighted binaries exercised under five argument profiles; this is 50 executions, not 50 unique benign executables. All benign network destinations are the isolated Sink at `10.0.0.1` or loopback.

Wave 2 adds another 50 malware artifacts across 9 families and 50 benign executions under five more profiles, but it is conditional: it runs only if wave 1 has complete retrieval, every sensor quality status accepted, zero packet counter discrepancies, zero reported kernel/eBPF loss, independent PCAP record counts matching tcpdump `captured`, and complete archive/hash parity. If any gate fails, wave 2 is withheld and the rejected cases are reported.

Runner schema/hash, class snapshots, sample selection, argument profiles, and settings are frozen in `experiment_manifest.json`, `selection.json`, and the ten malware round manifests. All captures use the broad interface capture (no BPF filter), 20-second fixed observations, 0.5-second windows, eBPF, a 16-MiB PCAP buffer, and a 1-second drain. No `--resume` is used; this is a new root and does not touch the paused 500-run cohort.

This campaign is sensor QA, not a balanced classifier dataset or prevalence-representative study. The malware selection is purposive. The benign side reuses ten ELF tools with varied profiles; it does not establish 50 unique benign program identities.

Results, validation, and final VM restoration state will be added after execution.
