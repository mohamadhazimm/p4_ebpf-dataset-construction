# Benign ELF Pilot

Status: the corrected three-workload retry completed and passed validation. The initial attempt is preserved separately and excluded from successful workload evidence.

This bounded pilot runs one direct ELF each for SQLite, FFmpeg, and Zstandard. The guest is named `Ubuntu-Clean-24.04`, but its copied package database and verified runtime packages indicate a 26.04 package generation; `/etc/os-release` was unavailable during preparation, so the OS release is not claimed as conclusively verified. The initial SQLite candidate was from Noble and proved incompatible with the guest's later `libsqlite3-0`; the accepted retry uses the signed Resolute CLI version matching the installed guest library. Zstandard remains the verified Noble candidate. The Noble FFmpeg candidate conflicts with the guest's installed VA-API versions, so the pilot uses FFmpeg 7:8.0.1-3ubuntu2 and its signed 26.04 dependency bundle. Each workload uses only local files, with no external-network destination configured.

`experiment_manifest.json` freezes the runner/source hashes, baseline snapshot, planned child snapshots, settings, package/binary hashes, and strict per-run quality gate. Candidate package provenance is documented in the sibling `benign-elf-internet-candidates-20261020/README.md`.

FFmpeg dependencies were downloaded from signed Ubuntu 26.04 repositories into a temporary host cache, then installed offline in the isolated child snapshot. The resolver planned 62 new packages, zero upgrades, and zero removals; `dpkg --audit` was clean. The first batch dry-run rejected the original Zstandard basename because `+` is not allowed by the batch script; it executed no workload. The selected name now uses a hyphen-only alias with identical archive bytes. The first prepared snapshot is retained but superseded by the corrected-name child.

## Initial Attempt

The first collection is preserved at `runs/collection/`. All three retrievals and sensor-quality gates passed, but SQLite exited 1 with a CLI/runtime SQLite version mismatch. FFmpeg and Zstandard exited 0, yet all three output targets were absolute paths under `/tmp/malware-lab/extracted`, outside the per-run archive. This attempt is not counted as successful workload evidence.

## Corrected Retry

The accepted retry is at `runs/collection-r2/`, using runner schema `2026-10-19.14` / SHA-256 `b366c337481e82e3118038ac966f3b35d5a5195123213a763a5ba2a8b1bf09d9` and snapshot `clean-benign-elf-pilot-v14-r3-20261020T122312Z` (UUID `816f2414-dff9-4b0c-84b7-02b1b8413ab9`). The SQLite CLI is package `3.46.1-9ubuntu0.3`; the guest's `libsqlite3-0` has the same version, and the exact executable reported SQLite 3.46.1 inside the guest. All workload outputs use relative sample-workspace names.

All three samples exited 0 and have accepted collection quality. Each run has 40 telemetry windows and 169 finite declared features. Across the three runs, 198 PCAP records were captured; received/captured discrepancy, kernel-reported drops, eBPF lost events, and interface drops were all zero. The 36 regular archive members hash-match the host-extracted files. The archives contain a 20,480-byte SQLite database, 118,418-byte MP4, and 296-byte Zstandard output. SQLite reported `500|41791750`; artifact hashes are recorded in `pilot_retry_validation.json`.

Repeat the read-only checks from the study root with `/usr/bin/python3 data/versioned-collector/benign-elf-pilot-v14-20261020T122312Z/validate_pilot_retry.py`. The validator and machine-readable report hashes are pinned in `retry_manifest.json`. This purposive three-workload pilot verifies these local executions and captures only; it is not representative benign-workload or detector-performance evidence. The paused large collection was not resumed, no malware was run, and no model was trained.
