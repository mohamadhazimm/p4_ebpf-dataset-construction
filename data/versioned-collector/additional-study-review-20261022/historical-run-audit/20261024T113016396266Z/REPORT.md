# Historical Run Audit: 7,337 Recorded Sample Runs

Date: 2026-10-24. Read-only. No VM operation, no sample execution and no run modified.
Produced by [`audit_historical_runs.py`](../../audit_historical_runs.py), SHA
`456389373e7eceaca4f5f89d54c833b45a276c6e1d352a7f8e7b02fec30659bd`. Per-run table:
[`runs.csv`](runs.csv), SHA `8dcff3f6...`. Totals: [`summary.json`](summary.json), SHA `b391a887...`.

## Scope and method

Every `host_run.txt` under `vbox-runs/hybrid-rf-study-20261010/data/` is in scope: 7,337 runs, about 40
experiments and 19 collector schemas. Label counts: 3,811 malware, 2,662 benign, 602 scenario, 44 null and 218 other.
Metadata fields grew over time: 2,924 runs come from an unversioned runner, and only `.19.5`+ records quality
verdicts. For older runs, packet counters come from `packet_capture.log` and eBPF loss from
`ebpf_collector.log`. A field that is missing is reported as unavailable, never as clean. "Leaking" means a
byte marker of a known background service occurs anywhere in the PCAP. The markers are NetworkManager
connectivity check, apt download, NTP DNS, mDNS, cups and reverse DNS. Presence is not proof the traffic fell
inside a feature window, although a tshark analysis of the 417-case joint dataset found it in-window in all
417. P4 alignment results are reused from the five existing modeling audits rather than recomputed.

## Retrieval failures: 212 runs, 203 of them malware

| Cause | Runs | Notes |
|---|---:|---|
| Batch/runner version mismatch (`unrecognized arguments --packet-capture-password-file`) | 42 | all `malware/revision4`; historical setup error |
| Guest Control copy/archive failed after all retries, guest session terminated, `tar` killed | ~68 | repeat offenders: `4dc06ec` (LockBit) x7, `3fafbee` (JackSkid) x5, `5e4076c8`, `7050da3`, `f1fbc28` x4 |
| Runner died with an empty log | 28 | 8 of these left partial PCAPs over 5 MB (heavy network activity) |
| Sample not extracted / path missing / `extract_failed` | 38 | mostly `malware/revision4` |
| PCAP permission error (`/tmp/.malware-pcap-*.pcap`) | 15 | still present in `.18` cohorts (cohort-100 1, cohort-expansion 2) |
| Runner not staged in snapshot | 11 | historical setup error |
| Unsupported architecture / exec format | 15 | |
| eBPF failed to start (bpftrace program error) | 7 | `benign/revision3`, `hybrid_scenarios/v6` |

Failure rate: **malware 5.3% (203/3,811) vs benign 0.26% (7/2,662).** Missingness depends on the label and on
the sample. The same disruptive samples fail every time, so they are absent from every dataset.

## Dropping (completed runs)

| Version | Runs | PCAP counter gap | Kernel drops | eBPF lost | Untracked-thread events dropped |
|---|---:|---:|---:|---:|---:|
| unversioned | 2,924 | 1,570 | 0 | 32 | 688 |
| `.17.2` | 1,474 | 934 | 0 | 4 | 1,463 |
| `.18.1` | 1,418 | 189 | 1 | 35 | 20 |
| `.19.3-.19.12` | 194 | 50 | 2 | 4 | 0 |
| `.19.13-.19.14` | 336 | 0 | 4 | 0 | 0 |
| `.20.15-.20.17` | 106 | 0 | 0 | 0 | 0 |
| `.20.18` | 624 | 2 | 0 | 5 | 4 |
| `.24.19` | 35 | 0 | 0 | 0 | 0 |

- The counter gap (tcpdump `received > captured`) disappears once immediate mode arrives (`.13`/`.14`).
- **eBPF event loss is almost all malware: 72 runs vs 2 benign.**
- The old runner discarded events from threads it did not track. That affected 35% of malware runs vs 24% of
  benign, so host features undercount descendant activity, and more so for malware. Fixed from `.18.1`.
- From `.19.5` on, lossy runs are rejected (27 quality rejections). Before that, they entered the datasets
  without any gate.
- Nonfinite telemetry: none. Unresolved syscall ABI: none.

## Slipping

- **Early-stop observations:** 4,320 runs (unversioned 2,877, `.17.2` 1,443) recorded fewer windows than
  requested, because observation ended when the sample exited. Affected: 66% of benign runs vs 55% of malware.
  This is a duration confound. Fixed observation from `.18.1` gives 0.
- **Window drift:** the largest per-run deviation of any window from the nominal 0.5 s.

  | Version family | Median | p90 | p99 | Max |
  |---|---:|---:|---:|---:|
  | `.18.1-.14` | 25.5 ms | 85.6 | 223.2 | 479.6 |
  | `.15-.18` | 31.3 ms | 96.5 | 206.4 | 647.6 |
  | `.19` | 25.2 ms | 76.4 | 139.8 | 139.8 |

  Drift occurs mid-run (492 of 510 windows over 50 ms are middle windows), and the 40 windows still total
  20.00 s. It differs only slightly by label: 28.8% of malware runs exceed 50 ms vs 25.0% of benign. Rate
  features divide by the nominal 0.5 s, so a 90 ms-longer window inflates that window's rates by about 18%.
- **P4 window alignment:** in every modeling audit, 8-12% of captures fail unique alignment
  (`telemetry_interval_counter_mismatch`): 51/417, 15/200, 18/194, 38/337, 21/178. Total in-window packets
  match exactly (absolute error 0). Only the per-window split differs, as boundary packets land in the
  neighbouring window. Nothing is lost; packets are attributed to the wrong window. The 33 quiet `.19`
  captures checked so far all aligned, but they carry few packets.

## Leaking

Background-service traffic is in **6,725 of the roughly 7,090 completed pre-`.19` captures**, across every
version and for benign, malware and null alike. In `.19` on the quiet snapshot it appears in 1 of 35: the
apt-contaminated null (`APT-HTTP`).

## Execution

Target exec was not observed in 24 runs. This is only measurable from `.15`, for example the CoinMiner
`execve` EFAULT. The exec gate excludes these runs.

## What is fixed and what is still open in the current collector (`.19`)

Fixed: tcpdump counter gaps (immediate mode), early-stop observation (fixed 20 s), untracked-thread drops,
perf-buffer eBPF loss in tested loads (16,384 pages, and rejected when it occurs), quality gating,
false no-traffic rejection (per-sample probes), and the main background services (quiet snapshot).

Still open:
1. apt background downloads, seen in 1 of 16 boots. Quiet-v2 masking exists, but no guest has tested it.
2. Mid-run window drift (p90 about 76 ms in `.19`) and the boundary misattribution it causes.
3. Retrieval failures concentrated in malware: guest-disrupting samples, the PCAP permission race and silent
   runner deaths including heavy-traffic samples. This biases which malware ends up in a dataset.
4. The 14 old `hybrid_scenarios/v6` retry directories that hold two runs each.

## Implications for existing datasets

The 417-case joint dataset (`.18` cohorts) is quality-gated for loss. It still carries background
traffic in every capture, excludes 51 misaligned captures from P4, and lacks every malware sample that failed
retrieval. All datasets built from unversioned, `.17.2` or `.18.1` runs also carry ungated counter gaps,
untracked-thread undercounting and, before `.18.1`, label-skewed observation lengths. Report these as
threats to validity. None of them can be repaired after the fact from the saved data.
