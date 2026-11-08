# High-Syscall Perf-Buffer Validation

## Why Events Were Lost

The LockBit repeat run archived 2,271,313 raw syscall rows in eight seconds and
reported 264,304 lost bpftrace events. The runner's `.6` launch set
`BPFTRACE_PERF_RB_PAGES` on `sudo`; sudo may filter that variable before
bpftrace starts. The old guest policy was not inspected, so this is a likely
contributor, not a proven explanation of the LockBit result.

The code also emits a raw syscall record for every tracked syscall and emits
additional named records for selected syscalls. This is a high sustained output
rate. A larger ring buffer absorbs bursts but cannot prevent loss if the
consumer cannot drain it quickly enough.

## Fix And Evidence

Runner schema `2026-10-19.7` moved the assignment to
`sudo /usr/bin/env BPFTRACE_PERF_RB_PAGES=N /usr/bin/bpftrace`, after privilege
elevation. A benign, read-only probe repeatedly called `stat('/etc/passwd')`
up to two million times, with no network operations or malware. Under the same
v7 runner and six-vCPU guest:

| Perf pages per CPU | Calls | Duration | Raw syscall rows | Lost events | Quality |
| ---: | ---: | ---: | ---: | ---: | --- |
| 1,024 | 2,000,000 | 2.807 s | 1,175,472 | 825,564 | rejected |
| 16,384 | 2,000,000 | 2.589 s | 2,001,036 | 0 | accepted |

Schema `2026-10-19.8` makes 16,384 pages the runner and batch default and keeps
the post-sudo environment assignment. A fresh v8 child snapshot was staged from
`clean-loss-mitigation-2026-10-19-r2`; the same probe was collected with the
perf-pages CLI option omitted. It completed 2,000,000 calls in 2.448 seconds
(~816,850 calls/s), archived all 2,001,036 raw syscall rows, reported zero
lost events, and was quality-accepted. Both sensors were active; PCAP reported
26 received/captured packets and zero kernel drops. All 10 archived regular
files hash-match host extraction.

Runner v8 SHA-256:
`1f08c55ec6c2304cc4598971e9ba8e03fcbe0f31cb0d2ca39cf7bc21a18fbaa0`.
The 16,384-page setting allocates about 64 MiB per CPU, or 384 MiB on this
6-vCPU guest. See `experiment_manifest.json`, `buffer-trial-16384.json`, and
`loss_results.json` for frozen settings and artifact hashes.

Repeat the archive, metadata, exact loss-log, and hash checks from the
workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/ebpf-high-syscall-v8-default-20261019/validate_high_syscall_v8.py
```

## Limits

The A/B supports insufficient perf-buffer capacity as the cause for this
synthetic event burst, and verifies the default works in one isolated run. It
does not prove zero loss for every syscall mix, malware sample, or longer
observation. LockBit's v6 trace remains rejected; it cannot be repaired
retroactively. No malware was run and the paused cohort was not resumed. The
guest was restored to `clean-tls-paired-2026-10-19`, powered off, and kept on
internal `malnet` only; Sink remains internal-only.