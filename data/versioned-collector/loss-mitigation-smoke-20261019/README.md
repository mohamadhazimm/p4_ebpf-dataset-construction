# Capture-Loss Mitigation Smoke, 2026-10-19

## Result

A bounded benign stress workload ran twice with the v5 runner and once with
v6. Each invocation produced exactly 50,000 IPv4 multicast datagrams to the
internal `malnet` group and 50,000 `stat` calls in a fixed 8-second / 0.5-second
window observation. The script refuses to run if the route is not `enp0s3`.
No malware ran.

| Trial | tcpdump buffer | bpftrace perf pages/CPU | Packets received by filter | Captured | PCAP drops | eBPF lost | Quality |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Low-buffer baseline, v5 | 64 KiB | 64 | 50,044 | 46,222 | 3,822 | 0 | rejected |
| Tuned, v5 | 16,384 KiB | 1,024 | 50,045 | 50,045 | 0 | 0 | accepted |
| Tuned metadata check, v6 | 16,384 KiB | 1,024 | 50,045 | 50,045 | 0 | 0 | accepted |

The low-buffer trial dropped 7.64% of packets reported received by the filter.
For this exact workload, the tuned profile captured all reported packets and
the bpftrace loss counter stayed zero. This is evidence for the tested benign
load, not a guarantee for arbitrary malware or event rates.

In v6, `net.core.rmem_max` was 4 MiB before capture, raised to 32 MiB during
capture to permit tcpdump's 16 MiB request, then restored to 4 MiB. No restore
error was recorded. The earlier v5 runs report the restored value in their
`rmem_max_effective` metadata field; v6 corrects this by separately recording
the value during capture and after restoration.

## Quality Gate

The runner writes numeric `packet_capture_statistics`,
`ebpf_lost_event_count`, `collection_quality_status`, and rejection reasons to
`run.json`. It repeats quality status/reasons in telemetry rows. Any reported
PCAP drop, unavailable requested loss counter, inactive requested sensor, or
bpftrace loss marks the collection `rejected` while preserving the retrieved
artifacts. Retrieval status remains separate from quality status.

An actual merge-and-build check confirmed the low-buffer sample is rejected by
`merge_collector_csvs.py` + `src/build_dataset.py`; both tuned samples remain
usable. Legacy files without the new quality field remain tagged
`legacy_unverified`, for historical reproducibility; they are not silently
certified by this new gate.

Focused tests: `/usr/bin/python3 -m unittest tests.test_malware_runner_hostmon -v`
passed **21/21**. Both batch and staging scripts pass `bash -n`.

## Provenance

- Runner v5: schema `2026-10-19.5`, SHA-256 `f092fb4c7b0d3366f199185fa5b0503b0889c26d8b3faba882501fbf2c032852`.
- Runner v6 metadata follow-up: schema `2026-10-19.6`, SHA-256 `6cce95960227814711aebd60bff711aef60d16d591e81c7ec4f113354b97b534`.
- Batch SHA-256: `87399063b958cc01d88463cb9c0cf10aa3d9124cbbbef9d7183b8be26c36fdc7`.
- Staging-helper SHA-256: `5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103`.
- Workload SHA-256: `ee0895cf7b86b26356aca11d995a9971061cc43770ff2d9683dec5f1c7640d44`.
- V5 snapshot: `clean-loss-mitigation-2026-10-19`.
- V6 metadata retry snapshot: `clean-loss-mitigation-2026-10-19-r2`.

The full per-run artifact hashes and downstream gate outcomes are in
[loss_mitigation_results.json](loss_mitigation_results.json). Recheck from the
workspace root with:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/loss-mitigation-smoke-20261019/validate_loss_mitigation.py
```

## Limits And Safety

This test changes both buffer settings together; it does not isolate their
individual effects. The baseline already showed zero bpftrace loss at roughly
101,000 raw syscalls, so this A/B does not demonstrate that the 1024-page
setting fixes the much higher event rates lost in Gunra/LockBit. A bounded
high-syscall known-answer stress test or separate buffer trials are still
needed before scaling malware collection. Buffer tuning reduces risk; it
cannot guarantee zero loss for arbitrary load.

The guest was restored to `clean-tls-paired-2026-10-19` and powered off.
Guest and Sink remained on isolated internal `malnet`; other NICs are off.
No malware, model training or paused-cohort resume occurred.