# IPv4 Endpoint Capture Repair, 2026-10-19

## Accepted Result

The repaired VM runner captures IPv4 addresses and human-order ports instead of
zero placeholders. Two fresh benign curl fixtures pass guest-side collection,
archive transfer, PCAP endpoint matching, and all four exported endpoint counts.

| Fixture | IPv4 endpoints in raw events | Endpoint feature maxima | Windows | Archive files matched |
| --- | --- | --- | ---: | ---: |
| curl-pair-01 | 127.0.0.53:53; 10.0.0.1:443 | 2, 2, 2, 2 | 40 | 10 |
| curl-pair-02 | 127.0.0.53:53; 10.0.0.1:443 | 2, 2, 2, 2 | 40 | 10 |

The four features are `host_unique_ip_total`, `host_unique_port_total`,
`host_unique_remote_ips`, and `host_unique_remote_ports`. All 320 cells
(four features x 40 windows x two runs) reconcile with independently counted
per-process or per-window endpoint sets. Both PCAPs decode TLS ClientHello
traffic to `10.0.0.1:443`, SNI `cdn.fwupd.org`, matching the raw connect peer.
Both runs completed with exit 0, active sensors, 169 finite features per row,
and zero reported PCAP kernel drops.

Each fixture also attempts four UNIX-domain connects. These intentionally have
zero IPv4 address/port fields, now explicitly distinguished by `family=1`.
The two actual IPv4 events are identified by `family=2` and decode as:

```text
addr=2130706485 port=53 family=2
addr=167772161 port=443 family=2
```

## Repair And Failed Attempt

The original probe applied `uptr` before pointer casts and used sockaddr pointer
offsets without normalizing to a byte address. The repair applies `uptr` to
each final typed dereference, casts `uservaddr` to `uint64` before adding byte
offsets, and assembles network-order address/port bytes explicitly. Other
socket families remain identifiable without being counted as IPv4 endpoints.

The first attempt fixed the family read but left pointer arithmetic unnormalized:
family decoded as 2 while IPv4 endpoints remained zero. Local tests passed but
the live endpoint-versus-PCAP gate failed. That attempt is retained unchanged
under `runs/benign`, snapshot `clean-endpoint-2026-10-19.3-benign`, runner SHA
`03e37b130584fab9554a8b56c6f96a2a9bb2f480681b3354be09550c2ec1b8e9`.
It is not accepted as a repaired capture.

Accepted outputs are only under `runs-byte-offsets/benign`, pinned by
[retry_manifest.json](retry_manifest.json). The original planning manifest is
[experiment_manifest.json](experiment_manifest.json). Do not merge attempts
merely because both share the new schema label: their runner hashes differ.

## Accepted Provenance

- Runner schema: `2026-10-19.3`; feature layout remains 169 features / 176 columns.
- Runner SHA-256: `8573b13f83b06bb1bcf1fd3216cc633bb2e48a79530e906b2b2eee924afddd9b`.
- Accepted child snapshot: `clean-endpoint-2026-10-19.3-r2-benign`.
- Baseline: `clean-tls-paired-2026-10-19`; original contents were not changed.
- Batch SHA-256: `509c39117d0517e4632fae4c90aa0c882bf1b152e7259e7b5dc04fe997b8d4c3`.
- Staging-helper SHA-256: `5fce8723cf31b6f1b104a87f646bd8e8686153d9212800d3de81684d93d94103`.
- Both Bash helpers now accept `--schema-version`; their historical default remains `2026-10-18.1`. Both stages/collections here explicitly supplied `--schema-version 2026-10-19.3`; schema and runner-hash checks remained mandatory.
- Settings: 20-second fixed observation, 0.5-second windows, `enp0s3`, eBPF, common launch wrapper and the existing per-fixture argument directory. Four benign executions occurred in total: two failed endpoint-validation controls and two accepted retry controls. No malware was executed.

`stage.log` / `collection.log` preserve the first attempt;
`retry-stage.log` / `retry-collection.log` preserve the accepted retry.
[endpoint_validation.json](endpoint_validation.json) includes artifact hashes
and the exact accepted per-case results.

## Validation And Safety

The narrow runner suite passed 15/15 tests, including probe generation,
normalized byte offsets, the four endpoint aggregates and exact port values.
Both Bash scripts pass `bash -n`; editor diagnostics report no errors in the
touched Python sources. Direct host CLI execution lacks `watchdog`, so local
tests use their existing dependency fallback; actual guest runs compiled,
attached and exercised the BPF probe successfully.

The guest and Sink were verified isolated to internal `malnet`, other NICs
disabled. Final guest state: powered off and restored to original snapshot
`clean-tls-paired-2026-10-19`, UUID `72de0a02-2e71-42b8-85e2-78c21d6b00f9`.
The pre-existing Sink remains running and isolated. No collection/coordinator
process remains. No old captures, frozen snapshot contents, or paused-cohort
manifests were rewritten; no detector was retrained and no large batch resumed.

## Scope

This fixes IPv4 connect-attempt metadata, not connection-success attribution.
IPv6 endpoint decoding and filesystem watch scope are unchanged. Only the new
benign r2 snapshot contains the accepted runner; a new malware snapshot must be
staged before a future repaired malware collection. Never substitute this hash
into the old paused run or silently merge its captures with the frozen runner.
Old zero endpoint values cannot be recovered from those raw events alone.
Zero reported PCAP drops does not prove zero unreported eBPF loss. This is not
classifier, live-P4, representative-workload or attack-activation evidence.

To repeat the read-only check from the workspace root:

```sh
/usr/bin/python3 vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/endpoint-fix-20261019T112828Z/validate_endpoints.py
```