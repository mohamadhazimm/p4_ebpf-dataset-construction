# Benign Attribution Pilot

## Result

All six benign captures passed the bounded execution, capture-quality, attribution and offline P4 checks. Known network traffic was recovered, but the controls also demonstrate unrelated traffic during null/file-only work. This supports a traffic-relevance/attribution concern; it does not establish the cause of the hybrid model's reversal.

No malware, model fitting, dataset merge, resplitting, production collector edit or service-policy change occurred. Existing datasets, models and consumed validation remain unchanged.

## Design

- One static native amd64 executable, two repeats each of null, file-only and internal-Sink TCP/UDP tasks; not six independent programs.
- Frozen order: null1, net1, file1, file2, net2, null2. No executed workload was retried or replaced.
- Fresh child `clean-attribution-v18-20261022T101347764368Z`, UUID `171ec879-4ac1-4354-a9d9-7569de73b6ed`, from `clean-current-runner-2026-10-18.1-malware`, restored for each case.
- Production runner schema `2026-10-20.18`, SHA-256 `3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49`; batch/staging pins unchanged.
- Standard fixed 20-second observation, 0.5-second windows, enp0s3, eBPF, common wrapper, immediate PCAP mode, 65,536-KiB buffer, 1,000-ms drain and 16,384 perf pages/CPU.
- Numeric Sink `10.0.0.1` only. TCP ports `65101/65102` to port80; UDP ports `65201/65202` to port65003. No DNS lookup is needed for the probe. PID, endpoints, realtime and monotonic clocks were logged.
- Staging inventoried services, addresses and routes in [staging.log](staging.log). Services were not suppressed. NetworkManager, Avahi, chrony and other services were running; this inventory is not packet-to-process ownership evidence.

## Measurements

| Case | Whole-PCAP Records | In-Window IPv4 TCP/UDP | Probe-Tuple Packets | Connectivity HTTP Requests |
| --- | ---: | ---: | ---: | ---: |
| null1 | 65 | 65 | 0 | 2 |
| net1 | 92 | 84 | 18 | 2 |
| file1 | 82 | 67 | 0 | 2 |
| file2 | 65 | 65 | 0 | 2 |
| net2 | 90 | 83 | 18 | 2 |
| null2 | 68 | 66 | 0 | 2 |
| Total | 462 | 430 | 36 | 12 |

- Each network repeat recovered one unique HTTP request marker, an actual HTTP200 response, 12 packets on its bidirectional TCP tuple and all six unique UDP markers exactly once inside telemetry windows. Probe PIDs were4622 and4597.
- Probe PIDs matched exec-success evidence. Each network repeat had two socket calls, one connect, seven sendto calls (one TCP send plus six UDP sends) and a matching named IPv4 connect to `10.0.0.1:80`. UDP marker times fell within the recorded probe execution interval.
- A separate passive Scapy check found six ICMP port-unreachable replies per network repeat quoting its exact UDP tuple. The UDP send/capture succeeded; no UDP application acceptance is claimed.
- Null/file controls had no designated probe tuple and zero recorded socket/connect/sendto/recvfrom/sendmsg/recvmsg calls for the probe PID. Both file outputs matched their exact expected128-line contents.
- Every case contained two in-window HTTP requests for `connectivity-check.ubuntu.com`, including null/file controls. This is unrelated to these controls' intended work. The hostname is not evidence of public contact: the VMs remained on isolated malnet.
- There were394 other in-window IPv4 TCP/UDP packets. Keep them unattributed rather than treating every unmatched packet as ambient. There were445 total in-window frames, including the12 quoted ICMP replies and three non-IPv4 frames;17 of the462 whole-PCAP records were outside modeled intervals.

## Validation

All six retrievals completed, all targets exactly executed in the intended native/static mode and exited0, and all collection-quality statuses were accepted. Independent checks reproduced40,560 finite feature cells,76 safe regular archive-member hashes,462 PCAP records matching received/captured counters, and870 stored-versus-offline P4 summary comparisons without mismatch. All six P4 alignments were unique, using recorded windows, Ethernet bytes and nominal rates. Reported kernel drops, packet discrepancies, eBPF loss and unresolved ABI were zero; links were up/carrier1 and buffer limits restored.

The saved audit reproduced exactly in a separate recheck. Independent transport checks verified all six outer-container hashes, exact executable member hashes/basenames and argument files. Local tests also rejected wrong tuple ports and positive loss/gap probes. Editor diagnostics and Pylance syntax checks passed. These bounded passes do not prove never-recorded-event completeness or arbitrary stress capacity.

## Cleanup

Saved and fresh read-only checks confirm the guest powered off on original `clean-tls-paired-2026-10-19`, UUID `72de0a02-2e71-42b8-85e2-78c21d6b00f9`. Guest and running Sink have only NIC1 internal malnet, NICs2-8 none. No competing collector/stager remained. See [final_vm_state.json](final_vm_state.json).

An earlier staging-only attempt `20261022T101145033339Z` stopped at an early address-readiness check before a child snapshot or control execution. Its failure and cleanup are preserved. Staging was corrected to inventory the early state; exact-address workload binding and all runtime gates remained enforced. Build-only attempt `20261022T101323397403Z` validated the generated staging Python/Bash without VM operation. Neither is an extra successful capture or an executed-control retry.

## Interpretation

The tested pipeline can export, align and recover these known packets correctly. However, all-interface P4 features also include traffic unrelated to the target task. Family balancing alone will not remove that attribution problem. This pilot does not prove general malware ownership, successful attacks, classifier effectiveness or that background traffic caused the observed model change.

The next design gate is a reviewed common background-controlled baseline and broader socket/process attribution, including UDP and descendants, with matched null controls and strict residual accounting. No service suppression, production instrumentation change, new collection release or detector evaluation is authorized by this report. Keep any later split redesign explicit and exploratory for already consumed validation.

## Evidence

- [protocol.json](protocol.json), SHA-256 `d282755fbee696f9417b903d56dc818b70265dab41abea5c9b045413c73ffa1d`.
- [validation.json](validation.json), SHA-256 `d8d45ef084064f9b9a394ff73d539b0a73fe1bfa8666e3bcf1b8c9ccdecbbb06`, also pinned in [status.json](status.json).
- Driver SHA-256 `3b2b242a87ae4f1498eaee47eb9d67af5a771861db3fc625506224bb2ddf89b6`; C source SHA-256 `2b294343448f23cc918d0d04a86fd9005d67e90749147d62a884319f1a58883e`.
- Exact PIDs, run/PCAP paths, clocks, tuples, markers, residual flows, archive counts and P4 diagnostics are in the validation record. Source/binary/transport/order hashes and arguments were frozen before execution in the protocol.