# Source Feasibility And Attribution Specification

Date: 2026-10-22. Status: **offline work complete; implementation/pilot not authorized or ready**.

This continues the [remediation plan](REMEDIATION_PLAN.md). The user approved the next offline source/task feasibility and instrumentation-design phase. No candidate workload, VM, new collector or model ran. No sources/packages were acquired or built. No existing source, capture, dataset, split, fitted model or consumed evaluation was changed. The current known-family target, global DDoSAgent/util-linux exclusions, primary balanced accuracy and 145/145/290 budgets remain unchanged. No pilot or collection is automatically launched by any artifact here.

## Measured Source Feasibility

Authoritative attempt: [summary](remediation-feasibility/20261022T121416376772Z/summary.json), [protocol](remediation-feasibility/20261022T121416376772Z/protocol.json), [build records](remediation-feasibility/20261022T121416376772Z/build_candidates.json), [source/task proposals](remediation-feasibility/20261022T121416376772Z/source_task_proposals.json).

The bounded assessment checked 321 original x64 build records and 13 matched-build records: 334 distinct hashes. Cached signatures on three Ubuntu InRelease files were reverified, source indexes checked against signed hashes/sizes, and every required descriptor/archive checked. Actual executable hashes, build provenance and ELF modes were checked without executing binaries. This reauthentication is offline against cached metadata/keyring, not a claim of newly acquired or current-security-certified software, upstream test-suite success or reproducible builds.

Historical exclusions use all seven recent source/order manifests, not just successful accepted rows: 491 planned hashes and 225 benign project/program units. Failed and rejected planned identities remain excluded. Known aliases such as nm-new/nm and ginstall/install are normalized. Coreutils is excluded from this diversity shortlist; util-linux stays globally excluded. Unsupported modes and the already-demonstrated nano/DEVNULL incompatibility are not waived.

The result is **22 unused build variants, 16 project/program units, zero new projects**. Nineteen variants are native amd64 static, three amd64 dynamic, and none of this shortlist is i386 static. This is not an exhaustive claim about all possible files elsewhere. Alternate libc/build variants are not counted as independent programs. The dynamic variants are git-shell, funzip and zipcloak; no substantive high-activity task was validated. Most remaining variants require terminal, input, dependency or safety review. A shortlist entry, including killall, is not permission to run it or target arbitrary processes.

This surplus cannot, by itself, establish independent project diversity or fill the missing activity ranges. No new activity was measured; no assertion of reaching 1,000/10,000 calls is made. Do not pad a task or select only favorable activity outcomes. The three missing benign cells remain amd64-dynamic 1,000-9,999 and >=10,000 calls, and i386-static >=10,000 calls.

## Source-Only Options

All eight options below have records in the checked signed indexes and are absent from the recent full plans. They are **not acquired source archives, built ELF identities, safe frozen argument manifests or untouched evaluation cases**. Historical exposure outside those recent plans is not certified absent. The machine-readable proposal retains all matched index versions/checksums rather than silently choosing a version. Architecture fields in source indexes do not prove a compatible native amd64 dynamic or i386 static build.

| Source Project | Proposed Program | Substantive Task And Outcome |
| --- | --- | --- |
| libarchive | bsdtar | Recover a deterministic multi-file archive and check every path/content hash. |
| perl | perl | Transform a fixed record corpus through the native ELF interpreter and compare exact output. |
| imagemagick | convert | Convert data-only images and check dimensions plus deterministic decoded pixels. |
| netcat-openbsd | nc | Receive a bounded marked stream from an isolated fixture under DEVNULL stdin; check target output and receipts. |
| openssh | sftp | Transfer a fixed data-only tree to an isolated authenticated fixture; check bytes and actual encrypted-session evidence. |
| lighttpd | lighttpd | Serve a bounded tree; verify exact response bodies and receipt logs. |
| nginx | nginx | Serve a bounded tree in foreground; verify worker identities and exact response bodies. |
| gnutls28 | certtool | Generate/parse disposable certificates with semantic checks; a later TLS task also needs dissector evidence. |

Recommended first source/build feasibility targets are libarchive, Perl and ImageMagick for distinct task domains, with netcat-openbsd for an explicit receiving-network task. This is a recommendation, not selected quotas or a release. Review dependencies, source licensing/build policy and exact signed versions before acquisition; prove actual ELF modes afterward. Static i386 dependencies and host/guest behavior remain open. Lighttpd/nginx similar server tasks must not be presented as automatically independent behavioral evidence. Fixtures may generate traffic only as a necessary part of the target task, not unrelated helper padding.

For any eventual known-family allocation, keep reviewed program/task/lineage units whole across roles, including shared-code groups from the earlier audit. New projects have no inherited role yet; freeze their prospective development/evaluation roles before outcomes. Do not reinterpret existing validation as blind or silently switch to unseen-family evaluation. Exact case/group quotas and precision requirements remain unagreed.

## Current Attribution Boundary

The unchanged [.18 dispatcher](../../../src/malware_runner.py#L2049) emits IPv4 connect destination/family, not a persistent socket identity or full bidirectional flow. Most other network entry records have no endpoints. A connect attempt is not connection success, and absence of connect does not exclude unconnected UDP, inherited sockets or target-induced daemon traffic.

The [parser](../../../src/malware_runner.py#L2398) consumes per-event ABI into internal state; the [CSV export](../../../src/malware_runner.py#L3230) omits that field. The new design must archive ABI explicitly. Declared root mode is insufficient for arbitrary mixed-ABI descendants. None of these changes is implemented here. Previously captured missing ABI/socket information cannot be reconstructed by this specification.

## Proposed Sidecar Contract

Use a separately versioned diagnostic sidecar, provisionally named `attribution-design-v1` in the synthetic oracle, not a production runner schema. A concrete backend must pass capability/build tests before it is selected. A libbpf CO-RE design with socket-operation/lifetime and packet observation hooks is a candidate, not verified support on the guest. BTF layouts, program types, helper availability, compat socketcall decoding, privileges and resource/loss behavior remain untested. Do not infer a packet's owner from the current PID in a packet/softirq hook.

| Evidence | Required Fields And Rules |
| --- | --- |
| Session | Run/capture ID, boot ID, kernel/BTF, tool/source hashes, schema, interface/index and network-namespace identity. |
| Process | TGID/TID, namespace identity, process start/lifetime, exact observed exec/image hash, parent/thread-exec changes, target-root/descendant decision and ABI on each relevant event. PID/COMM alone is insufficient. |
| Socket | Nonzero stable cookie or independently validated equivalent lifetime identity; namespace, open/close/generation, protocol/family, complete local/remote endpoints and source hook. Missing/overlapping lifetimes remain unknown/ambiguous. |
| Ownership | Time-qualified process/socket associations including fork/clone, dup/close, accepted sockets, inherited/pre-existing sockets, descriptor transfer and shared owners. Cgroup membership alone is not unique ownership. |
| Operation | Entry/exit correlation, return/errno and actual byte count; connect completion/state, bind/listen/accept, TCP read/write/send/recv and UDP sendto/recvfrom/sendmsg/recvmsg/sendmmsg/recvmmsg as applicable. Unsupported paths, including asynchronous or zero-copy variants, stay explicit. |
| UDP peer | Destination/source per datagram operation for unconnected sockets; no wildcard-bound-port attribution. Connected UDP peers may change. Keep half-open peer-validity intervals and invalidate stale peers. |
| Packet | Full tuple, direction, interface/netns, monotonic capture relation, frame ordinal/content hash and a verified link between the frame and socket identity. Cookie zero, ambiguous identical frames, fragmentation, tunneling, GSO/GRO or hook/PCAP byte differences stay unresolved unless separately tested. |
| Clocks | Realtime/monotonic calibration bracketed before/after capture, measured uncertainty and discontinuity handling. A join must not bridge ambiguous boundaries merely by widening a tolerance. |
| Loss | Separate sequence gaps, late events, map/queue pressure, perf/ring losses, PCAP counters and interface state. Zero warnings do not prove never-recorded completeness. Missing required counters blocks the relevant gate. |

Prefer a capture path that co-records packet/socket metadata. A full tuple/time match alone is only a candidate association, especially with UDP port reuse. The backend must demonstrate the frame link; the synthetic `frame_link_verified` field is a precondition, not proof generated by setting a boolean. Scope this evidence honestly when the backend cannot expose a cookie or observe the complete descriptor history.

The [synthetic oracle](attribution_contract.py) accepts only supplied verified frame/socket/lifetime evidence. Its outputs are `lineage_socket_associated`, `non_lineage_socket_associated`, `shared_socket`, `ambiguous_socket_lifetime` or `unknown`. Socket association is not proof of application receipt, payload causation or malicious behavior. A non-lineage daemon may be responding to the target: do not rename it ambient. Shared ownership is not forced to a class. Residual ARP/ICMP/fragments and unmatched IP traffic remain accounted for, not deleted. Exact kernel/process identity validation is a backend prerequisite, not implemented by the oracle.

Keep interface-wide P4 extraction unchanged as the primary contract: recorded windows, Ethernet bytes, nominal rates, TTL3 and all existing quality/alignment/parity gates. Attribution is a parallel diagnostic. Any attributed-only P4 representation is a separate experimental contract requiring explicit review; do not report it as a repair to the historical interface-wide model. New hooks/export/load require new runner/schema hashes and compatibility/overhead analysis even if the legacy 169 feature values appear unchanged on a bounded control.

## Benign Pilot Acceptance Matrix

This is an unexecuted matrix, not a frozen executable list, order or launch authorization. Use the three existing native strata only: amd64 static/dynamic and i386 static. Reuse existing ABI evidence; add mixed-ABI descendants only to cover the newly exported events. Freeze exact control/fixture/server identities and bounded repeats before execution; repeats are diagnostic, not independent software projects.

| Scenario | Required Discrimination |
| --- | --- |
| Null and file-only | Exact target/output; no designated target network operation/marker. Inventory all residual traffic; do not require the whole interface to be silent. |
| TCP client and accepted server socket | Full endpoints, connect result/state, process/socket/packet link and correct application body at the intended endpoint. |
| Unconnected and connected UDP | Unique marked datagrams recovered at the actual receiving application and an explicit receipt/echo. Sending/capturing UDP or ICMP port-unreachable alone fails the delivery claim. |
| Threads, descendants and ABI change | Leader exit, non-leader exec and native/compat transitions retain correct process identity, event ABI and socket association. |
| Descriptor sharing/transfer | Inherited/dup/shared sockets and transfers preserve ownership intervals; ambiguous or shared results are not coerced into target-only ownership. |
| Reuse/negative joins | Wrong port, namespace/run/boot mismatch, stale cookie/peer, PID reuse, missing frame link and overlapping lifetime records reject attribution. |
| Bounded rate/overhead | Known message/event counts at predeclared bounded rates; report CPU/memory/latency and all losses. These synthetic stress controls are not extra benign training samples. |

Keep distinct outcomes for retrieval, exact target exec, sensor quality, packet mapping, known-flow recovery, application receipt and scope coverage. Require strict finite 40x169 telemetry, safe archive/member hashes, independent PCAP received/captured counts, restored buffers, link readiness and unresolved-ABI checks. Mandatory known-control mappings/receipts must pass their declared checks; every residual/unknown count must be reported. A bounded pass cannot certify arbitrary workload completeness or general malware ownership.

Use a common isolated child and unchanged background service policy for all controls; inventory services without suppression. Restrict fixtures to loopback/internal numeric destinations. Freeze hashes, arguments, order, failure rules and cleanup before execution. Preserve each failed attempt; no silent retry/replacement or relaxed loss gate. Current phase makes no fresh VM-state claim. A later authorized driver must take the common lock, recheck isolation/process/hash evidence and restore the original clean powered-off baseline.

## Verification And Release Decision

[Verification](remediation-feasibility/20261022T121416376772Z/verification.json) checked 544 input hashes. [Independent verification](remediation-feasibility/20261022T121416376772Z/independent_verification.json) rehashed them, independently parsed all 334 ELF headers with the standard library, reconstructed all shortlist decisions from original plans and rechecked unchanged runner/batch/stager pins. Editor diagnostics are clean. Nineteen synthetic ownership cases plus invalid-endpoint rejection pass; they are design tests, not live evidence.

The first assessment stopped before output creation because net-tools/sqlite3 source locations came from the matched i386 authentication record rather than the x64 source directory. The checker now verifies that record's pinned hash and passes its explicit directories to the existing signature auditor. A cross-tree path regression passes. No source authentication was bypassed and no original audit/helper was edited.

Reproduce from the study root:

```bash
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/assess_remediation_feasibility.py --self-test
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/assess_remediation_feasibility.py --verify data/versioned-collector/additional-study-review-20261022/remediation-feasibility/20261022T121416376772Z
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/attribution_contract.py --self-test
```

`collection_ready=false`. The next authorization decision is exact benign source acquisition/build preparation and a scoped new-schema attribution implementation, followed by separately frozen benign-only validation. No malware/full collection, model fit, new allocation, prospective evaluation release or historical-data replacement is authorized by this specification. All eight earlier release gates remain unpassed; a completed specification is not empirical remediation.