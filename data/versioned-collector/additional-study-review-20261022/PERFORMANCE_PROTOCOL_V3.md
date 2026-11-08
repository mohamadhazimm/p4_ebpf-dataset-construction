# Performance Completion Repair V3

Date: 2026-10-23. Status: local repair and simulated regression only.

The user requested resolving the outstanding gates, then explicitly selected
**Keep original strict gate; no new attempt** when offered a benchmark-only
quiet-capture amendment. That decision controls: no amendment, new VM attempt,
malware/full collection, fitting, historical resume or merge is authorized.
The measured [V2 procedure](PERFORMANCE_PROTOCOL_V2.md), source and evidence
remain immutable. Its case007 rejection remains a rejection.

## Narrow Correction

[performance_v3.py](performance_v3.py) derives schema
`2026-10-23.26-performance-completion-harness` from hash-verified measured V2.
It exports the original `summarize` function required by the actual inherited
guest driver. Generated imports and broker routing target the new module;
all original feature/helper ASTs, lifecycle behavior and quality gates remain.

[check_performance_v3.py](check_performance_v3.py) provides a separate guest
binding and a local regression entry point. It deliberately exposes no host
execution or freeze-only CLI. The derived payload includes both new and
inherited adapter dependencies; no launch is queued.

## Local Verification

Run from the study root:

```bash
/usr/bin/python3 data/versioned-collector/additional-study-review-20261022/check_performance_v3.py --self-test
```

The regression executes the actual guest driver's complete84-position loop,
report and evidence-archive publication, with simulated subprocesses and
per-case measurements. It compares all four final ABI/task groups with the
independent saved-audit summarizer. Removing the export reproduces the actual
completion AttributeError after84 simulated positions. Injected quiet-quality
and runner failures stop at position8; a1.26 wall pair stops at position9;
median-wall, CPU and recorder-RSS violations reject at completion. Tests verify
unchanged commands, temporary credential permissions/deletion, archived report
equality, omission of credentials and no promotion to collection readiness.

Inherited actual local pidfd/wait4 accounting, helper-AST,84-case argv/parser,
startup, immediate FINISH/shrinking ACK, lifecycle failure/cleanup and independent
incomplete-design/corruption tests are also run. These are local checks, NOT
guest measurements or accepted overhead evidence.

## Unchanged Blocker

The original rule rejects zero captured packets with zero interface RX/TX
traffic even for the file and loopback-only tasks. Link up/carrier1, a correct
file result and zero reported drops do not establish capture liveness. No
unrelated traffic, task extension, service change, wait-for-traffic scheme,
clock-boundary movement or quality waiver is introduced.

Original16MiB/64-echo tasks,84-case order/two warmups/five repetitions,
20s observation,22s recorder request,12s ACK and the pre-Bash-Popen-to-pidfd-exit
wall INCLUDING observer setup remain unchanged. Approved limits remain
wall median<=1.10, every pair<=1.25, CPU median<=1.15, recorder RSS<=256MiB,
zero observed loss/errors/gaps. All417 assignments remain unchanged.

`performance_accepted=false`, `collection_ready=false`. A future attempt would
still require explicit authorization and an audited path through the unchanged
quality rule; local completion repair cannot supply that evidence. Final common
payload/helper/task/fixture/null/order and scoped fail-closed release checks
remain pending. This repair makes no new VM/Sink-state assertion.