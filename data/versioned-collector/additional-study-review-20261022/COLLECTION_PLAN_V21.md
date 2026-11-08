# Collection plan: `.21` collector on the headless quiet snapshot (draft for decision)

Status: **decisions made, nothing frozen or launched yet.** Prepared 2026-10-24 after the user chose "do 1 then 3".
Every VM phase below still needs an explicit approval.

**User decisions (2026-10-24, all recommended options):** D1 `150 + 150 (Recommended)`; D2 `About a third (Recommended)`; D3 `Collect first, then decide (Recommended)`; D4 `Family-held-out (Recommended)`.

**Feasibility amendment (user decision `Several tasks per program (Recommended)`):** only about 13-15 network-capable benign programs exist (all amd64), so D2 is met by building i386 versions of curl/wget/inetutils/openssl and giving each network program 3-4 different Sink tasks (HTTP, HTTPS, FTP, DNS lookup, ping, ...), for about 45-50 network-active benign cases. **All tasks of one program stay on the same side of the split**, and independence claims count programs, not tasks.

## What is ready

- **Collector**: `src/malware_runner.py` schema `2026-10-24.21` (SHA `4933ff5c…`). On the `.20` battery it counted
  every syscall and packet exactly in the regular tests, completed a 250,000-packet flood in 34 s, and flagged every
  overload. The `.21` VM check (microsecond window fix) is running at the time of writing.
- **Environment**: headless quiet child `clean-final-quiet-v19-20261024T150104720304Z` (UUID `7d211f0d…`):
  apt, update timers and snapd masked, no desktop. 10 of 10 traced boots were clean, and all 14 strict benign/null
  cases passed.
- **Throughput**: about **48 s per case** (15 cases in 12 min), so 300 cases take about 4 h.

## Design (recommended defaults)

1. **A new dataset.** Captures from this environment are never merged with `.20`/`.19`/`.18` or with desktop captures.
2. **Modes**: native amd64 dynamic, amd64 static and i386 static, each with both labels and its own null
   controls, so no mode belongs to one label only.
3. **Malware**: drawn from the whole recovered pool (535 originals, the 323-sample cohort and catalog extras).
   Strict native modes only, distinct member hashes, at most 10 per family per mode, round-robin across families.
   Selection does not depend on earlier runtime outcomes.
4. **Benign**: one distinct authenticated program per case, matched to the malware's mode, each with a checked
   outcome. **About a third are network-active against the Sink** (curl/wget over HTTP and HTTPS, ftp, ping and
   traceroute to 10.0.0.1, telnet to INetSim echo, and name lookups through the Sink's DNS). This removes the
   "any traffic means malware" shortcut seen in earlier cohorts. The amd64 builds exist already. i386
   network-capable builds still have to be made from the same authenticated sources.
5. **Nulls**: a pair per mode at the start, middle and end.
6. **Order and checkpoints**: seed-fixed interleaving of label and mode, run in batches of about 50 cases. After
   each batch, the nulls are audited and the run stops if the environment is no longer quiet.
7. **Per-case acceptance** (unchanged rules, nothing relaxed):
   - quality gate (zero loss, PCAP equal to counters), exact target exec, 40×169 finite features;
   - capture probes outside the windows, exact grid bounds, unique window attribution, IPv4 readiness;
   - benign and null cases: quiet-v3.5 default-deny traffic classification;
   - malware traffic is attributed to the sample and recorded, not rejected.
8. **No retries or replacements.** The only exception is the batch's existing one-time VM restart for a boot hang,
   which is recorded. Exclusions are reported by family, mode and label, so selection bias stays visible.

## Splits (decision D4)

- **Family-held-out (recommended)**: whole malware families and whole benign projects reserved for validation, as
  in the earlier native designs. Many identities were examined in older environments, so this is a
  *new-environment, family-held-out* test, not a blind one.
- **Never-used identities**: 235 never-planned native samples exist, but they cover only XorDDoS (198), Mirai (35)
  and FlyLegitBot (2). That is too narrow for a primary test, but usable as a secondary check.

## Known limits that remain

- Syscall bursts above about 1M events lose events and are **rejected**: the heaviest samples are under-represented.
  Fixing this needs in-kernel counting (decision D3).
- About 1% of boots hang. The batch restarts the VM once. The cause is unknown.
- The P4 features are an offline reconstruction from the PCAP, not live switch measurements.

## Decisions needed

| | Question | Recommended |
|---|---|---|
| D1 | Size | 150 malware + 150 benign + 9 nulls (about 4 h of VM time) |
| D2 | Network-active benign share | About a third, all against the internal Sink |
| D3 | Burst-loss fix | Collect now; report rejections; decide on in-kernel counting from the measured rejection rate |
| D4 | Split | Family-held-out; never-used identities as a secondary check |

## Next steps after the decisions

1. Local only: build the selection and workloads (plus the i386 network builds) and a `collect_v21.py` driver.
   It reuses the frozen `.19` driver's phase machinery, `.21` pins and the quiet-v3.5 validator. Freeze the plan.
2. VM, each step approved: read-only preflight, stage, dry-run, then batches with checkpoints.
3. Saved-only audit: acceptance and exclusion report. No model fitting or merging without a separate decision.

---

## Measured feasibility (2026-10-24, aggregate counts only — no per-sample records)

Malware pool = recovered 535 originals ∪ the 323-sample cohort, strict native modes only, DDoSAgent globally
excluded, matched45's 45 identities not reused. Counts are available samples per mode / distinct family groups:

| Mode | Available malware | Distinct families | Note |
|---|---:|---:|---|
| native amd64 **dynamic** | **~13–18** | ~8 | **scarce; most families are singletons** (Mirai, CoinMiner, DDoSAgent, LockBit, Bert, Akira, CatStorm, INC) |
| native amd64 static | 150+ | 15+ | plenty (Mirai-heavy; also Qilin, Akira, Gafgyt, BrickStorm, Prometei, DeskRAT, …) |
| native i386 static | 280+ | ~12 | plenty but XorDDoS-dominated; cap-10 de-skews it |

Benign programs available per mode (distinct, authenticated, already built):
- amd64 **dynamic**: ~12 (coreutils dynamic + curl/wget/openssl/git/rsync/tar/zip/xz/jq/less/zstd). Network: curl, wget, openssl.
- amd64 static: 80+ (matched45 19 + redesign 63). No network (static amd64 net tools hit the guest-NSS crash).
- i386 static: 60+ (matched45 21 + i386-holdout ~30 + **10 new musl network tools**: curl, wget, openssl, ftp, logger, ping, telnet, tftp, traceroute, whois — all ELF32 i386 static, verified).

### Consequence for the mode mix
A perfectly even 50/50/50 split is **not possible**: amd64-dynamic malware tops out at ~13–18. Keeping the approved
rule "each mode carries both labels, no mode belongs to one label only", the recommended mix for 150 malware + 150 benign is:

| Mode | Malware | Benign | Network-active benign |
|---|---:|---:|---|
| amd64 dynamic | 12 | 12 | 3 programs (curl/wget/openssl), 3–4 Sink tasks each |
| amd64 static | 69 | 69 | 0 (static amd64 net tools unusable) |
| i386 static | 69 | 69 | ~10 programs (the musl tools), 3–4 Sink tasks each |
| **Total** | **150** | **150** | ~45–50 network-active benign **cases** |

- Malware selection: ≤10 per family per mode, round-robin across families, outcome-independent. Family-held-out
  split (~70/30) reserves whole families for validation in each mode. amd64-dynamic's singleton families make a
  clean held-out split there weak; its 12 cases are best treated as **training-only** (as the earlier native-x64
  design treated amd64-static), with the family-held-out validation drawn from amd64-static and i386-static.
- Network-active benign share (~a third) is met by giving each network program several distinct Sink tasks; all
  tasks of one program stay on the same split side, and independence is counted by program, not task.

**This mode mix is the one new decision the measurement forced** (the approved plan did not fix per-mode counts).
It is recorded here for the freeze-approval gate; nothing is built or launched yet.

**Decision (2026-10-24): mode mix = 12 / 69 / 69, amd64-dynamic training-only.** User chose this; validation is family-held-out from amd64-static and i386-static only.

**Decision (2026-10-24): family cap kept at <=10/family/mode.** The pool gives ~97 diverse malware
(11 dyn / 55 amd64-static / 31 i386-static, 34% Mirai+XorDDoS) rather than a 150 that would be ~53%
two mega-families. Collection is ~97 malware + ~97 mode-matched benign + 9 nulls. N is below the
original D1=150 by the user's choice, in favour of diversity and a stronger family-held-out split.

## Frozen selection composition (2026-10-24, local artifacts written)

- **Malware** `v21-collection-selection/<ts>/malware_selection.json`: 97 cases (11 amd64-dyn / 55 amd64-static /
  31 i386-static), split 71 training / 26 validation (family-held-out; dyn training-only). <=10/family/mode,
  round-robin, outcome-independent, DDoSAgent + matched45's 45 identities excluded. 87 transports are AES-zip-ready,
  10 i386 raw-ELF sources need wrapping at packaging time.
- **Benign** `v21-collection-selection/benign-<ts>/benign_plan.json`: 97 cases (11 / 55 / 31), 27 network-active
  (28%, Sink only), split 69 training / 28 validation (benign-project-held-out, validation projects disjoint from
  training). Non-network programs reuse validated matched45/redesign/i386-holdout workloads; the 19 i386 musl
  network tasks are new and get validated in the benign-only preflight.
- **Nulls**: 9 (3 per mode, start/middle/end).
- **Total**: 97 + 97 + 9 = 203 cases (~2.7 h VM).

### Remaining local build (before any VM phase)
1. Package 97 malware transports (87 reuse AES zips; wrap 10 i386 raw-ELF into AES zips) + 97 benign transports
   (reuse the three suites' binaries/fixtures/arguments; stage the 10 i386 musl network binaries) + arguments.
2. Write `collect_v21.py` reusing `collect_v19.py`'s phase machinery, re-pinned to `.21`
   (runner `4933ff5c…`, schema `2026-10-24.21`), the headless quiet snapshot
   `clean-final-quiet-v19-20261024T150104720304Z`, and the quiet-v3.5 default-deny validator.
3. Freeze the protocol, then the VM phases (each approved): benign-only preflight (validates the new i386 network
   tasks + full staging) → stage → dry-run → batches with null checkpoints.

## Benign bound to concrete validated transports (2026-10-24)

`bind_v21_benign.py` -> `v21-collection-selection/benign-binding-<ts>/benign_binding.json`: 97 benign
(11 amd64-dyn / 55 amd64-static / 31 i386-static), split 68 train / 29 val across 27 projects (single global
project-held-out, 13 validation projects). Sources: 66 from redesign-native-x64 (guest-validated amd64 transports),
8 from the i386-held-out amendment (guest-validated i386), and 23 **candidate** static-musl i386 Sink tasks
(curl/wget/openssl/ping/traceroute/telnet/ftp/tftp/whois/logger to 10.0.0.1) validated at the benign-only preflight.
Network-active: 25 cases (26%) = 2 amd64-dyn (curl/wget HTTP) + 23 i386 musl.

### Scientific gap found: amd64-static benign has no Sink-network task
Redesign's amd64-static "network" programs (ping/ftp/whois/traceroute/telnet) used **loopback fixture services**
(ports 65014/65015), not enp0s3, so they produce no captured traffic; its curl/wget are dynamic-linked. So in the
largest mode (55 malware + 55 benign) malware can be network-active while benign is not, partially recreating the
"any traffic = malware" shortcut this collection exists to break. `musl:amd64` is available as a binary package, so
amd64-static curl/wget/openssl Sink clients can be built natively (cheaper than the i386 cross-build) to close it.
This is a decision for the plan-review gate.

## Driver written, self-tested, and plan FROZEN (2026-10-24)

`collect_v21.py` (approval-gated phase driver; reuses collect_v19 helpers + the quiet-v3.5 frame primitives; adds a v21
traffic gate = default-deny for null/non-network benign, guest<->Sink allowed+required for network benign, malware
traffic recorded-not-rejected) passes `--self-test` (pins/corruption guards, the v21 traffic gate, deterministic
203-case payload + malware member hashes + no stale fixture prefixes + setup syntax, saved-.19 rejected on .21
provenance, SIMULATED approval gate + read-only preflight). Editor diagnostics clean.

**Frozen attempt:** `v21-collection/20261024T175120095850Z/`, protocol SHA `8d7267bbbc2cda0fed5650ff92a0fa5d71fc53cf4dfe9b9e4f7b6dca952f4503`.
203 cases (97 malware / 97 benign / 9 null), mode-matched 11/55/31 for both labels, 34 network-active benign, payload
189 MB. Pins installed `.21` runner `4933ff5c...`, batch `4490a4ce...`, stager `5fce8723...`; baseline = headless quiet
child `clean-final-quiet-v19-20261024T150104720304Z`. `verify_plan` re-passes. `collection_ready=false`, nothing launched.

**Phases (each needs explicit approval):** preflight (read-only) -> preflight-benign (stage a benign+null child, run the
97 benign + 9 null only, confirm which musl Sink tasks produce enp0s3 traffic, drop non-answering ones; NO malware) ->
stage -> dry-run -> collect. The benign-only preflight is the first substantive VM step and runs no malware.
