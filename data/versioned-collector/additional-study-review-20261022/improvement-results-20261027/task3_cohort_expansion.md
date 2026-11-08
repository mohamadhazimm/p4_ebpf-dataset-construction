# Task 3 — Cohort expansion: candidate inventory (offline, no VM)

Classified 566 unique quarantined samples across all incoming pools by
in-memory ELF header (no execution). Raw: `cohort_expansion_candidate.json`,
`cohort_expansion_classified.json`.

## Mode breakdown (566 unique)
- native_static 288, native_dynamic 51 → **339 native-usable**
- static-PIE (unsupported) 20, not-ELF 11
- emulated (qemu-user, other ISA): ARM 79, MIPS 61, m68k 13, SH 12, AArch64 7,
  SPARC/PPC/misc ~24 → ~180 out of scope

## Honest read of "new" material
The classifier flagged 339 native-usable samples not already collected, but
most are NOT new families:
- `gafgyt` 68, `mirai` 68, `tsunami` 10 are **case-variant labels of existing
  cohort families** (Gafgyt/Mirai/Tsunami). These are ~200+ MORE samples of
  families already in the cohort → they tighten per-family confidence
  intervals but add **no family diversity**.
- Genuinely new families are the thin C2/evasive set: `c2?` 18 (Sliver,
  CobaltStrike, Meterpreter, Winnti, Merlin) + `evasive?` 20 (Rekoobe, BPFDoor)
  ≈ 7 new families. Caveats from prior probes: near-duplicate within family
  (Rekoobe ~3–4 distinct builds; Meterpreter i386 near-identical), mostly
  amd64-dynamic (the degenerate/training-only mode in the current design), and
  behaviorally host-active but network-quiet — so they do NOT create hybrid
  headroom, only more never-seen families for the host held-out test.

## Realistic expansion value
- Add the ~7 new C2/evasive families to the held-out validation → raises
  never-seen families from 11 to ~16–18, which tightens the robust
  leave-one-family-out estimate (currently 0.63–0.72) and makes the host number
  far more credible. This is the real win.
- Deepening Mirai/Gafgyt/Tsunami tightens their CIs but won't move the headline.
- It will NOT make hybrid beat host on general malware (new families are
  host-active/net-quiet, consistent with the latent-complementarity finding).

## Gate
A benign match for the new modes (esp. amd64-dynamic) must be built, then VM
collection runs through preflight→stage→dry-run→collect, each needing explicit
approval. Nothing here executes a sample. `collection_ready=false`.
