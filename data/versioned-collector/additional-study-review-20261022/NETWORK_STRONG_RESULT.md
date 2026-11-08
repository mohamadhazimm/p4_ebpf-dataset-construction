# Network‑Strong Attacks: the P4/network half of the hybrid detector (thesis wrap‑up)

Written for: the thesis author (Hazim). Scope narrowed, per your direction, to the attacks where the network/P4 side
is the *strong* discriminator — volumetric DDoS floods and telnet scanning botnets. Date 2026‑10‑26.

## The claim, narrowed

For volumetric/flood network attacks, **payload‑free network flow features detect the attack essentially perfectly**,
and in the hybrid sandbox these floods are *also* host‑loud, so **network flow‑shape supplies a discrimination that
host syscall activity cannot** (precision / false‑alarm reduction). This is a scoped, honest contribution — not a
blanket "hybrid beats host," and not host‑evasion (a flood is host‑loud too).

## Feature contract (locked)

Host = the **ADFA‑LD‑validated syscall‑SEQUENCE descriptors** (`feature_columns.adfa-host.json`, 90 cols: total/unique
syscalls, entropy, avg/max run‑length, transition count, first50/100‑unique, rare‑syscall ratio, top‑syscall‑freq) —
**not** the raw `ebpf_*_count` launch counters (the earlier/deployed 175‑col set) and not the coarse ad‑hoc volume
counter. Network = the P4 flow features from `analyze_p4_pcap_ablation.py`. All host results below are stated in these
terms.

On the cleanest confound‑controlled general cohort (revision5, mode/activity‑matched, family/project‑held‑out), the
ADFA host contract already gives the general‑malware answer (`probe_adfa_heldout_revision5.py`): host‑90 held‑out
BA 0.93 / AUC 0.99 led by `rare_syscall_ratio`; hybrid 90+145 ≈ host (a wash, marginally lower AUC); P4 alone 0.75.
Conservative within‑training grouped‑OOF is host 0.63 / hybrid 0.72, so the robust range is ~0.63–0.72 and **the hybrid
does not beat host on general malware** — P4 has no held‑out headroom there. The network‑strong case below is the one
place P4 adds measurable value.

## Evidence 1 — network flow features detect all 7 DDoS attack types (CIC‑DDoS2019, 03‑11)

Offline sweep (`cic_sweep.py`), thesis payload‑free flow features only (packet/byte counters, lengths, IAT, duration,
bytes/s, packets/s, TCP flag counts — no IPs/ports/timestamps), RF‑200, seed 42, 70/30 split, balanced to the minority
class. Streamed from your zip (never extracted).

| DDoS type | balanced accuracy | test acc | benign / attack streamed |
| --- | ---: | ---: | --- |
| LDAP | 1.000 | 1.000 | 5,124 / 2,108,110 |
| MSSQL | 1.000 | 1.000 | 2,794 / 5,772,992 |
| NetBIOS | 1.000 | 1.000 | 1,321 / 3,454,578 |
| UDP | 1.000 | 1.000 | 3,134 / 3,779,072 |
| UDPLag | 1.000 | 1.000 | 4,068 / 721,097 |
| Syn | 0.9998 | 0.9998 | 35,790 / 4,284,751 |
| Portmap | 0.9982 | 0.9982 | 4,734 / 186,960 |

This is the network‑strong backbone: multiple real DDoS attack families, all cleanly separated by flow shape. Honest
caveat: this is in‑distribution (same‑capture benign) — an easy, well‑known separation that the thesis uses as the
feature‑selection/validation probe, not a held‑out generalization claim; and it is network‑only, so it cannot be merged
with the VM host+network cohort. Results: `cic-ddos-sweep/cic_sweep_results.json`.

## Evidence 2 — the hybrid precision point on a real sandbox flood (live)

Paired host+network capture (`precision-phase4/…`), a real Kaiten SYN flood vs benign high‑volume network workloads,
with true NIC counters, a flow capture, and a full per‑syscall‑id histogram per sample. The host side is scored under
the **locked ADFA contract**: distributional descriptors recomputed offline from each sample's histogram
(`scratchpad/adfa_precision.py` — entropy, unique/total syscalls, top‑syscall‑freq, rare‑ratio; the order‑dependent
run‑length/transition/first‑N descriptors need the raw ordered stream, which a flood overflows).

- The flood: **19.2 M host syscalls AND 4.18 M packets** — host‑loud *and* network‑loud. Flow shape: 100% SYN‑only,
  0 handshakes, unidirectional, 37,914 distinct destinations, port 23, 74‑byte uniform.
- Benign bulk (curl/openssl/wget/python to the Sink): **0.77–4.72 M host syscalls**, all established/bidirectional,
  handshook, 1 destination. `benign_bulk_post` (4.72 M syscalls) is *more host‑active than the non‑flooding malware*.
- **ADFA host sequence‑SHAPE does not separate the flood from benign bulk:** flood entropy 2.34 sits inside benign
  bulk's 1.17–3.97; flood top‑syscall‑freq 0.41 inside benign's 0.16–0.84 (the Kaiten connect‑scanner is a varied
  socket/connect/select/time/fcntl mix, not a low‑entropy loop). The only host descriptor that separates is raw
  `total_syscalls` (19.2 M vs ≤4.72 M) — a fragile ~4× margin a larger/longer benign job crosses; `rare_syscall_ratio`
  is ≈0 for everything at whole‑run scale.
- **Network flow‑shape separates categorically**: SYN‑only 1.0 vs 0.0, handshake‑completed false vs true,
  bidirectional false vs true, distinct‑dst 37,914 vs 1. This is a kind/qualitative boundary, not a fragile threshold.

Together: the network half detects the DDoS attack types (Evidence 1) and, when a process is network‑busy, tells a
malicious flood from benign bulk where the host half can't draw a robust boundary (Evidence 2) → the hybrid's genuine,
situational value is **precision** on network‑strong attacks. Honest caveat: the ADFA descriptors here are whole‑run,
system‑wide proxies for the contract's per‑window, lineage‑scoped `mean/max` features; the flood overflows the full
`.21` collector, so the true per‑window ADFA features on the flood itself remain unmeasured.

## What I sourced, and the honest limit on *live* flood collection

Per your ask I cast a wide non‑Triage net and retried Triage:
- **MalwareBazaar** (non‑Triage): 700+ new network‑strong ELF candidates; **sourced + quarantined 81** native‑usable
  (Tsunami 25 / Gafgyt 28 / Mirai 28).
- **Triage** (API recovered): decodes each bot's exact C2 IP:port; **sourced 15** native Gafgyt with exact endpoints.
- **MalShare**: reachable but near‑empty. **URLhaus/ThreatFox** (best fresh‑Mirai feed): need a separate free abuse.ch
  Auth‑Key — grab one for the PhD.

Measured, decisive limit: across **29 fresh bots and three trigger strategies** (generic multi‑port; Triage *exact* C2
IP:port; observe‑then‑trigger with the real observed ports) — **0 floods**. The bots are host‑active but emit no scan,
because fresh DDoS bots are *command‑driven*: a flood needs their exact C2 protocol emulated **and** the family‑specific
scan/attack command issued (per‑sample ENABLE password + master nick for IRC; a binary command for Gafgyt). The one
Kaiten floods only because its variant auto‑scans after registration **and** its C2 was fully reverse‑engineered. So a
live ~20–30‑flood / multi‑family cohort is genuine PhD work (per‑family C2 RE), not a wrap‑up step. The 96 quarantined
samples + the observe→trigger harness (`probe_net_strong_viability.py`) are ready PhD‑expansion material; the harness
already learns each bot's exact C2 endpoint, so adding per‑family command emulation is the remaining step.

## Bottom line for the thesis

Narrow to volumetric DDoS/flood attacks and present, with host = the ADFA sequence descriptors throughout: (1) on
general malware the ADFA host model carries detection and the hybrid adds nothing (revision5, held‑out BA 0.93,
robust ~0.63–0.72; P4 no headroom); (2) network flow features detect all 7 DDoS types at ~1.0 (CIC‑DDoS2019); (3) on a
real sandbox flood the ADFA host sequence‑shape overlaps benign bulk (entropy/top‑freq inside the benign range; only
fragile raw volume separates) while network flow‑shape separates categorically (SYN‑only, no handshake, 38k dsts) —
the hybrid's one genuine, situational win is **precision** on network‑strong attacks. State plainly that live
multi‑family flood collection is bounded by the need to emulate each botnet's C2 — the PhD‑expansion direction, and
that the true per‑window ADFA features on a flood are unmeasured because floods overflow the full collector. No model
was promoted and no dataset merged; the VM stayed isolated and was restored after every run.
