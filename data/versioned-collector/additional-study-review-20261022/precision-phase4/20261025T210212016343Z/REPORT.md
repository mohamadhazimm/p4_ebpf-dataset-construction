# Precision Experiment (Phase 4): network flow-shape separates a malicious flood from benign bulk where host syscall activity cannot

Written for: the thesis author (Hazim), as a results write-up for the hybrid P4+eBPF detector thesis.

Date: 2026-10-25 (produced autonomously overnight). Attempt: `precision-phase4/20261025T210212016343Z/`.
Protocol SHA-256 `96ed05f86807b24493592e43898cf3f1d7a5522ff48bb83c6aad3bb53875cf2c`.

## What this tests, and the honest framing

The earlier cohorts showed the hybrid detector does **not** beat host-only on general malware, because (a) most sandboxed
malware produces little/no in-window network, and (b) the one genuinely host-evasive class (Meterpreter reverse shells) is
narrow. This experiment asks a **different, narrower** question that the thesis can actually support:

> When a process is network-busy, can the host (eBPF syscall) side tell a **malicious flood** apart from **benign
> high-volume network traffic**? If not, does the **network (P4/flow) side** supply that distinction?

A userland flood is a `sendto()`/`connect()` storm, so it is **host-loud as well as network-loud** — this is **not**
host-evasion. The honest contribution here is **PRECISION / false-alarm reduction**: a host-activity signal that fires on
"busy process" will fire on benign bulk transfers too (false positives); the network flow-shape separates malicious-flood
from benign-bulk cleanly, so adding P4/network features reduces those false alarms.

## Method (all on the sealed, isolated lab)

Bespoke harness `probe_precision_phase4.py`: each sample runs 20 s in its own restored-baseline VM boot, with three
overflow-robust, paired measurements — an **in-kernel bpftrace syscall counter** (count() maps, no perf ring, so a flood
cannot overflow it the way the production `.21` collector does), the **true NIC rx/tx counters** (/sys), and a **tcpdump
flow capture** (snaplen 96, first 300k frames) for offline flow-shape. Safety: guest intnet-only on the sealed `malnet`
(scan SYNs die at the gateway, never leave the host); the Kaiten C2 channel is an in-guest `lo` alias with a
registration-only controller that sends **no attack command** (the bot's own autonomous telnet scanner is the flood);
the VM is restored to `clean-tls-paired-2026-10-19` and powered off after every sample (verified only-Sink-running).

Samples captured (9 of 11; `mirai_heavy` hit a boot-login race, `null` dropped its empty-argv — neither is needed for the
result): 1 malicious flood (Kaiten SYN scanner via C2), 2 host-storm malware (Gafgyt/Mirai, run without C2), 6 benign
bulk/high-rate network workloads to the Sink (curl POST/GET loops, curl high-rate, openssl bulk, wget loop, python stream).
The 4 Phase-3 Kaiten flood PCAPs are folded in as extra flood exemplars.

## Result 1 — HOST activity does NOT carry a malicious/benign boundary

Per-sample host syscalls over 20 s:

| class | sample | host syscalls | tx packets |
| --- | --- | ---: | ---: |
| malicious flood | gafgyt_kaiten_flood | **19,240,923** | 4,179,005 |
| malicious host-storm | mirai_a | 834,275 | 22 |
| malicious host-storm | gafgyt_a | 828,713 | 10 |
| benign bulk | benign_bulk_post | **4,720,270** | 1,777 |
| benign high-rate | benign_highrate | 1,497,924 | 10,288 |
| benign bulk | benign_bulk_get | 1,454,435 | 10,029 |
| benign | benign_wget_loop | 1,223,085 | 11,593 |
| benign | benign_py_stream | 776,185 | 23,102 |
| benign | benign_tls_bulk | 774,482 | 3,581 |
| (corroborating) mirai_heavy (validation run) | | 49,700,102 | 6 |

The benign network workloads span **0.77M–4.72M syscalls**, which **overlaps and exceeds** the host-storm malware
(0.83M). `benign_bulk_post` (4.72M) is **more host-active than either host-storm malware**. Every other host feature shows
the same overlap — `send_family_frac` benign 0.017–0.106 vs storm 0.10; `syscall_id_entropy` benign 1.17–3.97 vs
flood 2.34 / storm 2.95; `top_syscall_frac` benign 0.16–0.84 spans flood 0.41 and storm 0.31. There is **no host-activity
threshold or shape** that puts the malicious samples on one side and benign on the other.

## Result 2 — NETWORK flow-shape separates them completely

| network feature | malicious flood | benign (n=6) |
| --- | ---: | ---: |
| frac SYN-only | **1.0** | 0.0016 – 0.084 |
| handshake completed | **0 / 1** | **6 / 6** |
| bidirectional (replies seen) | **0 / 1** | **6 / 6** |
| distinct destination IPs | **37,914** | 1 |
| packets per destination | **7.9** | 638 – 19,873 |
| frac tiny (<=74 B) | 1.0 | 0.57 – 0.75 |

The flood is SYN-only, never completes a handshake, is unidirectional, sprays ~38k destinations at ~8 packets each. Benign
bulk always completes handshakes, is bidirectional, targets one host, and carries hundreds-to-thousands of packets per
destination. **Zero overlap** on handshake-completion, bidirectionality, destination count, and packets-per-destination.
All 4 Phase-3 flood PCAPs corroborate: SYN-only 1.0, no handshake, unidirectional, 11k–70k distinct dsts, ~6–36 pkts/dst.

Illustrative leave-one-out separability (n=9, 3 malicious vs 6 benign; tiny N, descriptive only):
**network-only BA 1.0** (0 errors); **host-only BA 0.67** — it both misclassifies the flood and false-alarms on benign
bulk (`benign_bulk_post`, `benign_tls_bulk`); hybrid BA 0.92 (one benign false positive, inherited from the host side).

## Honest reading / what this does and does not show

- **Supported:** a host-based (syscall-activity) detector cannot distinguish a malicious flood from benign high-volume
  network traffic without false alarms — benign bulk is as host-active as, or more than, host-active malware. Network
  flow-shape (handshake completion, directionality, destination fan-out, packets-per-destination, SYN-only fraction)
  separates them cleanly. So the P4/network half contributes **precision** (false-alarm reduction) on exactly the
  "busy network process" confusion case. This aligns with the confirmed CIC-DDoS result (network flow features detect
  varied DDoS ~1.0), which is the network-feature generalization backbone.
- **NOT shown:** general hybrid>host superiority; host-evasion (the flood is host-loud); detector generalization. N is
  tiny (1 flood + 2 host-storm + 6 benign); the flood is one bot family (Kaiten) — flood diversity rests on CIC, not this
  capture; the benign workloads are client-to-Sink loops, not representative of all benign network use; the Sink is a fake
  controller. The LOO BA numbers are illustrative, not statistically powerful — the descriptive feature overlap (host) and
  total separation (network) are the real evidence.
- **Complementarity, stated plainly:** host features catch host-active malware (including the 2 host-storm bots, which are
  network-silent); network features catch network-floods and refuse to flag benign bulk. The hybrid's value is
  **situational** (precision on network-busy processes; host-evasive reverse shells from the earlier C2 probe), not a
  blanket accuracy gain.

Machine-readable results: `run/precision_analysis.json`. Per-sample captures: `run/*.result.json`, `run/*.pcap`.
No model was promoted and no dataset was merged; this is a scoped precision demonstration.
