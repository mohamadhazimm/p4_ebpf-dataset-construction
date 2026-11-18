# Mitigation: time to containment, estimated offline (committee item 6)

Offline estimate from the 240 recorded executions of the release dataset (2026-11-15). No VM was operated, no
sample was executed, no existing file was changed. The switch rule itself is measured later on the hardware; this
folder estimates, from the recorded runs, how soon each run would be contained and how much of its traffic a drop
rule would have stopped. Files: `mitigation.py` (the whole analysis), `results.json`, `mitigation.log`, this README.

**Bottom line** (stacked hybrid, threshold 0.5, rule install L = 10 ms):

* **Time to containment.** 74% of malicious runs are flagged in the first 0.5-s window (95% of all detections), so
  the median time to containment of a flagged run is 0.86 s (0.5 s window + 0.35 s read + 10 ms install), for every
  attack type and for the malware, with all four detectors at threshold 0.5; 98% of
  the attack runs and 94% of the malware runs that send traffic are contained within 1 s.
* **The floods are faster than the pipeline.** The eight SYN and UDP floods send 15-100% of their packets before
  0.86 s,
  the earliest moment any rule of this pipeline can act. A drop rule stops 44% of an attack run's packets on average
  (53% of all attack packets pooled), which matches the ceiling of a detector that flags every attack in the first
  window (44%): the limit is the 0.5-s window plus the read budget, not the detector. It ranges from 0% (`syn_fan_40k`,
  all sent in 0.73 s) to 85% (`syn_fan_150k`, 6 s); Slowloris 50%, GoldenEye 36%.
* **Malware traffic is mostly stopped.** All 52 malware runs that send traffic are flagged, and 88% of their packets
  come after the rule (they send a little at a time over the 20 s). Of all 99 malware runs 75% are flagged within 20 s.
* **Install time hardly matters.** From L = 1 ms to 100 ms the stopped share of the attacks falls from 44% to 42%.
* **Cost: benign runs blocked.** At threshold 0.5, 20% of benign runs would be blocked (CLI programs 17%,
  network-active programs 24%, null runs 90%), 80% of the blocks at 0.86 s; the rule would cut 26% of the network-active
  programs' bytes (concatenated and network-only: 85%, they block the bulk uploads). At 0.8: 5% blocked, attacks
  contained 94%, 40% of their packets stopped; at 0.9: 1% blocked, 82% contained, 33% stopped.

## 1. What is estimated

* **Detection** is the streaming setup of REPORT 2.6, reproduced with the same code and protocol: per detector one
  model trained on the training rows at the nine prefixes of `compute_oof.STREAM_PREFIXES` (0.5, 1, 2, 3, 5, 8, 10,
  15 and 20 s; `compute_oof._fit_stream_models`), Table V protocol (grouped 5-fold, fold seeds 42 and 0-8, published
  groups), so every run is scored by models that never saw its family, project or attack instance. Each test run is
  scored after every 0.5-s window (prefixes 1-40; REPORT 2.6 evaluated the nine training prefixes only). The first
  window w whose probability reaches the threshold (0.5, 0.8, 0.9) is the verdict; a run not flagged within the 20 s
  is not contained.
* **Time to containment** T = (w + 1) x 0.5 s + R + L: the verdict on window w exists when the window ends; R =
  0.35 s is the collector's read budget (70% of a window); L is the time to install the rule, unmeasured, taken as
  1 ms, 10 ms or 100 ms. The earliest possible T is 0.851-0.95 s.
* **Rule**: per host (it matches the host's address or switch port), so every IPv4 frame the host sends at or after T
  is dropped and frames sent before T get through. A per-flow rule would not stop fan-out floods, whose every packet
  opens a new flow.
* **Traffic**: from each run's `packet_capture.pcap`, the IPv4 frames sent by the guest's NIC (Ethernet source
  `00:1b:21:0a:ee:09`) with offset in [0, 20 s) from `sample_started_wall_us`, the window anchor of the switch model;
  packets and frame bytes before and after T. The attacker is assumed not to react to the drop; traffic after the
  20-s observation is not counted.
* **Shares**: *mean per run* = mean over the (fold assignment, run) pairs of the run's stopped share, a run never
  flagged counting 0, so every run weighs the same; *pooled* = all packets of the group together, so the large floods
  dominate; *ceiling* = the share stopped if the run is flagged in the first window in every assignment.

## 2. Checks

| Check | Result |
| --- | --- |
| Streaming predictions at the nine prefixes vs `cache/stream.npz` (4 detectors x 10 assignments x 240 rows) | largest difference 0.0 |
| REPORT 2.6 numbers (`analyze_rigor.streaming`) vs `results/rigor.json` | identical |
| IPv4 TCP/UDP packets in the observation vs `net_pkts_total_delta__sum` of `features.csv` | equal in 240 of 240 runs |
| Source MAC of every frame from 10.0.0.10 | `00:1b:21:0a:ee:09` only |
| Outbound IPv4 frames with another source address (spoofing) | 0 |
| Outbound non-IPv4 frames (ARP), not counted | 2631 |

Evaluated after every window instead of the nine prefixes, the stacked hybrid flags 78% of malicious runs by 20 s
(REPORT 2.6: 78%) with 20% any-time false alarms (REPORT: 19%); 95% of its detections fall in the first window.

## 3. Attacks and malware, stacked hybrid (L = 10 ms)

| Group | Threshold | Contained by 20 s | Median T (s) | Within 1 s | Packets stopped (mean per run) | Bytes stopped | Packets stopped (pooled) | Ceiling |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SYN floods (4 runs) | 0.5 | 100% | 0.86 | 100% | 42% | 42% | 56% | 42% |
|  | 0.8 | 98% | 0.86 | 88% | 40% | 40% | 54% | 42% |
|  | 0.9 | 82% | 0.86 | 72% | 34% | 34% | 46% | 42% |
| UDP floods (4) | 0.5 | 100% | 0.86 | 98% | 44% | 44% | 52% | 45% |
|  | 0.8 | 98% | 0.86 | 82% | 40% | 40% | 50% | 45% |
|  | 0.9 | 88% | 0.86 | 52% | 35% | 35% | 47% | 45% |
| Slowloris (5) | 0.5 | 100% | 0.86 | 96% | 50% | 49% | 51% | 50% |
|  | 0.8 | 86% | 0.86 | 80% | 42% | 42% | 48% | 50% |
|  | 0.9 | 72% | 0.86 | 56% | 31% | 30% | 34% | 50% |
| GoldenEye (2) | 0.5 | 100% | 0.86 | 100% | 36% | 24% | 36% | 36% |
|  | 0.8 | 100% | 0.86 | 100% | 36% | 24% | 36% | 36% |
|  | 0.9 | 95% | 0.86 | 90% | 34% | 23% | 34% | 36% |
| All 15 attacks | 0.5 | 100% | 0.86 | 98% | 44% | 43% | 53% | 44% |
|  | 0.8 | 94% | 0.86 | 85% | 40% | 38% | 51% | 44% |
|  | 0.9 | 82% | 0.86 | 64% | 33% | 31% | 45% | 44% |
| Malware that sends (52) | 0.5 | 100% | 0.86 | 94% | 88% | 88% | 96% | 89% |
|  | 0.8 | 97% | 0.86 | 72% | 80% | 80% | 96% | 89% |
|  | 0.9 | 85% | 0.86 | 54% | 68% | 68% | 87% | 89% |

All 99 malware runs: contained by 20 s 75% / 56% / 45% at 0.5 / 0.8 / 0.9; the 47 that send nothing have nothing to stop.

## 4. All four detectors (L = 10 ms): contained by 20 s / median T / packets stopped (mean per run)

**Threshold 0.5**

| Group | Stacked | Concatenated | Host-only | Network-only |
| --- | --- | --- | --- | --- |
| SYN floods (4 runs) | 100% · 0.86 s · 42% | 100% · 0.86 s · 42% | 90% · 0.86 s · 38% | 100% · 0.86 s · 42% |
| UDP floods (4) | 100% · 0.86 s · 44% | 100% · 0.86 s · 45% | 100% · 0.86 s · 37% | 100% · 0.86 s · 45% |
| Slowloris (5) | 100% · 0.86 s · 50% | 98% · 0.86 s · 49% | 96% · 0.86 s · 44% | 100% · 0.86 s · 49% |
| GoldenEye (2) | 100% · 0.86 s · 36% | 100% · 0.86 s · 36% | 100% · 0.86 s · 36% | 100% · 0.86 s · 36% |
| All 15 attacks | 100% · 0.86 s · 44% | 99% · 0.86 s · 44% | 96% · 0.86 s · 40% | 100% · 0.86 s · 44% |
| Malware that sends (52) | 100% · 0.86 s · 88% | 100% · 0.86 s · 88% | 98% · 0.86 s · 86% | 100% · 0.86 s · 82% |
| All 99 malware | 75% · 0.86 s | 80% · 0.86 s | 77% · 0.86 s | 52% · 0.86 s |

**Threshold 0.8**

| Group | Stacked | Concatenated | Host-only | Network-only |
| --- | --- | --- | --- | --- |
| SYN floods (4 runs) | 98% · 0.86 s · 40% | 98% · 0.86 s · 38% | 90% · 0.86 s · 33% | 100% · 0.86 s · 42% |
| UDP floods (4) | 98% · 0.86 s · 40% | 100% · 0.86 s · 45% | 78% · 0.86 s · 34% | 100% · 0.86 s · 45% |
| Slowloris (5) | 86% · 0.86 s · 42% | 78% · 0.86 s · 40% | 68% · 0.86 s · 30% | 78% · 0.86 s · 40% |
| GoldenEye (2) | 100% · 0.86 s · 36% | 100% · 0.86 s · 36% | 100% · 0.86 s · 36% | 100% · 0.86 s · 36% |
| All 15 attacks | 94% · 0.86 s · 40% | 92% · 0.86 s · 40% | 81% · 0.86 s · 32% | 93% · 0.86 s · 41% |
| Malware that sends (52) | 97% · 0.86 s · 80% | 98% · 0.86 s · 85% | 81% · 0.86 s · 70% | 100% · 0.86 s · 82% |
| All 99 malware | 56% · 0.86 s | 71% · 0.86 s | 63% · 0.86 s | 52% · 0.86 s |

**Threshold 0.9**

| Group | Stacked | Concatenated | Host-only | Network-only |
| --- | --- | --- | --- | --- |
| SYN floods (4 runs) | 82% · 0.86 s · 34% | 72% · 0.86 s · 32% | 90% · 0.86 s · 33% | 88% · 0.86 s · 38% |
| UDP floods (4) | 88% · 0.86 s · 35% | 100% · 0.86 s · 43% | 70% · 0.86 s · 28% | 100% · 0.86 s · 45% |
| Slowloris (5) | 72% · 0.86 s · 31% | 78% · 0.86 s · 39% | 40% · 0.86 s · 20% | 78% · 0.86 s · 40% |
| GoldenEye (2) | 95% · 0.86 s · 34% | 100% · 0.86 s · 36% | 100% · 1.36 s · 33% | 100% · 1.36 s · 35% |
| All 15 attacks | 82% · 0.86 s · 33% | 85% · 0.86 s · 38% | 69% · 0.86 s · 27% | 89% · 0.86 s · 40% |
| Malware that sends (52) | 85% · 0.86 s · 68% | 91% · 0.86 s · 76% | 65% · 0.86 s · 56% | 99% · 0.86 s · 80% |
| All 99 malware | 45% · 0.86 s | 62% · 0.86 s | 51% · 0.86 s | 52% · 0.86 s |

## 5. Rule install time (stacked, threshold 0.5): median T / packets stopped / ceiling

| Group | L = 1 ms | L = 10 ms | L = 100 ms |
| --- | --- | --- | --- |
| SYN floods (4 runs) | 0.851 s · 43% · 43% | 0.860 s · 42% · 42% | 0.950 s · 38% · 38% |
| UDP floods (4) | 0.851 s · 44% · 45% | 0.860 s · 44% · 45% | 0.950 s · 40% · 40% |
| Slowloris (5) | 0.851 s · 50% · 50% | 0.860 s · 50% · 50% | 0.950 s · 49% · 49% |
| GoldenEye (2) | 0.851 s · 36% · 36% | 0.860 s · 36% · 36% | 0.950 s · 36% · 36% |
| All 15 attacks | 0.851 s · 44% · 45% | 0.860 s · 44% · 44% | 0.950 s · 42% · 42% |
| Malware that sends (52) | 0.851 s · 88% · 89% | 0.860 s · 88% · 89% | 0.950 s · 88% · 88% |

## 6. Per attack run (threshold 0.5, L = 10 ms)

Traffic: outbound packets, and when half, 90% and the last of them were sent. Detector cells: assignments in which
the run is flagged (of 10) · median T (s) · share of its packets stopped (mean over assignments).

| Run | Packets sent | Half by (s) | 90% by (s) | Last (s) | Sent before 0.86 s | Stacked | Concatenated | Host-only | Network-only |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- |
| syn_fan_40k | 39,846 | 0.35 | 0.65 | 0.73 | 100% | 10/10 · 0.86 · 0% | 10/10 · 0.86 · 0% | 9/10 · 0.86 · 0% | 10/10 · 0.86 · 0% |
| syn_fan_100k | 99,639 | 1.04 | 1.83 | 2.03 | 41% | 10/10 · 0.86 · 59% | 10/10 · 0.86 · 59% | 9/10 · 0.86 · 53% | 10/10 · 0.86 · 59% |
| syn_fan_150k | 149,423 | 3.04 | 5.56 | 6.07 | 15% | 10/10 · 0.86 · 85% | 10/10 · 0.86 · 85% | 9/10 · 0.86 · 76% | 10/10 · 0.86 · 85% |
| syn_sink_40k | 82,332 | 0.70 | 0.97 | 5.43 | 74% | 10/10 · 0.86 · 26% | 10/10 · 0.86 · 26% | 9/10 · 0.86 · 24% | 10/10 · 0.86 · 26% |
| udp_fan_60k | 59,776 | 0.45 | 3.38 | 3.45 | 64% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% |
| udp_sink_60k | 60,000 | 0.64 | 1.11 | 1.22 | 67% | 10/10 · 0.86 · 29% | 10/10 · 0.86 · 33% | 10/10 · 1.36 · 3% | 10/10 · 0.86 · 33% |
| udp_sink_150k | 150,000 | 0.78 | 1.41 | 1.56 | 55% | 10/10 · 0.86 · 45% | 10/10 · 0.86 · 45% | 10/10 · 0.86 · 45% | 10/10 · 0.86 · 45% |
| udp_sink_250k | 250,000 | 1.63 | 3.38 | 3.69 | 35% | 10/10 · 0.86 · 65% | 10/10 · 0.86 · 65% | 10/10 · 0.86 · 65% | 10/10 · 0.86 · 65% |
| slowloris_150 | 1,600 | 0.29 | 15.10 | 15.70 | 56% | 10/10 · 0.86 · 44% | 9/10 · 0.86 · 40% | 8/10 · 0.86 · 36% | 10/10 · 0.86 · 40% |
| slowloris_300 | 3,259 | 0.64 | 15.14 | 16.38 | 52% | 10/10 · 0.86 · 48% | 10/10 · 0.86 · 48% | 10/10 · 0.86 · 48% | 10/10 · 0.86 · 48% |
| slowloris_500 | 5,548 | 1.00 | 15.31 | 17.35 | 49% | 10/10 · 0.86 · 51% | 10/10 · 0.86 · 51% | 10/10 · 0.86 · 51% | 10/10 · 0.86 · 51% |
| slowloris_800 | 8,811 | 1.68 | 15.32 | 18.67 | 48% | 10/10 · 0.86 · 52% | 10/10 · 0.86 · 52% | 10/10 · 0.86 · 48% | 10/10 · 0.86 · 52% |
| slowloris_1000 | 11,021 | 2.16 | 15.38 | 19.62 | 47% | 10/10 · 0.86 · 53% | 10/10 · 0.86 · 53% | 10/10 · 0.86 · 39% | 10/10 · 0.86 · 53% |
| goldeneye_p10 | 19,674 | 0.41 | 11.33 | 19.99 | 64% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% |
| goldeneye_r10 | 19,485 | 0.41 | 11.41 | 20.00 | 64% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% | 10/10 · 0.86 · 36% |

The four SYN and four UDP runs are count-limited bursts from the study's C generator; they end after 0.7-6 s, so the
share stopped is set by how much of the burst comes after 0.86 s. Slowloris and GoldenEye keep sending to the end of
the observation (GoldenEye beyond it), so for them the share within 20 s is a lower bound: an attack running for
minutes would be stopped almost entirely.

## 7. Benign runs that would be blocked (any-time false alarms, L = 10 ms)

| Detector | Threshold | CLI programs (105) | Network-active (18) | Null (3) | All benign (126) | Median T of a block (s) | Network-active bytes cut (pooled) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Stacked | 0.5 | 17% | 24% | 90% | 20% | 0.86 | 26% |
|  | 0.8 | 3% | 8% | 40% | 5% | 0.86 | 8% |
|  | 0.9 | 1% | 0% | 10% | 1% | 1.36 | 0% |
| Concatenated | 0.5 | 18% | 48% | 90% | 24% | 0.86 | 85% |
|  | 0.8 | 4% | 3% | 80% | 6% | 0.86 | 8% |
|  | 0.9 | 2% | 2% | 60% | 4% | 0.86 | 7% |
| Host-only | 0.5 | 23% | 14% | 100% | 23% | 0.86 | 0% |
|  | 0.8 | 7% | 1% | 80% | 8% | 0.86 | 0% |
|  | 0.9 | 3% | 0% | 60% | 4% | 0.86 | 0% |
| Network-only | 0.5 | 8% | 39% | 0% | 12% | 0.86 | 85% |
|  | 0.8 | 2% | 13% | 0% | 3% | 0.86 | 8% |
|  | 0.9 | 0% | 2% | 0% | 0% | 1.86 | 7% |

*Network-active bytes cut*: of all outbound bytes of the 18 network-active benign runs over the ten assignments, the
share sent after a (wrong) block. The CLI programs send almost nothing (27 of them send 17,293 bytes in total), so
blocking them costs a false alarm rather than traffic.

The 18 network-active benign runs at threshold 0.5: assignments in which the run is blocked (of 10) · median T (s) ·
share of its bytes cut (mean over assignments). The three uploads hold 684 of the 690 MB these runs send.

| Run | Packets sent | MB sent | Stacked | Concatenated | Host-only | Network-only |
| --- | ---: | ---: | --- | --- | --- | --- |
| bulkup_200 | 5,768 | 105.3 | 4/10 · 0.86 · 21% | 10/10 · 0.86 · 68% | 0/10 · - · 0% | 10/10 · 0.86 · 68% |
| bulkup_400 | 11,586 | 210.5 | 4/10 · 0.86 · 25% | 10/10 · 0.86 · 85% | 0/10 · - · 0% | 10/10 · 0.86 · 85% |
| bulkup_700 | 19,892 | 368.4 | 4/10 · 0.86 · 27% | 10/10 · 0.86 · 91% | 0/10 · - · 0% | 10/10 · 0.86 · 91% |
| session_300 | 1,844 | 0.1 | 1/10 · 1.36 · 6% | 1/10 · 1.36 · 6% | 1/10 · 4.36 · 1% | 1/10 · 1.36 · 6% |
| session_600 | 3,614 | 0.3 | 1/10 · 1.36 · 9% | 1/10 · 1.36 · 9% | 1/10 · 8.36 · 0% | 1/10 · 1.36 · 9% |
| session_1000 | 6,000 | 0.4 | 1/10 · 1.36 · 9% | 1/10 · 1.36 · 9% | 1/10 · 11.86 · 0% | 1/10 · 1.36 · 9% |
| beacon_50 | 300 | 0.0 | 3/10 · 1.36 · 18% | 8/10 · 11.36 · 9% | 10/10 · 0.86 · 82% | 1/10 · 1.36 · 9% |
| beacon_100 | 605 | 0.0 | 2/10 · 9.11 · 9% | 8/10 · 16.86 · 9% | 10/10 · 0.86 · 94% | 1/10 · 1.36 · 9% |
| dns_2k | 2,000 | 0.1 | 5/10 · 0.86 · 0% | 10/10 · 0.86 · 0% | 0/10 · - · 0% | 9/10 · 0.86 · 0% |
| dns_5k | 5,000 | 0.3 | 5/10 · 0.86 · 0% | 10/10 · 0.86 · 0% | 0/10 · - · 0% | 10/10 · 0.86 · 0% |
| dns_10k | 10,000 | 0.7 | 6/10 · 0.86 · 16% | 10/10 · 0.86 · 32% | 0/10 · - · 0% | 10/10 · 0.86 · 29% |
| bulkdl | 1,801 | 0.1 | 1/10 · 1.36 · 6% | 1/10 · 1.36 · 6% | 1/10 · 3.86 · 0% | 1/10 · 1.36 · 6% |
| bulk400 | 2,399 | 0.2 | 1/10 · 1.36 · 6% | 1/10 · 1.36 · 6% | 1/10 · 4.36 · 0% | 1/10 · 1.36 · 6% |
| bulk700 | 4,200 | 0.3 | 1/10 · 1.36 · 8% | 1/10 · 1.36 · 8% | 0/10 · - · 0% | 1/10 · 1.36 · 8% |
| bulk1000 | 6,110 | 0.5 | 1/10 · 1.36 · 9% | 1/10 · 1.36 · 9% | 0/10 · - · 0% | 1/10 · 1.36 · 9% |
| bulk1300 | 8,038 | 0.6 | 1/10 · 1.36 · 9% | 1/10 · 1.36 · 9% | 0/10 · - · 0% | 1/10 · 1.36 · 9% |
| bulk1600 | 9,708 | 0.7 | 1/10 · 1.36 · 9% | 1/10 · 1.36 · 9% | 0/10 · - · 0% | 1/10 · 1.36 · 9% |
| bulk2000 | 12,000 | 0.9 | 1/10 · 1.36 · 9% | 1/10 · 1.36 · 9% | 0/10 · - · 0% | 1/10 · 1.36 · 9% |

The stacked hybrid blocks the three uploads and the DNS bursts in 4-6 of 10 assignments, the concatenated hybrid and
the network view in 9-10; the host view never blocks them but blocks the two beacons in every assignment, cutting
82-94% of their (few) bytes. The session and download runs are blocked only in one fold assignment (seed 4), by all
four detectors (the host view: the sessions and the two smaller downloads).

Benign units blocked in at least 3 of 10 assignments by the stacked hybrid at threshold 0.5:

| Unit | Runs | Blocked (share of run x assignment) | Median T (s) | Outbound packets | Packets cut (mean) |
| --- | ---: | ---: | ---: | ---: | ---: |
| project::rsync | 2 | 100% | 0.86 | 0 | - |
| null::null1 | 1 | 90% | 0.86 | 0 | - |
| null::null2 | 1 | 90% | 0.86 | 0 | - |
| null::nullidle | 1 | 90% | 0.86 | 0 | - |
| project::inetutils | 10 | 69% | 0.86 | 49 | 1% |
| network_benign::dns_10k | 1 | 60% | 0.86 | 10,000 | 16% |
| network_benign::dns_2k | 1 | 50% | 0.86 | 2,000 | 0% |
| network_benign::dns_5k | 1 | 50% | 0.86 | 5,000 | 0% |
| project::diffutils | 4 | 50% | 0.86 | 0 | - |
| project::jq | 2 | 50% | 3.36 | 0 | - |
| network_benign::bulkup_200 | 1 | 40% | 0.86 | 5,768 | 20% |
| network_benign::bulkup_400 | 1 | 40% | 0.86 | 11,586 | 25% |
| network_benign::bulkup_700 | 1 | 40% | 0.86 | 19,892 | 27% |
| project::lz4 | 6 | 40% | 0.86 | 0 | - |
| network_benign::beacon_50 | 1 | 30% | 1.36 | 300 | 18% |
| project::cpio | 2 | 30% | 0.86 | 0 | - |

## 8. Malware families that send traffic (stacked, threshold 0.5, L = 10 ms)

| Family | Runs | Runs that send | Flagged by 20 s (all its runs) | Median T (s) | Packets sent | Packets stopped (mean over the runs that send) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Chaos | 2 | 2 | 100% | 0.86 | 110,950 | 94% |
| Mirai | 9 | 6 | 86% | 0.86 | 1,046 | 92% |
| Kaiji | 10 | 10 | 100% | 0.86 | 241 | 90% |
| Gafgyt | 10 | 9 | 100% | 0.86 | 86 | 89% |
| Kaiten | 3 | 2 | 70% | 0.86 | 54 | 94% |
| Tsunami | 8 | 3 | 100% | 0.86 | 42 | 93% |
| Dofloo | 4 | 4 | 100% | 0.86 | 40 | 90% |
| CoinMiner | 2 | 2 | 100% | 3.86 | 34 | 88% |
| RapperBot | 1 | 1 | 100% | 0.86 | 21 | 95% |
| XorDDoS | 2 | 2 | 100% | 0.86 | 20 | 85% |
| DeskRAT | 3 | 1 | 100% | 0.86 | 17 | 47% |
| Katana | 2 | 2 | 100% | 0.86 | 16 | 73% |
| BrickStorm | 4 | 1 | 25% | 0.86 | 9 | 89% |
| DDoSAgent | 3 | 1 | 67% | 0.86 | 9 | 89% |
| Prometei | 2 | 2 | 100% | 0.86 | 9 | 94% |
| PromptLock | 1 | 1 | 100% | 0.86 | 9 | 89% |
| BillGates | 1 | 1 | 100% | 0.86 | 8 | 100% |
| Ngioweb | 2 | 2 | 100% | 0.86 | 8 | 50% |

## 9. Limitations

* An estimate from recorded runs: the rule, its install time L and the switch's behaviour after the rule are not
  measured; R = 0.35 s is the collector's budget, not a measured read time. The attacker does not react to the drop
  (no retransmissions, no change of address), and the host process is not stopped, only its traffic.
* The attacks are 15 runs of four types from two implementations (the C generator for SYN and UDP, Python tools for
  Slowloris and GoldenEye); the floods are short bursts, so the stopped share mostly measures how much of each burst
  falls after 0.86 s. Within the 20-s observation only; longer attacks would be stopped in a larger share.
* Detection comes from the streaming model under grouped cross-validation on an already-examined dataset (post hoc).
  First-window detection relies on the observation starting when the program starts, as in the dataset; a
  deployment has to decide when a process's first window begins (REPORT 4, socket attribution).
* Every one of the 52 malware runs that send traffic is flagged: in this dataset network traffic itself is rare among
  benign programs and unanswered connection attempts occur only in malware, so this is optimistic for malware whose
  traffic looks like benign clients'.
* The capture is taken on the sending guest, so the three TCP uploads appear as segmentation-offload super-frames of
  up to 65,226 bytes (their packet counts are capture frames, not wire packets; bytes are exact). The SYN/UDP floods,
  Slowloris, GoldenEye and the malware send small frames, so their packet shares are wire packets.
* A per-host rule cuts all of the host's traffic; with several programs on one host it would also cut the benign ones,
  unless the rule is scoped by the socket attribution of REPORT 4.

## 10. Files and hashes

Reproduce: `/usr/bin/python3 mitigation/mitigation.py --jobs 8` from `committee-eval-20261113/` (scikit-learn 1.7.0,
about 3 minutes on 8 CPUs; run here at nice 19 pinned to CPUs 8-11, 20-23). Runtime of this run: 180 s.

| File | SHA-256 |
| --- | --- |
| `mitigation/mitigation.py` | `8e9c0820674de51fd0889bac582f4191b1303395951a57927fd06995204978d9` |
| `mitigation/results.json` | `e579f54801261a57f1b998c1fa5aba1117317eed6ba4e7549747859e42ad9ee3` |
| `mitigation/mitigation.log` | `3aacdbe5ab57560a96deef81b7334b175914a9a2fb805205049d7ec0f147bf16` |
| input `features.csv` | `6d15da30a4bc1b9bcea47bce1b96c00f74ae5ddadd68255a17ed5d0b46c19c16` |
| input `independent_pool.json` | `5c71c08f3257b59ff4f3970bd9848a88095bbc256c826b7ea148c8f8bc234248` |
| input `cache/windows.npz` | `142678652eff20404bdaddaa50d7ecfb5fc9a445d90f8baa2c7ebbf0e1bbdaa7` |
| input `cache/stream.npz` | `77e53eddb8c4500109ce615211186d9000f32b0433a4c97e559d56bdedcab8a3` |
| input `results/rigor.json` | `d21cac173eef77d7eaae124fb3e214dea4b904e9c80aa3f6e9d4f29b0df3c694` |
| input `common.py` | `b3f8aac246d56ead8d7a78f2d38fec3b679018c5cf9f7ee7e3f1e7ed6e6a8b69` |
| input `compute_oof.py` | `30ec821e39d47665c3bb5fe66c292003a977f75848d98a66a1436ae8f5cd8ed0` |
| input `analyze_rigor.py` | `e1424bc78c9a2e6b2ee68fcca69961b866fa836b0d0392ccd3e8c85b8c874eab` |
| input `switch_model.py` | `d5a140fd5cda04afc9e6d73a28da354146ed184c9b381ca4d89a20543791eb80` |
| input: the 240 `packet_capture.pcap` (per-run hashes in `results.json` `pcap_sha256`), digest of that table | `22cb659a70e0ce59b0bed72825aa0d4cb34cc80fde24a30ee83282f5d4918360` |
